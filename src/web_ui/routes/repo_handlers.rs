//! Repository viewing handlers: tree browsing, blob viewing, and commit history.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use crate::git::{CommitInfo, ObjectId};
use super::utils::{
    render_template, render_error, add_user_to_context, format_time_ago,
    BranchInfo, Breadcrumb,
};
use super::lfs::{parse_lfs_pointer, check_lfs_file};
use super::diff::compute_diff;
use crate::web_ui::templates;

/// Tree entry info for templates
#[derive(serde::Serialize)]
struct TreeEntryInfo {
    name: String,
    full_path: String,
    is_dir: bool,
    is_lfs: bool,
    lfs_status: Option<String>,
    lfs_size: Option<String>,
    lfs_oid: Option<String>,
}

/// View tree root (no path)
pub async fn tree_root(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    tree_view_impl(state, &owner, &repo, &ref_name, "", headers).await
}

/// View tree at a specific path
pub async fn tree_path(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Response {
    tree_view_impl(state, &owner, &repo, &ref_name, &path, headers).await
}

/// Implementation for tree viewing
async fn tree_view_impl(
    state: Arc<AppState>,
    owner: &str,
    repo: &str,
    ref_name: &str,
    path: &str,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
    };

    // Resolve ref to commit
    let commit_id = match repo_handle.resolve_ref(&format!("refs/heads/{}", ref_name)) {
        Some(id) => id,
        None => return render_error(&format!("Branch '{}' not found", ref_name)),
    };

    // Get tree from commit
    let root_tree = match repo_handle.get_commit_tree(&commit_id) {
        Some(t) => t,
        None => return render_error("Could not read commit tree"),
    };

    // Navigate to path if specified
    let (tree_id, is_dir) = if path.is_empty() {
        (root_tree, true)
    } else {
        match repo_handle.resolve_path(&root_tree, path) {
            Some((id, is_dir)) => (id, is_dir),
            None => return render_error(&format!("Path '{}' not found", path)),
        }
    };

    if !is_dir {
        return render_error(&format!("'{}' is a file, not a directory", path));
    }

    // Parse tree entries
    let entries = match repo_handle.parse_tree(&tree_id) {
        Some(e) => e,
        None => return render_error("Could not parse tree"),
    };

    let mut context = Context::new();
    context.insert("owner", owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("ref_name", ref_name);
    context.insert("path", path);

    // Get branches for switcher
    let git_refs = repo_handle.list_refs();
    let branches: Vec<BranchInfo> = git_refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/"))
        .map(|r| BranchInfo {
            name: r.name.strip_prefix("refs/heads/").unwrap_or(&r.name).to_string(),
        })
        .collect();
    context.insert("branches", &branches);

    // Current directory name
    let current_name = if path.is_empty() {
        repo_name.to_string()
    } else {
        path.split('/').last().unwrap_or(repo_name).to_string()
    };
    context.insert("current_name", &current_name);

    // Build breadcrumbs
    let breadcrumbs: Vec<Breadcrumb> = if path.is_empty() {
        vec![]
    } else {
        let parts: Vec<&str> = path.split('/').collect();
        parts
            .iter()
            .enumerate()
            .map(|(i, name)| Breadcrumb {
                name: name.to_string(),
                path: parts[..=i].join("/"),
            })
            .collect()
    };
    context.insert("breadcrumbs", &breadcrumbs);

    // Parent path for ".." link
    let parent_path = if path.is_empty() {
        None
    } else {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() <= 1 {
            Some("".to_string())
        } else {
            Some(parts[..parts.len() - 1].join("/"))
        }
    };
    context.insert("parent_path", &parent_path);

    // Convert entries for template, checking for LFS files
    let entry_infos: Vec<TreeEntryInfo> = entries
        .iter()
        .map(|e| {
            let full_path = if path.is_empty() {
                e.name.clone()
            } else {
                format!("{}/{}", path, e.name)
            };

            let (is_lfs, lfs_status, lfs_size, lfs_oid) = check_lfs_file(&repo_handle, &state, e);

            TreeEntryInfo {
                name: e.name.clone(),
                full_path,
                is_dir: e.is_dir,
                is_lfs,
                lfs_status,
                lfs_size,
                lfs_oid,
            }
        })
        .collect();
    context.insert("entries", &entry_infos);
    context.insert("active_tab", "files");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("tree.html", &context)
}

/// View a file (blob)
pub async fn blob_view(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Response {
    use super::utils::format_size;

    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
    };

    let commit_id = match repo_handle.resolve_ref(&format!("refs/heads/{}", ref_name)) {
        Some(id) => id,
        None => return render_error(&format!("Branch '{}' not found", ref_name)),
    };

    let root_tree = match repo_handle.get_commit_tree(&commit_id) {
        Some(t) => t,
        None => return render_error("Could not read commit tree"),
    };

    let (blob_id, is_dir) = match repo_handle.resolve_path(&root_tree, &path) {
        Some((id, is_dir)) => (id, is_dir),
        None => return render_error(&format!("File '{}' not found", path)),
    };

    if is_dir {
        return render_error(&format!("'{}' is a directory, not a file", path));
    }

    let content = match repo_handle.get_blob_content(&blob_id) {
        Some(c) => c,
        None => return render_error("Could not read file content"),
    };

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("ref_name", &ref_name);
    context.insert("path", &path);

    let file_name = path.split('/').last().unwrap_or(&path);
    context.insert("file_name", file_name);

    // Build breadcrumbs
    let parts: Vec<&str> = path.split('/').collect();
    let breadcrumbs: Vec<Breadcrumb> = parts
        .iter()
        .enumerate()
        .map(|(i, name)| Breadcrumb {
            name: name.to_string(),
            path: parts[..=i].join("/"),
        })
        .collect();
    context.insert("breadcrumbs", &breadcrumbs);

    // Check if this is an LFS pointer file
    let (is_lfs, lfs_status, lfs_size, lfs_oid, actual_size_display) = if let Some(lfs_info) = parse_lfs_pointer(&content) {
        let status = state.cas.get_lfs_object_status(&lfs_info.oid);
        let status_str = status.map(|s| match s {
            crate::cas::store::LfsObjectStatus::Raw => "raw".to_string(),
            crate::cas::store::LfsObjectStatus::Processing => "processing".to_string(),
            crate::cas::store::LfsObjectStatus::Chunked => "chunked".to_string(),
        });
        let oid_hex = lfs_info.oid.to_hex();
        (true, status_str, Some(format_size(lfs_info.size)), Some(oid_hex), format_size(lfs_info.size))
    } else {
        let size = content.len() as u64;
        (false, None, None, None, format_size(size))
    };

    context.insert("is_lfs", &is_lfs);
    context.insert("lfs_status", &lfs_status);
    context.insert("lfs_size", &lfs_size);
    context.insert("lfs_oid", &lfs_oid);
    context.insert("size_display", &actual_size_display);
    context.insert("active_tab", "files");

    // Get branches for the header
    let git_refs = repo_handle.list_refs();
    let branches: Vec<BranchInfo> = git_refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/"))
        .map(|r| BranchInfo {
            name: r.name.strip_prefix("refs/heads/").unwrap_or(&r.name).to_string(),
        })
        .collect();
    context.insert("branches", &branches);

    // Check if binary
    let is_binary = is_lfs || content.iter().take(8000).any(|&b| b == 0);
    context.insert("is_binary", &is_binary);

    if is_binary {
        context.insert("content", &String::new());
        context.insert("line_count", &0);
    } else {
        let text = String::from_utf8_lossy(&content);
        let line_count = text.lines().count();
        context.insert("line_count", &line_count);
        context.insert("content", &text);
    }

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("blob.html", &context)
}

/// Query params for commits list
#[derive(serde::Deserialize, Default)]
pub struct CommitsQuery {
    pub page: Option<usize>,
}

/// Commit info for templates
#[derive(serde::Serialize)]
struct CommitInfoView {
    id: String,
    short_id: String,
    message: String,
    short_message: String,
    author_name: String,
    author_email: String,
    author_time: i64,
    author_time_ago: String,
    parent_ids: Vec<String>,
}

impl From<&CommitInfo> for CommitInfoView {
    fn from(c: &CommitInfo) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            id: c.id.to_hex(),
            short_id: c.id.to_hex()[..7].to_string(),
            message: c.message.clone(),
            short_message: c.short_message.clone(),
            author_name: c.author_name.clone(),
            author_email: c.author_email.clone(),
            author_time: c.author_time,
            author_time_ago: format_time_ago(now - c.author_time),
            parent_ids: c.parent_ids.iter().map(|p| p.to_hex()).collect(),
        }
    }
}

/// List commits for a branch
pub async fn commits_list(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name)): Path<(String, String, String)>,
    Query(query): Query<CommitsQuery>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
    };

    let commit_id = match repo_handle.resolve_ref(&format!("refs/heads/{}", ref_name)) {
        Some(id) => id,
        None => return render_error(&format!("Branch '{}' not found", ref_name)),
    };

    // Pagination: 30 commits per page
    let per_page = 30;
    let page = query.page.unwrap_or(1).max(1);
    let skip = (page - 1) * per_page;

    let commits = repo_handle.walk_commits(&commit_id, per_page + 1, skip);
    let has_next = commits.len() > per_page;
    let commits: Vec<CommitInfoView> = commits.iter().take(per_page).map(|c| c.into()).collect();

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("ref_name", &ref_name);
    context.insert("commits", &commits);
    context.insert("page", &page);
    context.insert("has_next", &has_next);
    context.insert("has_prev", &(page > 1));

    let git_refs = repo_handle.list_refs();
    let branches: Vec<BranchInfo> = git_refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/"))
        .map(|r| BranchInfo {
            name: r.name.strip_prefix("refs/heads/").unwrap_or(&r.name).to_string(),
        })
        .collect();
    context.insert("branches", &branches);
    context.insert("active_tab", "commits");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("commits.html", &context)
}

/// View a single commit with diff
pub async fn commit_view(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, sha)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
    };

    let commit_id = match ObjectId::from_hex(&sha) {
        Some(id) => id,
        None => return render_error(&format!("Invalid commit SHA: {}", sha)),
    };

    let commit_info = match repo_handle.get_commit_info(&commit_id) {
        Some(info) => info,
        None => return render_error(&format!("Commit '{}' not found", sha)),
    };

    let parent_tree = if !commit_info.parent_ids.is_empty() {
        repo_handle.get_commit_tree(&commit_info.parent_ids[0])
    } else {
        None
    };

    let file_changes = compute_diff(&repo_handle, parent_tree.as_ref(), &commit_info.tree_id);
    let commit_view: CommitInfoView = (&commit_info).into();

    let git_refs = repo_handle.list_refs();
    let branches: Vec<BranchInfo> = git_refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/"))
        .map(|r| BranchInfo {
            name: r.name.strip_prefix("refs/heads/").unwrap_or(&r.name).to_string(),
        })
        .collect();

    let default_branch = branches.first().map(|b| b.name.clone()).unwrap_or_else(|| "main".to_string());

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("commit", &commit_view);
    context.insert("file_changes", &file_changes);
    context.insert("total_additions", &file_changes.iter().map(|f| f.additions).sum::<usize>());
    context.insert("total_deletions", &file_changes.iter().map(|f| f.deletions).sum::<usize>());
    context.insert("files_changed", &file_changes.len());
    context.insert("branches", &branches);
    context.insert("ref_name", &default_branch);
    context.insert("active_tab", "commits");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("commit.html", &context)
}

/// Find README file and render as HTML
pub fn find_and_render_readme(repo: &crate::git::Repository, tree_id: &ObjectId) -> Option<String> {
    let entries = repo.parse_tree(tree_id)?;

    let readme_names = ["README.md", "readme.md", "README", "readme", "README.txt", "readme.txt"];

    for readme_name in readme_names {
        if let Some(entry) = entries.iter().find(|e| e.name.eq_ignore_ascii_case(readme_name) && !e.is_dir) {
            if let Some(content) = repo.get_blob_content(&entry.oid) {
                if content.iter().take(8000).any(|&b| b == 0) {
                    return None;
                }

                let text = String::from_utf8_lossy(&content);

                if entry.name.to_lowercase().ends_with(".md") {
                    return Some(templates::render_markdown(&text));
                } else {
                    return Some(format!("<pre>{}</pre>", ammonia::clean(&text)));
                }
            }
        }
    }

    None
}
