//! Web UI route handlers.

use axum::{
    extract::{Path, State, Form},
    http::StatusCode,
    response::{Html, IntoResponse, Response, Redirect},
    routing::get,
    Router,
};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use crate::git::{ObjectId, ObjectType, Repository, TreeEntry};
use super::templates;

/// Create the web UI router with all routes under /ui
pub fn create_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(index))
        .route("/ui", get(index))
        .route("/ui/repos", get(repos_list))
        .route("/ui/repos/:repo", get(repo_detail))
        .route("/ui/repos/:repo/tree/:ref", get(tree_root))
        .route("/ui/repos/:repo/tree/:ref/*path", get(tree_path))
        .route("/ui/repos/:repo/blob/:ref/*path", get(blob_view))
        .route("/ui/repos/:repo/edit/:ref/*path", get(edit_file).post(commit_file))
        .route("/ui/stats", get(stats))
}

/// Home page
async fn index(State(state): State<Arc<AppState>>) -> Response {
    let mut context = Context::new();

    let repos: Vec<String> = state.repos.list_repos();
    let stats = state.cas.stats();

    context.insert("repos", &repos);
    context.insert("repo_count", &repos.len());
    context.insert("block_count", &stats.block_count);
    context.insert("chunk_count", &stats.chunk_count);

    render_template("index.html", &context)
}

/// List all repositories
async fn repos_list(State(state): State<Arc<AppState>>) -> Response {
    let mut context = Context::new();

    let repos: Vec<String> = state.repos.list_repos();
    context.insert("repos", &repos);

    render_template("repos.html", &context)
}

/// Repository detail page
async fn repo_detail(
    State(state): State<Arc<AppState>>,
    Path(repo): Path<String>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");

    // Check if repo exists
    let repo_handle = match state.repos.get_repo(repo_name) {
        Ok(r) => r,
        Err(_) => {
            return render_error(&format!("Repository '{}' not found", repo_name));
        }
    };

    let mut context = Context::new();
    context.insert("repo_name", repo_name);

    // Get refs using public API - filter to just branches and extract short name
    let git_refs = repo_handle.list_refs();
    let refs: Vec<RefInfo> = git_refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/")) // Only branches, not HEAD
        .map(|r| {
            let hash = r.target.to_hex();
            let short_name = r.name.strip_prefix("refs/heads/").unwrap_or(&r.name);
            RefInfo {
                name: short_name.to_string(),
                short_hash: hash.chars().take(7).collect(),
                hash,
            }
        })
        .collect();

    context.insert("refs", &refs);

    render_template("repo.html", &context)
}

/// Stats page
async fn stats(State(state): State<Arc<AppState>>) -> Response {
    let mut context = Context::new();

    let repos: Vec<String> = state.repos.list_repos();
    let cas_stats = state.cas.stats();
    let lfs_stats = state.cas.lfs_stats();

    context.insert("repos", &repos);
    context.insert("repo_count", &repos.len());
    context.insert("block_count", &cas_stats.block_count);
    context.insert("chunk_count", &cas_stats.chunk_count);
    context.insert("reconstruction_count", &cas_stats.reconstruction_count);
    context.insert("lfs_object_count", &lfs_stats.object_count);

    render_template("index.html", &context)
}

/// Helper to render a template
fn render_template(name: &str, context: &Context) -> Response {
    match templates::render(name, context) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Template error: {}", e)).into_response()
        }
    }
}

/// Helper to render an error page
fn render_error(message: &str) -> Response {
    let mut context = Context::new();
    context.insert("message", message);

    match templates::render("error.html", &context) {
        Ok(html) => (StatusCode::NOT_FOUND, Html(html)).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, message.to_string()).into_response(),
    }
}

/// Reference info for templates
#[derive(serde::Serialize)]
struct RefInfo {
    name: String,
    hash: String,
    short_hash: String,
}

/// Tree entry info for templates
#[derive(serde::Serialize)]
struct TreeEntryInfo {
    name: String,
    full_path: String,
    is_dir: bool,
    is_lfs: bool,
    lfs_status: Option<String>, // "raw", "processing", "chunked"
    lfs_size: Option<String>,   // Human-readable size
    lfs_oid: Option<String>,    // LFS object ID for download URL
}

/// Breadcrumb for navigation
#[derive(serde::Serialize)]
struct Breadcrumb {
    name: String,
    path: String,
}

/// View tree root (no path)
async fn tree_root(
    State(state): State<Arc<AppState>>,
    Path((repo, ref_name)): Path<(String, String)>,
) -> Response {
    tree_view_impl(state, &repo, &ref_name, "").await
}

/// View tree at a specific path
async fn tree_path(
    State(state): State<Arc<AppState>>,
    Path((repo, ref_name, path)): Path<(String, String, String)>,
) -> Response {
    tree_view_impl(state, &repo, &ref_name, &path).await
}

/// Implementation for tree viewing
async fn tree_view_impl(
    state: Arc<AppState>,
    repo: &str,
    ref_name: &str,
    path: &str,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");

    let repo_handle = match state.repos.get_repo(repo_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", repo_name)),
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
        // It's a file, redirect to blob view
        return render_error(&format!("'{}' is a file, not a directory", path));
    }

    // Parse tree entries
    let entries = match repo_handle.parse_tree(&tree_id) {
        Some(e) => e,
        None => return render_error("Could not parse tree"),
    };

    let mut context = Context::new();
    context.insert("repo_name", repo_name);
    context.insert("ref_name", ref_name);
    context.insert("path", path);

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

            // Check if this is an LFS pointer file
            let (is_lfs, lfs_status, lfs_size, lfs_oid) = if !e.is_dir {
                if let Some(content) = repo_handle.get_blob_content(&e.oid) {
                    if let Some(lfs_info) = parse_lfs_pointer(&content) {
                        // Check CAS status
                        let status = state.cas.get_lfs_object_status(&lfs_info.oid);
                        let status_str = status.map(|s| match s {
                            crate::cas::store::LfsObjectStatus::Raw => "raw".to_string(),
                            crate::cas::store::LfsObjectStatus::Processing => "processing".to_string(),
                            crate::cas::store::LfsObjectStatus::Chunked => "chunked".to_string(),
                        });
                        let oid_hex = lfs_info.oid.to_hex();
                        (true, status_str, Some(format_size(lfs_info.size)), Some(oid_hex))
                    } else {
                        (false, None, None, None)
                    }
                } else {
                    (false, None, None, None)
                }
            } else {
                (false, None, None, None)
            };

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

    render_template("tree.html", &context)
}

/// View a file (blob)
async fn blob_view(
    State(state): State<Arc<AppState>>,
    Path((repo, ref_name, path)): Path<(String, String, String)>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");

    let repo_handle = match state.repos.get_repo(repo_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", repo_name)),
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

    // Navigate to file
    let (blob_id, is_dir) = match repo_handle.resolve_path(&root_tree, &path) {
        Some((id, is_dir)) => (id, is_dir),
        None => return render_error(&format!("File '{}' not found", path)),
    };

    if is_dir {
        return render_error(&format!("'{}' is a directory, not a file", path));
    }

    // Get blob content
    let content = match repo_handle.get_blob_content(&blob_id) {
        Some(c) => c,
        None => return render_error("Could not read file content"),
    };

    let mut context = Context::new();
    context.insert("repo_name", repo_name);
    context.insert("ref_name", &ref_name);
    context.insert("path", &path);

    // File name
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
        // Check CAS status
        let status = state.cas.get_lfs_object_status(&lfs_info.oid);
        let status_str = status.map(|s| match s {
            crate::cas::store::LfsObjectStatus::Raw => "raw".to_string(),
            crate::cas::store::LfsObjectStatus::Processing => "processing".to_string(),
            crate::cas::store::LfsObjectStatus::Chunked => "chunked".to_string(),
        });
        let oid_hex = lfs_info.oid.to_hex();
        (true, status_str, Some(format_size(lfs_info.size)), Some(oid_hex), format_size(lfs_info.size))
    } else {
        // Regular file - use content size
        let size = content.len() as u64;
        (false, None, None, None, format_size(size))
    };

    context.insert("is_lfs", &is_lfs);
    context.insert("lfs_status", &lfs_status);
    context.insert("lfs_size", &lfs_size);
    context.insert("lfs_oid", &lfs_oid);
    context.insert("size_display", &actual_size_display);

    // Check if binary (don't show content for LFS pointers either - they're just metadata)
    let is_binary = is_lfs || content.iter().take(8000).any(|&b| b == 0);
    context.insert("is_binary", &is_binary);

    if is_binary {
        context.insert("lines", &Vec::<String>::new());
        context.insert("line_count", &0);
    } else {
        // Convert to string and split into lines
        let text = String::from_utf8_lossy(&content);
        let lines: Vec<String> = text.lines().map(|l| html_escape(l)).collect();
        context.insert("line_count", &lines.len());
        context.insert("lines", &lines);
    }

    render_template("blob.html", &context)
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Parsed LFS pointer info
struct LfsPointerInfo {
    oid: crate::cas::ContentHash,
    size: u64,
}

/// Parse an LFS pointer file
fn parse_lfs_pointer(content: &[u8]) -> Option<LfsPointerInfo> {
    // LFS pointers are small text files
    if content.len() > 1024 {
        return None;
    }

    let text = std::str::from_utf8(content).ok()?;

    // Must start with version line
    if !text.starts_with("version https://git-lfs.github.com/spec/v1") {
        return None;
    }

    let mut oid: Option<crate::cas::ContentHash> = None;
    let mut size: Option<u64> = None;

    for line in text.lines() {
        if let Some(hash) = line.strip_prefix("oid sha256:") {
            oid = crate::cas::ContentHash::from_hex(hash.trim());
        } else if let Some(s) = line.strip_prefix("size ") {
            size = s.trim().parse().ok();
        }
    }

    Some(LfsPointerInfo {
        oid: oid?,
        size: size?,
    })
}

/// Format a file size for display
fn format_size(size: u64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Edit file form
#[derive(serde::Deserialize)]
struct EditForm {
    content: String,
    message: Option<String>,
}

/// Edit a file (GET - show editor)
async fn edit_file(
    State(state): State<Arc<AppState>>,
    Path((repo, ref_name, path)): Path<(String, String, String)>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");

    let repo_handle = match state.repos.get_repo(repo_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", repo_name)),
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

    // Navigate to file
    let (blob_id, is_dir) = match repo_handle.resolve_path(&root_tree, &path) {
        Some((id, is_dir)) => (id, is_dir),
        None => return render_error(&format!("File '{}' not found", path)),
    };

    if is_dir {
        return render_error(&format!("'{}' is a directory, not a file", path));
    }

    // Get blob content
    let content = match repo_handle.get_blob_content(&blob_id) {
        Some(c) => c,
        None => return render_error("Could not read file content"),
    };

    // Check if LFS file - can't edit those
    if parse_lfs_pointer(&content).is_some() {
        return render_error("Cannot edit LFS files in the browser");
    }

    // Check if binary
    if content.iter().take(8000).any(|&b| b == 0) {
        return render_error("Cannot edit binary files in the browser");
    }

    let mut context = Context::new();
    context.insert("repo_name", repo_name);
    context.insert("ref_name", &ref_name);
    context.insert("path", &path);

    // File name
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

    // File content as string
    let text = String::from_utf8_lossy(&content).to_string();
    context.insert("content", &text);

    render_template("edit.html", &context)
}

/// Commit file changes (POST)
async fn commit_file(
    State(state): State<Arc<AppState>>,
    Path((repo, ref_name, path)): Path<(String, String, String)>,
    Form(form): Form<EditForm>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");

    let repo_handle = match state.repos.get_repo(repo_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", repo_name)),
    };

    // Resolve ref to commit (this will be the parent)
    let parent_commit_id = match repo_handle.resolve_ref(&format!("refs/heads/{}", ref_name)) {
        Some(id) => id,
        None => return render_error(&format!("Branch '{}' not found", ref_name)),
    };

    // Get the current tree
    let root_tree = match repo_handle.get_commit_tree(&parent_commit_id) {
        Some(t) => t,
        None => return render_error("Could not read commit tree"),
    };

    // Create new blob with the edited content
    let new_content = form.content.as_bytes();
    let new_blob_id = repo_handle.create_object(
        ObjectType::Blob,
        new_content,
    );

    // Build new tree with the updated file
    let new_tree_id = match build_updated_tree(&repo_handle, &root_tree, &path, &new_blob_id) {
        Some(id) => id,
        None => return render_error("Failed to update tree"),
    };

    // Create commit message
    let message = form.message
        .filter(|m| !m.trim().is_empty())
        .unwrap_or_else(|| format!("Update {}", path));

    // Create new commit
    let new_commit_id = repo_handle.create_commit(
        &new_tree_id,
        &[parent_commit_id],
        &message,
        "Web User",
        "web@openxet.local",
    );

    // Update the ref
    let _ = repo_handle.update_ref(&format!("refs/heads/{}", ref_name), new_commit_id);

    // Redirect to the file view
    Redirect::to(&format!("/ui/repos/{}/blob/{}/{}", repo_name, ref_name, path)).into_response()
}

/// Build an updated tree with a file changed at the given path
fn build_updated_tree(
    repo: &Repository,
    current_tree: &ObjectId,
    path: &str,
    new_blob_id: &ObjectId,
) -> Option<ObjectId> {
    let parts: Vec<&str> = path.split('/').collect();
    build_tree_recursive(repo, current_tree, &parts, new_blob_id)
}

fn build_tree_recursive(
    repo: &Repository,
    current_tree: &ObjectId,
    path_parts: &[&str],
    new_blob_id: &ObjectId,
) -> Option<ObjectId> {
    if path_parts.is_empty() {
        return None;
    }

    let entries = repo.parse_tree(current_tree)?;
    let target_name = path_parts[0];
    let is_final = path_parts.len() == 1;

    let mut new_entries: Vec<TreeEntry> = Vec::new();
    let mut found = false;

    for entry in entries {
        if entry.name == target_name {
            found = true;
            if is_final {
                // Replace this blob with the new one
                new_entries.push(TreeEntry {
                    mode: entry.mode,
                    name: entry.name,
                    oid: *new_blob_id,
                    is_dir: false,
                    is_executable: false,
                    is_symlink: false,
                });
            } else {
                // Recurse into subdirectory
                let new_subtree_id = build_tree_recursive(
                    repo,
                    &entry.oid,
                    &path_parts[1..],
                    new_blob_id,
                )?;
                new_entries.push(TreeEntry {
                    mode: entry.mode,
                    name: entry.name,
                    oid: new_subtree_id,
                    is_dir: true,
                    is_executable: false,
                    is_symlink: false,
                });
            }
        } else {
            new_entries.push(entry);
        }
    }

    if !found {
        return None;
    }

    // Serialize the new tree
    let tree_data = serialize_tree(&new_entries);
    let new_tree_id = repo.create_object(ObjectType::Tree, &tree_data);
    Some(new_tree_id)
}

/// Serialize tree entries to git tree format
fn serialize_tree(entries: &[TreeEntry]) -> Vec<u8> {
    let mut data = Vec::new();

    // Sort entries (git requires sorted trees)
    let mut sorted_entries: Vec<_> = entries.iter().collect();
    sorted_entries.sort_by(|a, b| {
        // Directories end with / for sorting purposes
        let a_name = if a.is_dir { format!("{}/", a.name) } else { a.name.clone() };
        let b_name = if b.is_dir { format!("{}/", b.name) } else { b.name.clone() };
        a_name.cmp(&b_name)
    });

    for entry in sorted_entries {
        // Format: mode SP name NUL oid
        data.extend_from_slice(entry.mode.as_bytes());
        data.push(b' ');
        data.extend_from_slice(entry.name.as_bytes());
        data.push(0);
        data.extend_from_slice(entry.oid.as_bytes());
    }

    data
}
