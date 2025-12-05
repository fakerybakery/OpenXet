//! Web UI route handlers.

use axum::{
    extract::{Path, State, Form, Query},
    http::{StatusCode, HeaderMap},
    response::{Html, IntoResponse, Response, Redirect},
    routing::get,
    Router,
};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use crate::db::entities::{discussion, discussion_comment, discussion_event, org_member, user};
use crate::git::{CommitInfo, ObjectId, ObjectType, Repository, TreeEntry};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set};
use super::templates;

/// Create the web UI router with GitHub-like routes
/// Routes: /:owner/:repo, /:owner/:repo/tree/:ref, etc.
pub fn create_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(index))
        // Auth pages
        .route("/-/login", get(login_page).post(login_submit))
        .route("/-/signup", get(signup_page).post(signup_submit))
        .route("/-/logout", get(logout))
        // Repo management
        .route("/-/new", get(new_repo_page).post(create_repo))
        // Org management
        .route("/-/new-org", get(new_org_page).post(create_org))
        // Stats page
        .route("/-/stats", get(stats))
        // Search
        .route("/-/search", get(search))
        // User/org profile page (must come before /:owner/:repo)
        .route("/:owner", get(user_profile))
        .route("/:owner/members", axum::routing::post(add_org_member))
        .route("/:owner/members/:username/remove", axum::routing::post(remove_org_member))
        // Repository routes (owner/repo format)
        .route("/:owner/:repo", get(repo_detail))
        .route("/:owner/:repo/tree/:ref", get(tree_root))
        .route("/:owner/:repo/tree/:ref/*path", get(tree_path))
        .route("/:owner/:repo/blob/:ref/*path", get(blob_view))
        .route("/:owner/:repo/edit/:ref/*path", get(edit_file).post(commit_file))
        .route("/:owner/:repo/new/:ref", get(new_file).post(commit_new_file))
        .route("/:owner/:repo/new/:ref/*path", get(new_file_in_dir).post(commit_new_file_in_dir))
        // Commit history and viewing
        .route("/:owner/:repo/commits/:ref", get(commits_list))
        .route("/:owner/:repo/commit/:sha", get(commit_view))
        // Community discussions
        .route("/:owner/:repo/discussions", get(discussions_list))
        .route("/:owner/:repo/discussions/new", get(new_discussion_page).post(create_discussion))
        .route("/:owner/:repo/discussions/:id", get(discussion_detail).post(post_comment))
        .route("/:owner/:repo/discussions/:id/close", axum::routing::post(close_discussion))
        .route("/:owner/:repo/discussions/:id/reopen", axum::routing::post(reopen_discussion))
}

/// Home page
async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let mut context = Context::new();

    let repos: Vec<String> = state.repos.list_repos();
    let cas_stats = state.cas.stats();
    let lfs_stats = state.cas.lfs_stats();

    context.insert("repos", &repos);
    context.insert("repo_count", &repos.len());
    context.insert("block_count", &cas_stats.block_count);
    context.insert("chunk_count", &cas_stats.chunk_count);

    // LFS storage stats for savings display
    context.insert("lfs_object_count", &lfs_stats.object_count);
    context.insert("total_uploaded", &format_size(lfs_stats.total_logical_size));
    context.insert("total_stored", &format_size(lfs_stats.total_physical_size));
    context.insert("total_uploaded_bytes", &lfs_stats.total_logical_size);
    context.insert("total_stored_bytes", &lfs_stats.total_physical_size);

    // Calculate savings
    let savings_bytes = lfs_stats.total_logical_size.saturating_sub(lfs_stats.total_physical_size);
    let savings_percent = if lfs_stats.total_logical_size > 0 {
        (savings_bytes as f64 / lfs_stats.total_logical_size as f64) * 100.0
    } else {
        0.0
    };
    context.insert("savings", &format_size(savings_bytes));
    context.insert("savings_percent", &format!("{:.1}", savings_percent));
    context.insert("dedup_ratio", &format!("{:.2}x", lfs_stats.dedup_ratio));

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("index.html", &context)
}

/// Member info for templates
#[derive(serde::Serialize)]
struct MemberInfo {
    username: String,
    role: String,
}

/// Org info for templates
#[derive(serde::Serialize)]
struct OrgInfo {
    name: String,
    role: String,
}

/// User/org profile page - shows repos, and for orgs shows members, for users shows orgs
async fn user_profile(
    State(state): State<Arc<AppState>>,
    Path(owner): Path<String>,
    headers: HeaderMap,
) -> Response {
    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Try to find user/org in database
    let owner_user = user::Entity::find()
        .filter(user::Column::Username.eq(&owner))
        .one(db.as_ref())
        .await
        .ok()
        .flatten();

    // Get all repos owned by this user/org
    let all_repos = state.repos.list_repos();
    let user_repos: Vec<String> = all_repos
        .iter()
        .filter(|r| r.starts_with(&format!("{}/", owner)))
        .cloned()
        .collect();

    // If no user in DB and no repos, show 404
    if owner_user.is_none() && user_repos.is_empty() {
        return render_error(&format!("'{}' not found", owner));
    }

    let is_org = owner_user.as_ref().map(|u| u.is_org).unwrap_or(false);
    let current_user = get_current_user(&state, &headers).await;

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repos", &user_repos);
    context.insert("repo_count", &user_repos.len());
    context.insert("is_org", &is_org);

    if is_org {
        // Org page: show members
        let owner_id = owner_user.as_ref().map(|u| u.id).unwrap_or(0);

        let members = org_member::Entity::find()
            .filter(org_member::Column::OrgId.eq(owner_id))
            .all(db.as_ref())
            .await
            .unwrap_or_default();

        let mut member_infos = Vec::new();
        for member in &members {
            if let Ok(Some(u)) = user::Entity::find_by_id(member.user_id).one(db.as_ref()).await {
                member_infos.push(MemberInfo {
                    username: u.username,
                    role: member.role.clone(),
                });
            }
        }

        context.insert("members", &member_infos);
        context.insert("member_count", &member_infos.len());

        // Check if current user is org owner (can manage members)
        let is_org_owner = if let Some(ref cu) = current_user {
            member_infos.iter().any(|m| m.username == *cu && m.role == "owner")
        } else {
            false
        };
        context.insert("is_org_owner", &is_org_owner);
    } else {
        // User page: show orgs they belong to
        if let Some(ref owner_user) = owner_user {
            let memberships = org_member::Entity::find()
                .filter(org_member::Column::UserId.eq(owner_user.id))
                .all(db.as_ref())
                .await
                .unwrap_or_default();

            let mut org_infos = Vec::new();
            for membership in memberships {
                if let Ok(Some(org)) = user::Entity::find_by_id(membership.org_id).one(db.as_ref()).await {
                    if org.is_org {
                        org_infos.push(OrgInfo {
                            name: org.username,
                            role: membership.role,
                        });
                    }
                }
            }

            context.insert("orgs", &org_infos);
            context.insert("org_count", &org_infos.len());
        }
    }

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("user.html", &context)
}

/// Query params for repo page
#[derive(serde::Deserialize, Default)]
struct RepoQuery {
    tab: Option<String>,
    branch: Option<String>,
}

/// Repository detail page with tabs
async fn repo_detail(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<RepoQuery>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Check if repo exists
    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => {
            return render_error(&format!("Repository '{}' not found", full_name));
        }
    };

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);

    // Get branches
    let git_refs = repo_handle.list_refs();
    let branches: Vec<BranchInfo> = git_refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/"))
        .map(|r| {
            let short_name = r.name.strip_prefix("refs/heads/").unwrap_or(&r.name);
            BranchInfo {
                name: short_name.to_string(),
            }
        })
        .collect();

    // Determine current branch: query param > "main" > first branch
    let current_branch = query.branch
        .or_else(|| branches.iter().find(|b| b.name == "main").map(|b| b.name.clone()))
        .or_else(|| branches.first().map(|b| b.name.clone()))
        .unwrap_or_else(|| "main".to_string());

    let active_tab = query.tab.unwrap_or_else(|| "overview".to_string());

    context.insert("branches", &branches);
    context.insert("current_branch", &current_branch);
    context.insert("active_tab", &active_tab);

    // Get commit and tree for current branch
    let commit_id = repo_handle.resolve_ref(&format!("refs/heads/{}", current_branch));

    if let Some(commit_id) = commit_id {
        if let Some(root_tree) = repo_handle.get_commit_tree(&commit_id) {
            // For overview tab: try to find and render README
            if active_tab == "overview" {
                if let Some(readme_html) = find_and_render_readme(&repo_handle, &root_tree) {
                    context.insert("readme_html", &readme_html);
                }
            }

            // For files tab: get root tree entries
            if active_tab == "files" {
                if let Some(entries) = repo_handle.parse_tree(&root_tree) {
                    let entry_infos: Vec<TreeEntryInfo> = entries
                        .iter()
                        .map(|e| {
                            let (is_lfs, lfs_status, lfs_size, lfs_oid) = check_lfs_file(&repo_handle, &state, e);
                            TreeEntryInfo {
                                name: e.name.clone(),
                                full_path: e.name.clone(),
                                is_dir: e.is_dir,
                                is_lfs,
                                lfs_status,
                                lfs_size,
                                lfs_oid,
                            }
                        })
                        .collect();
                    context.insert("entries", &entry_infos);
                }
            }
        }
    }

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("repo.html", &context)
}

/// Branch info for templates
#[derive(serde::Serialize)]
struct BranchInfo {
    name: String,
}

/// Find README file and render as HTML
fn find_and_render_readme(repo: &Repository, tree_id: &ObjectId) -> Option<String> {
    let entries = repo.parse_tree(tree_id)?;

    // Look for README variants (case-insensitive)
    let readme_names = ["README.md", "readme.md", "README", "readme", "README.txt", "readme.txt"];

    for readme_name in readme_names {
        if let Some(entry) = entries.iter().find(|e| e.name.eq_ignore_ascii_case(readme_name) && !e.is_dir) {
            if let Some(content) = repo.get_blob_content(&entry.oid) {
                // Check it's not binary
                if content.iter().take(8000).any(|&b| b == 0) {
                    return None;
                }

                let text = String::from_utf8_lossy(&content);

                // If it's a .md file, render as markdown
                if entry.name.to_lowercase().ends_with(".md") {
                    return Some(templates::render_markdown(&text));
                } else {
                    // Plain text - wrap in <pre>
                    return Some(format!("<pre>{}</pre>", ammonia::clean(&text)));
                }
            }
        }
    }

    None
}

/// Check if a tree entry is an LFS file and get its status
fn check_lfs_file(
    repo: &Repository,
    state: &Arc<AppState>,
    entry: &crate::git::TreeEntry,
) -> (bool, Option<String>, Option<String>, Option<String>) {
    if entry.is_dir {
        return (false, None, None, None);
    }

    if let Some(content) = repo.get_blob_content(&entry.oid) {
        if let Some(lfs_info) = parse_lfs_pointer(&content) {
            let status = state.cas.get_lfs_object_status(&lfs_info.oid);
            let status_str = status.map(|s| match s {
                crate::cas::store::LfsObjectStatus::Raw => "raw".to_string(),
                crate::cas::store::LfsObjectStatus::Processing => "processing".to_string(),
                crate::cas::store::LfsObjectStatus::Chunked => "chunked".to_string(),
            });
            let oid_hex = lfs_info.oid.to_hex();
            return (true, status_str, Some(format_size(lfs_info.size)), Some(oid_hex));
        }
    }

    (false, None, None, None)
}

/// Stats page
async fn stats(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("index.html", &context)
}

/// Search query params
#[derive(serde::Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

/// Search result item
#[derive(serde::Serialize)]
struct SearchResult {
    name: String,
    description: Option<String>,
}

/// Search response for JSON API
#[derive(serde::Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
    query: String,
}

/// Search page and API
async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Response {
    let raw_query = query.q.unwrap_or_default();
    let q = raw_query.trim().to_lowercase();

    // Get all repos and filter by query
    let repos: Vec<String> = state.repos.list_repos();

    let results: Vec<SearchResult> = if q.is_empty() {
        repos.iter().take(20).map(|name| SearchResult {
            name: name.clone(),
            description: None,
        }).collect()
    } else {
        repos.iter()
            .filter(|name| name.to_lowercase().contains(&q))
            .take(20)
            .map(|name| SearchResult {
                name: name.clone(),
                description: None,
            })
            .collect()
    };

    // Check if this is a JSON request (from the dropdown)
    let accept = headers.get("accept").and_then(|h| h.to_str().ok()).unwrap_or("");
    if accept.contains("application/json") || headers.get("x-requested-with").is_some() {
        let response = SearchResponse {
            results,
            query: q,
        };
        return axum::Json(response).into_response();
    }

    // For full page request, render search results page
    let mut context = Context::new();
    context.insert("query", &raw_query);
    context.insert("results", &results);
    context.insert("result_count", &results.len());
    add_user_to_context(&mut context, &state, &headers).await;

    render_template("search.html", &context)
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

/// Extract current username from cookie token
async fn get_current_user(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("token=") {
            // Validate token and get username
            if let Some(username) = state.auth.get_username_for_token(token).await {
                return Some(username);
            }
        }
    }
    None
}

/// Add current user to context if logged in
async fn add_user_to_context(context: &mut Context, state: &AppState, headers: &HeaderMap) {
    if let Some(username) = get_current_user(state, headers).await {
        context.insert("current_user", &username);
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
    Path((owner, repo, ref_name)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    tree_view_impl(state, &owner, &repo, &ref_name, "", headers).await
}

/// View tree at a specific path
async fn tree_path(
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
        // It's a file, redirect to blob view
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
    context.insert("active_tab", "files");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("tree.html", &context)
}

/// View a file (blob)
async fn blob_view(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, path)): Path<(String, String, String, String)>,
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
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
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

    // Check if binary (don't show content for LFS pointers either - they're just metadata)
    let is_binary = is_lfs || content.iter().take(8000).any(|&b| b == 0);
    context.insert("is_binary", &is_binary);

    if is_binary {
        context.insert("content", &String::new());
        context.insert("line_count", &0);
    } else {
        // Convert to string
        let text = String::from_utf8_lossy(&content);
        let line_count = text.lines().count();
        context.insert("line_count", &line_count);
        context.insert("content", &text);
    }

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("blob.html", &context)
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
    filename: String,
    message: Option<String>,
}

/// Edit a file (GET - show editor)
async fn edit_file(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, path)): Path<(String, String, String, String)>,
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
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
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
    context.insert("is_new", &false);
    context.insert("active_tab", "files");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("edit.html", &context)
}

/// New file (GET - show editor for new file) - root level
async fn new_file(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    render_new_file_form(&state, &headers, &owner, &repo, &ref_name, "").await
}

/// New file (GET - show editor for new file) - in directory
async fn new_file_in_dir(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, dir_path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Response {
    render_new_file_form(&state, &headers, &owner, &repo, &ref_name, &dir_path).await
}

async fn render_new_file_form(state: &AppState, headers: &HeaderMap, owner: &str, repo: &str, ref_name: &str, dir_path: &str) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let mut context = Context::new();
    context.insert("owner", owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("ref_name", ref_name);
    context.insert("is_new", &true);
    context.insert("content", &"");

    // Set initial path based on directory
    let initial_path = if dir_path.is_empty() {
        String::new()
    } else {
        format!("{}/", dir_path)
    };
    context.insert("path", &initial_path);
    context.insert("file_name", &"");

    // Empty breadcrumbs for new file
    let breadcrumbs: Vec<Breadcrumb> = Vec::new();
    context.insert("breadcrumbs", &breadcrumbs);
    context.insert("active_tab", "files");

    add_user_to_context(&mut context, state, headers).await;

    render_template("edit.html", &context)
}

/// Commit file changes (POST)
async fn commit_file(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, path)): Path<(String, String, String, String)>,
    Form(form): Form<EditForm>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
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

    // Normalize filename (trim slashes)
    let new_path = form.filename.trim().trim_matches('/').to_string();
    if new_path.is_empty() {
        return render_error("Filename cannot be empty");
    }

    // Check if this is a rename/move
    let old_path = path.trim_matches('/');
    let is_rename = !old_path.is_empty() && old_path != new_path;
    let is_new = old_path.is_empty();

    // Create new blob with the edited content
    let new_content = form.content.as_bytes();
    let new_blob_id = repo_handle.create_object(
        ObjectType::Blob,
        new_content,
    );

    // Build new tree
    let new_tree_id = if is_rename {
        // First delete old path, then add new path
        let tree_after_delete = match build_tree_with_deletion(&repo_handle, &root_tree, old_path) {
            Some(id) => id,
            None => return render_error("Failed to delete old file"),
        };
        match build_tree_with_addition(&repo_handle, &tree_after_delete, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to create file at new path"),
        }
    } else if is_new {
        // Just add the new file
        match build_tree_with_addition(&repo_handle, &root_tree, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to create file"),
        }
    } else {
        // Simple update
        match build_updated_tree(&repo_handle, &root_tree, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to update tree"),
        }
    };

    // Create commit message
    let default_message = if is_new {
        format!("Create {}", new_path)
    } else if is_rename {
        format!("Rename {} to {}", old_path, new_path)
    } else {
        format!("Update {}", new_path)
    };
    let message = form.message
        .filter(|m| !m.trim().is_empty())
        .unwrap_or(default_message);

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
    Redirect::to(&format!("/{}/{}/blob/{}/{}", owner, repo_name, ref_name, new_path)).into_response()
}

/// Commit new file (POST) - root level
async fn commit_new_file(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name)): Path<(String, String, String)>,
    Form(form): Form<EditForm>,
) -> Response {
    commit_file_impl(state, &owner, &repo, &ref_name, "", form).await
}

/// Commit new file (POST) - in directory
async fn commit_new_file_in_dir(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, _dir)): Path<(String, String, String, String)>,
    Form(form): Form<EditForm>,
) -> Response {
    // The dir in path is just for context; actual path comes from form.filename
    commit_file_impl(state, &owner, &repo, &ref_name, "", form).await
}

/// Shared implementation for committing files (edit, rename, new)
async fn commit_file_impl(
    state: Arc<AppState>,
    owner: &str,
    repo: &str,
    ref_name: &str,
    original_path: &str,
    form: EditForm,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
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

    // Normalize filename (trim slashes)
    let new_path = form.filename.trim().trim_matches('/').to_string();
    if new_path.is_empty() {
        return render_error("Filename cannot be empty");
    }

    // Check if this is a rename/move
    let old_path = original_path.trim_matches('/');
    let is_rename = !old_path.is_empty() && old_path != new_path;
    let is_new = old_path.is_empty();

    // Create new blob with the edited content
    let new_content = form.content.as_bytes();
    let new_blob_id = repo_handle.create_object(
        ObjectType::Blob,
        new_content,
    );

    // Build new tree
    let new_tree_id = if is_rename {
        // First delete old path, then add new path
        let tree_after_delete = match build_tree_with_deletion(&repo_handle, &root_tree, old_path) {
            Some(id) => id,
            None => return render_error("Failed to delete old file"),
        };
        match build_tree_with_addition(&repo_handle, &tree_after_delete, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to create file at new path"),
        }
    } else if is_new {
        // Just add the new file
        match build_tree_with_addition(&repo_handle, &root_tree, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to create file"),
        }
    } else {
        // Simple update
        match build_updated_tree(&repo_handle, &root_tree, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to update tree"),
        }
    };

    // Create commit message
    let default_message = if is_new {
        format!("Create {}", new_path)
    } else if is_rename {
        format!("Rename {} to {}", old_path, new_path)
    } else {
        format!("Update {}", new_path)
    };
    let message = form.message
        .filter(|m| !m.trim().is_empty())
        .unwrap_or(default_message);

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
    Redirect::to(&format!("/{}/{}/blob/{}/{}", owner, repo_name, ref_name, new_path)).into_response()
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

/// Build a tree with a new file added at the given path
fn build_tree_with_addition(
    repo: &Repository,
    current_tree: &ObjectId,
    path: &str,
    new_blob_id: &ObjectId,
) -> Option<ObjectId> {
    let parts: Vec<&str> = path.split('/').collect();
    add_to_tree_recursive(repo, Some(current_tree), &parts, new_blob_id)
}

fn add_to_tree_recursive(
    repo: &Repository,
    current_tree: Option<&ObjectId>,
    path_parts: &[&str],
    new_blob_id: &ObjectId,
) -> Option<ObjectId> {
    if path_parts.is_empty() {
        return None;
    }

    let mut entries: Vec<TreeEntry> = current_tree
        .and_then(|t| repo.parse_tree(t))
        .unwrap_or_default();

    let target_name = path_parts[0];
    let is_final = path_parts.len() == 1;

    if is_final {
        // Add or replace the file
        entries.retain(|e| e.name != target_name);
        entries.push(TreeEntry {
            mode: "100644".to_string(),
            name: target_name.to_string(),
            oid: *new_blob_id,
            is_dir: false,
            is_executable: false,
            is_symlink: false,
        });
    } else {
        // Find or create subdirectory
        let existing_subtree = entries.iter().find(|e| e.name == target_name && e.is_dir);
        let subtree_oid = existing_subtree.map(|e| e.oid);

        let new_subtree_id = add_to_tree_recursive(
            repo,
            subtree_oid.as_ref(),
            &path_parts[1..],
            new_blob_id,
        )?;

        entries.retain(|e| e.name != target_name);
        entries.push(TreeEntry {
            mode: "40000".to_string(),
            name: target_name.to_string(),
            oid: new_subtree_id,
            is_dir: true,
            is_executable: false,
            is_symlink: false,
        });
    }

    let tree_data = serialize_tree(&entries);
    Some(repo.create_object(ObjectType::Tree, &tree_data))
}

/// Build a tree with a file deleted at the given path
fn build_tree_with_deletion(
    repo: &Repository,
    current_tree: &ObjectId,
    path: &str,
) -> Option<ObjectId> {
    let parts: Vec<&str> = path.split('/').collect();
    delete_from_tree_recursive(repo, current_tree, &parts)
}

fn delete_from_tree_recursive(
    repo: &Repository,
    current_tree: &ObjectId,
    path_parts: &[&str],
) -> Option<ObjectId> {
    if path_parts.is_empty() {
        return None;
    }

    let entries = repo.parse_tree(current_tree)?;
    let target_name = path_parts[0];
    let is_final = path_parts.len() == 1;

    let mut new_entries: Vec<TreeEntry> = Vec::new();

    for entry in entries {
        if entry.name == target_name {
            if is_final {
                // Skip this entry (delete it)
                continue;
            } else {
                // Recurse into subdirectory
                let new_subtree_id = delete_from_tree_recursive(
                    repo,
                    &entry.oid,
                    &path_parts[1..],
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

    let tree_data = serialize_tree(&new_entries);
    Some(repo.create_object(ObjectType::Tree, &tree_data))
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

// ============================================================================
// Commit History Handlers
// ============================================================================

/// Query params for commits list
#[derive(serde::Deserialize, Default)]
struct CommitsQuery {
    page: Option<usize>,
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

/// Format seconds ago as human-readable string
fn format_time_ago(seconds: i64) -> String {
    if seconds < 0 {
        return "in the future".to_string();
    }
    if seconds < 60 {
        return format!("{} seconds ago", seconds);
    }
    let minutes = seconds / 60;
    if minutes < 60 {
        return format!("{} minute{} ago", minutes, if minutes == 1 { "" } else { "s" });
    }
    let hours = minutes / 60;
    if hours < 24 {
        return format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" });
    }
    let days = hours / 24;
    if days < 30 {
        return format!("{} day{} ago", days, if days == 1 { "" } else { "s" });
    }
    let months = days / 30;
    if months < 12 {
        return format!("{} month{} ago", months, if months == 1 { "" } else { "s" });
    }
    let years = months / 12;
    format!("{} year{} ago", years, if years == 1 { "" } else { "s" })
}

/// Format a Unix timestamp as a relative time string
fn format_relative_time(timestamp: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_time_ago(now - timestamp)
}

/// List commits for a branch
async fn commits_list(
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

    // Resolve ref to commit
    let commit_id = match repo_handle.resolve_ref(&format!("refs/heads/{}", ref_name)) {
        Some(id) => id,
        None => return render_error(&format!("Branch '{}' not found", ref_name)),
    };

    // Pagination: 30 commits per page
    let per_page = 30;
    let page = query.page.unwrap_or(1).max(1);
    let skip = (page - 1) * per_page;

    // Walk commits - get one extra to check if there's a next page
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

    // Get branches for dropdown
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

/// File change info for commit view
#[derive(serde::Serialize)]
struct FileChange {
    path: String,
    status: String, // "added", "modified", "deleted"
    additions: usize,
    deletions: usize,
    diff_lines: Vec<DiffLine>,
    is_binary: bool,
}

/// A single line in a diff
#[derive(serde::Serialize)]
struct DiffLine {
    line_type: String, // "add", "del", "context", "header"
    content: String,
    old_line: Option<usize>,
    new_line: Option<usize>,
}

/// View a single commit with diff
async fn commit_view(
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

    // Parse commit SHA
    let commit_id = match ObjectId::from_hex(&sha) {
        Some(id) => id,
        None => return render_error(&format!("Invalid commit SHA: {}", sha)),
    };

    // Get commit info
    let commit_info = match repo_handle.get_commit_info(&commit_id) {
        Some(info) => info,
        None => return render_error(&format!("Commit '{}' not found", sha)),
    };

    // Get the parent tree (if any) for diff
    let parent_tree = if !commit_info.parent_ids.is_empty() {
        repo_handle.get_commit_tree(&commit_info.parent_ids[0])
    } else {
        None
    };

    // Compute diff between parent and this commit's tree
    let file_changes = compute_diff(&repo_handle, parent_tree.as_ref(), &commit_info.tree_id);

    let commit_view: CommitInfoView = (&commit_info).into();

    // Get branches for navigation
    let git_refs = repo_handle.list_refs();
    let branches: Vec<BranchInfo> = git_refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/"))
        .map(|r| BranchInfo {
            name: r.name.strip_prefix("refs/heads/").unwrap_or(&r.name).to_string(),
        })
        .collect();

    // Use first branch as default ref_name for navigation
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

/// Compute diff between two trees
fn compute_diff(
    repo: &Repository,
    old_tree: Option<&ObjectId>,
    new_tree: &ObjectId,
) -> Vec<FileChange> {
    let mut changes = Vec::new();

    // Collect entries from both trees
    let old_entries = old_tree
        .and_then(|t| repo.parse_tree(t))
        .unwrap_or_default();
    let new_entries = repo.parse_tree(new_tree).unwrap_or_default();

    // Build maps for lookup
    let old_map: std::collections::HashMap<&str, &TreeEntry> =
        old_entries.iter().map(|e| (e.name.as_str(), e)).collect();
    let new_map: std::collections::HashMap<&str, &TreeEntry> =
        new_entries.iter().map(|e| (e.name.as_str(), e)).collect();

    // Find added and modified files
    for new_entry in &new_entries {
        if new_entry.is_dir {
            // Recursively diff directories
            let old_subdir = old_map.get(new_entry.name.as_str())
                .filter(|e| e.is_dir)
                .map(|e| e.oid);
            let sub_changes = compute_diff_recursive(
                repo,
                old_subdir.as_ref(),
                &new_entry.oid,
                &new_entry.name,
            );
            changes.extend(sub_changes);
        } else {
            match old_map.get(new_entry.name.as_str()) {
                Some(old_entry) if old_entry.oid == new_entry.oid => {
                    // Unchanged
                }
                Some(old_entry) => {
                    // Modified
                    let diff = compute_file_diff(repo, &old_entry.oid, &new_entry.oid, &new_entry.name);
                    changes.push(diff);
                }
                None => {
                    // Added
                    let diff = compute_file_diff(repo, &ObjectId::from_raw([0; 20]), &new_entry.oid, &new_entry.name);
                    changes.push(diff);
                }
            }
        }
    }

    // Find deleted files
    for old_entry in &old_entries {
        if !new_map.contains_key(old_entry.name.as_str()) {
            if old_entry.is_dir {
                // Recursively mark deleted
                let sub_changes = compute_diff_recursive(
                    repo,
                    Some(&old_entry.oid),
                    &ObjectId::from_raw([0; 20]),
                    &old_entry.name,
                );
                changes.extend(sub_changes);
            } else {
                let diff = compute_file_diff(repo, &old_entry.oid, &ObjectId::from_raw([0; 20]), &old_entry.name);
                changes.push(diff);
            }
        }
    }

    changes
}

/// Recursively compute diff for subdirectories
fn compute_diff_recursive(
    repo: &Repository,
    old_tree: Option<&ObjectId>,
    new_tree: &ObjectId,
    prefix: &str,
) -> Vec<FileChange> {
    let mut changes = Vec::new();

    let is_empty_tree = new_tree.as_bytes() == &[0; 20];

    let old_entries = old_tree
        .and_then(|t| repo.parse_tree(t))
        .unwrap_or_default();
    let new_entries = if is_empty_tree {
        vec![]
    } else {
        repo.parse_tree(new_tree).unwrap_or_default()
    };

    let old_map: std::collections::HashMap<&str, &TreeEntry> =
        old_entries.iter().map(|e| (e.name.as_str(), e)).collect();
    let new_map: std::collections::HashMap<&str, &TreeEntry> =
        new_entries.iter().map(|e| (e.name.as_str(), e)).collect();

    for new_entry in &new_entries {
        let full_path = format!("{}/{}", prefix, new_entry.name);
        if new_entry.is_dir {
            let old_subdir = old_map.get(new_entry.name.as_str())
                .filter(|e| e.is_dir)
                .map(|e| e.oid);
            let sub_changes = compute_diff_recursive(repo, old_subdir.as_ref(), &new_entry.oid, &full_path);
            changes.extend(sub_changes);
        } else {
            match old_map.get(new_entry.name.as_str()) {
                Some(old_entry) if old_entry.oid == new_entry.oid => {}
                Some(old_entry) => {
                    let diff = compute_file_diff(repo, &old_entry.oid, &new_entry.oid, &full_path);
                    changes.push(diff);
                }
                None => {
                    let diff = compute_file_diff(repo, &ObjectId::from_raw([0; 20]), &new_entry.oid, &full_path);
                    changes.push(diff);
                }
            }
        }
    }

    for old_entry in &old_entries {
        if !new_map.contains_key(old_entry.name.as_str()) {
            let full_path = format!("{}/{}", prefix, old_entry.name);
            if old_entry.is_dir {
                let sub_changes = compute_diff_recursive(repo, Some(&old_entry.oid), &ObjectId::from_raw([0; 20]), &full_path);
                changes.extend(sub_changes);
            } else {
                let diff = compute_file_diff(repo, &old_entry.oid, &ObjectId::from_raw([0; 20]), &full_path);
                changes.push(diff);
            }
        }
    }

    changes
}

/// Compute diff for a single file
fn compute_file_diff(
    repo: &Repository,
    old_id: &ObjectId,
    new_id: &ObjectId,
    path: &str,
) -> FileChange {
    let is_empty = |id: &ObjectId| id.as_bytes() == &[0; 20];

    let old_content = if is_empty(old_id) {
        None
    } else {
        repo.get_blob_content(old_id)
    };

    let new_content = if is_empty(new_id) {
        None
    } else {
        repo.get_blob_content(new_id)
    };

    // Check for binary content
    let is_binary = old_content.as_ref().map(|c| c.iter().take(8000).any(|&b| b == 0)).unwrap_or(false)
        || new_content.as_ref().map(|c| c.iter().take(8000).any(|&b| b == 0)).unwrap_or(false);

    if is_binary {
        let status = match (&old_content, &new_content) {
            (None, Some(_)) => "added",
            (Some(_), None) => "deleted",
            _ => "modified",
        };
        return FileChange {
            path: path.to_string(),
            status: status.to_string(),
            additions: 0,
            deletions: 0,
            diff_lines: vec![DiffLine {
                line_type: "header".to_string(),
                content: "Binary file changed".to_string(),
                old_line: None,
                new_line: None,
            }],
            is_binary: true,
        };
    }

    let old_text = old_content
        .as_ref()
        .map(|c| String::from_utf8_lossy(c).to_string())
        .unwrap_or_default();
    let new_text = new_content
        .as_ref()
        .map(|c| String::from_utf8_lossy(c).to_string())
        .unwrap_or_default();

    let status = match (&old_content, &new_content) {
        (None, Some(_)) => "added",
        (Some(_), None) => "deleted",
        _ => "modified",
    };

    // Generate simple line-by-line diff
    let (diff_lines, additions, deletions) = generate_diff(&old_text, &new_text);

    FileChange {
        path: path.to_string(),
        status: status.to_string(),
        additions,
        deletions,
        diff_lines,
        is_binary: false,
    }
}

/// Generate a simple line-by-line diff
fn generate_diff(old: &str, new: &str) -> (Vec<DiffLine>, usize, usize) {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    // Use a simple LCS-based diff
    let mut diff_lines = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;

    // Simple diff: for small files, just show what changed
    // For production, you'd use a proper diff algorithm like Myers or patience
    if old_lines.is_empty() {
        // All additions
        for (i, line) in new_lines.iter().enumerate() {
            diff_lines.push(DiffLine {
                line_type: "add".to_string(),
                content: ammonia::clean(line),
                old_line: None,
                new_line: Some(i + 1),
            });
            additions += 1;
        }
    } else if new_lines.is_empty() {
        // All deletions
        for (i, line) in old_lines.iter().enumerate() {
            diff_lines.push(DiffLine {
                line_type: "del".to_string(),
                content: ammonia::clean(line),
                old_line: Some(i + 1),
                new_line: None,
            });
            deletions += 1;
        }
    } else {
        // Use simple line comparison with LCS
        let lcs = compute_lcs(&old_lines, &new_lines);
        let (lines, adds, dels) = build_diff_from_lcs(&old_lines, &new_lines, &lcs);
        diff_lines = lines;
        additions = adds;
        deletions = dels;
    }

    (diff_lines, additions, deletions)
}

/// Compute LCS (Longest Common Subsequence) indices
fn compute_lcs<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<(usize, usize)> {
    let m = old.len();
    let n = new.len();

    // Build LCS length table
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if old[i - 1] == new[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    // Backtrack to find LCS
    let mut result = Vec::new();
    let mut i = m;
    let mut j = n;
    while i > 0 && j > 0 {
        if old[i - 1] == new[j - 1] {
            result.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] > dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    result.reverse();
    result
}

/// Build diff lines from LCS
fn build_diff_from_lcs(old: &[&str], new: &[&str], lcs: &[(usize, usize)]) -> (Vec<DiffLine>, usize, usize) {
    let mut lines = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;

    let mut old_idx = 0;
    let mut new_idx = 0;
    let mut lcs_idx = 0;

    while old_idx < old.len() || new_idx < new.len() {
        if lcs_idx < lcs.len() {
            let (lcs_old, lcs_new) = lcs[lcs_idx];

            // Output deletions before this LCS element
            while old_idx < lcs_old {
                lines.push(DiffLine {
                    line_type: "del".to_string(),
                    content: ammonia::clean(old[old_idx]),
                    old_line: Some(old_idx + 1),
                    new_line: None,
                });
                deletions += 1;
                old_idx += 1;
            }

            // Output additions before this LCS element
            while new_idx < lcs_new {
                lines.push(DiffLine {
                    line_type: "add".to_string(),
                    content: ammonia::clean(new[new_idx]),
                    old_line: None,
                    new_line: Some(new_idx + 1),
                });
                additions += 1;
                new_idx += 1;
            }

            // Output the common line
            lines.push(DiffLine {
                line_type: "context".to_string(),
                content: ammonia::clean(old[old_idx]),
                old_line: Some(old_idx + 1),
                new_line: Some(new_idx + 1),
            });
            old_idx += 1;
            new_idx += 1;
            lcs_idx += 1;
        } else {
            // No more LCS elements, output remaining
            while old_idx < old.len() {
                lines.push(DiffLine {
                    line_type: "del".to_string(),
                    content: ammonia::clean(old[old_idx]),
                    old_line: Some(old_idx + 1),
                    new_line: None,
                });
                deletions += 1;
                old_idx += 1;
            }
            while new_idx < new.len() {
                lines.push(DiffLine {
                    line_type: "add".to_string(),
                    content: ammonia::clean(new[new_idx]),
                    old_line: None,
                    new_line: Some(new_idx + 1),
                });
                additions += 1;
                new_idx += 1;
            }
        }
    }

    (lines, additions, deletions)
}

// ============================================================================
// Authentication Web UI Handlers
// ============================================================================

/// Login form data
#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

/// Signup form data
#[derive(serde::Deserialize)]
struct SignupForm {
    username: String,
    password: String,
    email: Option<String>,
}

/// Login page (GET)
async fn login_page(Query(query): Query<std::collections::HashMap<String, String>>) -> Response {
    let mut context = Context::new();
    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }
    if let Some(msg) = query.get("message") {
        context.insert("message", msg);
    }
    render_template("login.html", &context)
}

/// Login submit (POST)
async fn login_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    match state.auth.authenticate(&form.username, &form.password).await {
        Ok(token) => {
            // Set cookie and redirect to home
            // For simplicity, we'll redirect with the token in a cookie
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("Location", "/")
                .header("Set-Cookie", format!("token={}; Path=/; HttpOnly; SameSite=Lax", token.token))
                .body(axum::body::Body::empty())
                .unwrap()
        }
        Err(_) => {
            Redirect::to("/-/login?error=Invalid+username+or+password").into_response()
        }
    }
}

/// Signup page (GET)
async fn signup_page(Query(query): Query<std::collections::HashMap<String, String>>) -> Response {
    let mut context = Context::new();
    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }
    render_template("signup.html", &context)
}

/// Signup submit (POST)
async fn signup_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<SignupForm>,
) -> Response {
    // Validate
    if form.username.len() < 2 {
        return Redirect::to("/-/signup?error=Username+must+be+at+least+2+characters").into_response();
    }
    if form.password.len() < 4 {
        return Redirect::to("/-/signup?error=Password+must+be+at+least+4+characters").into_response();
    }
    // Only allow alphanumeric and dashes in username
    if !form.username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Redirect::to("/-/signup?error=Username+can+only+contain+letters,+numbers,+dashes,+and+underscores").into_response();
    }

    match state.auth.register_user(&form.username, &form.password, form.email.as_deref()).await {
        Ok(_) => {
            // Redirect to login with success message
            Redirect::to("/-/login?message=Account+created!+Please+log+in.").into_response()
        }
        Err(e) => {
            let error_msg = e.to_string().replace(' ', "+");
            Redirect::to(&format!("/-/signup?error={}", error_msg)).into_response()
        }
    }
}

/// Logout (GET)
async fn logout() -> Response {
    // Clear cookie and redirect
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("Location", "/")
        .header("Set-Cookie", "token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        .body(axum::body::Body::empty())
        .unwrap()
}

// ============================================================================
// Repository Creation Handlers
// ============================================================================

/// New repo form data
#[derive(serde::Deserialize)]
struct NewRepoForm {
    name: String,
    namespace: String,
}

/// New repository page (GET)
async fn new_repo_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let mut context = Context::new();

    // Check if user is logged in
    let current_user = get_current_user(&state, &headers).await;
    if current_user.is_none() {
        return Redirect::to("/-/login?error=Please+sign+in+to+create+a+repository").into_response();
    }
    let username = current_user.clone().unwrap();

    context.insert("current_user", &current_user);

    // Get user's organizations for namespace dropdown
    let mut namespaces: Vec<String> = vec![username.clone()];

    if let Some(db) = &state.db {
        // Get the user record
        if let Ok(Some(user_record)) = user::Entity::find()
            .filter(user::Column::Username.eq(&username))
            .one(db.as_ref())
            .await
        {
            // Get orgs this user is a member of
            let memberships = org_member::Entity::find()
                .filter(org_member::Column::UserId.eq(user_record.id))
                .all(db.as_ref())
                .await
                .unwrap_or_default();

            for membership in memberships {
                // Get the org (which is also a user record with is_org=true)
                if let Ok(Some(org)) = user::Entity::find_by_id(membership.org_id)
                    .one(db.as_ref())
                    .await
                {
                    namespaces.push(org.username);
                }
            }
        }
    }

    context.insert("namespaces", &namespaces);

    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }

    render_template("new_repo.html", &context)
}

/// Create repository (POST)
async fn create_repo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<NewRepoForm>,
) -> Response {
    // Check if user is logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+create+a+repository").into_response(),
    };

    // Validate repo name
    let name = form.name.trim();
    if name.is_empty() {
        return Redirect::to("/-/new?error=Repository+name+cannot+be+empty").into_response();
    }
    if name.len() < 2 {
        return Redirect::to("/-/new?error=Repository+name+must+be+at+least+2+characters").into_response();
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Redirect::to("/-/new?error=Repository+name+can+only+contain+letters,+numbers,+dashes,+underscores,+and+dots").into_response();
    }

    // Validate namespace - must be current user or an org the user is a member of
    let namespace = form.namespace.trim();
    if namespace.is_empty() {
        return Redirect::to("/-/new?error=Please+select+a+namespace").into_response();
    }

    // Check if user is allowed to create in this namespace
    let allowed = if namespace == current_user {
        true
    } else if let Some(db) = &state.db {
        // Check if namespace is an org the user is a member of
        let user_record = user::Entity::find()
            .filter(user::Column::Username.eq(&current_user))
            .one(db.as_ref())
            .await
            .ok()
            .flatten();

        let org_record = user::Entity::find()
            .filter(user::Column::Username.eq(namespace))
            .filter(user::Column::IsOrg.eq(true))
            .one(db.as_ref())
            .await
            .ok()
            .flatten();

        if let (Some(user), Some(org)) = (user_record, org_record) {
            org_member::Entity::find()
                .filter(org_member::Column::UserId.eq(user.id))
                .filter(org_member::Column::OrgId.eq(org.id))
                .one(db.as_ref())
                .await
                .map(|r| r.is_some())
                .unwrap_or(false)
        } else {
            false
        }
    } else {
        false
    };

    if !allowed {
        return Redirect::to("/-/new?error=You+don't+have+permission+to+create+repositories+in+this+namespace").into_response();
    }

    // Create repo path
    let full_name = format!("{}/{}", namespace, name);

    // Check if repo already exists
    if state.repos.get_repo(&full_name).is_ok() {
        return Redirect::to("/-/new?error=Repository+already+exists").into_response();
    }

    // Create the repository
    let _ = state.repos.get_or_create_repo(&full_name);

    // Redirect to the new repo
    Redirect::to(&format!("/{}", full_name)).into_response()
}

// ============================================================================
// Organization Handlers
// ============================================================================

/// Form for creating a new org
#[derive(serde::Deserialize)]
struct NewOrgForm {
    name: String,
}

/// New organization page (GET)
async fn new_org_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let mut context = Context::new();

    // Check if user is logged in
    let current_user = get_current_user(&state, &headers).await;
    if current_user.is_none() {
        return Redirect::to("/-/login?error=Please+sign+in+to+create+an+organization").into_response();
    }

    context.insert("current_user", &current_user);

    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }

    render_template("new_org.html", &context)
}

/// Create organization (POST)
async fn create_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<NewOrgForm>,
) -> Response {
    // Check if user is logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+create+an+organization").into_response(),
    };

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Validate org name
    let name = form.name.trim();
    if name.is_empty() {
        return Redirect::to("/-/new-org?error=Organization+name+cannot+be+empty").into_response();
    }
    if name.len() < 2 {
        return Redirect::to("/-/new-org?error=Organization+name+must+be+at+least+2+characters").into_response();
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Redirect::to("/-/new-org?error=Organization+name+can+only+contain+letters,+numbers,+dashes,+and+underscores").into_response();
    }

    // Check if name is already taken (user or org)
    let existing = user::Entity::find()
        .filter(user::Column::Username.eq(name))
        .one(db.as_ref())
        .await;

    if matches!(existing, Ok(Some(_))) {
        return Redirect::to("/-/new-org?error=Name+is+already+taken").into_response();
    }

    // Get current user's ID
    let creator = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Create the organization (is_org = true)
    let new_org = user::ActiveModel {
        username: Set(name.to_string()),
        password_hash: Set(String::new()), // Orgs don't have passwords
        display_name: Set(Some(name.to_string())),
        email: Set(None),
        is_org: Set(true),
        created_at: Set(now),
        ..Default::default()
    };

    let org = match new_org.insert(db.as_ref()).await {
        Ok(o) => o,
        Err(e) => return render_error(&format!("Failed to create organization: {}", e)),
    };

    // Add creator as org owner
    let membership = org_member::ActiveModel {
        org_id: Set(org.id),
        user_id: Set(creator.id),
        role: Set("owner".to_string()),
        created_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = membership.insert(db.as_ref()).await {
        return render_error(&format!("Failed to add owner to organization: {}", e));
    }

    // Redirect to the new org
    Redirect::to(&format!("/{}", name)).into_response()
}

/// Form for adding a member
#[derive(serde::Deserialize)]
struct AddMemberForm {
    username: String,
}

/// Add member to organization (POST)
async fn add_org_member(
    State(state): State<Arc<AppState>>,
    Path(org_name): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AddMemberForm>,
) -> Response {
    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Check if user is logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in").into_response(),
    };

    // Get org
    let org = match user::Entity::find()
        .filter(user::Column::Username.eq(&org_name))
        .filter(user::Column::IsOrg.eq(true))
        .one(db.as_ref())
        .await
    {
        Ok(Some(o)) => o,
        _ => return render_error("Organization not found"),
    };

    // Check if current user is org owner
    let current_user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let is_owner = org_member::Entity::find()
        .filter(org_member::Column::OrgId.eq(org.id))
        .filter(org_member::Column::UserId.eq(current_user_record.id))
        .filter(org_member::Column::Role.eq("owner"))
        .one(db.as_ref())
        .await
        .map(|r| r.is_some())
        .unwrap_or(false);

    if !is_owner {
        return render_error("Only organization owners can add members");
    }

    // Find user to add
    let new_member = match user::Entity::find()
        .filter(user::Column::Username.eq(form.username.trim()))
        .filter(user::Column::IsOrg.eq(false))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return Redirect::to(&format!("/{}?error=User+not+found", org_name)).into_response(),
    };

    // Check if already a member
    let existing = org_member::Entity::find()
        .filter(org_member::Column::OrgId.eq(org.id))
        .filter(org_member::Column::UserId.eq(new_member.id))
        .one(db.as_ref())
        .await;

    if matches!(existing, Ok(Some(_))) {
        return Redirect::to(&format!("/{}?error=User+is+already+a+member", org_name)).into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Add member
    let membership = org_member::ActiveModel {
        org_id: Set(org.id),
        user_id: Set(new_member.id),
        role: Set("member".to_string()),
        created_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = membership.insert(db.as_ref()).await {
        return render_error(&format!("Failed to add member: {}", e));
    }

    Redirect::to(&format!("/{}", org_name)).into_response()
}

/// Remove member from organization (POST)
async fn remove_org_member(
    State(state): State<Arc<AppState>>,
    Path((org_name, username)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Check if user is logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in").into_response(),
    };

    // Get org
    let org = match user::Entity::find()
        .filter(user::Column::Username.eq(&org_name))
        .filter(user::Column::IsOrg.eq(true))
        .one(db.as_ref())
        .await
    {
        Ok(Some(o)) => o,
        _ => return render_error("Organization not found"),
    };

    // Check if current user is org owner
    let current_user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let is_owner = org_member::Entity::find()
        .filter(org_member::Column::OrgId.eq(org.id))
        .filter(org_member::Column::UserId.eq(current_user_record.id))
        .filter(org_member::Column::Role.eq("owner"))
        .one(db.as_ref())
        .await
        .map(|r| r.is_some())
        .unwrap_or(false);

    if !is_owner {
        return render_error("Only organization owners can remove members");
    }

    // Find member to remove
    let member_to_remove = match user::Entity::find()
        .filter(user::Column::Username.eq(&username))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    // Don't allow removing yourself if you're the only owner
    if member_to_remove.id == current_user_record.id {
        let owner_count = org_member::Entity::find()
            .filter(org_member::Column::OrgId.eq(org.id))
            .filter(org_member::Column::Role.eq("owner"))
            .count(db.as_ref())
            .await
            .unwrap_or(0);

        if owner_count <= 1 {
            return Redirect::to(&format!("/{}?error=Cannot+remove+the+only+owner", org_name)).into_response();
        }
    }

    // Remove membership
    let _ = org_member::Entity::delete_many()
        .filter(org_member::Column::OrgId.eq(org.id))
        .filter(org_member::Column::UserId.eq(member_to_remove.id))
        .exec(db.as_ref())
        .await;

    Redirect::to(&format!("/{}", org_name)).into_response()
}

// ============================================================================
// Community Discussion Handlers
// ============================================================================

/// Discussion info for templates
#[derive(serde::Serialize)]
struct DiscussionInfo {
    id: i32,
    title: String,
    author: String,
    status: String,
    comment_count: usize,
    created_at: String,
    updated_at: String,
}

/// Timeline item - unified comment or event for chronological display
#[derive(serde::Serialize)]
struct TimelineItem {
    item_type: String, // "comment", "event", or "op" (original post)
    author: String,
    content: Option<String>,
    event_type: Option<String>,
    old_value: Option<String>,
    new_value: Option<String>,
    created_at: String,
    timestamp: i64, // For sorting
}

/// Form for creating a new discussion
#[derive(serde::Deserialize)]
struct NewDiscussionForm {
    title: String,
    content: String,
}

/// Form for posting a comment
#[derive(serde::Deserialize)]
struct NewCommentForm {
    content: String,
}

/// List discussions for a repo
async fn discussions_list(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Check if repo exists
    if state.repos.get_repo(&full_name).is_err() {
        return render_error(&format!("Repository '{}' not found", full_name));
    }

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Get discussions for this repo
    let discussions = discussion::Entity::find()
        .filter(discussion::Column::RepoName.eq(&full_name))
        .order_by_desc(discussion::Column::UpdatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    // Build discussion info with author names and comment counts
    let mut discussion_infos = Vec::new();
    for disc in discussions {
        let author = user::Entity::find_by_id(disc.author_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        let comment_count = discussion_comment::Entity::find()
            .filter(discussion_comment::Column::DiscussionId.eq(disc.id))
            .count(db.as_ref())
            .await
            .unwrap_or(0) as usize;

        discussion_infos.push(DiscussionInfo {
            id: disc.id,
            title: disc.title,
            author,
            status: disc.status,
            comment_count,
            created_at: format_relative_time(disc.created_at),
            updated_at: format_relative_time(disc.updated_at),
        });
    }

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("discussions", &discussion_infos);
    context.insert("discussion_count", &discussion_infos.len());
    context.insert("active_tab", "community");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("discussions.html", &context)
}

/// New discussion page (GET)
async fn new_discussion_page(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Check if user is logged in
    let current_user = get_current_user(&state, &headers).await;
    if current_user.is_none() {
        return Redirect::to(&format!("/-/login?error=Please+sign+in+to+start+a+discussion")).into_response();
    }

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("current_user", &current_user);
    context.insert("active_tab", "community");

    render_template("new_discussion.html", &context)
}

/// Create a new discussion (POST)
async fn create_discussion(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<NewDiscussionForm>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Check if user is logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+start+a+discussion").into_response(),
    };

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Get user ID
    let user = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Create discussion
    let new_discussion = discussion::ActiveModel {
        repo_name: Set(full_name.clone()),
        author_id: Set(user.id),
        title: Set(form.title.clone()),
        status: Set("open".to_string()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let disc = match new_discussion.insert(db.as_ref()).await {
        Ok(d) => d,
        Err(e) => return render_error(&format!("Failed to create discussion: {}", e)),
    };

    // Create first comment with content
    if !form.content.trim().is_empty() {
        let first_comment = discussion_comment::ActiveModel {
            discussion_id: Set(disc.id),
            author_id: Set(user.id),
            content: Set(form.content),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };
        let _ = first_comment.insert(db.as_ref()).await;
    }

    Redirect::to(&format!("/{}/discussions/{}", full_name, disc.id)).into_response()
}

/// View a discussion thread
async fn discussion_detail(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, id)): Path<(String, String, i32)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Get discussion
    let disc = match discussion::Entity::find_by_id(id)
        .one(db.as_ref())
        .await
    {
        Ok(Some(d)) if d.repo_name == full_name => d,
        _ => return render_error("Discussion not found"),
    };

    // Get author
    let author = user::Entity::find_by_id(disc.author_id)
        .one(db.as_ref())
        .await
        .ok()
        .flatten()
        .map(|u| u.username)
        .unwrap_or_else(|| "unknown".to_string());

    // Get comments
    let comments = discussion_comment::Entity::find()
        .filter(discussion_comment::Column::DiscussionId.eq(id))
        .order_by_asc(discussion_comment::Column::CreatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    // Get events (close/reopen/rename/lock activities)
    let events = discussion_event::Entity::find()
        .filter(discussion_event::Column::DiscussionId.eq(id))
        .order_by_asc(discussion_event::Column::CreatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    // Build unified timeline
    let mut timeline: Vec<TimelineItem> = Vec::new();

    // Add comments to timeline (first comment is the original post)
    let mut is_first = true;
    for comment in &comments {
        let comment_author = user::Entity::find_by_id(comment.author_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        timeline.push(TimelineItem {
            item_type: if is_first { "op".to_string() } else { "comment".to_string() },
            author: comment_author,
            content: Some(comment.content.clone()),
            event_type: None,
            old_value: None,
            new_value: None,
            created_at: format_relative_time(comment.created_at),
            timestamp: comment.created_at,
        });
        is_first = false;
    }

    // Add events to timeline
    for event in events {
        let event_actor = user::Entity::find_by_id(event.actor_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        timeline.push(TimelineItem {
            item_type: "event".to_string(),
            author: event_actor,
            content: None,
            event_type: Some(event.event_type),
            old_value: event.old_value,
            new_value: event.new_value,
            created_at: format_relative_time(event.created_at),
            timestamp: event.created_at,
        });
    }

    // Sort timeline by timestamp (but keep OP first)
    if !timeline.is_empty() {
        let op = timeline.remove(0);
        timeline.sort_by_key(|item| item.timestamp);
        timeline.insert(0, op);
    }

    let reply_count = comments.len().saturating_sub(1); // Exclude OP

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("discussion_id", &disc.id);
    context.insert("discussion_title", &disc.title);
    context.insert("discussion_author", &author);
    context.insert("discussion_status", &disc.status);
    context.insert("discussion_created", &format_relative_time(disc.created_at));
    context.insert("timeline", &timeline);
    context.insert("reply_count", &reply_count);
    context.insert("active_tab", "community");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("discussion.html", &context)
}

/// Post a comment to a discussion (POST)
async fn post_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, id)): Path<(String, String, i32)>,
    headers: HeaderMap,
    Form(form): Form<NewCommentForm>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Check if user is logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+comment").into_response(),
    };

    if form.content.trim().is_empty() {
        return Redirect::to(&format!("/{}/discussions/{}", full_name, id)).into_response();
    }

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Get user ID
    let user = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Create comment
    let new_comment = discussion_comment::ActiveModel {
        discussion_id: Set(id),
        author_id: Set(user.id),
        content: Set(form.content),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = new_comment.insert(db.as_ref()).await {
        return render_error(&format!("Failed to post comment: {}", e));
    }

    // Update discussion timestamp
    let _ = discussion::Entity::update_many()
        .col_expr(discussion::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(discussion::Column::Id.eq(id))
        .exec(db.as_ref())
        .await;

    Redirect::to(&format!("/{}/discussions/{}", full_name, id)).into_response()
}

/// Close a discussion (POST)
async fn close_discussion(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, id)): Path<(String, String, i32)>,
    headers: HeaderMap,
) -> Response {
    update_discussion_status(state, &owner, &repo, id, "closed", &headers).await
}

/// Reopen a discussion (POST)
async fn reopen_discussion(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, id)): Path<(String, String, i32)>,
    headers: HeaderMap,
) -> Response {
    update_discussion_status(state, &owner, &repo, id, "open", &headers).await
}

/// Helper to update discussion status
async fn update_discussion_status(
    state: Arc<AppState>,
    owner: &str,
    repo: &str,
    id: i32,
    new_status: &str,
    headers: &HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Check if user is logged in and is the owner
    let current_user = match get_current_user(&state, headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in").into_response(),
    };

    // Only repo owner can close/reopen discussions
    if current_user != owner {
        return render_error("Only the repository owner can close or reopen discussions");
    }

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Get user ID for event recording
    let actor = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    // Get current discussion status
    let disc = match discussion::Entity::find_by_id(id)
        .one(db.as_ref())
        .await
    {
        Ok(Some(d)) if d.repo_name == full_name => d,
        _ => return render_error("Discussion not found"),
    };

    let old_status = disc.status.clone();

    // Update discussion status
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let _ = discussion::Entity::update_many()
        .col_expr(discussion::Column::Status, sea_orm::sea_query::Expr::value(new_status))
        .col_expr(discussion::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(discussion::Column::Id.eq(id))
        .filter(discussion::Column::RepoName.eq(&full_name))
        .exec(db.as_ref())
        .await;

    // Record the event
    let event_type = if new_status == "closed" { "closed" } else { "reopened" };
    let new_event = discussion_event::ActiveModel {
        discussion_id: Set(id),
        actor_id: Set(actor.id),
        event_type: Set(event_type.to_string()),
        old_value: Set(Some(old_status)),
        new_value: Set(Some(new_status.to_string())),
        created_at: Set(now),
        ..Default::default()
    };
    let _ = new_event.insert(db.as_ref()).await;

    Redirect::to(&format!("/{}/discussions/{}", full_name, id)).into_response()
}
