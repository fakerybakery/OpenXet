//! HuggingFace API request handlers.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::Bytes;

use super::types::*;
use crate::api::AppState;
use crate::git::ObjectType;

// ============================================================================
// Constants
// ============================================================================

/// Threshold for LFS upload (10MB)
const LFS_THRESHOLD: u64 = 10 * 1024 * 1024;

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract repo name from HF-style path, stripping repo type prefix.
/// `/api/models/user/repo` → `user/repo`
/// `/api/datasets/user/repo` → `user/repo`
fn normalize_repo_path(owner: &str, repo: &str) -> String {
    format!("{}/{}", owner, repo.trim_end_matches(".git"))
}

/// Get the base URL for responses (from Host header or default)
fn get_base_url(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|host| {
            // Check if it looks like HTTPS (port 443 or no port with common patterns)
            if host.ends_with(":443") || (!host.contains(':') && !host.starts_with("localhost")) {
                format!("https://{}", host.trim_end_matches(":443"))
            } else {
                format!("http://{}", host)
            }
        })
        .unwrap_or_else(|| "http://localhost:8080".to_string())
}

/// JSON response helper
fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    match serde_json::to_string(body) {
        Ok(json) => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("JSON serialization error: {}", e)))
            .unwrap(),
    }
}

// ============================================================================
// Authentication Handlers
// ============================================================================

/// GET /api/whoami-v2 - Return current user info
pub async fn whoami() -> Response {
    // Accept any token, return anonymous user info
    json_response(StatusCode::OK, &WhoamiResponse::default())
}

// ============================================================================
// Repository Management Handlers
// ============================================================================

/// POST /api/repos/create - Create a new repository
pub async fn create_repo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<CreateRepoRequest>,
) -> Response {
    let owner = req.organization.as_deref().unwrap_or("anonymous");
    let repo_name = format!("{}/{}", owner, req.name);
    let repo_type = req.repo_type.as_deref().unwrap_or("model");

    // Create or get existing repo
    let _ = state.repos.get_or_create_repo(&repo_name);

    let base_url = get_base_url(&headers);
    let response = CreateRepoResponse {
        repo_type: repo_type.to_string(),
        id: repo_name.clone(),
        name: req.name,
        private: req.private.unwrap_or(false),
        url: format!("{}/{}", base_url, repo_name),
    };

    json_response(StatusCode::OK, &response)
}

/// GET /api/models/:owner/:repo - Get model repo info
/// GET /api/datasets/:owner/:repo - Get dataset repo info
/// GET /api/spaces/:owner/:repo - Get space repo info
pub async fn repo_info(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repo_name = normalize_repo_path(&owner, &repo);

    // Check if repo exists, create if not
    let repo_handle = state.repos.get_or_create_repo(&repo_name);

    // Get HEAD commit SHA
    let sha = repo_handle
        .resolve_ref("refs/heads/main")
        .map(|id| id.to_hex())
        .unwrap_or_else(|| "0".repeat(40));

    // Collect file list from tree
    let siblings = collect_repo_files(&repo_handle);

    let response = RepoInfoResponse {
        id: repo_name.clone(),
        model_id: repo_name,
        author: owner,
        sha,
        private: false,
        disabled: false,
        gated: false,
        tags: vec![],
        siblings,
        created_at: "2024-01-01T00:00:00.000Z".to_string(),
        last_modified: "2024-01-01T00:00:00.000Z".to_string(),
    };

    json_response(StatusCode::OK, &response)
}

/// GET /api/{type}s/:owner/:repo/revision/:revision - Get repo info at specific revision
pub async fn repo_info_revision(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, revision)): Path<(String, String, String)>,
) -> Response {
    let repo_name = normalize_repo_path(&owner, &repo);

    // Check if repo exists
    let repo_handle = match state.repos.get_repo(&repo_name) {
        Ok(r) => r,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("x-error-code", "RepoNotFound")
                .body(Body::from("Repository not found"))
                .unwrap();
        }
    };

    // Resolve the revision (could be branch name, tag, or commit SHA)
    let commit_id = if revision.len() == 40 && revision.chars().all(|c| c.is_ascii_hexdigit()) {
        // Looks like a full SHA
        crate::git::ObjectId::from_hex(&revision)
    } else {
        // Try as branch name
        repo_handle.resolve_ref(&format!("refs/heads/{}", revision))
    };

    let sha = match commit_id {
        Some(id) => id.to_hex(),
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("x-error-code", "RevisionNotFound")
                .body(Body::from("Revision not found"))
                .unwrap();
        }
    };

    // Collect file list from tree at this revision
    let siblings = collect_repo_files_at_revision(&repo_handle, &sha);

    let response = RepoInfoResponse {
        id: repo_name.clone(),
        model_id: repo_name,
        author: owner,
        sha,
        private: false,
        disabled: false,
        gated: false,
        tags: vec![],
        siblings,
        created_at: "2024-01-01T00:00:00.000Z".to_string(),
        last_modified: "2024-01-01T00:00:00.000Z".to_string(),
    };

    json_response(StatusCode::OK, &response)
}

/// Collect all files from a repository at a specific revision
fn collect_repo_files_at_revision(repo: &crate::git::Repository, sha: &str) -> Vec<RepoSibling> {
    let mut files = Vec::new();

    let commit_id = match crate::git::ObjectId::from_hex(sha) {
        Some(id) => id,
        None => return files,
    };

    let tree_id = match repo.get_commit_tree(&commit_id) {
        Some(id) => id,
        None => return files,
    };

    collect_files_recursive(repo, &tree_id, "", &mut files);
    files
}

/// Collect all files from a repository's current HEAD
fn collect_repo_files(repo: &crate::git::Repository) -> Vec<RepoSibling> {
    let mut files = Vec::new();

    let commit_id = match repo.resolve_ref("refs/heads/main") {
        Some(id) => id,
        None => return files,
    };

    let tree_id = match repo.get_commit_tree(&commit_id) {
        Some(id) => id,
        None => return files,
    };

    collect_files_recursive(repo, &tree_id, "", &mut files);
    files
}

/// Recursively collect files from tree
fn collect_files_recursive(
    repo: &crate::git::Repository,
    tree_id: &crate::git::ObjectId,
    prefix: &str,
    files: &mut Vec<RepoSibling>,
) {
    let entries = match repo.parse_tree(tree_id) {
        Some(e) => e,
        None => return,
    };

    for entry in entries {
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{}/{}", prefix, entry.name)
        };

        if entry.is_dir {
            collect_files_recursive(repo, &entry.oid, &path, files);
        } else {
            files.push(RepoSibling {
                rfilename: path,
                size: None,
                blob_id: Some(entry.oid.to_hex()),
            });
        }
    }
}

// ============================================================================
// Tree Listing Handler
// ============================================================================

/// GET /api/{type}s/:owner/:repo/tree/:revision - List files in tree
pub async fn tree_list(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, _revision)): Path<(String, String, String)>,
    Query(query): Query<TreeQuery>,
) -> Response {
    let repo_name = normalize_repo_path(&owner, &repo);

    let repo_handle = match state.repos.get_repo(&repo_name) {
        Ok(r) => r,
        Err(_) => {
            // Return empty tree for non-existent repos
            return json_response(StatusCode::OK, &Vec::<TreeEntry>::new());
        }
    };

    let commit_id = match repo_handle.resolve_ref("refs/heads/main") {
        Some(id) => id,
        None => return json_response(StatusCode::OK, &Vec::<TreeEntry>::new()),
    };

    let tree_id = match repo_handle.get_commit_tree(&commit_id) {
        Some(id) => id,
        None => return json_response(StatusCode::OK, &Vec::<TreeEntry>::new()),
    };

    let recursive = query.recursive.unwrap_or(false);
    let entries = collect_tree_entries(&repo_handle, &tree_id, "", recursive);

    json_response(StatusCode::OK, &entries)
}

/// GET /api/{type}s/:owner/:repo/tree/:revision/*path - List files in tree at path
pub async fn tree_list_path(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, revision, path)): Path<(String, String, String, String)>,
    Query(query): Query<TreeQuery>,
) -> Response {
    let repo_name = normalize_repo_path(&owner, &repo);
    let path = path.trim_start_matches('/');

    let repo_handle = match state.repos.get_repo(&repo_name) {
        Ok(r) => r,
        Err(_) => {
            return json_response(StatusCode::OK, &Vec::<TreeEntry>::new());
        }
    };

    // Resolve revision (could be branch or commit SHA)
    let commit_id = if revision.len() == 40 && revision.chars().all(|c| c.is_ascii_hexdigit()) {
        crate::git::ObjectId::from_hex(&revision)
    } else {
        repo_handle.resolve_ref(&format!("refs/heads/{}", revision))
    };

    let commit_id = match commit_id {
        Some(id) => id,
        None => return json_response(StatusCode::OK, &Vec::<TreeEntry>::new()),
    };

    let tree_id = match repo_handle.get_commit_tree(&commit_id) {
        Some(id) => id,
        None => return json_response(StatusCode::OK, &Vec::<TreeEntry>::new()),
    };

    // Navigate to the requested path
    let target_tree_id = if path.is_empty() {
        tree_id
    } else {
        match navigate_to_path(&repo_handle, &tree_id, path) {
            Some(id) => id,
            None => return json_response(StatusCode::OK, &Vec::<TreeEntry>::new()),
        }
    };

    let recursive = query.recursive.unwrap_or(false);
    let entries = collect_tree_entries(&repo_handle, &target_tree_id, path, recursive);

    json_response(StatusCode::OK, &entries)
}

/// Navigate through tree to find subtree at path
fn navigate_to_path(
    repo: &crate::git::Repository,
    tree_id: &crate::git::ObjectId,
    path: &str,
) -> Option<crate::git::ObjectId> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current_tree = *tree_id;

    for part in parts {
        let entries = repo.parse_tree(&current_tree)?;
        let entry = entries.iter().find(|e| e.name == part && e.is_dir)?;
        current_tree = entry.oid;
    }

    Some(current_tree)
}

/// Collect tree entries for listing
fn collect_tree_entries(
    repo: &crate::git::Repository,
    tree_id: &crate::git::ObjectId,
    prefix: &str,
    recursive: bool,
) -> Vec<TreeEntry> {
    let mut result = Vec::new();

    let entries = match repo.parse_tree(tree_id) {
        Some(e) => e,
        None => return result,
    };

    for entry in entries {
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{}/{}", prefix, entry.name)
        };

        if entry.is_dir {
            result.push(TreeEntry {
                entry_type: "directory".to_string(),
                path: path.clone(),
                size: None,
                oid: entry.oid.to_hex(),
            });

            if recursive {
                let sub_entries = collect_tree_entries(repo, &entry.oid, &path, true);
                result.extend(sub_entries);
            }
        } else {
            // Get file size from blob
            let size = repo.get_blob_content(&entry.oid).map(|c| c.len() as u64);

            result.push(TreeEntry {
                entry_type: "file".to_string(),
                path,
                size,
                oid: entry.oid.to_hex(),
            });
        }
    }

    result
}

// ============================================================================
// Upload Handlers
// ============================================================================

/// POST /api/{type}s/:owner/:repo/preupload/:revision - Pre-upload check
pub async fn preupload(
    Path((_owner, _repo, _revision)): Path<(String, String, String)>,
    axum::Json(req): axum::Json<PreuploadRequest>,
) -> Response {
    // Determine upload mode for each file
    let files: Vec<PreuploadFileResponse> = req
        .files
        .into_iter()
        .map(|f| PreuploadFileResponse {
            path: f.path,
            upload_mode: if f.size > LFS_THRESHOLD {
                "lfs".to_string()
            } else {
                "regular".to_string()
            },
            should_ignore: false,
            oid: None,
        })
        .collect();

    json_response(StatusCode::OK, &PreuploadResponse { files })
}

/// POST /api/{type}s/:owner/:repo/commit/:revision - Commit files
pub async fn commit(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, _revision)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo_name = normalize_repo_path(&owner, &repo);
    let base_url = get_base_url(&headers);

    // Parse NDJSON body
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid UTF-8 in body"))
                .unwrap();
        }
    };

    // Parse commit data from NDJSON
    let mut commit_message = String::new();
    let mut files_to_add: Vec<(String, Vec<u8>)> = Vec::new();

    for line in body_str.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let key = parsed.get("key").and_then(|k| k.as_str()).unwrap_or("");
        let value = parsed.get("value");

        match key {
            "header" => {
                if let Some(v) = value {
                    commit_message = v
                        .get("summary")
                        .and_then(|s| s.as_str())
                        .unwrap_or("Update via HF API")
                        .to_string();
                }
            }
            "file" => {
                if let Some(v) = value {
                    let path = v.get("path").and_then(|p| p.as_str()).unwrap_or("");
                    let content = v.get("content").and_then(|c| c.as_str()).unwrap_or("");
                    let encoding = v.get("encoding").and_then(|e| e.as_str()).unwrap_or("");

                    let decoded = if encoding == "base64" {
                        BASE64.decode(content).unwrap_or_default()
                    } else {
                        content.as_bytes().to_vec()
                    };

                    if !path.is_empty() {
                        files_to_add.push((path.to_string(), decoded));
                    }
                }
            }
            "lfsFile" => {
                // LFS files are handled separately via LFS batch API
                // Just record the pointer
                if let Some(v) = value {
                    let path = v.get("path").and_then(|p| p.as_str()).unwrap_or("");
                    let oid = v.get("oid").and_then(|o| o.as_str()).unwrap_or("");
                    let size = v.get("size").and_then(|s| s.as_u64()).unwrap_or(0);

                    if !path.is_empty() && !oid.is_empty() {
                        let pointer = format!(
                            "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n",
                            oid, size
                        );
                        files_to_add.push((path.to_string(), pointer.into_bytes()));
                    }
                }
            }
            _ => {}
        }
    }

    // Get or create repository
    let repo_handle = state.repos.get_or_create_repo(&repo_name);

    // Get current HEAD tree (or empty tree)
    let parent_commit = repo_handle.resolve_ref("refs/heads/main");
    let current_tree = parent_commit.and_then(|c| repo_handle.get_commit_tree(&c));

    // Build new tree with added files
    let new_tree_id = build_tree_with_files(&repo_handle, current_tree.as_ref(), &files_to_add);

    let new_tree_id = match new_tree_id {
        Some(id) => id,
        None => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to build tree"))
                .unwrap();
        }
    };

    // Create commit
    let parent_ids: Vec<crate::git::ObjectId> = parent_commit.into_iter().collect();
    let commit_oid = repo_handle.create_commit(
        &new_tree_id,
        &parent_ids,
        &commit_message,
        "HuggingFace API",
        "hf@localhost",
    );

    // Update ref
    let _ = repo_handle.update_ref("refs/heads/main", commit_oid);

    let commit_hex = commit_oid.to_hex();
    let response = CommitResponse {
        success: true,
        commit_oid: commit_hex.clone(),
        commit_url: format!("{}/{}/commit/{}", base_url, repo_name, commit_hex),
        hook_output: String::new(),
    };

    json_response(StatusCode::OK, &response)
}

/// Build a new tree with files added
fn build_tree_with_files(
    repo: &crate::git::Repository,
    base_tree: Option<&crate::git::ObjectId>,
    files: &[(String, Vec<u8>)],
) -> Option<crate::git::ObjectId> {
    let mut tree_id = base_tree.copied();

    for (path, content) in files {
        // Create blob
        let blob_id = repo.create_object(ObjectType::Blob, content);

        // Add to tree
        tree_id = Some(add_file_to_tree(repo, tree_id.as_ref(), path, &blob_id)?);
    }

    tree_id.or_else(|| {
        // Create empty tree if no base and no files
        Some(repo.create_object(ObjectType::Tree, &[]))
    })
}

/// Add a single file to a tree, creating directories as needed
fn add_file_to_tree(
    repo: &crate::git::Repository,
    base_tree: Option<&crate::git::ObjectId>,
    path: &str,
    blob_id: &crate::git::ObjectId,
) -> Option<crate::git::ObjectId> {
    let parts: Vec<&str> = path.split('/').collect();
    add_to_tree_recursive(repo, base_tree, &parts, blob_id)
}

fn add_to_tree_recursive(
    repo: &crate::git::Repository,
    current_tree: Option<&crate::git::ObjectId>,
    path_parts: &[&str],
    blob_id: &crate::git::ObjectId,
) -> Option<crate::git::ObjectId> {
    if path_parts.is_empty() {
        return None;
    }

    let mut entries: Vec<crate::git::TreeEntry> = current_tree
        .and_then(|t| repo.parse_tree(t))
        .unwrap_or_default();

    let target_name = path_parts[0];
    let is_final = path_parts.len() == 1;

    if is_final {
        // Add or replace the file
        entries.retain(|e| e.name != target_name);
        entries.push(crate::git::TreeEntry {
            mode: "100644".to_string(),
            name: target_name.to_string(),
            oid: *blob_id,
            is_dir: false,
            is_executable: false,
            is_symlink: false,
        });
    } else {
        // Find or create subdirectory
        let existing_subtree = entries.iter().find(|e| e.name == target_name && e.is_dir);
        let subtree_oid = existing_subtree.map(|e| e.oid);

        let new_subtree_id =
            add_to_tree_recursive(repo, subtree_oid.as_ref(), &path_parts[1..], blob_id)?;

        entries.retain(|e| e.name != target_name);
        entries.push(crate::git::TreeEntry {
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

/// Serialize tree entries to git tree format
fn serialize_tree(entries: &[crate::git::TreeEntry]) -> Vec<u8> {
    let mut data = Vec::new();

    // Sort entries (git requires sorted trees)
    let mut sorted_entries: Vec<_> = entries.iter().collect();
    sorted_entries.sort_by(|a, b| {
        let a_name = if a.is_dir {
            format!("{}/", a.name)
        } else {
            a.name.clone()
        };
        let b_name = if b.is_dir {
            format!("{}/", b.name)
        } else {
            b.name.clone()
        };
        a_name.cmp(&b_name)
    });

    for entry in sorted_entries {
        data.extend_from_slice(entry.mode.as_bytes());
        data.push(b' ');
        data.extend_from_slice(entry.name.as_bytes());
        data.push(0);
        data.extend_from_slice(entry.oid.as_bytes());
    }

    data
}

// ============================================================================
// File Download Handlers
// ============================================================================

/// Path params for resolve without repo type prefix
#[derive(Debug, serde::Deserialize)]
pub struct ResolveParams {
    pub owner: String,
    pub repo: String,
    #[allow(dead_code)] // Captured but we use "main" for now
    pub revision: String,
    pub path: String,
}

/// GET/HEAD /:owner/:repo/resolve/:revision/*path - Download file (models default)
pub async fn resolve_file(
    method: Method,
    State(state): State<Arc<AppState>>,
    Path(params): Path<ResolveParams>,
) -> Response {
    resolve_file_impl(method, state, &params.owner, &params.repo, &params.path).await
}

/// GET/HEAD /datasets/:owner/:repo/resolve/:revision/*path - Download dataset file
pub async fn resolve_file_typed(
    method: Method,
    State(state): State<Arc<AppState>>,
    Path(params): Path<ResolveParams>,
) -> Response {
    resolve_file_impl(method, state, &params.owner, &params.repo, &params.path).await
}

/// Build a 404 response with HF-compatible headers
fn not_found_response(commit_id: Option<&crate::git::ObjectId>, message: &str) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("x-error-code", "EntryNotFound")
        .header("x-error-message", message);

    if let Some(id) = commit_id {
        builder = builder.header("X-Repo-Commit", id.to_hex());
    }

    builder.body(Body::from(message.to_string())).unwrap()
}

/// Shared implementation for file resolution
async fn resolve_file_impl(
    method: Method,
    state: Arc<AppState>,
    owner: &str,
    repo: &str,
    path: &str,
) -> Response {
    let repo_name = normalize_repo_path(owner, repo);

    // Strip leading slash from path if present
    let path = path.trim_start_matches('/');

    let repo_handle = match state.repos.get_repo(&repo_name) {
        Ok(r) => r,
        Err(_) => {
            return not_found_response(None, "Repository not found");
        }
    };

    // Resolve to blob - get commit first so we can include it in 404 responses
    let commit_id = match repo_handle.resolve_ref("refs/heads/main") {
        Some(id) => id,
        None => {
            return not_found_response(None, "No commits");
        }
    };

    let tree_id = match repo_handle.get_commit_tree(&commit_id) {
        Some(id) => id,
        None => {
            return not_found_response(Some(&commit_id), "Tree not found");
        }
    };

    let (blob_id, is_dir) = match repo_handle.resolve_path(&tree_id, path) {
        Some(r) => r,
        None => {
            // Return 404 with X-Repo-Commit header (like HF does)
            return not_found_response(Some(&commit_id), "Entry not found");
        }
    };

    if is_dir {
        return not_found_response(Some(&commit_id), "Entry not found");
    }

    let content = match repo_handle.get_blob_content(&blob_id) {
        Some(c) => c,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Blob not found"))
                .unwrap();
        }
    };

    let content_length = content.len();
    let etag = format!("\"{}\"", blob_id.to_hex());

    // Determine content type
    let content_type = guess_content_type(path);

    if method == Method::HEAD {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, content_length)
            .header(header::ETAG, &etag)
            .header("X-Repo-Commit", commit_id.to_hex())
            .header("X-Linked-ETag", &etag)
            .body(Body::empty())
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, content_length)
            .header(header::ETAG, &etag)
            .header("X-Repo-Commit", commit_id.to_hex())
            .body(Body::from(content))
            .unwrap()
    }
}

/// Guess content type from file extension
fn guess_content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        Some("py") => "text/x-python; charset=utf-8",
        Some("rs") => "text/x-rust; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript",
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("xml") => "application/xml",
        Some("yaml") | Some("yml") => "text/yaml; charset=utf-8",
        Some("toml") => "text/toml; charset=utf-8",
        Some("csv") => "text/csv; charset=utf-8",
        Some("parquet") => "application/octet-stream",
        Some("bin") | Some("safetensors") | Some("pt") | Some("onnx") => "application/octet-stream",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

// Note: LFS batch API is handled by the existing lfs module in api/lfs.rs

// ============================================================================
// Utility Handlers
// ============================================================================

/// POST /api/validate-yaml - Validate YAML content
pub async fn validate_yaml() -> Response {
    // Always return success - we don't actually validate YAML
    json_response(
        StatusCode::OK,
        &ValidateYamlResponse {
            errors: vec![],
            warnings: vec![],
        },
    )
}
