use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::Deserialize;

use super::auth::{AuthManager, Token};
use crate::cas::{CasStore, ContentHash};
use crate::error::ServerError;
use crate::git::{
    generate_ref_advertisement, handle_receive_pack, handle_upload_pack, GitService,
    RepositoryStore,
};
use tokio::sync::mpsc;

/// Application state shared across handlers
pub struct AppState {
    pub repos: RepositoryStore,
    pub cas: Arc<CasStore>,
    pub auth: AuthManager,
    /// Channel to queue objects for background processing
    pub process_tx: mpsc::UnboundedSender<ContentHash>,
}

impl AppState {
    pub fn new() -> Self {
        Self::with_storage_path(std::env::temp_dir().join("git-xet-cas"))
    }

    pub fn with_storage_path(storage_path: std::path::PathBuf) -> Self {
        // Create CasStore with Arc for sharing
        let cas = Arc::new(CasStore::with_storage_path(storage_path));

        // Start background worker for chunking/deduplication
        let process_tx = CasStore::start_background_worker(cas.clone());

        tracing::info!("Background CAS processing worker started");

        Self {
            repos: RepositoryStore::new(),
            cas,
            auth: AuthManager::new(),
            process_tx,
        }
    }

    /// Queue an object for background processing
    pub fn queue_for_processing(&self, oid: ContentHash) {
        if self.process_tx.send(oid).is_err() {
            tracing::error!("Failed to queue object for background processing");
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract authentication from headers
fn extract_auth(headers: &HeaderMap, auth: &AuthManager) -> Option<Token> {
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Basic ") {
                return auth.authenticate_basic(auth_str).ok();
            } else if auth_str.starts_with("Bearer ") {
                return auth.validate_bearer(auth_str).ok();
            }
        }
    }
    None
}

/// Require authentication response
fn require_auth_response() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git-Xet Server\"")
        .body(Body::from("Authentication required"))
        .unwrap()
}

/// Query params for info/refs
#[derive(Deserialize)]
pub struct InfoRefsQuery {
    pub service: Option<String>,
}

/// Wildcard GET handler - routes Git and LFS requests
pub async fn wildcard_get(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Response {
    tracing::debug!("wildcard_get: path={}", path);

    // Parse the path: expect {repo}/info/refs or {repo}.git/info/refs
    if path.ends_with("/info/refs") {
        let repo_path = path.trim_end_matches("/info/refs");
        return info_refs_inner(state, repo_path.to_string(), query, headers).await;
    }

    // LFS download: {repo}/info/lfs/objects/{oid}
    if path.contains("/info/lfs/objects/") && !path.ends_with("/batch") {
        let parts: Vec<&str> = path.splitn(2, "/info/lfs/objects/").collect();
        if parts.len() == 2 {
            let repo = parts[0].to_string();
            let oid = parts[1].to_string();
            return super::lfs::lfs_download(
                State(state),
                Path((repo, oid)),
                headers,
            ).await;
        }
    }

    // Not a Git request
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not found"))
        .unwrap()
}

/// Wildcard PUT handler - routes LFS uploads (streaming)
pub async fn wildcard_put(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    request: axum::extract::Request,
) -> Response {
    tracing::debug!("wildcard_put: path={}", path);

    // Extract headers before consuming request
    let headers = request.headers().clone();

    // LFS upload: {repo}/info/lfs/objects/{oid}
    if path.contains("/info/lfs/objects/") {
        let parts: Vec<&str> = path.splitn(2, "/info/lfs/objects/").collect();
        if parts.len() == 2 {
            let repo = parts[0].to_string();
            let oid = parts[1].to_string();
            return super::lfs::lfs_upload(
                State(state),
                Path((repo, oid)),
                headers,
                request,
            ).await;
        }
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not found"))
        .unwrap()
}

/// Wildcard POST handler - routes Git and LFS requests
pub async fn wildcard_post(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    tracing::debug!("wildcard_post: path={}", path);

    // Parse the path: expect {repo}/git-upload-pack or {repo}/git-receive-pack
    if path.ends_with("/git-upload-pack") {
        let repo_path = path.trim_end_matches("/git-upload-pack");
        return git_upload_pack_inner(state, repo_path.to_string(), headers, body).await;
    }

    if path.ends_with("/git-receive-pack") {
        let repo_path = path.trim_end_matches("/git-receive-pack");
        return git_receive_pack_inner(state, repo_path.to_string(), headers, body).await;
    }

    // LFS Batch API: {repo}/info/lfs/objects/batch
    if path.ends_with("/info/lfs/objects/batch") {
        let repo_path = path.trim_end_matches("/info/lfs/objects/batch");
        // Parse JSON body
        match serde_json::from_slice(&body) {
            Ok(request) => {
                return super::lfs::lfs_batch(
                    State(state),
                    Path(repo_path.to_string()),
                    headers,
                    axum::Json(request),
                ).await;
            }
            Err(e) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                    .body(Body::from(format!("{{\"message\": \"Invalid JSON: {}\"}}", e)))
                    .unwrap();
            }
        }
    }

    // LFS verify: {repo}/info/lfs/verify
    if path.ends_with("/info/lfs/verify") {
        let repo_path = path.trim_end_matches("/info/lfs/verify");
        match serde_json::from_slice(&body) {
            Ok(request) => {
                return super::lfs::lfs_verify(
                    State(state),
                    Path(repo_path.to_string()),
                    headers,
                    axum::Json(request),
                ).await;
            }
            Err(e) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                    .body(Body::from(format!("{{\"message\": \"Invalid JSON: {}\"}}", e)))
                    .unwrap();
            }
        }
    }

    // Not a Git request
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not found"))
        .unwrap()
}

/// GET /:repo/info/refs - Reference advertisement (inner impl)
async fn info_refs_inner(
    state: Arc<AppState>,
    repo_path: String,
    query: InfoRefsQuery,
    headers: HeaderMap,
) -> Response {
    tracing::debug!("info_refs_inner called with repo_path: {}", repo_path);
    let repo_name = repo_path.trim_end_matches(".git");
    tracing::debug!("repo_name after trimming: {}", repo_name);
    let token = extract_auth(&headers, &state.auth);

    // Check read permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), repo_name, false) {
        if matches!(e, ServerError::AuthRequired) {
            return require_auth_response();
        }
        return e.into_response();
    }

    let service = match query.service.as_deref() {
        Some(s) => match GitService::from_str(s) {
            Some(svc) => svc,
            None => {
                return ServerError::InvalidRequest(format!("Unknown service: {}", s))
                    .into_response()
            }
        },
        None => {
            return ServerError::InvalidRequest("Missing service parameter".to_string())
                .into_response()
        }
    };

    // Get or create repository
    let repo = state.repos.get_or_create_repo(repo_name);

    let body = generate_ref_advertisement(&repo, service);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, service.content_type())
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .unwrap()
}

/// POST /:repo/git-upload-pack - Handle fetch/clone (inner impl)
async fn git_upload_pack_inner(
    state: Arc<AppState>,
    repo_path: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    tracing::debug!("git_upload_pack_inner: repo_path={}", repo_path);
    let repo_name = repo_path.trim_end_matches(".git");
    let token = extract_auth(&headers, &state.auth);

    // Check read permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), repo_name, false) {
        if matches!(e, ServerError::AuthRequired) {
            return require_auth_response();
        }
        return e.into_response();
    }

    let repo = match state.repos.get_repo(repo_name) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    match handle_upload_pack(&repo, &body) {
        Ok(response_body) => Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                GitService::UploadPack.result_content_type(),
            )
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(response_body))
            .unwrap(),
        Err(e) => e.into_response(),
    }
}

/// POST /:repo/git-receive-pack - Handle push (inner impl)
async fn git_receive_pack_inner(
    state: Arc<AppState>,
    repo_path: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    tracing::debug!("git_receive_pack_inner: repo_path={}", repo_path);
    let repo_name = repo_path.trim_end_matches(".git");
    let token = extract_auth(&headers, &state.auth);

    // Check write permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), repo_name, true) {
        if matches!(e, ServerError::AuthRequired) {
            return require_auth_response();
        }
        return e.into_response();
    }

    let repo = state.repos.get_or_create_repo(repo_name);

    match handle_receive_pack(&repo, &body) {
        Ok(response_body) => Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                GitService::ReceivePack.result_content_type(),
            )
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(response_body))
            .unwrap(),
        Err(e) => e.into_response(),
    }
}

/// GET /api/repos - List repositories
pub async fn list_repos(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let token = extract_auth(&headers, &state.auth);

    if token.is_none() && !state.auth.anonymous_read_allowed() {
        return require_auth_response();
    }

    let repos = state.repos.list_repos();
    let json = serde_json::json!({
        "repositories": repos
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap()
}

/// POST /api/repos/:repo - Create repository
pub async fn create_repo(
    State(state): State<Arc<AppState>>,
    Path(repo_name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = extract_auth(&headers, &state.auth);

    // Require write permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, true) {
        if matches!(e, ServerError::AuthRequired) {
            return require_auth_response();
        }
        return e.into_response();
    }

    match state.repos.create_repo(&repo_name) {
        Ok(_) => {
            let json = serde_json::json!({
                "message": format!("Repository '{}' created", repo_name),
                "name": repo_name
            });
            Response::builder()
                .status(StatusCode::CREATED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap()
        }
        Err(e) => e.into_response(),
    }
}

/// DELETE /api/repos/:repo - Delete repository
pub async fn delete_repo(
    State(state): State<Arc<AppState>>,
    Path(repo_name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = extract_auth(&headers, &state.auth);

    // Check admin permission
    if let Some(t) = &token {
        if !t.permissions.can_admin {
            return ServerError::PermissionDenied.into_response();
        }
    } else {
        return require_auth_response();
    }

    match state.repos.delete_repo(&repo_name) {
        Ok(_) => {
            let json = serde_json::json!({
                "message": format!("Repository '{}' deleted", repo_name)
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap()
        }
        Err(e) => e.into_response(),
    }
}

/// GET /api/repos/:repo/refs - List refs
pub async fn list_refs(
    State(state): State<Arc<AppState>>,
    Path(repo_name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = extract_auth(&headers, &state.auth);

    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false) {
        if matches!(e, ServerError::AuthRequired) {
            return require_auth_response();
        }
        return e.into_response();
    }

    let repo = match state.repos.get_repo(&repo_name) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    let refs: Vec<_> = repo
        .list_refs()
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "target": r.target.to_hex(),
                "symbolic": r.is_symbolic,
                "symbolic_target": r.symbolic_target
            })
        })
        .collect();

    let json = serde_json::json!({
        "refs": refs
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap()
}

/// POST /api/auth/login - Login and get token
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<LoginRequest>,
) -> Response {
    match state.auth.authenticate(&req.username, &req.password) {
        Ok(token) => {
            let json = serde_json::json!({
                "token": token.token,
                "username": token.username,
                "expires_at": token.expires_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap()
        }
        Err(e) => e.into_response(),
    }
}

/// GET /api/cas/stats - CAS statistics
pub async fn cas_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let token = extract_auth(&headers, &state.auth);

    if token.is_none() {
        return require_auth_response();
    }

    let stats = state.cas.stats();
    let lfs_stats = state.cas.lfs_stats();

    let json = serde_json::json!({
        "chunks": stats.chunk_count,
        "xorbs": stats.xorb_count,
        "reconstructions": stats.reconstruction_count,
        "shards": stats.shard_count,
        "lfs": {
            "objects": lfs_stats.object_count,
            "chunks": lfs_stats.chunk_count,
            "logical_size": lfs_stats.total_logical_size,
            "physical_size": lfs_stats.total_physical_size,
            "dedup_ratio": lfs_stats.dedup_ratio
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap()
}

/// Health check endpoint
pub async fn health() -> Response {
    let json = serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION")
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap()
}
