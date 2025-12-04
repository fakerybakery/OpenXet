use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use sea_orm::DatabaseConnection;
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
        let cas = Arc::new(CasStore::with_storage_path(storage_path.clone()));

        // Create RepositoryStore with same storage path
        let repos = RepositoryStore::with_storage_path(storage_path.clone());

        // Start background worker for chunking/deduplication
        let process_tx = CasStore::start_background_worker(cas.clone());

        tracing::info!("Background CAS processing worker started");
        tracing::info!("Storage path: {:?}", storage_path);

        Self {
            repos,
            cas,
            auth: AuthManager::new(),
            process_tx,
        }
    }

    /// Create AppState with database connection for persistence
    pub async fn with_db(storage_path: std::path::PathBuf, db: Arc<DatabaseConnection>) -> crate::error::Result<Self> {
        // Create CasStore with database connection
        let mut cas = CasStore::with_storage_path(storage_path.clone());
        cas.set_db(db.clone());
        cas.load_from_db().await?;
        let cas = Arc::new(cas);

        // Create RepositoryStore with database connection
        let repos = RepositoryStore::with_db(storage_path.clone(), db);

        // Load existing repositories from database
        repos.load_from_db().await?;

        // Start background worker for chunking/deduplication
        let process_tx = CasStore::start_background_worker(cas.clone());

        tracing::info!("Background CAS processing worker started");
        tracing::info!("Storage path: {:?}", storage_path);

        Ok(Self {
            repos,
            cas,
            auth: AuthManager::new(),
            process_tx,
        })
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

// ============================================================================
// Git Smart HTTP Handlers (typed routes)
// ============================================================================

/// GET /:owner/:repo/info/refs - Reference advertisement
pub async fn git_info_refs(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);
    tracing::debug!("git_info_refs: repo_name={}", repo_name);
    let token = extract_auth(&headers, &state.auth);

    // Check read permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false) {
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
    let repo = state.repos.get_or_create_repo(&repo_name);

    let body = generate_ref_advertisement(&repo, service);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, service.content_type())
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .unwrap()
}

/// POST /:owner/:repo/git-upload-pack - Handle fetch/clone
pub async fn git_upload_pack(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);
    tracing::debug!("git_upload_pack: repo_name={}", repo_name);
    let token = extract_auth(&headers, &state.auth);

    // Check read permission
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

/// POST /:owner/:repo/git-receive-pack - Handle push
pub async fn git_receive_pack(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);
    tracing::debug!("git_receive_pack: repo_name={}", repo_name);
    let token = extract_auth(&headers, &state.auth);

    // Check write permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, true) {
        if matches!(e, ServerError::AuthRequired) {
            return require_auth_response();
        }
        return e.into_response();
    }

    let repo = state.repos.get_or_create_repo(&repo_name);

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

/// POST /api/repos/:owner/:repo - Create repository
pub async fn create_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = format!("{}/{}", owner, repo);
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

/// DELETE /api/repos/:owner/:repo - Delete repository
pub async fn delete_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = format!("{}/{}", owner, repo);
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

/// GET /api/repos/:owner/:repo/refs - List refs
pub async fn list_refs(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = format!("{}/{}", owner, repo);
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
        "blocks": stats.block_count,
        "reconstructions": stats.reconstruction_count,
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
