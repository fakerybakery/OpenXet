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
    /// Database connection (optional, for web UI features)
    pub db: Option<Arc<DatabaseConnection>>,
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
            db: None,
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
        let repos = RepositoryStore::with_db(storage_path.clone(), db.clone());

        // Load existing repositories from database
        repos.load_from_db().await?;

        // Start background worker for chunking/deduplication
        let process_tx = CasStore::start_background_worker(cas.clone());

        tracing::info!("Background CAS processing worker started");
        tracing::info!("Storage path: {:?}", storage_path);

        Ok(Self {
            repos,
            cas,
            auth: AuthManager::with_db(db.clone()),
            process_tx,
            db: Some(db),
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

/// Extract authentication from headers (async version)
async fn extract_auth(headers: &HeaderMap, auth: &AuthManager) -> Option<Token> {
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Basic ") {
                return auth.authenticate_basic(auth_str).await.ok();
            } else if auth_str.starts_with("Bearer ") {
                return auth.validate_bearer(auth_str).await.ok();
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
    let token = extract_auth(&headers, &state.auth).await;

    // Check read permission (always allowed for public repos)
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false).await {
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
    let token = extract_auth(&headers, &state.auth).await;

    // Check read permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false).await {
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
    let token = extract_auth(&headers, &state.auth).await;

    // Check write permission (must own repo or be org member)
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, true).await {
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
    let token = extract_auth(&headers, &state.auth).await;

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
    let token = extract_auth(&headers, &state.auth).await;

    // Require write permission (must be owner or org member)
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, true).await {
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
    let token = extract_auth(&headers, &state.auth).await;

    // Check write permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, true).await {
        if matches!(e, ServerError::AuthRequired) {
            return require_auth_response();
        }
        return e.into_response();
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
    let token = extract_auth(&headers, &state.auth).await;

    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false).await {
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

// ============================================================================
// Authentication Handlers
// ============================================================================

/// POST /api/auth/register - Register a new user
#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

/// Check if registration is disabled via environment variable
fn is_registration_disabled() -> bool {
    std::env::var("DISABLE_REGISTRATION")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<RegisterRequest>,
) -> Response {
    // Check if registration is disabled
    if is_registration_disabled() {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error": "Registration is currently closed"}"#))
            .unwrap();
    }

    match state.auth.register_user(&req.username, &req.password, req.email.as_deref()).await {
        Ok(user) => {
            let json = serde_json::json!({
                "message": "User registered successfully",
                "username": user.username,
                "id": user.id
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
    match state.auth.authenticate(&req.username, &req.password).await {
        Ok(token) => {
            let json = serde_json::json!({
                "token": token.token,
                "username": token.username,
                "user_id": token.user_id,
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

// ============================================================================
// Organization Handlers
// ============================================================================

/// POST /api/orgs - Create a new organization
#[derive(Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
}

pub async fn create_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<CreateOrgRequest>,
) -> Response {
    let token = match extract_auth(&headers, &state.auth).await {
        Some(t) => t,
        None => return require_auth_response(),
    };

    match state.auth.create_org(&req.name, token.user_id).await {
        Ok(org) => {
            let json = serde_json::json!({
                "message": "Organization created successfully",
                "name": org.username,
                "id": org.id
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

/// POST /api/orgs/:org/members - Add member to organization
#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub username: String,
    pub role: Option<String>,
}

pub async fn add_org_member(
    State(state): State<Arc<AppState>>,
    Path(org_name): Path<String>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<AddMemberRequest>,
) -> Response {
    let token = match extract_auth(&headers, &state.auth).await {
        Some(t) => t,
        None => return require_auth_response(),
    };

    // Get org
    let org = match state.auth.get_user_by_username(&org_name).await {
        Ok(Some(o)) if o.is_org => o,
        Ok(_) => return ServerError::NotFound.into_response(),
        Err(e) => return e.into_response(),
    };

    // Check if requester is org member (only members can add other members)
    match state.auth.is_org_member(org.id, token.user_id).await {
        Ok(true) => {}
        Ok(false) => return ServerError::PermissionDenied.into_response(),
        Err(e) => return e.into_response(),
    }

    // Get user to add
    let user = match state.auth.get_user_by_username(&req.username).await {
        Ok(Some(u)) if !u.is_org => u,
        Ok(_) => {
            return ServerError::InvalidRequest("User not found".to_string()).into_response()
        }
        Err(e) => return e.into_response(),
    };

    let role = req.role.as_deref().unwrap_or("member");

    match state.auth.add_org_member(org.id, user.id, role).await {
        Ok(()) => {
            let json = serde_json::json!({
                "message": format!("User '{}' added to organization '{}'", req.username, org_name)
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

/// DELETE /api/orgs/:org/members/:username - Remove member from organization
pub async fn remove_org_member(
    State(state): State<Arc<AppState>>,
    Path((org_name, username)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_auth(&headers, &state.auth).await {
        Some(t) => t,
        None => return require_auth_response(),
    };

    // Get org
    let org = match state.auth.get_user_by_username(&org_name).await {
        Ok(Some(o)) if o.is_org => o,
        Ok(_) => return ServerError::NotFound.into_response(),
        Err(e) => return e.into_response(),
    };

    // Check if requester is org member
    match state.auth.is_org_member(org.id, token.user_id).await {
        Ok(true) => {}
        Ok(false) => return ServerError::PermissionDenied.into_response(),
        Err(e) => return e.into_response(),
    }

    // Get user to remove
    let user = match state.auth.get_user_by_username(&username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ServerError::InvalidRequest("User not found".to_string()).into_response()
        }
        Err(e) => return e.into_response(),
    };

    match state.auth.remove_org_member(org.id, user.id).await {
        Ok(()) => {
            let json = serde_json::json!({
                "message": format!("User '{}' removed from organization '{}'", username, org_name)
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

/// GET /api/orgs/:org/members - List organization members
pub async fn get_org_members(
    State(state): State<Arc<AppState>>,
    Path(org_name): Path<String>,
) -> Response {
    // Get org
    let org = match state.auth.get_user_by_username(&org_name).await {
        Ok(Some(o)) if o.is_org => o,
        Ok(_) => return ServerError::NotFound.into_response(),
        Err(e) => return e.into_response(),
    };

    match state.auth.get_org_members(org.id).await {
        Ok(members) => {
            let member_list: Vec<_> = members
                .iter()
                .map(|(user, role)| {
                    serde_json::json!({
                        "username": user.username,
                        "id": user.id,
                        "role": role
                    })
                })
                .collect();

            let json = serde_json::json!({
                "organization": org_name,
                "members": member_list
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
    let token = extract_auth(&headers, &state.auth).await;

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
