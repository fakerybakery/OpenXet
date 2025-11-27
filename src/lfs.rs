//! Git LFS Server Implementation with Xet/CAS Backend
//!
//! This implements the Git LFS Batch API (https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md)
//! and bridges large file storage to our CAS (Content Addressable Storage) backend.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::auth::{AuthManager, Token};
use crate::cas::{CasStore, Chunk, ContentHash, Chunker};
use crate::handlers::AppState;

/// LFS Batch Request
#[derive(Debug, Deserialize)]
pub struct BatchRequest {
    pub operation: String, // "download" or "upload"
    pub transfers: Option<Vec<String>>,
    pub objects: Vec<LfsObject>,
    #[serde(rename = "ref")]
    pub git_ref: Option<GitRef>,
}

#[derive(Debug, Deserialize)]
pub struct GitRef {
    pub name: String,
}

/// LFS Object reference
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LfsObject {
    pub oid: String,  // SHA-256 hash of the content
    pub size: u64,
}

/// LFS Batch Response
#[derive(Debug, Serialize)]
pub struct BatchResponse {
    pub transfer: String,
    pub objects: Vec<ObjectResponse>,
}

/// Response for a single object
#[derive(Debug, Serialize)]
pub struct ObjectResponse {
    pub oid: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<ObjectActions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ObjectError>,
}

#[derive(Debug, Serialize)]
pub struct ObjectActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<ActionSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<ActionSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<ActionSpec>,
}

#[derive(Debug, Serialize)]
pub struct ActionSpec {
    pub href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ObjectError {
    pub code: u16,
    pub message: String,
}

/// Extract auth token from headers
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

/// POST /:repo/info/lfs/objects/batch - LFS Batch API
pub async fn lfs_batch(
    State(state): State<Arc<AppState>>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    Json(request): Json<BatchRequest>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let token = extract_auth(&headers, &state.auth);

    tracing::debug!(
        "LFS batch request: repo={} op={} objects={}",
        repo_name,
        request.operation,
        request.objects.len()
    );

    // Check permissions
    let needs_write = request.operation == "upload";
    if let Err(e) = state.auth.check_permission(token.as_ref(), repo_name, needs_write) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
            .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
            .body(Body::from(
                serde_json::json!({
                    "message": e.to_string(),
                    "request_id": uuid::Uuid::new_v4().to_string()
                })
                .to_string(),
            ))
            .unwrap();
    }

    // Get the host from headers for building URLs
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080");

    let scheme = "http"; // In production, detect from X-Forwarded-Proto

    // Get the authorization header to pass along to subsequent requests
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Process each object
    let mut responses = Vec::new();

    for obj in request.objects {
        let response = match request.operation.as_str() {
            "download" => process_download_object(&state, &obj, host, scheme, repo_name, &auth_header),
            "upload" => process_upload_object(&state, &obj, host, scheme, repo_name, &auth_header),
            _ => ObjectResponse {
                oid: obj.oid.clone(),
                size: obj.size,
                authenticated: Some(true),
                actions: None,
                error: Some(ObjectError {
                    code: 400,
                    message: format!("Unknown operation: {}", request.operation),
                }),
            },
        };
        responses.push(response);
    }

    let batch_response = BatchResponse {
        transfer: "basic".to_string(),
        objects: responses,
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
        .body(Body::from(serde_json::to_string(&batch_response).unwrap()))
        .unwrap()
}

/// Build auth headers map for LFS actions
fn build_auth_headers(auth_header: &Option<String>) -> Option<std::collections::HashMap<String, String>> {
    auth_header.as_ref().map(|auth| {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".to_string(), auth.clone());
        headers
    })
}

/// Process a download request for an object
fn process_download_object(
    state: &AppState,
    obj: &LfsObject,
    host: &str,
    scheme: &str,
    repo: &str,
    auth_header: &Option<String>,
) -> ObjectResponse {
    // Check if we have this object in CAS
    if let Some(hash) = ContentHash::from_hex(&obj.oid) {
        if state.cas.has_lfs_object(&hash) {
            return ObjectResponse {
                oid: obj.oid.clone(),
                size: obj.size,
                authenticated: Some(true),
                actions: Some(ObjectActions {
                    download: Some(ActionSpec {
                        href: format!("{}://{}/{}.git/info/lfs/objects/{}", scheme, host, repo, obj.oid),
                        header: build_auth_headers(auth_header),
                        expires_in: Some(3600),
                    }),
                    upload: None,
                    verify: None,
                }),
                error: None,
            };
        }
    }

    // Object not found
    ObjectResponse {
        oid: obj.oid.clone(),
        size: obj.size,
        authenticated: Some(true),
        actions: None,
        error: Some(ObjectError {
            code: 404,
            message: "Object not found".to_string(),
        }),
    }
}

/// Process an upload request for an object
fn process_upload_object(
    state: &AppState,
    obj: &LfsObject,
    host: &str,
    scheme: &str,
    repo: &str,
    auth_header: &Option<String>,
) -> ObjectResponse {
    // Check if we already have this object
    if let Some(hash) = ContentHash::from_hex(&obj.oid) {
        if state.cas.has_lfs_object(&hash) {
            // Already exists, no upload needed
            return ObjectResponse {
                oid: obj.oid.clone(),
                size: obj.size,
                authenticated: Some(true),
                actions: None, // No actions = already have it
                error: None,
            };
        }
    }

    // Need upload
    ObjectResponse {
        oid: obj.oid.clone(),
        size: obj.size,
        authenticated: Some(true),
        actions: Some(ObjectActions {
            download: None,
            upload: Some(ActionSpec {
                href: format!("{}://{}/{}.git/info/lfs/objects/{}", scheme, host, repo, obj.oid),
                header: build_auth_headers(auth_header),
                expires_in: Some(3600),
            }),
            verify: Some(ActionSpec {
                href: format!("{}://{}/{}.git/info/lfs/verify", scheme, host, repo),
                header: build_auth_headers(auth_header),
                expires_in: Some(3600),
            }),
        }),
        error: None,
    }
}

/// PUT /:repo/info/lfs/objects/:oid - Upload LFS object
pub async fn lfs_upload(
    State(state): State<Arc<AppState>>,
    Path((repo, oid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let token = extract_auth(&headers, &state.auth);

    let body_len = body.len();
    tracing::info!("LFS upload starting: repo={} oid={} size={}", repo_name, oid, body_len);

    // Check write permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), repo_name, true) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
            .body(Body::from(e.to_string()))
            .unwrap();
    }

    // Verify the OID matches the content (do in blocking task for large files)
    let body_clone = body.clone();
    let oid_clone = oid.clone();
    let hash_result = tokio::task::spawn_blocking(move || {
        let computed_hash = ContentHash::from_data(&body_clone);
        (computed_hash, computed_hash.to_hex() == oid_clone)
    })
    .await;

    let (computed_hash, hash_matches) = match hash_result {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Hash computation failed: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Hash computation failed"))
                .unwrap();
        }
    };

    if !hash_matches {
        tracing::warn!("OID mismatch: expected {}, got {}", oid, computed_hash.to_hex());
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
            .body(Body::from(
                serde_json::json!({
                    "message": format!("OID mismatch: expected {}, got {}", oid, computed_hash.to_hex())
                })
                .to_string(),
            ))
            .unwrap();
    }

    // Store in CAS with chunking for deduplication (also in blocking task)
    let state_clone = state.clone();
    let store_result = tokio::task::spawn_blocking(move || {
        state_clone.cas.store_lfs_object(computed_hash, body)
    })
    .await;

    let chunk_hashes = match store_result {
        Ok(hashes) => hashes,
        Err(e) => {
            tracing::error!("Storage failed: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Storage failed"))
                .unwrap();
        }
    };

    tracing::info!(
        "LFS object stored: oid={} size={} chunks={}",
        oid,
        body_len,
        chunk_hashes.len()
    );

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

/// GET /:repo/info/lfs/objects/:oid - Download LFS object
pub async fn lfs_download(
    State(state): State<Arc<AppState>>,
    Path((repo, oid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let token = extract_auth(&headers, &state.auth);

    tracing::debug!("LFS download: repo={} oid={}", repo_name, oid);

    // Check read permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), repo_name, false) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
            .body(Body::from(e.to_string()))
            .unwrap();
    }

    // Get from CAS
    let hash = match ContentHash::from_hex(&oid) {
        Some(h) => h,
        None => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid OID"))
                .unwrap();
        }
    };

    match state.cas.get_lfs_object(&hash) {
        Some(data) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, data.len().to_string())
            .body(Body::from(data))
            .unwrap(),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
            .body(Body::from(
                serde_json::json!({
                    "message": "Object not found"
                })
                .to_string(),
            ))
            .unwrap(),
    }
}

/// POST /:repo/info/lfs/verify - Verify uploaded object
pub async fn lfs_verify(
    State(state): State<Arc<AppState>>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    Json(obj): Json<LfsObject>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let token = extract_auth(&headers, &state.auth);

    tracing::debug!("LFS verify: repo={} oid={} size={}", repo_name, obj.oid, obj.size);

    // Check permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), repo_name, false) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
            .body(Body::from(e.to_string()))
            .unwrap();
    }

    // Check if object exists
    let hash = match ContentHash::from_hex(&obj.oid) {
        Some(h) => h,
        None => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid OID"))
                .unwrap();
        }
    };

    if state.cas.has_lfs_object(&hash) {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
            .body(Body::from(
                serde_json::json!({
                    "message": "Object not found"
                })
                .to_string(),
            ))
            .unwrap()
    }
}
