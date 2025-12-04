//! Git LFS Server Implementation with Xet/CAS Backend
//!
//! This implements the Git LFS Batch API (https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md)
//! and bridges large file storage to our CAS (Content Addressable Storage) backend.

#![allow(dead_code)] // Some fields are part of the LFS protocol but not used internally

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};

use super::auth::{AuthManager, Token};
use super::handlers::AppState;
use crate::cas::ContentHash;

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

/// POST /:owner/:repo/info/lfs/objects/batch - LFS Batch API
pub async fn lfs_batch(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<BatchRequest>,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);
    let token = extract_auth(&headers, &state.auth);

    tracing::debug!(
        "LFS batch request: repo={} op={} objects={}",
        repo_name,
        request.operation,
        request.objects.len()
    );

    // Check permissions
    let needs_write = request.operation == "upload";
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, needs_write) {
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
            "download" => process_download_object(&state, &obj, host, scheme, &repo_name, &auth_header),
            "upload" => process_upload_object(&state, &obj, host, scheme, &repo_name, &auth_header),
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

/// PUT /:owner/:repo/info/lfs/objects/:oid - Upload LFS object (streaming)
///
/// This handler streams the upload directly to disk without loading
/// the entire file into memory. Hash verification happens during streaming.
/// After the raw file is written, it's queued for background chunking/dedup.
pub async fn lfs_upload(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
    request: axum::extract::Request,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);
    let token = extract_auth(&headers, &state.auth);

    // Get content-length if available (for logging)
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    tracing::info!(
        "LFS upload starting (streaming): repo={} oid={} expected_size={}",
        repo_name, oid, content_length
    );

    // Check write permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, true) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
            .body(Body::from(e.to_string()))
            .unwrap();
    }

    // Parse the expected OID
    let expected_hash = match ContentHash::from_hex(&oid) {
        Some(h) => h,
        None => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                .body(Body::from(
                    serde_json::json!({
                        "message": "Invalid OID format"
                    })
                    .to_string(),
                ))
                .unwrap();
        }
    };

    // Get raw file path
    let raw_path = state.cas.raw_object_path(&expected_hash);

    // Stream body to file while computing hash
    let body_stream = request.into_body();

    match stream_to_file_with_hash(body_stream, &raw_path).await {
        Ok((computed_hash, total_size)) => {
            // Verify hash matches
            if computed_hash != expected_hash {
                // Clean up the file
                let _ = tokio::fs::remove_file(&raw_path).await;

                tracing::warn!(
                    "OID mismatch: expected {}, got {}",
                    expected_hash.to_hex(),
                    computed_hash.to_hex()
                );
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                    .body(Body::from(
                        serde_json::json!({
                            "message": format!(
                                "OID mismatch: expected {}, got {}",
                                expected_hash.to_hex(),
                                computed_hash.to_hex()
                            )
                        })
                        .to_string(),
                    ))
                    .unwrap();
            }

            // Register with CAS
            state.cas.register_raw_object(expected_hash, total_size, raw_path);

            // Queue for background chunking/deduplication
            state.queue_for_processing(expected_hash);

            tracing::info!(
                "LFS object stored raw (streaming): oid={} size={} - queued for background processing",
                oid,
                total_size
            );

            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            // Clean up partial file
            let _ = tokio::fs::remove_file(&raw_path).await;

            tracing::error!("LFS upload failed: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                .body(Body::from(
                    serde_json::json!({
                        "message": format!("Upload failed: {}", e)
                    })
                    .to_string(),
                ))
                .unwrap()
        }
    }
}

/// Stream request body to file while computing SHA-256 hash
/// Returns (computed_hash, total_bytes_written)
async fn stream_to_file_with_hash(
    body: axum::body::Body,
    path: &std::path::Path,
) -> Result<(ContentHash, u64), String> {
    use futures::StreamExt;
    use sha2::{Sha256, Digest};
    use tokio::io::AsyncWriteExt;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("Failed to create file: {}", e))?;

    let mut hasher = Sha256::new();
    let mut total_written = 0u64;

    let mut stream = http_body_util::BodyStream::new(body);

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| format!("Error reading body: {}", e))?;
        let data = chunk.into_data().map_err(|_| "Failed to get frame data")?;

        // Update hash
        hasher.update(&data);

        // Write to file
        file.write_all(&data)
            .await
            .map_err(|e| format!("Failed to write to file: {}", e))?;

        total_written += data.len() as u64;
    }

    file.sync_all()
        .await
        .map_err(|e| format!("Failed to sync file: {}", e))?;

    // Compute final hash
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result);

    Ok((ContentHash::from_raw(hash_bytes), total_written))
}

/// GET /:owner/:repo/info/lfs/objects/:oid - Download LFS object (streaming)
///
/// Streams the object from disk without loading it entirely into memory.
/// Works with both raw (not yet chunked) and chunked objects.
pub async fn lfs_download(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);
    let token = extract_auth(&headers, &state.auth);

    tracing::debug!("LFS download (streaming): repo={} oid={}", repo_name, oid);

    // Check read permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
            .body(Body::from(e.to_string()))
            .unwrap();
    }

    // Parse OID
    let hash = match ContentHash::from_hex(&oid) {
        Some(h) => h,
        None => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid OID"))
                .unwrap();
        }
    };

    // Get object size for Content-Length header
    let size = match state.cas.get_lfs_object_size(&hash) {
        Some(s) => s,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                .body(Body::from(
                    serde_json::json!({
                        "message": "Object not found"
                    })
                    .to_string(),
                ))
                .unwrap();
        }
    };

    // Get the source for streaming
    match state.cas.get_lfs_object_source(&hash) {
        Some(crate::cas::store::LfsObjectSource::RawFile(path)) => {
            // Stream from raw file
            match stream_file_response(path, size).await {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!("Failed to stream file: {}", e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Failed to read file"))
                        .unwrap()
                }
            }
        }
        Some(crate::cas::store::LfsObjectSource::Blocks(_file_hash)) => {
            // Reconstruct from Blocks using parallel streaming (HIGH PERFORMANCE)
            // This is how we achieve ~5 GB/s download speeds:
            // - Fetch multiple block ranges in parallel (32 concurrent by default)
            // - Stream bytes directly to client without buffering entire file
            match state.cas.reconstruct_file_stream(&hash, crate::cas::store::DEFAULT_FETCH_PARALLELISM) {
                Some(stream) => {
                    let total_size = stream.total_size;
                    let body = Body::from_stream(stream.into_stream());
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .header(header::CONTENT_LENGTH, total_size.to_string())
                        .body(body)
                        .unwrap()
                }
                None => Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Failed to reconstruct object"))
                    .unwrap(),
            }
        }
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

/// Stream a file as HTTP response
async fn stream_file_response(
    path: std::path::PathBuf,
    size: u64,
) -> Result<Response, std::io::Error> {
    use tokio_util::io::ReaderStream;

    let file = tokio::fs::File::open(&path).await?;
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, size.to_string())
        .body(body)
        .unwrap())
}

/// POST /:owner/:repo/info/lfs/verify - Verify uploaded object
pub async fn lfs_verify(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Json(obj): Json<LfsObject>,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);
    let token = extract_auth(&headers, &state.auth);

    tracing::debug!("LFS verify: repo={} oid={} size={}", repo_name, obj.oid, obj.size);

    // Check permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false) {
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
