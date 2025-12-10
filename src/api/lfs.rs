//! Git LFS Server Implementation with Xet/CAS Backend
//!
//! This implements the Git LFS Batch API (https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md)
//! and bridges large file storage to our CAS (Content Addressable Storage) backend.
//!
//! Supports both basic (single PUT) and multipart upload transfers.
//! Multipart is used for files >50MB to bypass CDN upload limits (e.g., Cloudflare's 100MB limit).

#![allow(dead_code)] // Some fields are part of the LFS protocol but not used internally

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::auth::{AuthManager, Token};
use super::handlers::AppState;
use crate::cas::ContentHash;

use once_cell::sync::Lazy;

/// Secret key for signing LFS URLs
/// MUST be set via LFS_URL_SECRET environment variable in production
static LFS_URL_SECRET: Lazy<Vec<u8>> = Lazy::new(|| {
    match std::env::var("LFS_URL_SECRET") {
        Ok(secret) if secret.len() >= 32 => secret.into_bytes(),
        Ok(secret) if !secret.is_empty() => {
            tracing::error!("LFS_URL_SECRET must be at least 32 characters");
            panic!("LFS_URL_SECRET must be at least 32 characters");
        }
        _ => {
            tracing::warn!("================================================");
            tracing::warn!("WARNING: LFS_URL_SECRET not set!");
            tracing::warn!("Using auto-generated secret (not persisted).");
            tracing::warn!("Set LFS_URL_SECRET env var in production.");
            tracing::warn!("================================================");
            // Generate a random secret for development
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut secret = vec![0u8; 32];
            rng.fill(&mut secret[..]);
            secret
        }
    }
});

/// URL signature validity in seconds
const LFS_URL_EXPIRY_SECS: u64 = 3600;

/// Multipart upload chunk size (10MB - small enough for Cloudflare to buffer quickly)
/// Smaller chunks = less buffering delay per request = faster uploads through CDN proxies
const MULTIPART_CHUNK_SIZE: u64 = 10 * 1024 * 1024;

/// Minimum file size for multipart upload (10MB)
/// Files smaller than this use basic single-PUT upload
const MULTIPART_THRESHOLD: u64 = 10 * 1024 * 1024;

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

/// Query parameters for signed LFS URLs
#[derive(Debug, Deserialize)]
pub struct LfsUrlParams {
    /// Expiry timestamp (Unix epoch seconds)
    pub expires: Option<u64>,
    /// HMAC signature
    pub sig: Option<String>,
    /// Part number for multipart uploads (1-indexed)
    pub part: Option<u32>,
}

/// Multipart completion request body
#[derive(Debug, Deserialize)]
pub struct MultipartCompleteRequest {
    /// OID of the complete file
    pub oid: String,
    /// Parts with their ETags (part numbers and hashes)
    pub parts: Vec<MultipartPart>,
}

/// A single part in multipart completion
#[derive(Debug, Deserialize)]
pub struct MultipartPart {
    /// Part number (1-indexed)
    #[serde(rename = "partNumber")]
    pub part_number: u32,
    /// ETag returned from part upload (we use the part's SHA256)
    pub etag: String,
}

/// Generate a signed URL for LFS operations
fn sign_lfs_url(base_url: &str, oid: &str, operation: &str) -> String {
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + LFS_URL_EXPIRY_SECS;

    let sig = generate_signature(oid, operation, expires);
    format!("{}?expires={}&sig={}", base_url, expires, sig)
}

/// Generate a signed URL for multipart part upload
fn sign_multipart_part_url(base_url: &str, oid: &str, part_num: u32) -> String {
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + LFS_URL_EXPIRY_SECS;

    let sig = generate_multipart_signature(oid, part_num, expires);
    format!("{}?expires={}&sig={}&part={}", base_url, expires, sig, part_num)
}

/// Generate HMAC signature for URL validation
fn generate_signature(oid: &str, operation: &str, expires: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&*LFS_URL_SECRET);
    hasher.update(oid.as_bytes());
    hasher.update(operation.as_bytes());
    hasher.update(expires.to_le_bytes());
    let result = hasher.finalize();
    // Use first 16 bytes, hex encoded (32 chars)
    result[..16].iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generate HMAC signature for multipart part URL validation
fn generate_multipart_signature(oid: &str, part_num: u32, expires: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&*LFS_URL_SECRET);
    hasher.update(oid.as_bytes());
    hasher.update(b"multipart");
    hasher.update(part_num.to_le_bytes());
    hasher.update(expires.to_le_bytes());
    let result = hasher.finalize();
    result[..16].iter().map(|b| format!("{:02x}", b)).collect()
}

/// Verify a multipart part URL signature
fn verify_multipart_signature(oid: &str, params: &LfsUrlParams) -> bool {
    let (expires, sig, part) = match (&params.expires, &params.sig, &params.part) {
        (Some(e), Some(s), Some(p)) => (*e, s.as_str(), *p),
        _ => return false,
    };

    // Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now > expires {
        tracing::debug!("Multipart URL signature expired");
        return false;
    }

    // Verify signature
    let expected = generate_multipart_signature(oid, part, expires);
    if sig != expected {
        tracing::debug!("Multipart URL signature mismatch");
        return false;
    }

    true
}

/// Verify a signed URL
fn verify_signature(oid: &str, operation: &str, params: &LfsUrlParams) -> bool {
    let (expires, sig) = match (&params.expires, &params.sig) {
        (Some(e), Some(s)) => (*e, s.as_str()),
        _ => return false,
    };

    // Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now > expires {
        tracing::debug!("LFS URL signature expired: now={} expires={}", now, expires);
        return false;
    }

    // Verify signature
    let expected = generate_signature(oid, operation, expires);
    if sig != expected {
        tracing::debug!("LFS URL signature mismatch");
        return false;
    }

    true
}

/// Extract auth token from headers (async)
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

/// POST /:owner/:repo/info/lfs/objects/batch - LFS Batch API
pub async fn lfs_batch(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<BatchRequest>,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);
    let token = extract_auth(&headers, &state.auth).await;

    // Check if client supports multipart uploads
    let supports_multipart = request
        .transfers
        .as_ref()
        .map(|t| t.iter().any(|s| s == "multipart"))
        .unwrap_or(false);

    tracing::debug!(
        "LFS batch request: repo={} op={} objects={} multipart={}",
        repo_name,
        request.operation,
        request.objects.len(),
        supports_multipart
    );

    // Check permissions
    let needs_write = request.operation == "upload";
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, needs_write).await {
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

    // Detect scheme from X-Forwarded-Proto (set by reverse proxy like nginx)
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_else(|| {
            // Fallback: check if host looks like it's behind HTTPS
            if host.ends_with(":443") || (!host.contains(':') && !host.starts_with("localhost")) {
                "https"
            } else {
                "http"
            }
        });

    // Get the authorization header to pass along to subsequent requests
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Determine if we should use multipart for uploads
    // Use multipart if: client supports it AND any object is large enough
    let use_multipart = supports_multipart
        && request.operation == "upload"
        && request.objects.iter().any(|o| o.size >= MULTIPART_THRESHOLD);

    // Process each object
    let mut responses = Vec::new();

    for obj in &request.objects {
        let response = match request.operation.as_str() {
            "download" => process_download_object(&state, obj, host, scheme, &repo_name, &auth_header),
            "upload" => {
                if use_multipart && obj.size >= MULTIPART_THRESHOLD {
                    process_multipart_upload_object(&state, obj, host, scheme, &repo_name)
                } else {
                    process_upload_object(&state, obj, host, scheme, &repo_name, &auth_header)
                }
            }
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
        transfer: if use_multipart { "multipart".to_string() } else { "basic".to_string() },
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
    _auth_header: &Option<String>,
) -> ObjectResponse {
    // Check if we have this object in CAS
    if let Some(hash) = ContentHash::from_hex(&obj.oid) {
        if state.cas.has_lfs_object(&hash) {
            let base_url = format!("{}://{}/{}.git/info/lfs/objects/{}", scheme, host, repo, obj.oid);
            let signed_url = sign_lfs_url(&base_url, &obj.oid, "download");
            return ObjectResponse {
                oid: obj.oid.clone(),
                size: obj.size,
                authenticated: Some(true),
                actions: Some(ObjectActions {
                    download: Some(ActionSpec {
                        href: signed_url,
                        header: None, // No headers needed - URL is signed
                        expires_in: Some(LFS_URL_EXPIRY_SECS),
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
    _auth_header: &Option<String>,
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

    // Generate signed URLs for upload and verify
    let upload_base = format!("{}://{}/{}.git/info/lfs/objects/{}", scheme, host, repo, obj.oid);
    let upload_url = sign_lfs_url(&upload_base, &obj.oid, "upload");

    let verify_base = format!("{}://{}/{}.git/info/lfs/verify/{}", scheme, host, repo, obj.oid);
    let verify_url = sign_lfs_url(&verify_base, &obj.oid, "verify");

    // Need upload
    ObjectResponse {
        oid: obj.oid.clone(),
        size: obj.size,
        authenticated: Some(true),
        actions: Some(ObjectActions {
            download: None,
            upload: Some(ActionSpec {
                href: upload_url,
                header: None, // No headers needed - URL is signed
                expires_in: Some(LFS_URL_EXPIRY_SECS),
            }),
            verify: Some(ActionSpec {
                href: verify_url,
                header: None, // No headers needed - URL is signed
                expires_in: Some(LFS_URL_EXPIRY_SECS),
            }),
        }),
        error: None,
    }
}

/// Process a multipart upload request for a large object
/// Returns upload URLs for each part, plus a completion URL
fn process_multipart_upload_object(
    state: &AppState,
    obj: &LfsObject,
    host: &str,
    scheme: &str,
    repo: &str,
) -> ObjectResponse {
    // Check if we already have this object
    if let Some(hash) = ContentHash::from_hex(&obj.oid) {
        if state.cas.has_lfs_object(&hash) {
            return ObjectResponse {
                oid: obj.oid.clone(),
                size: obj.size,
                authenticated: Some(true),
                actions: None, // No actions = already have it
                error: None,
            };
        }
    }

    // Calculate number of parts needed
    let num_parts = ((obj.size + MULTIPART_CHUNK_SIZE - 1) / MULTIPART_CHUNK_SIZE) as u32;

    // Base URL for part uploads (same endpoint, different signatures)
    let part_base = format!("{}://{}/{}.git/info/lfs/objects/{}", scheme, host, repo, obj.oid);

    // Completion URL (POST to finalize the upload)
    let completion_base = format!("{}://{}/{}.git/info/lfs/multipart/{}", scheme, host, repo, obj.oid);
    let completion_url = sign_lfs_url(&completion_base, &obj.oid, "multipart-complete");

    // Build header map with chunk_size and part URLs
    // HuggingFace client expects: { "chunk_size": "N", "1": "url1", "2": "url2", ... }
    let mut header_map = HashMap::new();
    header_map.insert("chunk_size".to_string(), MULTIPART_CHUNK_SIZE.to_string());

    for part_num in 1..=num_parts {
        let part_url = sign_multipart_part_url(&part_base, &obj.oid, part_num);
        header_map.insert(part_num.to_string(), part_url);
    }

    ObjectResponse {
        oid: obj.oid.clone(),
        size: obj.size,
        authenticated: Some(true),
        actions: Some(ObjectActions {
            download: None,
            upload: Some(ActionSpec {
                href: completion_url, // Completion endpoint
                header: Some(header_map), // Contains chunk_size and part URLs
                expires_in: Some(LFS_URL_EXPIRY_SECS),
            }),
            verify: None, // Verify happens as part of completion
        }),
        error: None,
    }
}

/// PUT /:owner/:repo/info/lfs/objects/:oid - Upload LFS object (streaming)
///
/// This handler streams the upload directly to disk without loading
/// the entire file into memory. Hash verification happens after upload.
/// After the raw file is written, it's queued for background chunking/dedup.
///
/// Also handles multipart part uploads when `part` query param is present.
/// Authentication is via signed URL (query params `expires` and `sig`).
pub async fn lfs_upload(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    Query(params): Query<LfsUrlParams>,
    headers: HeaderMap,
    request: axum::extract::Request,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);

    // Check if this is a multipart part upload
    if let Some(part_num) = params.part {
        return handle_multipart_part_upload(state, &oid, part_num, params, headers, request, &repo_name).await;
    }

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

    // Verify signed URL
    if !verify_signature(&oid, "upload", &params) {
        // Fall back to header-based auth if no valid signature
        let token = extract_auth(&headers, &state.auth).await;
        if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, true).await {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
                .body(Body::from(e.to_string()))
                .unwrap();
        }
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

    // Stream body to file FAST (no hashing during upload)
    let body_stream = request.into_body();

    match stream_to_file_fast(body_stream, &raw_path).await {
        Ok(total_size) => {
            tracing::info!(
                "LFS upload received: oid={} size={} - verifying hash...",
                oid,
                total_size
            );

            // Verify hash in blocking thread pool (doesn't block async runtime)
            match hash_file_blocking(raw_path.clone()).await {
                Ok(computed_hash) => {
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
                        "LFS object stored: oid={} size={} - queued for background processing",
                        oid,
                        total_size
                    );

                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap()
                }
                Err(e) => {
                    let _ = tokio::fs::remove_file(&raw_path).await;
                    tracing::error!("Hash verification failed: {}", e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(format!("Hash verification failed: {}", e)))
                        .unwrap()
                }
            }
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

/// Stream request body to file (no hashing - maximum speed)
/// Returns total_bytes_written
async fn stream_to_file_fast(
    body: axum::body::Body,
    path: &std::path::Path,
) -> Result<u64, String> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;

    let start = std::time::Instant::now();
    tracing::debug!("stream_to_file_fast: starting for {:?}", path);

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("Failed to create file: {}", e))?;

    tracing::debug!("stream_to_file_fast: file created in {:?}", start.elapsed());

    let mut total_written = 0u64;
    let mut chunk_count = 0u64;
    let mut stream = http_body_util::BodyStream::new(body);

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| format!("Error reading body: {}", e))?;
        // into_data() returns Err for trailers/non-data frames - skip those
        if let Ok(data) = chunk.into_data() {
            file.write_all(&data)
                .await
                .map_err(|e| format!("Failed to write to file: {}", e))?;

            total_written += data.len() as u64;
            chunk_count += 1;

            // Log progress every 10MB
            if total_written % (10 * 1024 * 1024) < data.len() as u64 {
                tracing::debug!(
                    "stream_to_file_fast: received {} MB in {:?}",
                    total_written / (1024 * 1024),
                    start.elapsed()
                );
            }
        }
    }

    file.flush()
        .await
        .map_err(|e| format!("Failed to flush file: {}", e))?;

    let elapsed = start.elapsed();
    let speed_mbps = if elapsed.as_secs_f64() > 0.0 {
        (total_written as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64()
    } else {
        0.0
    };

    tracing::info!(
        "stream_to_file_fast: wrote {} bytes in {} chunks, {:.1} MB/s, {:?}",
        total_written, chunk_count, speed_mbps, elapsed
    );

    Ok(total_written)
}

/// Hash a file in a blocking thread pool (doesn't block async runtime)
async fn hash_file_blocking(path: std::path::PathBuf) -> Result<ContentHash, String> {
    tokio::task::spawn_blocking(move || {
        use sha2::{Sha256, Digest};
        use std::io::Read;

        let mut file = std::fs::File::open(&path)
            .map_err(|e| format!("Failed to open file for hashing: {}", e))?;

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 8 * 1024 * 1024]; // 8MB read buffer

        loop {
            let n = file.read(&mut buffer)
                .map_err(|e| format!("Failed to read file: {}", e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);

        Ok(ContentHash::from_raw(hash_bytes))
    })
    .await
    .map_err(|e| format!("Hash task panicked: {}", e))?
}

/// GET /:owner/:repo/info/lfs/objects/:oid - Download LFS object (streaming)
///
/// Streams the object from disk without loading it entirely into memory.
/// Works with both raw (not yet chunked) and chunked objects.
///
/// Authentication is via signed URL (query params `expires` and `sig`).
pub async fn lfs_download(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    Query(params): Query<LfsUrlParams>,
    headers: HeaderMap,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);

    tracing::debug!("LFS download (streaming): repo={} oid={}", repo_name, oid);

    // Verify signed URL
    if !verify_signature(&oid, "download", &params) {
        // Fall back to header-based auth if no valid signature
        let token = extract_auth(&headers, &state.auth).await;
        if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false).await {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
                .body(Body::from(e.to_string()))
                .unwrap();
        }
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
    let token = extract_auth(&headers, &state.auth).await;

    tracing::debug!("LFS verify: repo={} oid={} size={}", repo_name, obj.oid, obj.size);

    // Check permission
    if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false).await {
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

/// POST /:owner/:repo/info/lfs/verify/:oid - Verify uploaded object (signed URL version)
pub async fn lfs_verify_signed(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    Query(params): Query<LfsUrlParams>,
    headers: HeaderMap,
    Json(obj): Json<LfsObject>,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);

    tracing::debug!("LFS verify (signed): repo={} oid={} size={}", repo_name, obj.oid, obj.size);

    // Verify signed URL
    if !verify_signature(&oid, "verify", &params) {
        // Fall back to header-based auth if no valid signature
        let token = extract_auth(&headers, &state.auth).await;
        if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, false).await {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
                .body(Body::from(e.to_string()))
                .unwrap();
        }
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

// ============================================================================
// Multipart Upload Handlers
// ============================================================================

/// Get the path for storing multipart upload parts
fn multipart_part_path(storage_path: &std::path::Path, oid: &str, part_num: u32) -> std::path::PathBuf {
    storage_path
        .join("multipart")
        .join(&oid[..2])
        .join(oid)
        .join(format!("part_{:05}", part_num))
}

/// Handle multipart part upload - streams part to disk FAST (no hashing during upload)
/// Returns immediately with a dummy ETag. Hash verification happens at completion time.
async fn handle_multipart_part_upload(
    state: Arc<AppState>,
    oid: &str,
    part_num: u32,
    params: LfsUrlParams,
    headers: HeaderMap,
    request: axum::extract::Request,
    repo_name: &str,
) -> Response {
    // Verify multipart signature
    if !verify_multipart_signature(oid, &params) {
        let token = extract_auth(&headers, &state.auth).await;
        if let Err(e) = state.auth.check_permission(token.as_ref(), repo_name, true).await {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
                .body(Body::from(e.to_string()))
                .unwrap();
        }
    }

    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    tracing::info!(
        "Multipart part upload: oid={} part={} size={}",
        oid, part_num, content_length
    );

    // Get part file path
    let part_path = multipart_part_path(&state.cas.storage_path(), oid, part_num);

    // Stream body to part file FAST - no hashing during upload!
    // Hash verification happens at completion time on the assembled file.
    let body_stream = request.into_body();

    match stream_to_file_fast(body_stream, &part_path).await {
        Ok(size) => {
            tracing::info!(
                "Multipart part stored: oid={} part={} size={}",
                oid, part_num, size
            );

            // Return a dummy ETag - HF client doesn't actually verify part ETags,
            // it just needs them for the completion request. We verify the full
            // file hash at completion time which is what actually matters.
            Response::builder()
                .status(StatusCode::OK)
                .header("ETag", format!("\"part{}\"", part_num))
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&part_path).await;
            tracing::error!("Multipart part upload failed: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                .body(Body::from(
                    serde_json::json!({
                        "message": format!("Part upload failed: {}", e)
                    })
                    .to_string(),
                ))
                .unwrap()
        }
    }
}

/// Stream to file while computing SHA256 hash - returns (size, hash_hex)
async fn stream_to_file_with_hash(
    body: axum::body::Body,
    path: &std::path::Path,
) -> Result<(u64, String), String> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;

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
        if let Ok(data) = chunk.into_data() {
            hasher.update(&data);
            file.write_all(&data)
                .await
                .map_err(|e| format!("Failed to write to file: {}", e))?;
            total_written += data.len() as u64;
        }
    }

    file.flush()
        .await
        .map_err(|e| format!("Failed to flush file: {}", e))?;

    let hash = hasher.finalize();
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    Ok((total_written, hash_hex))
}

/// POST /:owner/:repo/info/lfs/multipart/:oid - Complete multipart upload
///
/// Assembles all parts into the final file, verifies hash, and registers with CAS.
/// This is called by the client after all parts have been uploaded.
pub async fn lfs_multipart_complete(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    Query(params): Query<LfsUrlParams>,
    headers: HeaderMap,
    Json(req): Json<MultipartCompleteRequest>,
) -> Response {
    let repo_name_raw = repo.trim_end_matches(".git");
    let repo_name = format!("{}/{}", owner, repo_name_raw);

    tracing::info!(
        "Multipart complete: oid={} parts={}",
        oid,
        req.parts.len()
    );

    // Verify signed URL
    if !verify_signature(&oid, "multipart-complete", &params) {
        let token = extract_auth(&headers, &state.auth).await;
        if let Err(e) = state.auth.check_permission(token.as_ref(), &repo_name, true).await {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::WWW_AUTHENTICATE, "Basic realm=\"Git LFS\"")
                .body(Body::from(e.to_string()))
                .unwrap();
        }
    }

    // Parse expected OID
    let expected_hash = match ContentHash::from_hex(&oid) {
        Some(h) => h,
        None => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid OID"))
                .unwrap();
        }
    };

    // Sort parts by part number
    let mut parts = req.parts;
    parts.sort_by_key(|p| p.part_number);

    // Verify we have all parts (should be sequential from 1)
    for (i, part) in parts.iter().enumerate() {
        if part.part_number != (i + 1) as u32 {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                .body(Body::from(
                    serde_json::json!({
                        "message": format!("Missing part {}", i + 1)
                    })
                    .to_string(),
                ))
                .unwrap();
        }
    }

    // Assemble parts into final file (in blocking thread to avoid blocking async runtime)
    let storage_path = state.cas.storage_path().to_path_buf();
    let raw_path = state.cas.raw_object_path(&expected_hash);
    let raw_path_for_assembly = raw_path.clone();
    let oid_clone = oid.clone();
    let num_parts = parts.len();

    let assembly_result = tokio::task::spawn_blocking(move || {
        assemble_multipart_parts(&storage_path, &oid_clone, num_parts, &raw_path_for_assembly)
    })
    .await;

    let total_size = match assembly_result {
        Ok(Ok(size)) => size,
        Ok(Err(e)) => {
            tracing::error!("Failed to assemble parts: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/vnd.git-lfs+json")
                .body(Body::from(
                    serde_json::json!({
                        "message": format!("Failed to assemble parts: {}", e)
                    })
                    .to_string(),
                ))
                .unwrap();
        }
        Err(e) => {
            tracing::error!("Assembly task panicked: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Assembly failed"))
                .unwrap();
        }
    };

    // Verify final hash
    match hash_file_blocking(raw_path.clone()).await {
        Ok(computed_hash) => {
            if computed_hash != expected_hash {
                let _ = tokio::fs::remove_file(&raw_path).await;
                // Clean up parts
                let _ = cleanup_multipart_parts(&state.cas.storage_path(), &oid).await;

                tracing::warn!(
                    "Multipart OID mismatch: expected {}, got {}",
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

            // Clean up part files
            let _ = cleanup_multipart_parts(&state.cas.storage_path(), &oid).await;

            tracing::info!(
                "Multipart upload complete: oid={} size={} - queued for processing",
                oid,
                total_size
            );

            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&raw_path).await;
            let _ = cleanup_multipart_parts(&state.cas.storage_path(), &oid).await;
            tracing::error!("Hash verification failed: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Hash verification failed: {}", e)))
                .unwrap()
        }
    }
}

/// Assemble multipart parts into final file (blocking)
fn assemble_multipart_parts(
    storage_path: &std::path::Path,
    oid: &str,
    num_parts: usize,
    output_path: &std::path::Path,
) -> Result<u64, String> {
    use std::io::{Read, Write};

    // Create output directory
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
    }

    let mut output = std::fs::File::create(output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;

    let mut total_size = 0u64;
    let mut buffer = vec![0u8; 8 * 1024 * 1024]; // 8MB buffer

    for part_num in 1..=num_parts {
        let part_path = multipart_part_path(storage_path, oid, part_num as u32);
        let mut part_file = std::fs::File::open(&part_path)
            .map_err(|e| format!("Failed to open part {}: {}", part_num, e))?;

        loop {
            let n = part_file
                .read(&mut buffer)
                .map_err(|e| format!("Failed to read part {}: {}", part_num, e))?;
            if n == 0 {
                break;
            }
            output
                .write_all(&buffer[..n])
                .map_err(|e| format!("Failed to write: {}", e))?;
            total_size += n as u64;
        }
    }

    output.flush().map_err(|e| format!("Failed to flush: {}", e))?;

    Ok(total_size)
}

/// Clean up multipart part files
async fn cleanup_multipart_parts(storage_path: &std::path::Path, oid: &str) -> Result<(), String> {
    let parts_dir = storage_path
        .join("multipart")
        .join(&oid[..2])
        .join(oid);

    if parts_dir.exists() {
        tokio::fs::remove_dir_all(&parts_dir)
            .await
            .map_err(|e| format!("Failed to clean up parts: {}", e))?;
    }

    Ok(())
}
