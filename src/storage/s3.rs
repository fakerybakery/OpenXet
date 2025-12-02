//! S3-compatible storage backend.
//!
//! Provides high-performance storage using S3 with:
//! - Efficient byte range requests (HTTP Range header)
//! - Connection pooling for parallel fetches
//! - Compatible with AWS S3, MinIO, R2, etc.

use async_trait::async_trait;
use aws_sdk_s3::{
    config::{Builder, Credentials, Region},
    primitives::ByteStream,
    Client,
};
use bytes::Bytes;
use std::ops::Range;
use std::path::Path;

use super::backend::{StorageBackend, StorageError, StorageResult};

/// S3 storage backend configuration
#[derive(Clone, Debug)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// Optional prefix for all keys (e.g., "repos/myrepo/")
    pub prefix: Option<String>,
    /// AWS region
    pub region: String,
    /// Custom endpoint URL (for MinIO, R2, etc.)
    pub endpoint: Option<String>,
    /// Force path-style URLs (required for MinIO)
    pub force_path_style: bool,
}

impl S3Config {
    /// Create config for AWS S3
    pub fn aws(bucket: String, region: String) -> Self {
        Self {
            bucket,
            prefix: None,
            region,
            endpoint: None,
            force_path_style: false,
        }
    }

    /// Create config for MinIO or other S3-compatible storage
    pub fn minio(bucket: String, endpoint: String) -> Self {
        Self {
            bucket,
            prefix: None,
            region: "us-east-1".to_string(), // MinIO doesn't care about region
            endpoint: Some(endpoint),
            force_path_style: true,
        }
    }

    /// Set a key prefix
    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = Some(prefix);
        self
    }
}

/// S3-compatible storage backend
pub struct S3Storage {
    client: Client,
    bucket: String,
    prefix: Option<String>,
}

impl S3Storage {
    /// Create a new S3 storage backend from config
    pub async fn new(config: S3Config) -> Self {
        let mut builder = Builder::new()
            .region(Region::new(config.region))
            .force_path_style(config.force_path_style);

        if let Some(endpoint) = config.endpoint {
            builder = builder.endpoint_url(endpoint);
        }

        // Load credentials from environment or use defaults
        let sdk_config = aws_config::load_from_env().await;
        if let Some(creds) = sdk_config.credentials_provider() {
            builder = builder.credentials_provider(creds);
        }

        let client = Client::from_conf(builder.build());

        Self {
            client,
            bucket: config.bucket,
            prefix: config.prefix,
        }
    }

    /// Create S3 storage with explicit credentials (for testing)
    pub async fn with_credentials(
        config: S3Config,
        access_key: &str,
        secret_key: &str,
    ) -> Self {
        let creds = Credentials::new(access_key, secret_key, None, None, "static");

        let mut builder = Builder::new()
            .region(Region::new(config.region))
            .force_path_style(config.force_path_style)
            .credentials_provider(creds);

        if let Some(endpoint) = config.endpoint {
            builder = builder.endpoint_url(endpoint);
        }

        let client = Client::from_conf(builder.build());

        Self {
            client,
            bucket: config.bucket,
            prefix: config.prefix,
        }
    }

    /// Build the full S3 key from namespace and key
    fn full_key(&self, namespace: &str, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}{}/{}", prefix, namespace, key),
            None => format!("{}/{}", namespace, key),
        }
    }
}

#[async_trait]
impl StorageBackend for S3Storage {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Bytes> {
        let s3_key = self.full_key(namespace, key);

        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("NoSuchKey") || e.to_string().contains("404") {
                    StorageError::NotFound(format!("{}/{}", namespace, key))
                } else {
                    StorageError::Other(e.to_string())
                }
            })?;

        let data = result
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Other(e.to_string()))?;

        Ok(data.into_bytes())
    }

    async fn get_range(&self, namespace: &str, key: &str, range: Range<u64>) -> StorageResult<Bytes> {
        let s3_key = self.full_key(namespace, key);

        // S3 Range header format: "bytes=start-end" (inclusive on both ends)
        // Our range is [start, end) so we need end-1
        let range_header = format!("bytes={}-{}", range.start, range.end - 1);

        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .range(range_header)
            .send()
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("NoSuchKey") || err_str.contains("404") {
                    StorageError::NotFound(format!("{}/{}", namespace, key))
                } else if err_str.contains("InvalidRange") || err_str.contains("416") {
                    StorageError::InvalidRange(format!(
                        "Invalid range {}..{} for {}/{}",
                        range.start, range.end, namespace, key
                    ))
                } else {
                    StorageError::Other(err_str)
                }
            })?;

        let data = result
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Other(e.to_string()))?;

        Ok(data.into_bytes())
    }

    async fn put(&self, namespace: &str, key: &str, data: Bytes) -> StorageResult<()> {
        let s3_key = self.full_key(namespace, key);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| StorageError::Other(e.to_string()))?;

        Ok(())
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<()> {
        let s3_key = self.full_key(namespace, key);

        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| StorageError::Other(e.to_string()))?;

        Ok(())
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        let s3_key = self.full_key(namespace, key);

        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("404") || err_str.contains("NoSuchKey") || err_str.contains("NotFound") {
                    Ok(false)
                } else {
                    Err(StorageError::Other(err_str))
                }
            }
        }
    }

    async fn list(&self, namespace: &str, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let ns_prefix = match &self.prefix {
            Some(p) => format!("{}{}/", p, namespace),
            None => format!("{}/", namespace),
        };

        let full_prefix = match prefix {
            Some(p) => format!("{}{}", ns_prefix, p),
            None => ns_prefix.clone(),
        };

        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full_prefix);

            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }

            let result = request
                .send()
                .await
                .map_err(|e| StorageError::Other(e.to_string()))?;

            if let Some(contents) = result.contents {
                for obj in contents {
                    if let Some(key) = obj.key {
                        // Strip namespace prefix to return just the key
                        if let Some(stripped) = key.strip_prefix(&ns_prefix) {
                            keys.push(stripped.to_string());
                        }
                    }
                }
            }

            if result.is_truncated.unwrap_or(false) {
                continuation_token = result.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(keys)
    }

    async fn size(&self, namespace: &str, key: &str) -> StorageResult<u64> {
        let s3_key = self.full_key(namespace, key);

        let result = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("404") || err_str.contains("NoSuchKey") {
                    StorageError::NotFound(format!("{}/{}", namespace, key))
                } else {
                    StorageError::Other(err_str)
                }
            })?;

        Ok(result.content_length.unwrap_or(0) as u64)
    }

    async fn get_to_file(&self, namespace: &str, key: &str, local_path: &Path) -> StorageResult<()> {
        let s3_key = self.full_key(namespace, key);

        // Create parent directory
        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(StorageError::Io)?;
        }

        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("NoSuchKey") || e.to_string().contains("404") {
                    StorageError::NotFound(format!("{}/{}", namespace, key))
                } else {
                    StorageError::Other(e.to_string())
                }
            })?;

        // Stream to file
        let mut file = tokio::fs::File::create(local_path)
            .await
            .map_err(StorageError::Io)?;

        let mut stream = result.body.into_async_read();
        tokio::io::copy(&mut stream, &mut file)
            .await
            .map_err(StorageError::Io)?;

        Ok(())
    }

    async fn put_from_file(&self, namespace: &str, key: &str, local_path: &Path) -> StorageResult<()> {
        let s3_key = self.full_key(namespace, key);

        let body = ByteStream::from_path(local_path)
            .await
            .map_err(|e| StorageError::Other(e.to_string()))?;

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::Other(e.to_string()))?;

        Ok(())
    }

    async fn get_stream(
        &self,
        namespace: &str,
        key: &str,
    ) -> StorageResult<Box<dyn tokio::io::AsyncRead + Unpin + Send>> {
        let s3_key = self.full_key(namespace, key);

        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("NoSuchKey") || e.to_string().contains("404") {
                    StorageError::NotFound(format!("{}/{}", namespace, key))
                } else {
                    StorageError::Other(e.to_string())
                }
            })?;

        Ok(Box::new(result.body.into_async_read()))
    }
}
