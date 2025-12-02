//! Storage configuration.

use std::path::PathBuf;
use std::sync::Arc;

use super::{LocalStorage, S3Config, S3Storage, StorageBackend};

/// Storage backend type
#[derive(Debug, Clone)]
pub enum StorageType {
    /// Local filesystem storage
    Local { path: PathBuf },
    /// S3-compatible storage (AWS S3, MinIO, R2, etc.)
    S3(S3Config),
}

impl Default for StorageType {
    fn default() -> Self {
        StorageType::Local {
            path: std::env::temp_dir().join("git-xet-storage"),
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Storage backend type
    pub storage_type: StorageType,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::default(),
        }
    }
}

impl StorageConfig {
    /// Create config for local storage at the given path
    pub fn local(path: PathBuf) -> Self {
        Self {
            storage_type: StorageType::Local { path },
        }
    }

    /// Create config for AWS S3 storage
    pub fn s3(bucket: String, region: String) -> Self {
        Self {
            storage_type: StorageType::S3(S3Config::aws(bucket, region)),
        }
    }

    /// Create config for MinIO or other S3-compatible storage
    pub fn minio(bucket: String, endpoint: String) -> Self {
        Self {
            storage_type: StorageType::S3(S3Config::minio(bucket, endpoint)),
        }
    }

    /// Build a storage backend from this config (sync version for local only)
    pub fn build_local(&self) -> Option<Arc<dyn StorageBackend>> {
        match &self.storage_type {
            StorageType::Local { path } => {
                std::fs::create_dir_all(path).ok();
                Some(Arc::new(LocalStorage::new(path.clone())))
            }
            StorageType::S3(_) => None, // Use build_async for S3
        }
    }

    /// Build a storage backend from this config (async version, supports all backends)
    pub async fn build(&self) -> Arc<dyn StorageBackend> {
        match &self.storage_type {
            StorageType::Local { path } => {
                std::fs::create_dir_all(path).ok();
                Arc::new(LocalStorage::new(path.clone()))
            }
            StorageType::S3(config) => Arc::new(S3Storage::new(config.clone()).await),
        }
    }
}
