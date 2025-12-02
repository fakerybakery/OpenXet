//! Storage backend trait definition.
//!
//! Provides an abstraction over different storage backends (local filesystem, S3, etc.)
//! with support for efficient byte range requests - critical for fast file reconstruction.

use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;
use std::ops::Range;
use std::path::Path;

/// Storage error types
#[derive(Debug)]
pub enum StorageError {
    /// Object not found
    NotFound(String),
    /// IO error
    Io(std::io::Error),
    /// Invalid range request
    InvalidRange(String),
    /// Other error
    Other(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::NotFound(key) => write!(f, "Object not found: {}", key),
            StorageError::Io(e) => write!(f, "IO error: {}", e),
            StorageError::InvalidRange(msg) => write!(f, "Invalid range: {}", msg),
            StorageError::Other(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::NotFound {
            StorageError::NotFound(e.to_string())
        } else {
            StorageError::Io(e)
        }
    }
}

pub type StorageResult<T> = Result<T, StorageError>;

/// Storage backend trait for pluggable storage.
///
/// Keys are organized by namespace (e.g., "chunks", "git-objects", "raw")
/// to allow different storage policies per type.
///
/// The key method for fast file reconstruction is `get_range`, which fetches
/// only the needed byte range from an object. For S3, this maps directly to
/// HTTP Range requests, enabling parallel fetching of file segments.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Get an object by namespace and key
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Bytes>;

    /// Get a byte range from an object (critical for fast reconstruction)
    ///
    /// This is the key method for achieving high download speeds. For S3 backends,
    /// this maps to HTTP Range requests which can be parallelized. For local storage,
    /// this uses seek + read.
    ///
    /// Range is [start, end) - start inclusive, end exclusive.
    async fn get_range(&self, namespace: &str, key: &str, range: Range<u64>) -> StorageResult<Bytes>;

    /// Put an object by namespace and key
    async fn put(&self, namespace: &str, key: &str, data: Bytes) -> StorageResult<()>;

    /// Delete an object by namespace and key
    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<()>;

    /// Check if an object exists
    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool>;

    /// List all keys in a namespace (with optional prefix)
    async fn list(&self, namespace: &str, prefix: Option<&str>) -> StorageResult<Vec<String>>;

    /// Get the size of an object without reading it
    async fn size(&self, namespace: &str, key: &str) -> StorageResult<u64>;

    /// Stream an object to a local file path (for large objects)
    /// Returns the path to the local file
    async fn get_to_file(&self, namespace: &str, key: &str, local_path: &Path) -> StorageResult<()>;

    /// Stream a local file to storage (for large objects)
    async fn put_from_file(&self, namespace: &str, key: &str, local_path: &Path) -> StorageResult<()>;

    /// Get a reader for streaming large objects
    /// Returns a boxed async reader
    async fn get_stream(
        &self,
        namespace: &str,
        key: &str,
    ) -> StorageResult<Box<dyn tokio::io::AsyncRead + Unpin + Send>>;
}

/// Storage namespaces
pub mod namespaces {
    /// Git loose objects
    pub const GIT_OBJECTS: &str = "git-objects";
    /// Git pack files
    pub const GIT_PACKS: &str = "git-packs";
    /// CAS chunks (deduplicated) - deprecated, use BLOCKS
    pub const CAS_CHUNKS: &str = "cas-chunks";
    /// Blocks (bundled chunks, ~64MB each) - the unit of S3 storage
    pub const BLOCKS: &str = "blocks";
    /// Raw LFS objects (before chunking)
    pub const LFS_RAW: &str = "lfs-raw";
    /// Repository metadata
    pub const REPO_META: &str = "repo-meta";
}
