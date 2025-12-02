//! Storage backend abstraction.
//!
//! Provides a pluggable storage layer that can be backed by:
//! - Local filesystem (default)
//! - S3-compatible object storage (AWS S3, MinIO, R2, etc.)
//!
//! The key feature for fast file reconstruction is `get_range`, which enables
//! efficient byte range requests - critical for achieving high download speeds.

#![allow(dead_code)] // Public API methods for future use

mod backend;
mod config;
mod local;
mod s3;

pub use backend::{namespaces, StorageBackend};
pub use config::{StorageConfig, StorageType};
pub use local::LocalStorage;
pub use s3::{S3Config, S3Storage};
