//! HuggingFace-compatible API implementation.
//!
//! This module provides endpoints compatible with the HuggingFace Hub API,
//! allowing users to use `huggingface_hub` and `datasets` libraries with
//! this server by setting `HF_ENDPOINT`.
//!
//! Key differences from real HF Hub:
//! - No separate models/datasets/spaces repo types - all repos are unified
//! - Authentication accepts any token (no validation for now)
//! - repo_type in paths is stripped: `/datasets/user/repo` → `user/repo`

mod handlers;
mod routes;
mod types;

pub use routes::router;
