//! HuggingFace API route definitions.

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};

use super::handlers;
use crate::api::AppState;

/// Create the HuggingFace-compatible API router.
///
/// This router handles all HF Hub API endpoints, allowing clients using
/// `huggingface_hub` or `datasets` to interact with this server.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ================================================================
        // Authentication
        // ================================================================
        .route("/api/whoami", get(handlers::whoami))
        .route("/api/whoami-v2", get(handlers::whoami))
        // ================================================================
        // Repository Management
        // ================================================================
        .route("/api/repos/create", post(handlers::create_repo))
        // ================================================================
        // Repository Info (models/datasets/spaces all map to same handler)
        // ================================================================
        .route("/api/models/:owner/:repo", get(handlers::repo_info))
        .route("/api/datasets/:owner/:repo", get(handlers::repo_info))
        .route("/api/spaces/:owner/:repo", get(handlers::repo_info))
        // Repo info with specific revision
        .route(
            "/api/models/:owner/:repo/revision/:revision",
            get(handlers::repo_info_revision),
        )
        .route(
            "/api/datasets/:owner/:repo/revision/:revision",
            get(handlers::repo_info_revision),
        )
        .route(
            "/api/spaces/:owner/:repo/revision/:revision",
            get(handlers::repo_info_revision),
        )
        // ================================================================
        // Tree Listing
        // ================================================================
        .route(
            "/api/models/:owner/:repo/tree/:revision",
            get(handlers::tree_list),
        )
        .route(
            "/api/datasets/:owner/:repo/tree/:revision",
            get(handlers::tree_list),
        )
        .route(
            "/api/spaces/:owner/:repo/tree/:revision",
            get(handlers::tree_list),
        )
        // Tree listing with subpath
        .route(
            "/api/models/:owner/:repo/tree/:revision/*path",
            get(handlers::tree_list_path),
        )
        .route(
            "/api/datasets/:owner/:repo/tree/:revision/*path",
            get(handlers::tree_list_path),
        )
        .route(
            "/api/spaces/:owner/:repo/tree/:revision/*path",
            get(handlers::tree_list_path),
        )
        // ================================================================
        // Upload API
        // ================================================================
        .route(
            "/api/models/:owner/:repo/preupload/:revision",
            post(handlers::preupload),
        )
        .route(
            "/api/datasets/:owner/:repo/preupload/:revision",
            post(handlers::preupload),
        )
        .route(
            "/api/spaces/:owner/:repo/preupload/:revision",
            post(handlers::preupload),
        )
        .route(
            "/api/models/:owner/:repo/commit/:revision",
            post(handlers::commit),
        )
        .route(
            "/api/datasets/:owner/:repo/commit/:revision",
            post(handlers::commit),
        )
        .route(
            "/api/spaces/:owner/:repo/commit/:revision",
            post(handlers::commit),
        )
        // ================================================================
        // File Download (resolve)
        // ================================================================
        .route(
            "/:owner/:repo/resolve/:revision/*path",
            get(handlers::resolve_file).head(handlers::resolve_file),
        )
        .route(
            "/datasets/:owner/:repo/resolve/:revision/*path",
            get(handlers::resolve_file_typed).head(handlers::resolve_file_typed),
        )
        .route(
            "/models/:owner/:repo/resolve/:revision/*path",
            get(handlers::resolve_file_typed).head(handlers::resolve_file_typed),
        )
        .route(
            "/spaces/:owner/:repo/resolve/:revision/*path",
            get(handlers::resolve_file_typed).head(handlers::resolve_file_typed),
        )
        // Note: LFS routes are handled by git_router() in api/mod.rs
        // The existing lfs_batch handler works for HF clients too
        // ================================================================
        // Utilities
        // ================================================================
        .route("/api/validate-yaml", post(handlers::validate_yaml))
}
