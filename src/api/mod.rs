pub mod auth;
pub mod handlers;
pub mod lfs;

use std::sync::Arc;
use axum::{routing::{get, post}, Router};

pub use auth::{Permissions, User};
pub use handlers::{
    AppState, cas_stats, create_repo, delete_repo, health, list_refs, list_repos, login,
    git_info_refs, git_upload_pack, git_receive_pack,
};
pub use lfs::{lfs_batch, lfs_download, lfs_upload, lfs_verify};

/// Create Git Smart HTTP and LFS router
/// Routes are structured to avoid conflicts with web UI:
/// - Git: /:owner/:repo.git/info/refs, /:owner/:repo.git/git-upload-pack, etc.
/// - LFS: /:owner/:repo.git/info/lfs/objects/batch, etc.
pub fn git_router() -> Router<Arc<AppState>> {
    Router::new()
        // Git Smart HTTP endpoints
        // Format: /:owner/:repo.git/info/refs (note: .git is part of :repo)
        .route("/:owner/:repo/info/refs", get(git_info_refs))
        .route("/:owner/:repo/git-upload-pack", post(git_upload_pack))
        .route("/:owner/:repo/git-receive-pack", post(git_receive_pack))
        // LFS endpoints
        .route("/:owner/:repo/info/lfs/objects/batch", post(lfs_batch))
        .route("/:owner/:repo/info/lfs/objects/:oid", get(lfs_download).put(lfs_upload))
        .route("/:owner/:repo/info/lfs/verify", post(lfs_verify))
}
