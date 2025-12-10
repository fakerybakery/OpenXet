pub mod auth;
pub mod handlers;
pub mod hf_api;
pub mod lfs;

use std::sync::Arc;
use axum::{routing::{get, post}, Router};

pub use auth::{AuthManager, Token};
pub use handlers::{
    AppState, cas_stats, create_repo, delete_repo, health, list_refs, list_repos, login,
    git_info_refs, git_upload_pack, git_receive_pack,
    register, create_org, add_org_member, remove_org_member, get_org_members,
};
pub use lfs::{lfs_batch, lfs_download, lfs_upload, lfs_verify, lfs_verify_signed, lfs_multipart_complete};
pub use hf_api::router as hf_router;

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
        // LFS endpoints (standard path)
        .route("/:owner/:repo/info/lfs/objects/batch", post(lfs_batch))
        .route("/:owner/:repo/info/lfs/objects/:oid", get(lfs_download).put(lfs_upload))
        .route("/:owner/:repo/info/lfs/verify", post(lfs_verify))
        .route("/:owner/:repo/info/lfs/verify/:oid", post(lfs_verify_signed))
        .route("/:owner/:repo/info/lfs/multipart/:oid", post(lfs_multipart_complete))
        // LFS endpoints for HuggingFace typed paths (/datasets/, /models/, /spaces/)
        .route("/datasets/:owner/:repo/info/lfs/objects/batch", post(lfs_batch))
        .route("/datasets/:owner/:repo/info/lfs/objects/:oid", get(lfs_download).put(lfs_upload))
        .route("/datasets/:owner/:repo/info/lfs/verify", post(lfs_verify))
        .route("/datasets/:owner/:repo/info/lfs/verify/:oid", post(lfs_verify_signed))
        .route("/datasets/:owner/:repo/info/lfs/multipart/:oid", post(lfs_multipart_complete))
        .route("/models/:owner/:repo/info/lfs/objects/batch", post(lfs_batch))
        .route("/models/:owner/:repo/info/lfs/objects/:oid", get(lfs_download).put(lfs_upload))
        .route("/models/:owner/:repo/info/lfs/verify", post(lfs_verify))
        .route("/models/:owner/:repo/info/lfs/verify/:oid", post(lfs_verify_signed))
        .route("/models/:owner/:repo/info/lfs/multipart/:oid", post(lfs_multipart_complete))
        .route("/spaces/:owner/:repo/info/lfs/objects/batch", post(lfs_batch))
        .route("/spaces/:owner/:repo/info/lfs/objects/:oid", get(lfs_download).put(lfs_upload))
        .route("/spaces/:owner/:repo/info/lfs/verify", post(lfs_verify))
        .route("/spaces/:owner/:repo/info/lfs/verify/:oid", post(lfs_verify_signed))
        .route("/spaces/:owner/:repo/info/lfs/multipart/:oid", post(lfs_multipart_complete))
}
