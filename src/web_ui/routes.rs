//! Web UI route handlers.
//!
//! This module provides a clean, modular routing structure for the web UI.
//! Routes are organized by functional area and delegated to specialized handlers.

use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;

use crate::api::AppState;

// Module declarations - each contains handlers for a specific functional area
mod utils;
mod lfs;
mod tree_ops;
mod diff;
mod auth_handlers;
mod home_handlers;
mod repo_handlers;
mod edit_handlers;
mod discussion_handlers;
mod org_handlers;
mod like_handlers;
mod pr_handlers;
mod token_handlers;
mod trending_handlers;

// Re-export for use by other handlers
pub use like_handlers::{get_like_count, has_user_liked};

/// Create the web UI router with GitHub-like routes
///
/// Routes are organized hierarchically:
/// - `/-/*` - System routes (auth, new repo, stats, search)
/// - `/:owner` - User/org profile pages
/// - `/:owner/:repo` - Repository routes (code, commits, discussions)
pub fn create_router() -> Router<Arc<AppState>> {
    Router::new()
        // Home page
        .route("/", get(home_handlers::index))

        // Authentication routes
        .route("/-/login", get(auth_handlers::login_page).post(auth_handlers::login_submit))
        .route("/-/signup", get(auth_handlers::signup_page).post(auth_handlers::signup_submit))
        .route("/-/logout", get(auth_handlers::logout))

        // Repository management
        .route("/-/new", get(org_handlers::new_repo_page).post(org_handlers::create_repo))

        // Organization management
        .route("/-/new-org", get(org_handlers::new_org_page).post(org_handlers::create_org))

        // Stats, search, and trending
        .route("/-/stats", get(home_handlers::stats))
        .route("/-/search", get(home_handlers::search))
        .route("/-/trending", get(trending_handlers::trending_page))

        // Settings - Token management
        .route("/-/settings/tokens", get(token_handlers::tokens_page).post(token_handlers::create_token))
        .route("/-/settings/tokens/:id/revoke", axum::routing::post(token_handlers::revoke_token))
        .route("/-/settings/tokens/:id/delete", axum::routing::post(token_handlers::delete_token))

        // User/org profile page (must come before /:owner/:repo)
        .route("/:owner", get(home_handlers::user_profile))
        .route("/:owner/members", axum::routing::post(org_handlers::add_org_member))
        .route("/:owner/members/:username/remove", axum::routing::post(org_handlers::remove_org_member))

        // Repository routes (owner/repo format)
        .route("/:owner/:repo", get(home_handlers::repo_detail))

        // Code browsing
        .route("/:owner/:repo/tree/:ref", get(repo_handlers::tree_root))
        .route("/:owner/:repo/tree/:ref/*path", get(repo_handlers::tree_path))
        .route("/:owner/:repo/blob/:ref/*path", get(repo_handlers::blob_view))

        // File editing
        .route("/:owner/:repo/edit/:ref/*path", get(edit_handlers::edit_file).post(edit_handlers::commit_file))
        .route("/:owner/:repo/new/:ref", get(edit_handlers::new_file).post(edit_handlers::commit_new_file))
        .route("/:owner/:repo/new/:ref/*path", get(edit_handlers::new_file_in_dir).post(edit_handlers::commit_new_file_in_dir))

        // Commit history and viewing
        .route("/:owner/:repo/commits/:ref", get(repo_handlers::commits_list))
        .route("/:owner/:repo/commit/:sha", get(repo_handlers::commit_view))

        // Community (combined PRs + discussions)
        .route("/:owner/:repo/community", get(discussion_handlers::community_page))

        // Discussions (individual pages still work)
        .route("/:owner/:repo/discussions", get(discussion_handlers::discussions_list))
        .route("/:owner/:repo/discussions/new", get(discussion_handlers::new_discussion_page).post(discussion_handlers::create_discussion))
        .route("/:owner/:repo/discussions/:id", get(discussion_handlers::discussion_detail).post(discussion_handlers::post_comment))
        .route("/:owner/:repo/discussions/:id/close", axum::routing::post(discussion_handlers::close_discussion))
        .route("/:owner/:repo/discussions/:id/reopen", axum::routing::post(discussion_handlers::reopen_discussion))

        // Pull requests
        .route("/:owner/:repo/pulls", get(pr_handlers::pr_list))

        // Branch management
        .route("/:owner/:repo/branches/new", axum::routing::post(repo_handlers::create_branch))
        .route("/:owner/:repo/pulls/new", get(pr_handlers::new_pr_page).post(pr_handlers::create_pr))
        .route("/:owner/:repo/pulls/:number", get(pr_handlers::pr_detail).post(pr_handlers::post_pr_comment))
        .route("/:owner/:repo/pulls/:number/close", axum::routing::post(pr_handlers::close_pr))
        .route("/:owner/:repo/pulls/:number/reopen", axum::routing::post(pr_handlers::reopen_pr))
        .route("/:owner/:repo/pulls/:number/merge", axum::routing::post(pr_handlers::merge_pr))

        // Likes/stars
        .route("/:owner/:repo/like", axum::routing::post(like_handlers::like_repo))
        .route("/:owner/:repo/unlike", axum::routing::post(like_handlers::unlike_repo))
}
