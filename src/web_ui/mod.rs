//! Web UI Module
//!
//! A cleanly separated web interface for browsing repositories and files.
//!
//! ## Removal Instructions
//! To completely remove the web UI in under 5 minutes:
//! 1. Delete this directory: `rm -rf src/web_ui/`
//! 2. Remove from main.rs: delete `mod web_ui;` line
//! 3. Remove from main.rs: delete `.merge(web_ui::router())` line
//! 4. Remove from Cargo.toml: delete `tera = "1"` line
//! That's it!

mod routes;
mod templates;

use axum::Router;
use std::sync::Arc;

use crate::api::AppState;

/// Create the web UI router.
/// Mount this with `.merge(web_ui::router())` in main.rs
pub fn router() -> Router<Arc<AppState>> {
    routes::create_router()
}
