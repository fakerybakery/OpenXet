mod api;
mod cas;
mod db;
mod error;
mod git;
mod storage;
mod web_ui; // Optional: remove this line to disable web UI

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post},
    Router,
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api::{AppState, Permissions, User};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "git_xet_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Get storage path from environment or use default
    let storage_path = std::env::var("GIT_XET_STORAGE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("git-xet-storage"));

    // Initialize database
    let db_path = storage_path.join("git-xet.db");
    let db = db::init_database(&db_path)
        .await
        .expect("Failed to initialize database");
    let db = Arc::new(db);
    tracing::info!("Database initialized at {:?}", db_path);

    // Create application state with database connection
    let state = Arc::new(
        AppState::with_db(storage_path, db)
            .await
            .expect("Failed to create application state")
    );

    // Add default admin user (in production, load from config/env)
    state.auth.add_user(
        User::new("admin".to_string(), "admin")
            .with_global_permissions(Permissions::admin()),
    );

    // Add a demo user with read-only access
    state.auth.add_user(
        User::new("demo".to_string(), "demo")
            .with_global_permissions(Permissions::read_only()),
    );

    // Create a sample repository if none exist
    if state.repos.list_repos().is_empty() {
        let _ = state.repos.create_repo("demo/sample");
        tracing::info!("Sample repository 'demo/sample' created");
    } else {
        tracing::info!("Loaded {} repositories from database", state.repos.list_repos().len());
    }

    // Build router with explicit routes
    // Git/LFS routes use patterns that include ".git" or specific paths
    // Web UI routes use /:owner/:repo patterns for browsing
    let app = Router::new()
        // API endpoints (explicit /api prefix)
        .route("/api/repos", get(api::list_repos))
        .route("/api/repos/:owner/:repo", post(api::create_repo))
        .route("/api/repos/:owner/:repo", delete(api::delete_repo))
        .route("/api/repos/:owner/:repo/refs", get(api::list_refs))
        .route("/api/auth/login", post(api::login))
        .route("/api/cas/stats", get(api::cas_stats))
        // Health check
        .route("/health", get(api::health))
        // HuggingFace-compatible API (must come before git_router to handle /api/* paths)
        .merge(api::hf_router())
        // Merge Git/LFS router (uses nested paths to avoid conflicts)
        .merge(api::git_router())
        // Web UI (uses /:owner/:repo patterns)
        .merge(web_ui::router())
        .with_state(state)
        // Allow large file uploads (10GB limit)
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024 * 1024))
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::info!("Git-Xet Server starting on http://{}", addr);
    tracing::info!("Default credentials: admin/admin (full access), demo/demo (read-only)");
    tracing::info!("");
    tracing::info!("Usage:");
    tracing::info!("  Clone: git clone http://admin:admin@localhost:8080/demo/sample.git");
    tracing::info!("  Push:  git push http://admin:admin@localhost:8080/demo/sample.git main");
    tracing::info!("");
    tracing::info!("Web UI: http://{}/", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
