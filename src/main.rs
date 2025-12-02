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
        let _ = state.repos.create_repo("sample");
        tracing::info!("Sample repository 'sample' created");
    } else {
        tracing::info!("Loaded {} repositories from database", state.repos.list_repos().len());
    }

    // Build router - specific routes first, then wildcard
    let app = Router::new()
        // Web UI (Optional: remove .merge() line to disable web UI)
        .merge(web_ui::router())
        // API endpoints (must come before wildcard)
        .route("/api/repos", get(api::list_repos))
        .route("/api/repos/:repo", post(api::create_repo))
        .route("/api/repos/:repo", delete(api::delete_repo))
        .route("/api/repos/:repo/refs", get(api::list_refs))
        .route("/api/auth/login", post(api::login))
        .route("/api/cas/stats", get(api::cas_stats))
        // Health check
        .route("/health", get(api::health))
        // Git Smart HTTP + LFS endpoints (wildcard - catches remaining paths)
        .route("/*repo", get(api::wildcard_get).post(api::wildcard_post).put(api::wildcard_put))
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
    tracing::info!("  Clone: git clone http://admin:admin@localhost:8080/sample.git");
    tracing::info!("  Push:  git push http://admin:admin@localhost:8080/sample.git main");
    tracing::info!("");
    tracing::info!("Web UI: http://{}/", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
