mod api;
mod cas;
mod db;
mod error;
mod git;
mod storage;
mod web_ui;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    http::header::{HeaderName, HeaderValue},
    routing::{delete, get, post},
    Router,
};
use tower_http::{
    trace::TraceLayer,
    set_header::SetResponseHeaderLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api::AppState;

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

    // Bootstrap admin user from environment or generate random password
    if let Some(admin_password) = state.auth.ensure_admin_user_secure().await
        .expect("Failed to create admin user")
    {
        tracing::warn!("================================================");
        tracing::warn!("INITIAL ADMIN CREDENTIALS (change immediately!)");
        tracing::warn!("  Username: admin");
        tracing::warn!("  Password: {}", admin_password);
        tracing::warn!("================================================");
    }

    // Log repository count
    let repo_count = state.repos.list_repos().len();
    if repo_count == 0 {
        tracing::info!("No repositories found. Users can create repos under their username.");
    } else {
        tracing::info!("Loaded {} repositories from database", repo_count);
    }

    // Build router with explicit routes
    let app = Router::new()
        // API endpoints (explicit /api prefix)
        .route("/api/repos", get(api::list_repos))
        .route("/api/repos/:owner/:repo", post(api::create_repo))
        .route("/api/repos/:owner/:repo", delete(api::delete_repo))
        .route("/api/repos/:owner/:repo/refs", get(api::list_refs))
        // Auth endpoints
        .route("/api/auth/register", post(api::register))
        .route("/api/auth/login", post(api::login))
        // Organization endpoints
        .route("/api/orgs", post(api::create_org))
        .route("/api/orgs/:org/members", get(api::get_org_members))
        .route("/api/orgs/:org/members", post(api::add_org_member))
        .route("/api/orgs/:org/members/:username", delete(api::remove_org_member))
        // Stats
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
        .layer(TraceLayer::new_for_http())
        // Security headers
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';"),
        ));

    // Start server
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid HOST:PORT combination");
    tracing::info!("Git-Xet Server starting on http://{}", addr);
    tracing::info!("");
    tracing::info!("API Endpoints:");
    tracing::info!("  POST /api/auth/register - Register new user");
    tracing::info!("  POST /api/auth/login    - Login and get token");
    tracing::info!("  POST /api/orgs          - Create organization");
    tracing::info!("");
    tracing::info!("Users can push to repos under their username (e.g., alice/my-model)");
    tracing::info!("Org members can push to org repos (e.g., my-org/shared-model)");
    tracing::info!("");
    tracing::info!("Web UI: http://{}/", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
