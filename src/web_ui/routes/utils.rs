//! Shared utilities and helper functions for web UI.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use tera::Context;

use crate::api::AppState;
use crate::web_ui::templates;

/// CSRF secret key (generated once per server instance)
static CSRF_SECRET: Lazy<[u8; 32]> = Lazy::new(|| {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut secret = [0u8; 32];
    rng.fill(&mut secret);
    secret
});

/// Helper to render a template
pub fn render_template(name: &str, context: &Context) -> Response {
    match templates::render(name, context) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Template error: {}", e)).into_response()
        }
    }
}

/// Helper to render an error page
pub fn render_error(message: &str) -> Response {
    let mut context = Context::new();
    context.insert("message", message);

    match templates::render("error.html", &context) {
        Ok(html) => (StatusCode::NOT_FOUND, Html(html)).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, message.to_string()).into_response(),
    }
}

/// Extract current username from cookie token
pub async fn get_current_user(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("token=") {
            if let Some(username) = state.auth.get_username_for_token(token).await {
                return Some(username);
            }
        }
    }
    None
}

/// Add current user to context if logged in
pub async fn add_user_to_context(context: &mut Context, state: &AppState, headers: &HeaderMap) {
    if let Some(username) = get_current_user(state, headers).await {
        context.insert("current_user", &username);
    }
}

/// Generate a CSRF token for the current session
/// Token is HMAC(secret, session_token + timestamp)
pub fn generate_csrf_token(session_token: Option<&str>) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Create HMAC of session + timestamp
    let mut hasher = Sha256::new();
    hasher.update(&*CSRF_SECRET);
    hasher.update(session_token.unwrap_or("anonymous").as_bytes());
    hasher.update(timestamp.to_le_bytes());
    let hash = hasher.finalize();

    // Encode timestamp + hash
    let mut token_data = timestamp.to_le_bytes().to_vec();
    token_data.extend_from_slice(&hash[..16]); // 8 bytes timestamp + 16 bytes hash
    URL_SAFE_NO_PAD.encode(&token_data)
}

/// Verify a CSRF token
/// Returns true if valid and not expired (tokens valid for 1 hour)
pub fn verify_csrf_token(token: &str, session_token: Option<&str>) -> bool {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use subtle::ConstantTimeEq;

    const MAX_AGE_SECS: u64 = 3600; // 1 hour

    // Decode token
    let token_data = match URL_SAFE_NO_PAD.decode(token) {
        Ok(d) if d.len() == 24 => d, // 8 bytes timestamp + 16 bytes hash
        _ => return false,
    };

    // Extract timestamp
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&token_data[..8]);
    let token_timestamp = u64::from_le_bytes(ts_bytes);

    // Check expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now.saturating_sub(token_timestamp) > MAX_AGE_SECS {
        return false;
    }

    // Recompute expected hash
    let mut hasher = Sha256::new();
    hasher.update(&*CSRF_SECRET);
    hasher.update(session_token.unwrap_or("anonymous").as_bytes());
    hasher.update(token_timestamp.to_le_bytes());
    let expected_hash = hasher.finalize();

    // Constant-time comparison
    token_data[8..].ct_eq(&expected_hash[..16]).into()
}

/// Extract session token from headers (for CSRF validation)
pub fn get_session_token(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("token=") {
            return Some(token.to_string());
        }
    }
    None
}

/// Add CSRF token to context
pub async fn add_csrf_to_context(context: &mut Context, headers: &HeaderMap) {
    let session_token = get_session_token(headers);
    let csrf_token = generate_csrf_token(session_token.as_deref());
    context.insert("csrf_token", &csrf_token);
}

/// Format a file size for display
pub fn format_size(size: u64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format seconds ago as human-readable string
pub fn format_time_ago(seconds: i64) -> String {
    if seconds < 0 {
        return "in the future".to_string();
    }
    if seconds < 60 {
        return format!("{} seconds ago", seconds);
    }
    let minutes = seconds / 60;
    if minutes < 60 {
        return format!("{} minute{} ago", minutes, if minutes == 1 { "" } else { "s" });
    }
    let hours = minutes / 60;
    if hours < 24 {
        return format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" });
    }
    let days = hours / 24;
    if days < 30 {
        return format!("{} day{} ago", days, if days == 1 { "" } else { "s" });
    }
    let months = days / 30;
    if months < 12 {
        return format!("{} month{} ago", months, if months == 1 { "" } else { "s" });
    }
    let years = months / 12;
    format!("{} year{} ago", years, if years == 1 { "" } else { "s" })
}

/// Format a Unix timestamp as a relative time string
pub fn format_relative_time(timestamp: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_time_ago(now - timestamp)
}

/// Breadcrumb for navigation
#[derive(serde::Serialize)]
pub struct Breadcrumb {
    pub name: String,
    pub path: String,
}

/// Branch info for templates
#[derive(serde::Serialize)]
pub struct BranchInfo {
    pub name: String,
}
