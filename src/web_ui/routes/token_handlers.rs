//! Token management route handlers for the web UI.

use axum::{
    extract::{Form, Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use super::utils::{
    add_csrf_to_context, add_user_to_context, get_current_user, get_session_token,
    render_error, render_template, verify_csrf_token, format_relative_time,
};

/// Form for creating a new access token
#[derive(serde::Deserialize)]
pub struct CreateTokenForm {
    pub name: String,
    pub description: Option<String>,
    pub expires: String, // "never", "30", "60", "90", "365"
    pub csrf_token: String,
}

/// Form for revoking a token
#[derive(serde::Deserialize)]
pub struct RevokeTokenForm {
    pub csrf_token: String,
}

/// Query params for tokens page
#[derive(serde::Deserialize, Default)]
pub struct TokensQuery {
    pub created: Option<String>, // Newly created token (only shown once)
    pub success: Option<String>,
    pub error: Option<String>,
}

/// Token info for template
#[derive(serde::Serialize)]
pub struct TokenDisplay {
    pub id: i32,
    pub name: String,
    pub prefix: String,
    pub description: Option<String>,
    pub scopes: String,
    pub last_used: String,
    pub created: String,
    pub expires: String,
    pub is_active: bool,
}

/// Tokens management page (GET)
pub async fn tokens_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TokensQuery>,
) -> Response {
    let mut context = Context::new();
    add_user_to_context(&mut context, &state, &headers).await;
    add_csrf_to_context(&mut context, &headers).await;

    // Must be logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(user) => user,
        None => return Redirect::to("/-/login?error=Please+log+in+to+manage+tokens").into_response(),
    };

    // Get user ID
    let user = match state.auth.get_user_by_username(&current_user).await {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    // Get tokens
    let tokens = match state.auth.list_access_tokens(user.id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to list tokens: {:?}", e);
            return render_error("Failed to load tokens");
        }
    };

    // Format tokens for display
    let token_displays: Vec<TokenDisplay> = tokens
        .into_iter()
        .map(|t| TokenDisplay {
            id: t.id,
            name: t.name,
            prefix: t.prefix,
            description: t.description,
            scopes: t.scopes,
            last_used: if t.last_used_at == 0 {
                "Never".to_string()
            } else {
                format_relative_time(t.last_used_at)
            },
            created: format_relative_time(t.created_at),
            expires: if t.expires_at == 0 {
                "Never".to_string()
            } else {
                format_relative_time(t.expires_at)
            },
            is_active: t.is_active,
        })
        .collect();

    context.insert("tokens", &token_displays);
    context.insert("token_count", &token_displays.len());

    // Handle newly created token (show only once)
    if let Some(created_token) = query.created {
        context.insert("new_token", &created_token);
    }

    if let Some(success) = query.success {
        context.insert("success", &success);
    }

    if let Some(error) = query.error {
        context.insert("error", &error);
    }

    render_template("tokens.html", &context)
}

/// Create a new token (POST)
pub async fn create_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CreateTokenForm>,
) -> Response {
    // Verify CSRF
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return Redirect::to("/-/settings/tokens?error=Invalid+request.+Please+try+again.").into_response();
    }

    // Must be logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(user) => user,
        None => return Redirect::to("/-/login?error=Please+log+in").into_response(),
    };

    // Get user ID
    let user = match state.auth.get_user_by_username(&current_user).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/-/settings/tokens?error=User+not+found").into_response(),
    };

    // Validate name
    let name = form.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Redirect::to("/-/settings/tokens?error=Token+name+must+be+1-100+characters").into_response();
    }

    // Parse expiration
    let expires_in_days: Option<i64> = match form.expires.as_str() {
        "never" => None,
        "30" => Some(30),
        "60" => Some(60),
        "90" => Some(90),
        "365" => Some(365),
        _ => None,
    };

    // Create token
    match state.auth.create_access_token(
        user.id,
        name,
        form.description.as_deref().filter(|s| !s.is_empty()),
        None, // Default scopes
        expires_in_days,
    ).await {
        Ok(created) => {
            // Redirect with the new token (only shown once!)
            // Token is safe to include in URL since it only contains ox_ and hex chars
            Redirect::to(&format!("/-/settings/tokens?created={}", created.token)).into_response()
        }
        Err(e) => {
            let error_msg = e.to_string().replace(' ', "+");
            Redirect::to(&format!("/-/settings/tokens?error={}", error_msg)).into_response()
        }
    }
}

/// Revoke a token (POST)
pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token_id): Path<i32>,
    Form(form): Form<RevokeTokenForm>,
) -> Response {
    // Verify CSRF
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return Redirect::to("/-/settings/tokens?error=Invalid+request.+Please+try+again.").into_response();
    }

    // Must be logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(user) => user,
        None => return Redirect::to("/-/login?error=Please+log+in").into_response(),
    };

    // Get user ID
    let user = match state.auth.get_user_by_username(&current_user).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/-/settings/tokens?error=User+not+found").into_response(),
    };

    // Revoke token
    match state.auth.revoke_access_token(token_id, user.id).await {
        Ok(_) => {
            Redirect::to("/-/settings/tokens?success=Token+revoked+successfully").into_response()
        }
        Err(e) => {
            let error_msg = e.to_string().replace(' ', "+");
            Redirect::to(&format!("/-/settings/tokens?error={}", error_msg)).into_response()
        }
    }
}

/// Delete a token permanently (POST)
pub async fn delete_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token_id): Path<i32>,
    Form(form): Form<RevokeTokenForm>,
) -> Response {
    // Verify CSRF
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return Redirect::to("/-/settings/tokens?error=Invalid+request.+Please+try+again.").into_response();
    }

    // Must be logged in
    let current_user = match get_current_user(&state, &headers).await {
        Some(user) => user,
        None => return Redirect::to("/-/login?error=Please+log+in").into_response(),
    };

    // Get user ID
    let user = match state.auth.get_user_by_username(&current_user).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/-/settings/tokens?error=User+not+found").into_response(),
    };

    // Delete token
    match state.auth.delete_access_token(token_id, user.id).await {
        Ok(_) => {
            Redirect::to("/-/settings/tokens?success=Token+deleted+permanently").into_response()
        }
        Err(e) => {
            let error_msg = e.to_string().replace(' ', "+");
            Redirect::to(&format!("/-/settings/tokens?error={}", error_msg)).into_response()
        }
    }
}
