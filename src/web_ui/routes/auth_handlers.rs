//! Authentication route handlers for login, signup, and logout.

use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use super::utils::{render_template, add_csrf_to_context, get_session_token, verify_csrf_token};

/// Login form data
#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

/// Signup form data
#[derive(serde::Deserialize)]
pub struct SignupForm {
    pub username: String,
    pub password: String,
    pub email: String,
    pub csrf_token: String,
}

/// Login page (GET)
pub async fn login_page(
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let mut context = Context::new();
    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }
    if let Some(msg) = query.get("message") {
        context.insert("message", msg);
    }
    add_csrf_to_context(&mut context, &headers).await;
    render_template("login.html", &context)
}

/// Login submit (POST)
pub async fn login_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return Redirect::to("/-/login?error=Invalid+request.+Please+try+again.").into_response();
    }

    match state.auth.authenticate(&form.username, &form.password).await {
        Ok(token) => {
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("Location", "/")
                .header("Set-Cookie", format!("token={}; Path=/; HttpOnly; SameSite=Lax; Secure", token.token))
                .body(axum::body::Body::empty())
                .unwrap()
        }
        Err(_) => {
            Redirect::to("/-/login?error=Invalid+username+or+password").into_response()
        }
    }
}

/// Check if registration is disabled via environment variable
fn is_registration_disabled() -> bool {
    std::env::var("DISABLE_REGISTRATION")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Signup page (GET)
pub async fn signup_page(
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Check if registration is disabled
    if is_registration_disabled() {
        return Redirect::to("/-/login?error=Registration+is+currently+closed").into_response();
    }

    let mut context = Context::new();
    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }
    add_csrf_to_context(&mut context, &headers).await;
    render_template("signup.html", &context)
}

/// Signup submit (POST)
pub async fn signup_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SignupForm>,
) -> Response {
    // Check if registration is disabled
    if is_registration_disabled() {
        return Redirect::to("/-/login?error=Registration+is+currently+closed").into_response();
    }

    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return Redirect::to("/-/signup?error=Invalid+request.+Please+try+again.").into_response();
    }

    // Validate
    if form.username.len() < 2 {
        return Redirect::to("/-/signup?error=Username+must+be+at+least+2+characters").into_response();
    }
    if form.password.len() < 8 {
        return Redirect::to("/-/signup?error=Password+must+be+at+least+8+characters").into_response();
    }
    if !form.username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Redirect::to("/-/signup?error=Username+can+only+contain+letters,+numbers,+dashes,+and+underscores").into_response();
    }

    // Validate email
    let email = form.email.trim();
    if email.is_empty() {
        return Redirect::to("/-/signup?error=Email+is+required").into_response();
    }
    if !email.contains('@') || !email.contains('.') || email.len() < 5 {
        return Redirect::to("/-/signup?error=Please+enter+a+valid+email+address").into_response();
    }

    match state.auth.register_user(&form.username, &form.password, Some(email)).await {
        Ok(_) => {
            Redirect::to("/-/login?message=Account+created!+Please+log+in.").into_response()
        }
        Err(e) => {
            let error_msg = e.to_string().replace(' ', "+");
            Redirect::to(&format!("/-/signup?error={}", error_msg)).into_response()
        }
    }
}

/// Logout (GET)
pub async fn logout() -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("Location", "/")
        .header("Set-Cookie", "token=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0")
        .body(axum::body::Body::empty())
        .unwrap()
}
