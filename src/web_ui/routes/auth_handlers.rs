//! Authentication route handlers for login, signup, and logout.

use axum::{
    extract::{Form, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use super::utils::render_template;

/// Login form data
#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

/// Signup form data
#[derive(serde::Deserialize)]
pub struct SignupForm {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

/// Login page (GET)
pub async fn login_page(Query(query): Query<std::collections::HashMap<String, String>>) -> Response {
    let mut context = Context::new();
    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }
    if let Some(msg) = query.get("message") {
        context.insert("message", msg);
    }
    render_template("login.html", &context)
}

/// Login submit (POST)
pub async fn login_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    match state.auth.authenticate(&form.username, &form.password).await {
        Ok(token) => {
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("Location", "/")
                .header("Set-Cookie", format!("token={}; Path=/; HttpOnly; SameSite=Lax", token.token))
                .body(axum::body::Body::empty())
                .unwrap()
        }
        Err(_) => {
            Redirect::to("/-/login?error=Invalid+username+or+password").into_response()
        }
    }
}

/// Signup page (GET)
pub async fn signup_page(Query(query): Query<std::collections::HashMap<String, String>>) -> Response {
    let mut context = Context::new();
    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }
    render_template("signup.html", &context)
}

/// Signup submit (POST)
pub async fn signup_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<SignupForm>,
) -> Response {
    // Validate
    if form.username.len() < 2 {
        return Redirect::to("/-/signup?error=Username+must+be+at+least+2+characters").into_response();
    }
    if form.password.len() < 4 {
        return Redirect::to("/-/signup?error=Password+must+be+at+least+4+characters").into_response();
    }
    if !form.username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Redirect::to("/-/signup?error=Username+can+only+contain+letters,+numbers,+dashes,+and+underscores").into_response();
    }

    match state.auth.register_user(&form.username, &form.password, form.email.as_deref()).await {
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
        .header("Set-Cookie", "token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        .body(axum::body::Body::empty())
        .unwrap()
}
