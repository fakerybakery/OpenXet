//! Trending page handlers showing popular repositories.

use axum::{
    extract::State,
    http::HeaderMap,
    response::Response,
};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use super::utils::{render_template, render_error, add_user_to_context};
use super::like_handlers::get_trending_repos;

/// Trending repositories page
pub async fn trending_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let trending = get_trending_repos(db.as_ref(), 50).await;

    let mut context = Context::new();
    context.insert("trending_repos", &trending);
    context.insert("page_title", "Trending Repositories");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("trending.html", &context)
}
