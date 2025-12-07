//! Like/star handlers for repositories.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, Set};
use std::sync::Arc;

use crate::api::AppState;
use crate::db::entities::{repo_like, user};
use super::utils::{render_error, get_current_user, get_session_token, verify_csrf_token};

/// JSON response for like/unlike
#[derive(serde::Serialize)]
pub struct LikeResponse {
    pub success: bool,
    pub liked: bool,
    pub like_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn is_ajax_request(headers: &HeaderMap) -> bool {
    headers.get("accept")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false)
}

/// Form for like/unlike with CSRF
#[derive(serde::Deserialize)]
pub struct LikeForm {
    pub csrf_token: String,
}

/// Like a repository (POST)
pub async fn like_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<LikeForm>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);
    let is_ajax = is_ajax_request(&headers);

    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        if is_ajax {
            return Json(LikeResponse { success: false, liked: false, like_count: 0, error: Some("Invalid request".to_string()) }).into_response();
        }
        return render_error("Invalid request. Please try again.");
    }

    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => {
            if is_ajax {
                return Json(LikeResponse { success: false, liked: false, like_count: 0, error: Some("Not logged in".to_string()) }).into_response();
            }
            return Redirect::to("/-/login?error=Please+sign+in+to+like+repositories").into_response();
        }
    };

    let db = match &state.db {
        Some(db) => db,
        None => {
            if is_ajax {
                return Json(LikeResponse { success: false, liked: false, like_count: 0, error: Some("Database not available".to_string()) }).into_response();
            }
            return render_error("Database not available");
        }
    };

    // Get user ID
    let user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => {
            if is_ajax {
                return Json(LikeResponse { success: false, liked: false, like_count: 0, error: Some("User not found".to_string()) }).into_response();
            }
            return render_error("User not found");
        }
    };

    // Check if already liked
    let existing = repo_like::Entity::find()
        .filter(repo_like::Column::RepoName.eq(&full_name))
        .filter(repo_like::Column::UserId.eq(user_record.id))
        .one(db.as_ref())
        .await;

    if matches!(existing, Ok(Some(_))) {
        // Already liked
        let like_count = get_like_count(db.as_ref(), &full_name).await;
        if is_ajax {
            return Json(LikeResponse { success: true, liked: true, like_count, error: None }).into_response();
        }
        return Redirect::to(&format!("/{}", full_name)).into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let new_like = repo_like::ActiveModel {
        repo_name: Set(full_name.clone()),
        user_id: Set(user_record.id),
        created_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = new_like.insert(db.as_ref()).await {
        if is_ajax {
            return Json(LikeResponse { success: false, liked: false, like_count: 0, error: Some(e.to_string()) }).into_response();
        }
        return render_error(&format!("Failed to like repository: {}", e));
    }

    let like_count = get_like_count(db.as_ref(), &full_name).await;
    if is_ajax {
        return Json(LikeResponse { success: true, liked: true, like_count, error: None }).into_response();
    }
    Redirect::to(&format!("/{}", full_name)).into_response()
}

/// Unlike a repository (POST)
pub async fn unlike_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<LikeForm>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);
    let is_ajax = is_ajax_request(&headers);

    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        if is_ajax {
            return Json(LikeResponse { success: false, liked: true, like_count: 0, error: Some("Invalid request".to_string()) }).into_response();
        }
        return render_error("Invalid request. Please try again.");
    }

    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => {
            if is_ajax {
                return Json(LikeResponse { success: false, liked: true, like_count: 0, error: Some("Not logged in".to_string()) }).into_response();
            }
            return Redirect::to("/-/login?error=Please+sign+in").into_response();
        }
    };

    let db = match &state.db {
        Some(db) => db,
        None => {
            if is_ajax {
                return Json(LikeResponse { success: false, liked: true, like_count: 0, error: Some("Database not available".to_string()) }).into_response();
            }
            return render_error("Database not available");
        }
    };

    // Get user ID
    let user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => {
            if is_ajax {
                return Json(LikeResponse { success: false, liked: true, like_count: 0, error: Some("User not found".to_string()) }).into_response();
            }
            return render_error("User not found");
        }
    };

    // Delete the like
    let _ = repo_like::Entity::delete_many()
        .filter(repo_like::Column::RepoName.eq(&full_name))
        .filter(repo_like::Column::UserId.eq(user_record.id))
        .exec(db.as_ref())
        .await;

    let like_count = get_like_count(db.as_ref(), &full_name).await;
    if is_ajax {
        return Json(LikeResponse { success: true, liked: false, like_count, error: None }).into_response();
    }
    Redirect::to(&format!("/{}", full_name)).into_response()
}

/// Get like count for a repository
pub async fn get_like_count(db: &sea_orm::DatabaseConnection, repo_name: &str) -> u64 {
    repo_like::Entity::find()
        .filter(repo_like::Column::RepoName.eq(repo_name))
        .count(db)
        .await
        .unwrap_or(0)
}

/// Check if user has liked a repository
pub async fn has_user_liked(db: &sea_orm::DatabaseConnection, repo_name: &str, user_id: i32) -> bool {
    repo_like::Entity::find()
        .filter(repo_like::Column::RepoName.eq(repo_name))
        .filter(repo_like::Column::UserId.eq(user_id))
        .one(db)
        .await
        .map(|r| r.is_some())
        .unwrap_or(false)
}

/// Trending repository info
#[derive(serde::Serialize)]
pub struct TrendingRepo {
    pub name: String,
    pub owner: String,
    pub repo: String,
    pub like_count: u64,
    pub description: Option<String>,
}

/// Get trending repositories (most liked in last 7 days or all-time)
pub async fn get_trending_repos(db: &sea_orm::DatabaseConnection, limit: u64) -> Vec<TrendingRepo> {
    use sea_orm::{FromQueryResult, Statement};

    #[derive(FromQueryResult)]
    struct RepoLikeCount {
        repo_name: String,
        like_count: i64,
    }

    // SECURITY: Sanitize limit to prevent SQL injection - clamp to reasonable range
    let safe_limit = limit.min(100).max(1);

    // Get repos with most likes
    let results = db.query_all(Statement::from_string(
        db.get_database_backend(),
        format!(
            r#"
            SELECT repo_name, COUNT(*) as like_count
            FROM repo_likes
            GROUP BY repo_name
            ORDER BY like_count DESC
            LIMIT {}
            "#,
            safe_limit
        ),
    ))
    .await
    .unwrap_or_default();

    let mut trending = Vec::new();
    for row in results {
        if let (Ok(repo_name), Ok(like_count)) = (
            row.try_get::<String>("", "repo_name"),
            row.try_get::<i64>("", "like_count"),
        ) {
            let parts: Vec<&str> = repo_name.splitn(2, '/').collect();
            if parts.len() == 2 {
                trending.push(TrendingRepo {
                    name: repo_name.clone(),
                    owner: parts[0].to_string(),
                    repo: parts[1].to_string(),
                    like_count: like_count as u64,
                    description: None,
                });
            }
        }
    }

    trending
}
