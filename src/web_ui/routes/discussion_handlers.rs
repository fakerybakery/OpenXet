//! Community discussion handlers for repository forums.

use axum::{
    extract::{Form, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use crate::db::entities::{discussion, discussion_comment, discussion_event, user};
use super::utils::{render_template, render_error, add_user_to_context, add_csrf_to_context, get_current_user, get_session_token, verify_csrf_token, format_relative_time};

/// Discussion info for templates
#[derive(serde::Serialize)]
struct DiscussionInfo {
    id: i32,
    title: String,
    author: String,
    status: String,
    comment_count: usize,
    created_at: String,
    updated_at: String,
}

/// Timeline item - unified comment or event for chronological display
#[derive(serde::Serialize)]
struct TimelineItem {
    item_type: String, // "comment", "event", or "op" (original post)
    author: String,
    content: Option<String>,
    event_type: Option<String>,
    old_value: Option<String>,
    new_value: Option<String>,
    created_at: String,
    timestamp: i64,
}

/// Form for creating a new discussion
#[derive(serde::Deserialize)]
pub struct NewDiscussionForm {
    pub title: String,
    pub content: String,
    pub csrf_token: String,
}

/// Form for posting a comment
#[derive(serde::Deserialize)]
pub struct NewCommentForm {
    pub content: String,
    pub csrf_token: String,
}

/// Form for close/reopen actions (CSRF only)
#[derive(serde::Deserialize)]
pub struct StatusChangeForm {
    pub csrf_token: String,
}

/// Combined community page showing both PRs and discussions
pub async fn community_page(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    use crate::db::entities::{pull_request, pr_comment};

    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    if state.repos.get_repo(&full_name).is_err() {
        return render_error(&format!("Repository '{}' not found", full_name));
    }

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    // Get pull requests (limit to recent 10)
    let prs = pull_request::Entity::find()
        .filter(pull_request::Column::RepoName.eq(&full_name))
        .order_by_desc(pull_request::Column::UpdatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    let open_pr_count = prs.iter().filter(|pr| pr.status == "open").count();
    let closed_pr_count = prs.len() - open_pr_count;

    #[derive(serde::Serialize)]
    struct PrInfo {
        number: i32,
        title: String,
        author: String,
        status: String,
        source_branch: String,
        target_branch: String,
        comment_count: usize,
        created_at: String,
    }

    let mut pr_infos = Vec::new();
    for pr in prs.iter().take(10) {
        let author = user::Entity::find_by_id(pr.author_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        let comment_count = pr_comment::Entity::find()
            .filter(pr_comment::Column::PrId.eq(pr.id))
            .count(db.as_ref())
            .await
            .unwrap_or(0) as usize;

        pr_infos.push(PrInfo {
            number: pr.number,
            title: pr.title.clone(),
            author,
            status: pr.status.clone(),
            source_branch: pr.source_branch.clone(),
            target_branch: pr.target_branch.clone(),
            comment_count,
            created_at: format_relative_time(pr.created_at),
        });
    }

    // Get discussions (limit to recent 10)
    let discussions = discussion::Entity::find()
        .filter(discussion::Column::RepoName.eq(&full_name))
        .order_by_desc(discussion::Column::UpdatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    let mut discussion_infos = Vec::new();
    for disc in discussions.iter().take(10) {
        let author = user::Entity::find_by_id(disc.author_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        let comment_count = discussion_comment::Entity::find()
            .filter(discussion_comment::Column::DiscussionId.eq(disc.id))
            .count(db.as_ref())
            .await
            .unwrap_or(0) as usize;

        discussion_infos.push(DiscussionInfo {
            id: disc.id,
            title: disc.title.clone(),
            author,
            status: disc.status.clone(),
            comment_count,
            created_at: format_relative_time(disc.created_at),
            updated_at: format_relative_time(disc.updated_at),
        });
    }

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("pull_requests", &pr_infos);
    context.insert("open_pr_count", &open_pr_count);
    context.insert("closed_pr_count", &closed_pr_count);
    context.insert("discussions", &discussion_infos);
    context.insert("discussion_count", &discussions.len());
    context.insert("active_tab", "community");

    add_user_to_context(&mut context, &state, &headers).await;
    add_csrf_to_context(&mut context, &headers).await;

    render_template("community.html", &context)
}

/// List discussions for a repo
pub async fn discussions_list(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    if state.repos.get_repo(&full_name).is_err() {
        return render_error(&format!("Repository '{}' not found", full_name));
    }

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let discussions = discussion::Entity::find()
        .filter(discussion::Column::RepoName.eq(&full_name))
        .order_by_desc(discussion::Column::UpdatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    let mut discussion_infos = Vec::new();
    for disc in discussions {
        let author = user::Entity::find_by_id(disc.author_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        let comment_count = discussion_comment::Entity::find()
            .filter(discussion_comment::Column::DiscussionId.eq(disc.id))
            .count(db.as_ref())
            .await
            .unwrap_or(0) as usize;

        discussion_infos.push(DiscussionInfo {
            id: disc.id,
            title: disc.title,
            author,
            status: disc.status,
            comment_count,
            created_at: format_relative_time(disc.created_at),
            updated_at: format_relative_time(disc.updated_at),
        });
    }

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("discussions", &discussion_infos);
    context.insert("discussion_count", &discussion_infos.len());
    context.insert("active_tab", "community");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("discussions.html", &context)
}

/// New discussion page (GET)
pub async fn new_discussion_page(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let current_user = get_current_user(&state, &headers).await;
    if current_user.is_none() {
        return Redirect::to(&format!("/-/login?error=Please+sign+in+to+start+a+discussion")).into_response();
    }

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("current_user", &current_user);
    context.insert("active_tab", "community");
    add_csrf_to_context(&mut context, &headers).await;

    render_template("new_discussion.html", &context)
}

/// Create a new discussion (POST)
pub async fn create_discussion(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<NewDiscussionForm>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return render_error("Invalid request. Please try again.");
    }

    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+start+a+discussion").into_response(),
    };

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let user = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let new_discussion = discussion::ActiveModel {
        repo_name: Set(full_name.clone()),
        author_id: Set(user.id),
        title: Set(form.title.clone()),
        status: Set("open".to_string()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let disc = match new_discussion.insert(db.as_ref()).await {
        Ok(d) => d,
        Err(e) => return render_error(&format!("Failed to create discussion: {}", e)),
    };

    if !form.content.trim().is_empty() {
        let first_comment = discussion_comment::ActiveModel {
            discussion_id: Set(disc.id),
            author_id: Set(user.id),
            content: Set(form.content),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };
        let _ = first_comment.insert(db.as_ref()).await;
    }

    Redirect::to(&format!("/{}/discussions/{}", full_name, disc.id)).into_response()
}

/// View a discussion thread
pub async fn discussion_detail(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, id)): Path<(String, String, i32)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let disc = match discussion::Entity::find_by_id(id)
        .one(db.as_ref())
        .await
    {
        Ok(Some(d)) if d.repo_name == full_name => d,
        _ => return render_error("Discussion not found"),
    };

    let author = user::Entity::find_by_id(disc.author_id)
        .one(db.as_ref())
        .await
        .ok()
        .flatten()
        .map(|u| u.username)
        .unwrap_or_else(|| "unknown".to_string());

    let comments = discussion_comment::Entity::find()
        .filter(discussion_comment::Column::DiscussionId.eq(id))
        .order_by_asc(discussion_comment::Column::CreatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    let events = discussion_event::Entity::find()
        .filter(discussion_event::Column::DiscussionId.eq(id))
        .order_by_asc(discussion_event::Column::CreatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    let mut timeline: Vec<TimelineItem> = Vec::new();

    let mut is_first = true;
    for comment in &comments {
        let comment_author = user::Entity::find_by_id(comment.author_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        timeline.push(TimelineItem {
            item_type: if is_first { "op".to_string() } else { "comment".to_string() },
            author: comment_author,
            content: Some(comment.content.clone()),
            event_type: None,
            old_value: None,
            new_value: None,
            created_at: format_relative_time(comment.created_at),
            timestamp: comment.created_at,
        });
        is_first = false;
    }

    for event in events {
        let event_actor = user::Entity::find_by_id(event.actor_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        timeline.push(TimelineItem {
            item_type: "event".to_string(),
            author: event_actor,
            content: None,
            event_type: Some(event.event_type),
            old_value: event.old_value,
            new_value: event.new_value,
            created_at: format_relative_time(event.created_at),
            timestamp: event.created_at,
        });
    }

    if !timeline.is_empty() {
        let op = timeline.remove(0);
        timeline.sort_by_key(|item| item.timestamp);
        timeline.insert(0, op);
    }

    let reply_count = comments.len().saturating_sub(1);

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("discussion_id", &disc.id);
    context.insert("discussion_title", &disc.title);
    context.insert("discussion_author", &author);
    context.insert("discussion_status", &disc.status);
    context.insert("discussion_created", &format_relative_time(disc.created_at));
    context.insert("timeline", &timeline);
    context.insert("reply_count", &reply_count);
    context.insert("active_tab", "community");

    add_user_to_context(&mut context, &state, &headers).await;
    add_csrf_to_context(&mut context, &headers).await;

    render_template("discussion.html", &context)
}

/// Post a comment to a discussion (POST)
pub async fn post_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, id)): Path<(String, String, i32)>,
    headers: HeaderMap,
    Form(form): Form<NewCommentForm>,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return render_error("Invalid request. Please try again.");
    }

    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+comment").into_response(),
    };

    if form.content.trim().is_empty() {
        return Redirect::to(&format!("/{}/discussions/{}", full_name, id)).into_response();
    }

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let user = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let new_comment = discussion_comment::ActiveModel {
        discussion_id: Set(id),
        author_id: Set(user.id),
        content: Set(form.content),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = new_comment.insert(db.as_ref()).await {
        return render_error(&format!("Failed to post comment: {}", e));
    }

    let _ = discussion::Entity::update_many()
        .col_expr(discussion::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(discussion::Column::Id.eq(id))
        .exec(db.as_ref())
        .await;

    Redirect::to(&format!("/{}/discussions/{}", full_name, id)).into_response()
}

/// Close a discussion (POST)
pub async fn close_discussion(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, id)): Path<(String, String, i32)>,
    headers: HeaderMap,
    Form(form): Form<StatusChangeForm>,
) -> Response {
    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return super::utils::render_error("Invalid request. Please try again.");
    }
    update_discussion_status(state, &owner, &repo, id, "closed", &headers).await
}

/// Reopen a discussion (POST)
pub async fn reopen_discussion(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, id)): Path<(String, String, i32)>,
    headers: HeaderMap,
    Form(form): Form<StatusChangeForm>,
) -> Response {
    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return super::utils::render_error("Invalid request. Please try again.");
    }
    update_discussion_status(state, &owner, &repo, id, "open", &headers).await
}

/// Helper to update discussion status
async fn update_discussion_status(
    state: Arc<AppState>,
    owner: &str,
    repo: &str,
    id: i32,
    new_status: &str,
    headers: &HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let current_user = match get_current_user(&state, headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in").into_response(),
    };

    if current_user != owner {
        return render_error("Only the repository owner can close or reopen discussions");
    }

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let actor = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let disc = match discussion::Entity::find_by_id(id)
        .one(db.as_ref())
        .await
    {
        Ok(Some(d)) if d.repo_name == full_name => d,
        _ => return render_error("Discussion not found"),
    };

    let old_status = disc.status.clone();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let _ = discussion::Entity::update_many()
        .col_expr(discussion::Column::Status, sea_orm::sea_query::Expr::value(new_status))
        .col_expr(discussion::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(discussion::Column::Id.eq(id))
        .filter(discussion::Column::RepoName.eq(&full_name))
        .exec(db.as_ref())
        .await;

    let event_type = if new_status == "closed" { "closed" } else { "reopened" };
    let new_event = discussion_event::ActiveModel {
        discussion_id: Set(id),
        actor_id: Set(actor.id),
        event_type: Set(event_type.to_string()),
        old_value: Set(Some(old_status)),
        new_value: Set(Some(new_status.to_string())),
        created_at: Set(now),
        ..Default::default()
    };
    let _ = new_event.insert(db.as_ref()).await;

    Redirect::to(&format!("/{}/discussions/{}", full_name, id)).into_response()
}
