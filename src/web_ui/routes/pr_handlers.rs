//! Pull request handlers for code review and merging.

use axum::{
    extract::{Form, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use crate::db::entities::{pull_request, pr_comment, pr_event, user};
use crate::git::ObjectId;
use super::utils::{render_template, render_error, add_user_to_context, add_csrf_to_context, get_current_user, get_session_token, verify_csrf_token, format_relative_time, can_user_write_repo};
use super::diff::compute_diff;

/// PR info for templates
#[derive(serde::Serialize)]
pub struct PrInfo {
    pub id: i32,
    pub number: i32,
    pub title: String,
    pub author: String,
    pub status: String,
    pub source_branch: String,
    pub target_branch: String,
    pub comment_count: usize,
    pub created_at: String,
    pub updated_at: String,
}

/// Timeline item for PR
#[derive(serde::Serialize)]
pub struct PrTimelineItem {
    pub item_type: String, // "comment", "event", "description"
    pub author: String,
    pub content: Option<String>,
    pub event_type: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub created_at: String,
    pub timestamp: i64,
}

/// File change info for diff view
#[derive(serde::Serialize)]
pub struct FileChange {
    pub path: String,
    pub additions: usize,
    pub deletions: usize,
    pub diff_html: String,
}

/// Form for creating a new PR
#[derive(serde::Deserialize)]
pub struct NewPrForm {
    pub title: String,
    pub description: String,
    pub source_branch: String,
    pub target_branch: String,
    pub csrf_token: String,
}

/// Form for posting a comment
#[derive(serde::Deserialize)]
pub struct PrCommentForm {
    pub content: String,
    pub csrf_token: String,
}

/// Form for PR actions (close, reopen, merge)
#[derive(serde::Deserialize)]
pub struct PrActionForm {
    pub csrf_token: String,
}

/// List pull requests for a repo
pub async fn pr_list(
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

    let prs = pull_request::Entity::find()
        .filter(pull_request::Column::RepoName.eq(&full_name))
        .order_by_desc(pull_request::Column::UpdatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    let mut pr_infos = Vec::new();
    for pr in prs {
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
            id: pr.id,
            number: pr.number,
            title: pr.title,
            author,
            status: pr.status,
            source_branch: pr.source_branch,
            target_branch: pr.target_branch,
            comment_count,
            created_at: format_relative_time(pr.created_at),
            updated_at: format_relative_time(pr.updated_at),
        });
    }

    let open_count = pr_infos.iter().filter(|p| p.status == "open").count();
    let closed_count = pr_infos.iter().filter(|p| p.status != "open").count();

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("pull_requests", &pr_infos);
    context.insert("open_count", &open_count);
    context.insert("closed_count", &closed_count);
    context.insert("active_tab", "pull_requests");

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("pr_list.html", &context)
}

/// New PR page (GET)
pub async fn new_pr_page(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let current_user = get_current_user(&state, &headers).await;
    if current_user.is_none() {
        return Redirect::to(&format!("/-/login?error=Please+sign+in+to+create+a+pull+request")).into_response();
    }

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
    };

    // Get list of branches
    let refs = repo_handle.list_refs();
    let branches: Vec<String> = refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/"))
        .map(|r| r.name.strip_prefix("refs/heads/").unwrap_or(&r.name).to_string())
        .collect();

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("current_user", &current_user);
    context.insert("branches", &branches);
    context.insert("default_branch", &"main");
    context.insert("active_tab", "pull_requests");

    add_csrf_to_context(&mut context, &headers).await;

    render_template("new_pr.html", &context)
}

/// Create a new PR (POST)
pub async fn create_pr(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<NewPrForm>,
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
        None => return Redirect::to("/-/login?error=Please+sign+in+to+create+a+pull+request").into_response(),
    };

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    // Validate branches exist
    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
    };

    let source_ref = format!("refs/heads/{}", form.source_branch);
    let target_ref = format!("refs/heads/{}", form.target_branch);

    if repo_handle.get_ref(&source_ref).is_none() {
        return render_error(&format!("Source branch '{}' not found", form.source_branch));
    }
    if repo_handle.get_ref(&target_ref).is_none() {
        return render_error(&format!("Target branch '{}' not found", form.target_branch));
    }

    if form.source_branch == form.target_branch {
        return render_error("Source and target branches must be different");
    }

    // Get next PR number for this repo
    let max_number = pull_request::Entity::find()
        .filter(pull_request::Column::RepoName.eq(&full_name))
        .order_by_desc(pull_request::Column::Number)
        .one(db.as_ref())
        .await
        .ok()
        .flatten()
        .map(|pr| pr.number)
        .unwrap_or(0);

    let new_number = max_number + 1;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Get commit hashes
    let source_commit_id = repo_handle.resolve_ref(&source_ref);
    let source_commit = source_commit_id.as_ref().map(|id| id.to_hex());
    let target_commit = repo_handle.resolve_ref(&target_ref).map(|id| id.to_hex());

    let new_pr = pull_request::ActiveModel {
        repo_name: Set(full_name.clone()),
        number: Set(new_number),
        author_id: Set(user_record.id),
        title: Set(form.title.clone()),
        description: Set(form.description.clone()),
        source_branch: Set(form.source_branch.clone()),
        target_branch: Set(form.target_branch.clone()),
        source_commit: Set(source_commit),
        target_commit: Set(target_commit),
        status: Set("open".to_string()),
        merged_by: Set(None),
        merged_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let pr = match new_pr.insert(db.as_ref()).await {
        Ok(p) => p,
        Err(e) => return render_error(&format!("Failed to create pull request: {}", e)),
    };

    // Create PR ref (refs/pull/{number}/head) for tracking
    // This allows the PR to work even if the source branch is deleted
    if let Some(commit_id) = source_commit_id {
        let pr_ref = format!("refs/pull/{}/head", new_number);
        if let Err(e) = repo_handle.update_ref(&pr_ref, commit_id) {
            tracing::warn!("Failed to create PR ref {}: {}", pr_ref, e);
            // Don't fail the PR creation, just log the warning
        }
    }

    // Create opened event
    let event = pr_event::ActiveModel {
        pr_id: Set(pr.id),
        actor_id: Set(user_record.id),
        event_type: Set("opened".to_string()),
        old_value: Set(None),
        new_value: Set(None),
        created_at: Set(now),
        ..Default::default()
    };
    let _ = event.insert(db.as_ref()).await;

    Redirect::to(&format!("/{}/pulls/{}", full_name, new_number)).into_response()
}

/// View a pull request
pub async fn pr_detail(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let pr = match pull_request::Entity::find()
        .filter(pull_request::Column::RepoName.eq(&full_name))
        .filter(pull_request::Column::Number.eq(number))
        .one(db.as_ref())
        .await
    {
        Ok(Some(p)) => p,
        _ => return render_error("Pull request not found"),
    };

    let author = user::Entity::find_by_id(pr.author_id)
        .one(db.as_ref())
        .await
        .ok()
        .flatten()
        .map(|u| u.username)
        .unwrap_or_else(|| "unknown".to_string());

    // Get comments
    let comments = pr_comment::Entity::find()
        .filter(pr_comment::Column::PrId.eq(pr.id))
        .order_by_asc(pr_comment::Column::CreatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    // Get events
    let events = pr_event::Entity::find()
        .filter(pr_event::Column::PrId.eq(pr.id))
        .order_by_asc(pr_event::Column::CreatedAt)
        .all(db.as_ref())
        .await
        .unwrap_or_default();

    // Build timeline
    let mut timeline: Vec<PrTimelineItem> = Vec::new();

    // Add description as first item if not empty
    if !pr.description.is_empty() {
        timeline.push(PrTimelineItem {
            item_type: "description".to_string(),
            author: author.clone(),
            content: Some(pr.description.clone()),
            event_type: None,
            old_value: None,
            new_value: None,
            file_path: None,
            line_number: None,
            created_at: format_relative_time(pr.created_at),
            timestamp: pr.created_at,
        });
    }

    for comment in comments {
        let comment_author = user::Entity::find_by_id(comment.author_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        timeline.push(PrTimelineItem {
            item_type: "comment".to_string(),
            author: comment_author,
            content: Some(comment.content),
            event_type: None,
            old_value: None,
            new_value: None,
            file_path: comment.file_path,
            line_number: comment.line_number,
            created_at: format_relative_time(comment.created_at),
            timestamp: comment.created_at,
        });
    }

    for event in events {
        // Skip "opened" event as it's implied
        if event.event_type == "opened" {
            continue;
        }

        let event_actor = user::Entity::find_by_id(event.actor_id)
            .one(db.as_ref())
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "unknown".to_string());

        timeline.push(PrTimelineItem {
            item_type: "event".to_string(),
            author: event_actor,
            content: None,
            event_type: Some(event.event_type),
            old_value: event.old_value,
            new_value: event.new_value,
            file_path: None,
            line_number: None,
            created_at: format_relative_time(event.created_at),
            timestamp: event.created_at,
        });
    }

    // Sort timeline by timestamp
    timeline.sort_by_key(|item| item.timestamp);

    // Generate diff if we have commits
    let mut file_changes: Vec<FileChange> = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;

    if let (Some(source_commit), Some(target_commit)) = (&pr.source_commit, &pr.target_commit) {
        if let Ok(repo_handle) = state.repos.get_repo(&full_name) {
            if let (Some(source_id), Some(target_id)) = (
                ObjectId::from_hex(source_commit),
                ObjectId::from_hex(target_commit),
            ) {
                // Get trees from commits
                let source_tree = repo_handle.get_commit_tree(&source_id);
                let target_tree = repo_handle.get_commit_tree(&target_id);

                if let Some(source_tree) = source_tree {
                    let changes = compute_diff(&repo_handle, target_tree.as_ref(), &source_tree);
                    for change in changes {
                        additions += change.additions;
                        deletions += change.deletions;

                        // Convert diff lines to HTML
                        let diff_html = change.diff_lines.iter()
                            .map(|line| {
                                let class = match line.line_type.as_str() {
                                    "add" => "add",
                                    "del" => "del",
                                    _ => "",
                                };
                                format!("<span class=\"diff-line {}\">{}</span>", class,
                                    html_escape(&line.content))
                            })
                            .collect::<Vec<_>>()
                            .join("\n");

                        file_changes.push(FileChange {
                            path: change.path,
                            additions: change.additions,
                            deletions: change.deletions,
                            diff_html: format!("<pre>{}</pre>", diff_html),
                        });
                    }
                }
            }
        }
    }

    // Simple HTML escape helper
    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    // Check if current user can merge (must have write permission)
    let current_user = get_current_user(&state, &headers).await;
    let can_merge = if let Some(ref user) = current_user {
        // Only users with write access can merge PRs
        can_user_write_repo(&state, user, &owner).await
    } else {
        false
    };

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("pr_number", &pr.number);
    context.insert("pr_title", &pr.title);
    context.insert("pr_author", &author);
    context.insert("pr_status", &pr.status);
    context.insert("source_branch", &pr.source_branch);
    context.insert("target_branch", &pr.target_branch);
    context.insert("pr_created", &format_relative_time(pr.created_at));
    context.insert("timeline", &timeline);
    context.insert("file_changes", &file_changes);
    context.insert("additions", &additions);
    context.insert("deletions", &deletions);
    context.insert("files_changed", &file_changes.len());
    context.insert("can_merge", &can_merge);
    context.insert("active_tab", "pull_requests");

    add_user_to_context(&mut context, &state, &headers).await;
    add_csrf_to_context(&mut context, &headers).await;

    render_template("pr_detail.html", &context)
}

/// Post a comment on a PR
pub async fn post_pr_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    headers: HeaderMap,
    Form(form): Form<PrCommentForm>,
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
        return Redirect::to(&format!("/{}/pulls/{}", full_name, number)).into_response();
    }

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let pr = match pull_request::Entity::find()
        .filter(pull_request::Column::RepoName.eq(&full_name))
        .filter(pull_request::Column::Number.eq(number))
        .one(db.as_ref())
        .await
    {
        Ok(Some(p)) => p,
        _ => return render_error("Pull request not found"),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let new_comment = pr_comment::ActiveModel {
        pr_id: Set(pr.id),
        author_id: Set(user_record.id),
        content: Set(form.content),
        file_path: Set(None),
        line_number: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = new_comment.insert(db.as_ref()).await {
        return render_error(&format!("Failed to post comment: {}", e));
    }

    // Update PR updated_at
    let _ = pull_request::Entity::update_many()
        .col_expr(pull_request::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(pull_request::Column::Id.eq(pr.id))
        .exec(db.as_ref())
        .await;

    Redirect::to(&format!("/{}/pulls/{}", full_name, number)).into_response()
}

/// Close a PR
pub async fn close_pr(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    headers: HeaderMap,
    Form(form): Form<PrActionForm>,
) -> Response {
    update_pr_status(state, &owner, &repo, number, "closed", &headers, &form.csrf_token).await
}

/// Reopen a PR
pub async fn reopen_pr(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    headers: HeaderMap,
    Form(form): Form<PrActionForm>,
) -> Response {
    update_pr_status(state, &owner, &repo, number, "open", &headers, &form.csrf_token).await
}

/// Merge a PR
pub async fn merge_pr(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, number)): Path<(String, String, i32)>,
    headers: HeaderMap,
    Form(form): Form<PrActionForm>,
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
        None => return Redirect::to("/-/login?error=Please+sign+in").into_response(),
    };

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let pr = match pull_request::Entity::find()
        .filter(pull_request::Column::RepoName.eq(&full_name))
        .filter(pull_request::Column::Number.eq(number))
        .one(db.as_ref())
        .await
    {
        Ok(Some(p)) => p,
        _ => return render_error("Pull request not found"),
    };

    if pr.status != "open" {
        return render_error("Can only merge open pull requests");
    }

    // SECURITY: Only users with write permission can merge PRs
    // PR authors cannot merge their own PRs unless they have write access
    if !can_user_write_repo(&state, &current_user, &owner).await {
        return render_error("You don't have permission to merge pull requests in this repository. Only repository owners and organization members can merge.");
    }

    // Perform the merge by updating target branch to source commit
    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error("Repository not found"),
    };

    let source_ref = format!("refs/heads/{}", pr.source_branch);
    let target_ref = format!("refs/heads/{}", pr.target_branch);

    let source_commit = match repo_handle.resolve_ref(&source_ref) {
        Some(id) => id,
        None => return render_error("Source branch not found"),
    };

    // Fast-forward merge: update target branch to source commit
    if let Err(e) = repo_handle.update_ref(&target_ref, source_commit) {
        return render_error(&format!("Failed to merge: {}", e));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Update PR status
    let _ = pull_request::Entity::update_many()
        .col_expr(pull_request::Column::Status, sea_orm::sea_query::Expr::value("merged"))
        .col_expr(pull_request::Column::MergedBy, sea_orm::sea_query::Expr::value(user_record.id))
        .col_expr(pull_request::Column::MergedAt, sea_orm::sea_query::Expr::value(now))
        .col_expr(pull_request::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(pull_request::Column::Id.eq(pr.id))
        .exec(db.as_ref())
        .await;

    // Create merged event
    let event = pr_event::ActiveModel {
        pr_id: Set(pr.id),
        actor_id: Set(user_record.id),
        event_type: Set("merged".to_string()),
        old_value: Set(Some("open".to_string())),
        new_value: Set(Some("merged".to_string())),
        created_at: Set(now),
        ..Default::default()
    };
    let _ = event.insert(db.as_ref()).await;

    Redirect::to(&format!("/{}/pulls/{}", full_name, number)).into_response()
}

/// Helper to update PR status
async fn update_pr_status(
    state: Arc<AppState>,
    owner: &str,
    repo: &str,
    number: i32,
    new_status: &str,
    headers: &HeaderMap,
    csrf_token: &str,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // Verify CSRF token
    let session_token = get_session_token(headers);
    if !verify_csrf_token(csrf_token, session_token.as_deref()) {
        return render_error("Invalid request. Please try again.");
    }

    let current_user = match get_current_user(&state, headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in").into_response(),
    };

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let pr = match pull_request::Entity::find()
        .filter(pull_request::Column::RepoName.eq(&full_name))
        .filter(pull_request::Column::Number.eq(number))
        .one(db.as_ref())
        .await
    {
        Ok(Some(p)) => p,
        _ => return render_error("Pull request not found"),
    };

    // Check permission
    let pr_author = user::Entity::find_by_id(pr.author_id)
        .one(db.as_ref())
        .await
        .ok()
        .flatten()
        .map(|u| u.username)
        .unwrap_or_default();

    if current_user != owner && current_user != pr_author {
        return render_error("Only the repository owner or PR author can modify this pull request");
    }

    let old_status = pr.status.clone();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let _ = pull_request::Entity::update_many()
        .col_expr(pull_request::Column::Status, sea_orm::sea_query::Expr::value(new_status))
        .col_expr(pull_request::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
        .filter(pull_request::Column::Id.eq(pr.id))
        .exec(db.as_ref())
        .await;

    // Create event
    let event_type = if new_status == "closed" { "closed" } else { "reopened" };
    let event = pr_event::ActiveModel {
        pr_id: Set(pr.id),
        actor_id: Set(user_record.id),
        event_type: Set(event_type.to_string()),
        old_value: Set(Some(old_status)),
        new_value: Set(Some(new_status.to_string())),
        created_at: Set(now),
        ..Default::default()
    };
    let _ = event.insert(db.as_ref()).await;

    Redirect::to(&format!("/{}/pulls/{}", full_name, number)).into_response()
}
