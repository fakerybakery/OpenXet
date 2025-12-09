//! File editing handlers for creating and modifying files via the web UI.

use axum::{
    extract::{Form, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use crate::git::ObjectType;
use super::utils::{render_template, render_error, add_user_to_context, add_csrf_to_context, get_session_token, verify_csrf_token, get_current_user, can_user_write_repo, Breadcrumb};
use super::lfs::parse_lfs_pointer;
use super::tree_ops::{build_updated_tree, build_tree_with_addition, build_tree_with_deletion};

/// Edit file form
#[derive(serde::Deserialize)]
pub struct EditForm {
    pub content: String,
    pub filename: String,
    pub message: Option<String>,
    pub csrf_token: String,
}

/// Edit a file (GET - show editor)
pub async fn edit_file(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // SECURITY: Require authentication and write permission
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+edit+files").into_response(),
    };

    if !can_user_write_repo(&state, &current_user, &owner).await {
        return render_error("You don't have permission to edit files in this repository. Only repository owners and organization members can edit files.");
    }

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
    };

    let commit_id = match repo_handle.resolve_ref(&format!("refs/heads/{}", ref_name)) {
        Some(id) => id,
        None => return render_error(&format!("Branch '{}' not found", ref_name)),
    };

    let root_tree = match repo_handle.get_commit_tree(&commit_id) {
        Some(t) => t,
        None => return render_error("Could not read commit tree"),
    };

    let (blob_id, is_dir) = match repo_handle.resolve_path(&root_tree, &path) {
        Some((id, is_dir)) => (id, is_dir),
        None => return render_error(&format!("File '{}' not found", path)),
    };

    if is_dir {
        return render_error(&format!("'{}' is a directory, not a file", path));
    }

    let content = match repo_handle.get_blob_content(&blob_id) {
        Some(c) => c,
        None => return render_error("Could not read file content"),
    };

    if parse_lfs_pointer(&content).is_some() {
        return render_error("Cannot edit LFS files in the browser");
    }

    if content.iter().take(8000).any(|&b| b == 0) {
        return render_error("Cannot edit binary files in the browser");
    }

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("ref_name", &ref_name);
    context.insert("path", &path);

    let file_name = path.split('/').last().unwrap_or(&path);
    context.insert("file_name", file_name);

    let parts: Vec<&str> = path.split('/').collect();
    let breadcrumbs: Vec<Breadcrumb> = parts
        .iter()
        .enumerate()
        .map(|(i, name)| Breadcrumb {
            name: name.to_string(),
            path: parts[..=i].join("/"),
        })
        .collect();
    context.insert("breadcrumbs", &breadcrumbs);

    let text = String::from_utf8_lossy(&content).to_string();
    context.insert("content", &text);
    context.insert("is_new", &false);
    context.insert("active_tab", "files");

    add_user_to_context(&mut context, &state, &headers).await;
    add_csrf_to_context(&mut context, &headers).await;

    render_template("edit.html", &context)
}

/// New file (GET - show editor for new file) - root level
pub async fn new_file(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    render_new_file_form(&state, &headers, &owner, &repo, &ref_name, "").await
}

/// New file (GET - show editor for new file) - in directory
pub async fn new_file_in_dir(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, dir_path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Response {
    render_new_file_form(&state, &headers, &owner, &repo, &ref_name, &dir_path).await
}

async fn render_new_file_form(state: &AppState, headers: &HeaderMap, owner: &str, repo: &str, ref_name: &str, dir_path: &str) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    // SECURITY: Require authentication and write permission
    let current_user = match get_current_user(state, headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+create+files").into_response(),
    };

    if !can_user_write_repo(state, &current_user, owner).await {
        return render_error("You don't have permission to create files in this repository. Only repository owners and organization members can create files.");
    }

    let mut context = Context::new();
    context.insert("owner", owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);
    context.insert("ref_name", ref_name);
    context.insert("is_new", &true);
    context.insert("content", &"");

    let initial_path = if dir_path.is_empty() {
        String::new()
    } else {
        format!("{}/", dir_path)
    };
    context.insert("path", &initial_path);
    context.insert("file_name", &"");

    let breadcrumbs: Vec<Breadcrumb> = Vec::new();
    context.insert("breadcrumbs", &breadcrumbs);
    context.insert("active_tab", "files");

    add_user_to_context(&mut context, state, headers).await;
    add_csrf_to_context(&mut context, headers).await;

    render_template("edit.html", &context)
}

/// Commit file changes (POST)
pub async fn commit_file(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    Form(form): Form<EditForm>,
) -> Response {
    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return render_error("Invalid request. Please try again.");
    }

    // SECURITY: Require authentication and write permission
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+edit+files").into_response(),
    };

    if !can_user_write_repo(&state, &current_user, &owner).await {
        return render_error("You don't have permission to edit files in this repository. Only repository owners and organization members can edit files.");
    }

    commit_file_impl(state, &owner, &repo, &ref_name, &path, form).await
}

/// Commit new file (POST) - root level
pub async fn commit_new_file(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name)): Path<(String, String, String)>,
    headers: HeaderMap,
    Form(form): Form<EditForm>,
) -> Response {
    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return render_error("Invalid request. Please try again.");
    }

    // SECURITY: Require authentication and write permission
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+create+files").into_response(),
    };

    if !can_user_write_repo(&state, &current_user, &owner).await {
        return render_error("You don't have permission to create files in this repository. Only repository owners and organization members can create files.");
    }

    commit_file_impl(state, &owner, &repo, &ref_name, "", form).await
}

/// Commit new file (POST) - in directory
pub async fn commit_new_file_in_dir(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, ref_name, _dir)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    Form(form): Form<EditForm>,
) -> Response {
    // Verify CSRF token
    let session_token = get_session_token(&headers);
    if !verify_csrf_token(&form.csrf_token, session_token.as_deref()) {
        return render_error("Invalid request. Please try again.");
    }

    // SECURITY: Require authentication and write permission
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+create+files").into_response(),
    };

    if !can_user_write_repo(&state, &current_user, &owner).await {
        return render_error("You don't have permission to create files in this repository. Only repository owners and organization members can create files.");
    }

    commit_file_impl(state, &owner, &repo, &ref_name, "", form).await
}

/// Shared implementation for committing files (edit, rename, new)
async fn commit_file_impl(
    state: Arc<AppState>,
    owner: &str,
    repo: &str,
    ref_name: &str,
    original_path: &str,
    form: EditForm,
) -> Response {
    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => return render_error(&format!("Repository '{}' not found", full_name)),
    };

    let parent_commit_id = match repo_handle.resolve_ref(&format!("refs/heads/{}", ref_name)) {
        Some(id) => id,
        None => return render_error(&format!("Branch '{}' not found", ref_name)),
    };

    let root_tree = match repo_handle.get_commit_tree(&parent_commit_id) {
        Some(t) => t,
        None => return render_error("Could not read commit tree"),
    };

    let new_path = form.filename.trim().trim_matches('/').to_string();
    if new_path.is_empty() {
        return render_error("Filename cannot be empty");
    }

    let old_path = original_path.trim_matches('/');
    let is_rename = !old_path.is_empty() && old_path != new_path;
    let is_new = old_path.is_empty();

    let new_content = form.content.as_bytes();
    let new_blob_id = repo_handle.create_object(
        ObjectType::Blob,
        new_content,
    );

    let new_tree_id = if is_rename {
        let tree_after_delete = match build_tree_with_deletion(&repo_handle, &root_tree, old_path) {
            Some(id) => id,
            None => return render_error("Failed to delete old file"),
        };
        match build_tree_with_addition(&repo_handle, &tree_after_delete, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to create file at new path"),
        }
    } else if is_new {
        match build_tree_with_addition(&repo_handle, &root_tree, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to create file"),
        }
    } else {
        match build_updated_tree(&repo_handle, &root_tree, &new_path, &new_blob_id) {
            Some(id) => id,
            None => return render_error("Failed to update tree"),
        }
    };

    let default_message = if is_new {
        format!("Create {}", new_path)
    } else if is_rename {
        format!("Rename {} to {}", old_path, new_path)
    } else {
        format!("Update {}", new_path)
    };
    let message = form.message
        .filter(|m| !m.trim().is_empty())
        .unwrap_or(default_message);

    let new_commit_id = repo_handle.create_commit(
        &new_tree_id,
        &[parent_commit_id],
        &message,
        "Web User",
        "web@openxet.local",
    );

    let _ = repo_handle.update_ref(&format!("refs/heads/{}", ref_name), new_commit_id);

    Redirect::to(&format!("/{}/{}/blob/{}/{}", owner, repo_name, ref_name, new_path)).into_response()
}
