//! Organization management handlers: creating orgs, managing members.

use axum::{
    extract::{Form, Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use crate::db::entities::{org_member, user};
use super::utils::{render_template, render_error, get_current_user};

/// Form for creating a new org
#[derive(serde::Deserialize)]
pub struct NewOrgForm {
    pub name: String,
}

/// Form for adding a member
#[derive(serde::Deserialize)]
pub struct AddMemberForm {
    pub username: String,
}

/// New repository page (GET)
pub async fn new_repo_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let mut context = Context::new();

    let current_user = get_current_user(&state, &headers).await;
    if current_user.is_none() {
        return Redirect::to("/-/login?error=Please+sign+in+to+create+a+repository").into_response();
    }
    let username = current_user.clone().unwrap();

    context.insert("current_user", &current_user);

    let mut namespaces: Vec<String> = vec![username.clone()];

    if let Some(db) = &state.db {
        if let Ok(Some(user_record)) = user::Entity::find()
            .filter(user::Column::Username.eq(&username))
            .one(db.as_ref())
            .await
        {
            let memberships = org_member::Entity::find()
                .filter(org_member::Column::UserId.eq(user_record.id))
                .all(db.as_ref())
                .await
                .unwrap_or_default();

            for membership in memberships {
                if let Ok(Some(org)) = user::Entity::find_by_id(membership.org_id)
                    .one(db.as_ref())
                    .await
                {
                    namespaces.push(org.username);
                }
            }
        }
    }

    context.insert("namespaces", &namespaces);

    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }

    render_template("new_repo.html", &context)
}

/// Create repository (POST)
pub async fn create_repo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<super::home_handlers::NewRepoForm>,
) -> Response {
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+create+a+repository").into_response(),
    };

    let name = form.name.trim();
    if name.is_empty() {
        return Redirect::to("/-/new?error=Repository+name+cannot+be+empty").into_response();
    }
    if name.len() < 2 {
        return Redirect::to("/-/new?error=Repository+name+must+be+at+least+2+characters").into_response();
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Redirect::to("/-/new?error=Repository+name+can+only+contain+letters,+numbers,+dashes,+underscores,+and+dots").into_response();
    }

    let namespace = form.namespace.trim();
    if namespace.is_empty() {
        return Redirect::to("/-/new?error=Please+select+a+namespace").into_response();
    }

    let allowed = if namespace == current_user {
        true
    } else if let Some(db) = &state.db {
        let user_record = user::Entity::find()
            .filter(user::Column::Username.eq(&current_user))
            .one(db.as_ref())
            .await
            .ok()
            .flatten();

        let org_record = user::Entity::find()
            .filter(user::Column::Username.eq(namespace))
            .filter(user::Column::IsOrg.eq(true))
            .one(db.as_ref())
            .await
            .ok()
            .flatten();

        if let (Some(user), Some(org)) = (user_record, org_record) {
            org_member::Entity::find()
                .filter(org_member::Column::UserId.eq(user.id))
                .filter(org_member::Column::OrgId.eq(org.id))
                .one(db.as_ref())
                .await
                .map(|r| r.is_some())
                .unwrap_or(false)
        } else {
            false
        }
    } else {
        false
    };

    if !allowed {
        return Redirect::to("/-/new?error=You+don't+have+permission+to+create+repositories+in+this+namespace").into_response();
    }

    let full_name = format!("{}/{}", namespace, name);

    if state.repos.get_repo(&full_name).is_ok() {
        return Redirect::to("/-/new?error=Repository+already+exists").into_response();
    }

    let _ = state.repos.get_or_create_repo(&full_name);

    Redirect::to(&format!("/{}", full_name)).into_response()
}

/// New organization page (GET)
pub async fn new_org_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let mut context = Context::new();

    let current_user = get_current_user(&state, &headers).await;
    if current_user.is_none() {
        return Redirect::to("/-/login?error=Please+sign+in+to+create+an+organization").into_response();
    }

    context.insert("current_user", &current_user);

    if let Some(error) = query.get("error") {
        context.insert("error", error);
    }

    render_template("new_org.html", &context)
}

/// Create organization (POST)
pub async fn create_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<NewOrgForm>,
) -> Response {
    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in+to+create+an+organization").into_response(),
    };

    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let name = form.name.trim();
    if name.is_empty() {
        return Redirect::to("/-/new-org?error=Organization+name+cannot+be+empty").into_response();
    }
    if name.len() < 2 {
        return Redirect::to("/-/new-org?error=Organization+name+must+be+at+least+2+characters").into_response();
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Redirect::to("/-/new-org?error=Organization+name+can+only+contain+letters,+numbers,+dashes,+and+underscores").into_response();
    }

    let existing = user::Entity::find()
        .filter(user::Column::Username.eq(name))
        .one(db.as_ref())
        .await;

    if matches!(existing, Ok(Some(_))) {
        return Redirect::to("/-/new-org?error=Name+is+already+taken").into_response();
    }

    let creator = match user::Entity::find()
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

    let new_org = user::ActiveModel {
        username: Set(name.to_string()),
        password_hash: Set(String::new()),
        display_name: Set(Some(name.to_string())),
        email: Set(None),
        is_org: Set(true),
        created_at: Set(now),
        ..Default::default()
    };

    let org = match new_org.insert(db.as_ref()).await {
        Ok(o) => o,
        Err(e) => return render_error(&format!("Failed to create organization: {}", e)),
    };

    let membership = org_member::ActiveModel {
        org_id: Set(org.id),
        user_id: Set(creator.id),
        role: Set("owner".to_string()),
        created_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = membership.insert(db.as_ref()).await {
        return render_error(&format!("Failed to add owner to organization: {}", e));
    }

    Redirect::to(&format!("/{}", name)).into_response()
}

/// Add member to organization (POST)
pub async fn add_org_member(
    State(state): State<Arc<AppState>>,
    Path(org_name): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AddMemberForm>,
) -> Response {
    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in").into_response(),
    };

    let org = match user::Entity::find()
        .filter(user::Column::Username.eq(&org_name))
        .filter(user::Column::IsOrg.eq(true))
        .one(db.as_ref())
        .await
    {
        Ok(Some(o)) => o,
        _ => return render_error("Organization not found"),
    };

    let current_user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let is_owner = org_member::Entity::find()
        .filter(org_member::Column::OrgId.eq(org.id))
        .filter(org_member::Column::UserId.eq(current_user_record.id))
        .filter(org_member::Column::Role.eq("owner"))
        .one(db.as_ref())
        .await
        .map(|r| r.is_some())
        .unwrap_or(false);

    if !is_owner {
        return render_error("Only organization owners can add members");
    }

    let new_member = match user::Entity::find()
        .filter(user::Column::Username.eq(form.username.trim()))
        .filter(user::Column::IsOrg.eq(false))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return Redirect::to(&format!("/{}?error=User+not+found", org_name)).into_response(),
    };

    let existing = org_member::Entity::find()
        .filter(org_member::Column::OrgId.eq(org.id))
        .filter(org_member::Column::UserId.eq(new_member.id))
        .one(db.as_ref())
        .await;

    if matches!(existing, Ok(Some(_))) {
        return Redirect::to(&format!("/{}?error=User+is+already+a+member", org_name)).into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let membership = org_member::ActiveModel {
        org_id: Set(org.id),
        user_id: Set(new_member.id),
        role: Set("member".to_string()),
        created_at: Set(now),
        ..Default::default()
    };

    if let Err(e) = membership.insert(db.as_ref()).await {
        return render_error(&format!("Failed to add member: {}", e));
    }

    Redirect::to(&format!("/{}", org_name)).into_response()
}

/// Remove member from organization (POST)
pub async fn remove_org_member(
    State(state): State<Arc<AppState>>,
    Path((org_name, username)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let current_user = match get_current_user(&state, &headers).await {
        Some(u) => u,
        None => return Redirect::to("/-/login?error=Please+sign+in").into_response(),
    };

    let org = match user::Entity::find()
        .filter(user::Column::Username.eq(&org_name))
        .filter(user::Column::IsOrg.eq(true))
        .one(db.as_ref())
        .await
    {
        Ok(Some(o)) => o,
        _ => return render_error("Organization not found"),
    };

    let current_user_record = match user::Entity::find()
        .filter(user::Column::Username.eq(&current_user))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    let is_owner = org_member::Entity::find()
        .filter(org_member::Column::OrgId.eq(org.id))
        .filter(org_member::Column::UserId.eq(current_user_record.id))
        .filter(org_member::Column::Role.eq("owner"))
        .one(db.as_ref())
        .await
        .map(|r| r.is_some())
        .unwrap_or(false);

    if !is_owner {
        return render_error("Only organization owners can remove members");
    }

    let member_to_remove = match user::Entity::find()
        .filter(user::Column::Username.eq(&username))
        .one(db.as_ref())
        .await
    {
        Ok(Some(u)) => u,
        _ => return render_error("User not found"),
    };

    if member_to_remove.id == current_user_record.id {
        let owner_count = org_member::Entity::find()
            .filter(org_member::Column::OrgId.eq(org.id))
            .filter(org_member::Column::Role.eq("owner"))
            .count(db.as_ref())
            .await
            .unwrap_or(0);

        if owner_count <= 1 {
            return Redirect::to(&format!("/{}?error=Cannot+remove+the+only+owner", org_name)).into_response();
        }
    }

    let _ = org_member::Entity::delete_many()
        .filter(org_member::Column::OrgId.eq(org.id))
        .filter(org_member::Column::UserId.eq(member_to_remove.id))
        .exec(db.as_ref())
        .await;

    Redirect::to(&format!("/{}", org_name)).into_response()
}
