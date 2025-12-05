//! Home page, profile pages, and search handlers.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::sync::Arc;
use tera::Context;

use crate::api::AppState;
use crate::db::entities::{org_member, user};
use super::utils::{render_template, render_error, add_user_to_context, format_size};

/// Member info for templates
#[derive(serde::Serialize)]
struct MemberInfo {
    username: String,
    role: String,
}

/// Org info for templates
#[derive(serde::Serialize)]
struct OrgInfo {
    name: String,
    role: String,
}

/// New repo form data
#[derive(serde::Deserialize)]
pub struct NewRepoForm {
    pub name: String,
    pub namespace: String,
}

/// Query params for repo page
#[derive(serde::Deserialize, Default)]
pub struct RepoQuery {
    pub tab: Option<String>,
    pub branch: Option<String>,
}

/// Tree entry info for templates
#[derive(serde::Serialize)]
struct TreeEntryInfo {
    name: String,
    full_path: String,
    is_dir: bool,
    is_lfs: bool,
    lfs_status: Option<String>,
    lfs_size: Option<String>,
    lfs_oid: Option<String>,
}

/// Home page
pub async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let mut context = Context::new();

    let repos: Vec<String> = state.repos.list_repos();
    let cas_stats = state.cas.stats();
    let lfs_stats = state.cas.lfs_stats();

    context.insert("repos", &repos);
    context.insert("repo_count", &repos.len());
    context.insert("block_count", &cas_stats.block_count);
    context.insert("chunk_count", &cas_stats.chunk_count);

    context.insert("lfs_object_count", &lfs_stats.object_count);
    context.insert("total_uploaded", &format_size(lfs_stats.total_logical_size));
    context.insert("total_stored", &format_size(lfs_stats.total_physical_size));
    context.insert("total_uploaded_bytes", &lfs_stats.total_logical_size);
    context.insert("total_stored_bytes", &lfs_stats.total_physical_size);

    let savings_bytes = lfs_stats.total_logical_size.saturating_sub(lfs_stats.total_physical_size);
    let savings_percent = if lfs_stats.total_logical_size > 0 {
        (savings_bytes as f64 / lfs_stats.total_logical_size as f64) * 100.0
    } else {
        0.0
    };
    context.insert("savings", &format_size(savings_bytes));
    context.insert("savings_percent", &format!("{:.1}", savings_percent));
    context.insert("dedup_ratio", &format!("{:.2}x", lfs_stats.dedup_ratio));

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("index.html", &context)
}

/// User/org profile page
pub async fn user_profile(
    State(state): State<Arc<AppState>>,
    Path(owner): Path<String>,
    headers: HeaderMap,
) -> Response {
    let db = match &state.db {
        Some(db) => db,
        None => return render_error("Database not available"),
    };

    let owner_user = user::Entity::find()
        .filter(user::Column::Username.eq(&owner))
        .one(db.as_ref())
        .await
        .ok()
        .flatten();

    let all_repos = state.repos.list_repos();
    let user_repos: Vec<String> = all_repos
        .iter()
        .filter(|r| r.starts_with(&format!("{}/", owner)))
        .cloned()
        .collect();

    if owner_user.is_none() && user_repos.is_empty() {
        return render_error(&format!("'{}' not found", owner));
    }

    let is_org = owner_user.as_ref().map(|u| u.is_org).unwrap_or(false);
    let current_user = super::utils::get_current_user(&state, &headers).await;

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repos", &user_repos);
    context.insert("repo_count", &user_repos.len());
    context.insert("is_org", &is_org);

    if is_org {
        let owner_id = owner_user.as_ref().map(|u| u.id).unwrap_or(0);

        let members = org_member::Entity::find()
            .filter(org_member::Column::OrgId.eq(owner_id))
            .all(db.as_ref())
            .await
            .unwrap_or_default();

        let mut member_infos = Vec::new();
        for member in &members {
            if let Ok(Some(u)) = user::Entity::find_by_id(member.user_id).one(db.as_ref()).await {
                member_infos.push(MemberInfo {
                    username: u.username,
                    role: member.role.clone(),
                });
            }
        }

        context.insert("members", &member_infos);
        context.insert("member_count", &member_infos.len());

        let is_org_owner = if let Some(ref cu) = current_user {
            member_infos.iter().any(|m| m.username == *cu && m.role == "owner")
        } else {
            false
        };
        context.insert("is_org_owner", &is_org_owner);
    } else {
        if let Some(ref owner_user) = owner_user {
            let memberships = org_member::Entity::find()
                .filter(org_member::Column::UserId.eq(owner_user.id))
                .all(db.as_ref())
                .await
                .unwrap_or_default();

            let mut org_infos = Vec::new();
            for membership in memberships {
                if let Ok(Some(org)) = user::Entity::find_by_id(membership.org_id).one(db.as_ref()).await {
                    if org.is_org {
                        org_infos.push(OrgInfo {
                            name: org.username,
                            role: membership.role,
                        });
                    }
                }
            }

            context.insert("orgs", &org_infos);
            context.insert("org_count", &org_infos.len());
        }
    }

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("user.html", &context)
}

/// Repository detail page with tabs
pub async fn repo_detail(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<RepoQuery>,
    headers: HeaderMap,
) -> Response {
    use super::lfs::check_lfs_file;
    use super::repo_handlers::find_and_render_readme;
    use super::utils::BranchInfo;

    let repo_name = repo.trim_end_matches(".git");
    let full_name = format!("{}/{}", owner, repo_name);

    let repo_handle = match state.repos.get_repo(&full_name) {
        Ok(r) => r,
        Err(_) => {
            return render_error(&format!("Repository '{}' not found", full_name));
        }
    };

    let mut context = Context::new();
    context.insert("owner", &owner);
    context.insert("repo_name", repo_name);
    context.insert("full_name", &full_name);

    let git_refs = repo_handle.list_refs();
    let branches: Vec<BranchInfo> = git_refs
        .iter()
        .filter(|r| r.name.starts_with("refs/heads/"))
        .map(|r| {
            let short_name = r.name.strip_prefix("refs/heads/").unwrap_or(&r.name);
            BranchInfo {
                name: short_name.to_string(),
            }
        })
        .collect();

    let current_branch = query.branch
        .or_else(|| branches.iter().find(|b| b.name == "main").map(|b| b.name.clone()))
        .or_else(|| branches.first().map(|b| b.name.clone()))
        .unwrap_or_else(|| "main".to_string());

    let active_tab = query.tab.unwrap_or_else(|| "overview".to_string());

    context.insert("branches", &branches);
    context.insert("current_branch", &current_branch);
    context.insert("active_tab", &active_tab);

    let commit_id = repo_handle.resolve_ref(&format!("refs/heads/{}", current_branch));

    if let Some(commit_id) = commit_id {
        if let Some(root_tree) = repo_handle.get_commit_tree(&commit_id) {
            if active_tab == "overview" {
                if let Some(readme_html) = find_and_render_readme(&repo_handle, &root_tree) {
                    context.insert("readme_html", &readme_html);
                }
            }

            if active_tab == "files" {
                if let Some(entries) = repo_handle.parse_tree(&root_tree) {
                    let entry_infos: Vec<TreeEntryInfo> = entries
                        .iter()
                        .map(|e| {
                            let (is_lfs, lfs_status, lfs_size, lfs_oid) = check_lfs_file(&repo_handle, &state, e);
                            TreeEntryInfo {
                                name: e.name.clone(),
                                full_path: e.name.clone(),
                                is_dir: e.is_dir,
                                is_lfs,
                                lfs_status,
                                lfs_size,
                                lfs_oid,
                            }
                        })
                        .collect();
                    context.insert("entries", &entry_infos);
                }
            }
        }
    }

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("repo.html", &context)
}

/// Stats page
pub async fn stats(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let mut context = Context::new();

    let repos: Vec<String> = state.repos.list_repos();
    let cas_stats = state.cas.stats();
    let lfs_stats = state.cas.lfs_stats();

    context.insert("repos", &repos);
    context.insert("repo_count", &repos.len());
    context.insert("block_count", &cas_stats.block_count);
    context.insert("chunk_count", &cas_stats.chunk_count);
    context.insert("reconstruction_count", &cas_stats.reconstruction_count);
    context.insert("lfs_object_count", &lfs_stats.object_count);

    add_user_to_context(&mut context, &state, &headers).await;

    render_template("index.html", &context)
}

/// Search query params
#[derive(serde::Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

/// Search result item
#[derive(serde::Serialize)]
struct SearchResult {
    name: String,
    description: Option<String>,
}

/// Search response for JSON API
#[derive(serde::Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
    query: String,
}

/// Search page and API
pub async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Response {
    let raw_query = query.q.unwrap_or_default();
    let q = raw_query.trim().to_lowercase();

    let repos: Vec<String> = state.repos.list_repos();

    let results: Vec<SearchResult> = if q.is_empty() {
        repos.iter().take(20).map(|name| SearchResult {
            name: name.clone(),
            description: None,
        }).collect()
    } else {
        repos.iter()
            .filter(|name| name.to_lowercase().contains(&q))
            .take(20)
            .map(|name| SearchResult {
                name: name.clone(),
                description: None,
            })
            .collect()
    };

    let accept = headers.get("accept").and_then(|h| h.to_str().ok()).unwrap_or("");
    if accept.contains("application/json") || headers.get("x-requested-with").is_some() {
        let response = SearchResponse {
            results,
            query: q,
        };
        return axum::Json(response).into_response();
    }

    let mut context = Context::new();
    context.insert("query", &raw_query);
    context.insert("results", &results);
    context.insert("result_count", &results.len());
    add_user_to_context(&mut context, &state, &headers).await;

    render_template("search.html", &context)
}
