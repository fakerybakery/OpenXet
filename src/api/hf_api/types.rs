//! HuggingFace API types and data structures.

use serde::{Deserialize, Serialize};

// ============================================================================
// Request Types
// ============================================================================

/// POST /api/repos/create request body
#[derive(Debug, Deserialize)]
pub struct CreateRepoRequest {
    pub name: String,
    pub organization: Option<String>,
    #[serde(rename = "type")]
    pub repo_type: Option<String>,
    pub private: Option<bool>,
}

/// File info in preupload request
#[derive(Debug, Deserialize)]
pub struct PreuploadFile {
    pub path: String,
    pub size: u64,
    #[allow(dead_code)]
    pub sample: Option<String>,
}

/// POST /api/{type}s/{repo}/preupload/{revision} request body
#[derive(Debug, Deserialize)]
pub struct PreuploadRequest {
    pub files: Vec<PreuploadFile>,
}

// Note: LFS types are defined in api/lfs.rs and reused for HF compatibility

/// Query params for tree listing
#[derive(Debug, Deserialize, Default)]
pub struct TreeQuery {
    pub recursive: Option<bool>,
    #[allow(dead_code)]
    pub expand: Option<bool>,
}

// ============================================================================
// Response Types
// ============================================================================

/// Whoami response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoamiResponse {
    #[serde(rename = "type")]
    pub user_type: String,
    pub id: String,
    pub name: String,
    pub fullname: String,
    pub email: String,
    pub email_verified: bool,
    pub can_pay: bool,
    pub is_pro: bool,
    pub orgs: Vec<serde_json::Value>,
}

impl Default for WhoamiResponse {
    fn default() -> Self {
        Self {
            user_type: "user".to_string(),
            id: "anonymous-user".to_string(),
            name: "anonymous".to_string(),
            fullname: "Anonymous User".to_string(),
            email: "anonymous@localhost".to_string(),
            email_verified: true,
            can_pay: false,
            is_pro: false,
            orgs: vec![],
        }
    }
}

/// POST /api/repos/create response
#[derive(Debug, Serialize)]
pub struct CreateRepoResponse {
    #[serde(rename = "type")]
    pub repo_type: String,
    pub id: String,
    pub name: String,
    pub private: bool,
    pub url: String,
}

/// File info in preupload response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreuploadFileResponse {
    pub path: String,
    pub upload_mode: String,
    pub should_ignore: bool,
    pub oid: Option<String>,
}

/// POST /api/{type}s/{repo}/preupload/{revision} response
#[derive(Debug, Serialize)]
pub struct PreuploadResponse {
    pub files: Vec<PreuploadFileResponse>,
}

/// Commit response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitResponse {
    pub success: bool,
    pub commit_oid: String,
    pub commit_url: String,
    pub hook_output: String,
}

/// Sibling file in repo info
#[derive(Debug, Serialize)]
pub struct RepoSibling {
    pub rfilename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<String>,
}

/// Repository info response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInfoResponse {
    pub id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    pub author: String,
    pub sha: String,
    pub private: bool,
    pub disabled: bool,
    pub gated: bool,
    pub tags: Vec<String>,
    pub siblings: Vec<RepoSibling>,
    pub created_at: String,
    pub last_modified: String,
}

/// Tree entry for file listing
#[derive(Debug, Serialize)]
pub struct TreeEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub oid: String,
}

/// YAML validation response
#[derive(Debug, Serialize)]
pub struct ValidateYamlResponse {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}
