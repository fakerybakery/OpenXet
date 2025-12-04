//! Authentication and authorization module.
//!
//! Provides user management, permission checking, and token-based auth.
//! Users and organizations are stored in the database.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::RwLock;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
};
use sha2::{Digest, Sha256};

use crate::db::entities::{org_member, user};
use crate::error::{Result, ServerError};

/// Hash a password with salt
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"git-xet-server-salt:");
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    hash_password(password) == hash
}

/// An access token
#[derive(Clone, Debug)]
pub struct Token {
    pub token: String,
    pub user_id: i32,
    pub username: String,
    pub is_org: bool,
    pub expires_at: SystemTime,
}

impl Token {
    pub fn new(user_id: i32, username: String, is_org: bool, duration: Duration) -> Self {
        let token = generate_token();
        let expires_at = SystemTime::now() + duration;

        Self {
            token,
            user_id,
            username,
            is_org,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

/// Generate a secure random token
fn generate_token() -> String {
    let mut hasher = Sha256::new();

    // Use timestamp for uniqueness
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    hasher.update(timestamp.to_le_bytes());

    // Use thread ID
    let thread_id = std::thread::current().id();
    hasher.update(format!("{:?}", thread_id).as_bytes());

    // Use random-ish data from stack
    let stack_addr = &timestamp as *const _ as usize;
    hasher.update(stack_addr.to_le_bytes());

    let result = hasher.finalize();
    BASE64.encode(&result[..24]) // 24 bytes = 32 base64 chars
}

/// Authentication manager with database backend
pub struct AuthManager {
    db: Option<Arc<DatabaseConnection>>,
    tokens: RwLock<HashMap<String, Token>>,
    token_duration: Duration,
    allow_anonymous_read: bool,
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            db: None,
            tokens: RwLock::new(HashMap::new()),
            token_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            allow_anonymous_read: true, // Public read by default
        }
    }

    pub fn with_db(db: Arc<DatabaseConnection>) -> Self {
        Self {
            db: Some(db),
            tokens: RwLock::new(HashMap::new()),
            token_duration: Duration::from_secs(24 * 60 * 60),
            allow_anonymous_read: true,
        }
    }

    pub fn set_db(&mut self, db: Arc<DatabaseConnection>) {
        self.db = Some(db);
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        username: &str,
        password: &str,
        email: Option<&str>,
    ) -> Result<user::Model> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        // Check if username already exists
        let existing = user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        if existing.is_some() {
            return Err(ServerError::InvalidRequest(format!("Username '{}' already exists", username)));
        }

        // Create user
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let new_user = user::ActiveModel {
            username: Set(username.to_string()),
            password_hash: Set(hash_password(password)),
            display_name: Set(Some(username.to_string())),
            email: Set(email.map(|s| s.to_string())),
            is_org: Set(false),
            created_at: Set(now),
            ..Default::default()
        };

        let user = new_user
            .insert(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        tracing::info!("User '{}' registered", username);
        Ok(user)
    }

    /// Create a new organization
    pub async fn create_org(
        &self,
        org_name: &str,
        creator_id: i32,
    ) -> Result<user::Model> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        // Check if name already exists
        let existing = user::Entity::find()
            .filter(user::Column::Username.eq(org_name))
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        if existing.is_some() {
            return Err(ServerError::InvalidRequest(format!("Name '{}' already exists", org_name)));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Create org (an org is just a user with is_org=true and no password)
        let new_org = user::ActiveModel {
            username: Set(org_name.to_string()),
            password_hash: Set("".to_string()), // Orgs can't log in
            display_name: Set(Some(org_name.to_string())),
            email: Set(None),
            is_org: Set(true),
            created_at: Set(now),
            ..Default::default()
        };

        let org = new_org
            .insert(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        // Add creator as owner
        let membership = org_member::ActiveModel {
            org_id: Set(org.id),
            user_id: Set(creator_id),
            role: Set("owner".to_string()),
            created_at: Set(now),
            ..Default::default()
        };

        membership
            .insert(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        tracing::info!("Organization '{}' created by user {}", org_name, creator_id);
        Ok(org)
    }

    /// Add a user to an organization
    pub async fn add_org_member(
        &self,
        org_id: i32,
        user_id: i32,
        role: &str,
    ) -> Result<()> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let membership = org_member::ActiveModel {
            org_id: Set(org_id),
            user_id: Set(user_id),
            role: Set(role.to_string()),
            created_at: Set(now),
            ..Default::default()
        };

        membership
            .insert(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Remove a user from an organization
    pub async fn remove_org_member(&self, org_id: i32, user_id: i32) -> Result<()> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        org_member::Entity::delete_many()
            .filter(org_member::Column::OrgId.eq(org_id))
            .filter(org_member::Column::UserId.eq(user_id))
            .exec(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Get members of an organization
    pub async fn get_org_members(&self, org_id: i32) -> Result<Vec<(user::Model, String)>> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        let members = org_member::Entity::find()
            .filter(org_member::Column::OrgId.eq(org_id))
            .all(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        let mut result = Vec::new();
        for member in members {
            if let Some(user) = user::Entity::find_by_id(member.user_id)
                .one(db.as_ref())
                .await
                .map_err(|e| ServerError::Internal(e.to_string()))?
            {
                result.push((user, member.role));
            }
        }

        Ok(result)
    }

    /// Check if user is member of an organization
    pub async fn is_org_member(&self, org_id: i32, user_id: i32) -> Result<bool> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        let membership = org_member::Entity::find()
            .filter(org_member::Column::OrgId.eq(org_id))
            .filter(org_member::Column::UserId.eq(user_id))
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        Ok(membership.is_some())
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<user::Model>> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        let user = user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        Ok(user)
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, id: i32) -> Result<Option<user::Model>> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        let user = user::Entity::find_by_id(id)
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        Ok(user)
    }

    /// Authenticate with username/password, returns a token
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Token> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        let user = user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or(ServerError::AuthFailed)?;

        // Orgs can't log in
        if user.is_org {
            return Err(ServerError::AuthFailed);
        }

        if !verify_password(password, &user.password_hash) {
            return Err(ServerError::AuthFailed);
        }

        let token = Token::new(user.id, username.to_string(), false, self.token_duration);

        let mut tokens = self.tokens.write();
        tokens.insert(token.token.clone(), token.clone());

        Ok(token)
    }

    /// Validate a token and return the user info
    pub fn validate_token(&self, token_str: &str) -> Result<Token> {
        let tokens = self.tokens.read();
        let token = tokens
            .get(token_str)
            .ok_or(ServerError::AuthFailed)?;

        if token.is_expired() {
            return Err(ServerError::AuthFailed);
        }

        Ok(token.clone())
    }

    /// Get username for a valid token (for web session)
    pub async fn get_username_for_token(&self, token_str: &str) -> Option<String> {
        let tokens = self.tokens.read();
        let token = tokens.get(token_str)?;

        if token.is_expired() {
            return None;
        }

        Some(token.username.clone())
    }

    /// Parse Basic auth header and authenticate
    pub async fn authenticate_basic(&self, auth_header: &str) -> Result<Token> {
        if !auth_header.starts_with("Basic ") {
            return Err(ServerError::AuthFailed);
        }

        let encoded = &auth_header[6..];
        let decoded = BASE64
            .decode(encoded)
            .map_err(|_| ServerError::AuthFailed)?;
        let credentials =
            String::from_utf8(decoded).map_err(|_| ServerError::AuthFailed)?;

        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ServerError::AuthFailed);
        }

        self.authenticate(parts[0], parts[1]).await
    }

    /// Parse Bearer token header and validate
    ///
    /// Supports two formats:
    /// 1. Standard Bearer token (looked up in token store)
    /// 2. HuggingFace-style "username:password" format for direct auth
    pub async fn validate_bearer(&self, auth_header: &str) -> Result<Token> {
        if !auth_header.starts_with("Bearer ") {
            return Err(ServerError::AuthFailed);
        }

        let token_str = &auth_header[7..];

        // First, check if it's a "username:password" format (HuggingFace style)
        if let Some(colon_idx) = token_str.find(':') {
            let username = &token_str[..colon_idx];
            let password = &token_str[colon_idx + 1..];
            return self.authenticate(username, password).await;
        }

        // Otherwise, look up in token store
        self.validate_token(token_str)
    }

    /// Check if anonymous read is allowed
    pub fn anonymous_read_allowed(&self) -> bool {
        self.allow_anonymous_read
    }

    /// Check if user can write to a repo (owner or org member)
    /// repo_owner is the username of the repo owner (could be user or org)
    pub async fn can_write_to_repo(&self, token: Option<&Token>, repo_owner: &str) -> Result<bool> {
        let token = match token {
            Some(t) => t,
            None => return Ok(false),
        };

        // User owns the repo directly
        if token.username == repo_owner {
            return Ok(true);
        }

        // Check if repo_owner is an org and user is a member
        if let Some(owner) = self.get_user_by_username(repo_owner).await? {
            if owner.is_org {
                return self.is_org_member(owner.id, token.user_id).await;
            }
        }

        Ok(false)
    }

    /// Check permissions for a repo operation
    pub async fn check_permission(
        &self,
        token: Option<&Token>,
        repo: &str,
        needs_write: bool,
    ) -> Result<()> {
        if !needs_write {
            // Read is always allowed (public repos)
            return Ok(());
        }

        // For write, check ownership
        let parts: Vec<&str> = repo.split('/').collect();
        if parts.len() < 2 {
            return Err(ServerError::InvalidRequest("Invalid repo format".to_string()));
        }
        let repo_owner = parts[0];

        match token {
            Some(t) => {
                if self.can_write_to_repo(Some(t), repo_owner).await? {
                    Ok(())
                } else {
                    Err(ServerError::PermissionDenied)
                }
            }
            None => Err(ServerError::AuthRequired),
        }
    }

    /// Cleanup expired tokens
    pub fn cleanup_expired_tokens(&self) {
        let mut tokens = self.tokens.write();
        tokens.retain(|_, t| !t.is_expired());
    }

    /// Revoke a token
    pub fn revoke_token(&self, token_str: &str) {
        let mut tokens = self.tokens.write();
        tokens.remove(token_str);
    }

    /// Ensure default admin user exists (for bootstrapping)
    pub async fn ensure_admin_user(&self, username: &str, password: &str) -> Result<()> {
        if self.get_user_by_username(username).await?.is_none() {
            self.register_user(username, password, None).await?;
            tracing::info!("Created default admin user '{}'", username);
        }
        Ok(())
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash() {
        let hash1 = hash_password("test123");
        let hash2 = hash_password("test123");
        let hash3 = hash_password("different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert!(verify_password("test123", &hash1));
        assert!(!verify_password("wrong", &hash1));
    }
}
