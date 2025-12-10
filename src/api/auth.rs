//! Authentication and authorization module.
//!
//! Provides user management, permission checking, and token-based auth.
//! Users and organizations are stored in the database.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::RwLock;
use rand::Rng;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
};
use subtle::ConstantTimeEq;

use crate::db::entities::{access_token, org_member, user};
use crate::error::{Result, ServerError};

/// Hash a password using Argon2id with random salt
/// Returns the PHC-format hash string (includes salt, params, and hash)
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

/// Verify a password against an Argon2 hash using constant-time comparison
/// Also supports legacy SHA-256 hashes for migration (64 hex chars)
pub fn verify_password(password: &str, hash: &str) -> bool {
    // Check if this is a legacy SHA-256 hash (64 hex chars, no $ prefix)
    if hash.len() == 64 && !hash.starts_with('$') && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        // Legacy format - verify with constant-time comparison
        let legacy_hash = hash_password_legacy(password);
        return legacy_hash.as_bytes().ct_eq(hash.as_bytes()).into();
    }

    // Argon2 PHC format hash
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Legacy SHA-256 password hashing (for migration only - do not use for new passwords)
fn hash_password_legacy(password: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"git-xet-server-salt:");
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
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

/// Generate a cryptographically secure random token
fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    let mut token_bytes = [0u8; 32]; // 256 bits of entropy
    rng.fill(&mut token_bytes);
    BASE64.encode(token_bytes)
}

/// Generate a secure random password for initial admin setup
pub fn generate_random_password() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generate a secure access token with ox_ prefix
/// Format: ox_[32 random bytes as hex] = 67 characters total
pub fn generate_access_token() -> String {
    let mut rng = rand::thread_rng();
    let mut token_bytes = [0u8; 32]; // 256 bits of entropy
    rng.fill(&mut token_bytes);
    let hex: String = token_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("ox_{}", hex)
}

/// Hash an access token for secure storage using SHA-256
/// We use SHA-256 instead of Argon2 because:
/// 1. Access tokens have high entropy (256 bits) so no need for expensive hashing
/// 2. We need fast lookups during API requests
/// 3. The token itself is the secret, not a user-chosen password
pub fn hash_access_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Information about a created access token (returned only once at creation)
#[derive(Clone, Debug)]
pub struct CreatedAccessToken {
    /// The raw token (only shown once!)
    pub token: String,
    /// Token ID in database
    pub id: i32,
    /// Token name
    pub name: String,
    /// Token prefix for identification (ox_XXXXXXXX)
    pub prefix: String,
    /// Creation timestamp
    pub created_at: i64,
}

/// Information about an access token (for listing - no raw token)
#[derive(Clone, Debug)]
pub struct AccessTokenInfo {
    /// Token ID in database
    pub id: i32,
    /// Token name
    pub name: String,
    /// Token prefix for identification (ox_XXXXXXXX)
    pub prefix: String,
    /// Description
    pub description: Option<String>,
    /// Scopes
    pub scopes: String,
    /// Last used timestamp
    pub last_used_at: i64,
    /// Creation timestamp
    pub created_at: i64,
    /// Expiration timestamp (0 = never)
    pub expires_at: i64,
    /// Whether token is active
    pub is_active: bool,
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
    /// Supports three formats:
    /// 1. Access tokens (ox_* format) - validated against database
    /// 2. HuggingFace-style "username:password" format for direct auth
    /// 3. Standard Bearer token (looked up in session token store)
    pub async fn validate_bearer(&self, auth_header: &str) -> Result<Token> {
        if !auth_header.starts_with("Bearer ") {
            return Err(ServerError::AuthFailed);
        }

        let token_str = &auth_header[7..];

        // First, check if it's an access token (ox_* format)
        if token_str.starts_with("ox_") {
            return self.validate_access_token(token_str).await;
        }

        // Second, check if it's a "username:password" format (HuggingFace style)
        if let Some(colon_idx) = token_str.find(':') {
            let username = &token_str[..colon_idx];
            let password = &token_str[colon_idx + 1..];
            return self.authenticate(username, password).await;
        }

        // Otherwise, look up in session token store
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

    /// Revoke a session token
    pub fn revoke_token(&self, token_str: &str) {
        let mut tokens = self.tokens.write();
        tokens.remove(token_str);
    }

    // =========================================================================
    // Access Token Management (ox_* tokens for API authentication)
    // =========================================================================

    /// Create a new access token for a user
    /// Returns the created token info INCLUDING the raw token (only time it's visible!)
    pub async fn create_access_token(
        &self,
        user_id: i32,
        name: &str,
        description: Option<&str>,
        scopes: Option<&str>,
        expires_in_days: Option<i64>,
    ) -> Result<CreatedAccessToken> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        // Generate the raw token
        let raw_token = generate_access_token();
        let token_hash = hash_access_token(&raw_token);
        let token_prefix = raw_token[..11].to_string(); // "ox_" + first 8 hex chars

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expires_at = expires_in_days
            .map(|days| now + (days * 24 * 60 * 60))
            .unwrap_or(0); // 0 = never expires

        let new_token = access_token::ActiveModel {
            user_id: Set(user_id),
            name: Set(name.to_string()),
            token_hash: Set(token_hash),
            token_prefix: Set(token_prefix.clone()),
            description: Set(description.map(|s| s.to_string())),
            scopes: Set(scopes.unwrap_or("*").to_string()),
            last_used_at: Set(0),
            created_at: Set(now),
            expires_at: Set(expires_at),
            is_active: Set(true),
            ..Default::default()
        };

        let token_model = new_token
            .insert(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        tracing::info!("Access token '{}' created for user {}", name, user_id);

        Ok(CreatedAccessToken {
            token: raw_token,
            id: token_model.id,
            name: token_model.name,
            prefix: token_prefix,
            created_at: now,
        })
    }

    /// Validate an access token (ox_* format) and return user info
    /// Updates last_used_at on successful validation
    pub async fn validate_access_token(&self, token_str: &str) -> Result<Token> {
        // Must start with ox_
        if !token_str.starts_with("ox_") {
            return Err(ServerError::AuthFailed);
        }

        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        let token_hash = hash_access_token(token_str);

        // Find token by hash
        let token_model = access_token::Entity::find()
            .filter(access_token::Column::TokenHash.eq(&token_hash))
            .filter(access_token::Column::IsActive.eq(true))
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or(ServerError::AuthFailed)?;

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if token_model.expires_at > 0 && now > token_model.expires_at {
            return Err(ServerError::AuthFailed);
        }

        // Update last_used_at
        let mut active_model: access_token::ActiveModel = token_model.clone().into();
        active_model.last_used_at = Set(now);
        active_model
            .update(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        // Get user info
        let user = user::Entity::find_by_id(token_model.user_id)
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or(ServerError::AuthFailed)?;

        // Return a Token struct for compatibility with existing auth flow
        Ok(Token {
            token: token_str.to_string(),
            user_id: user.id,
            username: user.username,
            is_org: user.is_org,
            expires_at: if token_model.expires_at > 0 {
                UNIX_EPOCH + Duration::from_secs(token_model.expires_at as u64)
            } else {
                SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60) // Far future
            },
        })
    }

    /// List all access tokens for a user (without the actual token values)
    pub async fn list_access_tokens(&self, user_id: i32) -> Result<Vec<AccessTokenInfo>> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        let tokens = access_token::Entity::find()
            .filter(access_token::Column::UserId.eq(user_id))
            .all(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        Ok(tokens
            .into_iter()
            .map(|t| AccessTokenInfo {
                id: t.id,
                name: t.name,
                prefix: t.token_prefix,
                description: t.description,
                scopes: t.scopes,
                last_used_at: t.last_used_at,
                created_at: t.created_at,
                expires_at: t.expires_at,
                is_active: t.is_active,
            })
            .collect())
    }

    /// Revoke an access token by ID (user must own the token)
    pub async fn revoke_access_token(&self, token_id: i32, user_id: i32) -> Result<()> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        // Find the token and verify ownership
        let token = access_token::Entity::find_by_id(token_id)
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or(ServerError::NotFound)?;

        if token.user_id != user_id {
            return Err(ServerError::PermissionDenied);
        }

        // Soft delete by setting is_active = false
        let mut active_model: access_token::ActiveModel = token.into();
        active_model.is_active = Set(false);
        active_model
            .update(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        tracing::info!("Access token {} revoked by user {}", token_id, user_id);
        Ok(())
    }

    /// Delete an access token permanently by ID (user must own the token)
    pub async fn delete_access_token(&self, token_id: i32, user_id: i32) -> Result<()> {
        let db = self.db.as_ref().ok_or(ServerError::Internal("No database connection".to_string()))?;

        // Find the token and verify ownership
        let token = access_token::Entity::find_by_id(token_id)
            .one(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or(ServerError::NotFound)?;

        if token.user_id != user_id {
            return Err(ServerError::PermissionDenied);
        }

        // Hard delete
        access_token::Entity::delete_by_id(token_id)
            .exec(db.as_ref())
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        tracing::info!("Access token {} deleted by user {}", token_id, user_id);
        Ok(())
    }

    /// Ensure admin user exists with secure password handling
    ///
    /// Password priority:
    /// 1. GIT_XET_ADMIN_PASSWORD environment variable
    /// 2. Generate random password (returned to caller for display)
    ///
    /// Returns Some(password) if a new admin was created, None if admin already exists
    pub async fn ensure_admin_user_secure(&self) -> Result<Option<String>> {
        const ADMIN_USERNAME: &str = "admin";

        // Check if admin already exists
        if self.get_user_by_username(ADMIN_USERNAME).await?.is_some() {
            return Ok(None);
        }

        // Get password from environment or generate random one
        let (password, is_generated) = match std::env::var("GIT_XET_ADMIN_PASSWORD") {
            Ok(pwd) if !pwd.is_empty() => {
                if pwd.len() < 12 {
                    return Err(ServerError::InvalidRequest(
                        "GIT_XET_ADMIN_PASSWORD must be at least 12 characters".to_string()
                    ));
                }
                (pwd, false)
            }
            _ => (generate_random_password(), true),
        };

        self.register_user(ADMIN_USERNAME, &password, None).await?;
        tracing::info!("Created admin user '{}'", ADMIN_USERNAME);

        // Only return password if it was generated (so it can be displayed)
        if is_generated {
            Ok(Some(password))
        } else {
            Ok(None)
        }
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
    fn test_password_hash_argon2() {
        let hash1 = hash_password("test123");
        let hash2 = hash_password("test123");
        let hash3 = hash_password("different");

        // Argon2 hashes should be different each time (unique salts)
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);

        // But verification should work
        assert!(verify_password("test123", &hash1));
        assert!(verify_password("test123", &hash2));
        assert!(!verify_password("wrong", &hash1));
        assert!(!verify_password("test123", &hash3));

        // Hash should be in PHC format (starts with $argon2)
        assert!(hash1.starts_with("$argon2"));
    }

    #[test]
    fn test_legacy_password_migration() {
        // Legacy SHA-256 hash for "test123"
        let legacy_hash = hash_password_legacy("test123");
        assert_eq!(legacy_hash.len(), 64);
        assert!(legacy_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Should still verify correctly
        assert!(verify_password("test123", &legacy_hash));
        assert!(!verify_password("wrong", &legacy_hash));
    }

    #[test]
    fn test_token_generation() {
        let token1 = generate_token();
        let token2 = generate_token();

        // Tokens should be unique
        assert_ne!(token1, token2);

        // Tokens should be base64 encoded (44 chars for 32 bytes)
        assert_eq!(token1.len(), 44);
    }

    #[test]
    fn test_random_password_generation() {
        let pwd1 = generate_random_password();
        let pwd2 = generate_random_password();

        // Passwords should be unique
        assert_ne!(pwd1, pwd2);

        // Should be 24 characters
        assert_eq!(pwd1.len(), 24);
    }
}
