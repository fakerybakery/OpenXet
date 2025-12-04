//! Authentication and authorization module.
//!
//! Provides user management, permission checking, and token-based auth.

#![allow(dead_code)] // Many methods are part of the public API but not yet used internally

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};

use crate::error::{Result, ServerError};

/// User permissions
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub can_read: bool,
    pub can_write: bool,
    pub can_admin: bool,
}

impl Permissions {
    pub fn read_only() -> Self {
        Self {
            can_read: true,
            can_write: false,
            can_admin: false,
        }
    }

    pub fn read_write() -> Self {
        Self {
            can_read: true,
            can_write: true,
            can_admin: false,
        }
    }

    pub fn admin() -> Self {
        Self {
            can_read: true,
            can_write: true,
            can_admin: true,
        }
    }
}

/// A user account
#[derive(Clone, Debug)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub permissions: HashMap<String, Permissions>, // repo_name -> permissions
    pub global_permissions: Permissions,
}

impl User {
    pub fn new(username: String, password: &str) -> Self {
        Self {
            username,
            password_hash: hash_password(password),
            permissions: HashMap::new(),
            global_permissions: Permissions::read_only(),
        }
    }

    pub fn with_global_permissions(mut self, permissions: Permissions) -> Self {
        self.global_permissions = permissions;
        self
    }

    pub fn with_repo_permission(mut self, repo: &str, permissions: Permissions) -> Self {
        self.permissions.insert(repo.to_string(), permissions);
        self
    }

    pub fn verify_password(&self, password: &str) -> bool {
        hash_password(password) == self.password_hash
    }

    pub fn get_permissions(&self, repo: &str) -> &Permissions {
        self.permissions
            .get(repo)
            .unwrap_or(&self.global_permissions)
    }
}

/// Hash a password with salt
fn hash_password(password: &str) -> String {
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
    pub username: String,
    pub expires_at: SystemTime,
    pub permissions: Permissions,
}

impl Token {
    pub fn new(username: String, permissions: Permissions, duration: Duration) -> Self {
        let token = generate_token();
        let expires_at = SystemTime::now() + duration;

        Self {
            token,
            username,
            expires_at,
            permissions,
        }
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

/// Generate a secure random token
fn generate_token() -> String {
    use std::time::SystemTime;

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

/// Authentication manager
pub struct AuthManager {
    users: RwLock<HashMap<String, User>>,
    tokens: RwLock<HashMap<String, Token>>,
    token_duration: Duration,
    allow_anonymous_read: bool,
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            tokens: RwLock::new(HashMap::new()),
            token_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            allow_anonymous_read: false,
        }
    }

    pub fn with_anonymous_read(mut self, allow: bool) -> Self {
        self.allow_anonymous_read = allow;
        self
    }

    /// Add a user
    pub fn add_user(&self, user: User) {
        let mut users = self.users.write();
        users.insert(user.username.clone(), user);
    }

    /// Authenticate with username/password, returns a token
    pub fn authenticate(&self, username: &str, password: &str) -> Result<Token> {
        let users = self.users.read();
        let user = users
            .get(username)
            .ok_or(ServerError::AuthFailed)?;

        if !user.verify_password(password) {
            return Err(ServerError::AuthFailed);
        }

        let token = Token::new(
            username.to_string(),
            user.global_permissions.clone(),
            self.token_duration,
        );

        drop(users);

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

    /// Parse Basic auth header and authenticate
    pub fn authenticate_basic(&self, auth_header: &str) -> Result<Token> {
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

        self.authenticate(parts[0], parts[1])
    }

    /// Parse Bearer token header and validate
    ///
    /// Supports two formats:
    /// 1. Standard Bearer token (looked up in token store)
    /// 2. HuggingFace-style "username:password" format for direct auth
    pub fn validate_bearer(&self, auth_header: &str) -> Result<Token> {
        if !auth_header.starts_with("Bearer ") {
            return Err(ServerError::AuthFailed);
        }

        let token_str = &auth_header[7..];

        // First, check if it's a "username:password" format (HuggingFace style)
        if let Some(colon_idx) = token_str.find(':') {
            let username = &token_str[..colon_idx];
            let password = &token_str[colon_idx + 1..];
            return self.authenticate(username, password);
        }

        // Otherwise, look up in token store
        self.validate_token(token_str)
    }

    /// Check if anonymous read is allowed
    pub fn anonymous_read_allowed(&self) -> bool {
        self.allow_anonymous_read
    }

    /// Check permissions for a repo operation
    pub fn check_permission(
        &self,
        token: Option<&Token>,
        repo: &str,
        needs_write: bool,
    ) -> Result<()> {
        match token {
            Some(t) => {
                let users = self.users.read();
                if let Some(user) = users.get(&t.username) {
                    let perms = user.get_permissions(repo);
                    if needs_write && !perms.can_write {
                        return Err(ServerError::PermissionDenied);
                    }
                    if !perms.can_read {
                        return Err(ServerError::PermissionDenied);
                    }
                    Ok(())
                } else {
                    // Use token's permissions
                    if needs_write && !t.permissions.can_write {
                        return Err(ServerError::PermissionDenied);
                    }
                    Ok(())
                }
            }
            None => {
                if self.allow_anonymous_read && !needs_write {
                    Ok(())
                } else {
                    Err(ServerError::AuthRequired)
                }
            }
        }
    }

    /// Cleanup expired tokens
    pub fn cleanup_expired_tokens(&self) {
        let mut tokens = self.tokens.write();
        tokens.retain(|_, t| !t.is_expired());
    }

    /// Get user by username
    pub fn get_user(&self, username: &str) -> Option<User> {
        let users = self.users.read();
        users.get(username).cloned()
    }

    /// Revoke a token
    pub fn revoke_token(&self, token_str: &str) {
        let mut tokens = self.tokens.write();
        tokens.remove(token_str);
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
    }

    #[test]
    fn test_user_authentication() {
        let user = User::new("testuser".to_string(), "password123");
        assert!(user.verify_password("password123"));
        assert!(!user.verify_password("wrongpassword"));
    }

    #[test]
    fn test_auth_manager() {
        let auth = AuthManager::new();
        auth.add_user(
            User::new("admin".to_string(), "admin123")
                .with_global_permissions(Permissions::admin()),
        );

        // Successful auth
        let token = auth.authenticate("admin", "admin123").unwrap();
        assert!(!token.is_expired());
        assert!(token.permissions.can_admin);

        // Token validation
        let validated = auth.validate_token(&token.token).unwrap();
        assert_eq!(validated.username, "admin");

        // Failed auth
        assert!(auth.authenticate("admin", "wrong").is_err());
        assert!(auth.authenticate("nonexistent", "pass").is_err());
    }

    #[test]
    fn test_basic_auth() {
        let auth = AuthManager::new();
        auth.add_user(User::new("user".to_string(), "pass"));

        let header = format!("Basic {}", BASE64.encode(b"user:pass"));
        let token = auth.authenticate_basic(&header).unwrap();
        assert_eq!(token.username, "user");

        let bad_header = format!("Basic {}", BASE64.encode(b"user:wrong"));
        assert!(auth.authenticate_basic(&bad_header).is_err());
    }
}
