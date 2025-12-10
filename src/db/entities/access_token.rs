//! Access token entity for API authentication
//!
//! Tokens are stored with their SHA-256 hash (not the raw token).
//! The raw token is only shown once at creation time.
//! Format: ox_[32 random bytes as hex] = ox_ + 64 hex chars = 67 chars total

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "access_tokens")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// User ID who owns this token
    pub user_id: i32,
    /// User-provided name for this token (e.g., "CI/CD", "Local dev")
    pub name: String,
    /// SHA-256 hash of the token (we never store the raw token)
    pub token_hash: String,
    /// First 8 characters of token for identification (ox_XXXX...)
    pub token_prefix: String,
    /// Optional description
    pub description: Option<String>,
    /// Scopes/permissions (comma-separated, e.g., "read,write" or "*" for all)
    pub scopes: String,
    /// Last used timestamp (0 if never used)
    pub last_used_at: i64,
    /// Creation timestamp
    pub created_at: i64,
    /// Expiration timestamp (0 for never expires)
    pub expires_at: i64,
    /// Whether token is active (can be revoked)
    pub is_active: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id"
    )]
    User,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
