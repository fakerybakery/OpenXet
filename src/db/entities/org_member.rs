//! Organization member entity - links users to organizations

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "org_members")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub org_id: i32,
    pub user_id: i32,
    pub role: String, // "owner", "admin", "member"
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::OrgId",
        to = "super::user::Column::Id"
    )]
    Organization,
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id"
    )]
    User,
}

impl ActiveModelBehavior for ActiveModel {}
