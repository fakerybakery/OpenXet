//! Pull request entity

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "pull_requests")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub repo_name: String,
    pub number: i32,
    pub author_id: i32,
    pub title: String,
    pub description: String,
    pub source_branch: String,
    pub target_branch: String,
    pub source_commit: Option<String>,
    pub target_commit: Option<String>,
    pub status: String, // "open", "closed", "merged"
    pub merged_by: Option<i32>,
    pub merged_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::AuthorId",
        to = "super::user::Column::Id"
    )]
    Author,
    #[sea_orm(has_many = "super::pr_comment::Entity")]
    Comments,
    #[sea_orm(has_many = "super::pr_event::Entity")]
    Events,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Author.def()
    }
}

impl Related<super::pr_comment::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Comments.def()
    }
}

impl Related<super::pr_event::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Events.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
