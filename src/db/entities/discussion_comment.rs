//! Discussion comment entity

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "discussion_comments")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub discussion_id: i32,
    pub author_id: i32,
    pub content: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::discussion::Entity",
        from = "Column::DiscussionId",
        to = "super::discussion::Column::Id"
    )]
    Discussion,
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::AuthorId",
        to = "super::user::Column::Id"
    )]
    Author,
}

impl Related<super::discussion::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Discussion.def()
    }
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Author.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
