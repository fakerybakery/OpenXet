//! Discussion event entity for activity tracking

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "discussion_events")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub discussion_id: i32,
    pub actor_id: i32,
    pub event_type: String, // "closed", "reopened", "renamed", "locked", "unlocked"
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub created_at: i64,
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
        from = "Column::ActorId",
        to = "super::user::Column::Id"
    )]
    Actor,
}

impl Related<super::discussion::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Discussion.def()
    }
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Actor.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
