//! Repository entity

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "repositories")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub owner_id: i32,
    pub name: String,
    pub head: String,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::OwnerId",
        to = "super::user::Column::Id"
    )]
    Owner,
    #[sea_orm(has_many = "super::git_ref::Entity")]
    GitRefs,
    #[sea_orm(has_many = "super::git_object::Entity")]
    GitObjects,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Owner.def()
    }
}

impl Related<super::git_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::GitRefs.def()
    }
}

impl Related<super::git_object::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::GitObjects.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
