//! Repository entity

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "repositories")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub head: String,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::git_ref::Entity")]
    GitRefs,
    #[sea_orm(has_many = "super::git_object::Entity")]
    GitObjects,
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
