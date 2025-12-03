//! Git object entity (tracks which objects belong to which repo)

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "git_objects")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String, // repo_id + "/" + object_hash
    pub repo_id: i32,
    pub object_hash: String,   // 40-char hex SHA1
    pub object_type: i32,      // 0=blob, 1=tree, 2=commit, 3=tag
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::repository::Entity",
        from = "Column::RepoId",
        to = "super::repository::Column::Id"
    )]
    Repository,
}

impl Related<super::repository::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Repository.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
