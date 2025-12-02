//! Git reference entity (branches, tags, HEAD)

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "git_refs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String, // repo_name + "/" + ref_name
    pub repo_name: String,
    pub ref_name: String,
    pub target_hash: String, // 40-char hex SHA1
    pub is_symbolic: bool,
    pub symbolic_target: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::repository::Entity",
        from = "Column::RepoName",
        to = "super::repository::Column::Name"
    )]
    Repository,
}

impl Related<super::repository::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Repository.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
