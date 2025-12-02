//! LFS object entity

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "lfs_objects")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub oid: String,          // 64-char hex SHA256
    pub size: i64,
    pub status: i32,          // 0=Raw, 1=Processing, 2=Chunked
    pub raw_path: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::lfs_chunk::Entity")]
    Chunks,
}

impl Related<super::lfs_chunk::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Chunks.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
