//! CAS block entity (bundled chunks stored on disk/S3)

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cas_blocks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub hash: String,         // 64-char hex BLAKE3
    pub size: i64,
    pub chunk_count: i32,
    pub storage_key: String,  // Path/key in storage backend
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::cas_chunk::Entity")]
    Chunks,
}

impl Related<super::cas_chunk::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Chunks.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
