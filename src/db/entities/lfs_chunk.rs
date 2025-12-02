//! LFS chunk mapping entity (maps LFS object -> ordered chunks)

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "lfs_chunks")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub lfs_oid: String,      // FK to lfs_objects
    pub chunk_index: i32,     // Order in reconstruction
    pub chunk_hash: String,   // 64-char hex BLAKE3
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::lfs_object::Entity",
        from = "Column::LfsOid",
        to = "super::lfs_object::Column::Oid"
    )]
    LfsObject,
}

impl Related<super::lfs_object::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::LfsObject.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
