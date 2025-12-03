//! File segment entity (for file reconstruction)

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "file_segments")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub file_hash: String,      // 64-char hex hash of the file (LFS OID)
    pub segment_index: i32,     // Order within the file
    pub block_hash: String,     // 64-char hex hash of the block
    pub byte_start: i64,        // Start offset in block
    pub byte_end: i64,          // End offset in block
    pub segment_size: i64,      // Size of this segment
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::cas_block::Entity",
        from = "Column::BlockHash",
        to = "super::cas_block::Column::Hash"
    )]
    Block,
}

impl Related<super::cas_block::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Block.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
