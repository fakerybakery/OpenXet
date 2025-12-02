//! CAS chunk entity (content-addressable chunks)

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cas_chunks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub hash: String,         // 64-char hex BLAKE3
    pub size: i64,
    pub block_hash: String,   // Which block contains this chunk
    pub offset_in_block: i64, // Byte offset within block
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
