//! Database entities

pub mod user;
pub mod repository;
pub mod git_ref;
pub mod git_object;
pub mod lfs_object;
pub mod lfs_chunk;
pub mod cas_chunk;
pub mod cas_block;
pub mod file_segment;

// Re-export entities for convenient access (may not all be used yet)
#[allow(unused_imports)]
pub use user::Entity as User;
#[allow(unused_imports)]
pub use repository::Entity as Repository;
#[allow(unused_imports)]
pub use git_ref::Entity as GitRef;
#[allow(unused_imports)]
pub use git_object::Entity as GitObject;
#[allow(unused_imports)]
pub use lfs_object::Entity as LfsObject;
#[allow(unused_imports)]
pub use lfs_chunk::Entity as LfsChunk;
#[allow(unused_imports)]
pub use cas_chunk::Entity as CasChunk;
#[allow(unused_imports)]
pub use cas_block::Entity as CasBlock;
#[allow(unused_imports)]
pub use file_segment::Entity as FileSegment;
