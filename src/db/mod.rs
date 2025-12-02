//! Database module for SQLite persistence using SeaORM

pub mod entities;

use sea_orm::{Database, DatabaseConnection, DbErr, ConnectionTrait, Statement};
use std::path::Path;

/// Initialize database connection and create tables
pub async fn init_database(db_path: &Path) -> Result<DatabaseConnection, DbErr> {
    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
    tracing::info!("Connecting to database: {}", db_url);

    let db = Database::connect(&db_url).await?;

    // Create tables
    create_tables(&db).await?;

    Ok(db)
}

/// Create all tables if they don't exist
async fn create_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    // Repositories table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS repositories (
            name TEXT PRIMARY KEY,
            head TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        "#.to_string(),
    )).await?;

    // Git refs table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS git_refs (
            id TEXT PRIMARY KEY,
            repo_name TEXT NOT NULL,
            ref_name TEXT NOT NULL,
            target_hash TEXT NOT NULL,
            is_symbolic INTEGER NOT NULL DEFAULT 0,
            symbolic_target TEXT,
            FOREIGN KEY (repo_name) REFERENCES repositories(name) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index on git_refs for repo lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_git_refs_repo ON git_refs(repo_name)"#.to_string(),
    )).await?;

    // Git objects table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS git_objects (
            id TEXT PRIMARY KEY,
            repo_name TEXT NOT NULL,
            object_hash TEXT NOT NULL,
            object_type INTEGER NOT NULL,
            FOREIGN KEY (repo_name) REFERENCES repositories(name) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index on git_objects for repo and hash lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_git_objects_repo ON git_objects(repo_name)"#.to_string(),
    )).await?;
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_git_objects_hash ON git_objects(object_hash)"#.to_string(),
    )).await?;

    // LFS objects table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS lfs_objects (
            oid TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            raw_path TEXT
        )
        "#.to_string(),
    )).await?;

    // LFS chunks table (ordered chunks for reconstruction)
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS lfs_chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lfs_oid TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            chunk_hash TEXT NOT NULL,
            FOREIGN KEY (lfs_oid) REFERENCES lfs_objects(oid) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index for LFS chunk lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_lfs_chunks_oid ON lfs_chunks(lfs_oid)"#.to_string(),
    )).await?;

    // CAS blocks table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS cas_blocks (
            hash TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            chunk_count INTEGER NOT NULL,
            storage_key TEXT NOT NULL
        )
        "#.to_string(),
    )).await?;

    // CAS chunks table (maps chunks to blocks)
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS cas_chunks (
            hash TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            offset_in_block INTEGER NOT NULL,
            FOREIGN KEY (block_hash) REFERENCES cas_blocks(hash) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index for chunk-to-block lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_cas_chunks_block ON cas_chunks(block_hash)"#.to_string(),
    )).await?;

    tracing::info!("Database tables initialized");
    Ok(())
}
