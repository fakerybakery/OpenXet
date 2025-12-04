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
    // Users table (also used for organizations with is_org=1)
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL DEFAULT '',
            display_name TEXT,
            email TEXT,
            is_org INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )
        "#.to_string(),
    )).await?;

    // Migration: Add password_hash column if it doesn't exist (for older DBs)
    let _ = db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''"#.to_string(),
    )).await;

    // Migration: Add is_org column if it doesn't exist (for older DBs)
    let _ = db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"ALTER TABLE users ADD COLUMN is_org INTEGER NOT NULL DEFAULT 0"#.to_string(),
    )).await;

    // Organization members table (links users to orgs)
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS org_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            created_at INTEGER NOT NULL,
            FOREIGN KEY (org_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(org_id, user_id)
        )
        "#.to_string(),
    )).await?;

    // Create indexes for org member lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id)"#.to_string(),
    )).await?;
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id)"#.to_string(),
    )).await?;

    // Repositories table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            head TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(owner_id, name)
        )
        "#.to_string(),
    )).await?;

    // Create index for owner lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_repos_owner ON repositories(owner_id)"#.to_string(),
    )).await?;

    // Git refs table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS git_refs (
            id TEXT PRIMARY KEY,
            repo_id INTEGER NOT NULL,
            ref_name TEXT NOT NULL,
            target_hash TEXT NOT NULL,
            is_symbolic INTEGER NOT NULL DEFAULT 0,
            symbolic_target TEXT,
            FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index on git_refs for repo lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_git_refs_repo ON git_refs(repo_id)"#.to_string(),
    )).await?;

    // Git objects table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS git_objects (
            id TEXT PRIMARY KEY,
            repo_id INTEGER NOT NULL,
            object_hash TEXT NOT NULL,
            object_type INTEGER NOT NULL,
            FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index on git_objects for repo and hash lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_git_objects_repo ON git_objects(repo_id)"#.to_string(),
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

    // File segments table (for file reconstruction - maps file hash to block ranges)
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS file_segments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash TEXT NOT NULL,
            segment_index INTEGER NOT NULL,
            block_hash TEXT NOT NULL,
            byte_start INTEGER NOT NULL,
            byte_end INTEGER NOT NULL,
            segment_size INTEGER NOT NULL,
            FOREIGN KEY (block_hash) REFERENCES cas_blocks(hash) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index for file segment lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_file_segments_file ON file_segments(file_hash)"#.to_string(),
    )).await?;

    // Discussions table (community threads)
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS discussions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create indexes for discussion lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_discussions_repo ON discussions(repo_name)"#.to_string(),
    )).await?;
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_discussions_author ON discussions(author_id)"#.to_string(),
    )).await?;

    // Discussion comments table
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS discussion_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discussion_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (discussion_id) REFERENCES discussions(id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index for comment lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_comments_discussion ON discussion_comments(discussion_id)"#.to_string(),
    )).await?;

    // Discussion events table (for tracking close/reopen/rename/lock activities)
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"
        CREATE TABLE IF NOT EXISTS discussion_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discussion_id INTEGER NOT NULL,
            actor_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (discussion_id) REFERENCES discussions(id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#.to_string(),
    )).await?;

    // Create index for event lookups
    db.execute(Statement::from_string(
        db.get_database_backend(),
        r#"CREATE INDEX IF NOT EXISTS idx_events_discussion ON discussion_events(discussion_id)"#.to_string(),
    )).await?;

    tracing::info!("Database tables initialized");
    Ok(())
}
