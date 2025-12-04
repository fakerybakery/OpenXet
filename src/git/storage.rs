//! Git object storage module.
//!
//! Provides disk-backed storage for Git objects, refs, and repositories.
//! Refs and repository metadata are persisted in SQLite.
//! Objects are stored on disk via storage backend.

#![allow(dead_code)] // Many methods are part of the public API but not yet used internally

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use sha1::{Digest, Sha1};

use crate::db::entities::{git_object, git_ref, repository, user};
use crate::error::{Result, ServerError};
use crate::storage::{namespaces, StorageBackend, StorageConfig};

/// A 20-byte object ID (SHA-1 hash) - Git standard format
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 20]);

impl ObjectId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha1::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        let mut id = [0u8; 20];
        id.copy_from_slice(&result);
        Self(id)
    }

    /// Create an ObjectId from raw 20 bytes (no hashing)
    pub fn from_raw(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 40 {
            return None;
        }
        let mut id = [0u8; 20];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).ok()?;
            id[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Self(id))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl std::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectId({})", &self.to_hex()[..8])
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Git object types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectType {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl ObjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Blob => "blob",
            ObjectType::Tree => "tree",
            ObjectType::Commit => "commit",
            ObjectType::Tag => "tag",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "blob" => Some(ObjectType::Blob),
            "tree" => Some(ObjectType::Tree),
            "commit" => Some(ObjectType::Commit),
            "tag" => Some(ObjectType::Tag),
            _ => None,
        }
    }
}

/// A Git object stored in memory
#[derive(Clone, Debug)]
pub struct GitObject {
    pub object_type: ObjectType,
    pub data: Bytes,
}

impl GitObject {
    pub fn new(object_type: ObjectType, data: Bytes) -> Self {
        Self { object_type, data }
    }

    /// Compute the object ID (Git uses SHA-1, but we use SHA-256 for security)
    pub fn compute_id(&self) -> ObjectId {
        // Git object format: "<type> <size>\0<content>"
        let header = format!("{} {}\0", self.object_type.as_str(), self.data.len());
        let mut full_data = header.into_bytes();
        full_data.extend_from_slice(&self.data);
        ObjectId::from_bytes(&full_data)
    }
}

/// A Git reference (branch, tag, etc.)
#[derive(Clone, Debug)]
pub struct GitRef {
    pub name: String,
    pub target: ObjectId,
    pub is_symbolic: bool,
    pub symbolic_target: Option<String>,
}

/// Disk-backed Git repository with SQLite persistence
/// Objects are stored on disk via storage backend.
/// Refs and object index are cached in memory and persisted to SQLite.
pub struct Repository {
    pub name: String,  // "owner/repo" format
    pub repo_id: Option<i32>,  // Database ID
    storage: Arc<dyn StorageBackend>,
    /// Index of known objects (id -> object type code, for quick lookups)
    object_index: DashMap<ObjectId, u8>, // 0=blob, 1=tree, 2=commit, 3=tag
    refs: RwLock<HashMap<String, GitRef>>,
    head: RwLock<String>,
    storage_path: PathBuf,
    /// Database connection for persistence
    db: Option<Arc<DatabaseConnection>>,
}

impl Repository {
    pub fn new(name: String) -> Self {
        Self::with_storage_config(name, None, StorageConfig::default(), None)
    }

    pub fn with_storage_path(name: String, storage_path: PathBuf) -> Self {
        Self::with_storage_config(name, None, StorageConfig::local(storage_path), None)
    }

    pub fn with_db(name: String, repo_id: Option<i32>, storage_path: PathBuf, db: Arc<DatabaseConnection>) -> Self {
        Self::with_storage_config(name, repo_id, StorageConfig::local(storage_path), Some(db))
    }

    pub fn with_storage_config(name: String, repo_id: Option<i32>, config: StorageConfig, db: Option<Arc<DatabaseConnection>>) -> Self {
        let storage_path = match &config.storage_type {
            crate::storage::StorageType::Local { path } => path.clone(),
            crate::storage::StorageType::S3(_) => std::env::temp_dir().join("git-xet-cache"),
        };

        // For sync context, only local storage is supported
        let storage = config.build_local().expect(
            "S3 storage requires async initialization"
        );

        let repo = Self {
            name,
            repo_id,
            storage,
            object_index: DashMap::new(),
            refs: RwLock::new(HashMap::new()),
            head: RwLock::new("refs/heads/main".to_string()),
            storage_path,
            db,
        };

        // Create initial empty tree and commit
        repo.initialize_empty();
        repo
    }

    /// Set database connection (used when loading from existing repo)
    pub fn set_db(&mut self, db: Arc<DatabaseConnection>) {
        self.db = Some(db);
    }

    /// Set repo_id (used when loading from existing repo)
    pub fn set_repo_id(&mut self, repo_id: i32) {
        self.repo_id = Some(repo_id);
    }

    fn initialize_empty(&self) {
        // Create an empty tree
        let empty_tree = GitObject::new(ObjectType::Tree, Bytes::new());
        let tree_id = empty_tree.compute_id();
        self.store_object_sync(tree_id, &empty_tree);

        // Create initial commit
        let commit_data = format!(
            "tree {}\nauthor Git-Xet Server <server@git-xet.local> 0 +0000\ncommitter Git-Xet Server <server@git-xet.local> 0 +0000\n\nInitial commit\n",
            tree_id
        );
        let commit = GitObject::new(ObjectType::Commit, Bytes::from(commit_data));
        let commit_id = commit.compute_id();
        self.store_object_sync(commit_id, &commit);

        // Set up refs
        let mut refs = self.refs.write();
        refs.insert(
            "refs/heads/main".to_string(),
            GitRef {
                name: "refs/heads/main".to_string(),
                target: commit_id,
                is_symbolic: false,
                symbolic_target: None,
            },
        );
        refs.insert(
            "HEAD".to_string(),
            GitRef {
                name: "HEAD".to_string(),
                target: commit_id,
                is_symbolic: true,
                symbolic_target: Some("refs/heads/main".to_string()),
            },
        );
    }

    /// Get the object storage key
    fn object_key(&self, id: &ObjectId) -> String {
        format!("{}/{}", self.name, id.to_hex())
    }

    /// Store object synchronously (for initialization and sync contexts)
    fn store_object_sync(&self, id: ObjectId, object: &GitObject) {
        let type_code = match object.object_type {
            ObjectType::Blob => 0,
            ObjectType::Tree => 1,
            ObjectType::Commit => 2,
            ObjectType::Tag => 3,
        };

        // Serialize: first byte is type, rest is data
        let mut serialized = vec![type_code];
        serialized.extend_from_slice(&object.data);

        // Write to disk
        let hex = id.to_hex();
        let path = self.storage_path
            .join(namespaces::GIT_OBJECTS)
            .join(&self.name)
            .join(&hex[..2])
            .join(&hex[2..]);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, &serialized).ok();

        // Add to index
        self.object_index.insert(id, type_code);

        // Persist to database (fire-and-forget in sync context)
        if let (Some(db), Some(repo_id)) = (&self.db, self.repo_id) {
            let db = db.clone();
            let obj_hash = id.to_hex();
            let obj_id = format!("{}/{}", repo_id, obj_hash);
            tokio::spawn(async move {
                let model = git_object::ActiveModel {
                    id: Set(obj_id),
                    repo_id: Set(repo_id),
                    object_hash: Set(obj_hash),
                    object_type: Set(type_code as i32),
                };
                let _ = git_object::Entity::insert(model)
                    .on_conflict(
                        sea_orm::sea_query::OnConflict::column(git_object::Column::Id)
                            .do_nothing()
                            .to_owned()
                    )
                    .exec(&*db)
                    .await;
            });
        }
    }

    /// Store an object in the repository
    pub fn store_object(&self, object: GitObject) -> ObjectId {
        let id = object.compute_id();
        self.store_object_sync(id, &object);
        id
    }

    /// Get an object by ID
    pub fn get_object(&self, id: &ObjectId) -> Option<GitObject> {
        // Read from disk
        let hex = id.to_hex();
        let path = self.storage_path
            .join(namespaces::GIT_OBJECTS)
            .join(&self.name)
            .join(&hex[..2])
            .join(&hex[2..]);

        let data = std::fs::read(&path).ok()?;
        if data.is_empty() {
            return None;
        }

        let type_code = data[0];
        let object_type = match type_code {
            0 => ObjectType::Blob,
            1 => ObjectType::Tree,
            2 => ObjectType::Commit,
            3 => ObjectType::Tag,
            _ => return None,
        };

        Some(GitObject {
            object_type,
            data: Bytes::from(data[1..].to_vec()),
        })
    }

    /// Check if an object exists
    pub fn has_object(&self, id: &ObjectId) -> bool {
        // Fast check using index first
        if self.object_index.contains_key(id) {
            return true;
        }

        // Fall back to disk check
        let hex = id.to_hex();
        let path = self.storage_path
            .join(namespaces::GIT_OBJECTS)
            .join(&self.name)
            .join(&hex[..2])
            .join(&hex[2..]);

        path.exists()
    }

    /// Get a reference by name
    pub fn get_ref(&self, name: &str) -> Option<GitRef> {
        let refs = self.refs.read();
        refs.get(name).cloned()
    }

    /// Update a reference
    pub fn update_ref(&self, name: &str, target: ObjectId) -> Result<()> {
        let mut refs = self.refs.write();
        refs.insert(
            name.to_string(),
            GitRef {
                name: name.to_string(),
                target,
                is_symbolic: false,
                symbolic_target: None,
            },
        );

        // Persist to database
        if let (Some(db), Some(repo_id)) = (&self.db, self.repo_id) {
            let db = db.clone();
            let ref_name = name.to_string();
            let ref_id = format!("{}/{}", repo_id, ref_name);
            let target_hash = target.to_hex();
            tokio::spawn(async move {
                let model = git_ref::ActiveModel {
                    id: Set(ref_id.clone()),
                    repo_id: Set(repo_id),
                    ref_name: Set(ref_name),
                    target_hash: Set(target_hash),
                    is_symbolic: Set(false),
                    symbolic_target: Set(None),
                };
                // Use insert or update
                let _ = git_ref::Entity::insert(model)
                    .on_conflict(
                        sea_orm::sea_query::OnConflict::column(git_ref::Column::Id)
                            .update_columns([git_ref::Column::TargetHash])
                            .to_owned()
                    )
                    .exec(&*db)
                    .await;
            });
        }
        Ok(())
    }

    /// Delete a reference
    pub fn delete_ref(&self, name: &str) -> Result<()> {
        let mut refs = self.refs.write();
        refs.remove(name);

        // Persist to database
        if let (Some(db), Some(repo_id)) = (&self.db, self.repo_id) {
            let db = db.clone();
            let ref_id = format!("{}/{}", repo_id, name);
            tokio::spawn(async move {
                let _ = git_ref::Entity::delete_by_id(ref_id).exec(&*db).await;
            });
        }
        Ok(())
    }

    /// List all references
    pub fn list_refs(&self) -> Vec<GitRef> {
        let refs = self.refs.read();
        refs.values().cloned().collect()
    }

    /// Get HEAD reference
    pub fn get_head(&self) -> String {
        self.head.read().clone()
    }

    /// Resolve a reference (follow symbolic refs)
    pub fn resolve_ref(&self, name: &str) -> Option<ObjectId> {
        let refs = self.refs.read();
        let git_ref = refs.get(name)?;

        if git_ref.is_symbolic {
            if let Some(target) = &git_ref.symbolic_target {
                return refs.get(target).map(|r| r.target);
            }
        }
        Some(git_ref.target)
    }

    /// Get all object IDs (for pack generation)
    pub fn all_object_ids(&self) -> Vec<ObjectId> {
        self.object_index.iter().map(|r| *r.key()).collect()
    }

    /// Count objects
    pub fn object_count(&self) -> usize {
        self.object_index.len()
    }

    /// Parse a commit object and extract the tree hash
    pub fn get_commit_tree(&self, commit_id: &ObjectId) -> Option<ObjectId> {
        let obj = self.get_object(commit_id)?;
        if obj.object_type != ObjectType::Commit {
            return None;
        }

        // Commit format: "tree <hex>\n..."
        let data = std::str::from_utf8(&obj.data).ok()?;
        let tree_line = data.lines().find(|l| l.starts_with("tree "))?;
        let tree_hex = tree_line.strip_prefix("tree ")?;
        ObjectId::from_hex(tree_hex)
    }

    /// Parse a tree object and return its entries
    pub fn parse_tree(&self, tree_id: &ObjectId) -> Option<Vec<TreeEntry>> {
        let obj = self.get_object(tree_id)?;
        if obj.object_type != ObjectType::Tree {
            return None;
        }

        let mut entries = Vec::new();
        let data = &obj.data;
        let mut pos = 0;

        while pos < data.len() {
            // Find space after mode
            let space_pos = data[pos..].iter().position(|&b| b == b' ')?;
            let mode_bytes = &data[pos..pos + space_pos];
            let mode = std::str::from_utf8(mode_bytes).ok()?;

            pos += space_pos + 1;

            // Find null after name
            let null_pos = data[pos..].iter().position(|&b| b == 0)?;
            let name_bytes = &data[pos..pos + null_pos];
            let name = std::str::from_utf8(name_bytes).ok()?.to_string();

            pos += null_pos + 1;

            // Next 20 bytes are the SHA-1 hash
            if pos + 20 > data.len() {
                break;
            }
            let mut hash_bytes = [0u8; 20];
            hash_bytes.copy_from_slice(&data[pos..pos + 20]);
            let oid = ObjectId::from_raw(hash_bytes);

            pos += 20;

            let is_dir = mode == "40000" || mode == "040000";
            let is_executable = mode == "100755";
            let is_symlink = mode == "120000";

            entries.push(TreeEntry {
                name,
                oid,
                mode: mode.to_string(),
                is_dir,
                is_executable,
                is_symlink,
            });
        }

        // Sort: directories first, then alphabetically
        entries.sort_by(|a, b| {
            match (a.is_dir, b.is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.cmp(&b.name),
            }
        });

        Some(entries)
    }

    /// Get blob content as string (for text files)
    pub fn get_blob_content(&self, blob_id: &ObjectId) -> Option<Vec<u8>> {
        let obj = self.get_object(blob_id)?;
        if obj.object_type != ObjectType::Blob {
            return None;
        }
        Some(obj.data.to_vec())
    }

    /// Navigate to a path within a tree and return the object ID
    pub fn resolve_path(&self, tree_id: &ObjectId, path: &str) -> Option<(ObjectId, bool)> {
        if path.is_empty() || path == "/" {
            return Some((*tree_id, true)); // Root is always a directory
        }

        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let mut current_tree = *tree_id;

        for (i, part) in parts.iter().enumerate() {
            let entries = self.parse_tree(&current_tree)?;
            let entry = entries.iter().find(|e| e.name == *part)?;

            if i == parts.len() - 1 {
                // Last component - return it
                return Some((entry.oid, entry.is_dir));
            } else {
                // Not the last - must be a directory
                if !entry.is_dir {
                    return None;
                }
                current_tree = entry.oid;
            }
        }

        None
    }

    /// Store an object by type and raw data (public API for web editing)
    pub fn create_object(&self, object_type: ObjectType, data: &[u8]) -> ObjectId {
        let object = GitObject::new(object_type, Bytes::copy_from_slice(data));
        self.store_object(object)
    }

    /// Parse a commit object and return detailed info
    pub fn get_commit_info(&self, commit_id: &ObjectId) -> Option<CommitInfo> {
        let obj = self.get_object(commit_id)?;
        if obj.object_type != ObjectType::Commit {
            return None;
        }

        let data = std::str::from_utf8(&obj.data).ok()?;
        let mut tree_id = None;
        let mut parent_ids = Vec::new();
        let mut author_name = String::new();
        let mut author_email = String::new();
        let mut author_time: i64 = 0;
        let mut committer_name = String::new();
        let mut committer_email = String::new();
        let mut committer_time: i64 = 0;
        let mut in_message = false;
        let mut message_lines = Vec::new();

        for line in data.lines() {
            if in_message {
                message_lines.push(line);
            } else if line.is_empty() {
                in_message = true;
            } else if let Some(hash) = line.strip_prefix("tree ") {
                tree_id = ObjectId::from_hex(hash.trim());
            } else if let Some(hash) = line.strip_prefix("parent ") {
                if let Some(pid) = ObjectId::from_hex(hash.trim()) {
                    parent_ids.push(pid);
                }
            } else if let Some(rest) = line.strip_prefix("author ") {
                if let Some((name, email, time)) = parse_signature(rest) {
                    author_name = name;
                    author_email = email;
                    author_time = time;
                }
            } else if let Some(rest) = line.strip_prefix("committer ") {
                if let Some((name, email, time)) = parse_signature(rest) {
                    committer_name = name;
                    committer_email = email;
                    committer_time = time;
                }
            }
        }

        let message = message_lines.join("\n").trim().to_string();
        let short_message = message.lines().next().unwrap_or("").to_string();

        Some(CommitInfo {
            id: *commit_id,
            tree_id: tree_id?,
            parent_ids,
            author_name,
            author_email,
            author_time,
            committer_name,
            committer_email,
            committer_time,
            message,
            short_message,
        })
    }

    /// Walk commit history from a starting commit
    /// Returns commits in reverse chronological order, up to `limit` commits
    pub fn walk_commits(&self, start_id: &ObjectId, limit: usize, skip: usize) -> Vec<CommitInfo> {
        let mut commits = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(*start_id);
        let mut skipped = 0;

        while let Some(commit_id) = queue.pop_front() {
            if visited.contains(&commit_id) {
                continue;
            }
            visited.insert(commit_id);

            if let Some(info) = self.get_commit_info(&commit_id) {
                // Add parents to queue (for BFS traversal)
                for parent_id in &info.parent_ids {
                    if !visited.contains(parent_id) {
                        queue.push_back(*parent_id);
                    }
                }

                // Handle skip/limit
                if skipped < skip {
                    skipped += 1;
                    continue;
                }

                commits.push(info);
                if commits.len() >= limit {
                    break;
                }
            }
        }

        // Sort by commit time (most recent first)
        commits.sort_by(|a, b| b.committer_time.cmp(&a.committer_time));

        commits
    }

    /// Create a new commit
    pub fn create_commit(
        &self,
        tree_id: &ObjectId,
        parent_ids: &[ObjectId],
        message: &str,
        author_name: &str,
        author_email: &str,
    ) -> ObjectId {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut commit_data = String::new();
        commit_data.push_str(&format!("tree {}\n", tree_id.to_hex()));
        for parent in parent_ids {
            commit_data.push_str(&format!("parent {}\n", parent.to_hex()));
        }
        commit_data.push_str(&format!(
            "author {} <{}> {} +0000\n",
            author_name, author_email, timestamp
        ));
        commit_data.push_str(&format!(
            "committer {} <{}> {} +0000\n",
            author_name, author_email, timestamp
        ));
        commit_data.push_str(&format!("\n{}\n", message));

        let object = GitObject::new(ObjectType::Commit, Bytes::from(commit_data));
        self.store_object(object)
    }
}

/// A tree entry (file or subdirectory)
#[derive(Clone, Debug)]
pub struct TreeEntry {
    pub name: String,
    pub oid: ObjectId,
    pub mode: String,
    pub is_dir: bool,
    pub is_executable: bool,
    pub is_symlink: bool,
}

/// Parsed commit information
#[derive(Clone, Debug)]
pub struct CommitInfo {
    pub id: ObjectId,
    pub tree_id: ObjectId,
    pub parent_ids: Vec<ObjectId>,
    pub author_name: String,
    pub author_email: String,
    pub author_time: i64,
    pub committer_name: String,
    pub committer_email: String,
    pub committer_time: i64,
    pub message: String,
    pub short_message: String,
}

/// Repository storage manager with SQLite persistence
/// Repos are stored as "owner/repo" format (e.g., "alice/myproject")
pub struct RepositoryStore {
    repos: DashMap<String, Arc<Repository>>,  // key: "owner/repo"
    storage_path: PathBuf,
    db: Option<Arc<DatabaseConnection>>,
}

impl RepositoryStore {
    pub fn new() -> Self {
        Self {
            repos: DashMap::new(),
            storage_path: std::env::temp_dir().join("git-xet-storage"),
            db: None,
        }
    }

    pub fn with_storage_path(path: PathBuf) -> Self {
        Self {
            repos: DashMap::new(),
            storage_path: path,
            db: None,
        }
    }

    pub fn with_db(storage_path: PathBuf, db: Arc<DatabaseConnection>) -> Self {
        Self {
            repos: DashMap::new(),
            storage_path,
            db: Some(db),
        }
    }

    /// Load all repositories from database (call at startup)
    pub async fn load_from_db(&self) -> Result<()> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()), // No database configured
        };

        // Load all users first (for mapping owner_id -> username)
        let users: HashMap<i32, String> = user::Entity::find()
            .all(&**db)
            .await
            .map_err(|e| ServerError::Internal(format!("Failed to load users: {}", e)))?
            .into_iter()
            .map(|u| (u.id, u.username))
            .collect();

        // Load all repositories
        let repos = repository::Entity::find().all(&**db).await
            .map_err(|e| ServerError::Internal(format!("Failed to load repos: {}", e)))?;

        for repo_model in repos {
            let owner_name = match users.get(&repo_model.owner_id) {
                Some(name) => name.clone(),
                None => continue, // Skip repos with missing owners
            };
            let full_name = format!("{}/{}", owner_name, repo_model.name);
            let repo_id = repo_model.id;

            // Create repository with database connection
            let mut repo = Repository::with_storage_path(
                full_name.clone(),
                self.storage_path.clone(),
            );
            repo.set_db(db.clone());
            repo.set_repo_id(repo_id);

            // Load refs for this repository
            let refs = git_ref::Entity::find()
                .filter(git_ref::Column::RepoId.eq(repo_id))
                .all(&**db)
                .await
                .map_err(|e| ServerError::Internal(format!("Failed to load refs: {}", e)))?;

            // Populate refs
            {
                let mut refs_map = repo.refs.write();
                for ref_model in refs {
                    if let Some(target) = ObjectId::from_hex(&ref_model.target_hash) {
                        refs_map.insert(
                            ref_model.ref_name.clone(),
                            GitRef {
                                name: ref_model.ref_name,
                                target,
                                is_symbolic: ref_model.is_symbolic,
                                symbolic_target: ref_model.symbolic_target,
                            },
                        );
                    }
                }
            }

            // Set HEAD
            *repo.head.write() = repo_model.head;

            // Load object index for this repository
            let objects = git_object::Entity::find()
                .filter(git_object::Column::RepoId.eq(repo_id))
                .all(&**db)
                .await
                .map_err(|e| ServerError::Internal(format!("Failed to load objects: {}", e)))?;

            for obj in objects {
                if let Some(id) = ObjectId::from_hex(&obj.object_hash) {
                    repo.object_index.insert(id, obj.object_type as u8);
                }
            }

            self.repos.insert(full_name, Arc::new(repo));
        }

        tracing::info!("Loaded {} repositories from database", self.repos.len());
        Ok(())
    }

    /// Get or create a user by username
    pub async fn get_or_create_user(&self, username: &str) -> Result<i32> {
        let db = self.db.as_ref()
            .ok_or_else(|| ServerError::Internal("No database configured".to_string()))?;

        // Try to find existing user
        if let Some(existing) = user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .one(&**db)
            .await
            .map_err(|e| ServerError::Internal(format!("Failed to query user: {}", e)))?
        {
            return Ok(existing.id);
        }

        // Create new user
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = user::Entity::insert(user::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            username: Set(username.to_string()),
            password_hash: Set("".to_string()), // No password - created implicitly
            display_name: Set(None),
            email: Set(None),
            is_org: Set(false),
            created_at: Set(now),
        })
        .exec(&**db)
        .await
        .map_err(|e| ServerError::Internal(format!("Failed to create user: {}", e)))?;

        Ok(result.last_insert_id)
    }

    /// Create a new repository with owner
    pub async fn create_repo_async(&self, owner: &str, repo_name: &str) -> Result<Arc<Repository>> {
        let full_name = format!("{}/{}", owner, repo_name);

        if self.repos.contains_key(&full_name) {
            return Err(ServerError::RepoAlreadyExists(full_name));
        }

        let db = self.db.as_ref()
            .ok_or_else(|| ServerError::Internal("No database configured".to_string()))?;

        // Get or create the user
        let owner_id = self.get_or_create_user(owner).await?;

        // Create the repository in database
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = repository::Entity::insert(repository::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            owner_id: Set(owner_id),
            name: Set(repo_name.to_string()),
            head: Set("refs/heads/main".to_string()),
            created_at: Set(now),
        })
        .exec(&**db)
        .await
        .map_err(|e| ServerError::Internal(format!("Failed to create repo: {}", e)))?;

        let repo_id = result.last_insert_id;

        // Create in-memory repository
        let repo = Arc::new(Repository::with_db(
            full_name.clone(),
            Some(repo_id),
            self.storage_path.clone(),
            db.clone(),
        ));

        self.repos.insert(full_name, repo.clone());
        Ok(repo)
    }

    /// Create a new repository (sync version - spawns async task for DB)
    pub fn create_repo(&self, name: &str) -> Result<Arc<Repository>> {
        // Parse owner/repo format
        let (owner, repo_name) = parse_repo_path(name)?;

        if self.repos.contains_key(name) {
            return Err(ServerError::RepoAlreadyExists(name.to_string()));
        }

        // For sync context, create without repo_id initially
        // The async task will update it
        let repo = if let Some(db) = &self.db {
            Arc::new(Repository::with_db(
                name.to_string(),
                None,  // repo_id will be set by async task
                self.storage_path.clone(),
                db.clone(),
            ))
        } else {
            Arc::new(Repository::with_storage_path(
                name.to_string(),
                self.storage_path.clone(),
            ))
        };

        self.repos.insert(name.to_string(), repo.clone());

        // Persist to database asynchronously
        if let Some(db) = &self.db {
            let db = db.clone();
            let owner = owner.to_string();
            let repo_name = repo_name.to_string();
            tokio::spawn(async move {
                // Get or create user
                let owner_id = match user::Entity::find()
                    .filter(user::Column::Username.eq(&owner))
                    .one(&*db)
                    .await
                {
                    Ok(Some(u)) => u.id,
                    Ok(None) => {
                        // Create user
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64;
                        match user::Entity::insert(user::ActiveModel {
                            id: sea_orm::ActiveValue::NotSet,
                            username: Set(owner.clone()),
                            password_hash: Set("".to_string()), // No password
                            display_name: Set(None),
                            email: Set(None),
                            is_org: Set(false),
                            created_at: Set(now),
                        })
                        .exec(&*db)
                        .await
                        {
                            Ok(r) => r.last_insert_id,
                            Err(_) => return,
                        }
                    }
                    Err(_) => return,
                };

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                let _ = repository::Entity::insert(repository::ActiveModel {
                    id: sea_orm::ActiveValue::NotSet,
                    owner_id: Set(owner_id),
                    name: Set(repo_name),
                    head: Set("refs/heads/main".to_string()),
                    created_at: Set(now),
                })
                .exec(&*db)
                .await;
            });
        }

        Ok(repo)
    }

    /// Get an existing repository by "owner/repo" path
    pub fn get_repo(&self, name: &str) -> Result<Arc<Repository>> {
        self.repos
            .get(name)
            .map(|r| r.clone())
            .ok_or_else(|| ServerError::RepoNotFound(name.to_string()))
    }

    /// Get or create a repository
    pub fn get_or_create_repo(&self, name: &str) -> Arc<Repository> {
        if let Some(repo) = self.repos.get(name) {
            return repo.clone();
        }

        // Create new repo
        match self.create_repo(name) {
            Ok(repo) => repo,
            Err(_) => {
                // Race condition - another thread created it, get it
                self.repos.get(name).map(|r| r.clone()).unwrap_or_else(|| {
                    // Fallback: create without persistence
                    let repo = Arc::new(Repository::with_storage_path(
                        name.to_string(),
                        self.storage_path.clone(),
                    ));
                    self.repos.insert(name.to_string(), repo.clone());
                    repo
                })
            }
        }
    }

    /// Delete a repository
    pub fn delete_repo(&self, name: &str) -> Result<()> {
        let removed = self.repos
            .remove(name)
            .ok_or_else(|| ServerError::RepoNotFound(name.to_string()))?;

        // Delete from database
        if let (Some(db), Some(repo_id)) = (&self.db, removed.1.repo_id) {
            let db = db.clone();
            tokio::spawn(async move {
                let _ = repository::Entity::delete_by_id(repo_id).exec(&*db).await;
            });
        }

        Ok(())
    }

    /// List all repositories (returns "owner/repo" format)
    pub fn list_repos(&self) -> Vec<String> {
        self.repos.iter().map(|r| r.key().clone()).collect()
    }

    /// List repositories for a specific user
    pub fn list_user_repos(&self, owner: &str) -> Vec<String> {
        let prefix = format!("{}/", owner);
        self.repos
            .iter()
            .filter(|r| r.key().starts_with(&prefix))
            .map(|r| r.key().clone())
            .collect()
    }
}

/// Parse "owner/repo" format, returns (owner, repo_name)
pub fn parse_repo_path(path: &str) -> Result<(&str, &str)> {
    let path = path.trim_end_matches(".git");
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(ServerError::InvalidPath(format!(
            "Invalid repository path: {}. Expected format: owner/repo",
            path
        )));
    }
    Ok((parts[0], parts[1]))
}

impl Default for RepositoryStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a git signature line like "Name <email> timestamp timezone"
fn parse_signature(s: &str) -> Option<(String, String, i64)> {
    // Format: "Name <email> timestamp timezone"
    let email_start = s.find('<')?;
    let email_end = s.find('>')?;

    let name = s[..email_start].trim().to_string();
    let email = s[email_start + 1..email_end].to_string();

    // Parse timestamp after email
    let rest = s[email_end + 1..].trim();
    let timestamp: i64 = rest.split_whitespace().next()?.parse().ok()?;

    Some((name, email, timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_id() {
        let data = b"hello world";
        let id = ObjectId::from_bytes(data);
        let hex = id.to_hex();
        // Git uses SHA-1 which is 20 bytes = 40 hex chars
        assert_eq!(hex.len(), 40);

        let parsed = ObjectId::from_hex(&hex).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_repository() {
        let repo = Repository::new("test".to_string());

        // Should have initial commit
        assert!(repo.object_count() >= 2);

        // Should have HEAD and main refs
        assert!(repo.get_ref("HEAD").is_some());
        assert!(repo.get_ref("refs/heads/main").is_some());
    }

    #[test]
    fn test_store_object() {
        let repo = Repository::new("test".to_string());

        let blob = GitObject::new(ObjectType::Blob, Bytes::from("test content"));
        let id = repo.store_object(blob.clone());

        let retrieved = repo.get_object(&id).unwrap();
        assert_eq!(retrieved.data, blob.data);
    }
}
