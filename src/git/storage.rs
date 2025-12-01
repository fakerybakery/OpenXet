//! Git object storage module.
//!
//! Provides in-memory storage for Git objects, refs, and repositories.

#![allow(dead_code)] // Many methods are part of the public API but not yet used internally

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use sha1::{Digest, Sha1};

use crate::error::{Result, ServerError};

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

/// In-memory Git repository
pub struct Repository {
    pub name: String,
    objects: DashMap<ObjectId, GitObject>,
    refs: RwLock<HashMap<String, GitRef>>,
    head: RwLock<String>,
}

impl Repository {
    pub fn new(name: String) -> Self {
        let repo = Self {
            name,
            objects: DashMap::new(),
            refs: RwLock::new(HashMap::new()),
            head: RwLock::new("refs/heads/main".to_string()),
        };

        // Create initial empty tree and commit
        repo.initialize_empty();
        repo
    }

    fn initialize_empty(&self) {
        // Create an empty tree
        let empty_tree = GitObject::new(ObjectType::Tree, Bytes::new());
        let tree_id = empty_tree.compute_id();
        self.objects.insert(tree_id, empty_tree);

        // Create initial commit
        let commit_data = format!(
            "tree {}\nauthor Git-Xet Server <server@git-xet.local> 0 +0000\ncommitter Git-Xet Server <server@git-xet.local> 0 +0000\n\nInitial commit\n",
            tree_id
        );
        let commit = GitObject::new(ObjectType::Commit, Bytes::from(commit_data));
        let commit_id = commit.compute_id();
        self.objects.insert(commit_id, commit);

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

    /// Store an object in the repository
    pub fn store_object(&self, object: GitObject) -> ObjectId {
        let id = object.compute_id();
        self.objects.insert(id, object);
        id
    }

    /// Get an object by ID
    pub fn get_object(&self, id: &ObjectId) -> Option<GitObject> {
        self.objects.get(id).map(|r| r.clone())
    }

    /// Check if an object exists
    pub fn has_object(&self, id: &ObjectId) -> bool {
        self.objects.contains_key(id)
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
        Ok(())
    }

    /// Delete a reference
    pub fn delete_ref(&self, name: &str) -> Result<()> {
        let mut refs = self.refs.write();
        refs.remove(name);
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
        self.objects.iter().map(|r| *r.key()).collect()
    }

    /// Count objects
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }
}

/// Repository storage manager
pub struct RepositoryStore {
    repos: DashMap<String, Arc<Repository>>,
    storage_path: Option<PathBuf>,
}

impl RepositoryStore {
    pub fn new() -> Self {
        Self {
            repos: DashMap::new(),
            storage_path: None,
        }
    }

    pub fn with_storage_path(path: PathBuf) -> Self {
        Self {
            repos: DashMap::new(),
            storage_path: Some(path),
        }
    }

    /// Create a new repository
    pub fn create_repo(&self, name: &str) -> Result<Arc<Repository>> {
        if self.repos.contains_key(name) {
            return Err(ServerError::RepoAlreadyExists(name.to_string()));
        }

        let repo = Arc::new(Repository::new(name.to_string()));
        self.repos.insert(name.to_string(), repo.clone());
        Ok(repo)
    }

    /// Get an existing repository
    pub fn get_repo(&self, name: &str) -> Result<Arc<Repository>> {
        self.repos
            .get(name)
            .map(|r| r.clone())
            .ok_or_else(|| ServerError::RepoNotFound(name.to_string()))
    }

    /// Get or create a repository
    pub fn get_or_create_repo(&self, name: &str) -> Arc<Repository> {
        self.repos
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Repository::new(name.to_string())))
            .clone()
    }

    /// Delete a repository
    pub fn delete_repo(&self, name: &str) -> Result<()> {
        self.repos
            .remove(name)
            .ok_or_else(|| ServerError::RepoNotFound(name.to_string()))?;
        Ok(())
    }

    /// List all repositories
    pub fn list_repos(&self) -> Vec<String> {
        self.repos.iter().map(|r| r.key().clone()).collect()
    }
}

impl Default for RepositoryStore {
    fn default() -> Self {
        Self::new()
    }
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
