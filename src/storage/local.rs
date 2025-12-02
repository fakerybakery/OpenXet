//! Local filesystem storage backend.

use async_trait::async_trait;
use bytes::Bytes;
use std::ops::Range;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::backend::{StorageBackend, StorageError, StorageResult};

/// Local filesystem storage backend.
///
/// Stores objects in a directory structure:
/// ```text
/// {base_path}/
///   {namespace}/
///     {key[0..2]}/     # First 2 chars of key for sharding
///       {key[2..]}     # Rest of key as filename
/// ```
pub struct LocalStorage {
    base_path: PathBuf,
}

impl LocalStorage {
    /// Create a new local storage backend
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Get the full path for a key
    fn key_path(&self, namespace: &str, key: &str) -> PathBuf {
        if key.len() >= 2 {
            // Shard by first 2 characters for better filesystem performance
            self.base_path
                .join(namespace)
                .join(&key[..2])
                .join(&key[2..])
        } else {
            self.base_path.join(namespace).join(key)
        }
    }

    /// Ensure parent directory exists
    async fn ensure_parent(&self, path: &Path) -> StorageResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for LocalStorage {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Bytes> {
        let path = self.key_path(namespace, key);
        let data = fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(format!("{}/{}", namespace, key))
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(Bytes::from(data))
    }

    async fn get_range(&self, namespace: &str, key: &str, range: Range<u64>) -> StorageResult<Bytes> {
        let path = self.key_path(namespace, key);
        let mut file = fs::File::open(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(format!("{}/{}", namespace, key))
            } else {
                StorageError::Io(e)
            }
        })?;

        // Validate range
        let file_size = file.metadata().await?.len();
        if range.start >= file_size || range.end > file_size || range.start >= range.end {
            return Err(StorageError::InvalidRange(format!(
                "Invalid range {}..{} for file of size {}",
                range.start, range.end, file_size
            )));
        }

        // Seek to start position
        file.seek(std::io::SeekFrom::Start(range.start)).await?;

        // Read exactly the requested range
        let len = (range.end - range.start) as usize;
        let mut buffer = vec![0u8; len];
        file.read_exact(&mut buffer).await?;

        Ok(Bytes::from(buffer))
    }

    async fn put(&self, namespace: &str, key: &str, data: Bytes) -> StorageResult<()> {
        let path = self.key_path(namespace, key);
        self.ensure_parent(&path).await?;
        fs::write(&path, &data).await?;
        Ok(())
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<()> {
        let path = self.key_path(namespace, key);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // Already deleted
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        let path = self.key_path(namespace, key);
        Ok(path.exists())
    }

    async fn list(&self, namespace: &str, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let ns_path = self.base_path.join(namespace);
        if !ns_path.exists() {
            return Ok(Vec::new());
        }

        let mut keys = Vec::new();

        // Walk the sharded directory structure
        let mut shard_dirs = fs::read_dir(&ns_path).await?;
        while let Some(shard_entry) = shard_dirs.next_entry().await? {
            let shard_path = shard_entry.path();
            if !shard_path.is_dir() {
                continue;
            }

            let shard_name = shard_entry.file_name();
            let shard_str = shard_name.to_string_lossy();

            let mut files = fs::read_dir(&shard_path).await?;
            while let Some(file_entry) = files.next_entry().await? {
                let file_name = file_entry.file_name();
                let file_str = file_name.to_string_lossy();

                // Reconstruct full key
                let key = format!("{}{}", shard_str, file_str);

                // Apply prefix filter if specified
                if let Some(p) = prefix {
                    if !key.starts_with(p) {
                        continue;
                    }
                }

                keys.push(key);
            }
        }

        Ok(keys)
    }

    async fn size(&self, namespace: &str, key: &str) -> StorageResult<u64> {
        let path = self.key_path(namespace, key);
        let metadata = fs::metadata(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(format!("{}/{}", namespace, key))
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(metadata.len())
    }

    async fn get_to_file(&self, namespace: &str, key: &str, local_path: &Path) -> StorageResult<()> {
        let src_path = self.key_path(namespace, key);

        // For local storage, we can just copy
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::copy(&src_path, local_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(format!("{}/{}", namespace, key))
            } else {
                StorageError::Io(e)
            }
        })?;

        Ok(())
    }

    async fn put_from_file(&self, namespace: &str, key: &str, local_path: &Path) -> StorageResult<()> {
        let dest_path = self.key_path(namespace, key);
        self.ensure_parent(&dest_path).await?;

        // For local storage, we can just copy
        fs::copy(local_path, &dest_path).await?;

        Ok(())
    }

    async fn get_stream(
        &self,
        namespace: &str,
        key: &str,
    ) -> StorageResult<Box<dyn tokio::io::AsyncRead + Unpin + Send>> {
        let path = self.key_path(namespace, key);
        let file = fs::File::open(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(format!("{}/{}", namespace, key))
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(Box::new(file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_local_storage_basic() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        // Put and get
        let data = Bytes::from("hello world");
        storage.put("test", "abc123def456", data.clone()).await.unwrap();

        let retrieved = storage.get("test", "abc123def456").await.unwrap();
        assert_eq!(retrieved, data);

        // Exists
        assert!(storage.exists("test", "abc123def456").await.unwrap());
        assert!(!storage.exists("test", "nonexistent").await.unwrap());

        // Size
        let size = storage.size("test", "abc123def456").await.unwrap();
        assert_eq!(size, 11);

        // Delete
        storage.delete("test", "abc123def456").await.unwrap();
        assert!(!storage.exists("test", "abc123def456").await.unwrap());
    }

    #[tokio::test]
    async fn test_local_storage_list() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        // Put several objects
        storage.put("ns", "aabbccdd", Bytes::from("1")).await.unwrap();
        storage.put("ns", "aabbccee", Bytes::from("2")).await.unwrap();
        storage.put("ns", "xxyyzzww", Bytes::from("3")).await.unwrap();

        // List all
        let mut keys = storage.list("ns", None).await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["aabbccdd", "aabbccee", "xxyyzzww"]);

        // List with prefix
        let mut keys = storage.list("ns", Some("aabb")).await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["aabbccdd", "aabbccee"]);
    }

    #[tokio::test]
    async fn test_local_storage_streaming() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        // Create a test file
        let test_data = b"streaming test data";
        let src_file = temp_dir.path().join("source.txt");
        fs::write(&src_file, test_data).await.unwrap();

        // Put from file
        storage.put_from_file("stream", "file1", &src_file).await.unwrap();

        // Get to file
        let dest_file = temp_dir.path().join("dest.txt");
        storage.get_to_file("stream", "file1", &dest_file).await.unwrap();

        let read_data = fs::read(&dest_file).await.unwrap();
        assert_eq!(read_data, test_data);

        // Get stream
        let mut stream = storage.get_stream("stream", "file1").await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, test_data);
    }

    #[tokio::test]
    async fn test_local_storage_range() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        // Store test data: "0123456789"
        let data = Bytes::from("0123456789");
        storage.put("test", "abcdef123456", data).await.unwrap();

        // Get range [2, 5) should return "234"
        let range_data = storage.get_range("test", "abcdef123456", 2..5).await.unwrap();
        assert_eq!(range_data.as_ref(), b"234");

        // Get range [0, 3) should return "012"
        let range_data = storage.get_range("test", "abcdef123456", 0..3).await.unwrap();
        assert_eq!(range_data.as_ref(), b"012");

        // Get range [7, 10) should return "789"
        let range_data = storage.get_range("test", "abcdef123456", 7..10).await.unwrap();
        assert_eq!(range_data.as_ref(), b"789");

        // Invalid range should error
        let result = storage.get_range("test", "abcdef123456", 5..20).await;
        assert!(result.is_err());
    }
}
