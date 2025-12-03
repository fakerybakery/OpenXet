//! Content-Addressable Storage (CAS) module.
//!
//! Provides chunking, deduplication, and storage for large files.
//! Data is stored on disk via a pluggable storage backend (not in memory).
//! Metadata is persisted to SQLite database.

#![allow(dead_code)] // Many methods are part of the public API but not yet used internally

use bytes::Bytes;
use dashmap::DashMap;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::db::entities::{lfs_object, lfs_chunk, cas_chunk, cas_block, file_segment};
use crate::error::{Result, ServerError};
use crate::storage::{namespaces, StorageBackend, StorageConfig};

// ============================================================================
// Constants (aligned with xet-core)
// ============================================================================

/// Target chunk size for content-defined chunking (16KB like xet-core)
pub const TARGET_CDC_CHUNK_SIZE: usize = 16 * 1024;
/// Minimum chunk size = target / 4
pub const MIN_CHUNK_SIZE: usize = TARGET_CDC_CHUNK_SIZE / 4;
/// Maximum chunk size = target * 8
pub const MAX_CHUNK_SIZE: usize = TARGET_CDC_CHUNK_SIZE * 8;
/// Read buffer size for streaming (64KB)
pub const STREAM_BUFFER_SIZE: usize = 64 * 1024;
/// Target Block size (~64MB like HF Xet) - bundles chunks before upload to S3
/// This reduces S3 requests from millions to thousands for large files
pub const TARGET_BLOCK_SIZE: usize = 64 * 1024 * 1024;

/// Content hash (256-bit)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Self(hash)
    }

    /// Create from raw 32 bytes (no hashing, bytes are the hash)
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut hash = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).ok()?;
            hash[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Self(hash))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContentHash({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A chunk of deduplicated data
#[derive(Clone, Debug)]
pub struct Chunk {
    pub hash: ContentHash,
    pub data: Bytes,
    pub size: usize,
}

impl Chunk {
    pub fn new(data: Bytes) -> Self {
        let hash = ContentHash::from_data(&data);
        let size = data.len();
        Self { hash, data, size }
    }
}

/// A chunk entry within a Block (tracks byte offset within the block)
#[derive(Clone, Debug)]
pub struct BlockChunkEntry {
    /// Hash of this chunk
    pub chunk_hash: ContentHash,
    /// Size of this chunk in bytes
    pub chunk_size: u32,
    /// Byte offset of this chunk within the block data
    pub byte_offset: u32,
}

/// Block - a bundle of chunks (~64MB)
///
/// Blocks are the unit of storage in CAS (like HF Xet). Instead of storing
/// individual 64KB chunks, we bundle ~1000 chunks into a single ~64MB Block.
/// This dramatically reduces:
/// - Number of S3 requests for downloads (~780 vs 780,000 for 50GB file)
/// - Storage overhead (fewer objects to track)
///
/// The CAS server fetches byte ranges from Blocks to reconstruct files.
#[derive(Clone, Debug)]
pub struct Block {
    /// Hash of the block (computed from concatenated chunk data)
    pub hash: ContentHash,
    /// Chunk entries with their byte offsets within the block
    pub chunks: Vec<BlockChunkEntry>,
    /// Total size of the block data in bytes
    pub total_size: u32,
}

impl Block {
    /// Create a new Block from chunk data
    /// Returns the Block metadata and the concatenated data to store
    pub fn from_chunks(chunks: &[(ContentHash, Bytes)]) -> (Self, Bytes) {
        let mut hasher = Sha256::new();
        let mut entries = Vec::with_capacity(chunks.len());
        let mut data = Vec::new();
        let mut offset = 0u32;

        for (chunk_hash, chunk_data) in chunks {
            // Add to block data
            data.extend_from_slice(chunk_data);

            // Hash includes chunk data for content-addressing
            hasher.update(chunk_data);

            // Track chunk location
            entries.push(BlockChunkEntry {
                chunk_hash: *chunk_hash,
                chunk_size: chunk_data.len() as u32,
                byte_offset: offset,
            });

            offset += chunk_data.len() as u32;
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);

        let block = Self {
            hash: ContentHash(hash),
            chunks: entries,
            total_size: offset,
        };

        (block, Bytes::from(data))
    }

    /// Get the byte range for a specific chunk within this block
    pub fn chunk_byte_range(&self, chunk_index: usize) -> Option<(u32, u32)> {
        self.chunks.get(chunk_index).map(|entry| {
            (entry.byte_offset, entry.byte_offset + entry.chunk_size)
        })
    }

    /// Get the byte range spanning multiple consecutive chunks
    pub fn chunk_range_bytes(&self, start_idx: usize, end_idx: usize) -> Option<(u32, u32)> {
        if start_idx >= self.chunks.len() || end_idx > self.chunks.len() || start_idx >= end_idx {
            return None;
        }
        let start_offset = self.chunks[start_idx].byte_offset;
        let end_entry = &self.chunks[end_idx - 1];
        let end_offset = end_entry.byte_offset + end_entry.chunk_size;
        Some((start_offset, end_offset))
    }
}

/// A segment in file reconstruction - points to a byte range within a Block
#[derive(Clone, Debug)]
pub struct FileSegment {
    /// Hash of the Block containing this segment's data
    pub block_hash: ContentHash,
    /// Starting byte offset within the block
    pub byte_start: u32,
    /// Ending byte offset within the block (exclusive)
    pub byte_end: u32,
    /// Logical size of this segment (uncompressed)
    pub segment_size: u32,
}

/// File reconstruction information (Shard)
///
/// Maps a file hash to a list of segments, where each segment
/// is a byte range within a Block. This allows efficient reconstruction
/// by fetching only the needed byte ranges from Blocks.
///
/// In HF terminology, this metadata is stored in "shards" which are
/// synced between the CAS and clients for fast lookups.
#[derive(Clone, Debug)]
pub struct FileReconstruction {
    /// Hash of the complete file
    pub file_hash: ContentHash,
    /// Total size of the file
    pub total_size: u64,
    /// Ordered list of segments that make up the file
    pub segments: Vec<FileSegment>,
}

impl FileReconstruction {
    /// Create reconstruction info from a list of block segments
    pub fn new(file_hash: ContentHash, segments: Vec<FileSegment>) -> Self {
        let total_size = segments.iter().map(|s| s.segment_size as u64).sum();
        Self {
            file_hash,
            total_size,
            segments,
        }
    }

    /// Get the total number of Blocks needed to reconstruct this file
    pub fn block_count(&self) -> usize {
        let mut blocks: std::collections::HashSet<ContentHash> = std::collections::HashSet::new();
        for seg in &self.segments {
            blocks.insert(seg.block_hash);
        }
        blocks.len()
    }
}

/// Status of an LFS object in the storage system
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LfsObjectStatus {
    /// Object is stored raw, not yet chunked/deduped
    Raw,
    /// Object is being processed (chunking/dedup in progress)
    Processing,
    /// Object is fully processed and stored in CAS
    Chunked,
}

/// Metadata for an LFS object
#[derive(Clone, Debug)]
pub struct LfsObjectMeta {
    pub status: LfsObjectStatus,
    pub size: u64,
    /// For Raw/Processing: path to raw file
    /// For Chunked: None (data is in chunks)
    pub raw_path: Option<PathBuf>,
    /// For Chunked objects: list of chunk hashes in order
    pub chunk_hashes: Option<Vec<ContentHash>>,
}

// ============================================================================
// Parallel Streaming Reconstruction
// ============================================================================

/// Default parallelism for block fetching (concurrent S3 requests)
pub const DEFAULT_FETCH_PARALLELISM: usize = 32;

/// A stream that reconstructs a file from blocks with parallel fetching.
///
/// This enables streaming large files to clients without buffering the entire
/// file in memory. Segments are fetched in parallel but yielded in order.
pub struct ReconstructionStream {
    storage: Arc<dyn StorageBackend>,
    segments: Vec<FileSegment>,
    current_idx: usize,
    parallelism: usize,
    /// Buffer for out-of-order segments that arrived early
    pending: std::collections::HashMap<usize, Bytes>,
    /// Total size for progress tracking
    pub total_size: u64,
}

impl ReconstructionStream {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        reconstruction: FileReconstruction,
        parallelism: usize,
    ) -> Self {
        Self {
            storage,
            total_size: reconstruction.total_size,
            segments: reconstruction.segments,
            current_idx: 0,
            parallelism,
            pending: std::collections::HashMap::new(),
        }
    }

    /// Fetch the next batch of segments in parallel and return them in order.
    ///
    /// This method fetches up to `parallelism` segments concurrently,
    /// then returns them one at a time in the correct order.
    pub async fn next_chunk(&mut self) -> Option<Result<Bytes>> {
        use futures::stream::{self, StreamExt};

        // Check if we have a pending segment ready
        if let Some(data) = self.pending.remove(&self.current_idx) {
            self.current_idx += 1;
            return Some(Ok(data));
        }

        // If we've processed all segments, we're done
        if self.current_idx >= self.segments.len() {
            return None;
        }

        // Calculate how many segments to fetch in this batch
        let remaining = self.segments.len() - self.current_idx;
        let batch_size = remaining.min(self.parallelism);
        let batch_end = self.current_idx + batch_size;

        // Fetch batch in parallel
        let storage = self.storage.clone();
        let batch: Vec<(usize, FileSegment)> = self.segments[self.current_idx..batch_end]
            .iter()
            .enumerate()
            .map(|(i, s)| (self.current_idx + i, s.clone()))
            .collect();

        let fetches = stream::iter(batch)
            .map(|(idx, segment)| {
                let storage = storage.clone();
                async move {
                    let key = segment.block_hash.to_hex();
                    let range = segment.byte_start as u64..segment.byte_end as u64;
                    let data = storage
                        .get_range(namespaces::BLOCKS, &key, range)
                        .await
                        .map_err(|e| ServerError::Internal(e.to_string()))?;
                    Ok::<_, ServerError>((idx, data))
                }
            })
            .buffer_unordered(self.parallelism);

        let results: Vec<std::result::Result<(usize, Bytes), ServerError>> =
            fetches.collect().await;

        // Process results - store out-of-order ones, return the next in-order one
        for result in results {
            match result {
                Ok((idx, data)) => {
                    if idx == self.current_idx {
                        self.current_idx += 1;
                        // Before returning, check if we have subsequent segments ready
                        while let Some(next_data) = self.pending.remove(&self.current_idx) {
                            // We'll return these on subsequent calls
                            self.pending.insert(self.current_idx, next_data);
                            break;
                        }
                        return Some(Ok(data));
                    } else {
                        self.pending.insert(idx, data);
                    }
                }
                Err(e) => return Some(Err(e)),
            }
        }

        // Check pending again in case the first segment came out of order
        if let Some(data) = self.pending.remove(&self.current_idx) {
            self.current_idx += 1;
            return Some(Ok(data));
        }

        // This shouldn't happen unless there was an error
        None
    }

    /// Convert to a futures Stream for use with axum/hyper
    pub fn into_stream(
        self,
    ) -> impl futures::Stream<Item = std::result::Result<Bytes, std::io::Error>> {
        futures::stream::unfold(self, |mut stream| async move {
            match stream.next_chunk().await {
                Some(Ok(data)) => Some((Ok(data), stream)),
                Some(Err(e)) => Some((
                    Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
                    stream,
                )),
                None => None,
            }
        })
    }
}

/// Content-Addressable Storage backend with streaming and background processing.
///
/// Data is stored on disk via the storage backend, not in memory.
/// Metadata (hashes, sizes, LFS objects) is cached in memory and persisted to SQLite.
pub struct CasStore {
    /// Storage backend for persisting data
    storage: Arc<dyn StorageBackend>,
    /// Set of known chunk hashes (for dedup checking without disk access)
    chunk_index: DashMap<ContentHash, u64>, // hash -> size
    /// Block metadata (small, kept in memory for fast lookups)
    blocks: DashMap<ContentHash, Block>,
    /// File reconstruction info indexed by file hash (Shard data)
    reconstructions: DashMap<ContentHash, FileReconstruction>,
    /// LFS object metadata - tracks status and location of each object
    lfs_objects: DashMap<ContentHash, LfsObjectMeta>,
    /// Chunker for content-defined chunking
    chunker: Chunker,
    /// Storage path (for backward compat with raw_object_path)
    storage_path: PathBuf,
    /// Channel to send objects for background processing (unused - AppState holds this)
    process_tx: Option<mpsc::UnboundedSender<ContentHash>>,
    /// Counter for objects pending processing
    pending_count: AtomicU64,
    /// Database connection for persistence
    db: Option<Arc<DatabaseConnection>>,
}

impl CasStore {
    pub fn new() -> Self {
        Self::with_storage_config(StorageConfig::default())
    }

    pub fn with_storage_path(storage_path: PathBuf) -> Self {
        Self::with_storage_config(StorageConfig::local(storage_path))
    }

    pub fn with_storage_config(config: StorageConfig) -> Self {
        let storage_path = match &config.storage_type {
            crate::storage::StorageType::Local { path } => path.clone(),
            crate::storage::StorageType::S3(_) => std::env::temp_dir().join("git-xet-cache"),
        };

        // For sync context, only local storage is supported
        let storage = config.build_local().expect(
            "S3 storage requires async initialization. Use with_storage_config_async instead."
        );

        Self {
            storage,
            chunk_index: DashMap::new(),
            blocks: DashMap::new(),
            reconstructions: DashMap::new(),
            lfs_objects: DashMap::new(),
            chunker: Chunker::new(),
            storage_path,
            process_tx: None,
            pending_count: AtomicU64::new(0),
            db: None,
        }
    }

    /// Create with storage config (async version, supports all backends)
    pub async fn with_storage_config_async(config: StorageConfig) -> Self {
        let storage_path = match &config.storage_type {
            crate::storage::StorageType::Local { path } => path.clone(),
            crate::storage::StorageType::S3(_) => std::env::temp_dir().join("git-xet-cache"),
        };

        Self {
            storage: config.build().await,
            chunk_index: DashMap::new(),
            blocks: DashMap::new(),
            reconstructions: DashMap::new(),
            lfs_objects: DashMap::new(),
            chunker: Chunker::new(),
            storage_path,
            process_tx: None,
            pending_count: AtomicU64::new(0),
            db: None,
        }
    }

    /// Set database connection and load data from it
    pub fn set_db(&mut self, db: Arc<DatabaseConnection>) {
        self.db = Some(db);
    }

    /// Load LFS objects from database (call at startup)
    pub async fn load_from_db(&self) -> Result<()> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()), // No database configured
        };

        // Load LFS objects
        let lfs_objs = lfs_object::Entity::find().all(&**db).await
            .map_err(|e| ServerError::Internal(format!("Failed to load LFS objects: {}", e)))?;

        for obj in lfs_objs {
            if let Some(oid) = ContentHash::from_hex(&obj.oid) {
                let status = match obj.status {
                    0 => LfsObjectStatus::Raw,
                    1 => LfsObjectStatus::Processing,
                    2 => LfsObjectStatus::Chunked,
                    _ => LfsObjectStatus::Raw,
                };

                // Load chunk hashes if chunked
                let chunk_hashes = if status == LfsObjectStatus::Chunked {
                    let chunks = lfs_chunk::Entity::find()
                        .filter(lfs_chunk::Column::LfsOid.eq(&obj.oid))
                        .order_by_asc(lfs_chunk::Column::ChunkIndex)
                        .all(&**db)
                        .await
                        .map_err(|e| ServerError::Internal(format!("Failed to load chunks: {}", e)))?;

                    let hashes: Vec<ContentHash> = chunks
                        .into_iter()
                        .filter_map(|c| ContentHash::from_hex(&c.chunk_hash))
                        .collect();

                    if hashes.is_empty() { None } else { Some(hashes) }
                } else {
                    None
                };

                self.lfs_objects.insert(oid, LfsObjectMeta {
                    status,
                    size: obj.size as u64,
                    raw_path: obj.raw_path.map(PathBuf::from),
                    chunk_hashes,
                });
            }
        }

        // Load CAS blocks and their chunk entries
        let blocks = cas_block::Entity::find().all(&**db).await
            .map_err(|e| ServerError::Internal(format!("Failed to load blocks: {}", e)))?;

        for block_row in blocks {
            if let Some(block_hash) = ContentHash::from_hex(&block_row.hash) {
                // Load chunk entries for this block
                let chunk_entries = cas_chunk::Entity::find()
                    .filter(cas_chunk::Column::BlockHash.eq(&block_row.hash))
                    .order_by_asc(cas_chunk::Column::OffsetInBlock)
                    .all(&**db)
                    .await
                    .map_err(|e| ServerError::Internal(format!("Failed to load block chunks: {}", e)))?;

                let chunks: Vec<BlockChunkEntry> = chunk_entries
                    .into_iter()
                    .filter_map(|c| {
                        ContentHash::from_hex(&c.hash).map(|hash| BlockChunkEntry {
                            chunk_hash: hash,
                            chunk_size: c.size as u32,
                            byte_offset: c.offset_in_block as u32,
                        })
                    })
                    .collect();

                // Add chunks to deduplication index
                for entry in &chunks {
                    self.chunk_index.insert(entry.chunk_hash, entry.chunk_size as u64);
                }

                let block = Block {
                    hash: block_hash,
                    chunks,
                    total_size: block_row.size as u32,
                };
                self.blocks.insert(block_hash, block);
            }
        }

        // Load file reconstructions (segments)
        let segments = file_segment::Entity::find()
            .order_by_asc(file_segment::Column::FileHash)
            .order_by_asc(file_segment::Column::SegmentIndex)
            .all(&**db)
            .await
            .map_err(|e| ServerError::Internal(format!("Failed to load file segments: {}", e)))?;

        // Group segments by file hash
        let mut file_segments: std::collections::HashMap<String, Vec<FileSegment>> = std::collections::HashMap::new();
        for seg in segments {
            if let Some(block_hash) = ContentHash::from_hex(&seg.block_hash) {
                let segment = FileSegment {
                    block_hash,
                    byte_start: seg.byte_start as u32,
                    byte_end: seg.byte_end as u32,
                    segment_size: seg.segment_size as u32,
                };
                file_segments.entry(seg.file_hash).or_default().push(segment);
            }
        }

        // Create FileReconstruction objects
        for (file_hash_hex, segments) in file_segments {
            if let Some(file_hash) = ContentHash::from_hex(&file_hash_hex) {
                let reconstruction = FileReconstruction::new(file_hash, segments);
                self.reconstructions.insert(file_hash, reconstruction);
            }
        }

        tracing::info!(
            "Loaded {} LFS objects, {} blocks, {} chunks, {} file reconstructions from database",
            self.lfs_objects.len(),
            self.blocks.len(),
            self.chunk_index.len(),
            self.reconstructions.len()
        );
        Ok(())
    }

    /// Get the storage backend
    pub fn storage(&self) -> &Arc<dyn StorageBackend> {
        &self.storage
    }

    /// Get the path for storing a raw LFS object (for streaming uploads)
    pub fn raw_object_path(&self, oid: &ContentHash) -> PathBuf {
        self.storage_path
            .join(namespaces::LFS_RAW)
            .join(oid.to_hex())
    }

    /// Get the path for storing a chunk
    pub fn chunk_path(&self, hash: &ContentHash) -> PathBuf {
        let hex = hash.to_hex();
        // Use first 2 chars as subdirectory for better filesystem performance
        self.storage_path
            .join(namespaces::CAS_CHUNKS)
            .join(&hex[..2])
            .join(&hex[2..])
    }

    /// Start the background processing worker
    pub fn start_background_worker(cas: Arc<CasStore>) -> mpsc::UnboundedSender<ContentHash> {
        let (tx, mut rx) = mpsc::unbounded_channel::<ContentHash>();

        let cas_clone = cas.clone();
        tokio::spawn(async move {
            while let Some(oid) = rx.recv().await {
                tracing::debug!("Background worker processing LFS object: {}", oid.to_hex());
                if let Err(e) = cas_clone.process_raw_object(&oid).await {
                    tracing::error!("Failed to process LFS object {}: {}", oid.to_hex(), e);
                }
                cas_clone.pending_count.fetch_sub(1, Ordering::SeqCst);
            }
        });

        tx
    }

    /// Set the background processing channel
    pub fn set_process_channel(&mut self, tx: mpsc::UnboundedSender<ContentHash>) {
        self.process_tx = Some(tx);
    }

    /// Queue an object for background processing
    pub fn queue_for_processing(&self, oid: ContentHash) {
        if let Some(tx) = &self.process_tx {
            self.pending_count.fetch_add(1, Ordering::SeqCst);
            if tx.send(oid).is_err() {
                self.pending_count.fetch_sub(1, Ordering::SeqCst);
                tracing::error!("Failed to queue object for processing");
            }
        } else {
            tracing::warn!("No background worker configured, object will remain raw");
        }
    }

    /// Get count of objects pending background processing
    pub fn pending_processing_count(&self) -> u64 {
        self.pending_count.load(Ordering::SeqCst)
    }

    /// Register a raw object that was written directly to disk
    /// This is called by streaming upload handlers after writing the file
    /// Note: The caller should call queue_for_processing separately via AppState
    pub fn register_raw_object(&self, oid: ContentHash, size: u64, path: PathBuf) {
        self.lfs_objects.insert(
            oid,
            LfsObjectMeta {
                status: LfsObjectStatus::Raw,
                size,
                raw_path: Some(path.clone()),
                chunk_hashes: None,
            },
        );

        // Persist to database
        if let Some(db) = &self.db {
            let db = db.clone();
            let oid_hex = oid.to_hex();
            let path_str = path.to_string_lossy().to_string();
            tokio::spawn(async move {
                let model = lfs_object::ActiveModel {
                    oid: Set(oid_hex),
                    size: Set(size as i64),
                    status: Set(0), // Raw
                    raw_path: Set(Some(path_str)),
                };
                let _ = lfs_object::Entity::insert(model)
                    .on_conflict(
                        sea_orm::sea_query::OnConflict::column(lfs_object::Column::Oid)
                            .do_nothing()
                            .to_owned()
                    )
                    .exec(&*db)
                    .await;
            });
        }

        // Note: Background processing is queued by the caller via AppState.queue_for_processing()
        // This avoids the need for interior mutability in CasStore
    }

    /// Store a chunk to disk (async)
    pub async fn store_chunk(&self, data: Bytes) -> Result<ContentHash> {
        let hash = ContentHash::from_data(&data);
        let size = data.len() as u64;

        // Check if already stored (deduplication)
        if self.chunk_index.contains_key(&hash) {
            return Ok(hash);
        }

        // Store to backend
        self.storage
            .put(namespaces::CAS_CHUNKS, &hash.to_hex(), data)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        // Add to index
        self.chunk_index.insert(hash, size);

        Ok(hash)
    }

    /// Store a chunk synchronously (for use in sync contexts)
    /// Uses tokio::runtime::Handle to block on async
    pub fn store_chunk_sync(&self, data: Bytes) -> ContentHash {
        let hash = ContentHash::from_data(&data);
        let size = data.len() as u64;

        // Check if already stored (deduplication)
        if self.chunk_index.contains_key(&hash) {
            return hash;
        }

        // Store to backend using blocking
        let storage = self.storage.clone();
        let key = hash.to_hex();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = handle.block_on(async {
                storage.put(namespaces::CAS_CHUNKS, &key, data).await
            });
        } else {
            // Fallback: write directly to disk if no runtime
            let path = self.chunk_path(&hash);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&path, &data).ok();
        }

        // Add to index
        self.chunk_index.insert(hash, size);

        hash
    }

    /// Get a chunk by hash (async)
    pub async fn get_chunk(&self, hash: &ContentHash) -> Option<Chunk> {
        let data = self
            .storage
            .get(namespaces::CAS_CHUNKS, &hash.to_hex())
            .await
            .ok()?;
        let size = data.len();
        Some(Chunk {
            hash: *hash,
            data,
            size,
        })
    }

    /// Get a chunk synchronously
    pub fn get_chunk_sync(&self, hash: &ContentHash) -> Option<Chunk> {
        // Try direct file read for local storage
        let path = self.chunk_path(hash);
        let data = std::fs::read(&path).ok()?;
        let size = data.len();
        Some(Chunk {
            hash: *hash,
            data: Bytes::from(data),
            size,
        })
    }

    /// Check if a chunk exists (fast, uses in-memory index)
    pub fn has_chunk(&self, hash: &ContentHash) -> bool {
        self.chunk_index.contains_key(hash)
    }

    // =========================================================================
    // Block Storage (bundled chunks for efficient S3 storage)
    // =========================================================================

    /// Store a Block (bundled chunks) to disk
    /// Block data is stored in the BLOCKS namespace, metadata kept in memory
    pub async fn store_block(&self, chunks: Vec<(ContentHash, Bytes)>) -> Result<ContentHash> {
        let (block, data) = Block::from_chunks(&chunks);
        let hash = block.hash;

        // Store block data to disk
        self.storage
            .put(namespaces::BLOCKS, &hash.to_hex(), data)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        // Keep metadata in memory for fast lookups
        self.blocks.insert(hash, block);

        tracing::debug!("Stored block {} with {} chunks, {} bytes",
            hash.to_hex(), chunks.len(), self.blocks.get(&hash).map(|x| x.total_size).unwrap_or(0));

        Ok(hash)
    }

    /// Store a Block synchronously
    pub fn store_block_sync(&self, chunks: Vec<(ContentHash, Bytes)>) -> ContentHash {
        let (block, data) = Block::from_chunks(&chunks);
        let hash = block.hash;
        let hex = hash.to_hex();

        // Write to disk directly
        let path = self.storage_path
            .join(namespaces::BLOCKS)
            .join(&hex[..2])
            .join(&hex[2..]);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, &data).ok();

        // Persist block and chunk entries to database
        if let Some(db) = &self.db {
            let db = db.clone();
            let block_hash = hex.clone();
            let block_size = block.total_size as i64;
            let chunk_count = block.chunks.len() as i32;
            let chunk_entries: Vec<_> = block.chunks.iter().map(|e| {
                (e.chunk_hash.to_hex(), e.chunk_size as i64, e.byte_offset as i64)
            }).collect();

            tokio::spawn(async move {
                // Insert block metadata
                let block_model = cas_block::ActiveModel {
                    hash: Set(block_hash.clone()),
                    size: Set(block_size),
                    chunk_count: Set(chunk_count),
                    storage_key: Set(block_hash.clone()),
                };
                let _ = cas_block::Entity::insert(block_model)
                    .on_conflict(
                        sea_orm::sea_query::OnConflict::column(cas_block::Column::Hash)
                            .do_nothing()
                            .to_owned()
                    )
                    .exec(&*db)
                    .await;

                // Insert chunk entries
                for (chunk_hash, chunk_size, offset) in chunk_entries {
                    let chunk_model = cas_chunk::ActiveModel {
                        hash: Set(chunk_hash),
                        size: Set(chunk_size),
                        block_hash: Set(block_hash.clone()),
                        offset_in_block: Set(offset),
                    };
                    let _ = cas_chunk::Entity::insert(chunk_model)
                        .on_conflict(
                            sea_orm::sea_query::OnConflict::column(cas_chunk::Column::Hash)
                                .do_nothing()
                                .to_owned()
                        )
                        .exec(&*db)
                        .await;
                }
            });
        }

        // Keep metadata in memory
        self.blocks.insert(hash, block);

        hash
    }

    /// Get block metadata (fast, from memory)
    pub fn get_block_meta(&self, hash: &ContentHash) -> Option<Block> {
        self.blocks.get(hash).map(|r| r.clone())
    }

    /// Get full block data from disk
    pub async fn get_block_data(&self, hash: &ContentHash) -> Option<Bytes> {
        self.storage
            .get(namespaces::BLOCKS, &hash.to_hex())
            .await
            .ok()
    }

    /// Get a byte range from a block (for efficient partial fetches from S3)
    /// This is how the CAS server efficiently reconstructs files
    pub async fn get_block_range(&self, hash: &ContentHash, start: u32, end: u32) -> Option<Bytes> {
        let data = self.get_block_data(hash).await?;
        if end as usize > data.len() {
            return None;
        }
        Some(data.slice(start as usize..end as usize))
    }

    /// Get block range synchronously
    pub fn get_block_range_sync(&self, hash: &ContentHash, start: u32, end: u32) -> Option<Bytes> {
        let hex = hash.to_hex();
        let path = self.storage_path
            .join(namespaces::BLOCKS)
            .join(&hex[..2])
            .join(&hex[2..]);

        let data = std::fs::read(&path).ok()?;
        if end as usize > data.len() {
            return None;
        }
        Some(Bytes::from(data[start as usize..end as usize].to_vec()))
    }

    // =========================================================================
    // File Reconstruction
    // =========================================================================

    /// Store file reconstruction info
    pub fn store_reconstruction(&self, reconstruction: FileReconstruction) {
        let file_hash = reconstruction.file_hash;

        // Persist to database
        if let Some(db) = &self.db {
            let db = db.clone();
            let file_hash_hex = file_hash.to_hex();
            let segments: Vec<_> = reconstruction.segments.iter().enumerate().map(|(i, s)| {
                (i as i32, s.block_hash.to_hex(), s.byte_start as i64, s.byte_end as i64, s.segment_size as i64)
            }).collect();

            tokio::spawn(async move {
                // Insert all segments
                for (idx, block_hash, byte_start, byte_end, segment_size) in segments {
                    let model = file_segment::ActiveModel {
                        id: Set(Default::default()),
                        file_hash: Set(file_hash_hex.clone()),
                        segment_index: Set(idx),
                        block_hash: Set(block_hash),
                        byte_start: Set(byte_start),
                        byte_end: Set(byte_end),
                        segment_size: Set(segment_size),
                    };
                    let _ = file_segment::Entity::insert(model).exec(&*db).await;
                }
            });
        }

        // Keep in memory
        self.reconstructions.insert(file_hash, reconstruction);
    }

    /// Get file reconstruction info
    pub fn get_reconstruction(&self, file_hash: &ContentHash) -> Option<FileReconstruction> {
        self.reconstructions.get(file_hash).map(|r| r.clone())
    }

    /// Reconstruct a file from its hash using Block byte ranges
    /// This is what the CAS server does - fetches byte ranges from Blocks in S3
    pub async fn reconstruct_file(&self, file_hash: &ContentHash) -> Result<Bytes> {
        let reconstruction = self
            .get_reconstruction(file_hash)
            .ok_or_else(|| ServerError::ObjectNotFound(file_hash.to_hex()))?;

        let mut result = Vec::with_capacity(reconstruction.total_size as usize);

        for segment in &reconstruction.segments {
            let data = self
                .get_block_range(&segment.block_hash, segment.byte_start, segment.byte_end)
                .await
                .ok_or_else(|| ServerError::ObjectNotFound(segment.block_hash.to_hex()))?;
            result.extend_from_slice(&data);
        }

        Ok(Bytes::from(result))
    }

    /// Reconstruct a file synchronously
    pub fn reconstruct_file_sync(&self, file_hash: &ContentHash) -> Option<Bytes> {
        let reconstruction = self.get_reconstruction(file_hash)?;

        let mut result = Vec::with_capacity(reconstruction.total_size as usize);

        for segment in &reconstruction.segments {
            let data = self.get_block_range_sync(
                &segment.block_hash,
                segment.byte_start,
                segment.byte_end
            )?;
            result.extend_from_slice(&data);
        }

        Some(Bytes::from(result))
    }

    /// Reconstruct a file using parallel block fetches (HIGH PERFORMANCE)
    ///
    /// This is how HF achieves ~5 GB/s download speeds:
    /// - Fetch multiple block ranges in parallel (controlled by `parallelism`)
    /// - Stream results as they arrive (ordered for correct output)
    /// - For S3: uses HTTP Range requests for each segment
    ///
    /// For a 50GB file with ~780 blocks:
    /// - Sequential: 780 requests * ~100ms = 78 seconds
    /// - Parallel (32 concurrent): 780/32 * ~100ms = ~2.4 seconds
    pub async fn reconstruct_file_parallel(
        &self,
        file_hash: &ContentHash,
        parallelism: usize,
    ) -> Result<Bytes> {
        use futures::stream::{self, StreamExt};

        let reconstruction = self
            .get_reconstruction(file_hash)
            .ok_or_else(|| ServerError::ObjectNotFound(file_hash.to_hex()))?;

        // Create indexed segments for ordered reconstruction
        let indexed_segments: Vec<(usize, FileSegment)> = reconstruction
            .segments
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.clone()))
            .collect();

        // Fetch segments in parallel using buffer_unordered
        let storage = self.storage.clone();
        let fetches = stream::iter(indexed_segments)
            .map(|(idx, segment)| {
                let storage = storage.clone();
                async move {
                    let key = segment.block_hash.to_hex();
                    let range = segment.byte_start as u64..segment.byte_end as u64;
                    let data = storage
                        .get_range(namespaces::BLOCKS, &key, range)
                        .await
                        .map_err(|e| ServerError::Internal(e.to_string()))?;
                    Ok::<_, ServerError>((idx, data))
                }
            })
            .buffer_unordered(parallelism);

        // Collect results
        let results: Vec<(usize, Bytes)> = fetches
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        // Sort by index to maintain correct order
        let mut sorted_results = results;
        sorted_results.sort_by_key(|(idx, _)| *idx);

        // Assemble final result
        let mut output = Vec::with_capacity(reconstruction.total_size as usize);
        for (_, data) in sorted_results {
            output.extend_from_slice(&data);
        }

        Ok(Bytes::from(output))
    }

    /// Stream a reconstructed file with parallel fetching
    ///
    /// Returns a stream of bytes that can be piped directly to an HTTP response.
    /// This avoids buffering the entire file in memory.
    ///
    /// Uses a sliding window approach:
    /// - Prefetch `parallelism` segments ahead
    /// - Yield segments in order as they complete
    /// - Maintain back-pressure to avoid memory bloat
    pub fn reconstruct_file_stream(
        &self,
        file_hash: &ContentHash,
        parallelism: usize,
    ) -> Option<ReconstructionStream> {
        let reconstruction = self.get_reconstruction(file_hash)?;
        Some(ReconstructionStream::new(
            self.storage.clone(),
            reconstruction,
            parallelism,
        ))
    }

    /// Get statistics
    pub fn stats(&self) -> CasStats {
        CasStats {
            chunk_count: self.chunk_index.len(),
            block_count: self.blocks.len(),
            reconstruction_count: self.reconstructions.len(),
            lfs_object_count: self.lfs_objects.len(),
        }
    }

    // === LFS Object Storage with Streaming and Background Processing ===

    /// Store an LFS object from a stream - writes raw file immediately for fast uploads
    /// Queues background processing for chunking/deduplication
    /// Returns immediately after writing raw file (fast push)
    pub async fn store_lfs_object_stream<R: tokio::io::AsyncRead + Unpin>(
        &self,
        oid: ContentHash,
        _size: u64,
        mut reader: R,
    ) -> Result<()> {
        let raw_path = self.raw_object_path(&oid);

        // Write to raw storage with streaming (never loads full file in memory)
        let mut file = tokio::fs::File::create(&raw_path).await.map_err(|e| {
            ServerError::Internal(format!("Failed to create raw file: {}", e))
        })?;

        let mut buf = vec![0u8; STREAM_BUFFER_SIZE];
        let mut total_written = 0u64;

        loop {
            let n = reader.read(&mut buf).await.map_err(|e| {
                ServerError::Internal(format!("Failed to read from stream: {}", e))
            })?;

            if n == 0 {
                break;
            }

            file.write_all(&buf[..n]).await.map_err(|e| {
                ServerError::Internal(format!("Failed to write to raw file: {}", e))
            })?;

            total_written += n as u64;
        }

        file.sync_all().await.map_err(|e| {
            ServerError::Internal(format!("Failed to sync raw file: {}", e))
        })?;

        // Store metadata
        self.lfs_objects.insert(
            oid,
            LfsObjectMeta {
                status: LfsObjectStatus::Raw,
                size: total_written,
                raw_path: Some(raw_path.clone()),
                chunk_hashes: None,
            },
        );

        // Persist to database
        if let Some(db) = &self.db {
            let db = db.clone();
            let oid_hex = oid.to_hex();
            let path_str = raw_path.to_string_lossy().to_string();
            tokio::spawn(async move {
                let model = lfs_object::ActiveModel {
                    oid: Set(oid_hex),
                    size: Set(total_written as i64),
                    status: Set(0), // Raw
                    raw_path: Set(Some(path_str)),
                };
                let _ = lfs_object::Entity::insert(model)
                    .on_conflict(
                        sea_orm::sea_query::OnConflict::column(lfs_object::Column::Oid)
                            .do_nothing()
                            .to_owned()
                    )
                    .exec(&*db)
                    .await;
            });
        }

        tracing::info!(
            "LFS object {} stored raw ({} bytes), queuing for background processing",
            oid.to_hex(),
            total_written
        );

        // Queue for background chunking/deduplication
        self.queue_for_processing(oid);

        Ok(())
    }

    /// Store an LFS object from Bytes (legacy method for smaller files or sync contexts)
    /// Still queues background processing for consistency
    pub fn store_lfs_object(&self, oid: ContentHash, data: Bytes) -> Vec<ContentHash> {
        let raw_path = self.raw_object_path(&oid);
        let size = data.len() as u64;

        // Write synchronously for smaller files
        if let Err(e) = std::fs::write(&raw_path, &data) {
            tracing::error!("Failed to write raw LFS object: {}", e);
            return Vec::new();
        }

        // Store metadata as raw
        self.lfs_objects.insert(
            oid,
            LfsObjectMeta {
                status: LfsObjectStatus::Raw,
                size,
                raw_path: Some(raw_path.clone()),
                chunk_hashes: None,
            },
        );

        // Persist to database
        if let Some(db) = &self.db {
            let db = db.clone();
            let oid_hex = oid.to_hex();
            let path_str = raw_path.to_string_lossy().to_string();
            tokio::spawn(async move {
                let model = lfs_object::ActiveModel {
                    oid: Set(oid_hex),
                    size: Set(size as i64),
                    status: Set(0), // Raw
                    raw_path: Set(Some(path_str)),
                };
                let _ = lfs_object::Entity::insert(model)
                    .on_conflict(
                        sea_orm::sea_query::OnConflict::column(lfs_object::Column::Oid)
                            .do_nothing()
                            .to_owned()
                    )
                    .exec(&*db)
                    .await;
            });
        }

        // Queue for background processing
        self.queue_for_processing(oid);

        Vec::new() // Chunk hashes will be available after background processing
    }

    /// Process a raw object: chunk it and store in CAS (called by background worker)
    pub async fn process_raw_object(&self, oid: &ContentHash) -> Result<()> {
        // Get metadata and check status
        let meta = self.lfs_objects.get(oid).ok_or_else(|| {
            ServerError::ObjectNotFound(oid.to_hex())
        })?;

        if meta.status != LfsObjectStatus::Raw {
            tracing::debug!("Object {} already processed, skipping", oid.to_hex());
            return Ok(());
        }

        let raw_path = meta.raw_path.clone().ok_or_else(|| {
            ServerError::Internal("Raw object missing path".to_string())
        })?;
        let size = meta.size;
        drop(meta); // Release lock before long operation

        // Update status to processing
        if let Some(mut meta) = self.lfs_objects.get_mut(oid) {
            meta.status = LfsObjectStatus::Processing;
        }

        // Update database status to processing
        if let Some(db) = &self.db {
            let db = db.clone();
            let oid_hex = oid.to_hex();
            tokio::spawn(async move {
                let _ = lfs_object::Entity::update_many()
                    .col_expr(lfs_object::Column::Status, sea_orm::sea_query::Expr::value(1))
                    .filter(lfs_object::Column::Oid.eq(&oid_hex))
                    .exec(&*db)
                    .await;
            });
        }

        // Open raw file and chunk it with streaming
        let file = std::fs::File::open(&raw_path).map_err(|e| {
            ServerError::Internal(format!("Failed to open raw file: {}", e))
        })?;

        let chunk_hashes = self.chunk_and_store_streaming(file, *oid)?;

        // Update metadata to chunked
        if let Some(mut meta) = self.lfs_objects.get_mut(oid) {
            meta.status = LfsObjectStatus::Chunked;
            meta.raw_path = None;
            meta.chunk_hashes = Some(chunk_hashes.clone());
        }

        // Update database to chunked status and store chunk hashes
        if let Some(db) = &self.db {
            let db = db.clone();
            let oid_hex = oid.to_hex();
            let chunk_hashes_clone = chunk_hashes.clone();
            tokio::spawn(async move {
                // Update LFS object status
                let _ = lfs_object::Entity::update_many()
                    .col_expr(lfs_object::Column::Status, sea_orm::sea_query::Expr::value(2))
                    .col_expr(lfs_object::Column::RawPath, sea_orm::sea_query::Expr::value::<Option<String>>(None))
                    .filter(lfs_object::Column::Oid.eq(&oid_hex))
                    .exec(&*db)
                    .await;

                // Store chunk hashes for reconstruction
                for (i, chunk_hash) in chunk_hashes_clone.iter().enumerate() {
                    let model = lfs_chunk::ActiveModel {
                        id: Set(Default::default()),
                        lfs_oid: Set(oid_hex.clone()),
                        chunk_index: Set(i as i32),
                        chunk_hash: Set(chunk_hash.to_hex()),
                    };
                    let _ = lfs_chunk::Entity::insert(model).exec(&*db).await;
                }
            });
        }

        // Optionally delete raw file after successful chunking
        if let Err(e) = std::fs::remove_file(&raw_path) {
            tracing::warn!("Failed to remove raw file after chunking: {}", e);
        }

        tracing::info!(
            "LFS object {} processed: {} bytes -> {} chunks",
            oid.to_hex(),
            size,
            chunk_hashes.len()
        );

        Ok(())
    }

    /// Chunk and store data from a reader, bundling into Blocks (~64MB each)
    /// Returns the chunk hashes and creates reconstruction info (shard)
    fn chunk_and_store_streaming<R: Read>(&self, reader: R, file_hash: ContentHash) -> Result<Vec<ContentHash>> {
        let chunks = self.chunker.chunk_streaming(reader);
        let mut all_chunk_hashes = Vec::new();

        // Accumulator for building blocks
        let mut pending_chunks: Vec<(ContentHash, Bytes)> = Vec::new();
        let mut pending_size = 0usize;

        // Segments for file reconstruction (shard data)
        let mut segments: Vec<FileSegment> = Vec::new();

        for chunk_result in chunks {
            let chunk_data = chunk_result.map_err(|e| {
                ServerError::Internal(format!("Error reading chunk: {}", e))
            })?;

            let data = Bytes::from(chunk_data);
            let chunk_hash = ContentHash::from_data(&data);
            let chunk_size = data.len();

            // Add to pending block
            pending_chunks.push((chunk_hash, data));
            pending_size += chunk_size;
            all_chunk_hashes.push(chunk_hash);

            // If we've accumulated enough for a block, flush it
            if pending_size >= TARGET_BLOCK_SIZE {
                let block_hash = self.store_block_sync(pending_chunks.clone());

                // Get the block metadata to build segment info
                if let Some(block) = self.get_block_meta(&block_hash) {
                    // Create segment covering all chunks in this block
                    segments.push(FileSegment {
                        block_hash,
                        byte_start: 0,
                        byte_end: block.total_size,
                        segment_size: block.total_size,
                    });
                }

                // Reset accumulator
                pending_chunks.clear();
                pending_size = 0;
            }
        }

        // Flush remaining chunks as final block
        if !pending_chunks.is_empty() {
            let block_hash = self.store_block_sync(pending_chunks);

            if let Some(block) = self.get_block_meta(&block_hash) {
                segments.push(FileSegment {
                    block_hash,
                    byte_start: 0,
                    byte_end: block.total_size,
                    segment_size: block.total_size,
                });
            }
        }

        // Store file reconstruction info (shard)
        let reconstruction = FileReconstruction::new(file_hash, segments);
        self.store_reconstruction(reconstruction);

        tracing::debug!(
            "File {} chunked into {} chunks across {} blocks",
            file_hash.to_hex(),
            all_chunk_hashes.len(),
            self.get_reconstruction(&file_hash).map(|r| r.segments.len()).unwrap_or(0)
        );

        Ok(all_chunk_hashes)
    }

    /// Check if an LFS object exists (in any state)
    pub fn has_lfs_object(&self, oid: &ContentHash) -> bool {
        self.lfs_objects.contains_key(oid)
    }

    /// Get the status of an LFS object
    pub fn get_lfs_object_status(&self, oid: &ContentHash) -> Option<LfsObjectStatus> {
        self.lfs_objects.get(oid).map(|m| m.status.clone())
    }

    /// Get the size of an LFS object
    pub fn get_lfs_object_size(&self, oid: &ContentHash) -> Option<u64> {
        self.lfs_objects.get(oid).map(|m| m.size)
    }

    /// Get an LFS object - returns data from raw file or reconstructs from Xorbs
    pub fn get_lfs_object(&self, oid: &ContentHash) -> Option<Bytes> {
        let meta = self.lfs_objects.get(oid)?;

        match meta.status {
            LfsObjectStatus::Raw | LfsObjectStatus::Processing => {
                // Read from raw file
                if let Some(path) = &meta.raw_path {
                    std::fs::read(path).ok().map(Bytes::from)
                } else {
                    None
                }
            }
            LfsObjectStatus::Chunked => {
                // Reconstruct from Xorbs using byte ranges
                self.reconstruct_file_sync(oid)
            }
        }
    }

    /// Get source info for an LFS object
    /// Returns either raw file path or file hash for Xorb reconstruction
    pub fn get_lfs_object_source(&self, oid: &ContentHash) -> Option<LfsObjectSource> {
        let meta = self.lfs_objects.get(oid)?;

        match meta.status {
            LfsObjectStatus::Raw | LfsObjectStatus::Processing => {
                meta.raw_path.clone().map(LfsObjectSource::RawFile)
            }
            LfsObjectStatus::Chunked => {
                Some(LfsObjectSource::Blocks(*oid))
            }
        }
    }

    /// Get LFS storage statistics
    pub fn lfs_stats(&self) -> LfsStats {
        let mut raw_count = 0;
        let mut processing_count = 0;
        let mut chunked_count = 0;
        let mut total_size: u64 = 0;

        for entry in self.lfs_objects.iter() {
            total_size += entry.size;
            match entry.status {
                LfsObjectStatus::Raw => raw_count += 1,
                LfsObjectStatus::Processing => processing_count += 1,
                LfsObjectStatus::Chunked => chunked_count += 1,
            }
        }

        // Estimate physical size from chunk index (sizes stored in index)
        let mut total_chunk_size: u64 = 0;
        for entry in self.chunk_index.iter() {
            total_chunk_size += *entry.value();
        }

        LfsStats {
            object_count: self.lfs_objects.len(),
            raw_count,
            processing_count,
            chunked_count,
            chunk_count: self.chunk_index.len(),
            total_logical_size: total_size,
            total_physical_size: total_chunk_size,
            dedup_ratio: if total_chunk_size > 0 {
                total_size as f64 / total_chunk_size as f64
            } else {
                1.0
            },
        }
    }
}

/// Source for reading an LFS object
#[derive(Clone, Debug)]
pub enum LfsObjectSource {
    /// Object is stored as a raw file
    RawFile(PathBuf),
    /// Object is stored in Blocks (use file reconstruction to get data)
    Blocks(ContentHash),
}

use tokio::io::AsyncWriteExt;

/// LFS storage statistics
#[derive(Clone, Debug)]
pub struct LfsStats {
    pub object_count: usize,
    pub raw_count: usize,
    pub processing_count: usize,
    pub chunked_count: usize,
    pub chunk_count: usize,
    pub total_logical_size: u64,
    pub total_physical_size: u64,
    pub dedup_ratio: f64,
}

impl Default for CasStore {
    fn default() -> Self {
        Self::new()
    }
}

/// CAS storage statistics
#[derive(Clone, Debug)]
pub struct CasStats {
    pub chunk_count: usize,
    pub block_count: usize,
    pub reconstruction_count: usize,
    pub lfs_object_count: usize,
}

/// Content-based chunking using a rolling hash (simplified gear hash)
pub struct Chunker {
    min_chunk_size: usize,
    max_chunk_size: usize,
    target_chunk_size: usize,
    mask: u64,
}

impl Chunker {
    pub fn new() -> Self {
        Self::with_params(8 * 1024, 64 * 1024, 16 * 1024)
    }

    pub fn with_params(min: usize, max: usize, target: usize) -> Self {
        // Compute mask for target chunk size
        let bits = (target as f64).log2() as u32;
        let mask = (1u64 << bits) - 1;

        Self {
            min_chunk_size: min,
            max_chunk_size: max,
            target_chunk_size: target,
            mask,
        }
    }

    /// Chunk data into content-defined chunks
    pub fn chunk(&self, data: &[u8]) -> Vec<Bytes> {
        if data.is_empty() {
            return Vec::new();
        }

        let mut chunks = Vec::new();
        let mut start = 0;

        while start < data.len() {
            let end = self.find_chunk_boundary(&data[start..]);
            let chunk_end = start + end;

            chunks.push(Bytes::copy_from_slice(&data[start..chunk_end]));
            start = chunk_end;
        }

        chunks
    }

    /// Find the next chunk boundary using a rolling hash
    fn find_chunk_boundary(&self, data: &[u8]) -> usize {
        if data.len() <= self.min_chunk_size {
            return data.len();
        }

        let mut hash: u64 = 0;

        // Start looking for boundary after min_chunk_size
        for i in self.min_chunk_size..data.len() {
            if i >= self.max_chunk_size {
                return i;
            }

            // Gear hash rolling
            hash = (hash << 1).wrapping_add(GEAR_TABLE[data[i] as usize]);

            if (hash & self.mask) == 0 {
                return i + 1;
            }
        }

        data.len()
    }

    /// Chunk data from a reader using streaming (constant memory usage)
    /// Returns an iterator that yields chunks one at a time
    pub fn chunk_streaming<R: Read>(&self, reader: R) -> StreamingChunker<R> {
        StreamingChunker::new(reader, self.min_chunk_size, self.max_chunk_size, self.mask)
    }
}

/// Streaming chunker that reads from a reader and yields chunks
/// Uses constant memory regardless of input size
pub struct StreamingChunker<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    min_chunk_size: usize,
    max_chunk_size: usize,
    mask: u64,
    eof: bool,
}

impl<R: Read> StreamingChunker<R> {
    fn new(reader: R, min_chunk_size: usize, max_chunk_size: usize, mask: u64) -> Self {
        Self {
            reader,
            buffer: Vec::with_capacity(max_chunk_size * 2),
            min_chunk_size,
            max_chunk_size,
            mask,
            eof: false,
        }
    }

    /// Fill buffer from reader until we have enough data or EOF
    fn fill_buffer(&mut self) -> std::io::Result<()> {
        if self.eof {
            return Ok(());
        }

        let mut temp_buf = [0u8; STREAM_BUFFER_SIZE];

        // Keep reading until we have at least max_chunk_size or EOF
        while self.buffer.len() < self.max_chunk_size {
            let n = self.reader.read(&mut temp_buf)?;
            if n == 0 {
                self.eof = true;
                break;
            }
            self.buffer.extend_from_slice(&temp_buf[..n]);
        }

        Ok(())
    }

    /// Find chunk boundary in current buffer
    fn find_boundary(&self) -> usize {
        if self.buffer.len() <= self.min_chunk_size {
            return self.buffer.len();
        }

        let mut hash: u64 = 0;

        for i in self.min_chunk_size..self.buffer.len() {
            if i >= self.max_chunk_size {
                return i;
            }

            hash = (hash << 1).wrapping_add(GEAR_TABLE[self.buffer[i] as usize]);

            if (hash & self.mask) == 0 {
                return i + 1;
            }
        }

        // If we have EOF and still in buffer, return whole thing
        if self.eof {
            return self.buffer.len();
        }

        // Otherwise, return up to max chunk size
        self.max_chunk_size.min(self.buffer.len())
    }
}

impl<R: Read> Iterator for StreamingChunker<R> {
    type Item = std::io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Fill buffer
        if let Err(e) = self.fill_buffer() {
            return Some(Err(e));
        }

        // If buffer is empty and we hit EOF, we're done
        if self.buffer.is_empty() {
            return None;
        }

        // Find chunk boundary
        let boundary = self.find_boundary();

        // Extract chunk
        let chunk: Vec<u8> = self.buffer.drain(..boundary).collect();

        Some(Ok(chunk))
    }
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new()
    }
}

/// Gear hash lookup table (pre-computed random values)
static GEAR_TABLE: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0;
    let mut state: u64 = 0x123456789abcdef0;
    while i < 256 {
        // Simple PRNG for table generation
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        table[i] = state;
        i += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash() {
        let data = b"hello world";
        let hash = ContentHash::from_data(data);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);

        let parsed = ContentHash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_chunk_storage() {
        let temp_dir = std::env::temp_dir().join("cas-test-chunk-storage");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = CasStore::with_storage_path(temp_dir.clone());

        let data = Bytes::from("test data");
        let hash = store.store_chunk_sync(data.clone());

        let retrieved = store.get_chunk_sync(&hash).unwrap();
        assert_eq!(retrieved.data, data);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_chunker() {
        let chunker = Chunker::new();

        // Small data should be single chunk
        let small_data = vec![0u8; 1000];
        let chunks = chunker.chunk(&small_data);
        assert_eq!(chunks.len(), 1);

        // Large data should be multiple chunks
        let large_data = vec![0u8; 1024 * 1024]; // 1MB
        let chunks = chunker.chunk(&large_data);
        assert!(chunks.len() > 1);
    }

    #[test]
    fn test_streaming_chunker() {
        let chunker = Chunker::new();

        // Test streaming chunker produces same results as regular chunker
        let data = vec![0u8; 100_000]; // 100KB
        let regular_chunks = chunker.chunk(&data);

        let cursor = std::io::Cursor::new(&data);
        let streaming_chunks: Vec<Vec<u8>> = chunker
            .chunk_streaming(cursor)
            .map(|r| r.unwrap())
            .collect();

        // Same number of chunks
        assert_eq!(regular_chunks.len(), streaming_chunks.len());

        // Same content
        for (regular, streaming) in regular_chunks.iter().zip(streaming_chunks.iter()) {
            assert_eq!(regular.as_ref(), streaming.as_slice());
        }
    }

    #[test]
    fn test_register_raw_object() {
        let temp_dir = std::env::temp_dir().join("cas-test-raw");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = CasStore::with_storage_path(temp_dir.clone());

        // Create a test file
        let test_data = b"hello world test data";
        let oid = ContentHash::from_data(test_data);
        let raw_path = store.raw_object_path(&oid);

        std::fs::create_dir_all(raw_path.parent().unwrap()).unwrap();
        std::fs::write(&raw_path, test_data).unwrap();

        // Register it
        store.register_raw_object(oid, test_data.len() as u64, raw_path);

        // Should exist and be in Raw status
        assert!(store.has_lfs_object(&oid));
        assert_eq!(store.get_lfs_object_status(&oid), Some(LfsObjectStatus::Raw));
        assert_eq!(store.get_lfs_object_size(&oid), Some(test_data.len() as u64));

        // Should be able to get source
        match store.get_lfs_object_source(&oid) {
            Some(LfsObjectSource::RawFile(path)) => {
                assert!(path.exists());
            }
            _ => panic!("Expected RawFile source"),
        }

        // Should be able to read content
        let content = store.get_lfs_object(&oid).unwrap();
        assert_eq!(content.as_ref(), test_data);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_lfs_object_status_enum() {
        // Ensure status equality works
        assert_eq!(LfsObjectStatus::Raw, LfsObjectStatus::Raw);
        assert_ne!(LfsObjectStatus::Raw, LfsObjectStatus::Processing);
        assert_ne!(LfsObjectStatus::Processing, LfsObjectStatus::Chunked);
    }

    #[test]
    fn test_content_hash_from_raw() {
        let bytes = [0u8; 32];
        let hash = ContentHash::from_raw(bytes);
        assert_eq!(hash.as_bytes(), &bytes);

        // Different from hashing the same bytes
        let hashed = ContentHash::from_data(&bytes);
        assert_ne!(hash, hashed);
    }
}
