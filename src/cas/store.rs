//! Content-Addressable Storage (CAS) module.
//!
//! Provides chunking, deduplication, and storage for large files.

#![allow(dead_code)] // Many methods are part of the public API but not yet used internally

use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::error::{Result, ServerError};

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

/// Xorb (Xet Object) - a collection of chunks
#[derive(Clone, Debug)]
pub struct Xorb {
    pub hash: ContentHash,
    pub chunks: Vec<ContentHash>,
    pub total_size: usize,
}

impl Xorb {
    pub fn new(chunks: Vec<ContentHash>) -> Self {
        // Hash is computed from the chunk hashes
        let mut hasher = Sha256::new();
        for chunk_hash in &chunks {
            hasher.update(chunk_hash.as_bytes());
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);

        Self {
            hash: ContentHash(hash),
            chunks,
            total_size: 0,
        }
    }
}

/// File reconstruction information
#[derive(Clone, Debug)]
pub struct FileReconstruction {
    pub file_hash: ContentHash,
    pub total_size: u64,
    pub terms: Vec<ReconstructionTerm>,
}

/// A term in file reconstruction (points to xorb + chunk range)
#[derive(Clone, Debug)]
pub struct ReconstructionTerm {
    pub xorb_hash: ContentHash,
    pub chunk_start: u32,
    pub chunk_end: u32,
    pub unpacked_length: u64,
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

/// Content-Addressable Storage backend with streaming and background processing
pub struct CasStore {
    /// Stored chunks indexed by hash
    chunks: DashMap<ContentHash, Chunk>,
    /// Stored xorbs indexed by hash
    xorbs: DashMap<ContentHash, Xorb>,
    /// File reconstruction info indexed by file hash
    reconstructions: DashMap<ContentHash, FileReconstruction>,
    /// Shards for global deduplication
    shards: DashMap<ContentHash, Bytes>,
    /// LFS object metadata - tracks status and location of each object
    lfs_objects: DashMap<ContentHash, LfsObjectMeta>,
    /// Chunker for content-defined chunking
    chunker: Chunker,
    /// Storage directory for raw files
    storage_path: PathBuf,
    /// Channel to send objects for background processing (unused - AppState holds this)
    process_tx: Option<mpsc::UnboundedSender<ContentHash>>,
    /// Counter for objects pending processing
    pending_count: AtomicU64,
}

impl CasStore {
    pub fn new() -> Self {
        Self::with_storage_path(std::env::temp_dir().join("git-xet-cas"))
    }

    pub fn with_storage_path(storage_path: PathBuf) -> Self {
        // Create storage directories
        let raw_path = storage_path.join("raw");
        let chunks_path = storage_path.join("chunks");
        std::fs::create_dir_all(&raw_path).ok();
        std::fs::create_dir_all(&chunks_path).ok();

        Self {
            chunks: DashMap::new(),
            xorbs: DashMap::new(),
            reconstructions: DashMap::new(),
            shards: DashMap::new(),
            lfs_objects: DashMap::new(),
            chunker: Chunker::new(),
            storage_path,
            process_tx: None,
            pending_count: AtomicU64::new(0),
        }
    }

    /// Get the path for storing a raw LFS object
    pub fn raw_object_path(&self, oid: &ContentHash) -> PathBuf {
        self.storage_path.join("raw").join(oid.to_hex())
    }

    /// Get the path for storing a chunk
    pub fn chunk_path(&self, hash: &ContentHash) -> PathBuf {
        let hex = hash.to_hex();
        // Use first 2 chars as subdirectory for better filesystem performance
        self.storage_path
            .join("chunks")
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
                raw_path: Some(path),
                chunk_hashes: None,
            },
        );

        // Note: Background processing is queued by the caller via AppState.queue_for_processing()
        // This avoids the need for interior mutability in CasStore
    }

    /// Store a chunk
    pub fn store_chunk(&self, data: Bytes) -> ContentHash {
        let chunk = Chunk::new(data);
        let hash = chunk.hash;
        self.chunks.insert(hash, chunk);
        hash
    }

    /// Get a chunk by hash
    pub fn get_chunk(&self, hash: &ContentHash) -> Option<Chunk> {
        self.chunks.get(hash).map(|r| r.clone())
    }

    /// Check if a chunk exists
    pub fn has_chunk(&self, hash: &ContentHash) -> bool {
        self.chunks.contains_key(hash)
    }

    /// Store a xorb
    pub fn store_xorb(&self, xorb: Xorb) -> ContentHash {
        let hash = xorb.hash;
        self.xorbs.insert(hash, xorb);
        hash
    }

    /// Get a xorb by hash
    pub fn get_xorb(&self, hash: &ContentHash) -> Option<Xorb> {
        self.xorbs.get(hash).map(|r| r.clone())
    }

    /// Store file reconstruction info
    pub fn store_reconstruction(&self, reconstruction: FileReconstruction) {
        self.reconstructions
            .insert(reconstruction.file_hash, reconstruction);
    }

    /// Get file reconstruction info
    pub fn get_reconstruction(&self, file_hash: &ContentHash) -> Option<FileReconstruction> {
        self.reconstructions.get(file_hash).map(|r| r.clone())
    }

    /// Store a shard
    pub fn store_shard(&self, data: Bytes) -> ContentHash {
        let hash = ContentHash::from_data(&data);
        self.shards.insert(hash, data);
        hash
    }

    /// Get a shard by hash
    pub fn get_shard(&self, hash: &ContentHash) -> Option<Bytes> {
        self.shards.get(hash).map(|r| r.clone())
    }

    /// Reconstruct a file from its hash
    pub fn reconstruct_file(&self, file_hash: &ContentHash) -> Result<Bytes> {
        let reconstruction = self
            .get_reconstruction(file_hash)
            .ok_or_else(|| ServerError::ObjectNotFound(file_hash.to_hex()))?;

        let mut result = Vec::with_capacity(reconstruction.total_size as usize);

        for term in &reconstruction.terms {
            let xorb = self
                .get_xorb(&term.xorb_hash)
                .ok_or_else(|| ServerError::ObjectNotFound(term.xorb_hash.to_hex()))?;

            for i in term.chunk_start..term.chunk_end {
                let chunk_hash = &xorb.chunks[i as usize];
                let chunk = self
                    .get_chunk(chunk_hash)
                    .ok_or_else(|| ServerError::ObjectNotFound(chunk_hash.to_hex()))?;
                result.extend_from_slice(&chunk.data);
            }
        }

        Ok(Bytes::from(result))
    }

    /// Get statistics
    pub fn stats(&self) -> CasStats {
        CasStats {
            chunk_count: self.chunks.len(),
            xorb_count: self.xorbs.len(),
            reconstruction_count: self.reconstructions.len(),
            shard_count: self.shards.len(),
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
                raw_path: Some(raw_path),
                chunk_hashes: None,
            },
        );

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
                raw_path: Some(raw_path),
                chunk_hashes: None,
            },
        );

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

        // Open raw file and chunk it with streaming
        let file = std::fs::File::open(&raw_path).map_err(|e| {
            ServerError::Internal(format!("Failed to open raw file: {}", e))
        })?;

        let chunk_hashes = self.chunk_and_store_streaming(file)?;

        // Update metadata to chunked
        if let Some(mut meta) = self.lfs_objects.get_mut(oid) {
            meta.status = LfsObjectStatus::Chunked;
            meta.raw_path = None;
            meta.chunk_hashes = Some(chunk_hashes.clone());
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

    /// Chunk and store data from a reader using streaming (constant memory usage)
    fn chunk_and_store_streaming<R: Read>(&self, reader: R) -> Result<Vec<ContentHash>> {
        let chunks = self.chunker.chunk_streaming(reader);
        let mut chunk_hashes = Vec::new();

        for chunk_data in chunks {
            let chunk_data = chunk_data.map_err(|e| {
                ServerError::Internal(format!("Error reading chunk: {}", e))
            })?;

            let chunk = Chunk::new(Bytes::from(chunk_data));
            let hash = chunk.hash;
            chunk_hashes.push(hash);

            // Only store if not already present (deduplication)
            self.chunks.entry(hash).or_insert(chunk);
        }

        Ok(chunk_hashes)
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

    /// Get an LFS object - returns path for streaming or reconstructs from chunks
    /// For large files, use get_lfs_object_reader instead
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
                // Reconstruct from chunks
                let chunk_hashes = meta.chunk_hashes.as_ref()?;
                let mut data = Vec::new();

                for hash in chunk_hashes {
                    let chunk = self.chunks.get(hash)?;
                    data.extend_from_slice(&chunk.data);
                }

                Some(Bytes::from(data))
            }
        }
    }

    /// Get a streaming reader for an LFS object (for large files)
    /// Returns either a file reader (for raw) or a chunk iterator (for chunked)
    pub fn get_lfs_object_path(&self, oid: &ContentHash) -> Option<LfsObjectSource> {
        let meta = self.lfs_objects.get(oid)?;

        match meta.status {
            LfsObjectStatus::Raw | LfsObjectStatus::Processing => {
                meta.raw_path.clone().map(LfsObjectSource::RawFile)
            }
            LfsObjectStatus::Chunked => {
                meta.chunk_hashes.clone().map(LfsObjectSource::Chunks)
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

        let mut total_chunk_size: u64 = 0;
        for chunk in self.chunks.iter() {
            total_chunk_size += chunk.data.len() as u64;
        }

        LfsStats {
            object_count: self.lfs_objects.len(),
            raw_count,
            processing_count,
            chunked_count,
            chunk_count: self.chunks.len(),
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
    /// Object is stored as chunks (list of chunk hashes)
    Chunks(Vec<ContentHash>),
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
    pub xorb_count: usize,
    pub reconstruction_count: usize,
    pub shard_count: usize,
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
        let store = CasStore::new();

        let data = Bytes::from("test data");
        let hash = store.store_chunk(data.clone());

        let retrieved = store.get_chunk(&hash).unwrap();
        assert_eq!(retrieved.data, data);
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

        // Should be able to get path
        match store.get_lfs_object_path(&oid) {
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
