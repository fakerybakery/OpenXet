use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};

use crate::error::{Result, ServerError};

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

/// Content-Addressable Storage backend
pub struct CasStore {
    /// Stored chunks indexed by hash
    chunks: DashMap<ContentHash, Chunk>,
    /// Stored xorbs indexed by hash
    xorbs: DashMap<ContentHash, Xorb>,
    /// File reconstruction info indexed by file hash
    reconstructions: DashMap<ContentHash, FileReconstruction>,
    /// Shards for global deduplication
    shards: DashMap<ContentHash, Bytes>,
    /// LFS objects - maps LFS OID to list of chunk hashes
    lfs_objects: DashMap<ContentHash, Vec<ContentHash>>,
    /// Chunker for content-defined chunking
    chunker: Chunker,
}

impl CasStore {
    pub fn new() -> Self {
        Self {
            chunks: DashMap::new(),
            xorbs: DashMap::new(),
            reconstructions: DashMap::new(),
            shards: DashMap::new(),
            lfs_objects: DashMap::new(),
            chunker: Chunker::new(),
        }
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

    // === LFS Object Storage (Central Store) ===

    /// Store an LFS object with content-defined chunking for deduplication
    /// Returns the list of chunk hashes
    pub fn store_lfs_object(&self, oid: ContentHash, data: Bytes) -> Vec<ContentHash> {
        // Chunk the data for deduplication
        let chunks = self.chunker.chunk(&data);

        let mut chunk_hashes = Vec::with_capacity(chunks.len());

        for chunk_data in chunks {
            let chunk = Chunk::new(chunk_data);
            let hash = chunk.hash;
            chunk_hashes.push(hash);

            // Only store if not already present (deduplication)
            self.chunks.entry(hash).or_insert(chunk);
        }

        // Store the mapping from OID to chunk list
        self.lfs_objects.insert(oid, chunk_hashes.clone());

        tracing::debug!(
            "Stored LFS object {} with {} chunks",
            oid.to_hex(),
            chunk_hashes.len()
        );

        chunk_hashes
    }

    /// Check if an LFS object exists
    pub fn has_lfs_object(&self, oid: &ContentHash) -> bool {
        self.lfs_objects.contains_key(oid)
    }

    /// Get an LFS object by reconstructing from chunks
    pub fn get_lfs_object(&self, oid: &ContentHash) -> Option<Bytes> {
        let chunk_hashes = self.lfs_objects.get(oid)?;

        let mut data = Vec::new();

        for hash in chunk_hashes.iter() {
            let chunk = self.chunks.get(hash)?;
            data.extend_from_slice(&chunk.data);
        }

        Some(Bytes::from(data))
    }

    /// Get LFS storage statistics
    pub fn lfs_stats(&self) -> LfsStats {
        let mut total_size: u64 = 0;
        let mut total_chunk_size: u64 = 0;

        for entry in self.lfs_objects.iter() {
            for hash in entry.value().iter() {
                if let Some(chunk) = self.chunks.get(hash) {
                    total_size += chunk.data.len() as u64;
                }
            }
        }

        for chunk in self.chunks.iter() {
            total_chunk_size += chunk.data.len() as u64;
        }

        LfsStats {
            object_count: self.lfs_objects.len(),
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

/// LFS storage statistics
#[derive(Clone, Debug)]
pub struct LfsStats {
    pub object_count: usize,
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
}
