//! LFS (Large File Storage) utilities.

use crate::cas::ContentHash;
use crate::git::Repository;

/// Parsed LFS pointer info
pub struct LfsPointerInfo {
    pub oid: ContentHash,
    pub size: u64,
}

/// Parse an LFS pointer file
pub fn parse_lfs_pointer(content: &[u8]) -> Option<LfsPointerInfo> {
    // LFS pointers are small text files
    if content.len() > 1024 {
        return None;
    }

    let text = std::str::from_utf8(content).ok()?;

    // Must start with version line
    if !text.starts_with("version https://git-lfs.github.com/spec/v1") {
        return None;
    }

    let mut oid: Option<ContentHash> = None;
    let mut size: Option<u64> = None;

    for line in text.lines() {
        if let Some(hash) = line.strip_prefix("oid sha256:") {
            oid = ContentHash::from_hex(hash.trim());
        } else if let Some(s) = line.strip_prefix("size ") {
            size = s.trim().parse().ok();
        }
    }

    Some(LfsPointerInfo {
        oid: oid?,
        size: size?,
    })
}

/// Check if a tree entry is an LFS file and get its status
pub fn check_lfs_file(
    repo: &Repository,
    state: &std::sync::Arc<crate::api::AppState>,
    entry: &crate::git::TreeEntry,
) -> (bool, Option<String>, Option<String>, Option<String>) {
    use super::utils::format_size;

    if entry.is_dir {
        return (false, None, None, None);
    }

    if let Some(content) = repo.get_blob_content(&entry.oid) {
        if let Some(lfs_info) = parse_lfs_pointer(&content) {
            let status = state.cas.get_lfs_object_status(&lfs_info.oid);
            let status_str = status.map(|s| match s {
                crate::cas::store::LfsObjectStatus::Raw => "raw".to_string(),
                crate::cas::store::LfsObjectStatus::Processing => "processing".to_string(),
                crate::cas::store::LfsObjectStatus::Chunked => "chunked".to_string(),
            });
            let oid_hex = lfs_info.oid.to_hex();
            return (true, status_str, Some(format_size(lfs_info.size)), Some(oid_hex));
        }
    }

    (false, None, None, None)
}
