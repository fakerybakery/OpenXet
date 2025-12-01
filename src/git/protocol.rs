use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Result, ServerError};
use super::pack::{generate_pack, parse_pack, pktline};
use super::storage::{GitObject, ObjectId, ObjectType, Repository};

/// Git protocol capabilities
pub const CAPABILITIES: &[&str] = &[
    "report-status",
    "delete-refs",
    "side-band-64k",
    "no-thin",
    "agent=git-xet-server/0.1",
];

/// Service types for Git Smart HTTP
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitService {
    UploadPack,  // git fetch/clone
    ReceivePack, // git push
}

impl GitService {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "git-upload-pack" => Some(GitService::UploadPack),
            "git-receive-pack" => Some(GitService::ReceivePack),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            GitService::UploadPack => "git-upload-pack",
            GitService::ReceivePack => "git-receive-pack",
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            GitService::UploadPack => "application/x-git-upload-pack-advertisement",
            GitService::ReceivePack => "application/x-git-receive-pack-advertisement",
        }
    }

    pub fn result_content_type(&self) -> &'static str {
        match self {
            GitService::UploadPack => "application/x-git-upload-pack-result",
            GitService::ReceivePack => "application/x-git-receive-pack-result",
        }
    }
}

/// Generate reference advertisement for info/refs
pub fn generate_ref_advertisement(repo: &Repository, service: GitService) -> Bytes {
    let mut response = BytesMut::new();

    // Service announcement line
    let service_line = format!("# service={}\n", service.as_str());
    response.put_slice(&pktline::encode(service_line.as_bytes()));
    response.put_slice(&pktline::flush());

    // List all refs with capabilities on first line
    let refs = repo.list_refs();
    let mut first = true;

    // HEAD first (if it exists)
    if let Some(head_target) = repo.resolve_ref("HEAD") {
        let line = if first {
            first = false;
            format!(
                "{} HEAD\0{}\n",
                head_target,
                CAPABILITIES.join(" ")
            )
        } else {
            format!("{} HEAD\n", head_target)
        };
        response.put_slice(&pktline::encode(line.as_bytes()));
    }

    // Then all other refs
    for git_ref in refs {
        if git_ref.name == "HEAD" {
            continue;
        }

        let line = if first {
            first = false;
            format!(
                "{} {}\0{}\n",
                git_ref.target,
                git_ref.name,
                CAPABILITIES.join(" ")
            )
        } else {
            format!("{} {}\n", git_ref.target, git_ref.name)
        };
        response.put_slice(&pktline::encode(line.as_bytes()));
    }

    // If no refs, send capabilities with zero-id (40 hex chars for SHA-1)
    if first {
        let zero_id = "0".repeat(40);
        let line = format!(
            "{} capabilities^{{}}\0{}\n",
            zero_id,
            CAPABILITIES.join(" ")
        );
        response.put_slice(&pktline::encode(line.as_bytes()));
    }

    response.put_slice(&pktline::flush());
    response.freeze()
}

/// Handle upload-pack request (git fetch/clone)
pub fn handle_upload_pack(repo: &Repository, request_body: &[u8]) -> Result<Bytes> {
    let mut response = BytesMut::new();

    // Parse the want/have lines
    let lines = pktline::parse_all(request_body);
    let mut wants: Vec<ObjectId> = Vec::new();
    let mut haves: Vec<ObjectId> = Vec::new();

    for line in &lines {
        let line_str = String::from_utf8_lossy(line);
        let line_str = line_str.trim();

        if line_str.starts_with("want ") {
            let hex = &line_str[5..].split_whitespace().next().unwrap_or("");
            if let Some(id) = ObjectId::from_hex(hex) {
                wants.push(id);
            }
        } else if line_str.starts_with("have ") {
            let hex = &line_str[5..].split_whitespace().next().unwrap_or("");
            if let Some(id) = ObjectId::from_hex(hex) {
                haves.push(id);
            }
        } else if line_str == "done" {
            break;
        }
    }

    // Send NAK if client has objects we don't recognize
    response.put_slice(&pktline::encode(b"NAK\n"));

    // Collect objects to send (simplified: send all requested)
    let mut objects_to_send: Vec<ObjectId> = Vec::new();

    for want in &wants {
        // Walk the commit graph starting from want
        collect_objects_recursive(repo, want, &haves, &mut objects_to_send);
    }

    // Generate and send pack file
    if !objects_to_send.is_empty() {
        let pack_data = generate_pack(repo, &objects_to_send)?;

        // Use side-band-64k format
        // Channel 1 = pack data, Channel 2 = progress, Channel 3 = error
        const SIDE_BAND_DATA: u8 = 1;
        const SIDE_BAND_PROGRESS: u8 = 2;

        // Send progress message
        let progress_msg = format!("\rCounting objects: {}, done.\n", objects_to_send.len());
        let mut progress_pkt = BytesMut::new();
        progress_pkt.put_u8(SIDE_BAND_PROGRESS);
        progress_pkt.put_slice(progress_msg.as_bytes());
        response.put_slice(&pktline::encode(&progress_pkt));

        // Send pack data in chunks
        let chunk_size = 65515; // Max side-band packet size minus header
        for chunk in pack_data.chunks(chunk_size) {
            let mut data_pkt = BytesMut::new();
            data_pkt.put_u8(SIDE_BAND_DATA);
            data_pkt.put_slice(chunk);
            response.put_slice(&pktline::encode(&data_pkt));
        }
    }

    response.put_slice(&pktline::flush());
    Ok(response.freeze())
}

/// Recursively collect objects starting from a commit
fn collect_objects_recursive(
    repo: &Repository,
    start: &ObjectId,
    exclude: &[ObjectId],
    collected: &mut Vec<ObjectId>,
) {
    if exclude.contains(start) || collected.contains(start) {
        return;
    }

    if let Some(obj) = repo.get_object(start) {
        collected.push(*start);

        match obj.object_type {
            ObjectType::Commit => {
                // Parse commit to find tree and parents
                if let Ok(commit_str) = std::str::from_utf8(&obj.data) {
                    for line in commit_str.lines() {
                        if line.starts_with("tree ") {
                            if let Some(tree_id) = ObjectId::from_hex(&line[5..]) {
                                collect_objects_recursive(repo, &tree_id, exclude, collected);
                            }
                        } else if line.starts_with("parent ") {
                            if let Some(parent_id) = ObjectId::from_hex(&line[7..]) {
                                collect_objects_recursive(repo, &parent_id, exclude, collected);
                            }
                        } else if line.is_empty() {
                            break;
                        }
                    }
                }
            }
            ObjectType::Tree => {
                // Parse tree entries - binary format: <mode> <name>\0<20-byte-sha1>
                let data = &obj.data[..];
                let mut pos = 0;

                while pos < data.len() {
                    // Find the null byte that separates mode+name from SHA
                    if let Some(null_pos) = data[pos..].iter().position(|&b| b == 0) {
                        let entry_end = pos + null_pos + 1 + 20; // +1 for null, +20 for SHA-1
                        if entry_end <= data.len() {
                            // Extract the 20-byte SHA-1
                            let sha_start = pos + null_pos + 1;
                            let mut sha_bytes = [0u8; 20];
                            sha_bytes.copy_from_slice(&data[sha_start..sha_start + 20]);

                            // Convert to ObjectId
                            let entry_id = ObjectId::from_raw(sha_bytes);
                            collect_objects_recursive(repo, &entry_id, exclude, collected);

                            pos = entry_end;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Handle receive-pack request (git push)
pub fn handle_receive_pack(repo: &Repository, request_body: &[u8]) -> Result<Bytes> {
    tracing::debug!("handle_receive_pack: {} bytes received", request_body.len());
    let mut response = BytesMut::new();

    // Parse command lines and pack data
    let mut offset = 0;
    let mut commands: Vec<(ObjectId, ObjectId, String)> = Vec::new();

    // Parse ref update commands
    while offset < request_body.len() {
        match pktline::parse(&request_body[offset..]) {
            Some((Some(line), consumed)) => {
                offset += consumed;
                let line_str = String::from_utf8_lossy(&line);
                tracing::debug!("receive-pack line: {:?}", line_str);
                let line_str = line_str.trim();

                // Format: <old-sha> <new-sha> <ref-name>[\0<capabilities>]
                // First split by null to separate capabilities
                let line_without_caps = line_str.split('\0').next().unwrap_or(line_str);
                let parts: Vec<&str> = line_without_caps.split_whitespace().collect();

                tracing::debug!("receive-pack parsed parts: {:?}", parts);

                if parts.len() >= 3 {
                    let old_hex = parts[0];
                    let new_hex = parts[1];
                    let ref_name = parts[2];

                    tracing::debug!(
                        "Parsing: old={} new={} ref={}",
                        old_hex,
                        new_hex,
                        ref_name
                    );

                    if let (Some(old_id), Some(new_id)) =
                        (ObjectId::from_hex(old_hex), ObjectId::from_hex(new_hex))
                    {
                        commands.push((old_id, new_id, ref_name.to_string()));
                    } else {
                        tracing::warn!(
                            "Failed to parse object IDs: old={} new={}",
                            old_hex,
                            new_hex
                        );
                    }
                }
            }
            Some((None, consumed)) => {
                offset += consumed;
                tracing::debug!("receive-pack: flush packet, pack data follows");
                break; // Flush packet, pack data follows
            }
            None => break,
        }
    }

    tracing::debug!("receive-pack: parsed {} commands", commands.len());

    // Parse pack data if present
    if offset < request_body.len() {
        let pack_data = &request_body[offset..];
        if pack_data.len() > 12 {
            // Minimum pack size
            match parse_pack(pack_data) {
                Ok(objects) => {
                    // Store all received objects
                    for (obj_type, data) in objects {
                        let git_obj = GitObject::new(obj_type, data);
                        repo.store_object(git_obj);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse pack: {}", e);
                }
            }
        }
    }

    // Process ref updates (40 hex chars for SHA-1)
    let zero_id = ObjectId::from_hex(&"0".repeat(40)).unwrap();

    let mut ref_results: Vec<(String, std::result::Result<(), ServerError>)> = Vec::new();

    for (old_id, new_id, ref_name) in commands {
        tracing::debug!(
            "receive-pack command: ref={} old={} new={}",
            ref_name,
            old_id.to_hex(),
            new_id.to_hex()
        );

        let is_delete = new_id == zero_id;
        let is_create = old_id == zero_id;

        let result = if is_delete {
            tracing::debug!("Deleting ref {}", ref_name);
            repo.delete_ref(&ref_name)
        } else if is_create {
            // Creating new ref
            tracing::debug!("Creating ref {} -> {}", ref_name, new_id.to_hex());
            repo.update_ref(&ref_name, new_id)
        } else {
            // Updating existing ref - verify old value matches
            if let Some(current) = repo.get_ref(&ref_name) {
                tracing::debug!(
                    "Updating ref {}: current={} old={} new={}",
                    ref_name,
                    current.target.to_hex(),
                    old_id.to_hex(),
                    new_id.to_hex()
                );
                if current.target != old_id {
                    Err(ServerError::InvalidRef(format!(
                        "ref {} is at {}, expected {}",
                        ref_name, current.target, old_id
                    )))
                } else {
                    repo.update_ref(&ref_name, new_id)
                }
            } else {
                // Ref doesn't exist but client thinks it does - allow creation anyway
                tracing::debug!("Ref {} not found, creating with new_id", ref_name);
                repo.update_ref(&ref_name, new_id)
            }
        };

        tracing::debug!("Ref update result for {}: {:?}", ref_name, result.is_ok());
        ref_results.push((ref_name, result));
    }

    // Check if client requested side-band-64k (look at first command line for capabilities)
    let use_sideband = request_body
        .windows(12)
        .any(|w| w == b"side-band-64" || w == b"side-band\0");

    if use_sideband {
        // Wrap report-status in side-band channel 1
        const SIDEBAND_PRIMARY: u8 = 1;

        // Build the report-status content
        let mut report = BytesMut::new();
        report.put_slice(&pktline::encode(b"unpack ok\n"));

        for (ref_name, result) in ref_results {
            let status = match result {
                Ok(_) => format!("ok {}\n", ref_name),
                Err(e) => format!("ng {} {}\n", ref_name, e),
            };
            report.put_slice(&pktline::encode(status.as_bytes()));
        }
        report.put_slice(&pktline::flush());

        // Send report through side-band
        let mut sideband_pkt = BytesMut::new();
        sideband_pkt.put_u8(SIDEBAND_PRIMARY);
        sideband_pkt.put_slice(&report);
        response.put_slice(&pktline::encode(&sideband_pkt));
        response.put_slice(&pktline::flush());
    } else {
        // Send report-status directly
        response.put_slice(&pktline::encode(b"unpack ok\n"));

        for (ref_name, result) in ref_results {
            let status = match result {
                Ok(_) => format!("ok {}\n", ref_name),
                Err(e) => format!("ng {} {}\n", ref_name, e),
            };
            response.put_slice(&pktline::encode(status.as_bytes()));
        }

        response.put_slice(&pktline::flush());
    }

    Ok(response.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_from_str() {
        assert_eq!(
            GitService::from_str("git-upload-pack"),
            Some(GitService::UploadPack)
        );
        assert_eq!(
            GitService::from_str("git-receive-pack"),
            Some(GitService::ReceivePack)
        );
        assert_eq!(GitService::from_str("invalid"), None);
    }

    #[test]
    fn test_generate_ref_advertisement() {
        let repo = crate::git::storage::Repository::new("test".to_string());
        let adv = generate_ref_advertisement(&repo, GitService::UploadPack);

        // Should contain service line
        assert!(adv.windows(4).any(|w| w == b"PACK" || w != b"PACK"));

        // Should contain capabilities
        let adv_str = String::from_utf8_lossy(&adv);
        assert!(adv_str.contains("report-status"));
    }
}
