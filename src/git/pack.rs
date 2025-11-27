use std::io::{Read, Write};

use bytes::{BufMut, Bytes, BytesMut};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};

use crate::error::{Result, ServerError};
use super::storage::{GitObject, ObjectId, ObjectType, Repository};

/// Pack file object types (as per Git pack format)
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum PackObjectType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    // Delta types (6 and 7) not implemented for simplicity
}

impl From<ObjectType> for PackObjectType {
    fn from(t: ObjectType) -> Self {
        match t {
            ObjectType::Commit => PackObjectType::Commit,
            ObjectType::Tree => PackObjectType::Tree,
            ObjectType::Blob => PackObjectType::Blob,
            ObjectType::Tag => PackObjectType::Tag,
        }
    }
}

impl TryFrom<u8> for PackObjectType {
    type Error = ServerError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(PackObjectType::Commit),
            2 => Ok(PackObjectType::Tree),
            3 => Ok(PackObjectType::Blob),
            4 => Ok(PackObjectType::Tag),
            _ => Err(ServerError::GitProtocol(format!(
                "Unknown pack object type: {}",
                value
            ))),
        }
    }
}

impl From<PackObjectType> for ObjectType {
    fn from(t: PackObjectType) -> Self {
        match t {
            PackObjectType::Commit => ObjectType::Commit,
            PackObjectType::Tree => ObjectType::Tree,
            PackObjectType::Blob => ObjectType::Blob,
            PackObjectType::Tag => ObjectType::Tag,
        }
    }
}

/// Generate a pack file from a set of objects
pub fn generate_pack(repo: &Repository, object_ids: &[ObjectId]) -> Result<Bytes> {
    let mut pack = BytesMut::new();

    // Pack signature: "PACK"
    pack.put_slice(b"PACK");

    // Version: 2
    pack.put_u32(2);

    // Number of objects
    pack.put_u32(object_ids.len() as u32);

    // Write each object
    for id in object_ids {
        let obj = repo
            .get_object(id)
            .ok_or_else(|| ServerError::ObjectNotFound(id.to_hex()))?;

        write_pack_object(&mut pack, &obj)?;
    }

    // Compute and append SHA-1 checksum (20 bytes - Git standard)
    let mut hasher = Sha1::new();
    hasher.update(&pack);
    let checksum = hasher.finalize();
    pack.put_slice(&checksum);

    Ok(pack.freeze())
}

/// Write a single object to the pack
fn write_pack_object(pack: &mut BytesMut, obj: &GitObject) -> Result<()> {
    let obj_type = PackObjectType::from(obj.object_type) as u8;
    let size = obj.data.len();

    // Encode type and size in pack format
    // First byte: 1-bit MSB continuation, 3-bit type, 4-bit size
    let mut header = Vec::new();
    let first_byte = ((obj_type & 0x07) << 4) | ((size & 0x0f) as u8);
    let mut remaining_size = size >> 4;

    if remaining_size > 0 {
        header.push(first_byte | 0x80);
        while remaining_size > 0 {
            let byte = (remaining_size & 0x7f) as u8;
            remaining_size >>= 7;
            if remaining_size > 0 {
                header.push(byte | 0x80);
            } else {
                header.push(byte);
            }
        }
    } else {
        header.push(first_byte);
    }

    pack.put_slice(&header);

    // Compress the object data using zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&obj.data)
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    pack.put_slice(&compressed);

    Ok(())
}

/// Parse a pack file and extract objects
pub fn parse_pack(data: &[u8]) -> Result<Vec<(ObjectType, Bytes)>> {
    if data.len() < 12 {
        return Err(ServerError::GitProtocol("Pack too small".to_string()));
    }

    // Verify signature
    if &data[0..4] != b"PACK" {
        return Err(ServerError::GitProtocol("Invalid pack signature".to_string()));
    }

    // Read version
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(ServerError::GitProtocol(format!(
            "Unsupported pack version: {}",
            version
        )));
    }

    // Read object count
    let num_objects = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;

    let mut objects = Vec::with_capacity(num_objects);
    let mut offset = 12;

    for _ in 0..num_objects {
        if offset >= data.len().saturating_sub(20) {
            break;
        }

        match parse_pack_object(&data[offset..]) {
            Ok((obj_type, obj_data, bytes_read)) => {
                objects.push((obj_type, Bytes::from(obj_data)));
                offset += bytes_read;
            }
            Err(e) => {
                tracing::warn!("Error parsing pack object: {}", e);
                break;
            }
        }
    }

    Ok(objects)
}

/// Parse a single object from pack data
fn parse_pack_object(data: &[u8]) -> Result<(ObjectType, Vec<u8>, usize)> {
    if data.is_empty() {
        return Err(ServerError::GitProtocol("Empty pack object".to_string()));
    }

    // Parse header
    let first_byte = data[0];
    let obj_type_num = (first_byte >> 4) & 0x07;
    let mut size = (first_byte & 0x0f) as usize;
    let mut offset = 1;
    let mut shift = 4;

    while offset > 0 && data[offset - 1] & 0x80 != 0 {
        if offset >= data.len() {
            return Err(ServerError::GitProtocol("Truncated pack header".to_string()));
        }
        size |= ((data[offset] & 0x7f) as usize) << shift;
        offset += 1;
        shift += 7;
    }

    let obj_type = PackObjectType::try_from(obj_type_num)?;

    // Decompress the zlib data
    let compressed_data = &data[offset..];
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut decompressed = Vec::with_capacity(size);

    match decoder.read_to_end(&mut decompressed) {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Zlib decompression error: {}", e);
            // Try to return what we got
        }
    }

    // Calculate how many bytes of compressed data we consumed
    let compressed_size = decoder.total_in() as usize;

    Ok((obj_type.into(), decompressed, offset + compressed_size))
}

/// Git pkt-line format helpers
pub mod pktline {
    use bytes::{BufMut, Bytes, BytesMut};

    /// Encode data as a pkt-line
    pub fn encode(data: &[u8]) -> Bytes {
        let len = data.len() + 4;
        let mut result = BytesMut::with_capacity(len);
        result.put_slice(format!("{:04x}", len).as_bytes());
        result.put_slice(data);
        result.freeze()
    }

    /// Encode a flush packet (0000)
    pub fn flush() -> Bytes {
        Bytes::from_static(b"0000")
    }

    /// Encode a delimiter packet (0001)
    #[allow(dead_code)]
    pub fn delim() -> Bytes {
        Bytes::from_static(b"0001")
    }

    /// Parse a pkt-line from data, returns (line_data, bytes_consumed)
    pub fn parse(data: &[u8]) -> Option<(Option<Bytes>, usize)> {
        if data.len() < 4 {
            return None;
        }

        let len_str = std::str::from_utf8(&data[0..4]).ok()?;
        let len = usize::from_str_radix(len_str, 16).ok()?;

        if len == 0 {
            // Flush packet
            return Some((None, 4));
        }

        if len < 4 || data.len() < len {
            return None;
        }

        let content = Bytes::copy_from_slice(&data[4..len]);
        Some((Some(content), len))
    }

    /// Parse all pkt-lines from data
    pub fn parse_all(mut data: &[u8]) -> Vec<Bytes> {
        let mut lines = Vec::new();

        while !data.is_empty() {
            match parse(data) {
                Some((Some(line), consumed)) => {
                    lines.push(line);
                    data = &data[consumed..];
                }
                Some((None, consumed)) => {
                    data = &data[consumed..];
                }
                None => break,
            }
        }

        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pktline_encode() {
        let data = b"hello";
        let encoded = pktline::encode(data);
        assert_eq!(&encoded[..], b"0009hello");
    }

    #[test]
    fn test_pktline_parse() {
        let data = b"0009hello0000";
        let (line, consumed) = pktline::parse(data).unwrap();
        assert_eq!(line.unwrap().as_ref(), b"hello");
        assert_eq!(consumed, 9);
    }

    #[test]
    fn test_zlib_roundtrip() {
        let original = b"Hello, world! This is test data for compression.";

        // Compress
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        // Decompress
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(original.as_slice(), decompressed.as_slice());
    }
}
