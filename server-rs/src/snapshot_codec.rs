//! Snapshot field codec (backend/src/snapshots/snapshotCodec.ts):
//! `br1:` + base64(brotli(utf8)), used only when it is shorter than the raw value.

use std::io::{Read, Write};

use base64::{engine::general_purpose::STANDARD, Engine};

pub const PREFIX: &str = "br1:";
const QUALITY: u32 = 5;
const MAX_DECOMPRESSED_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError;

/// Node `encodeSnapshotField`.
pub fn encode(value: &str) -> String {
    if value.is_empty() || value.starts_with(PREFIX) || value.len() > MAX_DECOMPRESSED_BYTES {
        return value.to_string();
    }
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, QUALITY, 22);
        if writer.write_all(value.as_bytes()).is_err() {
            return value.to_string();
        }
    }
    let encoded = format!("{PREFIX}{}", STANDARD.encode(compressed));
    if encoded.len() < value.len() {
        encoded
    } else {
        value.to_string()
    }
}

/// Node `decodeSnapshotField`: raw values pass through.
pub fn decode(value: &str) -> Result<String, DecodeError> {
    let Some(payload) = value.strip_prefix(PREFIX) else {
        return Ok(value.to_string());
    };
    let compressed = STANDARD.decode(payload).map_err(|_| DecodeError)?;
    let mut out = Vec::new();
    brotli::Decompressor::new(compressed.as_slice(), 4096)
        .take(MAX_DECOMPRESSED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| DecodeError)?;
    if out.len() > MAX_DECOMPRESSED_BYTES {
        return Err(DecodeError);
    }
    String::from_utf8(out).map_err(|_| DecodeError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn decodes_node_encoded_field() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/snapshot-node.json")).unwrap();
        let encoded = fixture["encoded"].as_str().unwrap();
        assert!(encoded.starts_with(PREFIX));
        assert_eq!(decode(encoded).unwrap(), fixture["plain"].as_str().unwrap());
    }

    #[test]
    fn round_trips_and_compresses_large_values() {
        let value = "[{\"type\":\"rectangle\"}]".repeat(200);
        let encoded = encode(&value);
        assert!(encoded.starts_with(PREFIX));
        assert!(encoded.len() < value.len());
        assert_eq!(decode(&encoded).unwrap(), value);
    }

    #[test]
    fn keeps_small_and_already_encoded_values_raw() {
        assert_eq!(encode("{}"), "{}");
        assert_eq!(encode(""), "");
        assert_eq!(encode("br1:abc"), "br1:abc");
        assert_eq!(decode("{}").unwrap(), "{}");
        assert_eq!(decode("").unwrap(), "");
    }

    #[test]
    fn corrupt_payload_is_an_error() {
        assert_eq!(decode("br1:not-base64!"), Err(DecodeError));
        assert_eq!(decode("br1:aGVsbG8="), Err(DecodeError));
    }
}
