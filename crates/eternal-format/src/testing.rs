#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_test_module,
    dead_code
)]

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

pub fn vectors_dir() -> PathBuf {
    let mut path = workspace_root();
    path.push("tests");
    path.push("vectors");
    path.push("format-v1");
    path
}

pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = {
        let mut p = vectors_dir();
        p.push(name);
        p
    };
    fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture {name} not found at {}: {e}", path.display()))
}

pub fn fixture_string(name: &str) -> String {
    let path = {
        let mut p = vectors_dir();
        p.push(name);
        p
    };
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {name} not found at {}: {e}", path.display()))
}

pub fn manifest_json() -> serde_json::Value {
    let text = fixture_string("manifest.json");
    serde_json::from_str(&text).expect("manifest.json is valid JSON")
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

pub fn mutate_byte(data: &mut [u8]) {
    if !data.is_empty() {
        data[0] = data[0].wrapping_add(1);
    }
}

/// Create a temporary directory that is automatically cleaned up on drop.
pub struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    pub fn new(prefix: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("{}-{}", prefix, std::process::id()));
        fs::create_dir_all(&path).expect("create temp repo dir");
        TempRepo { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_fixture_checksum() {
        let manifest = manifest_json();
        let fixtures = manifest["fixtures"].as_array().expect("fixtures array");
        assert!(!fixtures.is_empty(), "at least one fixture");

        for entry in fixtures {
            let filename = entry["filename"].as_str().expect("filename");
            let expected = entry["sha256"].as_str().expect("sha256").to_lowercase();
            let data = fixture_bytes(filename);
            let actual = sha256_hex(&data);
            assert_eq!(actual, expected, "SHA-256 mismatch for {filename}");
        }
    }

    #[test]
    fn temp_repo_creates_and_cleans_up() {
        let repo = TempRepo::new("test-eternal");
        assert!(repo.path().exists());
        let p = repo.path().to_owned();
        drop(repo);
        assert!(!p.exists());
    }
}

// ---------------------------------------------------------------------------
// F3.9 — Complete format-v1 fixtures
// ---------------------------------------------------------------------------

#[cfg(test)]
mod f3_9_tests {
    use crate::canonical::{CanonicalDecoder, DecodeError, Value};
    use crate::limits::FormatLimits;
    use crate::record::{
        ContentManifestPayload, EncodedChunkPayload, RefUpdatePayload, RepoCommitPayload,
    };

    fn fixture(name: &str) -> Vec<u8> {
        super::fixture_bytes(name)
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // -------------------------------------------------------------------
    // Valid fixture decode tests
    // -------------------------------------------------------------------

    #[test]
    fn f3_9_canonical_cbor_decodes_and_reencodes() {
        let bytes = fixture("canonical-cbor-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid canonical CBOR");
        assert_eq!(val.reencode(), bytes, "re-encode must match original bytes");
    }

    #[test]
    fn f3_9_ref_update_payload_decodes() {
        let bytes = fixture("ref-update-payload-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload = RefUpdatePayload::try_from(val).expect("valid RefUpdatePayload");
        assert_eq!(payload.format_version(), 1);
        assert_eq!(payload.ref_name().as_str(), "refs/heads/main");
        assert_eq!(payload.sequence(), 1);
        let expected =
            hex_bytes("7dea7eee1b4158006eda482d51e7c70e80e35da194aff957736cf1492c60166d");
        assert_eq!(
            payload.record_id().unwrap().as_bytes().as_slice(),
            expected.as_slice(),
            "RefUpdateId must match FORMAT.md §21.4"
        );
    }

    #[test]
    fn f3_9_ref_update_envelope_is_5_entry_map() {
        let bytes = fixture("ref-update-envelope-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        match &val {
            Value::Map(pairs) => {
                assert_eq!(pairs.len(), 5);
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 4, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("envelope is not a map"),
        }
    }

    #[test]
    fn f3_9_content_manifest_decodes() {
        let bytes = fixture("content-manifest-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload = ContentManifestPayload::try_from(val).expect("valid ContentManifestPayload");
        assert_eq!(payload.format_version(), 1);
        assert_eq!(payload.total_size(), 3);
        assert_eq!(payload.chunks().len(), 1);
        let expected =
            hex_bytes("82e7a89be4027272587e2be2d62df0660e2fed5e646369e9d29ed74379de9527");
        assert_eq!(
            payload.record_id().unwrap().as_bytes().as_slice(),
            expected.as_slice(),
            "ContentManifestId must match FORMAT.md §21.5"
        );
    }

    #[test]
    fn f3_9_repo_commit_decodes() {
        let bytes = fixture("repo-commit-payload-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload = RepoCommitPayload::try_from(val).expect("valid RepoCommitPayload");
        assert_eq!(payload.format_version(), 1);
        assert_eq!(payload.parents().len(), 0);
        assert_eq!(payload.changes().len(), 1);
        let expected =
            hex_bytes("0d19d99e8640b5e7caf03d2ee64e0fcb609553de1c1e2fbf046028f13e532870");
        assert_eq!(
            payload.record_id().unwrap().as_bytes().as_slice(),
            expected.as_slice(),
            "RepoCommitId must match FORMAT.md §21.7"
        );
    }

    #[test]
    fn f3_9_encoded_chunk_decodes() {
        let bytes = fixture("encoded-chunk-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload = EncodedChunkPayload::try_from(val).expect("valid EncodedChunkPayload");
        assert_eq!(payload.format_version(), 1);
        assert_eq!(payload.plaintext_length(), 3);
        let expected =
            hex_bytes("906b402a5344630ff9de40dcb5eb736564c2b2a6741a4f86cbcf304d3afadde0");
        assert_eq!(
            payload.record_id().unwrap().as_bytes().as_slice(),
            expected.as_slice(),
            "EncodedChunkRecordId must match FORMAT.md §21.9"
        );
    }

    #[test]
    fn f3_9_segment_header_length_and_magic() {
        let bytes = fixture("segment-header-v1.bin");
        assert_eq!(bytes.len(), 62);
        assert_eq!(&bytes[0..4], b"ETSE");
    }

    #[test]
    fn f3_9_pack_magic() {
        let bytes = fixture("pack-v1.pack");
        assert_eq!(&bytes[0..8], b"ETPACK\0\0");
    }

    #[test]
    fn f3_9_pack_index_magic() {
        let bytes = fixture("pack-v1.idx");
        assert_eq!(&bytes[0..4], b"ETID");
    }

    #[test]
    fn f3_9_store_manifest_decodes() {
        let bytes = fixture("store-manifest-v1.cbor");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        match &val {
            Value::Map(pairs) => {
                assert!(!pairs.is_empty());
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 7, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
    }

    // -------------------------------------------------------------------
    // Invalid fixture rejection tests
    // -------------------------------------------------------------------

    #[test]
    fn f3_9_duplicate_key_cbor_rejected() {
        let bytes = fixture("cbor-invalid-duplicate-key.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let err = dec.decode().expect_err("must reject duplicate key");
        assert!(matches!(err, DecodeError::DuplicateMapKey));
    }

    #[test]
    fn f3_9_trailing_garbage_rejected() {
        let bytes = fixture("canonical-cbor-v1-invalid-trailing.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let err = dec.decode().expect_err("must reject trailing data");
        assert!(matches!(err, DecodeError::TrailingData));
    }

    #[test]
    fn f3_9_truncated_cbor_rejected() {
        let bytes = fixture("canonical-cbor-v1-invalid-truncated.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let err = dec.decode().expect_err("must reject truncated CBOR");
        assert!(matches!(err, DecodeError::UnexpectedEof));
    }

    #[test]
    fn f3_9_corrupted_cbor_rejected() {
        let bytes = fixture("store-manifest-v1-invalid-corrupted.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let err = dec.decode().expect_err("must reject corrupted CBOR");
        // 0xFF is major type 7, additional info 31 → treated as indefinite length
        assert!(matches!(err, DecodeError::IndefiniteLengthUnsupported));
    }

    #[test]
    fn f3_9_truncated_store_manifest_rejected() {
        let bytes = fixture("store-manifest-v1-invalid-truncated.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let err = dec.decode().expect_err("must reject truncated CBOR");
        assert!(matches!(err, DecodeError::UnexpectedEof));
    }

    #[test]
    fn f3_9_invalid_magic_detected() {
        let bytes = fixture("segment-header-v1-invalid-magic.bin");
        assert_ne!(&bytes[0..4], b"ETSE");
        assert_eq!(bytes[0], 0x00);
    }

    #[test]
    fn f3_9_invalid_crc_detected() {
        let bytes = fixture("segment-header-v1-invalid-crc.bin");
        let valid_crc = [0x61, 0x8b, 0xfc, 0xc3];
        assert_ne!(&bytes[58..62], &valid_crc);
    }
}
