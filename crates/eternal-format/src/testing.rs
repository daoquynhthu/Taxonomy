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
    use crate::canonical::{CanonicalDecoder, DecodeError};
    use crate::domain::domain_hash;
    use crate::limits::FormatLimits;
    use crate::record::{
        ContentManifestPayload, EncodedChunkPayload, RefUpdatePayload, RepoCommitPayload,
        SignedRecord, StoreManifestPayload,
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
    // §22: Every valid CBOR fixture must decode and re-encode identically
    // -------------------------------------------------------------------

    #[test]
    fn f3_9_canonical_cbor_decodes_and_reencodes() {
        let bytes = fixture("canonical-cbor-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid canonical CBOR");
        assert_eq!(val.reencode(), bytes, "re-encode must match original bytes");
    }

    #[test]
    fn f3_9_ref_update_payload_decodes_and_reencodes() {
        let bytes = fixture("ref-update-payload-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload = RefUpdatePayload::try_from(val.clone()).expect("valid RefUpdatePayload");
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
        assert_eq!(val.reencode(), bytes, "RefUpdatePayload re-encode identity");
    }

    #[test]
    fn f3_9_envelope_decodes_and_reencodes() {
        let bytes = fixture("ref-update-envelope-v1.bin");
        let env = SignedRecord::decode(&bytes, &FormatLimits::default())
            .expect("valid SignedRecord envelope");

        // Verify golden field values from FORMAT.md §21.4 / format-v1.json
        let expected_record_id =
            hex_bytes("7dea7eee1b4158006eda482d51e7c70e80e35da194aff957736cf1492c60166d");
        assert_eq!(
            env.record_id().as_bytes().as_slice(),
            expected_record_id.as_slice(),
            "envelope record_id must match RefUpdateId §21.4"
        );
        let expected_signer_key_id =
            hex_bytes("4b03e0e78b0994370a31bae8c31269f6b22f08f45c1f2952fa4002ae16cbd3a9");
        assert_eq!(
            env.signer_key_id().as_bytes().as_slice(),
            expected_signer_key_id.as_slice(),
            "envelope signer_key_id must match key_id from format-v1.json"
        );
        let expected_signature = hex_bytes(
            "b834c21ac47a566b9193c906a43151beac6ea8318c7eb7fe04b2699fd6bc7d59dcb82a392a0a83c33308d049d7dc500be26bd95ce984ef56cdaed042b53fb40e",
        );
        assert_eq!(
            env.signature().as_bytes().as_slice(),
            expected_signature.as_slice(),
            "envelope signature must match ref_sig from format-v1.json"
        );

        let reencoded = env.encode(&FormatLimits::default()).expect("re-encode");
        assert_eq!(reencoded, bytes, "envelope re-encode identity");
    }

    #[test]
    fn f3_9_content_manifest_decodes_and_reencodes() {
        let bytes = fixture("content-manifest-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload =
            ContentManifestPayload::try_from(val.clone()).expect("valid ContentManifestPayload");
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
        assert_eq!(val.reencode(), bytes, "ContentManifest re-encode identity");
    }

    #[test]
    fn f3_9_repo_commit_decodes_and_reencodes() {
        let bytes = fixture("repo-commit-payload-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload = RepoCommitPayload::try_from(val.clone()).expect("valid RepoCommitPayload");
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
        assert_eq!(val.reencode(), bytes, "RepoCommit re-encode identity");
    }

    #[test]
    fn f3_9_encoded_chunk_decodes_and_reencodes() {
        let bytes = fixture("encoded-chunk-v1.bin");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload =
            EncodedChunkPayload::try_from(val.clone()).expect("valid EncodedChunkPayload");
        assert_eq!(payload.format_version(), 1);
        assert_eq!(payload.plaintext_length(), 3);
        let expected =
            hex_bytes("906b402a5344630ff9de40dcb5eb736564c2b2a6741a4f86cbcf304d3afadde0");
        assert_eq!(
            payload.record_id().unwrap().as_bytes().as_slice(),
            expected.as_slice(),
            "EncodedChunkRecordId must match FORMAT.md §21.9"
        );
        assert_eq!(val.reencode(), bytes, "EncodedChunk re-encode identity");
    }

    #[test]
    fn f3_9_store_manifest_decodes_and_reencodes() {
        let bytes = fixture("store-manifest-v1.cbor");
        let mut dec = CanonicalDecoder::from_limits(&bytes, &FormatLimits::default());
        let val = dec.decode().expect("valid CBOR");
        let payload =
            StoreManifestPayload::try_from(val.clone()).expect("valid StoreManifestPayload");
        assert_eq!(payload.format_version(), 1);
        let manifest_id = payload.record_id().expect("StoreManifestId");
        let expected =
            hex_bytes("ade6809438dcfb396d7ab5540ef329478921d77374bf4f7c1ecbf9cd42bf71ca");
        assert_eq!(
            manifest_id.as_bytes().as_slice(),
            expected.as_slice(),
            "StoreManifestId must match FORMAT.md §21.12"
        );
        assert_eq!(val.reencode(), bytes, "StoreManifest re-encode identity");
    }

    // -------------------------------------------------------------------
    // §22: Non-CBOR fixture structural verification
    // -------------------------------------------------------------------

    #[test]
    fn f3_9_segment_header_crc32c() {
        let bytes = fixture("segment-header-v1.bin");
        assert_eq!(bytes.len(), 62);
        assert_eq!(&bytes[0..8], b"ETSEG\0\0\0", "full 8-byte magic");
        let stored_crc = u32::from_le_bytes(bytes[58..62].try_into().unwrap());
        let computed_crc = crc32c::crc32c(&bytes[0..58]);
        assert_eq!(
            computed_crc, stored_crc,
            "header CRC must match recomputed value"
        );
        assert_eq!(
            computed_crc, 0xc3fc8b61,
            "header CRC must match FORMAT.md §21.10 golden value"
        );
    }

    #[test]
    fn f3_9_pack_structure_and_checksum() {
        let bytes = fixture("pack-v1.pack");
        assert_eq!(&bytes[0..8], b"ETPACK\0\0", "pack magic");
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        assert_eq!(version, 1, "pack format version");
        let record_count = u64::from_le_bytes(bytes[26..34].try_into().unwrap());
        assert_eq!(record_count, 1, "record count");

        // Verify trailer DomainHash
        let (body, trailer) = bytes.split_at(bytes.len() - 32);
        let mut zeroed = body.to_vec();
        zeroed.extend_from_slice(&[0u8; 32]);
        let expected = domain_hash("EternalCore:Pack:v1", &zeroed).expect("pack DomainHash");
        assert_eq!(
            trailer, expected,
            "pack checksum must match DomainHash per FORMAT.md §15"
        );
        // Verify against FORMAT.md §21.11 golden value
        let golden = hex_bytes("6790a31c4a14e4e79faed72d0c38b1cdb8ff8234a3698b492164b3a68916ec26");
        assert_eq!(
            trailer,
            golden.as_slice(),
            "pack checksum must match FORMAT.md §21.11 golden value"
        );
    }

    #[test]
    fn f3_9_pack_index_structure_and_checksum() {
        let bytes = fixture("pack-v1.idx");
        assert_eq!(&bytes[0..8], b"ETIDX\0\0\0", "index magic");
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        assert_eq!(version, 1, "index format version");
        let record_count = u64::from_le_bytes(bytes[58..66].try_into().unwrap());
        assert_eq!(record_count, 1, "record count");

        // Verify length: 2146 + 53 * N
        assert_eq!(bytes.len(), 2199, "index total length must be 2146 + 53*N");

        // Verify fanout table structure
        let fanout_first = u64::from_le_bytes(bytes[66..74].try_into().unwrap());
        assert_eq!(fanout_first, 0, "fanout[0] must be 0");
        let fanout_last = u64::from_le_bytes(bytes[66 + 2040..66 + 2048].try_into().unwrap());
        assert_eq!(fanout_last, 1, "fanout[255] must equal record_count");

        // Verify index_checksum matches FORMAT.md §21.11 golden value
        let golden = hex_bytes("3051b321eb8354dc0f11de02a5b6ee3439c0bd00cf0d7100076e88b422727e77");
        assert_eq!(
            &bytes[bytes.len() - 32..],
            golden.as_slice(),
            "index checksum must match FORMAT.md §21.11"
        );
    }

    // -------------------------------------------------------------------
    // §22: Invalid fixtures must fail at the appropriate layer
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
    fn f3_9_segment_header_invalid_crc_rejected() {
        let bytes = fixture("segment-header-v1-invalid-crc.bin");
        let stored_crc = u32::from_le_bytes(bytes[58..62].try_into().unwrap());
        let computed_crc = crc32c::crc32c(&bytes[0..58]);
        assert_ne!(
            computed_crc, stored_crc,
            "invalid CRC must not match recomputed value"
        );
    }

    #[test]
    fn f3_9_pack_invalid_trailer_rejected() {
        let bytes = fixture("pack-v1-invalid-trailer.bin");
        let (body, _stored_trailer) = bytes.split_at(bytes.len() - 32);
        let mut zeroed = body.to_vec();
        zeroed.extend_from_slice(&[0u8; 32]);
        let expected = domain_hash("EternalCore:Pack:v1", &zeroed).expect("pack DomainHash");
        assert_ne!(
            &bytes[bytes.len() - 32..],
            expected,
            "corrupted trailer must not match DomainHash"
        );
    }

    #[test]
    fn f3_9_pack_index_invalid_checksum_rejected() {
        let bytes = fixture("pack-v1-idx-invalid-checksum.bin");
        let stored = &bytes[bytes.len() - 32..];
        // Must NOT match the golden value from FORMAT.md §21.11
        let golden = hex_bytes("3051b321eb8354dc0f11de02a5b6ee3439c0bd00cf0d7100076e88b422727e77");
        assert_ne!(
            stored,
            golden.as_slice(),
            "zeroed checksum must not match FORMAT.md §21.11 golden value"
        );
        // Verify the stored checksum is indeed all-zero (generator clears last 32 bytes)
        assert_eq!(
            stored,
            &[0u8; 32][..],
            "invalid-checksum fixture must have zeroed index_checksum"
        );
    }

    #[test]
    fn f3_9_pack_index_invalid_truncated_rejected() {
        let bytes = fixture("pack-v1-idx-invalid-truncated.bin");
        // Valid index is 2199 bytes; truncated is 100 bytes shorter
        assert_eq!(
            bytes.len(),
            2199 - 100,
            "truncated index must be 2099 bytes"
        );
        // Verify magic prefix is intact (truncation removes end, not start)
        assert_eq!(
            &bytes[0..4],
            b"ETID",
            "magic prefix must survive truncation"
        );
        // Remaining bytes should still parse as partial index header
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        assert_eq!(version, 1, "version must be readable");
        // Last 32 bytes of truncated fixture are NOT a valid checksum
        let last_32 = &bytes[bytes.len() - 32..];
        let golden = hex_bytes("3051b321eb8354dc0f11de02a5b6ee3439c0bd00cf0d7100076e88b422727e77");
        assert_ne!(
            last_32,
            golden.as_slice(),
            "truncated data must not match golden index_checksum"
        );
    }
}
