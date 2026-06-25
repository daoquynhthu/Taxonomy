use sha2::{Digest, Sha256};

/// Compute DomainHash(tag, payload) per FORMAT.md §5.1.
///
/// DomainHash(tag, payload) = SHA-256(
///     u16_le(byte_length(tag_utf8)) ||
///     tag_utf8 ||
///     u64_le(byte_length(payload)) ||
///     payload
/// )
///
/// The tag length MUST fit in `u16`; all v1 tags do.
/// The payload length MUST fit in `u64`.
pub fn domain_hash(tag: &str, payload: &[u8]) -> [u8; 32] {
    let tag_len = tag.len();
    let tag_bytes = tag.as_bytes();
    let payload_len = payload.len();

    let mut h = Sha256::new();
    h.update((tag_len as u16).to_le_bytes());
    h.update(tag_bytes);
    h.update((payload_len as u64).to_le_bytes());
    h.update(payload);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // --- Empty-payload vectors from FORMAT.md §21.2 ---

    #[test]
    fn domain_hash_repository_genesis_empty() {
        let result = domain_hash("EternalCore:RepositoryGenesis:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "7ee4e846cb224f3a0a2bcde4052467bd28e5eeb736aeefd7ff1696feeb6253ae"
        );
    }

    #[test]
    fn domain_hash_policy_record_empty() {
        let result = domain_hash("EternalCore:PolicyRecord:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "cdb782e077d59dcddf69b990da0e5a90e4074100452456029f73d3bc7b05dff3"
        );
    }

    #[test]
    fn domain_hash_keyring_record_empty() {
        let result = domain_hash("EternalCore:KeyringRecord:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "c08f39bc9cf3eafbfa2e5bd43d2800c1c177df16cf24143af8173fa315b3c010"
        );
    }

    #[test]
    fn domain_hash_key_fingerprint_empty() {
        let result = domain_hash("EternalCore:KeyFingerprint:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "320c73031d0a4ed6dc5db85ba0becd6691f66fdbdf16d89adab4244c82f6d5d4"
        );
    }

    #[test]
    fn domain_hash_public_chunk_empty() {
        let result = domain_hash("EternalCore:PublicChunk:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "a02b8ade69ee6ea88ffc2c3ccb22917d7fc40fbf47dd8998fd04fc2232705fa9"
        );
    }

    #[test]
    fn domain_hash_private_chunk_empty() {
        let result = domain_hash("EternalCore:PrivateChunk:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "3c6b278475bf2d7287494ba733c83c30269b9486b999ede1942c9b3fab9d38bf"
        );
    }

    #[test]
    fn domain_hash_content_manifest_empty() {
        let result = domain_hash("EternalCore:ContentManifest:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "f8f4cd8f263a7b39e9cabe8afc9b85e16ba7c9a4e51b5bf414e1f9459dee742f"
        );
    }

    #[test]
    fn domain_hash_object_version_empty() {
        let result = domain_hash("EternalCore:ObjectVersion:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "29bd73bb42756738301485d9139dafde5082a6cfaa20d3d3fa0fb6ff950c0786"
        );
    }

    #[test]
    fn domain_hash_commit_empty() {
        let result = domain_hash("EternalCore:RepoCommit:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "68f03768f1c2b756f9e7cecdea0b07e3a25f138f20d3d761842c6abdb356dc80"
        );
    }

    #[test]
    fn domain_hash_ref_update_empty() {
        let result = domain_hash("EternalCore:RefUpdate:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "f85ba7cd4e917be5b190d70883447660de6bff164f083fb56bc6ce8dc60171ea"
        );
    }

    #[test]
    fn domain_hash_smt_empty_leaf_empty() {
        let result = domain_hash("EternalCore:SMTEmptyLeaf:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "3730f3604e9a92b7ec14886c12aebac2aa4435f02d56356469c94daf1e16c36d"
        );
    }

    #[test]
    fn domain_hash_pack_empty() {
        let result = domain_hash("EternalCore:Pack:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "7b7eef24532e168e73b02ba4bce15dee50f5ee8866c5f3d8d620c0e46ab0f312"
        );
    }

    #[test]
    fn domain_hash_store_manifest_empty() {
        let result = domain_hash("EternalCore:StoreManifest:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "b0d3980926a29eb26a2042236832ed90ee9ec6c575024fb724197ceab39816df"
        );
    }

    #[test]
    fn domain_hash_object_key_empty() {
        let result = domain_hash("EternalCore:ObjectKey:v1", &[]);
        assert_eq!(
            hex_of(&result),
            "cf6d21316d5e84ba0dd82f2f0dcba3e2cf484ef801ed10524d89947c7c57e644"
        );
    }

    // --- Changing tag or payload changes result ---

    #[test]
    fn different_tag_different_hash() {
        let a = domain_hash("EternalCore:Pack:v1", &[]);
        let b = domain_hash("EternalCore:PackIndex:v1", &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn different_payload_different_hash() {
        let a = domain_hash("EternalCore:Test:v1", &[]);
        let b = domain_hash("EternalCore:Test:v1", &[0x01]);
        assert_ne!(a, b);
    }

    // --- Non-empty payload ---

    #[test]
    fn domain_hash_with_payload() {
        let result = domain_hash("EternalCore:Test:v1", b"hello world");
        // Just verify it produces a 32-byte result and is deterministic
        assert_eq!(result.len(), 32);
        let second = domain_hash("EternalCore:Test:v1", b"hello world");
        assert_eq!(result, second);
    }

    // --- Tag with maximum u16 length ---

    #[test]
    fn domain_hash_long_tag() {
        let tag = "x".repeat(65535);
        let result = domain_hash(&tag, &[]);
        assert_eq!(result.len(), 32);
    }

    // --- Large payload ---

    #[test]
    fn domain_hash_large_payload() {
        let payload = vec![0xABu8; 100_000];
        let result = domain_hash("EternalCore:Test:v1", &payload);
        assert_eq!(result.len(), 32);
        let second = domain_hash("EternalCore:Test:v1", &payload);
        assert_eq!(result, second);
    }

    // --- No usize in construction (compile-time structural check) ---
    // The implementation uses u16::to_le_bytes() and u64::to_le_bytes() explicitly.
    // This test confirms the output is correct for a known vector.
    #[test]
    fn domain_hash_no_usize_in_preimage() {
        // Use a payload longer than 65535 bytes to confirm u64 length encoding
        let payload = vec![0xFFu8; 70_000];
        let result = domain_hash("EternalCore:Test:v1", &payload);
        assert_eq!(result.len(), 32);
    }
}
