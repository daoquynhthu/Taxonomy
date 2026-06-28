# Progress

## F3.11 — Freeze format v1 (Hard Gate G3)
- Status: RED (G3 reopened — BLOCKERs unresolved: ISSUE-0031 G3_REOPENED marker deferred)
- Commit: 62b2d6f (initial freeze); re-freezed at b0826a0; current baseline 4d62478
- Completed: Hard Gate G3 — every required fixture exists (23 files: 11 valid + 10 invalid + 2 meta). Every valid fixture decodes and re-encodes identically (7 CBOR fixtures re-encode identity + 4 non-CBOR fixtures via structured validation). Every invalid fixture rejected with expected structured class (5 CBOR via `DecodeError` variants + 5 non-CBOR via `PhysicalFormatError` variants). All format parsers fuzz-smoke clean (cbor + names + records, 3×50000 runs, 0 crashes/timeouts/panics). Freeze baseline recorded in `tests/vectors/format-v1/freeze-baseline.json` with SHA-256 hashes of all format-defining source files, fixtures, and fuzz targets. G3 reopening enforced by `scripts/check-format-freeze.ps1` (git-authority mode). Non-CBOR physical format validation added in `crates/eternal-format/src/physical.rs` with structured `PhysicalFormatError` enum. All invalid fixture tests now route through validation functions and assert exact error variant. Full combined gate evidence in `gate-report.json` and `fuzz-smoke-report.json`.
- Corrected by:
  - ISSUE-0024: `physical.rs` — magic constants corrected to 8 bytes, `InvalidFormatVersion` error added, `validate_pack_index` uses `DomainHash` per FORMAT §16.5. (6d0a0c0)
  - ISSUE-0025: `generate-gate-report.ps1` — G3 script guards changed from `if (Test-Path) { run }` to `if (-not (Test-Path)) { exit 1 }`, fail-closed on missing scripts. (6867b9b)
  - ISSUE-0023: `freeze-baseline.json` `frozen_commit` set to `62b2d6f`; `check-format-freeze.ps1` rewritten to use `git diff --quiet <frozen_commit> -- <path>`. Plan-ledger G3_REOPENED marker check deferred. (0f199fb)
  - ISSUE-0026: `fuzz-smoke.ps1` corpus seeding made deterministic (wipes corpus dir before re-seeding). (b0826a0)
- Tests: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features` (592 pass, 0 fail, 0 ignored); `cargo test --doc --workspace --all-features`; `scripts/check-deps.ps1`; `scripts/check-specs.ps1`; `scripts/check-fixtures.ps1`; `scripts/check-format-freeze.ps1` (exits 1 — G3 reopened); `scripts/check-plan-ledger.ps1`; `scripts/fuzz-smoke.ps1` (cbor 63MB + names 54MB + records 59MB peak RSS, all clean, records corpus = 415 files)
- Evidence: `gate-report.json` (full Hard Gate G3 artifact per PLAN.md §4.3 including fuzz smoke); `fuzz-smoke-report.json` (3 targets, 150k total runs, 0 crashes)
- Follow-up: Fix remaining F3 BLOCKERs, implement G3_REOPENED plan-ledger marker, then re-freeze G3 with new frozen_commit

## F3.10 — Fuzz all record decoders

- Status: GREEN
- Commit: 2d5aeec (audit-fix: `fuzz-smoke.ps1` fail-closed on missing nightly/cargo-fuzz; auto-seed records corpus from `tests/vectors/format-v1`; invoke decoders on arbitrary `Value` not only `Map`)
- Completed: Added `fuzz/targets/records.rs` fuzz target exercising `SignedRecord::decode()` + 25 `TryFrom<Value>` payload decoders (F3.2–F3.7) under `FormatLimits`. Decoders invoked on every decoded `Value` variant (not only `Map`), exercising both successful schema paths and `rejects_not_a_map` rejection paths. `fuzz-smoke.ps1` now fails (exit 1) when nightly or cargo-fuzz is missing, and auto-seeds the records corpus from committed `tests/vectors/format-v1` fixtures (256 files) before running. 50000 runs, 57MB RSS, 0 crashes/timeouts/panics. Registered in `fuzz/Cargo.toml` and `scripts/fuzz-smoke.ps1`.
- Tests: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features` (592 pass); `scripts/fuzz-smoke.ps1` (cbor + names + records: 3×50000 runs, all clean, records corpus = 256 seed files)
- Gate: standard task gate + fuzz-smoke — all pass
- Corrected: ISSUE-0026 (fuzz corpus reproducibility) — `fuzz-smoke.ps1` now wipes `fuzz/corpus/records/` before re-seeding from fixtures, making corpus count deterministic per checkout. (b0826a0)
- Follow-up: F3.11

## F3.9 — Complete format-v1 fixtures

- Status: GREEN
- Commit: 6272ad8 (audit fix: reencode identity for all 7 valid CBOR fixtures, full StoreManifest/SignedRecord decode, CRC32C recompute, pack domain hash, index structural validation + invalid fixture rejection coverage)
- Completed: Generated 7 missing valid binary fixtures from FORMAT.md §21 golden vectors (canonical-cbor, ref-update-payload, ref-update-envelope, content-manifest, repo-commit-payload, encoded-chunk, encrypted-chunk-ciphertext) and 10 invalid/corrupted fixture variants. All 22 fixtures registered in manifest.json with SHA-256 checksums. Added 20 F3.9 fixture consumption tests: decode/re-encode byte identity for every valid CBOR fixture (RefUpdatePayload, ContentManifest, RepoCommit, EncodedChunk, StoreManifest); full SignedRecord envelope decode with all 4 field checks; segment header CRC32C recompute against FORMAT.md §21.10 golden value; pack trailer DomainHash verification per FORMAT.md §15; index length/fanout/structure per FORMAT.md §16 plus checksum golden match; invalid fixture rejection at the appropriate layer (CRC mismatch, domain hash mismatch, zeroed checksum, truncated data). Generator at `scripts/gen-format-v1-fixtures.ps1`.
- Tests: 592 unit + 1 integration (`cargo test --workspace --all-features`); 20 F3.9 tests (up from 17): added reencode identity to 5 payload tests, full StoreManifest + StoreManifestId golden match, full SignedRecord decode + reencode, CRC32C recompute for valid + invalid segment headers, pack DomainHash recompute, index structural + golden checksum, invalid trailer/checksum/truncated rejection. `crc32c` dev-dependency added.
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `scripts/check-fixtures` — all pass
- Follow-up: F3.10

## F3.8 — Implement record registry

- Status: GREEN
- Commit: 78618aa (ISSUE-0020 fixes: SELF)
- Completed: `RecordClass`, `RecordIdRule` (`CborDomainHash`/`SMTLeafConcat`/`SMTInternalConcat`), `RecordFileKind` (`FrameRecord`/`StandalonePayload`), `NonFrameFileKind` (`StoreManifest`/`CurrentPointer`/`RefPointer`); `RecordTypeInfo` with `id_rule` and `file_kind`; `RECORD_TYPES` table for all 11 frame codes (1..=11) with tags per FORMAT.md §5.3; `NON_FRAME_RECORD_TYPES` with all three non-frame kinds (StoreManifest + CBOR tag, CURRENT pointer with no ID rule, ref pointer with no ID rule). `is_non_frame_file()`, `lookup_non_frame()`, `lookup_record_type()` public APIs.
- Tests: 572 unit + 1 integration (`cargo test --workspace --all-features`); 16 F3.8 tests — 8 original + 8 audit fix: `record_id_rule_cbor_domain_hash`, `record_id_rule_smt_leaf`, `record_id_rule_smt_internal`, `record_id_rule_tags_match_format`, `all_frame_types_have_frame_file_kind`, `non_frame_files_not_in_frame_registry`, `store_manifest_id_rule`, `pointer_files_have_no_id_rule`.
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features` — all pass
- Follow-up: F3.9

## F3.7 — Implement StoreManifest schemas

- Status: GREEN
- Commit: c88a53d (ISSUE-0019 fixes: 5f83061)
- Completed: SegmentDescriptor (§11.1), PackDescriptor (§11.2), StoreManifestPayload (§11.3) with `new()` constructors, `TryFrom<Value>` decoding, `From<&T> for Value` encoding. `record_id()` returns `StoreManifestId`. ISSUE-0019 fixes: `repository_genesis_id` uses `RepositoryGenesisId` newtype; v1 segment path pattern enforced.
- Tests: 556 unit + 1 integration; 29 F3.7 tests (25 original + 4 v1 path rejection)
- Gate: fmt + clippy + test — all pass
- Follow-up: F3.8

## F3.6 — Implement state and ref payload schemas

- Status: GREEN
- Commit: 242ee9a
- Completed: `ObjectChange` (§9.17) with sorted-unique ObjectId check via `check_changes_sorted_unique()`. `RepoCommitPayload` (§9.18, signed type 9) with parent count ≤64, parent[0] as baseline, sorted `parents[1..]`, sorted-unique changes, CBOR-based `record_id()`, MissingField rejection for fields 2 and 3. `RefUpdatePayload` (§9.19, signed type 10) with sequence ≥1, nullable target/deletion representation, tag constraint enforcement (non-null target, no predecessor, sequence=1), CBOR-based `record_id()`. `TransactionEndPayload` (§9.20, unsigned type 11, segment-only) with `end_frame_offset >= first_frame_offset`, CBOR-based `record_id()`. `record_ids_root()` (§9.21) via `DomainHash("EternalCore:TransactionBatch:v1", concat_record_ids)`. All structs use typed hash_id wrappers (VersionId, RepoCommitId, RefUpdateId, SmtRoot, PolicyId, KeyringId, KeyId) instead of raw `[u8; 32]`. All structs have `TryFrom<Value>` decoding with `reject_unknown_keys()`, `From<&T> for Value` encoding with unsigned integer field keys, and public accessors. New ID type `TransactionEndId` added to `ids.rs`. Type registry (`PhysicalContainer` enum, `type_allowed_container()` function) marks TransactionEnd (type 11) as `Segment`-only; unknown type codes return `None`.
- Tests: 527 unit + 1 integration (`cargo test --workspace --all-features`); 40 F3.6 tests — ObjectChange: field-numbers, roundtrip, rejects-not-a-map, unknown-field, invalid-object-id. RepoCommitPayload: field-numbers, roundtrip, roundtrip-with-parents, rejects-not-a-map, unknown-field, bad-format-version, too-many-parents, unsorted-parents, unsorted-changes, missing-parents, missing-changes, record-id-deterministic. RefUpdatePayload: field-numbers, roundtrip, null-target-deletion, rejects-not-a-map, unknown-field, bad-format-version, zero-sequence, invalid-ref-name, tag-null-target, tag-with-predecessor, tag-wrong-sequence, record-id-deterministic. TransactionEndPayload: field-numbers, roundtrip, rejects-not-a-map, bad-format-version, end-offset-before-first-offset, unknown-field, record-id-deterministic. record_ids_root: empty, one, two, deterministic. Type registry: transaction-end-is-segment-only, unknown-code-returns-none.
- Audit fixes (ISSUE-0018): (1) BLOCKER — all F3.6 struct fields use hash_id newtypes instead of raw `[u8; 32]`; (2) BLOCKER — parent[0] is state baseline, only `parents[1..]` checked sorted; (3) BLOCKER — missing `parents`/`changes` rejected with MissingField instead of defaulting to empty; (4) BLOCKER — tag updates enforce non-null target, no predecessor, sequence=1; (5) HIGH — TransactionEndPayload checks `end_frame_offset >= first_frame_offset`.
- Evidence: All field-number tests confirm keys 0..N encode. CBOR roundtrip byte fidelity. Deletion target encoded as null for RefUpdate with None target. RefUpdatePayload rejects sequence=0. Parents >64 and unsorted parents rejected. Missing parents/changes reject with MissingField. Unsorted ObjectChange entries rejected. Tag with null target/predecessor/wrong-sequence rejected. TransactionEnd with end_offset < first_offset rejected. Empty ref name rejected as InvalidText. Deterministic record_id passes for all three payload types. Empty/single/multi record_ids_root matches direct DomainHash.
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cargo test --doc --workspace --all-features` — all pass
- Follow-up: F3.7 Implement StoreManifest schemas

## F3.5 — Implement SMT payload and proof schemas

- Status: GREEN
- Commit: 58ffa0a (golden fixture: merged determinism + sibling-order tests into one golden fixture test with include_bytes against committed binary fixture)
- Completed: `SMTLeafPayload` (§9.15, record type 7, unsigned semantic ID) with `object_key: ObjectKey`, `version_id: VersionId`; `SMTInternalPayload` (§9.16, record type 8, unsigned semantic ID) with `left_child/right_child: [u8; 32]`; `SMTProof` (§10.6, protocol object) with `root: SmtRoot`, `object_key: ObjectKey`, `version_id: Option<VersionId>`, `siblings: Vec<[u8; 32]>` (exactly 256). All three implement `new()` with format_version=1 validation, `TryFrom<Value>` decoding with `reject_unknown_keys()`, and `From<&T> for Value` encoding with unsigned integer field keys. `SMTLeafPayload::record_id()` returns `SmtLeafId` via `DomainHash("EternalCore:SMTLeaf:v1", object_key || version_id)`. `SMTInternalPayload::record_id()` returns `SmtInternalId` via `DomainHash("EternalCore:SMTInternal:v1", left_child || right_child)`. `SMTProof` rejects malformed siblings count != 256 and wrong sibling byte length.
- New ID types in `ids.rs`: `SmtLeafId`, `SmtInternalId` (hash_id! macro).
- Key addition: `object_key_bit()` helper in `record.rs` extracts a single bit from ObjectKey at given SMT depth (MSB first, per FORMAT.md §10.1).
- Tests: 485 unit + 1 integration (`cargo test --workspace --all-features`); 36 F3.5 tests — 23 payload struct tests + 7 bit-order tests (depth 0/1/7/8/255, known ObjectKey fixture, out-of-range) + 1 golden fixture test (determinism + include_bytes golden comparison + structural invariants: 5 map entries, format_version=1, 256 siblings, sibling[0]=[0x00;32], sibling[255]=[0xFF;32], root=[0x01;32], object_key=[0x02;32], version_id=[0x03;32]) + 5 ISSUE-0017 regression tests (3 canonical_value_from_value map-order, 1 ObjectVersionPayload unsorted metadata, 1 canonical_value_from_value sorted accept).
- Evidence: All field-number tests confirm keys 0..N encode. CBOR roundtrip byte fidelity. Sibling length/count validation. Bit ordering verified at depths 0/1/7/8/255 against known ObjectKey fixture. Golden CBOR bytes (8816 bytes, `tests/fixtures/golden_smt_proof.bin`) verified via `include_bytes!` — deterministic re-encode matches committed fixture exactly. Structural invariants confirmed: CBOR map with 5 entries, format_version=1, 256 siblings in leaf-to-root order.
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cargo test --doc --workspace --all-features` — all pass
- Follow-up: F3.6 Implement state and ref payload schemas

## F3.4 — Implement object payload schemas

- Status: GREEN
- Commit: 3499c75 (fix: `ad57a7b`; regress-fix: SELF)
- Completed: `Relation` (§9.13) and `ObjectVersionPayload` (§9.14, signed type 6) with `new()` constructors validating constraints per FORMAT.md, `From<&T> for Value` map encoding with unsigned integer field keys, and `TryFrom<Value>` decoding with `reject_unknown_keys()`. `check_relations_sorted_unique()` enforces relation ordering by `(target_object_id, relation_type)`. Tombstone invariant: tombstone=true ⇒ content_manifest_id=None, tombstone=false ⇒ content_manifest_id=Some(ContentManifestId). Parent count limited to `ABSOLUTE_MAX_OBJECT_VERSION_PARENTS` (64) with duplicate rejection, and `parents[1..]` checked lexicographically sorted when parents.len() > 2. Metadata stored as `CanonicalValue` (not raw `Value`) with validation via `canonical_value_from_value()` per FORMAT.md §4.5 tagged-array encoding. Relation count capped at `ABSOLUTE_MAX_RELATIONS` (100,000). `record_id()` produces `VersionId` via domain hash `"EternalCore:ObjectVersion:v1"`.
- Key additions in `canonical.rs`: `canonical_value_from_value()` — decodes tagged-array `[discriminant, payload]` to `CanonicalValue`; `value_from_canonical_value()` — encodes back; `From<CanonicalValue> for Value` — direct conversion. Both reusable by future payload schemas needing CanonicalValue validation.
- Tests: 486 unit + 1 integration (`cargo test --workspace --all-features`); 30 F3.4 tests (21 initial + 6 ISSUE-0016 regression + 3 ISSUE-0017 regression: `cv_from_value_rejects_unsorted_map_entries`, `cv_from_value_rejects_duplicate_map_entries`, `cv_from_value_accepts_sorted_map_entries`, `object_version_rejects_unsorted_canonical_metadata_map`).
- Audit fixes:
  - ISSUE-0016: (1) BLOCKER — metadata validated as CanonicalValue tagged-array instead of raw Value; (2) BLOCKER — relation count ≤ 100k enforced; (3) HIGH — unsorted additional parents rejected.
  - ISSUE-0017: (1) BLOCKER — `canonical_value_from_value()` now rejects unsorted `CanonicalValue::Map` entries with `DecodeError::UnsortedMapKey` instead of silently normalizing via BTreeMap; (2) BLOCKER — `object_key_bit()` helper added with MSB-first bit extraction per FORMAT.md §10.1, verified at depths 0/1/7/8/255 including known ObjectKey fixture.
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cargo test --doc --workspace --all-features` — all pass
- Follow-up: F3.5

## F3.3 — Implement content payload schemas

- Status: GREEN
- Commit: 5e1d8f1
- Completed: All 6 content payload types — CodecDescriptor (§8.3), EncryptionDescriptor (§8.4), ChunkingDescriptor (§7.4), ContentManifestChunkEntry (§9.10), EncodedChunkPayload (§9.9, unsigned type 4), ContentManifestPayload (§9.12, unsigned type 5) — with `new()` constructors validating constraints per FORMAT.md, `From<&T> for Value` map encoding with unsigned integer field keys, and `TryFrom<Value>` decoding with `reject_unknown_keys()` in every impl. `compute_content_root()` (§9.11) implements hash-tree construction (ContentLeaf/ContentNode/ContentEmpty domain tags). `EncodedChunkPayload::record_id()` and `ContentManifestPayload::record_id()` produce domain-hash record IDs. ISSUE-0015 fully resolved: (1) ChunkingDescriptor::new() validates all fixed v1 parameters exactly including gear_table_id against normative `FASTCDC_V1_GEAR_TABLE_ID`; `new_v1()` uses the normative constant; (2) CodecDescriptor::try_from reads algorithm first, rejects keys per algorithm; (3) EncodedChunkPayload + ContentManifestChunkEntry use `ChunkId` newtype at public constructor boundary (constructors accept `ChunkId`, not `[u8; 32]`); (4) codec=none + encryption=null enforces encoded_bytes.len() == plaintext_length; (5) ContentManifestChunkEntry rejects zero plaintext_length, ContentManifestPayload uses checked_add for total_size; (6) sort_by → sort_by_key for clippy 1.96.0.
- Tests: 423 unit + 1 integration (`cargo test --workspace --all-features`); 57 new F3.3 tests — roundtrip × 6 (all types), field-number fixture × 6, `rejects_unknown_field` × 6, `rejects_not_a_map` × 3, validation rejection per-type (bad algorithm/version/level/profile/format_version/plaintext_length/encoded_bytes/total_size/content_root), `compute_content_root` (empty/single/multi leaf), `record_id` distinctness × 2, plus 10 ISSUE-0015 regression tests (ChunkingDescriptor rejects wrong min/avg/max/norm/gear_table_id, CodecDescriptor algorithm=0 rejects zstd fields, ChunkEntry rejects zero plaintext_length, EncodedChunk rejects mismatched encoded_bytes for codec=none+null encryption, EncodedChunk accepts matching encoded_bytes with distinct ChunkIds, ChunkingDescriptor new_v1 uses normative gear_table_id). CodecDescriptor: algorithm 0 vs 1 field encoding; EncryptionDescriptor: algorithm=1 only, key_epoch>0, nonce[24], aad_profile=1; ChunkingDescriptor: `new_v1()` defaults; EncodedChunkPayload: plaintext_length 1..8388608, codec none+null encryption roundtrip; ContentManifestPayload: total_size validated vs chunk sum, content_root recomputed.
- Evidence: All field-number tests confirm sorted 0..N encodes. CBOR `From<&T>`→`TryFrom<Value>` roundtrip byte fidelity. Validation rejections at exact boundaries. Content root: empty→ContentEmpty, single leaf matches ContentLeaf domain hash, two leaves produce ContentNode.
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cargo test --doc --workspace --all-features` — all pass
- Follow-up: F3.4 Implement object payload schemas (Relation, ObjectVersionPayload, tombstone field invariants)

## F3.2 — Implement repository authority payload schemas

- Status: GREEN
- Commit: 0d4e4c8 (ISSUE-0022 fixes: b1e291f, 1574b79)
- Completed: All 8 payload structs (RepositoryGenesisPayload, PublicKeyEntry, RefPermissionEntry, PolicyRecordPayload, PasswordKdfDescriptor, KeySlot, WrappedDek, KeyringRecordPayload) with `new()` constructors validating constraints per FORMAT.md §9.1–§9.8 and CRYPTO.md §10.1, `From<&T> for Value` map encoding with unsigned integer field keys, and `TryFrom<Value>` decoding with shared field-extraction helpers. Audit loop: (1) reject_unknown_keys in every TryFrom; (2) field_nullable_bytes returns Err(MissingField) on missing key; (3) RefPattern::new() validates permission patterns; (4) all payload struct fields private with accessors; (5) KeySlotLabel::new() rejects control chars; (6) KeyId recomputation via domain_hash in PublicKeyEntry/RepositoryGenesisPayload; (7) checked usize::try_from replaces as usize; (8) field_int accepts Value::U64 <= i64::MAX (CBOR major type 0); (9) KeySlot::try_from rejects missing password_kdf key (3) instead of treating as None; (10) SignedRecord fields private with accessors, encode() validates payload is map and canonicalizes keys (sort + dedup); (11) KeySlot.wrapped_secret exactly 48 bytes (32-byte ciphertext + 16-byte tag). ISSUE-0022 (BLOCKER, F3.11 audit 2026-06-28): all 14 authority payload ID fields changed from raw `[u8; 32]` to `KeyId`/`PolicyId`/`KeyringId` newtypes per FORMAT.md §3.3 (13 fields in b1e291f, `PublicKeyEntry.key_id` in 1574b79).
- Tests: 366 unit + 1 integration (`cargo test --workspace --all-features`); 18 new regression tests — 7 field_int direct (U64 zero/positive/i64::max/overflow/I64 negative/reject type/reject missing), 2 encode canonicalization (unsorted keys sorted, duplicate keys rejected), 9 CBOR roundtrip across 3 additional payload types (PolicyRecordPayload, RepositoryGenesisPayload, KeyringRecordPayload at created_at_ns = 0/42/-1) — CBOR byte roundtrip (created_at_ns = 0, 42, -1), key_slot_rejects_missing_password_kdf_key, signed_record_encode_rejects_non_map_payload; wrapped_secret negative tests expanded to 0/47/49 bytes.
- Evidence: field-number tests for all 8 types; sorted-unique rejection for all 6 array fields; KeyId mismatch rejected; 3 negative wrapped_secret length tests; CBOR roundtrip catches field_int U64→i64 conversion; encode rejects non-map and duplicate payload keys; KeySlot rejects missing optional field.
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cargo test --doc --workspace --all-features` — all pass
- Follow-up: F3.5 Implement SMT payload and proof schemas

## F3.1 — Implement SignedRecord envelope

- Status: GREEN
- Commit: 0241b86
- Completed: SignedRecord<P> envelope (default P=Value) per FORMAT.md §4.6 / ARCHITECTURE.md §4.3. Payload uses Value::Map with unsigned integer field keys (required by F3.2+ record schemas). encode() checks output against max_metadata_bytes. Decode validates envelope_version=1, record_id=32B, signer_key_id=32B, signature=64B, payload is map.
- Tests: 266 (`cargo test --workspace --all-features`: 265 unit + 1 integration); 13 new tests in record module: roundtrip, re-encode identity, decode roundtrip stability, unsigned integer payload key preservation, 5 malformed-length rejections, non-map payload, wrong version, missing fields, empty input, payload-ID-signature-independence, oversized payload rejection
- Evidence: `record.rs` — `signed_record_encode_decode_roundtrip`, `signed_record_reencodes_identically`, `signed_record_decode_roundtrip_byte_stable`, `signed_record_unsigned_integer_payload_keys_roundtrip`, `signed_record_rejects_wrong_record_id_length`, `signed_record_rejects_wrong_signer_key_id_length`, `signed_record_rejects_wrong_signature_length`, `signed_record_rejects_non_map_payload`, `signed_record_rejects_wrong_version`, `signed_record_rejects_missing_fields`, `signed_record_rejects_empty_input`, `signed_record_payload_id_excludes_signature`, `signed_record_encode_rejects_oversized_payload`
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cargo test --doc --workspace --all-features` — all pass
- Follow-up: F3.2 Repository authority payload schemas

## F2.9 — Freeze format primitives

- Status: GREEN
- Commit: SELF
- Completed: Hard Gate G2. All FORMAT.md §21 primitive vectors match (CBOR golden vector, DomainHash empty-payload vectors, fixture manifest checksums). Encoder output verified byte-stable (deterministic across independent calls and separate encode_canonical_value invocations). Decoder rejects all 16 FORMAT.md §4 non-canonical cases (non-shortest integers, indefinite-length items, floats, tags, undefined, invalid UTF-8, duplicate/unsorted map keys, depth exceeded, oversized strings, unexpected EOF, trailing data) plus non-shortest simple values (false/true/null) and reserved simple values. `eternal-format` dependencies confirmed: serde, serde_json, ciborium, sha2 only — no filesystem, network, policy, or key-store crate.
- Tests: 253 (`cargo test --workspace --all-features`: 252 unit + 1 integration); `cargo test --doc --workspace --all-features`; `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Evidence: `g2_rejects_all_non_canonical_cbor`, `g2_encoder_byte_stability`, `g2_encode_canonical_value_is_deterministic` (canonical.rs); `g2_no_forbidden_dependencies` (tests/g2_dependency_check.rs)
- Follow-up: F3 unlocked.
- Audit: Parallel audit found and fixed 3 issues: unchecked `*node_count += 1` in `decode_cv_inner` replaced with `checked_add` (canonical.rs:1412); missing non-shortest simple-value and reserved-simple rejection assertions added to `g2_rejects_all_non_canonical_cbor`; `g2_no_forbidden_dependencies` rewritten to parse Cargo.toml via `include_str!` with explicit forbidden-crate check (was vacuous).

## F2.8 — Fuzz primitive decoding

- Status: GREEN
- Commit: SELF
- Completed: Fuzz targets `cbor` and `names` under `fuzz/targets/` using `cargo-fuzz` / `libfuzzer-sys`. cbor target exercises both `decode()` and `decode_canonical_value()` with encoded round-trip verification. names target uses strict `std::str::from_utf8` with Display→FromStr round-trip. Script `scripts/fuzz-smoke.ps1` runs both with explicit `-max_len=65536 -timeout=2 -rss_limit_mb=512 -runs=50000` and produces `fuzz-smoke-report.json`. Each target completed 50 000 inputs with zero crashes, zero timeouts, bounded RSS (cbor: 66 MiB, names: 54 MiB).
- Tests: `scripts/fuzz-smoke.ps1`; `scripts/check-plan-ledger.ps1`; `cargo test --workspace --all-features` (249 tests)
- Evidence: cbor: 624 cov, 359 corpus entries; names: 298 cov, 198 corpus entries. plan-ledger.json validates correctly.
- Follow-up: None (GREEN)

## F2.7 — Implement normative limits

- Status: GREEN
- Commit: SELF
- Completed: Full FormatLimits with all 17 FORMAT §20 limits, zero/overflow rejection, two-phase encode (pre-compute exact CBOR size with checked arithmetic → check max_metadata_bytes → allocate Vec::with_capacity → encode), exhaustive 17-field tests.
- Tests: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features` (249 tests)
- Evidence: compute_encoded_size() matches actual encoded length for all CanonicalValue variants including Map. Encode rejects at exact limit boundary (+1 byte). Small strings summing over limit rejected. All zero/overflow/limit tests pass.
- Follow-up: None (GREEN)

## F2.6 — Implement constrained names

- Status: GREEN
- Commit: SELF
- Completed: ObjectId, RefName, RefPattern types in ids.rs with full format validation and NameError enum. DataType (1..256), RelationType (1..256), KeySlotLabel (1..128), CommitMessage (0..1_048_576) added. Longest-prefix specificity comparison. Audit fix: RefPattern changed from pub enum to struct + private RefPatternKind; fields no longer bypassable via direct construction; Display/FromStr updated to use self.kind; matches() takes &RefName; bare ref prefix rejected; validate_simple_text helper for constrained types.
- Tests: `cargo test --workspace --all-features` (195 tests)
- Evidence: ObjectId rejects all invalid forms; RefPattern exact + namespace validation; matches() exact equality + prefix matching; specificity() ordering correct; bare `refs/heads/` rejected; all constrained types enforce bounds.
- Follow-up: None (GREEN)

## F2.5 — Implement CanonicalValue tagged union

- Status: GREEN
- Commit: eaa52bc
- Completed: CanonicalValue enum (Null/Bool/I64/U64/Text/Bytes/Array/Map) with FORMAT.md §4.5 tagged-array encoder and decoder. TryFrom<serde_json::Value> with float rejection. JsonParser deleted, replaced with serde_json::Deserializer + custom Visitor. Integer type unified (v ≤ i64::MAX → I64). TrailingData reachable. Depth, node count, NUL rejection, string length limit enforced. G1 CI artifact verified (run 28212653235, 224 pass 0 fail 0 ignored).
- Tests: `cargo test --workspace --all-features` (224 tests)
- Evidence: 224 tests pass. Two JSON entry points produce identical CanonicalValue and identical CBOR bytes. All audit findings addressed. CI artifact verified on GitHub.
- Follow-up: None (GREEN)

## F2.4 — Implement bounded deterministic CBOR decoder

- Status: GREEN
- Commit: SELF
- Completed: CanonicalDecoder with depth-bounded recursive descent, checked allocation, and rejection of all non-canonical forms. Value enum with reencode(). Audit fix: all unchecked `as usize` casts replaced with `usize_from_u64()` helper returning ValueTooLarge on overflow.
- Tests: `cargo test --workspace --all-features` (195 tests)
- Evidence: Golden vector re-encodes identically; rejects non-shortest integers, indefinite items, floats, tag, undefined, invalid UTF-8, duplicate/unsorted map keys, depth exceeded, oversized string, trailing data.
- Follow-up: None (GREEN)

## F2.3 — Implement deterministic CBOR encoder

- Status: GREEN
- Commit: SELF
- Completed: CanonicalEncoder with shortest integer/string-length encoding, CanonicalSortedMap helper. Audit fix: CanonicalSortedMap made pub(crate); insert_u64 made pub(crate); finish() returns Result<(), CanonicalEncodeError> with duplicate-key detection; stringly-typed error replaced with structured CanonicalEncodeError enum.
- Tests: `cargo test --workspace --all-features` (195 tests)
- Evidence: Golden vector match; shortest u64/i64 at every boundary; empty/24-byte string length encoding; map key sorting; duplicate keys rejected; determinism.
- Follow-up: None (GREEN)

## F2.2 — Implement DomainHash

- Status: GREEN
- Commit: SELF
- Completed: domain_hash(tag, payload) implementing exact length-prefixed SHA-256 construction from FORMAT.md §5.1 using u16::to_le_bytes() and u64::to_le_bytes(). Audit fix: returns Result<[u8;32], DomainHashError> instead of infallible; tags exceeding u16::MAX rejected with TagTooLong error; Display + Error impls for DomainHashError.
- Tests: `cargo test --workspace --all-features` (195 tests)
- Evidence: 13 empty-payload domain vectors match FORMAT.md §21.2 byte-for-byte; long tag (65535) succeeds; 65536-byte tag rejected; large payload handled.
- Follow-up: None (GREEN)

## F2.1 — Implement primitive fixed-width types

- Status: GREEN
- Commit: SELF
- Completed: Private-field wrappers for UUID (16 bytes), 14 hash-id types (32 bytes each), Signature (64 bytes), PublicKey (32 bytes), Timestamp (i64), and BoundedLength (u64 with max bound). All hash IDs via hash_id! macro. Audit fix: BoundedLength::new_unchecked changed from pub to pub(crate) to prevent bypass of max bound.
- Tests: `cargo test --workspace --all-features` (195 tests)
- Evidence: Round-trip bytes and display/parse; malformed length rejection; bound rejection; distinct-type compile check; no external access to unchecked construction.
- Follow-up: None (GREEN)

## P1.6 — Freeze workspace baseline

- Status: GREEN
- Commit: eaa52bc
- Completed: G1 hard gate passes locally and in CI. generate-gate-report.ps1 produces machine-readable artifact with all PLAN.md §4.3 fields. CI artifact verified on GitHub (run 28212653235): 9 steps exit 0, 224 test pass 0 fail 0 ignored, fixture checksum non-null.
- Tests: Full G1 gate via CI: `cargo fmt --all -- --check`; `cargo clippy -D warnings`; `cargo check --all-targets`; `cargo test --workspace` (224 pass); `cargo test --doc`; `scripts/check-deps.ps1`; `scripts/check-specs.ps1`; `scripts/check-fixtures.ps1`; `scripts/check-plan-ledger.ps1`
- Evidence: https://github.com/daoquynhthu/Taxonomy/actions/runs/28212653235 — gate-report artifact contains commit eaa52bc, rustc 1.96.0, Linux x86_64, passed=224 failed=0 ignored=0, fixture checksum 9b133f...
- Follow-up: None (GREEN)

## P0/P1 — post-audit fixes

- Status: GREEN
- Commit: SELF
- Completed: Audit revealed 5 gaps — fixtures not in tests/vectors/format-v1/; G0 command path mismatch; missing TempRepo helper; missing crash-failpoints CI job; check-deps untested. All fixed and verified.
- Tests: Full G0 gate + G1 gate + check-deps edge-failure test
- Evidence: All gates pass; check-deps correctly returns non-zero on bad edge

## P1.5 — Establish CI jobs

- Status: GREEN
- Commit: SELF
- Completed: GitHub Actions workflows for PR checks (lint, test, spec-checks, dep-check) and scheduled jobs (fuzz, cross-platform, benchmarks)
- Tests: `.github/workflows/ci.yml`; `.github/workflows/scheduled.yml`
- Evidence: Jobs defined for Linux stable, PWsh spec/fixture/dep checks

## P1.4 — Establish shared test support

- Status: GREEN
- Commit: SELF
- Completed: eternal-format/src/testing.rs with fixture loading, SHA-256 helpers, byte mutation; smoke test loads and checksum-verifies all fixtures
- Tests: `cargo test -p eternal-format -- testing::tests::smoke_fixture_checksum`
- Evidence: 1 test passes verifying all 5 fixture file checksums

## P1.3 — Establish lint and formatting policy

- Status: GREEN
- Commit: SELF
- Completed: Workspace lint config (deny warnings, unwrap_used, expect_used, panic); rustfmt.toml; all crates have [lints] workspace = true and #![forbid(unsafe_code)]
- Tests: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Evidence: Both pass

## P1.2 — Enforce dependency direction

- Status: GREEN
- Commit: SELF
- Completed: scripts/check-deps.ps1 validates approved dependency edges; forbidden edges removed (eternal-net → eternal-crypto; eternal-cli → eternal-format/crypto)
- Tests: `powershell -File scripts/check-deps.ps1`
- Evidence: All 6 crates match allowed edges

## P1.1 — Create the workspace skeleton

- Status: GREEN
- Commit: SELF (baseline) + f6f983f (lint/unsafe integration)
- Completed: 6 crate stubs with empty public surface and `#![forbid(unsafe_code)]`
- Tests: `cargo check --workspace`
- Evidence: Workspace compiles

## P0.5 — Freeze Phase 0

- Status: GREEN
- Commit: SELF
- Completed: G0 hard gate passes — specs verified, fixture checksums match, task ledger validated, no conflicts
- Tests: `powershell -File scripts/check-specs.ps1`; `powershell -File scripts/check-fixtures.ps1`; `powershell -File scripts/check-plan-ledger.ps1`
- Evidence: All three scripts exit 0
- Follow-up: begin P1 workspace and CI baseline

## P0.4 — Create the task ledger

- Status: GREEN
- Commit: SELF
- Completed: Machine-readable task ledger in scripts/plan-ledger.json with all 147 tasks; validation script rejects GREEN tasks with RED dependencies
- Tests: `powershell -File scripts/check-plan-ledger.ps1`
- Evidence: Script validates dependency consistency, cycle-freedom, and 4 GREEN / 144 RED tasks

## P0.3 — Create specification reference checks

- Status: GREEN
- Commit: SELF
- Completed: scripts/check-specs.ps1 verifies required docs, major headings, fixture paths, and absence of obsolete terms
- Tests: `powershell -File scripts/check-specs.ps1`
- Evidence: 8 documents, 13 headings, 6 fixtures, and 4 obsolete-term patterns pass

## P0.2 — Install format fixtures

- Status: GREEN
- Commit: SELF
- Completed: Binary fixtures verified against tests/vectors/manifest.json; all SHA-256 match; no fixture is dynamically generated
- Tests: `powershell -File scripts/check-fixtures.ps1`
- Evidence: 5 fixture files match length and checksum

## P0.1 — Install the authoritative document set

- Status: GREEN
- Commit: SELF
- Completed: All 6 specification documents + PLAN.md + Agent.md installed under docs/; obsolete copies marked non-authoritative; internal references resolve
- Evidence: check-specs verifies all docs and headings

## P0.0 — baseline workspace skeleton

- Status: GREEN
- Commit: SELF
- Completed: Commit empty crate stubs, workspace config, specification documents, and prototype archive as baseline
- Tests: `cargo check --workspace`
- Evidence: workspace compiles with 6 crates, `#![forbid(unsafe_code)]` enforced
- Follow-up: begin Phase P0 specification and repository control tasks
