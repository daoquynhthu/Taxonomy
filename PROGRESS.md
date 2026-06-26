# Progress

## F3.2 — Implement repository authority payload schemas

- Status: GREEN
- Commit: SELF
- Completed: All 8 payload structs (RepositoryGenesisPayload, PublicKeyEntry, RefPermissionEntry, PolicyRecordPayload, PasswordKdfDescriptor, KeySlot, WrappedDek, KeyringRecordPayload) with `new()` constructors validating constraints per FORMAT.md §9.1–§9.8, `From<&T> for Value` map encoding with unsigned integer field keys, and `TryFrom<Value>` decoding with shared field-extraction helpers. PolicyRecordPayload validates 5 sorted-unique array types (introduced_keys, administrators, writers, per_ref_permissions, tag_creators, revoked_keys). KeySlot validates conditional slot_kind requirements (password_kdf for kind 1, recipient_key_id/ephemeral_public_key for kinds 2/3) and wrap_algorithm=1. WrappedDek validates nonzero key_epoch, non-empty slots sorted by slot_id. KeyringRecordPayload validates sorted content_id_key_slots, sorted dek_slots, sorted unique retired_key_epochs.
- Tests: 330 unit + 1 integration (`cargo test --workspace --all-features`); 89 new tests in record module — 64 F3.2-specific (roundtrip × 8, field-number fixture × 8, validation/rejection × 40+, sorted-unique × 8) + 25 existing SignedRecord tests
- Evidence: field-number fixture tests prove each field appears at the correct CBOR unsigned-integer key for all 8 types; sorted-unique rejection tests for all 6 array-type fields (writers, administrators, tag_creators, revoked_keys, introduced_keys, per_ref_permissions, key_slots, dek_slots, retired_key_epochs); conditional KeySlot constraint tests (password_without_kdf, password_with_recipient, recipient_without_key, recipient_without_ephemeral).
- Gate: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cargo test --doc --workspace --all-features` — all pass
- Follow-up: F3.3 Record-layer encode/decode

## F3.1 — Implement SignedRecord envelope

- Status: GREEN
- Commit: SELF
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
