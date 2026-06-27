# Issues

## ISSUE-0019 — F3.7 StoreManifestPayload loses RepositoryGenesisId type separation and accepts non-v1 segment paths

- Status: RESOLVED
- Severity: BLOCKER
- Discovered in: F3.7 audit 2026-06-27 (commit c88a53d)
- Affected scope: crates/eternal-format/src/record.rs, docs/FORMAT.md §3.3, §11.1–§11.3, docs/PLAN.md F3.7
- Evidence:
  1. BLOCKER — StoreManifestPayload.repository_genesis_id is stored and exposed as raw `[u8; 32]` even though FORMAT.md defines RepositoryGenesisId as a distinct ID type and FORMAT.md §3.3 forbids silent coercion between ID types. `ids.rs` already defines `RepositoryGenesisId` via `hash_id!`.
  2. HIGH — SegmentDescriptor only validates normalized relative paths, but does not enforce the v1 path form `objects/active/segment-<generation>-<uuid>.seg` per FORMAT.md §11.1, nor consistency with store_generation and segment_id.
  3. PROGRESS.md and scripts/plan-ledger.json mark F3.7 GREEN before these structural issues are closed.
- Violated invariant: FORMAT.md §3.3 — distinct ID types must remain distinct Rust types; FORMAT.md §11.1 — SegmentDescriptor relative_path must match v1 structure.
- Required decision: Use RepositoryGenesisId in StoreManifestPayload constructor, fields, accessors, TryFrom, and From. Enforce SegmentDescriptor v1 path pattern. Update PROGRESS.md and plan-ledger.json only after tests pass.
- Work stopped: F3.7, F3.8 and later tasks.
- Resolution: RESOLVED by commit 5f83061 (RepositoryGenesisId newtype, v1 path pattern enforcement, 4 new tests, 556 tests + fmt + clippy clean). PROGRESS.md and plan-ledger.json updated.

## ISSUE-0018 — F3.6 audit regression: raw [u8; 32] types, missing-field defaulting, no tag constraints

- Status: RESOLVED
- Severity: BLOCKER
- Discovered in: F3.6 audit 2026-06-27 (commit 242ee9a)
- Affected scope: crates/eternal-format/src/record.rs, docs/FORMAT.md §9.17–§9.21, docs/PLAN.md F3.6
- Evidence:
  1. BLOCKER — ObjectChange, RepoCommitPayload, RefUpdatePayload used raw `[u8; 32]` fields where FORMAT.md defines distinct types: VersionId, RepoCommitId, RefUpdateId, SmtRoot, PolicyId, KeyringId, KeyId. All existing hash_id newtypes in `ids.rs` must be used.
  2. BLOCKER — RepoCommitPayload decoded parents[0] treated as a generic sorted entry rather than the state baseline per FORMAT.md §9.18. Parent validation sorted all elements, but parent[0] has no sort requirement.
  3. BLOCKER — RepoCommitPayload `parents` (field 2) and `changes` (field 3) decoded to `vec![]` on missing field instead of returning `PayloadError::MissingField`. FORMAT.md §4.3 requires rejection of missing required array fields.
  4. BLOCKER — RefUpdatePayload for `refs/tags/*` did not enforce non-null target_commit_id, no predecessor, and sequence=1. FORMAT.md §9.19 requires all three invariants.
  5. HIGH — TransactionEndPayload accepted `end_frame_offset < first_frame_offset` instead of requiring `end_frame_offset >= first_frame_offset`.
- Violated invariant: Agent.md §5: "Production library code must not use unwrap, expect" (BLOCKER 1 is a type safety violation); FORMAT.md §4.3 missing-field rejection; FORMAT.md §9.18 parent baseline semantics; FORMAT.md §9.19 tag constraints; FORMAT.md §9.20 offset ordering.
- Required decision: Fix all 4 BLOCKERs and 1 HIGH in F3.6 record.rs. Update tests to use newtype wrappers. Add negative tests for each violation.
- Work stopped: F3.6 (now unblocked after fix)
- Resolution: RESOLVED by commit baca9692 (all 4 BLOCKERs + HIGH fixed; types use hash_id wrappers; parents[0] is baseline; missing fields reject with MissingField; tag constraints enforced; end_frame_offset >= first_frame_offset checked; new tests added: repo_commit_payload_rejects_missing_parents, repo_commit_payload_rejects_missing_changes, ref_update_payload_rejects_tag_null_target, ref_update_payload_rejects_tag_with_predecessor, ref_update_payload_rejects_tag_wrong_sequence, transaction_end_payload_rejects_end_offset_before_first_offset)

## ISSUE-0017 — F3.4/F3.5 audit regression: CanonicalValue map order silently normalized, F3.5 proof fixture evidence missing

- Status: RESOLVED
- Severity: BLOCKER
- Discovered in: F3.4/F3.5 audit 2026-06-27 (commit 58ffa0a)
- Affected scope: crates/eternal-format/src/canonical.rs, crates/eternal-format/src/record.rs, docs/FORMAT.md §4.5, §10.1, §10.6, docs/PLAN.md F3.5
- Evidence:
  1. canonical_value_from_value() accepted CanonicalValue::Map entries in arbitrary order and stored them in BTreeMap, silently normalizing unsorted authoritative metadata instead of rejecting it.
  2. F3.5 lacked bit-order helper (object_key_bit) and deterministic proof CBOR fixture tests.
- Violated invariant: Agent.md §5 rejects non-canonical authoritative encodings; PLAN.md F3.5 Green requires bit order + proof fixture bytes.
- Required decision: Add sorted-key check to canonical_value_from_value() tag-7 decoder; add object_key_bit() helper with MSB-first bit extraction; add proof determinism and sibling-order tests.
- Work stopped: F3.5, F3.6 (now unblocked after fix)
- Resolution: RESOLVED by commit 96161d8 (canonical_value_from_value now rejects unsorted map entries with DecodeError::UnsortedMapKey; 3 canonical_value tests + 1 ObjectVersionPayload test added; object_key_bit() helper with 7 bit-order tests; 2 proof fixture tests; 486 total / fmt+clippy clean). Golden fixture binary (tests/fixtures/golden_smt_proof.bin, 8816 bytes) committed and verified via include_bytes! in smt_proof_golden_fixture test. 485 tests / fmt+clippy clean.

## ISSUE-0015 — F3.3 content payload schemas accept invalid descriptors and lose ChunkId type separation

- Status: RESOLVED
- Severity: BLOCKER
- Discovered in: F3.3 audit 2026-06-26 (commit 5e1d8f1)
- Affected scope: crates/eternal-format/src/record.rs, docs/FORMAT.md §7.4, §8.3, §9.9–§9.12, docs/PLAN.md F3.3
- Evidence:
  1. ChunkingDescriptor validates only algorithm/version but not fixed v1 sizes (minimum_size=1_048_576, average_size=4_194_304, maximum_size=8_388_608, normalization=2) or fixed gear_table_id. Caller can pass arbitrary values via `new()` or via decoder.
  2. CodecDescriptor::try_from calls `reject_unknown_keys(pairs, 3)` which accepts algorithm=0 maps containing zstd-only fields (keys 1 and 2). The level/profile are silently set to None instead of being rejected.
  3. EncodedChunkPayload and ContentManifestChunkEntry store chunk_id as raw `[u8; 32]` instead of `ChunkId`, violating the F3.3 Green requirement that "logical and physical identifiers remain distinct Rust types."
  4. codec=none + encryption=null does not enforce `encoded_bytes.len() == plaintext_length`. FORMAT.md §9.9 specifies encoded_bytes equals raw chunk bytes in this case.
  5. ContentManifestChunkEntry::new accepts plaintext_length=0 (zero-length chunks invalid per FORMAT.md §7.3). ContentManifestPayload::new sums chunk lengths with `u64::Iterator::sum()` (not checked_add; wraps in release).
  6. CI clippy fails on Rust 1.96.0: `clippy::unnecessary_sort_by` on `sort_by(|a,b| ...)` at record.rs:1530.

- Violated invariant: (1) Fixed chunking descriptor must be exactly fixed; (2) codec algorithm 0 schema must reject zstd-only fields; (3) logical ChunkId and physical EncodedChunkRecordId must be distinct Rust types per PLAN.md Green; (4) public no-codec/no-encryption encoded_bytes must equal plaintext_length; (5) chunk entries must reject zero length and total_size must use checked arithmetic; (6) clippy must pass.
- Required fix: (1) ChunkingDescriptor::new() verify all fixed v1 parameters exactly; (2) CodecDescriptor::try_from reject algorithm=0 maps with extraneous keys by checking key count or using an algorithm-dependent `reject_unknown_keys`; (3) use `ChunkId` newtype for chunk_id fields; (4) enforce `encoded_bytes.len() == plaintext_length` when codec=none and encryption=null; (5) reject zero plaintext_length in ContentManifestChunkEntry; use `checked_add` for total_size summation; (6) change `sort_by` to `sort_by_key` at record.rs:1530.
- Work stopped: F3.3, all downstream F3 tasks.
- Resolution: Fixed in commit SELF. All 6 items addressed: (1) ChunkingDescriptor::new() validates all fixed v1 parameters exactly including gear_table_id against normative `FASTCDC_V1_GEAR_TABLE_ID`; `new_v1()` uses the normative constant; (2) CodecDescriptor::try_from reads algorithm first, then rejects keys based on algorithm; (3) EncodedChunkPayload and ContentManifestChunkEntry use ChunkId newtype at public constructor boundary (constructors accept ChunkId, not [u8;32]); (4) codec=none + encryption=null enforces encoded_bytes.len() == plaintext_length; (5) ContentManifestChunkEntry rejects zero plaintext_length, ContentManifestPayload uses checked_add for total_size; (6) sort_by → sort_by_key for clippy 1.96.0. 423 tests pass, fmt + clippy clean.

## ISSUE-0013 — F2.8 fuzz targets incomplete: missing CI job, lossy UTF-8, partial decoder coverage, ledger corruption

- Status: RESOLVED
- Severity: BLOCKER
- Discovered in: F2.8 review 2026-06-26
- Affected scope: fuzz/targets/cbor.rs, fuzz/targets/names.rs, scripts/plan-ledger.json, CI gate
- Evidence: (1) plan-ledger.json written as `null` by ConvertTo-Json with uninitialized variable; (2) no CI job builds or runs fuzz targets; (3) names target uses `String::from_utf8_lossy` instead of strict `std::str::from_utf8`; (4) cbor target only tests `decode_canonical_value`, missing lower-level `decode()` path; (5) no explicit `-max_len`, `-timeout`, `-rss_limit_mb` in fuzz arguments.
- Violated invariant: F2.8 requires "bounded smoke fuzz job completes without panic, timeout, or unbounded allocation" with a reproducible, verifiable gate.
- Required decision: Restore ledger, fix fuzz targets, add fuzz-smoke CI script with explicit resource bounds.
- Work stopped: F2.9
- Resolution: Fixed in commit `8521932`. plan-ledger.json restored from parent commit. cbor target now tests both `decode()` and `decode_canonical_value()` with encode round-trip. names target uses strict `std::str::from_utf8` with Display→FromStr round-trip. fuzz-smoke.ps1 script added with explicit `-max_len=65536 -timeout=2 -rss_limit_mb=512 -runs=50000`. Both targets pass 50 000 runs, zero crashes, bounded memory (≤66 MiB). 249 workspace tests pass, ledger checker passes.

## ISSUE-0012 — F2.7 implementation incomplete: FormatLimits not a complete limits type

- Status: RESOLVED
- Severity: BLOCKER
- Discovered in: F2.7 review 2026-06-26
- Affected scope: crates/eternal-format/src/limits.rs, crates/eternal-format/src/canonical.rs, FORMAT.md §20, F2.7
- Evidence: Three remaining blockers: (1) max_metadata_bytes only applied to JSON input, not CBOR encoded metadata total; (2) ABSOLUTE_MAX_SEGMENT_SIZE is u32::MAX (4_294_967_295) not exact 4 GiB (4_294_967_296); (3) impl_target_segment_size can exceed configured max_segment_size. Default value tests only cover 3 of 17 fields.
- Violated invariant: F2.7 requires "one limits type with the exact format defaults and checked override validation."
- Required decision: Enforce max_metadata_bytes on encoded CBOR length. Fix segment size to exact 4 GiB (u64). Remove impl_target_segment_size from struct. Add exhaustive tests for all 17 fields.
- Work stopped: F2.7, F2.8
- Resolution: Round 3 fix — pre-compute exact CBOR size with checked arithmetic before allocating output buffer. Encode side now two-phase: (1) compute_encoded_size() validates all limits and returns exact byte count; (2) check against max_metadata_bytes; (3) allocate Vec::with_capacity(exact_size) and encode. decode side unchanged (input length checked before parse). Segment size and exhaustive tests unchanged from round 3. Final RESOLVED at commit `SELF`. 249 tests pass (0 fail).

## ISSUE-0011 — Multi-task commit violates Agent.md single-task discipline

- Status: RESOLVED
- Severity: HIGH
- Discovered in: Audit 2026-06-26
- Affected scope: Agent.md, commit 2739a53
- Evidence: Commit 2739a53 titled "F2.5+P1.6: audit fixes..." combines two numbered tasks into one commit. Agent.md §7 requires one numbered task per commit.
- Violated invariant: Agent.md §2.5 / §7 — one reviewable commit per numbered task.
- Required decision: Do not re-write history, but flag as process deviation and enforce single-task commits going forward.
- Work stopped: none
- Resolution: RESOLVED — process deviation recorded. From commit 5b3593b onward, single-task discipline restored (F2.5 only in both 5b3593b and b99af6f).

## ISSUE-0001 — Ledger checker does not verify PLAN.md task completeness

- Status: RESOLVED
- Severity: BLOCKER
- Discovered in: Audit 2026-06-25
- Affected scope: scripts/check-plan-ledger.ps1, plan-ledger.json, P0.4, P0.5, P1.x, F2.x
- Evidence: Script only checks dependency existence and cycles; does not parse PLAN.md to verify every task ID is present in ledger, or that no extra/missing/duplicate IDs exist.
- Violated invariant: P0.4 gate "ledger validation passes" requires complete PLAN.md ↔ ledger alignment.
- Required decision: Expand checker to parse PLAN.md headings and verify exact task ID match.
- Work stopped: P0.4, P0.5, P1.x, F2.x
- Resolution: RESOLVED (checker rewritten to parse PLAN.md headings and verify exact task ID match)

## ISSUE-0002 — G1 lacks machine-readable CI gate artifact

- Status: RESOLVED
- Severity: BLOCKER
- Discovered in: Audit 2026-06-25
- Affected scope: CI workflows, scripts/generate-gate-report.ps1, G1
- Evidence: CI runs commands but produces no gate-report.json with commit SHA, rustc version, exit codes, test counts, fixture manifest checksum, ignored test list.
- Violated invariant: G1 requires verifiable CI evidence.
- Required decision: Add gate-report.json generation to CI and upload as artifact.
- Work stopped: G1, all downstream gates
- Resolution: RESOLVED — CI artifact verified on GitHub run 28212653235 (commit eaa52bc):
   1. All 9 steps exit 0
   2. test_counts: passed=224, failed=0, ignored=0
   3. fixture_checksum: sha256=9b133f154b74ad346cd80fcc59500e18ebead1113d78851854733e92342434ba
   4. artifact uploaded: gate-report.zip (ID 7895510237, 5487 bytes)
   5. Evidence: https://github.com/daoquynhthu/Taxonomy/actions/runs/28212653235

## ISSUE-0003 — DomainHash silently truncates tags longer than u16::MAX

- Status: RESOLVED
- Severity: CRITICAL
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/domain.rs, FORMAT.md §5.1, F2.2
- Evidence: `(tag_len as u16).to_le_bytes()` truncates without check. tag 65535 accepted, 65536 silently produces wrong preimage.
- Violated invariant: Tag length MUST fit in u16.
- Required decision: domain_hash must return Result and reject tag > 65535, payload > u64::MAX.
- Work stopped: F2.2
- Resolution: RESOLVED (domain_hash returns Result, rejects tag > 65535)

## ISSUE-0004 — CanonicalSortedMap can emit duplicate encoded keys

- Status: RESOLVED
- Severity: CRITICAL
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/canonical.rs, FORMAT.md §4, F2.3
- Evidence: `insert_raw` is pub, `finish()` sorts but does not dedup. Authoritative writer can produce illegal duplicate map keys.
- Violated invariant: Encoded CBOR maps must have unique keys.
- Required decision: Make insert_raw pub(crate), finish() return Result, reject duplicate keys after sort.
- Work stopped: F2.3
- Resolution: RESOLVED (finish() returns Result with duplicate-key detection)

## ISSUE-0005 — F2.6 implementation incomplete (missing types + encapsulation holes)

- Status: RESOLVED
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/ids.rs, FORMAT.md §6, F2.6
- Evidence: DataType, RelationType, CommitMessage, KeySlotLabel not implemented. Bare ref prefix `refs/heads/` accepted as valid suffix (empty suffix should be rejected because suffix must follow non-empty ObjectId path rules). RefPattern fields are pub (callers can bypass new()). matches() accepts &str instead of &RefName.
- Violated invariant: All FORMAT.md §6 constrained text types must exist with checked construction.
- Required decision: Add missing types; make RefPattern fields private via struct+inner enum; matches() take &RefName; reject bare prefixes.
- Work stopped: F2.6
- Resolution: RESOLVED (RefPattern changed from pub enum to struct + private RefPatternKind; Display/FromStr updated to use self.kind; DataType, RelationType, CommitMessage, KeySlotLabel added previously)

## ISSUE-0006 — BoundedLength::new_unchecked is pub allowing bypass of max check

- Status: RESOLVED
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/ids.rs, F2.1
- Evidence: `pub const fn new_unchecked(value: u64) -> Self` visible to external callers.
- Violated invariant: BoundedLength must enforce its maximum.
- Required decision: Change to pub(crate).
- Work stopped: F2.1
- Resolution: RESOLVED (new_unchecked changed to pub(crate))

## ISSUE-0007 — CBOR decoder uses unchecked u64→usize casts

- Status: RESOLVED
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/canonical.rs, F2.4
- Evidence: `len as usize` at lines 415, 426, 438, 452 without checked conversion.
- Violated invariant: All untrusted lengths must be checked before allocation/slicing.
- Required decision: Use usize::try_from and return structured error on overflow.
- Work stopped: F2.4
- Resolution: RESOLVED (all as usize casts replaced with usize_from_u64 helper)

## ISSUE-0008 — F2.5 lacks JSON conversion adapter required by GREEN criteria

- Status: RESOLVED
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/canonical.rs, F2.5
- Evidence: No `TryFrom<serde_json::Value> for CanonicalValue` implementation. GREEN criterion "floating JSON input is rejected by conversion adapters" not met.
- Violated invariant: CanonicalValue must provide JSON→CV conversion with float rejection and proper limits.
- Required decision: Implement encode_canonical_value() with depth ≤ 64, nodes ≤ 1,000,000, string ≤ 1,048,576, NUL rejection. TryFrom<serde_json::Value> must also enforce these limits and remove false duplicate-key detection.
- Work stopped: F2.5
- Resolution: RESOLVED — all findings addressed. Commits 5b3593b, b99af6f, 0b95235, eaa52bc. G1 CI artifact verified (run 28212653235). plan-ledger P1.6 + F2.5 promoted to GREEN.

## ISSUE-0009 — PROGRESS.md PENDING commit references are self-referential

- Status: RESOLVED
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: PROGRESS.md
- Evidence: Entries record "Commit: PENDING" then update to commit hash in same commit, creating circular reference. Also duplicate entries per task (original + audit correction), not newest-first.
- Required decision: Replace "Commit: PENDING" pattern with "Commit: SELF". Merge audit corrections into original entries. Sort newest-first.
- Work stopped: none
- Resolution: RESOLVED (all PENDING replaced with SELF; audit corrections merged into original entries; entries sorted newest-first; no duplicates remain)

## ISSUE-0010 — CanonicalSortedMap API completeness: stringly-typed error + public insert_u64

- Status: RESOLVED
- Severity: HIGH
- Discovered in: Code review 2026-06-25
- Affected scope: crates/eternal-format/src/canonical.rs, F2.3
- Evidence: `finish()` returns `Result<(), &'static str>` (stringly-typed, no structured error). `insert_u64` is pub so external callers can inject malformed pre-encoded values. `CanonicalSortedMap` itself is pub despite only being used by future record encoders.
- Violated invariant: PLAN.md prohibits stringly-typed format errors; encoder helpers must not expose raw pre-encoded paths.
- Required decision: Add structured `CanonicalEncodeError`. Make `finish()` return `Result<(), CanonicalEncodeError>`. Make `insert_u64` and `CanonicalSortedMap` pub(crate). Document that F3 record encoders call through controlled field encoding.
- Work stopped: F2.3
- Resolution: RESOLVED (CanonicalSortedMap made pub(crate); insert_u64 made pub(crate); finish() returns Result<(), CanonicalEncodeError>; CanonicalEncodeError enum with DuplicateMapKey variant)
