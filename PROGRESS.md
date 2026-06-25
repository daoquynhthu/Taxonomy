# Progress

## F2.2 — audit correction: DomainHash returns Result

- Status: GREEN
- Commit: SELF
- Completed: domain_hash(tag, payload) now returns Result<[u8; 32], DomainHashError> instead of infallible [u8; 32]. Tags exceeding u16::MAX are rejected with TagTooLong error. New error type DomainHashError with Display and Error impls.
- Tests: `cargo test --workspace --all-features` (151 tests)
- Evidence: All 13 golden vectors still match; long tag (65535) succeeds; 65536-byte tag correctly rejected; large payloads still work.
- Follow-up: F2.3 audit correction (CanonicalSortedMap dedup check)

## F2.4 — audit correction: checked usize conversions in CBOR decoder

- Status: GREEN
- Commit: SELF
- Completed: All unchecked `len as usize` casts in decoder replaced with `self.usize_from_u64()` helper that returns `ValueTooLarge` on overflow. Covers byte/text lengths, array capacity, map count, CanonicalValue array/map capacity. No `as usize` casts remain in canonical.rs.
- Tests: `cargo test --workspace --all-features` (151 tests)
- Evidence: Decoder now rejects lengths exceeding usize::MAX (32-bit safety); all existing tests pass.
- Follow-up: F2.5 audit correction (JSON conversion adapter)

## F2.3 — audit correction: CanonicalSortedMap dedup + insert_raw visibility

- Status: GREEN
- Commit: SELF
- Completed: CanonicalSortedMap::finish() now returns Result<(), &'static str> with duplicate-key detection. insert_raw changed to pub(crate). Fmt check, clippy pass, 151 tests.
- Tests: `cargo test --workspace --all-features` (151 tests)
- Evidence: Duplicate encoded keys are detected and rejected; existing tests pass unchanged.
- Follow-up: F2.4 audit correction (checked usize conversions in decoder)

## F2.1 — audit correction: BoundedLength::new_unchecked visibility

- Status: GREEN
- Commit: 99c3ea5
- Completed: BoundedLength::new_unchecked changed from pub to pub(crate) per audit HIGH 2. Added dead_code allow for future internal use.
- Tests: `cargo test --workspace --all-features` (150 tests)
- Evidence: No external access to unchecked construction; internal future use preserved.
- Follow-up: F2.2 audit correction (DomainHash Result return type)

## F2.6 — Implement constrained names

- Status: GREEN
- Commit: PENDING
- Completed: ObjectId, RefName, RefPattern types in ids.rs with full format validation. NameError enum for all rejection modes. Longest-prefix specificity comparison with deterministic tests.
- Tests: `cargo test --workspace --all-features` (150 tests)
- Evidence: ObjectId rejects empty/too-long/leading-slash/trailing-slash/empty-segment/dot/dotdot/control/invalid-char; RefName rejects invalid-prefix/lock-suffix/double-slash/at-brace/backslash/non-ascii/dotdot/control/too-long; RefPattern exact + namespace validation; matches() exact equality + prefix matching; specificity() ordering exact > longer-prefix > shorter-prefix.
- Follow-up: F2.7 (normative limits)

## F2.5 — Implement CanonicalValue tagged union

- Status: GREEN
- Commit: PENDING
- Completed: CanonicalValue enum (Null/Bool/I64/U64/Text/Bytes/Array/Map) with FORMAT.md §4.5 tagged-array encoder and decoder. Depth/nesting limits enforced.
- Tests: `cargo test --workspace --all-features` (114 tests)
- Evidence: Round-trip for all 8 variants; nested Array/Map round-trip; rejects discriminant out of range, non-array outer, wrong payload types, non-text map key, duplicate/unsorted text keys, float in payload, depth exceeded, node count exceeded, trailing data.
- Follow-up: F2.6 (constrained names)

## F2.4 — Implement bounded deterministic CBOR decoder

- Status: GREEN
- Commit: SELF
- Completed: CanonicalDecoder with depth-bounded recursive descent, checked allocation, and rejection of all non-canonical forms. Value enum with reencode(). All FORMAT.md §4 rejection criteria implemented.
- Tests: `cargo test --workspace --all-features` (89 tests)
- Evidence: Golden vector re-encodes identically; rejects non-shortest integers, indefinite items, floats, tag, undefined, invalid UTF-8, duplicate/unsorted map keys, depth exceeded, oversized string, trailing data.
- Follow-up: F2.5 (CanonicalValue)

## F2.3 — Implement deterministic CBOR encoder

- Status: GREEN
- Commit: SELF
- Completed: CanonicalEncoder with shortest integer/string-length encoding, SortedMap helper; matches FORMAT.md §21.1 golden vector exactly. No indefinite-length, float, or tag APIs exposed.
- Tests: `cargo test --workspace --all-features` (57 tests)
- Evidence: Golden vector match; shortest u64/i64 at every boundary; empty/24-byte string length encoding; map key sorting; nested array; determinism.
- Follow-up: F2.4 (bounded CBOR decoder)

## F2.2 — Implement DomainHash

- Status: GREEN
- Commit: SELF
- Completed: domain_hash(tag, payload) implementing the exact length-prefixed SHA-256 construction from FORMAT.md §5.1 using u16::to_le_bytes() and u64::to_le_bytes() (no usize in preimage).
- Tests: `cargo test --workspace --all-features` (43 tests)
- Evidence: 13 empty-payload domain vectors match FORMAT.md §21.2 byte-for-byte; different tag/payload changes result; long tag (65535 bytes) and large payload (100k) handled correctly.
- Follow-up: F2.3 (deterministic CBOR encoder)

## F2.1 — Implement primitive fixed-width types

- Status: GREEN
- Commit: SELF
- Completed: Private-field wrappers for UUID (16 bytes), 14 hash-id types (32 bytes each), Signature (64 bytes), PublicKey (32 bytes), Timestamp (i64), and BoundedLength (u64 with max bound).
- Tests: `cargo test --workspace --all-features` (23 tests)
- Evidence: Round-trip bytes and display/parse for each type; malformed length rejection for UUID, RecordId, Signature, PublicKey; bound rejection for BoundedLength; distinct-type compile check.
- Follow-up: F2.2 (DomainHash)

## P0/P1 — post-audit fixes (fixture path alignment, TempRepo, crash-failpoints, G0 compatibility)

- Status: GREEN
- Commit: SELF
- Completed: Audit revealed 5 gaps — fixtures not in tests/vectors/format-v1/; G0 command path mismatch; missing TempRepo helper; missing crash-failpoints CI job; check-deps untested. All fixed and verified.
- Tests: Full G0 gate + G1 gate + check-deps edge-failure test
- Evidence: All gates pass; check-deps correctly returns non-zero on bad edge

## P1.6 — Freeze workspace baseline

- Status: GREEN
- Commit: SELF
- Completed: G1 hard gate passes — standard task gate (fmt, clippy, test, doc-test), check-deps, check-specs, check-fixtures, check-plan-ledger all exit 0
- Tests: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cargo test --doc --workspace --all-features`; `powershell -File scripts/check-deps.ps1`
- Evidence: 11 GREEN tasks in ledger, all scripts exit 0
- Follow-up: begin F2 canonical format primitives

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
