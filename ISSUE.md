# Issues

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

- Status: OPEN
- Severity: BLOCKER
- Discovered in: Audit 2026-06-25
- Affected scope: CI workflows, G1
- Evidence: CI runs commands but produces no gate-report.json with commit SHA, rustc version, exit codes, test counts, fixture manifest checksum, ignored test list.
- Violated invariant: G1 requires verifiable CI evidence.
- Required decision: Add gate-report.json generation to CI and upload as artifact.
- Work stopped: G1, all downstream gates
- Resolution: PENDING

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
- Resolution: RESOLVED (encode_canonical_value() added with FormatLimits; TryFrom<serde_json::Value> enforces depth/node/string/NUL limits; JsonDuplicateKey/JsonFloatUnsupported/JsonDepthExceeded/JsonNumberOutOfRange removed from DecodeError; 12 new tests)

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
