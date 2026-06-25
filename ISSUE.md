# Issues

## ISSUE-0001 — Ledger checker does not verify PLAN.md task completeness

- Status: OPEN
- Severity: BLOCKER
- Discovered in: Audit 2026-06-25
- Affected scope: scripts/check-plan-ledger.ps1, plan-ledger.json, P0.4, P0.5, P1.x, F2.x
- Evidence: Script only checks dependency existence and cycles; does not parse PLAN.md to verify every task ID is present in ledger, or that no extra/missing/duplicate IDs exist.
- Violated invariant: P0.4 gate "ledger validation passes" requires complete PLAN.md ↔ ledger alignment.
- Required decision: Expand checker to parse PLAN.md headings and verify exact task ID match.
- Work stopped: P0.4, P0.5, P1.x, F2.x
- Resolution: PENDING

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

- Status: OPEN
- Severity: CRITICAL
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/domain.rs, FORMAT.md §5.1, F2.2
- Evidence: `(tag_len as u16).to_le_bytes()` truncates without check. tag 65535 accepted, 65536 silently produces wrong preimage.
- Violated invariant: Tag length MUST fit in u16.
- Required decision: domain_hash must return Result and reject tag > 65535, payload > u64::MAX.
- Work stopped: F2.2
- Resolution: PENDING

## ISSUE-0004 — CanonicalSortedMap can emit duplicate encoded keys

- Status: OPEN
- Severity: CRITICAL
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/canonical.rs, FORMAT.md §4, F2.3
- Evidence: `insert_raw` is pub, `finish()` sorts but does not dedup. Authoritative writer can produce illegal duplicate map keys.
- Violated invariant: Encoded CBOR maps must have unique keys.
- Required decision: Make insert_raw pub(crate), finish() return Result, reject duplicate keys after sort.
- Work stopped: F2.3
- Resolution: PENDING

## ISSUE-0005 — F2.6 implementation incomplete (missing types + encapsulation holes)

- Status: OPEN
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/ids.rs, FORMAT.md §6, F2.6
- Evidence: DataType, RelationType, CommitMessage, KeySlotLabel not implemented. Bare ref prefix `refs/heads/` accepted as valid suffix (empty suffix should be rejected because suffix must follow non-empty ObjectId path rules). RefPattern fields are pub (callers can bypass new()). matches() accepts &str instead of &RefName.
- Violated invariant: All FORMAT.md §6 constrained text types must exist with checked construction.
- Required decision: Add missing types; make RefPattern fields private; matches() take &RefName; reject bare prefixes.
- Work stopped: F2.6
- Resolution: PENDING

## ISSUE-0006 — BoundedLength::new_unchecked is pub allowing bypass of max check

- Status: OPEN
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/ids.rs, F2.1
- Evidence: `pub const fn new_unchecked(value: u64) -> Self` visible to external callers.
- Violated invariant: BoundedLength must enforce its maximum.
- Required decision: Change to pub(crate).
- Work stopped: F2.1
- Resolution: PENDING

## ISSUE-0007 — CBOR decoder uses unchecked u64→usize casts

- Status: OPEN
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/canonical.rs, F2.4
- Evidence: `len as usize` at lines 415, 426, 438, 452 without checked conversion.
- Violated invariant: All untrusted lengths must be checked before allocation/slicing.
- Required decision: Use usize::try_from and return structured error on overflow.
- Work stopped: F2.4
- Resolution: PENDING

## ISSUE-0008 — F2.5 lacks JSON conversion adapter required by GREEN criteria

- Status: OPEN
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: crates/eternal-format/src/canonical.rs, F2.5
- Evidence: No `TryFrom<serde_json::Value> for CanonicalValue` implementation. GREEN criterion "floating JSON input is rejected by conversion adapters" not met.
- Violated invariant: CanonicalValue must provide JSON→CV conversion with float rejection.
- Required decision: Implement TryFrom<serde_json::Value> with float/number-range/depth/node-count checking.
- Work stopped: F2.5
- Resolution: PENDING

## ISSUE-0009 — PROGRESS.md PENDING commit references are self-referential

- Status: OPEN
- Severity: HIGH
- Discovered in: Audit 2026-06-25
- Affected scope: PROGRESS.md
- Evidence: Entries record "Commit: PENDING" then update to commit hash in same commit, creating circular reference.
- Required decision: Replace "Commit: PENDING" pattern with "Commit: SELF" (commit identity is implicit in git history).
- Work stopped: none
- Resolution: PENDING
