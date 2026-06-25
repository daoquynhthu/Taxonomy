# EternalCore Agent Operating Rules

> Status: mandatory repository workflow
>
> This file defines how an implementation Agent operates. It does not redefine architecture, format, transaction, cryptographic, policy, synchronization, or task semantics.

## 1. Authority

Before changing code, read the active task in `docs/PLAN.md` and the specifications it references.

Normative precedence:

1. `docs/FORMAT.md`
2. `docs/TRANSACTIONS.md`
3. `docs/CRYPTO.md`
4. `docs/POLICY.md`
5. `docs/SYNC.md`
6. `docs/ARCHITECTURE.md`
7. `docs/PLAN.md`
8. `Agent.md`

If two normative documents conflict, stop implementation and record the conflict in `ISSUE.md`. Do not choose an interpretation or modify a specification without explicit authorization.

## 2. Task Discipline

- Work on exactly one numbered `PLAN.md` task at a time.
- Start only when every declared dependency and preceding hard gate is green.
- Modify only the files and crates required by the active task.
- Do not implement nearby future work, compatibility paths, optional algorithms, speculative abstractions, or premature optimizations.
- Do not weaken tests, durability, validation, authorization, or parser limits to make a gate pass.
- A task is complete only when every listed deliverable and gate is satisfied by objective evidence.
- When a gate is red, stop opening new paths and repair the smallest violated invariant.
- Never mark a task green by judgment alone.

## 3. Required Repository Records

The Agent MUST maintain both `PROGRESS.md` and `ISSUE.md` at the repository root.

### 3.1 `PROGRESS.md`

`PROGRESS.md` is a concise execution ledger, not a diary. Update it in the same commit as every completed task.

Keep one entry per completed task, newest first:

```markdown
## <task-id> — <short title>

- Status: GREEN
- Commit: <commit hash or PENDING before commit>
- Completed: <one-sentence summary of observable output>
- Tests: `<command>`; `<command>`
- Evidence: <fixture, failpoint, CI artifact, or test file references>
- Follow-up: none | <strictly bounded item already present in PLAN.md>
```

Rules:

- Record only completed work and verified results.
- Keep each entry short; do not restate design documents or paste logs.
- Do not record planned work as completed.
- Do not use percentages, subjective confidence, or claims such as “mostly done.”
- Correct an inaccurate entry in place and mention the correction in the current task entry.
- A red or blocked task belongs in `ISSUE.md`, not as a completed progress entry.

### 3.2 `ISSUE.md`

`ISSUE.md` records only material issues that require explicit resolution or can invalidate a gate. It is not a general backlog.

Create an issue for:

- a major implementation blocker;
- a contradiction or missing invariant in the specifications or plan;
- a security, integrity, authorization, durability, interoperability, or data-loss defect found by audit or testing;
- a previously green task proven incorrect;
- a required external dependency or platform behavior that cannot satisfy the specification.

Do not create an issue for routine compiler errors, ordinary test failures under active repair, formatting work, minor refactoring, or future enhancements already covered by `PLAN.md`.

Use this format, newest first:

```markdown
## ISSUE-<four digits> — <short title>

- Status: OPEN | RESOLVED | SUPERSEDED
- Severity: BLOCKER | CRITICAL | HIGH
- Discovered in: <task-id, audit, test, or commit>
- Affected scope: <documents, crates, formats, gates>
- Evidence: <minimal reproduction, failing command, or exact conflicting sections>
- Violated invariant: <single precise invariant>
- Required decision: <single question or amendment required>
- Work stopped: <task ids blocked by this issue>
- Resolution: pending | <approved resolution and commit/document revision>
```

Issue rules:

- Assign IDs monotonically; never reuse or delete an issue ID.
- Preserve resolved issues as an audit trail.
- Do not silently work around an open blocker.
- When an issue invalidates completed work, reopen the affected gates and state this in both the issue resolution and the next `PROGRESS.md` entry.
- Only an approved specification amendment, a verified implementation fix, or proof that the report was invalid may resolve an issue.

## 4. Change Procedure

For each task:

1. Read the task, dependencies, allowed scope, red conditions, and gate commands.
2. Inspect the current implementation and relevant tests before editing.
3. Write or update the negative test that exposes the missing behavior.
4. Implement the smallest complete change satisfying the specification.
5. Run focused tests during development.
6. Run the full task gate and every affected cumulative gate.
7. Inspect the diff for out-of-scope changes, placeholders, disabled checks, and accidental format changes.
8. Update `PROGRESS.md`, or create/update `ISSUE.md` if blocked.
9. Commit only the active task.

Do not rewrite unrelated code solely for style. Refactoring is allowed only when required to complete the active task safely and must remain inside its dependency boundary.

## 5. Code and Validation Rules

- Preserve `#![forbid(unsafe_code)]` across workspace crates.
- Production library code must not use `unwrap`, `expect`, `panic!`, `todo!`, or `unimplemented!` on reachable paths.
- Treat all decoded lengths, offsets, counts, recursion, allocations, and network inputs as untrusted.
- Use checked arithmetic before allocation, seeking, slicing, or conversion.
- Reject non-canonical or unsupported authoritative encodings; do not normalize and accept them silently.
- Caches and indices are never authoritative.
- A ref must never become visible before its complete immutable graph is durable and verified.
- Do not add fallback algorithms or compatibility behavior absent from the specifications.
- Do not change normative fixtures to match implementation output. A fixture changes only through an authorized format amendment.
- Tests must exercise failure paths as well as successful construction.

## 6. Gate and Failure Handling

A green result requires the exact commands named in `PLAN.md` to exit successfully. Preserve command output or CI artifacts required by the gate.

At the first meaningful failure:

1. stop unrelated work;
2. preserve the command and first relevant error;
3. identify the violated invariant;
4. determine whether it is an implementation defect or a material specification/plan issue;
5. fix the active task, or record an `ISSUE.md` entry and stop if authorization is required;
6. rerun all gates affected by the fix.

Never respond to a failure by:

- deleting or ignoring the test;
- broadening accepted malformed input;
- skipping checksum, signature, policy, graph, or durability validation;
- reducing an fsync or atomic publication requirement;
- introducing silent data repair;
- continuing into a downstream task.

## 7. Commits and Reports

Use one reviewable commit per numbered task:

```text
<task-id>: <imperative summary>
```

Before submission, the diff must contain:

- only the active task and unavoidable compile-preserving dependency edits;
- its tests;
- the corresponding concise `PROGRESS.md` update;
- any required `ISSUE.md` update.

The completion report is limited to:

```text
Task:
Changed:
Tests added:
Gate commands:
Result:
Issues: none | ISSUE-xxxx
```

Do not propose unrelated next work. The next available task is determined only by `PLAN.md` and the current gate state.

## 8. Prohibited Actions

The Agent must not:

- alter normative semantics without authorization;
- combine multiple numbered tasks into one implementation change;
- claim completion with failing, ignored, missing, or non-behavioral tests;
- make `index.db`, process memory, wall-clock time, or remote claims authoritative;
- force-update refs, auto-merge conflicts, or invent conflict branches;
- bypass quarantine or core validation during import;
- expose secrets in logs, fixtures, panic messages, process arguments, or progress records;
- use `PROGRESS.md` or `ISSUE.md` as a substitute for tests or specification amendments;
- delete historical progress or issue records to make the project appear green.
