# EternalCore v4 Transactions and Crash-Consistency Specification

> Status: implementation baseline
>
> This document defines the normative transaction, durability, concurrency, recovery, and publication rules for EternalCore v4. It is subordinate to `ARCHITECTURE.md` for system architecture and to `FORMAT.md` for byte-level encoding. Where an older draft conflicts with this document, this document wins for transaction semantics.

## 1. Scope

EternalCore does not use a general-purpose transactional database as its authority. Transactionality is obtained from four properties:

1. immutable, content-addressed records;
2. append-only active segments;
3. signed predecessor-linked reference updates;
4. atomic replacement of very small pointer files after referenced records are durable.

This document specifies:

- logical object transactions;
- ref-only transactions;
- repository initialization;
- physical StoreManifest publication;
- segment sealing;
- pack compaction and garbage collection publication;
- synchronization receive and ref update;
- writer locking and read snapshots;
- large-object prepublication writes;
- optimistic conflict detection;
- crash recovery;
- ambiguous commit outcomes;
- required failpoint and recovery tests.

This document does not define:

- record field encodings, which are defined by `FORMAT.md`;
- detailed authorization policy evaluation, which is defined by `POLICY.md`;
- cryptographic algorithms, which are defined by `CRYPTO.md`;
- wire messages, which are defined by `SYNC.md`.

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

## 2. Transaction model

### 2.1 Immutable data and mutable pointers

EternalCore has two distinct transaction domains.

The logical domain is:

```text
ref pointer file
  -> RefUpdateId
  -> signed RefUpdate
  -> RepoCommitId
  -> signed RepoCommit
  -> object_state_root
  -> immutable logical graph
```

The physical domain is:

```text
CURRENT
  -> StoreManifestId
  -> active segment + sealed pack/index set
```

A logical transaction publishes a new branch or tag state by replacing one ref pointer file.

A physical-layout transaction publishes a new storage-file set by replacing `CURRENT`.

These two pointer classes have different meanings and MUST NOT be conflated:

- ref replacement is a logical state publication;
- `CURRENT` replacement is a physical layout publication;
- `TransactionEnd` is an append-batch completion marker and is neither publication point.

### 2.2 Visibility and durability

For any atomic pointer replacement, EternalCore distinguishes:

- **visibility point**: the successful same-directory atomic rename;
- **durable publication point**: successful synchronization of the containing directory after the rename.

After the visibility point, concurrent processes may observe the new pointer.

The operation MUST NOT be acknowledged as durably committed until the directory synchronization succeeds.

If rename succeeds but directory synchronization fails or its result is unknown, the operation outcome is **ambiguous**. Recovery may expose either the old pointer or the new pointer, but never a partial pointer file.

### 2.3 No in-place rollback

EternalCore never rolls back immutable writes. Aborting a transaction means that no mutable logical pointer is advanced.

An aborted or crashed transaction MAY leave:

- complete immutable records;
- complete physical append batches;
- verified incoming packs;
- temporary files;
- obsolete StoreManifest generations.

Such data is unreachable or unpublished and is reclaimed later. Transaction abort MUST NOT rewrite or erase already durable immutable records as part of correctness.

### 2.4 Transaction classes

EternalCore v4 defines these transaction classes:

| Class | Publishes through | Examples |
|---|---|---|
| logical state transaction | one ref pointer | put, delete, rollback, resolved merge, policy update, keyring update |
| ref-only transaction | one ref pointer | branch create/delete/recreate, tag create, pin create/delete |
| local control transaction | local pointer file | HEAD switch |
| physical append batch | TransactionEnd + segment fsync | chunk prewrite, final logical record batch |
| physical layout transaction | CURRENT | seal, pack import, compaction, GC |
| repository initialization | directory rename | creation of a new `.eternal` repository |

One API operation MAY contain multiple physical append batches and at most one logical ref publication.

A physical append batch MUST fit in one active segment and MUST NOT span segment files.

## 3. Core invariants

Every implementation MUST preserve all of the following.

1. A ref pointer never names a `RefUpdate` whose required logical metadata graph is incomplete in the currently published physical store.
2. For a normal local write, every referenced content chunk has at least one locally readable `EncodedChunk` before ref publication.
3. For a metadata-complete partial clone, a missing content chunk is allowed only when it is explicitly recorded as promised by a configured promisor remote.
4. A ref pointer is replaced only after the `RefUpdate`, target `RepoCommit`, changed `ObjectVersion` records, required SMT nodes, policy/keyring records, manifests, and non-promised content records are durable.
5. A ref CAS compares `RefUpdateId`, never only `RepoCommitId`.
6. `RefUpdate.sequence` increments exactly from its predecessor and prevents ABA through delete/recreate cycles.
7. A transaction that loses its optimistic validation MUST NOT silently overwrite intervening work.
8. A `RepoCommit.object_state_root` is reproducible from parent 0 and its ordered `changes` list.
9. A transaction is acknowledged only after its publication pointer and containing directory are durable.
10. A reader observes one pinned logical state and one compatible pinned physical generation.
11. `index.db` is never part of logical or physical commit authority.
12. Sealing, compaction, GC, and incoming-pack publication never modify an already published pack.
13. Files used by a pinned reader generation are not moved or deleted until that generation has no live readers.
14. Recovery never invents a ref, commit, record, StoreManifest, or transaction that cannot be verified from durable bytes.
15. Ordinary repository opening never guesses between multiple possible recovery histories.

## 4. Required filesystem primitives

### 4.1 Platform abstraction

The implementation MUST expose a platform durability layer with at least these operations:

```rust
trait DurableFs {
    fn sync_file(&self, file: &File) -> Result<()>;
    fn sync_dir(&self, dir: &Path) -> Result<()>;
    fn atomic_replace(&self, source: &Path, destination: &Path) -> Result<()>;
    fn atomic_rename_new(&self, source: &Path, destination: &Path) -> Result<()>;
    fn acquire_exclusive_lock(&self, path: &Path) -> Result<LockGuard>;
    fn acquire_shared_lock(&self, path: &Path) -> Result<LockGuard>;
}
```

The backend MUST use the strongest documented equivalent on the host platform.

If the filesystem or platform cannot provide reliable advisory locking, same-directory atomic rename, and the required durability synchronization, writable open MUST fail with `DurabilityUnsupported`.

Read-only open MAY remain available.

### 4.2 File creation

A new immutable file MUST be created with exclusive-create semantics. The implementation MUST NOT overwrite an existing immutable file.

If an immutable destination already exists:

1. verify its complete contents and identifier;
2. accept it only if it is byte-identical to the intended file;
3. otherwise fail with `IdentifierCollisionOrCorruption`.

### 4.3 Atomic pointer replacement

Mutable pointer replacement MUST use a temporary file in the same directory as the destination.

Normative sequence:

1. create a uniquely named temporary file with exclusive-create semantics;
2. write the complete pointer bytes;
3. synchronize the temporary file;
4. atomically replace the destination;
5. synchronize the containing directory;
6. remove any surviving temporary name if safe.

Temporary pointer files MUST NOT be interpreted as authoritative during ordinary open.

### 4.4 Path safety

Transaction code MUST NOT follow untrusted symbolic links while opening repository-internal paths.

The implementation SHOULD use directory-relative, no-follow operations where available.

Every path used in a StoreManifest or pointer file MUST first pass the normalization and repository-boundary checks from `FORMAT.md`.

### 4.5 Write completion

All write operations MUST handle short writes and interruptions. A successful high-level write means every requested byte was accepted by the operating system before synchronization is attempted.

A write syscall returning success does not imply durability.

## 5. Locking and lock order

### 5.1 Repository writer lock

All mutation of the following resources is serialized by the operating-system advisory lock on:

```text
.eternal/write.lock
```

The writer lock covers:

- append to the active segment;
- active-segment truncation;
- ref pointer replacement;
- HEAD replacement;
- StoreManifest and CURRENT publication;
- sealing;
- incoming-pack publication;
- compaction;
- garbage collection publication;
- index cache mutation performed as part of these operations.

Only one process may hold the writer lock exclusively.

The implementation MUST NOT break an advisory lock based on PID age, timestamps, or a stale-looking lockfile.

Diagnostic PID, node ID, and acquisition time are non-authoritative.

### 5.2 Generation reader locks

To prevent deletion or movement of files used by existing readers, each StoreManifest generation has a local generation lock:

```text
.eternal/locks/generation-<generation>.lock
```

A reader snapshot holds a shared lock for its pinned generation.

A maintenance operation MUST acquire the exclusive generation lock before moving or deleting any file that is required by that generation.

Publication of a newer generation does not require exclusive access to the older generation lock. Retirement does.

Generation lock files are local coordination files and are not part of the repository format or synchronization protocol.

### 5.3 Lock order

The global order is:

```text
repository writer lock
  -> physical files / temporary files
  -> pointer file or CURRENT replacement
  -> directory synchronization
  -> index.db write transaction
```

A process MUST NOT acquire the repository writer lock while holding an `index.db` write transaction.

A process MUST NOT wait for network I/O, user input, password entry, or long-running content transformation while holding the writer lock, except for the bounded final publication phase.

Generation shared locks MAY be held without the writer lock. An exclusive generation lock used for retirement is acquired only after publication and outside the critical publication sequence.

### 5.4 No ref-specific lock

The baseline implementation does not use separate ref locks. The repository writer lock serializes local ref updates.

Network CAS is executed by the receiving repository while holding its repository writer lock.

## 6. Read snapshots

### 6.1 Snapshot objective

A read snapshot must pin:

- one symbolic ref name;
- one `RefUpdateId`;
- one target `RepoCommitId` and state root;
- one StoreManifest generation that contains, or can resolve, the pinned graph.

### 6.2 Snapshot acquisition

For `HEAD`-based reads, use this retry loop:

1. read and validate `CURRENT` as `C1`;
2. open and validate the named StoreManifest;
3. acquire a shared generation lock for `C1.generation`;
4. re-read `CURRENT`; if it differs from `C1`, release and retry;
5. read and validate `HEAD`, obtaining a concrete ref name;
6. read the ref pointer as `R1`;
7. re-read the same ref pointer as `R2`;
8. re-read `CURRENT` as `C2`;
9. accept only if `C1 == C2` and `R1 == R2`; otherwise release and retry;
10. resolve and validate the immutable graph from `R1` using the pinned generation.

For an explicit ref, omit the HEAD read but retain the double ref read and double CURRENT validation.

This algorithm prevents a snapshot from combining a ref published under a newer physical generation with an older generation that cannot resolve it.

### 6.3 Active-segment visibility

The active segment is append-only. A reader:

- accepts only complete frames;
- validates CRC and RecordId;
- ignores an incomplete tail;
- resolves a ref only through records covered by a valid `TransactionEnd` batch;
- MAY use a cache for locations but MUST fall back to verified segment scanning when the cache is stale.

Because ref publication occurs only after the relevant segment fsync, every accepted ref target must be resolvable from a complete durable append batch.

### 6.4 Snapshot lifetime

A reader holds the generation shared lock until all readers, iterators, or stream handles derived from the snapshot are closed.

An `ObjectReader` MUST retain the snapshot guard internally. Returning only a raw file offset without the guard is invalid.

### 6.5 Ref history retention and snapshots

GC roots and reflog retention protect recently superseded ref states. The generation lock protects physical files only; it does not itself create a logical GC root.

A long-lived process requiring a logical state beyond the configured reflog window MUST create a pin ref.

## 7. Physical append batches

### 7.1 Purpose

A physical append batch is a contiguous sequence of non-`TransactionEnd` frames followed by exactly one `TransactionEnd` frame in the same active segment.

It proves that a bounded set of immutable records was appended as one complete physical batch.

It does not make those records logically reachable.

### 7.2 Batch construction

While holding the writer lock:

1. determine the current active segment from the current StoreManifest;
2. validate its header and last complete batch boundary;
3. record `first_frame_offset`;
4. append each new record frame in physical order;
5. collect each frame RecordId in the same order;
6. record the start offset of the `TransactionEnd` frame as `end_frame_offset`;
7. construct and append `TransactionEnd`;
8. synchronize the active segment;
9. release the writer lock unless a logical publication immediately follows.

A batch MUST contain at least one non-end record.

Record IDs within one batch MUST be unique.

A writer SHOULD omit a record already available in the current StoreManifest. Before reusing an existing record, it MUST verify that the existing type and payload match the expected RecordId.

### 7.3 Segment capacity

A physical append batch MUST NOT cross an active-segment boundary.

Before appending, the writer computes a conservative upper bound for:

- all frame headers;
- payloads;
- CRC fields;
- the final `TransactionEnd` frame.

If the batch would exceed the active segment hard maximum, the batch MUST be split at an immutable-record boundary.

If the current segment lacks room for the next batch, the writer seals it before starting the batch.

A single record larger than the `FORMAT.md` payload limit is invalid and cannot be split by the transaction layer.

### 7.4 Large content

A logical object write may involve content much larger than one segment.

Large content is handled as follows:

1. stream, chunk, hash, compress, and optionally encrypt content outside the long-lived publication lock;
2. publish generated `EncodedChunk` records in one or more physical append batches;
3. seal segments as needed between batches;
4. leave these records logically unreachable during preparation;
5. create the `ContentManifest` after the complete chunk sequence is known;
6. perform one final logical publication transaction that references the prepared content.

A process crash during preparation leaves only unreachable immutable records.

The final logical publication MUST revalidate its optimistic dependencies before creating or publishing the final `RepoCommit` and `RefUpdate`.

### 7.5 Batch IDs

Each physical append attempt uses a fresh random transaction UUID.

A UUID from a completed `TransactionEnd` MUST NOT be reused for a different batch.

The transaction UUID is diagnostic and recovery metadata. It is not a logical idempotency key and is not a commit identifier.

### 7.6 Unfinished trailing batch

Frames after the last valid `TransactionEnd` are not a complete physical batch, even when their individual CRCs and RecordIds verify.

During recovery under the writer lock, the active segment is truncated to the byte immediately after the last valid `TransactionEnd` frame.

This rule discards complete but unpublished trailing frames written before a crash prevented `TransactionEnd` completion.

## 8. Logical transaction lifecycle

### 8.1 States

A complete write operation progresses through these conceptual states:

```text
PLANNING
  -> CONTENT_PREPARED
  -> TRANSACTION_OPEN
  -> VALIDATED
  -> RECORD_BATCH_DURABLE
  -> REF_VISIBLE
  -> COMMITTED
  -> CACHE_UPDATED
```

Definitions:

- `PLANNING`: a process-local write plan and optimistic dependencies exist;
- `CONTENT_PREPARED`: required immutable content is durable or promised;
- `TRANSACTION_OPEN`: the writer lock is held and the bounded logical transaction has begun;
- `VALIDATED`: optimistic dependencies and authorization hold against the publication base;
- `RECORD_BATCH_DURABLE`: final records and TransactionEnd are synchronized;
- `REF_VISIBLE`: ref rename succeeded;
- `COMMITTED`: ref directory synchronization succeeded;
- `CACHE_UPDATED`: rebuildable cache reflects the commit.

Only `COMMITTED` is acknowledged as durable success. The logical transaction itself exists only from `TRANSACTION_OPEN` until the writer lock is released. Content preparation is not a persistent or cross-process transaction.

### 8.2 Write plan and lock-scoped transaction

Before the writer lock is acquired, a process-local write plan may record:

```rust
struct WritePlan {
    operation_uuid: Uuid,
    target_ref: RefName,
    initial_ref_update_id: RefUpdateId,
    initial_commit_id: RepoCommitId,
    initial_state_root: SmtRoot,
    initial_policy_id: PolicyId,
    initial_keyring_id: KeyringId,
    read_set: BTreeMap<ObjectId, Option<VersionId>>,
    write_intents: BTreeMap<ObjectId, MutationIntent>,
    isolation: IsolationMode,
}
```

The plan is not authoritative and is not persisted as a cross-process staging area. Prepared immutable records may be durable, but the plan remains process-local.

After the writer lock is acquired, the implementation creates a bounded lock-scoped transaction from the validated plan. That transaction MUST finish or abort before the writer lock is released.

### 8.3 Isolation modes

EternalCore supports two write-isolation modes.

#### ObjectSnapshot

This is the default for direct object mutations.

At final publication, if the target ref advanced, the transaction may rebase onto the new tip only when:

- `policy_id` is unchanged;
- `keyring_id` is unchanged;
- every object in the read set still maps to the same `VersionId` or absence;
- no transaction-wide predicate dependency was declared;
- the operation is not a merge or administrative transition.

If these conditions hold, the implementation recomputes the SMT changes and creates the `RepoCommit` against the latest target commit.

Unrelated object updates therefore need not cause failure.

#### SerializableBranch

This mode requires the target `RefUpdateId` to remain exactly equal to `initial_ref_update_id`.

It is mandatory for:

- transactions derived from list, search, or range predicates;
- merge transactions;
- policy transitions;
- keyring transitions;
- ref namespace administration that depends on a branch state;
- callers explicitly requesting whole-branch compare-and-swap.

There is no automatic predicate locking or phantom detection in v4. Predicate-dependent writes use `SerializableBranch`.

### 8.4 Read set

Every object whose current value influences a write MUST appear in the read set.

Every mutated object is implicitly in the read set.

For creation, the expected value is absence.

For update, delete, and rollback, the expected value is the current `VersionId`.

Soft relation targets do not enter the read set unless the caller explicitly validates or derives behavior from their state.

### 8.5 Authorization dependency

The final publication phase always re-evaluates authorization against the policy that governs the current publication base.

A key revoked after transaction preparation cannot publish using an earlier cached authorization result.

If the policy changes during an ObjectSnapshot transaction, automatic rebase is forbidden and the transaction fails with `PolicyChanged`.

### 8.6 Keyring dependency

A transaction that creates encrypted records records the exact keyring and key epoch used during preparation.

If the target branch keyring changes before publication, automatic rebase is forbidden unless `CRYPTO.md` explicitly proves the prepared encoding remains valid under the new keyring. The baseline implementation returns `KeyringChanged`.

## 9. Normal object-state transaction

### 9.1 Preparation phase

Outside the bounded final writer-lock section, the implementation may:

- read the base snapshot;
- collect metadata and relations;
- read user content;
- perform deterministic chunking;
- calculate ChunkIds;
- compress and encrypt chunks;
- sign records whose payload dependencies are already fixed;
- prewrite immutable content records through physical append batches.

The implementation MUST NOT hold the writer lock while waiting for user input or reading an unbounded external stream.

### 9.2 Final publication phase

The normative publication sequence is:

1. acquire the repository writer lock;
2. read and validate the current StoreManifest and active segment;
3. read `HEAD` or the explicit target ref;
4. read and validate the current ref pointer and `RefUpdate`;
5. resolve the current target `RepoCommit`, state root, policy, and keyring;
6. validate isolation dependencies;
7. re-evaluate authorization;
8. verify all reused/prepared content records are present or validly promised;
9. if ObjectSnapshot rebase is allowed, set the current target commit as parent 0 and recompute changes against its state root;
10. finalize any new `ContentManifest` records;
11. create and sign one `ObjectVersion` for each mutated object;
12. apply changes in canonical ObjectId order and create required SMT records;
13. create and sign the `RepoCommit`;
14. create and sign the successor `RefUpdate`;
15. append all final missing records as one physical append batch ending in `TransactionEnd`;
16. synchronize the active segment;
17. re-read the ref pointer and require the expected predecessor `RefUpdateId`;
18. write the new RefUpdateId to a same-directory temporary ref file;
19. synchronize the temporary ref file;
20. atomically replace the ref pointer file;
21. synchronize the ref directory;
22. update `index.db` in a best-effort cache transaction;
23. release the writer lock;
24. return `VersionId` values, `RepoCommitId`, and `RefUpdateId`.

The writer lock MUST remain held from step 1 through step 23.

### 9.3 Final batch record closure

Before ref replacement, the implementation MUST verify that the target commit closure is resolvable.

The required local metadata closure includes:

- RepositoryGenesis;
- policy chain required for authorization;
- keyring chain required for content interpretation;
- target RepoCommit and required parent commits;
- changed ObjectVersions and their parent lineage required by policy;
- ContentManifests;
- all non-default SMT nodes required by the target state root;
- RefUpdate predecessor chain required for CAS validation.

For a full local repository, every referenced ChunkId must have at least one usable EncodedChunk.

For a partial clone, missing chunks must be registered as promises before logical publication.

### 9.4 Multi-object batch

A batch transaction produces:

- zero or more prepared content append batches;
- one final `ObjectVersion` per changed object;
- one ordered `RepoCommit.changes` list;
- one new state root;
- one `RepoCommit`;
- one `RefUpdate`;
- one ref pointer replacement.

Mutations to the same ObjectId within one transaction are folded into one final mutation before record creation.

The final change list is sorted by ObjectId UTF-8 bytes and contains no duplicate ObjectId.

### 9.5 Empty-change administrative commit

Policy or keyring updates use an empty `changes` list and preserve the parent state root.

The transaction writes the new PolicyRecord or KeyringRecord, then a RepoCommit referencing the new authority state, then a RefUpdate.

Authorization of a policy transition is evaluated against the first parent commit's policy, never against the new policy being introduced.

### 9.6 No manual uncommitted branch state

The v4 core has no persistent working tree, index, or `--no-commit` mode.

Every successful object mutation publishes exactly one RepoCommit and one RefUpdate.

Process-local batch APIs are allowed, but they publish atomically through one ref update.

## 10. Ref-only transactions

### 10.1 General sequence

A ref-only transaction creates a signed RefUpdate that targets an existing RepoCommit or null.

Normative sequence:

1. perform all remote I/O and user interaction before locking;
2. acquire writer lock;
3. read current policy and relevant ref state;
4. authorize the operation;
5. construct and sign RefUpdate;
6. append RefUpdate plus TransactionEnd;
7. synchronize active segment;
8. revalidate predecessor CAS;
9. atomically replace the ref pointer;
10. synchronize ref directory;
11. update cache best-effort;
12. release writer lock.

No RepoCommit is created unless the logical repository state itself changes.

### 10.2 Branch creation

A branch creation RefUpdate has:

- `previous_ref_update_id = null` only if the branch was never created;
- `target_commit_id = existing commit`;
- `sequence = 1`.

If a branch pointer file already exists and points to a deletion RefUpdate, recreation extends that deletion record and increments the sequence. It is not a fresh sequence-1 creation.

### 10.3 Branch deletion

A branch deletion RefUpdate:

- names the current RefUpdate as predecessor;
- has `target_commit_id = null`;
- increments sequence exactly;
- leaves the ref pointer file present, pointing to the deletion update.

Deleting the branch currently named by HEAD is rejected. The caller must switch HEAD first.

### 10.4 Tag creation

A v4 tag is create-only:

- predecessor is null;
- target is non-null;
- sequence is 1.

An existing or deleted tag name cannot be updated or recreated by the v4 core.

### 10.5 Pin and merge-request refs

Pins and merge-request refs use the same predecessor-linked CAS protocol. Their authorization and lifecycle rules are defined by `POLICY.md`.

## 11. HEAD transaction

HEAD is local-only and is not a signed repository record.

Switching HEAD performs:

1. acquire writer lock;
2. validate the destination is a non-deleted `refs/heads/*` ref;
3. write the new HEAD content to a same-directory temporary file;
4. synchronize the temporary file;
5. atomically replace HEAD;
6. synchronize `.eternal`;
7. release writer lock.

A HEAD switch does not create RepoCommit or RefUpdate records.

A read snapshot that already pinned a concrete ref is unaffected by a concurrent later HEAD switch.

## 12. Merge transactions

### 12.1 Preparation

Merge analysis may run outside the writer lock against pinned target and source snapshots.

The merge computes:

- target tip;
- source tip;
- merge base;
- three-way object results;
- conflict set;
- proposed resolutions.

If any conflict remains unresolved, no logical or ref publication occurs.

### 12.2 Publication

Merge uses `SerializableBranch` isolation.

Before publication, the implementation requires:

- target ref tip unchanged;
- source ref tip unchanged;
- merge base still valid for those tips;
- governing policy unchanged;
- governing keyring unchanged where relevant.

The merge RepoCommit has:

- parent 0 = current target tip;
- parent 1 = source tip;
- any additional parents ordered as required by `FORMAT.md`;
- changes applied to parent 0 state;
- one resolved ObjectVersion for each true object conflict, with both conflicting VersionIds as parents.

The transaction then follows the normal final publication protocol.

The implementation MUST NOT create synthetic conflict refs per ObjectId.

## 13. Repository initialization transaction

### 13.1 Temporary repository root

Initialization MUST be constructed under a sibling temporary directory:

```text
.<repo-name>.eternal-init-<uuid>/
```

or an equivalent same-filesystem path.

The final `.eternal` destination MUST not already exist.

### 13.2 Initialization contents

The initializer creates:

- repository directory structure;
- creator signing key storage;
- local config with fresh node ID;
- RepositoryGenesis;
- initial PolicyRecord;
- initial KeyringRecord;
- initial empty-state RepoCommit;
- initial refs/heads/main RefUpdate;
- active segment with one or more complete TransactionEnd batches;
- generation-1 StoreManifest;
- CURRENT;
- HEAD;
- refs/heads/main pointer;
- optional rebuildable index.

### 13.3 Initialization publication

Normative sequence:

1. create temporary root with restrictive permissions;
2. create and synchronize required immutable and mutable files;
3. synchronize every created directory bottom-up;
4. verify repository opening entirely within the temporary root;
5. atomically rename the temporary root to final `.eternal`;
6. synchronize the parent directory;
7. report success.

If the final directory rename succeeds but parent synchronization fails, initialization outcome is ambiguous. The caller must test whether `.eternal` exists and validates before retrying.

Ordinary initialization MUST NOT merge into or repair a pre-existing `.eternal` directory.

## 14. Segment recovery

### 14.1 Recovery trigger

Writable repository open performs active-segment recovery while holding the writer lock.

Read-only open never truncates files.

### 14.2 Scan algorithm

Recovery:

1. reads CURRENT and validates the current StoreManifest;
2. opens the named active segment;
3. validates its fixed header and repository/generation identity;
4. scans frames from the header end;
5. validates every complete frame CRC and RecordId;
6. validates every TransactionEnd against the immediately preceding uncovered frames;
7. tracks the byte after the last valid TransactionEnd frame;
8. stops at the first incomplete or invalid tail condition;
9. truncates the segment to the last valid TransactionEnd boundary;
10. synchronizes the truncated segment;
11. rebuilds or invalidates active-segment cache entries beyond that boundary.

### 14.3 TransactionEnd validation

A valid TransactionEnd requires:

- matching repository ID;
- `first_frame_offset` equal to the first uncovered non-end frame;
- `end_frame_offset` equal to the start of the TransactionEnd frame;
- `record_count` equal to the number of covered frames;
- no covered frame of type TransactionEnd;
- record IDs root matching physical append order;
- all covered frames individually valid.

A TransactionEnd that attempts to overlap, skip, or reorder frames is corruption.

### 14.4 Invalid frame inside committed region

If an invalid frame occurs before a later ref-visible transaction that depends on it, recovery MUST fail loudly with `CommittedStorageCorruption`.

The implementation MUST NOT search for a later valid frame boundary or silently roll the ref backward.

### 14.5 Ref validation after recovery

After active-segment recovery, writable open validates every visible ref pointer required for normal operation.

If a ref points to a record truncated as an unfinished batch, the repository is corrupt. This condition indicates violation of the required fsync-before-ref protocol or underlying storage failure.

Automatic ref rollback is forbidden.

## 15. Ref publication and ambiguous outcomes

### 15.1 Definite abort

Before ref rename succeeds, an error means the new logical state was not published by that operation.

Durable immutable orphan records may remain.

### 15.2 Definite commit

After ref directory synchronization succeeds, the new RefUpdate is durably committed and the API returns success.

### 15.3 Ambiguous commit

If ref rename may have succeeded but directory synchronization or process completion is uncertain, the API returns:

```rust
CommitOutcomeUnknown {
    ref_name: RefName,
    expected_ref_update_id: RefUpdateId,
    expected_repo_commit_id: Option<RepoCommitId>,
}
```

The caller MUST resolve ambiguity by reading the ref:

- if it equals `expected_ref_update_id`, the operation committed;
- if it equals the expected predecessor, the operation did not commit;
- if it names a later descendant RefUpdate, walk the predecessor chain to determine whether the expected update committed and was subsequently superseded;
- otherwise report divergence or corruption.

A caller MUST NOT blindly repeat a mutation after `CommitOutcomeUnknown`.

### 15.4 Idempotent retry

If the ref still equals the expected predecessor, the implementation MAY retry using the same already constructed immutable records and RefUpdate, provided:

- all record IDs and signatures are unchanged;
- the predecessor and sequence still match;
- authorization remains valid;
- the required records remain present.

If any dependency changed, a new logical transaction must be constructed.

## 16. Index cache transaction

### 16.1 Non-authoritative role

`index.db` is updated only after logical or physical publication is durable.

A cache failure MUST NOT cause the implementation to claim that a committed ref was rolled back.

### 16.2 Cache watermark

The cache SHOULD record:

- current StoreManifestId;
- active segment ID;
- last indexed complete TransactionEnd offset;
- cached RefUpdateIds;
- schema version.

On open, the cache is trusted only when these watermarks agree with authoritative files.

### 16.3 Update outcome

If cache update fails after commit:

- return logical success with a cache-degraded warning;
- mark the in-memory cache unusable;
- rebuild lazily or on next open;
- never change the ref as compensation.

## 17. Segment sealing transaction

### 17.1 Preconditions

Sealing occurs when:

- the target segment size threshold is reached;
- the next append batch would not fit;
- the user explicitly requests sealing;
- maintenance requires a stable pack boundary.

The segment must first be recovered to its last valid TransactionEnd boundary.

### 17.2 Pack contents

The pack builder copies only non-TransactionEnd records from complete physical batches.

TransactionEnd records are segment-local and MUST NOT enter packs.

The pack builder MAY deduplicate identical RecordIds across batches. If the same RecordId is associated with different type or payload bytes, sealing fails as corruption.

### 17.3 Publication sequence

Normative sequence:

1. acquire writer lock;
2. validate CURRENT and current StoreManifest;
3. recover the active segment to the last valid batch boundary;
4. synchronize and close the current active segment for append;
5. build temporary pack and index in `objects/tmp/`;
6. verify every copied record, pack checksum, index checksum, offsets, and counts;
7. synchronize temporary pack and index;
8. atomically move pack and index to their immutable final names;
9. synchronize the pack directory;
10. create a new active segment with generation `old + 1`;
11. synchronize the new active segment and active directory;
12. construct the new StoreManifest listing the new active segment and complete new pack set;
13. write the manifest to a temporary file and synchronize it;
14. atomically move it to its content-addressed final filename;
15. synchronize the manifest directory;
16. write and synchronize temporary CURRENT;
17. atomically replace CURRENT;
18. synchronize `.eternal`;
19. release writer lock;
20. retire the old active segment only after obtaining the old generation's exclusive generation lock.

The old active segment MUST remain at its original path while any reader pins the old generation. It MUST NOT be moved immediately after CURRENT publication.

### 17.4 Crash outcomes

- before CURRENT rename: old generation remains authoritative; new files are ignored or orphaned;
- after CURRENT rename but before `.eternal` synchronization: recovery may expose old or new generation;
- after `.eternal` synchronization: new generation is durable;
- old files are not deleted until the new generation is durable and no old reader remains.

### 17.5 Sealing and logical publication

A logical transaction MUST NOT switch StoreManifest generation between final segment fsync and ref rename.

If sealing is necessary for the final append batch, seal before appending that batch.

## 18. Physical layout publication

### 18.1 StoreManifest monotonicity

A new StoreManifest:

- increments generation exactly by one;
- names the previous StoreManifestId;
- retains every physical file required by current logical roots unless a verified replacement contains identical records;
- names exactly one newly created active segment whose header generation equals the new manifest generation;
- lists a complete, sorted pack set.

Because the active segment descriptor is generation-bound, every StoreManifest generation transition rotates the active segment. The previous active segment is recovered, closed, and represented by one or more sealed packs in the new generation before CURRENT can switch. A layout transaction MUST NOT reuse an old-generation active segment in a new StoreManifest.

### 18.2 CURRENT publication

Every physical layout publication uses the following common preparation rule before CURRENT replacement:

1. recover and close the current active segment;
2. convert all complete non-TransactionEnd records from that segment into a verified sealed pack, unless an identical verified copy is already included;
3. create and synchronize a new active segment whose generation equals the new StoreManifest generation;
4. include both the closed-segment records and the layout operation's added or replacement packs in the new manifest.

CURRENT is replaced only after:

- every newly named file exists at its final path;
- every newly named file verifies;
- every newly named file is synchronized;
- relevant containing directories are synchronized;
- the new StoreManifest is synchronized at its final name.

### 18.3 Ordinary open behavior

Ordinary open follows only CURRENT.

It ignores:

- unreferenced manifests;
- unreferenced packs;
- files under tmp;
- files under incoming;
- files under trash.

It does not choose the numerically highest generation by scanning the filesystem.

### 18.4 Explicit CURRENT repair

If CURRENT is missing or corrupt, ordinary open fails.

An explicit repair command MAY scan StoreManifest files and select a candidate only when:

- the complete predecessor chain is valid;
- generations are contiguous;
- all referenced files verify;
- repository_genesis_id is identical;
- there is exactly one highest valid candidate chain.

If multiple incomparable candidates exist, repair requires operator choice and MUST NOT guess.

Repair publishes the selected manifest through the normal atomic CURRENT replacement sequence.

## 19. Compaction and garbage collection

### 19.1 Snapshot phase

Compaction and GC may perform expensive mark and pack-building work without holding the writer lock.

They first acquire a read snapshot containing:

- StoreManifestId;
- all logical root RefUpdateIds included in the operation;
- policy and keyring roots;
- reflog retention boundary;
- pin and merge-request refs;
- promised-object metadata relevant to the clone.

The snapshot generation is held through pack construction.

### 19.2 Publication validation

Before publication, the maintenance operation acquires the writer lock and re-reads:

- CURRENT;
- every logical root ref;
- retention configuration that affects reachability.

If any value differs from the maintenance snapshot, publication is aborted and recomputed. The baseline implementation does not incrementally patch an out-of-date GC mark set.

### 19.3 Replacement pack publication

After validation:

1. verify all replacement packs and indexes;
2. recover and close the current active segment;
3. build a verified sealed pack for complete records from that active segment, deduplicating against the replacement set;
4. create and synchronize the next-generation active segment;
5. synchronize all replacement/segment packs and their directory;
6. create and synchronize a new StoreManifest generation containing the replacement set, the closed-segment records, and the new active segment;
7. publish CURRENT atomically;
8. synchronize `.eternal`;
9. release writer lock;
10. obtain exclusive locks for obsolete generations before retirement;
11. move obsolete files to trash;
12. delete trash only under configured retention and platform rules.

### 19.4 No physical-pack references in commits

RepoCommits reference logical record IDs, not pack paths.

Changing pack layout does not change:

- VersionId;
- RepoCommitId;
- RefUpdateId;
- SMT root;
- ContentManifestId.

### 19.5 Encrypted encoding retention

For each reachable private ChunkId, GC MUST preserve at least one verified usable EncodedChunk.

An old key-epoch encoding is removed only after a replacement encoding under the accepted epoch has been completely written, authenticated, published in the physical store, and proven readable.

A promised but locally absent chunk is not treated as corruption and has no local encoding to collect.

## 20. Synchronization receive transaction

### 20.1 Quarantine

Network bytes are received outside the writer lock into a quarantine path:

```text
.eternal/objects/incoming/<session-id>/
```

Incoming files are not visible through CURRENT and are not trusted.

### 20.2 Verification before publication

Before physical publication, the receiver verifies:

- physical pack and index format;
- pack/index binding;
- all RecordIds;
- signed envelopes and signer keys;
- repository_id;
- RepositoryGenesis identity;
- policy chain and authorization;
- RepoCommit transitions;
- SMT roots;
- ContentManifest structure;
- required metadata closure;
- declared partial-clone promises.

Unknown or unauthorized records may remain quarantined temporarily but cannot be published as a ref target.

### 20.3 Physical import

To import a verified incoming pack:

1. acquire writer lock;
2. revalidate current StoreManifest and repository identity;
3. deduplicate against existing RecordIds;
4. copy or materialize canonical temporary pack/index files in the destination pack directory;
5. recover and close the current active segment;
6. build a verified sealed pack for complete records from that active segment, deduplicating against the imported and existing pack set;
7. create and synchronize the next-generation active segment;
8. synchronize final pack/index files and the pack directory;
9. create and synchronize a new StoreManifest generation including the imported pack, the closed-segment records, the retained pack set, and the new active segment;
10. publish CURRENT;
11. synchronize `.eternal`;
12. release writer lock.

This makes records physically available but does not update refs.

### 20.4 Remote ref CAS

After physical import, the receiver performs a separate logical ref transaction:

1. acquire writer lock;
2. read current ref pointer;
3. validate expected predecessor RefUpdateId;
4. revalidate target graph and current authorization;
5. append the incoming or locally created RefUpdate if not already stored;
6. ensure its append batch is durable;
7. atomically replace ref pointer;
8. synchronize ref directory;
9. release writer lock.

If CAS fails, imported immutable records remain physically available and logically unreachable until another ref references them or GC removes them.

### 20.5 Network ambiguity

If a network client disconnects around CAS, it treats the result as ambiguous and queries the remote ref chain using the expected RefUpdateId.

The server MUST make ref update requests idempotent by RefUpdateId:

- requesting publication of the already-current RefUpdate succeeds;
- requesting a RefUpdate already present in the predecessor history reports already-applied;
- requesting a conflicting successor fails CAS.

## 21. Partial clone publication

### 21.1 Metadata completeness

A partial clone may publish a logical ref only after all logical metadata is present:

- genesis;
- policies and public keys;
- keyring metadata permitted to the node;
- commits;
- RefUpdates;
- ObjectVersions;
- ContentManifests;
- SMT nodes.

Interest filters affect EncodedChunk prefetch only.

### 21.2 Promise installation

Before ref publication, every omitted ChunkId must be associated with at least one promisor remote in local non-authoritative promise metadata.

Promise metadata must be made durable before the ref pointer is replaced.

If promise metadata is lost, logical verification remains possible, but content availability is degraded and must be reconstructed from configured remotes.

### 21.3 On-demand fetch

An on-demand chunk fetch uses the synchronization quarantine and physical import protocol. It does not create a RepoCommit or RefUpdate because logical state does not change.

## 22. Error handling

### 22.1 Transaction errors

Implementations SHOULD expose distinct errors for:

- `WriteConflict`;
- `PredicateConflict`;
- `PolicyChanged`;
- `KeyringChanged`;
- `AuthorizationDenied`;
- `RefCasFailed`;
- `CommitOutcomeUnknown`;
- `DurabilityUnsupported`;
- `ActiveSegmentCorrupt`;
- `CommittedStorageCorruption`;
- `StoreManifestConflict`;
- `GenerationChanged`;
- `PromisedContentMissing`;
- `CacheDegraded`;
- `ResourceLimitExceeded`.

### 22.2 No compensating ref rollback

Once ref rename may have succeeded, error handling MUST NOT move the ref backward as compensation.

Any later reversal is a new signed RefUpdate and, when object state changes, a new RepoCommit.

### 22.3 Error precedence

When multiple failures occur, the returned error must preserve publication ambiguity.

For example, if ref rename succeeds, ref-directory synchronization fails, and cache update also fails, the result is `CommitOutcomeUnknown`, not `CacheDegraded`.

## 23. Durability modes and group commit

### 23.1 Strict durability

Strict durability is the normative default.

A strict logical transaction requires:

- active segment synchronization before ref rename;
- temporary ref synchronization before rename;
- ref directory synchronization after rename.

A strict physical-layout transaction requires:

- every new physical file synchronized;
- containing directories synchronized;
- StoreManifest synchronized;
- CURRENT file and `.eternal` directory synchronized.

### 23.2 Group commit

An implementation MAY group multiple prepared transactions for performance only if it preserves the same ordering guarantees.

It MAY batch active-segment synchronization across multiple complete append batches. It MUST NOT batch away the required durable pointer publication of an individual transaction.

For transactions on the same ref:

- successor order is serialized;
- all record batches may be covered by one segment synchronization;
- each ref rename is followed by ref-directory synchronization before the next successor is acknowledged;
- a failure may commit only an acknowledged ordered prefix plus at most one ambiguous successor.

For transactions on different refs, each ref CAS and publication result remains independent. Directory synchronization MUST be performed so that each returned result can be classified as committed, aborted, or ambiguous.

The API reports the result of every transaction separately.

### 23.3 Non-durable benchmark mode

A benchmark-only mode may omit or batch durability operations, but it MUST:

- be explicitly named non-durable;
- never be the CLI default;
- never claim crash consistency;
- be impossible to enable accidentally through repository data.

## 24. Crash outcome tables

### 24.1 Logical transaction

| Crash point | Allowed recovered logical state | Residue |
|---|---|---|
| during prepared chunk computation | old | temporary memory/files |
| during prewrite record frame | old | tail truncated |
| after prewrite TransactionEnd, before fsync | old | batch may survive as orphan |
| after prewrite fsync | old | durable orphan content |
| during final record frames | old | final tail truncated |
| after final TransactionEnd, before segment fsync | old | final batch may survive as orphan |
| after segment fsync, before ref temp write | old | durable orphan graph |
| during ref temp write | old | ignored temp file |
| after ref temp fsync, before rename | old | ignored temp file |
| after ref rename, before ref-dir fsync | old or new | ambiguous publication |
| after ref-dir fsync | new | possible stale cache |
| during cache update | new | cache rebuilt later |

No row permits a ref to expose only part of the new immutable graph.

### 24.2 Physical layout transaction

| Crash point | Allowed CURRENT | Residue |
|---|---|---|
| during pack/index build | old | tmp files |
| after pack/index fsync, before final names | old | tmp files |
| after final pack names, before manifest | old | unreferenced packs |
| during StoreManifest write | old | temp/unreferenced manifest |
| after StoreManifest fsync, before CURRENT rename | old | complete unreferenced generation |
| after CURRENT rename, before `.eternal` sync | old or new | both generations remain valid |
| after `.eternal` sync | new | old files retained |
| during old-file retirement | new | trash or old files |

### 24.3 Initialization

| Crash point | Allowed result |
|---|---|
| before final directory rename | no repository; temporary root may remain |
| after directory rename, before parent sync | absent or complete repository |
| after parent sync | complete repository |

## 25. Failpoint test matrix

### 25.1 Byte-boundary segment tests

For generated transactions of representative sizes, tests MUST terminate the process or truncate the active segment at every byte boundary across:

- frame header;
- RecordId;
- payload length;
- payload;
- frame CRC;
- TransactionEnd payload;
- TransactionEnd CRC.

Writable recovery must truncate to the last valid TransactionEnd boundary and preserve all earlier committed refs.

### 25.2 Logical publication failpoints

Inject failure immediately before and after:

1. each final frame append;
2. TransactionEnd append;
3. active segment synchronization;
4. final ref predecessor re-read;
5. temporary ref creation;
6. temporary ref write completion;
7. temporary ref synchronization;
8. ref rename;
9. ref-directory synchronization;
10. index cache transaction.

Each recovery must expose old or new logical state according to Section 24.1.

### 25.3 Physical publication failpoints

Inject failure immediately before and after:

1. old segment close;
2. pack write;
3. index write;
4. pack synchronization;
5. index synchronization;
6. final pack rename;
7. final index rename;
8. pack-directory synchronization;
9. new active-segment creation;
10. new active-segment synchronization;
11. StoreManifest write;
12. StoreManifest synchronization;
13. StoreManifest final rename;
14. manifest-directory synchronization;
15. CURRENT temporary write;
16. CURRENT temporary synchronization;
17. CURRENT rename;
18. `.eternal` synchronization;
19. exclusive old-generation lock acquisition;
20. old-file move to trash;
21. trash deletion.

### 25.4 Concurrency tests

Tests MUST cover:

- two writers racing on the same ref;
- two writers changing unrelated objects with ObjectSnapshot rebase;
- two writers changing the same object;
- policy revocation during content preparation;
- keyring rotation during encrypted content preparation;
- HEAD switch during read snapshot acquisition;
- ref update during snapshot acquisition;
- sealing during snapshot acquisition;
- GC publication while readers pin the old generation;
- branch delete/recreate ABA attempts;
- sync CAS retry after connection loss.

### 25.5 Required assertions

Every crash/concurrency test must assert:

- every visible pointer file is syntactically complete;
- every visible RefUpdate verifies and matches its ref path;
- every visible target commit closure is complete or validly promised;
- every visible RepoCommit transition recomputes;
- every visible SMT root verifies;
- CURRENT names one complete StoreManifest generation;
- no published pack/index pair disagrees;
- cache deletion does not change logical results;
- no operation reports definite failure when the expected RefUpdate is durably current;
- no operation reports definite success before required directory synchronization.

## 26. Transaction API requirements

### 26.1 Preparation and lock-scoped transaction API

Unbounded content work uses a preparation API that returns immutable prepared-content handles. The final batch API is lock-scoped and conceptually equivalent to:

```rust
pub fn transaction<F, T>(
    &mut self,
    plan: WritePlan,
    operation: F,
) -> Result<TransactionCommit<T>>
where
    F: FnOnce(&mut Transaction) -> Result<T>;
```

The implementation acquires the writer lock before invoking the bounded final closure and releases it only after the transaction commits or aborts. The closure may register object reads, writes, deletes, rollbacks, and already prepared content handles. It MUST NOT perform unbounded stream input, network I/O, password prompting, or other indefinite waits.

The transaction publishes one RepoCommit and one RefUpdate on success.

### 26.2 Streaming put

`put_stream` must not buffer the entire object.

It returns success only after final logical publication. Prepared chunk batches are internal implementation details.

If publication conflicts after content preparation, the API returns a conflict while leaving prepared chunks as reusable or GC-eligible immutable records.

### 26.3 Expected-version operations

Mutation APIs SHOULD accept an explicit expected current VersionId or expected absence.

CLI operations obtain this expectation from their opening snapshot and fail on conflicting changes rather than silently replacing them.

### 26.4 Commit result

A successful logical commit result includes:

```rust
struct TransactionCommit<T> {
    value: T,
    repo_commit_id: RepoCommitId,
    ref_update_id: RefUpdateId,
    cache_status: CacheStatus,
}
```

Object mutations additionally return their resulting VersionIds.

### 26.5 Cancellation

Cancellation before final segment synchronization aborts publication and leaves at most temporary data or incomplete trailing frames.

Cancellation after final segment synchronization but before ref publication leaves durable orphans.

Cancellation is disabled or deferred during the short interval from ref rename through ref-directory synchronization so that the API can accurately classify the outcome.

## 27. Security properties of transaction ordering

The required ordering prevents:

- refs pointing to unwritten content;
- metadata-only commits whose chunks were never durable;
- ABA through branch deletion and recreation;
- policy self-authorization;
- stale authorization after key revocation;
- stale encrypted writes after keyring change;
- partial StoreManifest publication;
- use-after-delete of old packs by live readers;
- silent lost updates on the same object;
- accidental interpretation of untrusted incoming packs as repository state.

It does not prevent:

- rollback of an entire repository snapshot by an attacker controlling all local storage and no external trusted tip;
- loss after storage hardware falsely reports successful durability;
- malicious authorized writers creating semantically harmful but correctly signed records;
- physical recovery of deleted bytes from SSDs, snapshots, or backups;
- denial of service by a party able to exhaust disk space or hold filesystem locks.

## 28. Implementation checklist

Before transaction code is considered complete, the implementation must demonstrate:

- strict writer-lock serialization;
- cross-process generation pins;
- complete physical append-batch validation;
- large-object writes spanning multiple segment generations;
- object-level optimistic rebase without lost update;
- strict branch isolation for predicate and merge transactions;
- policy/keyring revalidation at publication;
- deterministic final RepoCommit transition;
- segment fsync before ref rename;
- ref-directory fsync before success;
- explicit ambiguous-outcome handling;
- synchronous baseline sealing;
- StoreManifest generation publication;
- old-generation reader protection;
- quarantine-first synchronization import;
- best-effort cache update with rebuild;
- byte-boundary crash recovery tests;
- fail-loud behavior on committed graph corruption.

## 29. Final transaction rule

The complete correctness rule is:

> Immutable records may become durable early and may remain orphaned, but no mutable logical pointer may expose them until the entire referenced graph is durable, authorized, validated against the current predecessor state, and published by an atomic predecessor-linked ref replacement. No physical file set may become authoritative until every named file is durable and an immutable StoreManifest is published through CURRENT.
