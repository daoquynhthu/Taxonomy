# EternalCore v4 Architecture

> Status: implementation baseline
>
> This document defines the authoritative architecture and on-disk model for the Rust rewrite of EternalCore. Where this document conflicts with older v4 drafts, this document wins.

## 1. Purpose and Scope

EternalCore is a content-addressed, cryptographically verifiable, distributed generic object persistence engine. It stores arbitrary binary content under user-defined object identifiers while preserving immutable history, authenticated authorship, branchable repository state, crash-safe local storage, selective content replication, and optional encrypted-at-rest payloads.

The architecture is built around one rule:

> EternalCore consists of immutable content-addressed records plus a deliberately tiny mutable control layer.

The immutable layer contains content, logical object versions, repository commits, policy records, keyring records, Sparse Merkle Tree nodes, and signed reference updates. The mutable layer contains only local pointers such as `CURRENT`, `HEAD`, and ref files. Every mutable pointer must reference an already durable immutable record.

### 1.1 Goals

EternalCore v4 must provide:

- immutable logical object history;
- deterministic canonical encoding and domain-separated identifiers;
- authenticated authorship and authorization;
- branchable repository state represented by signed commit DAGs;
- constant-depth authenticated state updates through a 256-level Sparse Merkle Tree;
- streaming storage and retrieval of very large objects;
- deterministic content-defined chunking and chunk-level deduplication;
- crash consistency without a general-purpose transactional database;
- rebuildable indices;
- explicit merge semantics without last-writer-wins behavior;
- metadata-complete partial clones with optional lazy content fetching;
- optional XChaCha20-Poly1305 encryption with a KEK/DEK/key-epoch model;
- structural verification, storage verification, and full logical-content audit as separate operations.

### 1.2 Non-goals

The following are not v4 goals:

- Byzantine consensus between mutually distrustful writers;
- automatic semantic conflict resolution;
- writable repositories on NFS, SMB, or filesystems without reliable advisory locks and atomic rename;
- trusted timestamps;
- guaranteed physical erasure on SSDs, copy-on-write filesystems, snapshots, or remote backups;
- cross-repository merge between unrelated `repository_id` values;
- SQL as an authoritative data model;
- transparent mutable-file semantics.

## 2. System Model and Invariants

### 2.1 Identity domains

EternalCore distinguishes three identities:

- `repository_id`: the logical identity of a repository. All clones of the same repository share it.
- `federation_id`: an administrative isolation boundary. Repositories in different federations do not synchronize directly.
- `node_id`: the identity of one physical working copy. Every clone has a distinct node ID.

A valid direct synchronization session requires:

```text
local.repository_id == remote.repository_id
local.federation_id == remote.federation_id
local.node_id != remote.node_id
```

Different repositories may exchange data only through an explicit import operation that creates new records under the destination `repository_id`.

### 2.2 Authoritative state

The authoritative logical state of a branch is:

```text
Ref file
  -> RefUpdateId
  -> signed RefUpdate
  -> RepoCommitId
  -> signed RepoCommit
  -> object_state_root
  -> Sparse Merkle Tree mapping ObjectId to VersionId
```

The authoritative physical storage state is:

```text
CURRENT
  -> immutable StoreManifest
  -> active segment and sealed pack/index set
```

The logical commit point is the atomic replacement of a ref file after all referenced immutable records have been durably written.

The physical-layout commit point is the atomic replacement of `CURRENT` after the replacement StoreManifest and all files it references are durable.

### 2.3 Required invariants

Every implementation must preserve all of the following:

1. A ref never points to a `RefUpdate` whose target graph is incomplete on local storage.
2. A `RepoCommit` state root is reproducible from its first parent state plus its ordered `changes` list.
3. Every logical authorization record is signed by the key named in its payload.
4. Every signed record includes `repository_id` in its signed payload.
5. Every immutable record has a deterministic record-specific identifier: unsigned records hash their deterministic payload encoding, while signed records use the domain hash of the inner signed payload and store the detached signature in the envelope.
6. Re-encryption or recompression never changes `ContentManifestId`, `VersionId`, or `RepoCommitId`.
7. A branch-sensitive query is always evaluated against an explicit state root obtained from `HEAD` or a named ref.
8. Cache loss never causes logical data loss.
9. A crash can leave unreachable immutable records, but cannot expose a ref to a partially durable object graph.
10. A reader accepts only complete frames whose CRC and record identifier both verify.

## 3. Repository Bootstrap and Authority

### 3.1 RepositoryGenesis

Each repository begins with one signed `RepositoryGenesis` record.

```text
RepositoryGenesisPayload {
    format_version: u16,
    repository_id: UUID,
    federation_id: UUID,
    creator_key_id: KeyId,
    creator_public_key: [u8; 32],
    initial_policy_id: PolicyId,
    initial_keyring_id: KeyringId,
    created_at_ns: i64,
}
```

The creator signs the genesis payload. The embedded creator public key provides the trust bootstrap required to validate the initial policy. The `repository_id` is generated before the initial policy and keyring records are created, so no identity cycle exists.

### 3.2 Node configuration

Local-only configuration lives in `.eternal/config.toml` and contains:

- `node_id`;
- remote endpoints;
- local branch preference;
- local cache settings;
- performance limits;
- password-slot configuration references;
- promisor remote configuration.

It is not authoritative for repository identity, permissions, branch state, or cryptographic key history.

### 3.3 PolicyRecord

Authorization is represented by an immutable signed policy chain.

```text
PolicyRecordPayload {
    format_version: u16,
    repository_id: UUID,
    previous_policy_id: Option<PolicyId>,
    policy_sequence: u64,
    administrators: Set<KeyId>,
    writers: Set<KeyId>,
    per_ref_permissions: Map<RefPattern, Set<KeyId>>,
    tag_creators: Set<KeyId>,
    revoked_keys: Set<KeyId>,
    created_at_ns: i64,
    author_key_id: KeyId,
}
```

Rules:

- the initial policy has no predecessor and is signed by the genesis creator;
- each later policy must be signed by an administrator authorized by the previous policy;
- `policy_sequence` increments by exactly one;
- removing or revoking a key affects future authorization only;
- historical public keys remain available permanently so historical signatures remain verifiable;
- `trusted_keys/` may exist as a local cache, but it is rebuilt from the policy chain and is never authoritative;
- every `RepoCommit` records the policy state that becomes current after that commit; authorization of the transition is always evaluated against the first parent commit's policy, preventing a commit from authorizing itself.

### 3.4 KeyringRecord

Repository encryption state is represented by an immutable signed keyring chain.

```text
KeyringRecordPayload {
    format_version: u16,
    repository_id: UUID,
    previous_keyring_id: Option<KeyringId>,
    key_epoch: u64,
    content_id_key_slots: Vec<KeySlot>,
    dek_slots: Vec<WrappedDek>,
    retired_key_epochs: Set<u64>,
    created_at_ns: i64,
    author_key_id: KeyId,
}
```

A repository without payload encryption still has an initial empty keyring record. Every `RepoCommit` records the keyring state against which its encrypted content mappings were created.

## 4. Canonical Encoding, Hashing, and Signed Envelopes

### 4.1 Deterministic encoding

All protocol and on-disk logical records use RFC 8949 deterministic CBOR with the following restrictions:

- no indefinite-length arrays, maps, byte strings, or text strings;
- shortest valid integer representation;
- no floating-point values in authoritative records;
- unique map keys;
- fixed integer field keys defined in `FORMAT.md`;
- maps emitted in deterministic encoded-key order;
- UTF-8 text must be valid and preserved byte-for-byte; EternalCore does not silently normalize Unicode;
- unknown mandatory fields cause rejection; explicitly designated extension maps may preserve unknown optional fields.

User metadata is represented by `CanonicalValue`:

```rust
pub enum CanonicalValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<CanonicalValue>),
    Map(BTreeMap<String, CanonicalValue>),
}
```

Decimal values must be stored as application-defined canonical strings. JSON input is accepted by the CLI only after conversion into `CanonicalValue`; JSON floating-point numbers are rejected unless supplied as strings.

### 4.2 Domain-separated identifiers

The generic hash construction is:

```text
DomainHash = SHA-256(
    u16_le(domain_tag_length) ||
    domain_tag_utf8 ||
    u64_le(payload_length) ||
    payload
)
```

No platform-sized integer may enter the hash preimage.

Important domain tags include:

| Record or context | Domain tag |
|---|---|
| Repository genesis | `EternalCore:RepositoryGenesis:v1` |
| Policy record | `EternalCore:PolicyRecord:v1` |
| Keyring record | `EternalCore:KeyringRecord:v1` |
| Public chunk ID | `EternalCore:PublicChunk:v1` |
| Encrypted chunk ID HMAC context | `EternalCore:PrivateChunk:v1` |
| Encoded chunk | `EternalCore:EncodedChunk:v1` |
| Content manifest | `EternalCore:ContentManifest:v1` |
| Object version | `EternalCore:ObjectVersion:v1` |
| Repository commit | `EternalCore:RepoCommit:v1` |
| Reference update | `EternalCore:RefUpdate:v1` |
| Object key | `EternalCore:ObjectKey:v1` |
| SMT empty leaf | `EternalCore:SMTEmptyLeaf:v1` |
| SMT leaf | `EternalCore:SMTLeaf:v1` |
| SMT internal node | `EternalCore:SMTInternal:v1` |
| Active-segment frame | `EternalCore:SegmentFrame:v1` |
| Pack checksum | `EternalCore:Pack:v1` |
| Pack index checksum | `EternalCore:PackIndex:v1` |
| Store manifest | `EternalCore:StoreManifest:v1` |

### 4.3 SignedRecord envelope

Logical authorization records use detached signatures:

```rust
pub struct SignedRecord<P> {
    pub payload: P,
    pub record_id: DomainHash,
    pub signer_key_id: KeyId,
    pub signature: Signature,
}
```

Construction:

```text
record_id = domain_hash(record_domain, deterministic_cbor(payload))
signature = Ed25519.sign(signing_key, record_id)
```

Validation requires:

- recomputed record ID equals the stored record ID;
- `payload.author_key_id == signer_key_id` where the payload has an author field;
- the public key fingerprint equals `signer_key_id`;
- signature verification succeeds;
- the relevant policy authorizes the signer for the attempted operation.

Signatures never participate in the identifier of the payload they authenticate, avoiding self-reference. In physical frames, a signed record's frame `record_id` equals the inner payload `record_id`; validation parses the envelope and recomputes the identifier from the inner payload rather than hashing the envelope as a whole.

## 5. Logical Content Model

### 5.1 ObjectId

`ObjectId` is a semantic identifier supplied by the caller.

Rules:

- UTF-8;
- 1 to 1024 bytes;
- allowed characters in v4 core: ASCII letters, digits, `_`, `-`, `.`, and `/`;
- no leading `/`;
- no empty path segment;
- no `.` or `..` segment;
- no trailing `/`;
- canonical representation is the exact validated UTF-8 byte sequence.

The SMT key is:

```text
ObjectKey = domain_hash("EternalCore:ObjectKey:v1", object_id_bytes)
```

### 5.2 Deterministic content-defined chunking

All non-empty payloads are split using versioned deterministic FastCDC parameters:

```text
minimum chunk size: 1 MiB
average chunk size: 4 MiB
maximum chunk size: 8 MiB
gear table: fixed by FORMAT.md
normalization level: fixed by FORMAT.md
algorithm version: 1
```

The exact gear table and cut-point rules are part of the stable format specification and golden-vector suite.

An empty object has:

```text
total_size = 0
chunks = []
```

No zero-length chunk record is created.

### 5.3 ChunkId

Chunk identity is calculated over raw chunk bytes and never includes the chunk position.

For unencrypted repositories or explicitly public content:

```text
ChunkId = domain_hash("EternalCore:PublicChunk:v1", raw_chunk_bytes)
```

For encrypted content:

```text
ChunkId = HMAC-SHA256(
    ContentIdKey,
    "EternalCore:PrivateChunk:v1" || raw_chunk_bytes
)
```

The keyed form provides deterministic within-repository deduplication without exposing a public plaintext hash suitable for offline dictionary attacks.

### 5.4 EncodedChunk

`EncodedChunk` is a physical representation of one logical chunk.

```text
EncodedChunkPayload {
    format_version: u16,
    repository_id: UUID,
    chunk_id: ChunkId,
    plaintext_length: u64,
    codec: CodecDescriptor,
    encryption: Option<EncryptionDescriptor>,
    encoded_bytes: bytes,
}
```

Supported codecs in v4:

```text
none
zstd(level, implementation_profile)
```

The zstd profile, level range, and deterministic encoder settings are fixed in `FORMAT.md`.

An encoded chunk is addressed by:

```text
EncodedChunkRecordId = domain_hash(
    "EternalCore:EncodedChunk:v1",
    deterministic_cbor(payload)
)
```

One `ChunkId` may have multiple encoded representations. The storage cache maps:

```text
ChunkId -> [EncodedChunkRecordId]
EncodedChunkRecordId -> PhysicalLocation
```

### 5.5 ContentManifest

`ContentManifest` describes logical content only.

```text
ContentManifestPayload {
    format_version: u16,
    repository_id: UUID,
    chunking_scheme: ChunkingDescriptor,
    total_size: u64,
    chunks: [
        {
            chunk_id: ChunkId,
            plaintext_length: u64,
        }
    ],
    content_root: ContentRoot,
}
```

`content_root` is a domain-separated Merkle root over the ordered sequence of `(chunk_id, plaintext_length)` leaves. The empty-content root is a fixed golden-vector value.

The manifest contains no codec, nonce, key ID, ciphertext identifier, or pack location. Therefore recompression and re-encryption do not change the manifest identifier.

```text
ContentManifestId = domain_hash(
    "EternalCore:ContentManifest:v1",
    deterministic_cbor(payload)
)
```

### 5.6 ObjectVersion

`ObjectVersion` is the authoritative record for one logical mutation of one object.

```text
ObjectVersionPayload {
    format_version: u16,
    repository_id: UUID,
    object_id: ObjectId,
    content_manifest_id: Option<ContentManifestId>,
    parents: Vec<VersionId>,
    data_type: String,
    metadata: CanonicalValue,
    relations: Vec<Relation>,
    tombstone: bool,
    created_at_ns: i64,
    author_key_id: KeyId,
}
```

```text
Relation {
    target_object_id: ObjectId,
    relation_type: String,
}
```

Rules:

- first version: `parents = []`;
- normal update: exactly one parent, equal to the current version at the transaction base state;
- conflict-resolving version: two or more parents;
- tombstone version: `tombstone = true` and `content_manifest_id = None`;
- non-tombstone version: `content_manifest_id` is required;
- relations form the complete relation set for that version;
- relation targets are soft references and may be absent or tombstoned;
- `created_at_ns` is an authenticated declaration, not trusted time;
- numeric persistent version numbers do not exist.

The signed payload ID is the `VersionId`.

A CLI may display first-parent path positions such as “version 7,” but those numbers are local presentation values and never enter APIs, storage, signatures, or synchronization.

## 6. Authenticated Repository State

### 6.1 Sparse Merkle Tree

Each branch state is represented by a 256-level Sparse Merkle Tree mapping:

```text
ObjectKey -> VersionId
```

The tree has fixed depth 256. Update cost is therefore 256 path steps, independent of the number of objects.

#### Empty hashes

```text
empty[256] = domain_hash("EternalCore:SMTEmptyLeaf:v1", empty_bytes)
empty[d] = domain_hash(
    "EternalCore:SMTInternal:v1",
    empty[d + 1] || empty[d + 1]
)
```

#### Leaf hash

```text
leaf_hash = domain_hash(
    "EternalCore:SMTLeaf:v1",
    object_key || version_id
)
```

#### Internal node hash

```text
node_hash = domain_hash(
    "EternalCore:SMTInternal:v1",
    left_child_hash || right_child_hash
)
```

Non-default leaves and internal nodes are stored as immutable content-addressed records. Nodes may use a compact physical encoding, but the logical hash remains the unambiguous left/right construction above.

The tree supports:

- point lookup;
- membership proof;
- non-membership proof;
- update with persistent structural sharing;
- recursive hash comparison for branch diff and merge.

### 6.2 RepoCommit

A repository commit records a state transition.

```text
RepoCommitPayload {
    format_version: u16,
    repository_id: UUID,
    parents: Vec<RepoCommitId>,
    changes: Vec<ObjectChange>,
    object_state_root: SmtRoot,
    policy_id: PolicyId,
    keyring_id: KeyringId,
    created_at_ns: i64,
    message: String,
    author_key_id: KeyId,
}

ObjectChange {
    object_id: ObjectId,
    old_version_id: Option<VersionId>,
    new_version_id: VersionId,
}
```

Rules:

- `changes` are sorted by canonical `ObjectId` bytes and contain no duplicate object ID;
- for a single-parent commit, each `old_version_id` must match the value in the first parent state;
- for a merge commit, `parent[0]` is the state baseline and all `changes` apply to that baseline;
- extra parents record incorporated history but are not ambiguous state baselines;
- a genesis commit has no parent and uses the empty SMT root as its baseline;
- applying all `changes` to the baseline must reproduce `object_state_root` exactly;
- every new `VersionId` must resolve to a valid signed `ObjectVersion` whose `object_id` matches the change entry;
- `changes` may be empty for an administrative commit that advances policy or keyring state without changing object state;
- for a non-genesis commit, the signer and eventual ref update are authorized under the first parent's policy, not the new `policy_id`;
- a changed `policy_id` must extend the first parent's policy chain by one valid administrator-authorized transition;
- a changed `keyring_id` must extend the first parent's keyring chain and be authorized under the first parent's policy.

`RepoCommit` contains no ref update, avoiding identifier self-reference.

### 6.3 RefUpdate

A mutable ref file points to an immutable signed `RefUpdate`.

```text
RefUpdatePayload {
    format_version: u16,
    repository_id: UUID,
    ref_name: String,
    previous_ref_update_id: Option<RefUpdateId>,
    target_commit_id: RepoCommitId,
    sequence: u64,
    created_at_ns: i64,
    author_key_id: KeyId,
}
```

Rules:

- first update: `previous_ref_update_id = None`, `sequence = 1`;
- every later update increments sequence by exactly one;
- CAS compares the current `RefUpdateId`, not only the target commit, preventing ABA;
- for an existing ref, the policy pinned by the predecessor RefUpdate's target commit must authorize the signer for `ref_name`; for first creation, the valid policy pinned by the target commit governs namespace creation, and that target commit must itself pass the parent-policy transition rules;
- `refs/tags/*` are create-only in v4 core;
- branch deletion creates an explicit signed deletion update in the ref log and then removes the mutable pointer;
- ref history remains reachable through the `previous_ref_update_id` chain and the local reflog retention roots.

### 6.4 HEAD

`.eternal/HEAD` contains one symbolic ref name, normally:

```text
refs/heads/main
```

HEAD is a local working-copy preference and is not synchronized.

## 7. Physical Storage Architecture

### 7.1 Repository layout

```text
<repo>/
└── .eternal/
    ├── HEAD
    ├── CURRENT
    ├── config.toml
    ├── write.lock
    │
    ├── manifests/
    │   └── store-<generation>-<manifest-id>.cbor
    │
    ├── objects/
    │   ├── active/
    │   │   └── segment-<generation>-<uuid>.seg
    │   ├── packs/
    │   │   ├── pack-<checksum>.pack
    │   │   └── pack-<checksum>.idx
    │   ├── tmp/
    │   └── trash/
    │
    ├── refs/
    │   ├── heads/
    │   ├── tags/
    │   ├── pins/
    │   ├── merge-requests/
    │   └── logs/
    │
    ├── identity/
    │   ├── signing-public.key
    │   ├── signing-private.enc
    │   ├── encryption-public.key
    │   └── encryption-private.enc
    │
    └── index.db
```

### 7.2 Record types

The physical store can contain the following immutable records:

| Code | Record type |
|---:|---|
| 1 | RepositoryGenesis |
| 2 | PolicyRecord |
| 3 | KeyringRecord |
| 4 | EncodedChunk |
| 5 | ContentManifest |
| 6 | ObjectVersion |
| 7 | SMT leaf |
| 8 | SMT internal node |
| 9 | RepoCommit |
| 10 | RefUpdate |
| 11 | TransactionEnd |

All signed logical records are stored as deterministic `SignedRecord` envelopes.

### 7.3 Active segment

The active segment is the only append destination.

#### Header

```text
magic:              8 bytes = "ETSEG\0\0\0"
format_version:     u16 LE
repository_id:      16 bytes
segment_id:         UUID
store_generation:   u64 LE
created_at_ns:      i64 LE
header_crc32c:      u32 LE
```

#### Frame

```text
record_type:        u8
record_id:          [u8; 32]
payload_length:     u64 LE
payload:            [u8; payload_length]
frame_crc32c:       u32 LE
```

The frame CRC covers:

```text
record_type || record_id || payload_length || payload
```

A reader accepts a frame only if:

- the full frame is present;
- CRC32C verifies;
- the record-specific identifier verifies: unsigned payloads are hashed directly, while signed envelopes are parsed and checked against the hash of their inner payload;
- type and payload schema agree;
- configured size limits are satisfied.

An incomplete trailing frame is ignored by readers. It is physically truncated only during recovery while holding the writer lock.

#### TransactionEnd

Every logical transaction ends with:

```text
TransactionEndPayload {
    format_version: u16,
    repository_id: UUID,
    transaction_id: UUID,
    first_frame_offset: u64,
    end_frame_offset: u64,
    record_count: u64,
    record_ids_root: DomainHash,
}
```

`TransactionEnd` is not the logical commit point; it proves that the immutable record batch was fully appended before the segment fsync.

### 7.4 Sealed pack

A pack contains immutable records only.

#### Pack layout

```text
Header
  magic:              8 bytes = "ETPACK\0\0"
  format_version:     u16 LE
  repository_id:      16 bytes
  record_count:       u64 LE

Record frames
  record_type:        u8
  record_id:          [u8; 32]
  payload_length:     u64 LE
  payload
  frame_crc32c:       u32 LE

Trailer
  pack_checksum:      [u8; 32]
```

The pack checksum covers the entire file with the checksum field treated as zero.

Pack filenames are:

```text
pack-<pack-checksum-hex>.pack
```

Packs are never modified after publication.

### 7.5 External pack index

Each pack has one external index:

```text
magic
format_version
repository_id
pack_checksum
record_count
fanout[256]              // cumulative u64 counts by first record-ID byte
sorted_record_ids[]      // [32] bytes each
record_types[]           // u8 each
offsets[]                // u64 each
payload_lengths[]        // u64 each
frame_crc32c[]           // u32 each
index_checksum
```

The index checksum is domain-separated and binds the corresponding pack checksum. Every offset is 64-bit from format version 1.

### 7.6 StoreManifest and CURRENT

A StoreManifest describes one complete physical layout generation.

```text
StoreManifestPayload {
    format_version: u16,
    repository_id: UUID,
    generation: u64,
    previous_manifest_id: Option<StoreManifestId>,
    active_segment: SegmentDescriptor,
    sealed_packs: Vec<PackDescriptor>,
    created_at_ns: i64,
}
```

`sealed_packs` are sorted by pack checksum.

`CURRENT` contains exactly one StoreManifest filename followed by a newline. It is replaced atomically using a temporary file, fsync, rename, and parent-directory fsync.

Only files referenced by the current StoreManifest participate in normal reads and index rebuild. Unreferenced files in `tmp/`, `trash/`, or the object directory are not automatically trusted.

## 8. Transactions and Crash Consistency

### 8.1 Single-object write transaction

A normal `put`, `delete`, or `rollback` performs:

1. acquire the repository advisory writer lock;
2. read `HEAD`, current ref file, current `RefUpdate`, and base `RepoCommit`;
3. validate the caller against the active policy;
4. stream and chunk input content if applicable;
5. write any missing `EncodedChunk` records;
6. write `ContentManifest` if applicable;
7. write signed `ObjectVersion`;
8. persist new SMT path nodes;
9. write signed `RepoCommit`;
10. write signed `RefUpdate` whose predecessor is the current ref update;
11. append `TransactionEnd`;
12. fsync the active segment;
13. write a temporary ref file containing the new `RefUpdateId`;
14. fsync the temporary ref file;
15. atomically replace the ref file;
16. fsync the ref directory;
17. update `index.db` as a best-effort cache operation;
18. release the writer lock.

Crash outcomes:

- before active-segment fsync: transaction does not exist;
- after segment fsync but before ref rename: durable unreachable records remain as GC-eligible orphans;
- after ref rename: the branch exposes the complete new state;
- cache failure never invalidates the transaction.

### 8.2 Batch transaction

The library exposes a transaction API that stages multiple object mutations against one base state and produces one `RepoCommit` plus one `RefUpdate`.

A batch transaction is process-local and must finish before the writer lock is released. v4 has no persistent cross-process staging area and no `--no-commit` mode.

### 8.3 Ref CAS

Before step 15, the implementation re-reads the ref file while still holding the writer lock and verifies that it contains the expected predecessor `RefUpdateId`. A mismatch aborts without changing the ref.

Network-side ref updates use the same predecessor-ID CAS rule at the receiving node.

### 8.4 Segment sealing

Sealing is synchronous in the baseline implementation:

1. acquire writer lock;
2. close and fsync current active segment;
3. build temporary pack and index from the closed segment;
4. verify all frames, identifiers, pack checksum, and index checksum;
5. fsync pack, index, and pack directory;
6. create and fsync a new active segment;
7. create and fsync the next StoreManifest generation;
8. atomically replace `CURRENT`;
9. fsync `.eternal`;
10. release writer lock;
11. move the old segment to `trash/`;
12. delete it only after no live reader pins the old StoreManifest generation.

### 8.5 Compaction and GC publication

Compaction and GC create replacement packs without modifying old packs. They publish the new pack set through a new StoreManifest generation, atomically switch `CURRENT`, then retire old files through `trash/`.

## 9. Concurrency and Read Snapshots

### 9.1 Writer locking

EternalCore uses an operating-system advisory lock handle on `.eternal/write.lock`.

- process exit releases the lock automatically;
- PID, node ID, and acquisition time may be written for diagnostics only;
- the application never breaks a lock solely because a PID appears dead or a timeout elapsed;
- writable operation on filesystems without reliable advisory locks and rename semantics fails loudly.

### 9.2 Reader snapshot

A branch read snapshot pins:

1. the current StoreManifest generation;
2. the symbolic ref named by HEAD or an explicit ref;
3. the current RefUpdateId;
4. the target RepoCommitId and state root.

All subsequent lookups use this pinned state root and physical store generation. A concurrent writer may publish a newer state, but the reader continues to observe a consistent older snapshot.

### 9.3 Active-segment reads

Readers may read complete verified frames from the active segment. They ignore an incomplete tail. A reader never treats an incomplete tail as repository corruption.

## 10. Object Operations

### 10.1 Put

`put` creates a new `ObjectVersion` whose parent is the current state value for the object, or no parent if the object is absent.

The result is:

```text
VersionId
RepoCommitId
RefUpdateId
```

### 10.2 Delete

Deletion creates a tombstone ObjectVersion. The SMT continues to map the object ID to that tombstone version, preserving authenticated deletion history.

### 10.3 Rollback

Rollback accepts a `VersionId` or an unambiguous prefix and creates a new version that reuses the historical `ContentManifestId`. Its parent is the current version. Rollback never moves state directly to an old version and never removes intervening history.

### 10.4 Relations

Relations are versioned metadata embedded in ObjectVersion. They are soft directed edges:

```text
source ObjectVersion -> target ObjectId + relation_type
```

A relation does not guarantee that the target exists, is non-tombstoned, or remains unchanged.

### 10.5 Listing and search

Search indices are caches keyed by state root. A query must always specify or derive a state root. No global branch-independent “latest object” index exists.

## 11. Cryptography and Key Management

### 11.1 Signatures

EternalCore uses Ed25519 through a maintained high-level library. Private signing keys are not stored unencrypted by default.

Preferred key backends:

1. operating-system key store;
2. hardware-backed key provider;
3. encrypted PKCS#8 file backend.

The public key file is stored in a documented raw or OpenSSH public-key format; the architecture does not call OpenSSH public-key text “PEM.”

### 11.2 Payload encryption

Chunk encryption uses XChaCha20-Poly1305 from a high-level AEAD implementation.

Each encrypted chunk uses:

- a random 192-bit nonce;
- a DEK associated with a key epoch;
- deterministic canonical AAD.

AAD contains:

```text
repository_id
format_version
chunk_id
plaintext_length
codec descriptor
encryption algorithm
key_epoch
```

Authentication failure is fatal for that encoding.

### 11.3 Key hierarchy

```text
password or recipient private key
        -> unwrap KEK slot
        -> unwrap ContentIdKey and DEKs
        -> decrypt EncodedChunk
```

Supported key slots:

- password slot using Argon2id-derived KEK;
- recipient slot using a dedicated X25519 encryption key;
- recovery slot using an offline recovery public key.

Signing keys and encryption keys are separate.

### 11.4 Password slots

A password slot stores:

```text
salt: 16 or more random bytes
Argon2id version
memory cost
iteration cost
parallelism
wrap nonce
wrapped secret
```

Setup calibrates Argon2id toward approximately 500 ms on the current machine, with a minimum memory cost of 64 MiB. The password is obtained through a secure terminal prompt or protected file descriptor, not a default environment variable.

### 11.5 Re-encryption

DEK rotation:

1. creates a new key epoch;
2. writes a new KeyringRecord;
3. creates new EncodedChunk records for reachable logical chunks;
4. verifies each new encoding;
5. creates an administrative RepoCommit with an empty `changes` list, the same `object_state_root`, and the new `keyring_id`;
6. leaves every existing ContentManifestId and VersionId unchanged;
7. allows later compaction to remove obsolete encodings after policy-defined retention.

Changing a password only rewraps secrets, creates a new KeyringRecord, and publishes it through an administrative RepoCommit with unchanged object state. Existing historical RepoCommitIds are never rewritten; the branch tip advances to a new administrative commit.

### 11.6 Security limits

EternalCore does not claim:

- trusted wall-clock time;
- rollback detection against an attacker who can replace the entire repository and all external trust anchors;
- secure physical deletion from SSD flash translation layers, snapshots, or backups;
- metadata confidentiality for ObjectId, data type, relations, and object-version records in a metadata-complete partial clone.

## 12. Branches, Merge, and Conflict Semantics

### 12.1 Branch model

Each branch is one mutable ref pointing to a signed RefUpdate. Multiple writers work on different branches. A branch update is serialized at its receiving node by ref CAS; EternalCore has no distributed lock.

### 12.2 Merge base

Merge finds the best common ancestor commit of `ours` and `theirs`. The state maps of base, ours, and theirs are compared recursively by SMT node hash.

### 12.3 Three-way object merge

For each changed ObjectId:

```text
ours == theirs   -> use ours
ours == base     -> use theirs
theirs == base   -> use ours
otherwise        -> conflict
```

Tombstone VersionIds participate exactly like any other VersionId.

### 12.4 Conflict handling

If any conflict remains:

- no merge RepoCommit is created;
- no ref moves;
- a structured conflict report is returned;
- the user or calling application creates resolving ObjectVersions;
- each resolving ObjectVersion lists both conflicting VersionIds as parents.

The final merge commit has:

```text
parents[0] = current branch tip
parents[1] = source branch tip
changes = resolved delta applied to parent[0]
object_state_root = resolved state
```

EternalCore never creates synthetic “conflict refs” that point to an object version.

## 13. Distributed Synchronization

### 13.1 Trust and handshake

A network session establishes:

- protocol version and feature negotiation;
- mutual challenge-response authentication;
- local and remote node IDs;
- repository and federation identity;
- transport limits;
- promisor and partial-clone capabilities.

Authentication proves possession of an allowed node key. Authorization to update a ref is evaluated separately from the target commit policy and ref permissions.

### 13.2 Negotiation

Peers exchange:

- ref names and current RefUpdateIds;
- target RepoCommitIds;
- known Store-independent RecordIds as needed;
- protocol feature sets.

Missing logical history is discovered by walking the commit DAG to a common ancestor. EternalCore does not exchange the complete set of all object hashes.

### 13.3 Metadata-complete partial clone

Selective sync always transfers enough logical metadata to validate repository state:

- RepositoryGenesis;
- PolicyRecord chain required by fetched commits;
- public KeyringRecord metadata;
- RefUpdates;
- RepoCommits;
- required SMT nodes;
- ObjectVersions;
- ContentManifests.

Interest filters control prefetch of `EncodedChunk` records only.

A missing content chunk is recorded as promised by a named promisor remote. The local repository can verify branch state and metadata while deferring chunk download until `get` or explicit prefetch.

### 13.4 Content transfer

Content transfer is streamed and bounded. The protocol defines:

- maximum frame size;
- maximum requested identifiers per batch;
- backpressure;
- cancellation;
- pack checksum;
- resumable transfer token;
- per-session byte and object limits.

The receiver validates frame CRC, RecordId, repository identity, schema, and applicable signatures before publishing records into the active segment.

### 13.5 Ref update

A remote ref update request contains:

```text
ref_name
expected_previous_ref_update_id
new_ref_update_id
```

The receiver verifies:

1. all records required by the new target commit exist locally or are valid promised content;
2. signed-record integrity;
3. policy-chain validity;
4. commit state transition;
5. ref permission;
6. predecessor-ID CAS.

Only then may it replace the ref file.

### 13.6 Same-repository requirement

Direct push, pull, and merge require equal `repository_id`. Importing from another repository creates destination-native ObjectVersions and does not preserve source signatures as destination authorization; source records may be retained as provenance metadata.

## 14. Cache and Index Architecture

`index.db` is a rebuildable `redb` cache. Recommended tables:

```text
record_location:
    RecordId -> {store_generation, file_id, offset, length, record_type}

chunk_encodings:
    ChunkId -> [EncodedChunkRecordId]

ref_cache:
    RefUpdateId -> {ref_name, target_commit_id, sequence}

state_cache:
    (SmtRoot, ObjectKey) -> VersionId

type_cache:
    (SmtRoot, DataType) -> [ObjectId]

commit_cache:
    RepoCommitId -> {parents, state_root, policy_id, keyring_id}

promisor_cache:
    ChunkId -> [RemoteId]
```

Index rebuild scans only the active segment and packs named by the StoreManifest referenced by CURRENT. Unreferenced temporary or orphan files are ignored unless an explicit salvage command is used.

## 15. Core Rust Architecture

### 15.1 Workspace

```text
eternal/
├── Cargo.toml
├── crates/
│   ├── eternal-format/
│   │   ├── canonical.rs
│   │   ├── domain.rs
│   │   ├── record.rs
│   │   ├── ids.rs
│   │   └── limits.rs
│   │
│   ├── eternal-store/
│   │   ├── segment.rs
│   │   ├── pack.rs
│   │   ├── pack_index.rs
│   │   ├── store_manifest.rs
│   │   ├── lock.rs
│   │   ├── recovery.rs
│   │   └── cache.rs
│   │
│   ├── eternal-core/
│   │   ├── repository.rs
│   │   ├── transaction.rs
│   │   ├── object.rs
│   │   ├── content.rs
│   │   ├── smt.rs
│   │   ├── commit.rs
│   │   ├── refs.rs
│   │   ├── merge.rs
│   │   ├── policy.rs
│   │   ├── keyring.rs
│   │   ├── verify.rs
│   │   └── gc.rs
│   │
│   ├── eternal-crypto/
│   │   ├── signing.rs
│   │   ├── encryption.rs
│   │   ├── key_slots.rs
│   │   └── password.rs
│   │
│   ├── eternal-net/
│   │   ├── protocol.rs
│   │   ├── adapter.rs
│   │   ├── local_fs.rs
│   │   ├── transport.rs
│   │   └── auth.rs
│   │
│   └── eternal-cli/
│       ├── main.rs
│       ├── commands/
│       ├── output.rs
│       └── progress.rs
│
├── tests/
├── fuzz/
├── benches/
└── docs/
    ├── ARCHITECTURE.md
    ├── FORMAT.md
    ├── TRANSACTIONS.md
    ├── CRYPTO.md
    ├── POLICY.md
    └── SYNC.md
```

`eternal-format` and `eternal-store` contain no CLI concerns. `eternal-core` owns logical semantics. `eternal-net` never writes refs directly; it invokes validated core operations.

### 15.2 Public API

```rust
pub struct EternalCore {
    // opaque
}

pub struct WriteOutcome {
    pub version_id: VersionId,
    pub commit_id: RepoCommitId,
    pub ref_update_id: RefUpdateId,
}

impl EternalCore {
    pub fn init(path: &Path, options: InitOptions) -> Result<Self>;
    pub fn open(path: &Path, options: OpenOptions) -> Result<Self>;

    pub fn put(
        &mut self,
        id: &ObjectId,
        content: &[u8],
        options: PutOptions,
    ) -> Result<WriteOutcome>;

    pub fn put_stream<R: Read>(
        &mut self,
        id: &ObjectId,
        source: R,
        options: PutOptions,
    ) -> Result<WriteOutcome>;

    pub fn delete(
        &mut self,
        id: &ObjectId,
        options: DeleteOptions,
    ) -> Result<WriteOutcome>;

    pub fn rollback(
        &mut self,
        id: &ObjectId,
        target: VersionId,
        options: RollbackOptions,
    ) -> Result<WriteOutcome>;

    pub fn transaction<T, F>(&mut self, operation: F) -> Result<T>
    where
        F: FnOnce(&mut Transaction<'_>) -> Result<T>;

    pub fn get(&self, id: &ObjectId) -> Result<Option<ObjectContent>>;
    pub fn get_at(
        &self,
        id: &ObjectId,
        version: VersionId,
    ) -> Result<Option<ObjectContent>>;

    pub fn open_reader(
        &self,
        id: &ObjectId,
        version: Option<VersionId>,
    ) -> Result<Option<ObjectReader>>;

    pub fn log(&self, id: &ObjectId) -> Result<Vec<VersionSummary>>;
    pub fn list(&self, query: Query) -> Result<Vec<ObjectSummary>>;

    pub fn merge(&mut self, source_ref: &RefName) -> Result<MergeOutcome>;

    pub fn verify_metadata(&self) -> Result<VerifyReport>;
    pub fn verify_storage(&self) -> Result<VerifyReport>;
    pub fn audit_content(&self, keys: &KeyAccess) -> Result<AuditReport>;

    pub fn rebuild_cache(&mut self) -> Result<()>;
    pub fn seal(&mut self) -> Result<SealReport>;
    pub fn gc(&mut self, policy: GcPolicy) -> Result<GcReport>;

    pub async fn push(
        &mut self,
        remote: &dyn RemoteAdapter,
        spec: PushSpec,
    ) -> Result<PushReport>;

    pub async fn pull(
        &mut self,
        remote: &dyn RemoteAdapter,
        spec: PullSpec,
    ) -> Result<PullReport>;
}
```

### 15.3 RemoteAdapter

```rust
#[async_trait]
pub trait RemoteAdapter: Send + Sync {
    async fn handshake(&self, request: HandshakeRequest)
        -> Result<HandshakeResponse>;

    async fn list_refs(&self) -> Result<Vec<RemoteRef>>;

    async fn negotiate(
        &self,
        request: NegotiationRequest,
    ) -> Result<NegotiationResponse>;

    async fn fetch_records(
        &self,
        request: FetchRequest,
        sink: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<FetchReceipt>;

    async fn fetch_chunk_encoding(
        &self,
        chunk_id: ChunkId,
        sink: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<FetchReceipt>;

    async fn propose_ref_update(
        &self,
        proposal: RefUpdateProposal,
    ) -> Result<RefUpdateResult>;
}
```

## 16. CLI

```text
eternal init [path]
eternal status

eternal put <object-id> [file]
eternal get <object-id>
eternal get <object-id> --version <version-id-or-prefix>
eternal delete <object-id>
eternal rollback <object-id> <version-id-or-prefix>
eternal log <object-id>
eternal list [query]

eternal branch list
eternal branch create <name> [commit-id]
eternal branch delete <name>
eternal checkout <branch>
eternal merge <branch>

eternal tag create <name> [commit-id]
eternal pin add <record-or-version-id>
eternal pin remove <name>

eternal verify metadata
eternal verify storage
eternal audit content
eternal rebuild-cache
eternal seal
eternal gc

eternal remote add <name> <url>
eternal remote remove <name>
eternal remote list
eternal push <remote> [refspec]
eternal pull <remote> [refspec]
eternal prefetch <query>

eternal key policy-show
eternal key add-writer <public-key>
eternal key revoke <key-id>
eternal key rotate-signing

eternal encrypt setup
eternal encrypt add-recipient <public-key>
eternal encrypt change-password
eternal encrypt rotate-dek
```

There is no manual `commit` command and no `put --no-commit`. Each write command is atomic at one ref update. Batch writes use an explicit transaction-oriented import or API command.

## 17. Verification and Audit

### 17.1 verify metadata

Fast structural verification checks:

- CURRENT syntax;
- StoreManifest identifier and generation chain;
- presence and bounds of referenced packs, indexes, and active segment;
- index checksums;
- ref-file syntax;
- RefUpdate and RepoCommit identifier resolution;
- schema and size-limit compliance for directly referenced metadata.

It does not sequentially read every payload.

### 17.2 verify storage

Storage verification sequentially reads all files in the current StoreManifest and checks:

- segment and pack headers;
- complete-frame boundaries;
- CRC32C;
- RecordId recomputation;
- pack checksum;
- pack/index agreement;
- duplicate RecordId consistency;
- active-segment tail handling.

It does not decrypt or decompress chunk payloads.

### 17.3 audit content

Full audit additionally checks:

- all signed-record signatures;
- genesis, policy, and keyring chains;
- authorization at each RefUpdate and RepoCommit;
- RepoCommit state transitions;
- SMT node hashes and roots;
- ContentManifest roots;
- decryption and AEAD tags;
- decompression;
- logical ChunkId recomputation;
- ObjectVersion parent and content invariants;
- promised-content status.

Encrypted chunks unavailable due to missing keys are reported as `content_not_audited_locked`, not as verified plaintext.

## 18. Garbage Collection

### 18.1 Roots

GC roots include:

- all `refs/heads/*`;
- all `refs/tags/*`;
- all `refs/pins/*`;
- all `refs/merge-requests/*`;
- current RefUpdate chains within reflog retention;
- explicitly retained policy and keyring history;
- promised-object metadata;
- active reader generation pins.

### 18.2 Logical reachability

From each root, GC retains:

- RefUpdate chain required by retention policy;
- target RepoCommit DAG;
- referenced policy and keyring records;
- reachable SMT nodes;
- current ObjectVersions plus their parent histories according to retention policy;
- ContentManifests;
- for every reachable ChunkId, at least one usable EncodedChunk representation.

Current key-epoch encodings are preferred. An old encoding may be removed only after a replacement has passed full verification.

### 18.3 Physical publication

GC:

1. constructs replacement packs;
2. verifies them;
3. writes the next StoreManifest generation;
4. atomically switches CURRENT;
5. moves superseded files to trash;
6. deletes them only after generation pins expire.

Commits reference records, not packfiles. Therefore pack deletion decisions are based on StoreManifest generations and record reachability, never direct commit-to-pack references.

## 19. Error Model and Resource Limits

Core errors are structured and non-stringly typed:

```rust
pub enum Error {
    Io,
    UnsupportedFilesystem,
    LockUnavailable,
    RepositoryNotFound,
    InvalidRepositoryGenesis,
    RepositoryIdentityMismatch,
    FederationMismatch,
    InvalidObjectId,
    ObjectNotFound,
    VersionNotFound,
    RecordNotFound,
    InvalidCanonicalEncoding,
    RecordIdMismatch,
    SignatureInvalid,
    PolicyViolation,
    RefConflict,
    InvalidStateTransition,
    SmtProofInvalid,
    ContentLocked,
    ContentAuthenticationFailed,
    ContentCorrupt,
    PackCorrupt,
    PackIndexMismatch,
    StoreManifestCorrupt,
    PromisedContentUnavailable,
    ResourceLimitExceeded,
    ProtocolViolation,
    Network,
}
```

All parsers enforce configurable hard limits, including:

- maximum record payload;
- maximum metadata depth and element count;
- maximum relation count;
- maximum commit change count;
- maximum parent count;
- maximum pack size;
- maximum protocol frame;
- maximum decompressed chunk size;
- maximum compression expansion ratio;
- maximum requested record batch.

## 20. Testing Strategy

### 20.1 Golden vectors

`docs/FORMAT.md` must include stable vectors for:

- deterministic CBOR;
- every domain hash;
- signed-record envelopes;
- ContentManifest root;
- SMT empty hashes, inclusion proofs, and non-inclusion proofs;
- RepoCommit transition;
- RefUpdate chain;
- EncodedChunk AEAD;
- pack checksum and pack index checksum;
- StoreManifest identifier.

Vectors must match on x86-64 and ARM64 across Linux, Windows, and macOS.

### 20.2 Crash failpoints

Integration tests inject process termination before and after every:

- frame write;
- TransactionEnd write;
- active-segment fsync;
- temporary ref write;
- ref-file fsync;
- ref rename;
- ref-directory fsync;
- pack write;
- pack/index fsync;
- StoreManifest write;
- CURRENT rename;
- parent-directory fsync.

After recovery, the repository must expose exactly the old logical state or the new logical state, never a partial reachable graph.

### 20.3 Required properties

- `put_stream` followed by `open_reader` reproduces identical bytes;
- re-encryption preserves every existing ContentManifestId and VersionId, while publishing the new keyring through an empty-change administrative RepoCommit;
- encrypted mode does not store public plaintext chunk hashes;
- same `(ObjectId -> VersionId)` map produces the same SMT root;
- RepoCommit changes reproduce the declared root;
- RefUpdate predecessor CAS prevents ABA;
- key revocation blocks future writes but preserves historical verification;
- same-repository clones with different node IDs synchronize;
- different repositories reject direct synchronization;
- partial clones validate logical state without local content;
- three-way merge handles update/update, update/delete, and delete/delete correctly;
- pack/index disagreement fails loudly;
- index rebuild ignores files outside the active StoreManifest;
- active-segment truncation at every byte boundary recovers safely;
- fuzzed parsers never panic or allocate beyond configured limits.

### 20.4 Fuzz targets

Separate fuzz targets cover:

- canonical CBOR decoder;
- SignedRecord parser;
- each logical payload schema;
- active-segment frames;
- pack and pack index;
- StoreManifest;
- SMT proof verification;
- sync protocol frames;
- compression and decompression limit enforcement.

## 21. Performance Targets

Performance targets are measured separately for hot cache, cold cache, durable fsync mode, and relaxed batching mode.

Baseline target environment:

```text
CPU: 4 or more modern x86-64 or ARM64 cores
RAM: 16 GiB
Disk: local NVMe SSD with at least 500 MB/s sequential read
OS: Ubuntu 24.04 primary, current supported Windows and macOS secondary
```

Targets:

| Operation | Dataset | Target |
|---|---:|---:|
| hot object lookup | 1 KiB object | < 150 µs |
| cold object lookup | 1 KiB object | < 2 ms excluding remote fetch |
| durable single put | 1 KiB object | median < 10 ms on baseline NVMe |
| streaming put | 100 MiB | at least 150 MiB/s with `none` codec |
| streaming get | 100 MiB | at least 250 MiB/s with `none` codec |
| metadata verify | 100k objects | < 2 s |
| storage verify | 1 GiB pack set | hardware-limited sequential throughput |
| full audit | 1 TiB | target 250 MiB/s or better on capable hardware |
| 1% delta sync negotiation | 100k-object repository | < 5 s excluding WAN transfer |
| SMT point update | any repository size | fixed 256-level update |

Hard correctness requirements take precedence over performance targets.

## 22. Implementation Order

### Phase 0 — specification freeze

Before implementation:

- finalize `FORMAT.md` with integer field keys and byte layouts;
- finalize `TRANSACTIONS.md` with crash-state matrix;
- finalize `CRYPTO.md` with key-slot and AAD definitions;
- finalize `POLICY.md` with authorization transition rules;
- finalize `SYNC.md` with streamed framing and limits;
- publish golden vectors;
- define all record size limits and parser rejection behavior.

### Phase 1 — physical immutable store

Implement:

- canonical encoding and domain hashing;
- generic record framing;
- active segment;
- pack and external index;
- StoreManifest and CURRENT;
- writer lock;
- recovery and failpoints;
- record-location cache;
- raw immutable record put/get;
- sealing.

No ObjectVersion or user-facing `put` exists yet.

### Phase 2 — logical repository core

Implement:

- RepositoryGenesis;
- PolicyRecord;
- empty KeyringRecord;
- ContentManifest and public EncodedChunk;
- ObjectVersion;
- 256-level SMT;
- RepoCommit;
- RefUpdate and HEAD;
- single-object and batch transactions;
- put/get/delete/rollback/log/list;
- metadata and storage verification.

### Phase 3 — production single-node behavior

Implement:

- branch and tag operations;
- three-way merge;
- state-root-aware caches;
- full content audit;
- reflog and pins;
- GC and compaction;
- reader generation pinning;
- cross-platform lock and fsync semantics.

### Phase 4 — local synchronization

Implement:

- RemoteAdapter;
- local-filesystem adapter;
- commit-DAG negotiation;
- streamed record transfer;
- ref CAS;
- partial clone and promisor content;
- interrupted-transfer resume.

### Phase 5 — network synchronization

Implement:

- protocol version negotiation;
- mutual authentication;
- TCP or QUIC transport;
- backpressure and rate limits;
- remote policy enforcement;
- operational observability.

### Phase 6 — encrypted content

Implement:

- private keyed ChunkId;
- XChaCha20-Poly1305 EncodedChunk;
- password, X25519 recipient, and recovery key slots;
- secure private-key backends;
- password change;
- DEK rotation and verified re-encoding;
- locked-content audit reporting.

### Phase 7 — hardening and distribution

Implement:

- continuous fuzzing;
- property and model tests;
- benchmark regression tracking;
- package distribution;
- migration tooling;
- formal review of format and transaction invariants.

## 23. Final Architectural Summary

EternalCore v4 has four distinct layers:

1. **Logical records** — signed, immutable, repository-bound statements about policy, keys, objects, and commits.
2. **Authenticated state** — a persistent 256-level Sparse Merkle Tree committed by signed RepoCommits.
3. **Mutable control** — tiny CAS-updated ref pointers and one physical StoreManifest pointer.
4. **Physical storage** — append-only active segments and immutable sealed packs, with rebuildable caches.

The architecture deliberately avoids making packfiles, caches, timestamps, or mutable configuration authoritative. A logical mutation becomes visible only after a signed RefUpdate atomically points to a fully durable immutable graph. Physical repacking, compression changes, encryption rotation, and cache rebuilds can then occur without changing logical object identity or repository history.
