# EternalCore v4 Synchronization Protocol

> Status: implementation baseline
>
> This document defines the network and local-remote synchronization protocol for EternalCore format version 1. It is subordinate to `ARCHITECTURE.md` for the repository model, `FORMAT.md` for immutable record bytes and identifiers, `TRANSACTIONS.md` for local publication and durability, `CRYPTO.md` for repository cryptography, and `POLICY.md` for authorization. Where an older synchronization note conflicts with this document, this document wins.

## 1. Purpose and scope

This specification defines:

- authenticated transport between EternalCore nodes;
- node admission and remote pinning;
- protocol and feature negotiation;
- ref advertisement and stable remote snapshots;
- commit-DAG and immutable-record discovery without whole-repository hash-set exchange;
- streamed transfer of standard EternalCore packs and indexes;
- quarantine, validation, physical import, and ref publication ordering;
- pull, push, fetch-only, and on-demand chunk retrieval;
- metadata-complete partial clones and promisor remotes;
- cancellation, backpressure, resumable transfer, retry, and idempotency;
- limits, error classes, observability, fuzzing, and interoperability tests.

This document does not redefine:

- canonical record encoding;
- RecordId computation;
- signed-record validation;
- policy or ref authorization;
- local filesystem durability;
- merge semantics;
- cross-repository import.

Synchronization moves and publishes already defined immutable records. It does not create a second repository state model.

## 2. Normative language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

A format-v1 implementation MUST NOT silently weaken any failed check. In particular:

```text
transport authentication != repository authorization
repository identity match != permission to update a ref
record possession != record validity
record validity != state-transition validity
state-transition validity != ref publication
successful transfer != successful ref CAS
```

An implementation may support additional transports or future protocol versions, but the protocol described here is the only mandatory v1 network profile.

## 3. Protocol model

### 3.1 Immutable transfer, mutable publication

A synchronization operation has two independent results:

1. immutable records may become physically available on the receiver;
2. a mutable ref may or may not be published.

Failure of ref publication does not invalidate already imported immutable records. Such records remain detached and may later become reachable or be collected by GC.

### 3.2 No distributed transaction

EternalCore does not perform a distributed atomic transaction across two repositories.

The sender can prove that it transmitted bytes. The receiver can prove that it validated and durably imported bytes. Only the receiver can atomically publish its local ref.

A network disconnect around ref publication therefore produces an ambiguous client-side result. Resolution is performed by querying the remote ref chain, never by attempting a compensating rollback.

### 3.3 No distributed lock

A remote node does not acquire a repository-wide distributed lock. The receiving node serializes its own local writes through the writer lock and protects ref publication through predecessor-linked CAS.

### 3.4 Same-repository synchronization

Direct fetch, pull, push, and merge transport between initialized repositories require all of the following:

```text
local.repository_id == remote.repository_id
local.federation_id == remote.federation_id
local.repository_genesis_id == remote.repository_genesis_id
local.node_id != remote.node_id
```

Equality of `repository_id` alone is insufficient. Matching the exact `RepositoryGenesisId` prevents accidental or malicious reuse of a repository UUID with a different trust anchor.

A new working copy uses the separately defined bootstrap-clone mode in Section 9. Bootstrap clone is permitted only when the destination is uninitialized and the expected RepositoryGenesisId is configured out of band.

Data from another repository identity may enter only through explicit import. Import creates destination-native manifests, object versions, commits, and signatures and is outside this protocol.

## 4. Synchronization invariants

Every conforming implementation MUST preserve these invariants:

1. A receiver never publishes a ref before all mandatory logical metadata for the target state is locally durable and validated.
2. Missing payload content is permitted only when the receiver is a metadata-complete partial clone and each missing `ChunkId` has durable promise metadata naming at least one configured promisor remote.
3. A transfer pack is never trusted because it arrived over an authenticated channel; every pack, index, RecordId, signature, schema, repository binding, and state transition is independently validated.
4. A sender never chooses the receiver's authorization result.
5. Ref CAS compares `RefUpdateId`, not only `RepoCommitId`.
6. The protocol never silently creates a conflict branch after CAS failure.
7. Ref advertisements are derived from one pinned server snapshot and are not mixed across changing snapshots.
8. Transfer resume never permits bytes from one transfer plan to be spliced into another.
9. A partial clone omits only `EncodedChunk` records. It does not omit required genesis, policies, public keys, keyring metadata, commits, RefUpdates, SMT nodes, ObjectVersions, or ContentManifests.
10. Network data is bounded before allocation and before decompression.
11. No protocol message can make an unreferenced physical file authoritative without a valid local StoreManifest publication.
12. No protocol message can make an immutable graph logically authoritative without a valid local ref publication.

## 5. Identities and local remote configuration

### 5.1 Repository identity

Repository identity comes only from the locally validated `RepositoryGenesis` reachable through the current StoreManifest. The synchronization implementation MUST NOT take `repository_id` or `federation_id` from `config.toml` as authority.

### 5.2 Node identity

Each physical working copy has:

- a random UUID `node_id`;
- a dedicated Ed25519 transport keypair;
- a transport public-key fingerprint;
- local endpoint configuration.

The transport key is distinct from:

- repository content-signing keys;
- policy administrator keys;
- X25519 recipient keys;
- payload-encryption keys.

Possession of a transport key grants no repository role. The private transport key MUST use the same operating-system keystore or encrypted local-secret storage discipline required by `CRYPTO.md`; it MUST NOT be stored in synchronized immutable records.

### 5.3 RemoteId

A configured remote has a local stable identifier:

```text
RemoteId = locally generated UUID
```

`RemoteId` is not synchronized and is not derived from the transport key. This permits explicit transport-key rotation without rewriting all local promise entries.

A remote configuration contains at least:

```text
RemoteConfig {
    remote_id
    name
    endpoint
    expected_node_id
    pinned_transport_key_fingerprint
    expected_repository_genesis_id
    allow_fetch
    allow_push
    allow_ref_publication
    allow_clone
    promisor
    enabled
}
```

### 5.4 No implicit trust on first use

The baseline protocol does not use automatic trust on first use.

Before a network connection is accepted, the operator or provisioning system MUST explicitly configure:

- the expected `node_id`;
- the expected transport-key fingerprint;
- the endpoint;
- the local admission capabilities.

A CLI may display an untrusted fingerprint for out-of-band verification, but it MUST NOT persist or trust it without an explicit operator action.

### 5.5 Local admission versus repository policy

Local admission answers whether a peer may:

- establish a session;
- read repository metadata;
- request content;
- upload immutable records;
- request ref publication.

Repository policy separately answers whether a specific signed commit and RefUpdate are authorized.

Both checks are required. A locally admitted peer can still be denied every ref update.

## 6. Mandatory transport profile

### 6.1 Transport

The mandatory v1 network transport is:

```text
TCP
  + TLS 1.3
  + mutual Ed25519 certificate authentication
  + ALPN "eternal-sync/1"
  + EternalCore framing
```

TLS versions below 1.3 are forbidden.

### 6.2 Certificates and pinning

Each side presents a self-signed X.509 certificate containing its dedicated Ed25519 transport public key.

The certificate is a transport container, not a public-CA identity. Validation is performed by exact pinning:

1. extract the SubjectPublicKeyInfo bytes;
2. compute the configured transport fingerprint;
3. compare it with the pinned fingerprint;
4. verify proof of possession through the TLS 1.3 handshake;
5. compare the application `node_id` with the configured expected node ID.

System CA roots, DNS PKI, certificate common names, and certificate labels do not grant trust. The mutually authenticated TLS 1.3 handshake is the protocol's required mutual challenge-response proof of transport-key possession.

Certificate wall-clock validity dates are informational in the baseline pinned-key profile. They MUST NOT override an exact fingerprint mismatch.

### 6.3 Transport key fingerprint

The transport fingerprint is:

```text
SHA256(
    u16_le(len("EternalCore:TransportKey:v1")) ||
    "EternalCore:TransportKey:v1" ||
    u64_le(len(spki_der)) ||
    spki_der
)
```

The fingerprint is local transport configuration and is not a repository `KeyId`.

### 6.4 Early data and resumption

TLS 1.3 early data (0-RTT) MUST be disabled.

The baseline implementation MUST perform a full mutually authenticated handshake for each new TCP connection. Session resumption is not part of the mandatory v1 profile.

This prevents replay ambiguity for mutating protocol requests and keeps node-key pinning behavior uniform.

### 6.5 Application channel binding

After TLS establishment, both peers obtain 32 exporter bytes using:

```text
label   = "EXPORTER-EternalCore-Sync-v1"
context = empty
length  = 32
```

The application session ID is:

```text
SessionId = SHA256(
    "EternalCore:SyncSession:v1" ||
    tls_exporter ||
    min(local_node_id, remote_node_id) ||
    max(local_node_id, remote_node_id) ||
    initiator_nonce ||
    acceptor_nonce
)
```

`SessionId` binds logs, resume plans, and control messages to one authenticated TLS channel. It is not a repository record and is never reused as a cryptographic key.

### 6.6 Local filesystem adapter

A `LocalFileSystemAdapter` performs the same logical negotiation and validation without TLS. It still MUST check:

- repository ID;
- federation ID;
- RepositoryGenesisId;
- distinct node IDs;
- local admission configuration;
- all record and authorization rules.

A filesystem path is not trusted merely because it is local.

## 7. Wire framing

### 7.1 Connection preface

Immediately after TLS and ALPN negotiation, the initiator writes:

```text
8 bytes: "ETSYNC\0\1"
```

The acceptor responds with the same 8-byte preface.

Any mismatch closes the connection with no protocol fallback.

### 7.2 Frame header

Every frame has a 16-byte header in network byte order:

```text
payload_length: u32 BE
frame_type:     u16 BE
flags:          u16 BE
request_id:     u64 BE
payload:        payload_length bytes
```

Rules:

- `payload_length` excludes the 16-byte header;
- reserved flag bits MUST be zero;
- `request_id = 0` is reserved for session-level messages;
- request IDs are chosen by the requester and MUST NOT be reused while active;
- a peer MUST reject a frame before allocating the declared payload when it exceeds the negotiated limit;
- TLS provides wire integrity, so no additional frame CRC is used;
- repository pack CRCs, checksums, and RecordIds remain mandatory after receipt.

### 7.3 Flags

Format v1 defines:

| Bit | Name | Meaning |
|---:|---|---|
| 0 | `END` | final frame for this response stream |
| 1 | `CANCELLED` | request ended due to cancellation |
| 2 | `MORE` | additional page or data frame follows |
| 3–15 | reserved | MUST be zero |

`END` and `MORE` MUST NOT both be set.

### 7.4 Payload encodings

Control frames use the same deterministic RFC 8949 CBOR subset defined by `FORMAT.md`:

- fixed integer map keys;
- definite lengths only;
- shortest integers;
- no floating point;
- unique keys;
- no unknown mandatory v1 fields.

Data frames use a fixed binary prefix followed by raw bytes and are not CBOR-wrapped.

### 7.5 Frame types

| Code | Name | Direction |
|---:|---|---|
| 1 | `HELLO` | both |
| 2 | `HELLO_ACK` | both |
| 3 | `OPEN_SNAPSHOT` | client → server |
| 4 | `SNAPSHOT_OPENED` | server → client |
| 5 | `LIST_REFS` | client → server |
| 6 | `REFS_PAGE` | server → client |
| 7 | `GRAPH_PLAN` | client → server |
| 8 | `INVENTORY_PAGE` | server → client |
| 9 | `NEED_RECORDS` | client → server |
| 10 | `TRANSFER_DESCRIPTOR` | server → client |
| 11 | `TRANSFER_READ` | client → server |
| 12 | `TRANSFER_DATA` | server → client |
| 13 | `TRANSFER_FINISH` | server → client |
| 14 | `PUSH_PLAN` | sender → receiver |
| 15 | `MISSING_RECORDS_PAGE` | receiver → sender |
| 16 | `TRANSFER_UPLOAD_DESCRIPTOR` | sender → receiver |
| 17 | `TRANSFER_UPLOAD_DATA` | sender → receiver |
| 18 | `TRANSFER_UPLOAD_FINISH` | sender → receiver |
| 19 | `PUBLISH_REF` | requester → receiver |
| 20 | `PUBLISH_RESULT` | receiver → requester |
| 21 | `REF_STATUS` | requester → receiver |
| 22 | `REF_STATUS_RESULT` | receiver → requester |
| 23 | `PROMISE_OFFER` | server → client |
| 24 | `FETCH_CHUNKS` | client → server |
| 25 | `CANCEL` | both |
| 26 | `PING` | both |
| 27 | `PONG` | both |
| 28 | `ERROR` | both |

Unknown frame types are fatal for protocol major version 1.

## 8. Session handshake

### 8.1 HELLO schema

`HELLO` uses request ID 0 and the following integer keys:

| Key | Field | Type |
|---:|---|---|
| 0 | protocol_major | uint = 1 |
| 1 | protocol_minor | uint |
| 2 | repository_id | null or bytes(16) |
| 3 | federation_id | null or bytes(16) |
| 4 | repository_genesis_id | null or bytes(32) |
| 5 | node_id | bytes(16) |
| 6 | format_versions | array<uint> |
| 7 | feature_bits | uint |
| 8 | required_feature_bits | uint |
| 9 | max_control_frame | uint |
| 10 | max_data_frame | uint |
| 11 | max_concurrent_requests | uint |
| 12 | initiator_or_acceptor_nonce | bytes(32) |
| 13 | software_id | text |
| 14 | software_version | text |
| 15 | session_mode | existing_repository=1, bootstrap_clone=2 |
| 16 | expected_repository_genesis_id | null or bytes(32) |

`software_id` and `software_version` are diagnostic only and MUST NOT affect trust.

### 8.2 Feature bits

Protocol major 1 baseline writers emit `protocol_minor = 0`. A peer advertising a nonzero minor version may be accepted only by an implementation that explicitly supports that minor and all selected semantics; otherwise negotiation fails.

Format v1 defines:

| Bit | Feature |
|---:|---|
| 0 | standard pack-v1 transfer |
| 1 | resumable transfer |
| 2 | metadata-complete partial clone |
| 3 | interest-filter v1 |
| 4 | on-demand chunk fetch |
| 5 | ref deletion tombstones |
| 6 | batched inventory pages |
| 7 | transfer cancellation |
| 8 | promise offers |
| 9–63 | reserved |

Negotiated features are the intersection of both peers' advertised bits.

If either peer's `required_feature_bits` is not a subset of the intersection, the session fails with `RequiredFeatureUnavailable`.

### 8.3 HELLO validation

A peer MUST reject the session when:

- protocol major differs from 1;
- format version 1 is absent;
- an initialized-repository session has differing repository IDs, federation IDs, or RepositoryGenesisIds;
- a bootstrap-clone session does not name an out-of-band expected RepositoryGenesisId equal to the server's validated genesis ID;
- a bootstrap-clone initiator supplies non-null local repository identity fields;
- the server is not configured to permit bootstrap clone;
- node IDs are equal;
- the presented transport fingerprint or `node_id` does not match local remote configuration;
- configured local admission forbids the session;
- any negotiated limit is below the protocol minimum;
- the nonce is not exactly 32 bytes.

### 8.4 HELLO_ACK

After validating both HELLO messages, each peer sends `HELLO_ACK` containing:

| Key | Field | Type |
|---:|---|---|
| 0 | selected_protocol_minor | uint |
| 1 | selected_format_version | uint = 1 |
| 2 | selected_feature_bits | uint |
| 3 | control_frame_limit | uint |
| 4 | data_frame_limit | uint |
| 5 | concurrent_request_limit | uint |
| 6 | session_id | bytes(32) |

The selected frame and concurrency limits are the minimum of the two advertised values and the local configured caps. Selected feature bits are the exact negotiated intersection.

Both peers MUST compute the same `SessionId`. A mismatch terminates the session.

### 8.5 Session state

After HELLO_ACK, the session enters `READY`.

Before `READY`, only preface, HELLO, HELLO_ACK, and ERROR are valid.

## 9. Bootstrap clone

### 9.1 Purpose

Bootstrap clone creates a new physical working copy of an existing repository. It is not a cross-repository import and preserves the source repository's immutable record identities and RefUpdates.

### 9.2 Trust requirement

Before cloning, the operator MUST configure out of band:

- the remote endpoint;
- expected remote node ID;
- pinned transport-key fingerprint;
- expected RepositoryGenesisId.

The baseline does not allow “accept whatever genesis this pinned server presents.” Transport identity and repository trust anchor are separate pins.

### 9.3 Bootstrap HELLO

The uninitialized client sends `session_mode = bootstrap_clone`, null repository/federation/genesis identity fields, and the configured `expected_repository_genesis_id`.

The server sends its normal validated identity fields. The session proceeds only when the server's RepositoryGenesisId equals the expected value and local server admission permits clone.

### 9.4 Bootstrap transfer

The client requests at least:

- RepositoryGenesis;
- initial and reachable PolicyRecords/public keys;
- reachable KeyringRecords;
- selected refs and RefUpdate histories;
- RepoCommit DAGs;
- SMT nodes;
- ObjectVersions;
- ContentManifests;
- all EncodedChunks for a full clone, or durable promises for a partial clone.

The client independently verifies the embedded creator key, genesis signature, exact RepositoryGenesisId, policy bootstrap, every selected ref graph, and all transferred records.

### 9.5 Local initialization

The destination creates the repository through the initialization transaction defined by `TRANSACTIONS.md`:

1. create a temporary `.eternal` tree on the destination filesystem;
2. generate a new local `node_id` and dedicated transport key;
3. install validated immutable packs and indexes;
4. create the initial StoreManifest and CURRENT;
5. install selected ref pointer files exactly to validated RefUpdateIds;
6. install durable promises before refs for a partial clone;
7. write local configuration and remote pinning;
8. fsync files/directories bottom-up;
9. atomically rename the complete temporary repository into place.

The client does not create new RepoCommits or RefUpdates merely to clone.

### 9.6 Bootstrap restrictions

A bootstrap session:

- is valid only for an uninitialized destination;
- cannot push or request remote ref publication;
- cannot change the advertised repository identity;
- fails if the destination path already contains a valid `.eternal`;
- does not use TOFU;
- must not mix records from multiple remote snapshots.

After successful initialization, all later sessions use ordinary initialized-repository mode.

## 10. Stable synchronization snapshots

### 10.1 Purpose

Ref lists and graph plans must come from one consistent remote view. A server therefore creates a transient `SyncSnapshot` before advertising refs or building a transfer plan.

### 10.2 Snapshot contents

A snapshot pins:

- current StoreManifest generation;
- current ref-file values for all visible refs;
- the corresponding RefUpdate and target commit IDs;
- repository identity and genesis ID;
- local promisor availability metadata relevant to the request.

The snapshot does not freeze future writes. It only keeps the advertised view and required physical files available for the snapshot lifetime.

### 10.3 OPEN_SNAPSHOT

The request contains:

| Key | Field | Type |
|---:|---|---|
| 0 | requested_ttl_seconds | uint |
| 1 | purpose | enum: fetch=1, push=2, inspect=3 |

The server clamps the TTL to its configured range.

### 10.4 SNAPSHOT_OPENED

The response contains:

| Key | Field | Type |
|---:|---|---|
| 0 | snapshot_id | bytes(16) random UUID |
| 1 | expires_at_ns | int |
| 2 | store_generation | uint |
| 3 | ref_generation_token | bytes(32) |
| 4 | max_inventory_entries | uint |

`ref_generation_token` is a session-local hash of the pinned ref map and is used only to detect accidental snapshot mixing.

### 10.5 Expiry

A request using an expired or unknown snapshot fails with `SnapshotExpired`.

The client may open a new snapshot and restart negotiation. It MUST NOT combine inventory pages from different snapshots.

## 11. Ref advertisement

### 11.1 LIST_REFS

The client requests visible refs from a snapshot, optionally with a canonical prefix such as `refs/heads/`.

The request contains:

| Key | Field | Type |
|---:|---|---|
| 0 | snapshot_id | bytes(16) |
| 1 | prefix | null or text |
| 2 | continuation | null or bytes |
| 3 | page_limit | uint |

### 11.2 Ref advertisement entry

Each entry contains:

| Key | Field | Type |
|---:|---|---|
| 0 | ref_name | text |
| 1 | ref_update_id | bytes(32) |
| 2 | target_commit_id | null or bytes(32) |
| 3 | sequence | uint |
| 4 | deleted | bool |

Entries are sorted by ref-name UTF-8 bytes.

### 11.3 Advertisement is not authority

A ref advertisement is an optimization and a statement from the current transport peer. The client must still fetch and validate the advertised RefUpdate and its predecessor/target graph before treating it as repository evidence.

### 11.4 Visibility

The core v1 protocol has no repository-level metadata read ACL. Local server admission may expose all refs or a configured ref-prefix subset.

A server MUST NOT advertise a ref and later deny the mandatory metadata needed to validate it, except because of concurrent snapshot expiry or server failure.

## 12. Graph discovery and inventory

### 12.1 Goals

Graph discovery must:

- avoid exchanging the complete set of every local RecordId;
- discover the closure of explicitly requested refs;
- stop at exact known immutable boundaries where possible;
- remain correct when the peers have divergent histories;
- permit the receiver to independently detect omitted dependencies.

### 12.2 GRAPH_PLAN request

A fetcher sends:

| Key | Field | Type |
|---:|---|---|
| 0 | snapshot_id | bytes(16) |
| 1 | wanted_ref_update_ids | array<bytes(32)> |
| 2 | have_ref_update_ids | array<bytes(32)> |
| 3 | have_commit_ids | array<bytes(32)> |
| 4 | clone_mode | full=1, metadata_complete=2 |
| 5 | interest_set | null or InterestSet |
| 6 | include_object_history | bool, MUST be true in v1 |
| 7 | page_limit | uint |

The `have` lists are hints and stop points. They do not prove possession. The client later requests only records absent from its physical store.

### 12.3 Server traversal

For each wanted RefUpdate, the server traverses:

1. RefUpdate predecessor history required to connect the wanted update to an advertised or supplied known predecessor;
2. target RepoCommit DAG through all parents until an exact `have_commit_id` or genesis boundary;
3. policy records and public-key introductions needed to validate those commits;
4. keyring records needed to interpret their content mappings;
5. RepoCommit changes and the SMT nodes required to validate each target state transition;
6. ObjectVersions referenced by current states and commit changes;
7. ObjectVersion parent history;
8. ContentManifests referenced by all included ObjectVersions;
9. EncodedChunks selected by clone mode and interests.

For an ordinary initialized-repository session, the exact RepositoryGenesisId was already validated during HELLO, so the genesis record may be omitted when the receiver confirms it is locally present. Bootstrap clone always transfers the genesis record.

A full clone selects at least one usable EncodedChunk representation for every reachable ChunkId; it need not transfer redundant encodings of the same ChunkId. A metadata-complete partial clone selects at least one representation for every currently matched interest and creates promises for every other reachable absent ChunkId, including content reachable only through retained history.

### 12.4 Inventory entries

An inventory entry contains:

| Key | Field | Type |
|---:|---|---|
| 0 | record_id | bytes(32) |
| 1 | record_type | uint |
| 2 | stored_payload_length | uint |
| 3 | logical_class | metadata=1, content=2 |
| 4 | required_for_publication | bool |

Entries are sorted first by logical dependency class and then by `(record_type, record_id)`.

The inventory is not hashed into repository state and is not trusted as complete.

### 12.5 Iterative closure completion

After receiving records, the client validates them and computes its own missing dependency set.

If a required metadata RecordId is missing, the client requests it through a subsequent `NEED_RECORDS` request. This repeats until:

- the closure is complete; or
- the peer reports the record unavailable; or
- a configured round/record limit is reached.

A server cannot make an incomplete graph acceptable by omitting a dependency from the inventory.

### 12.6 Inventory pagination

Each `INVENTORY_PAGE` includes:

- `snapshot_id`;
- `plan_id`;
- page sequence;
- entries;
- continuation token or null;
- cumulative entry count;
- final-page flag.

Continuation tokens are opaque, snapshot-bound, plan-bound, and time-limited.

## 13. Interest filters

### 13.1 Scope

Interest filters control prefetch of `EncodedChunk` records only. They do not remove logical metadata.

### 13.2 InterestSet

An `InterestSet` is an array of predicates. An object is selected when it matches at least one predicate. An empty set means all content.

Format v1 predicates are:

```text
DataTypeEquals(text)
ObjectIdPrefix(text)
MetadataEquals(path, CanonicalValue)
```

### 13.3 Deterministic evaluation

Rules:

- `DataTypeEquals` compares exact UTF-8 bytes;
- `ObjectIdPrefix` compares canonical ObjectId UTF-8 bytes and is not a filesystem path match;
- `MetadataEquals` follows an array of exact map keys from the ObjectVersion metadata root;
- absent paths do not match;
- equality uses canonical `CanonicalValue` semantics;
- predicates are OR-combined;
- filtering is evaluated against the current ObjectVersion selected by the target SMT state;
- tombstones never request content.

### 13.4 Security boundary

Interests are availability and bandwidth preferences, not confidentiality controls. A metadata-complete peer still observes ObjectIds, metadata, relations, manifests, sizes, and repository topology.

## 14. Record selection and NEED_RECORDS

### 14.1 Client-side need calculation

The client compares each inventory RecordId against its `record_location` cache or direct store lookup.

A cache hit is accepted only after the referenced local record can be located under the currently pinned StoreManifest generation. Missing or stale cache entries fall back to direct lookup.

### 14.2 NEED_RECORDS request

The request contains:

| Key | Field | Type |
|---:|---|---|
| 0 | snapshot_id | bytes(16) |
| 1 | plan_id | bytes(16) |
| 2 | record_ids | array<bytes(32)> |
| 3 | transfer_preferences | map |

The list is sorted and unique.

### 14.3 Request limits

The default maximum is 4096 RecordIds per request. The negotiated hard maximum MUST NOT exceed 65536.

A larger need set is split across multiple requests or transferred through a server-generated continuation plan.

## 15. Transfer-pack format

### 15.1 Standard format reuse

Network record transfer uses an ordinary EternalCore format-v1 sealed pack and external `.idx` as defined by `FORMAT.md`.

The network protocol does not define a second object serialization.

A transfer pack:

- contains only requested immutable record types 1 through 10;
- never contains `TransactionEnd`;
- never contains StoreManifest files, CURRENT, HEAD, ref pointer files, local config, private keys, cache records, or promise metadata;
- may contain records already present at the receiver;
- may combine records from multiple sender packs and active-segment batches;
- is immutable once its descriptor is issued.

### 15.2 Transfer descriptor

`TRANSFER_DESCRIPTOR` contains:

| Key | Field | Type |
|---:|---|---|
| 0 | transfer_id | bytes(16) |
| 1 | snapshot_id | bytes(16) |
| 2 | plan_id | bytes(16) |
| 3 | pack_checksum | bytes(32) |
| 4 | pack_size | uint |
| 5 | index_checksum | bytes(32) |
| 6 | index_size | uint |
| 7 | record_count | uint |
| 8 | expires_at_ns | int |
| 9 | resumable | bool |

### 15.3 No transport recompression

TLS records and EternalCore frames MUST NOT apply a second protocol-level compression layer.

EncodedChunk records already carry their specified compression/encryption representation. Compressing arbitrary control or pack streams creates avoidable complexity and decompression-risk surface.

### 15.4 Data frame payload

`TRANSFER_DATA` has the binary payload:

```text
transfer_id: 16 bytes
target:      u8      // 1 = pack, 2 = index
reserved:    7 bytes zero
offset:      u64 BE
data:        remaining frame bytes
```

The requested range MUST lie entirely inside the descriptor's declared object size.

### 15.5 Transfer ordering

A client MAY request pack and index ranges in any order, but the baseline implementation SHOULD fetch the index first, then the pack sequentially.

Overlapping or repeated ranges are allowed only as exact retries. Conflicting bytes for the same `(transfer_id, target, offset)` terminate the transfer as corruption.

## 16. Resumable download

### 16.1 Resume token

`transfer_id` is an opaque server-side resume token bound to:

- SessionId that created the plan;
- authenticated RemoteId;
- snapshot and plan IDs;
- exact pack and index checksums;
- exact sizes;
- expiry time.

A server MAY permit a new TLS session from the same pinned remote to resume the transfer. In that case it rebinds the transfer to the new SessionId only after full mutual authentication and exact descriptor confirmation.

### 16.2 Client state

The client stores under quarantine:

```text
objects/incoming/<transfer_id>/descriptor.cbor
objects/incoming/<transfer_id>/pack.partial
objects/incoming/<transfer_id>/index.partial
objects/incoming/<transfer_id>/ranges.cbor
```

This state is local and non-authoritative.

### 16.3 Resume verification

Before resuming, the client MUST:

- reload and validate the descriptor;
- verify every retained completed range against locally stored range hashes or re-read it;
- require the same final pack and index checksums;
- truncate any uncommitted trailing bytes;
- reject descriptor changes under the same transfer ID.

### 16.4 Expired resume

If a transfer expires, the client opens a new snapshot and plan. Existing partial bytes may be reused only when the new descriptor has identical pack/index checksums and sizes.

## 17. Receiver quarantine and validation

### 17.1 Quarantine rule

Incoming bytes are written only under `objects/incoming/` until complete validation succeeds.

Ordinary reads, index rebuild, audit, and ref resolution MUST ignore quarantine files.

### 17.2 Validation order

After full pack and index receipt, the receiver performs:

1. exact file-size checks;
2. index checksum verification;
3. pack checksum verification;
4. pack/index binding verification;
5. bounds, ordering, fanout, offset, length, and CRC validation;
6. per-record frame parsing;
7. RecordId recomputation;
8. deterministic CBOR and schema validation;
9. repository ID validation;
10. strict signature validation for signed records;
11. duplicate RecordId consistency checks.

A duplicate RecordId with a different record type or payload is fatal corruption.

### 17.3 Logical validation

Physical validation does not authorize publication.

Before a ref update, the receiver additionally validates:

- RepositoryGenesis anchor;
- public-key registry;
- policy chains;
- keyring chains;
- RepoCommit parent and change semantics;
- SMT transitions and target root;
- ObjectVersion lineage constraints;
- ContentManifest structure;
- ref predecessor, sequence, lifecycle, and permission;
- promise closure for omitted chunks.

### 17.4 Physical import

A validated incoming pack is published through the physical-layout transaction defined by `TRANSACTIONS.md`:

1. obtain the writer lock;
2. revalidate the pack and index identity;
3. close and seal the current active segment as required by the generation transition;
4. move the incoming pack/index to immutable final names;
5. create the next active segment;
6. create and fsync the next StoreManifest containing the complete pack set;
7. atomically replace CURRENT;
8. fsync `.eternal`;
9. release the writer lock.

Only after this step may the imported records satisfy a logical ref publication closure.

### 17.5 Import without ref update

Fetch-only and failed push operations may import immutable records without changing a ref. This is valid. Such records are detached until reachable.

## 18. Pull protocol

### 18.1 Pull meaning

A pull operation obtains a selected remote ref graph and optionally attempts to publish that exact RefUpdate locally.

It never performs an automatic merge.

### 18.2 Pull phases

A complete pull is:

1. authenticate and negotiate session;
2. open remote snapshot;
3. list remote refs;
4. select wanted RefUpdateIds;
5. build graph plan;
6. receive inventory;
7. request absent mandatory metadata records;
8. request selected EncodedChunks or install promises;
9. receive transfer pack(s);
10. validate in quarantine;
11. physically import pack(s);
12. complete iterative metadata closure validation;
13. optionally request local ref publication;
14. report transferred, imported, promised, and published results separately.

### 18.3 Fetch-only mode

Fetch-only mode stops after immutable import and promise installation. It does not create or move a ref.

The imported RefUpdate remains an immutable detached record and may later be inspected or explicitly published.

### 18.4 Local ref publication after pull

To publish the remote RefUpdate into the same local ref name:

- the local current RefUpdateId must equal the candidate's `previous_ref_update_id`;
- local policy validation must authorize the candidate RefUpdate signer for that ref;
- the complete target graph must be available or validly promised;
- local ref CAS and durability follow `TRANSACTIONS.md`.

If the local ref diverged, pull returns `RefCasMismatch` and leaves the imported records detached.

### 18.5 No implicit remote-tracking repository refs

The core protocol does not automatically create `refs/remotes/*` repository refs because every repository ref is policy-governed authoritative state.

A client may store last-seen remote advertisements in a local non-authoritative cache keyed by `RemoteId`. Such cache entries are not RefUpdates and are not synchronized.

## 19. Push protocol

### 19.1 Explicit target

A push request explicitly names:

- destination ref name;
- expected previous RefUpdateId, or null for authorized creation;
- candidate new RefUpdateId;
- requested operation: create, update, delete, or create-tag.

The receiver never infers a branch name and never creates a conflict branch.

### 19.2 PUSH_PLAN

The sender first sends:

| Key | Field | Type |
|---:|---|---|
| 0 | snapshot_id | bytes(16) |
| 1 | ref_name | text |
| 2 | expected_previous_ref_update_id | null or bytes(32) |
| 3 | new_ref_update_id | bytes(32) |
| 4 | operation | enum |
| 5 | offered_inventory_pages | uint |
| 6 | allow_promises | bool |

The receiver performs an early check of:

- local admission;
- current ref predecessor;
- obvious ref lifecycle constraints;
- limits.

Early success is not final authorization.

### 19.3 Missing-record negotiation

The sender supplies inventory pages for the candidate closure. The receiver returns sorted unique RecordIds it lacks.

The receiver computes need from local storage; it MUST NOT trust the sender's claim that a record is unnecessary.

If validation of received records discovers additional missing dependencies, the receiver requests another missing-record round.

### 19.4 Upload transfer

The sender constructs an ordinary pack/index containing only requested records and sends a `TRANSFER_UPLOAD_DESCRIPTOR` followed by ordered upload data frames.

The receiver:

- streams into quarantine;
- enforces declared sizes;
- verifies final checksums;
- performs physical and logical validation;
- imports the pack through a StoreManifest generation transaction.

### 19.5 Push into a partial clone

A receiver may accept omitted EncodedChunks only when all of the following hold:

- it is explicitly configured as a metadata-complete partial clone;
- `allow_promises` was requested;
- the authenticated sender is configured locally as a promisor;
- the sender provides a valid promise offer for each omitted ChunkId;
- promise metadata is durably installed before ref publication.

Otherwise every current referenced ChunkId must have a usable local encoding before publication.

### 19.6 Final publication

After immutable import, the sender issues `PUBLISH_REF`.

The receiver re-reads the current ref under its writer lock and performs all publication-time checks again. Results from PUSH_PLAN are not a lock or reservation.

## 20. Ref publication protocol

### 20.1 PUBLISH_REF schema

| Key | Field | Type |
|---:|---|---|
| 0 | ref_name | text |
| 1 | expected_previous_ref_update_id | null or bytes(32) |
| 2 | new_ref_update_id | bytes(32) |
| 3 | operation | create=1, update=2, delete=3, create_tag=4 |
| 4 | client_operation_id | bytes(16) |

`client_operation_id` is diagnostic/idempotency metadata and is not part of repository state.

### 20.2 Validation order

The receiver MUST validate in this order:

1. local remote admission allows publication requests;
2. ref name and operation are structurally valid;
3. candidate RefUpdate record is present;
4. candidate RefUpdateId recomputes;
5. candidate signed payload uses the exact ref name;
6. repository ID matches;
7. predecessor and sequence satisfy ref lifecycle rules;
8. target commit graph is metadata-complete;
9. content closure is local or validly promised;
10. all signatures and policy chains validate;
11. target RepoCommit transition validates;
12. RefUpdate signer has ref permission under the governing predecessor policy;
13. current local ref file still equals the expected predecessor;
14. local ref pointer replacement and directory fsync succeed.

### 20.3 Result codes

`PUBLISH_RESULT` contains one status:

| Status | Meaning |
|---|---|
| `APPLIED` | ref durably points to candidate |
| `ALREADY_CURRENT` | ref already points to candidate |
| `ALREADY_IN_HISTORY` | candidate is in predecessor history but not current |
| `CAS_MISMATCH` | current predecessor differs |
| `DENIED` | local admission or repository authorization denied |
| `INVALID_GRAPH` | immutable graph or transition invalid |
| `MISSING_METADATA` | required logical record unavailable |
| `MISSING_CONTENT` | required content neither local nor promised |
| `OUTCOME_UNKNOWN` | receiver cannot determine durability outcome |

### 20.4 Idempotency

Publication is idempotent by candidate `RefUpdateId`:

- if current ref equals candidate, return `ALREADY_CURRENT` as success-equivalent;
- if candidate is already in the current predecessor history, return `ALREADY_IN_HISTORY` and do not rewind;
- if current ref is a conflicting successor, return `CAS_MISMATCH`;
- replaying a tag-creation request for the already-current tag returns `ALREADY_CURRENT`; any different tag target is denied.

### 20.5 Ambiguous client result

If the connection closes after request transmission and before a definitive result, the client sends `REF_STATUS` on a new authenticated session.

It queries:

- ref name;
- candidate RefUpdateId;
- expected predecessor.

The response states whether the candidate is current, in history, absent, or conflicts.

The client MUST NOT blindly retry with a changed predecessor.

## 21. Metadata-complete partial clone

### 21.1 Mandatory metadata closure

A partial clone with a published ref MUST locally possess all required:

- RepositoryGenesis;
- PolicyRecords and introduced public keys;
- KeyringRecords as public metadata;
- RefUpdates;
- RepoCommits;
- SMT nodes;
- ObjectVersions and required parent lineage;
- ContentManifests.

Only EncodedChunk records may be absent.

### 21.2 Promise metadata

Promise metadata is local, durable, non-authoritative availability state.

The baseline local store is a synchronized `redb` database separate from `index.db`, for example:

```text
.eternal/promises.db
```

Each entry is keyed by `(repository_id, ChunkId, RemoteId)` and contains:

```text
PromiseEntry {
    remote_id
    chunk_id
    offered_encoded_record_ids[]
    observed_snapshot_id
    observed_at_ns
    last_verified_at_ns
    status
}
```

Loss of `promises.db` does not invalidate repository signatures or state roots, but it degrades content availability and must be reported. `promises.db` is synchronized to stable storage before any ref publication that depends on it, but it is not part of RecordId, RepoCommit, RefUpdate, or StoreManifest authority.

### 21.3 Promise offer

A server sends `PROMISE_OFFER` containing:

- snapshot ID;
- ChunkId;
- one or more available EncodedChunk RecordIds;
- encoded lengths;
- key epochs/codec metadata available from the EncodedChunk records;
- expiry or availability hint.

A promise offer is authenticated by the session but is not an immutable repository guarantee. The remote may later lose the data.

### 21.4 Promise installation ordering

Before publishing a ref that omits chunks, the receiver MUST:

1. verify the promisor remote is configured and enabled;
2. verify every missing ChunkId has at least one offer;
3. durably write and synchronize promise metadata;
4. recheck that all non-content metadata is complete;
5. only then replace the ref pointer.

### 21.5 Promisor failure

If all configured promisors fail to supply a promised chunk, the object remains logically valid but unavailable. The read operation returns `PromisedContentUnavailable` with the affected ChunkId and configured RemoteIds.

It MUST NOT report repository corruption solely because promised content is unavailable.

### 21.6 Promise reconstruction

When promise metadata is lost, an operator may run promise reconstruction against configured remotes. The operation:

- scans reachable ContentManifests for absent ChunkIds;
- queries configured promisor remotes;
- installs promises only after authenticated offers;
- reports chunks with no available promisor.

## 22. On-demand chunk fetch

### 22.1 Trigger

`get`, `open_reader`, explicit prefetch, or full content audit may request an absent promised ChunkId.

### 22.2 FETCH_CHUNKS

The client requests sorted unique ChunkIds and optionally acceptable encoding constraints:

- supported codec IDs;
- available key epochs;
- maximum encoded size;
- preferred EncodedChunk RecordIds from promises.

### 22.3 Server response

The server resolves each ChunkId to one or more available EncodedChunk records and returns an inventory/transfer descriptor.

The client chooses one usable encoding. It is not required to download every representation.

### 22.4 Import

On-demand chunks use the same quarantine, pack verification, and StoreManifest publication procedure as ordinary transfer.

No RepoCommit or RefUpdate is created because logical state does not change.

### 22.5 Read retry

After successful import, the reader re-resolves the ChunkId from the new StoreManifest generation and continues. It does not retain a raw pointer into a retired generation across the fetch.

## 23. Transfer uploads

### 23.1 Upload descriptor

An upload descriptor declares:

- transfer ID;
- exact pack/index sizes and checksums;
- record count;
- destination session;
- expiry;
- associated push plan;
- sender RemoteId.

### 23.2 Ordered upload

The baseline receiver requires sequential upload from offset zero for pack and index separately. This bounds sparse-file abuse and simplifies durability.

A resumed upload begins at the receiver-advertised contiguous durable offset.

### 23.3 Upload durability

The receiver may periodically fsync quarantine partial files. Such synchronization makes resume progress durable but does not publish repository data.

### 23.4 Upload completion

At `TRANSFER_UPLOAD_FINISH`, the receiver verifies exact final lengths and checksums before returning upload success.

Upload success means only “quarantine bytes complete and verified.” Physical import and ref publication are separate responses.

## 24. Cancellation and flow control

### 24.1 Cancellation

Either peer may send `CANCEL` for an active request ID.

Cancellation is cooperative. The receiver:

- stops generating new response data;
- releases snapshot/plan resources when safe;
- may retain already durable quarantine bytes for resume;
- never rolls back an already published StoreManifest or ref.

### 24.2 Backpressure

The implementation MUST use bounded producer/consumer queues.

A sender MUST stop reading pack bytes from disk when the network writer queue reaches its configured limit. A receiver MUST stop accepting additional transfer frames when its quarantine writer queue is full.

### 24.3 Concurrent requests

The negotiated maximum defaults to 16 and MUST NOT exceed 256 in v1.

Mutating operations for the same destination ref are still serialized by the repository writer lock and ref CAS regardless of protocol concurrency.

### 24.4 Keepalive

PING/PONG may be used for long pack builds or validation periods. A keepalive contains no repository state and does not extend snapshot or transfer expiry unless the server explicitly renews it.

## 25. Resource limits

### 25.1 Required defaults

A baseline implementation uses:

| Resource | Default | Hard v1 maximum |
|---|---:|---:|
| control frame payload | 1 MiB | 8 MiB |
| data frame payload | 1 MiB | 8 MiB |
| active requests | 16 | 256 |
| RecordIds per request | 4096 | 65536 |
| ref advertisement page | 4096 | 65536 |
| inventory page | 8192 | 65536 |
| graph traversal commits | 1,000,000 | configurable fail-loud |
| ObjectVersion parent depth | format limit / configured audit limit | fail-loud |
| transfer pack size | configured | `u64` format bound |
| snapshot TTL | 15 minutes | 1 hour |
| transfer TTL | 1 hour | 24 hours |
| quarantine total | configured | fail-loud |

### 25.2 Pre-allocation checks

All lengths and counts are checked:

- before integer conversion;
- before multiplication/addition;
- before allocation;
- before file growth;
- before decompression;
- before recursive or graph traversal.

### 25.3 Traversal limits

Hitting a traversal limit returns `TraversalLimitExceeded`. The implementation MUST NOT treat a truncated traversal as a complete graph.

### 25.4 Rate limiting

Servers SHOULD support local per-RemoteId limits for:

- connection attempts;
- snapshots;
- graph plans;
- inventory entries;
- transferred bytes;
- failed publication requests;
- on-demand chunk fetches.

Rate limits are local operational controls and do not alter repository policy.

## 26. Error protocol

### 26.1 ERROR schema

`ERROR` contains:

| Key | Field | Type |
|---:|---|---|
| 0 | error_code | uint |
| 1 | class | protocol=1, auth=2, identity=3, storage=4, graph=5, policy=6, ref=7, limit=8, temporary=9 |
| 2 | retryable | bool |
| 3 | message | bounded text |
| 4 | related_request_id | uint |
| 5 | detail | null or bounded CanonicalValue |

Security-sensitive servers SHOULD omit details that reveal local filesystem paths, key-slot state, or internal policy data beyond what the authenticated peer is admitted to read.

### 26.2 Core error codes

At minimum:

- `ProtocolVersionMismatch`;
- `RequiredFeatureUnavailable`;
- `TransportIdentityMismatch`;
- `NodeIdMismatch`;
- `SameNodeRejected`;
- `RepositoryMismatch`;
- `FederationMismatch`;
- `GenesisMismatch`;
- `RemoteAdmissionDenied`;
- `SnapshotExpired`;
- `UnknownSnapshot`;
- `UnknownPlan`;
- `UnknownTransfer`;
- `TransferExpired`;
- `FrameTooLarge`;
- `MalformedControlMessage`;
- `ResourceLimitExceeded`;
- `TraversalLimitExceeded`;
- `RecordUnavailable`;
- `PackChecksumMismatch`;
- `IndexChecksumMismatch`;
- `RecordIdMismatch`;
- `SignatureInvalid`;
- `PolicyInvalid`;
- `AuthorizationDenied`;
- `CommitTransitionInvalid`;
- `RefUpdateInvalid`;
- `RefCasMismatch`;
- `PromisorNotConfigured`;
- `PromisedContentUnavailable`;
- `PhysicalImportFailed`;
- `CommitOutcomeUnknown`;
- `Cancelled`;
- `TemporaryUnavailable`.

### 26.3 Connection-fatal errors

The connection MUST close after:

- TLS identity failure;
- preface mismatch;
- HELLO identity mismatch;
- malformed frame header;
- declared frame over hard limit;
- repeated request-ID collision;
- conflicting data for the same transfer range;
- protocol state-machine violation;
- detected deliberate checksum substitution.

Record-level validation errors may fail one request without closing the session unless the implementation judges the peer malicious.

## 27. Client and server state machines

### 27.1 Connection state

```text
TCP_CONNECTED
  -> TLS_AUTHENTICATED
  -> PREFACE_EXCHANGED
  -> HELLO_EXCHANGED
  -> READY
  -> CLOSING
  -> CLOSED
```

No state may be skipped.

### 27.2 Fetch state

```text
READY
  -> SNAPSHOT_OPEN
  -> REFS_ADVERTISED
  -> GRAPH_PLANNED
  -> INVENTORY_COMPLETE
  -> TRANSFER_IN_PROGRESS
  -> QUARANTINE_COMPLETE
  -> PHYSICALLY_IMPORTED
  -> CLOSURE_VALIDATED
  -> OPTIONAL_REF_PUBLISHED
  -> DONE
```

### 27.3 Push state

```text
READY
  -> SNAPSHOT_OPEN
  -> PUSH_PRECHECKED
  -> MISSING_SET_NEGOTIATED
  -> UPLOAD_IN_PROGRESS
  -> QUARANTINE_COMPLETE
  -> PHYSICALLY_IMPORTED
  -> GRAPH_VALIDATED
  -> REF_PUBLICATION_REQUESTED
  -> DONE_OR_AMBIGUOUS
```

### 27.4 State-machine enforcement

A peer receiving a message invalid for the current request state returns `ProtocolStateViolation` and cancels the request. Repeated violations close the connection.

## 28. Ref divergence and merge interaction

### 28.1 Divergence detection

A ref diverges when the candidate RefUpdate's predecessor is not the receiver's current RefUpdateId.

The protocol does not reinterpret divergence as an automatic merge request.

### 28.2 Allowed outcomes

On divergence, the receiver may:

- return `RefCasMismatch`;
- retain the imported immutable graph;
- return current ref information permitted by local admission.

It MUST NOT:

- force-update the ref;
- create `main-CONFLICT-*`;
- choose last-writer-wins;
- rewrite the candidate RefUpdate;
- sign a new local RefUpdate without an explicit authorized operation.

### 28.3 Explicit merge

The user or application performs merge using the local merge algorithm defined by `ARCHITECTURE.md`. The resulting ObjectVersions, RepoCommit, and RefUpdate are new local records and may then be pushed normally.

## 29. Policy and keyring behavior during synchronization

### 29.1 Historical validation

The receiver validates each record under the policy selected by its immutable predecessor history, not under the receiver's current branch policy by timestamp.

### 29.2 Detached malicious policy graph

A peer may send a self-consistent but unanchored policy graph. The receiver MUST reject its use for ref publication unless it is connected through the valid genesis and first-parent policy transition rules.

### 29.3 Revoked keys

A historical record signed before revocation may remain historically valid. A detached future RepoCommit or RefUpdate signed by a key revoked in the governing predecessor policy cannot be published, regardless of its claimed timestamp.

### 29.4 Keyring metadata

Metadata-complete synchronization transfers KeyringRecord structure and wrapped slots as immutable metadata. It does not transmit unwrapped ContentIdKeys, DEKs, KEKs, passwords, or recipient private keys.

A receiver that lacks decryption material may still validate storage bytes, signatures, and logical metadata but cannot claim plaintext audit success.

## 30. Security considerations

### 30.1 Downgrade resistance

TLS version, ALPN, protocol major, format version, and required feature bits are fail-closed. There is no fallback to plaintext or an older ad-hoc protocol on the same endpoint.

### 30.2 Replay

TLS 0-RTT is disabled. Ref mutation additionally requires exact predecessor-linked CAS and idempotent RefUpdateId processing.

Replaying immutable pack bytes is harmless when RecordIds and payloads are identical. Conflicting bytes under the same RecordId are corruption.

### 30.3 Metadata disclosure

An admitted metadata-complete peer can observe repository metadata described in `POLICY.md` and `CRYPTO.md`. Payload encryption does not hide this information.

Operators requiring metadata isolation must deny synchronization admission or use separate repositories. Interest filters are not access control.

### 30.4 Traffic analysis

TLS hides message content but not endpoint identity, connection timing, total byte counts, or approximate object sizes. Traffic-analysis resistance is not a v1 goal.

### 30.5 Malicious pack construction

A malicious peer may attempt:

- oversized lengths;
- integer overflow;
- pathological CBOR nesting;
- invalid offsets;
- overlapping ranges;
- duplicate IDs;
- decompression bombs;
- deep commit graphs;
- missing dependencies;
- signature-valid but unauthorized records.

All corresponding checks are mandatory and occur before publication.

### 30.6 Request smuggling and desynchronization

Frame boundaries are fixed by the 16-byte header and negotiated length limits. Control CBOR must consume exactly the frame payload; trailing bytes are invalid.

### 30.7 Path safety

Network-provided identifiers are never used directly as filesystem paths.

Transfer IDs, pack checksums, and RecordIds are converted through fixed encoders into implementation-controlled filenames. Ref names are validated by `FORMAT.md` before any ref-path mapping.

### 30.8 Quarantine isolation

Quarantine files are not mmaped or parsed by ordinary readers. Validation uses bounded parsers and does not publish paths until checks succeed.

### 30.9 Server-side request authorization

A server evaluates local admission at request time, not only at connection time. Disabling a remote prevents new requests even on an already established session.

An in-progress physical transfer may finish according to local policy, but ref publication must recheck admission.

## 31. Rust interfaces

### 31.1 RemoteAdapter

```rust
#[async_trait]
pub trait RemoteAdapter: Send + Sync {
    async fn connect(&self) -> Result<Box<dyn SyncSession>>;
}
```

### 31.2 SyncSession

```rust
#[async_trait]
pub trait SyncSession: Send + Sync {
    fn peer(&self) -> &AuthenticatedPeer;
    fn negotiated(&self) -> &NegotiatedProtocol;

    async fn open_snapshot(
        &self,
        purpose: SnapshotPurpose,
    ) -> Result<RemoteSnapshot>;

    async fn list_refs(
        &self,
        snapshot: &RemoteSnapshot,
        prefix: Option<&str>,
    ) -> Result<RefStream>;

    async fn plan_fetch(
        &self,
        request: FetchPlanRequest,
    ) -> Result<FetchPlan>;

    async fn fetch_records(
        &self,
        request: NeedRecordsRequest,
        sink: &mut dyn AsyncPackSink,
    ) -> Result<TransferReport>;

    async fn plan_push(
        &self,
        request: PushPlanRequest,
    ) -> Result<PushPlan>;

    async fn upload_pack(
        &self,
        descriptor: UploadDescriptor,
        source: &mut dyn AsyncPackSource,
    ) -> Result<UploadReport>;

    async fn publish_ref(
        &self,
        request: PublishRefRequest,
    ) -> Result<PublishRefResult>;

    async fn query_ref_status(
        &self,
        request: RefStatusRequest,
    ) -> Result<RefStatusResult>;

    async fn fetch_chunks(
        &self,
        request: FetchChunksRequest,
        sink: &mut dyn AsyncPackSink,
    ) -> Result<TransferReport>;

    async fn cancel(&self, request_id: u64) -> Result<()>;
}
```

### 31.3 No `Vec<u8>` pack API

Pack transfer APIs MUST stream through bounded async readers/writers. They MUST NOT require an entire pack or object to be held in memory.

### 31.4 AuthenticatedPeer

```rust
pub struct AuthenticatedPeer {
    pub remote_id: RemoteId,
    pub node_id: NodeId,
    pub transport_fingerprint: [u8; 32],
    pub repository_id: RepositoryId,
    pub federation_id: FederationId,
    pub repository_genesis_id: RepositoryGenesisId,
    pub admission: AdmissionCapabilities,
}
```

### 31.5 Server interfaces

The server separates:

```text
transport/session service
snapshot service
graph planner
pack builder
quarantine receiver
record validator
physical importer
policy validator
ref publisher
promise store
```

The network handler MUST NOT write ref files directly.

## 32. CLI behavior

### 32.1 Remote configuration

Recommended commands:

```text
eternal remote add <name> <endpoint> \
    --node-id <uuid> \
    --transport-key <fingerprint> \
    --allow-fetch \
    [--allow-push] \
    [--promisor]

eternal remote rotate-key <name> \
    --old <fingerprint> \
    --new <fingerprint>
```

Transport-key rotation is an explicit local operation and does not create a RepoCommit.

### 32.2 Fetch

```text
eternal fetch <remote> <ref>
```

Fetch imports immutable records and updates only local non-authoritative remote-observation cache.

### 32.3 Pull

```text
eternal pull <remote> <ref> [--publish]
```

Without `--publish`, pull behaves as fetch-only. With `--publish`, it attempts exact predecessor-linked publication of the received RefUpdate and refuses divergence.

### 32.4 Push

```text
eternal push <remote> <local-ref>:<remote-ref>
```

The command displays:

- expected remote predecessor;
- local candidate RefUpdateId;
- records/bytes to upload;
- whether content promises are involved;
- requested ref operation.

Non-fast-forward or creation/deletion operations require explicit confirmation according to CLI policy, but the core authorization rules remain unchanged.

### 32.5 Output separation

CLI output MUST distinguish:

- records transferred;
- records imported;
- chunks promised;
- graph validated;
- ref applied;
- ref not applied;
- publication outcome unknown.

A successful transfer with failed CAS is not displayed as a successful push.

## 33. Observability and audit logs

### 33.1 Safe fields

Operational logs may contain:

- SessionId;
- RemoteId and node ID;
- request ID;
- snapshot/plan/transfer IDs;
- ref name;
- counts and byte totals;
- checksums and public RecordIds;
- result/error class;
- elapsed time.

### 33.2 Forbidden fields

Logs MUST NOT contain:

- passwords;
- private keys;
- ContentIdKey;
- DEKs or KEKs;
- unwrapped key slots;
- decrypted payload bytes;
- TLS private material;
- arbitrary user metadata by default.

### 33.3 Repository audit evidence

Transport logs are not repository authorization evidence. The authoritative evidence remains immutable records and mutable ref pointers.

## 34. Mandatory tests

### 34.1 Transport tests

Tests MUST cover:

- TLS 1.3 only;
- ALPN mismatch rejection;
- exact transport-key pinning;
- wrong node ID rejection;
- same node ID rejection;
- client certificate absence;
- TLS 0-RTT disabled;
- SessionId equality and channel binding;
- transport-key rotation requiring explicit local update.

### 34.2 Identity tests

Tests MUST cover:

- same repository/federation/genesis accepted;
- repository mismatch rejected;
- federation mismatch rejected;
- same repository ID with different genesis rejected;
- config values cannot override validated genesis identity;
- different node IDs of the same clone family synchronize.

### 34.3 Framing tests

Tests MUST cover:

- every frame type;
- short headers;
- oversized payload declaration;
- reserved flags;
- duplicate request IDs;
- invalid CBOR;
- trailing control bytes;
- interleaved request streams;
- cancellation;
- connection-fatal state violations.

### 34.4 Snapshot tests

Tests MUST cover:

- stable ref advertisement under concurrent writes;
- snapshot expiry;
- no page mixing across snapshots;
- generation pin prevents source pack deletion;
- resource release after cancellation/expiry.

### 34.5 Graph-planning tests

Tests MUST cover:

- empty repository;
- linear history;
- merge DAG;
- divergent refs;
- supplied have boundary;
- no common boundary until genesis;
- policy/keyring ancestry;
- ObjectVersion parent history;
- complete SMT closure;
- maliciously omitted inventory dependency detected by client;
- traversal limit fail-loud;
- no whole-repository hash-set exchange.

### 34.6 Transfer tests

Tests MUST cover:

- standard pack/index round trip;
- streaming without whole-pack buffering;
- index-first and sequential pack fetch;
- interrupted download and resume;
- descriptor mismatch on resume;
- conflicting repeated range;
- pack checksum mismatch;
- index checksum mismatch;
- duplicate identical RecordId accepted/deduplicated;
- duplicate conflicting RecordId rejected;
- TransactionEnd rejected from transfer pack;
- StoreManifest/CURRENT/ref/private-key files cannot be transferred as records.

### 34.7 Quarantine and import tests

Tests MUST cover failpoints:

- before quarantine write;
- during partial write;
- after quarantine fsync;
- before validation;
- after validation;
- during active-segment sealing;
- before new StoreManifest fsync;
- before/after CURRENT rename;
- before/after `.eternal` directory fsync;
- before old generation retirement.

At every failpoint, ordinary open sees either the old physical generation or the complete new one.

### 34.8 Pull tests

Tests MUST cover:

- fetch-only imports no ref;
- exact-predecessor pull publishes;
- divergent pull refuses publication;
- imported records survive CAS failure;
- no implicit remote-tracking ref;
- no automatic merge;
- ambiguous publication resolved by REF_STATUS.

### 34.9 Push tests

Tests MUST cover:

- remote missing-set negotiation;
- early CAS mismatch avoids unnecessary transfer where possible;
- concurrent remote update after precheck causes final CAS failure;
- valid signatures without authorization rejected;
- explicit branch creation authorization;
- branch deletion tombstone;
- immutable tag behavior;
- no automatic conflict branch;
- idempotent replay of candidate RefUpdateId.

### 34.10 Partial-clone tests

Tests MUST cover:

- metadata-complete clone with zero EncodedChunks;
- interest-selected prefetch;
- exact deterministic filter behavior;
- promise durability before ref publication;
- configured promisor requirement;
- promise loss reported as degraded availability;
- on-demand chunk import without RepoCommit;
- multiple promisors and failover;
- all promisors unavailable;
- missing policy/commit/SMT/manifest cannot be promised;
- metadata remains visible despite encrypted content.

### 34.11 Security tests

Tests MUST cover:

- downgrade rejection;
- no plaintext fallback;
- malformed X.509/SPKI handling;
- wrong pinned key with correct repository metadata;
- malicious lengths and integer overflow;
- path traversal attempts in ref names and transfer IDs;
- decompression bomb limits after chunk fetch;
- replayed PUBLISH_REF;
- self-authorizing policy graph;
- revoked-key detached commit;
- rate-limit enforcement;
- sensitive-data log review.

### 34.12 Property tests

Properties include:

- imported immutable records never change their RecordId;
- any published ref target has complete mandatory metadata closure;
- publication outcome is one of old ref or exact candidate ref, never partial bytes;
- transfer resume with the same descriptor produces the same final pack bytes;
- different descriptors cannot share resume state;
- filtering changes only EncodedChunk selection, never logical metadata closure;
- CAS failure never creates a ref;
- on-demand chunk fetch never changes logical state IDs.

### 34.13 Fuzzing

Fuzz targets MUST include:

- frame header parser;
- every control CBOR message;
- inventory pagination and continuation tokens;
- transfer descriptor and range parser;
- promise-offer parser;
- graph planner with cyclic/malformed input attempts;
- ref publication request state machine;
- quarantine pack/index parser;
- error-message parser.

Fuzzing must enforce memory, time, recursion, and output limits.

### 34.14 Interoperability

At least two independent protocol implementations or one implementation plus a protocol fixture harness MUST demonstrate:

- HELLO/HELLO_ACK byte compatibility;
- ref advertisement compatibility;
- graph inventory compatibility;
- standard pack/index transfer;
- resumable range behavior;
- PUBLISH_REF idempotency;
- partial-clone promise behavior;
- all mandatory negative cases.

## 35. Required protocol fixtures

The repository SHOULD add:

```text
tests/vectors/sync-v1/
├── hello-client.cbor
├── hello-server.cbor
├── hello-ack.cbor
├── ref-page.cbor
├── graph-plan.cbor
├── inventory-page.cbor
├── transfer-descriptor.cbor
├── promise-offer.cbor
├── publish-ref.cbor
├── publish-result.cbor
├── error.cbor
├── transfer.pack
├── transfer.idx
└── transcript.json
```

Fixtures MUST use fixed test identities, non-secret test keys, fixed TLS-exporter test bytes, fixed nonces, and exact expected SessionId.

They are protocol conformance vectors, not runtime repository data.

## 36. Implementation order

### Phase S0: protocol fixtures and state machines

- define all control CBOR field maps;
- generate golden messages;
- implement frame parser and request dispatcher;
- implement state-machine tests;
- implement mock transport.

### Phase S1: local filesystem synchronization

- snapshots;
- ref advertisement;
- graph planner;
- inventory and need calculation;
- standard transfer-pack builder;
- quarantine and physical import;
- fetch-only;
- exact ref publication.

This phase proves protocol semantics without network complexity.

### Phase S2: TLS/TCP transport

- dedicated node transport keys;
- pinned mutual TLS 1.3;
- ALPN and preface;
- HELLO negotiation;
- bounded async framing;
- cancellation/backpressure.

### Phase S3: push and resume

- push precheck;
- missing-set negotiation;
- streamed upload;
- resumable download/upload;
- ambiguous publication query.

### Phase S4: partial clone

- interest evaluation;
- durable promise store;
- promise offers;
- on-demand ChunkId fetch;
- promisor failover and reconstruction.

### Phase S5: hardening

- rate limits;
- fuzzing;
- malicious-peer tests;
- cross-platform tests;
- interoperability harness;
- operational telemetry and redaction audit.

## 37. Conformance checklist

A synchronization implementation is conforming only when:

- [ ] TLS 1.3 mutual pinned transport authentication is enforced;
- [ ] TLS early data and plaintext fallback are disabled;
- [ ] repository, federation, genesis, and node identities are checked;
- [ ] HELLO limits and required features are fail-closed;
- [ ] all ref advertisements and plans use one pinned snapshot;
- [ ] graph discovery is closure-specific and does not exchange global hash sets;
- [ ] control messages use deterministic bounded CBOR;
- [ ] pack transfer uses standard format-v1 pack/index bytes;
- [ ] transfer data is streamed and resumable without whole-pack memory buffering;
- [ ] all incoming bytes remain quarantined before validation;
- [ ] physical import uses StoreManifest generation publication;
- [ ] logical publication uses exact RefUpdateId CAS;
- [ ] every incoming graph is independently validated under POLICY.md;
- [ ] no CAS failure causes an implicit branch, merge, or force update;
- [ ] partial clone omits only EncodedChunk records;
- [ ] promises are durable before ref publication;
- [ ] on-demand content fetch does not create logical commits;
- [ ] publication requests are idempotent by RefUpdateId;
- [ ] ambiguous outcomes are resolved by remote ref-status query;
- [ ] limits are checked before allocation and traversal;
- [ ] logs exclude secret and plaintext material;
- [ ] mandatory failpoint, fuzz, security, and interoperability tests pass.

## 38. Final invariant

> Synchronization may copy immutable evidence and may request one predecessor-linked mutable publication, but it never grants trust by transport alone, never weakens repository validation, never hides a conflict behind an automatic branch or merge, and never exposes a ref until the receiver has independently validated and durably installed the complete target graph or its explicitly permitted content promises.
