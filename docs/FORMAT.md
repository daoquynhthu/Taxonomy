# EternalCore v4 Storage Format Specification

> Status: implementation baseline  
> Format family: EternalCore v4  
> Logical format version: 1  
> Physical segment/pack/index version: 1
>
> This document is normative. It fixes the byte-level and deterministic-encoding rules required by `ARCHITECTURE.md`. An implementation that produces records differing from these rules is not v4-compatible, even when the decoded data appears equivalent.

## 1. Scope and authority

This specification defines:

- primitive byte representations;
- the deterministic CBOR profile;
- domain-separated identifiers;
- signed-record envelopes;
- field numbers and value constraints for every v4 logical record;
- deterministic content-defined chunking;
- content roots and Sparse Merkle Tree hashes;
- active-segment, pack, external-index, ref, `HEAD`, `CURRENT`, and StoreManifest formats;
- record validation and compatibility behavior;
- normative golden vectors.

Cryptographic policy and operational procedures are expanded in `CRYPTO.md`, transaction ordering in `TRANSACTIONS.md`, authorization in `POLICY.md`, and network framing in `SYNC.md`. Those documents may add validation requirements but must not redefine bytes or identifiers fixed here.

Where this document closes a representation omitted by `ARCHITECTURE.md`, this document is controlling for the format. In particular, v1 fixes the following:

1. `StoreManifest` carries `repository_genesis_id`, making the trust bootstrap locatable without treating `config.toml` as authority.
2. `PolicyRecord` carries newly introduced public keys, so every historical signature remains verifiable from immutable records.
3. `RefUpdate.target_commit_id` is nullable; a null target is the signed tombstone for a deleted branch. Ref pointer files are retained and point to that tombstone update.
4. `TransactionEnd` is segment-local physical metadata and is not copied into sealed packs.

## 2. Conformance language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

A conforming reader MUST:

- reject non-canonical encodings;
- reject identifiers that do not recompute exactly;
- reject malformed lengths before allocating payload-sized memory;
- reject unknown v1 fields, enum values, record types, or mandatory algorithms;
- enforce all structural limits in Section 20;
- fail loudly rather than reinterpret malformed data.

A conforming writer MUST emit exactly one canonical representation for a logical value.

## 3. Primitive representations

### 3.1 Byte order

All fixed-width integers in binary headers and hash preimages use little-endian byte order unless explicitly stated otherwise.

CBOR integers use RFC 8949 network-order argument bytes as required by CBOR itself.

### 3.2 UUID

A UUID is exactly 16 bytes in RFC 4122 canonical byte order. Implementations MUST NOT use the mixed-endian in-memory layout historically associated with Windows GUID structures.

The textual form, when used by a CLI, is lowercase hexadecimal with hyphens. Textual UUIDs never enter an identifier preimage.

### 3.3 Hash and identifier

Every hash-like identifier is exactly 32 bytes.

Text form is exactly 64 lowercase hexadecimal characters. Uppercase hexadecimal is rejected in authoritative pointer files.

The following are distinct Rust/newtype domains even though they share the same byte width:

- `RecordId`
- `RepositoryGenesisId`
- `PolicyId`
- `KeyringId`
- `ChunkId`
- `EncodedChunkRecordId`
- `ContentManifestId`
- `VersionId`
- `RepoCommitId`
- `RefUpdateId`
- `ObjectKey`
- `SmtRoot`
- `StoreManifestId`
- `KeyId`

Implementations MUST NOT silently coerce between these types.

### 3.4 Signature and public keys

- Ed25519 public key: 32 raw bytes.
- Ed25519 signature: 64 raw bytes.
- X25519 public key: 32 raw bytes.

A signing implementation MUST reject non-canonical Ed25519 signatures according to its high-level library's strict verification behavior.

### 3.5 Timestamp

`created_at_ns` is an `i64` count of Unix nanoseconds. It is an authenticated declaration only. No format validation treats it as trusted time, monotonic time, or an authorization clock.

### 3.6 Text

All text is well-formed UTF-8. EternalCore performs no Unicode normalization. Equality is byte equality of the UTF-8 encoding.

NUL and ASCII control characters U+0000 through U+001F and U+007F are forbidden in all identifier-like strings, ref names, data types, relation types, key-slot labels, and paths. User metadata text MAY contain controls other than NUL if permitted by the caller, but CLI output MUST escape them.

## 4. Deterministic CBOR profile

### 4.1 Base profile

EternalCore uses RFC 8949 core deterministic encoding with these additional restrictions:

- no indefinite-length item;
- shortest integer and length encoding only;
- no floating-point value;
- no CBOR tag;
- no undefined value;
- no simple value other than `false`, `true`, and `null`;
- no duplicate map key;
- map keys sorted by bytewise lexicographic order of their deterministic CBOR encodings;
- authoritative record maps use unsigned integer keys only;
- unknown map keys are rejected in format version 1.

All record field keys in v1 are between 0 and 23, so their deterministic order is ordinary ascending numeric order.

### 4.2 Integer ranges

- Unsigned schema fields are CBOR major type 0 and MUST fit in `u64`.
- Signed schema fields are major type 0 or 1 and MUST fit in `i64`.
- A negative integer less than `i64::MIN` is invalid.
- Positive values in a field declared `i64` MUST not exceed `i64::MAX`.

### 4.3 Optional values

An optional field is always present in its enclosing fixed-schema map. Absence is encoded as CBOR `null`. Omitting the key is non-canonical.

### 4.4 Sets

A logical set is encoded as an array sorted by the canonical byte representation specified for that element type. Duplicate elements are invalid.

For 32-byte identifiers, order is unsigned lexicographic byte order.

### 4.5 CanonicalValue

User metadata uses an explicitly tagged union so positive `I64` and `U64` values remain distinguishable.

| Variant | Encoding |
|---|---|
| Null | `[0]` |
| Bool | `[1, bool]` |
| I64 | `[2, integer]` |
| U64 | `[3, unsigned]` |
| Text | `[4, text]` |
| Bytes | `[5, bytes]` |
| Array | `[6, [CanonicalValue...]]` |
| Map | `[7, [[text_key, CanonicalValue]...]]` |

Map entries are sorted by raw UTF-8 key bytes and keys are unique. A `CanonicalValue::Map` is deliberately an array of pairs rather than a CBOR map, avoiding ambiguity between application key ordering and record field ordering.

Maximum nesting and element limits are defined in Section 20.

### 4.6 SignedRecord envelope

Every signed logical record is physically encoded as this map:

| Key | Field | Type | Requirement |
|---:|---|---|---|
| 0 | envelope_version | uint | exactly 1 |
| 1 | payload | map | record-specific payload |
| 2 | record_id | bytes(32) | ID of canonical payload |
| 3 | signer_key_id | bytes(32) | signer fingerprint |
| 4 | signature | bytes(64) | Ed25519 signature over `record_id` |

The envelope itself has no separate identifier. A segment or pack frame containing a signed record uses the inner `record_id` as its frame ID.

For payloads with `author_key_id`, it MUST equal `signer_key_id`. For `RepositoryGenesis`, `creator_key_id` MUST equal `signer_key_id`.

## 5. Domain separation and identifiers

### 5.1 Generic DomainHash

```text
DomainHash(tag, payload) = SHA-256(
    u16_le(byte_length(tag_utf8)) ||
    tag_utf8 ||
    u64_le(byte_length(payload)) ||
    payload
)
```

The tag length MUST fit in `u16`; all v1 tags do. The payload length MUST fit in `u64`.

### 5.2 KeyId

```text
KeyId = DomainHash(
    "EternalCore:KeyFingerprint:v1",
    algorithm_id_u8 || raw_public_key
)
```

Algorithm IDs:

| ID | Key algorithm |
|---:|---|
| 1 | Ed25519 signing key |
| 2 | X25519 encryption recipient key |

### 5.3 Domain tags

| Context | Tag |
|---|---|
| RepositoryGenesis payload | `EternalCore:RepositoryGenesis:v1` |
| PolicyRecord payload | `EternalCore:PolicyRecord:v1` |
| KeyringRecord payload | `EternalCore:KeyringRecord:v1` |
| Key fingerprint | `EternalCore:KeyFingerprint:v1` |
| Public ChunkId | `EternalCore:PublicChunk:v1` |
| Private ChunkId HMAC context | `EternalCore:PrivateChunk:v1` |
| FastCDC gear entry | `EternalCore:FastCDCGear:v1` |
| FastCDC gear table | `EternalCore:FastCDCGearTable:v1` |
| EncodedChunk payload | `EternalCore:EncodedChunk:v1` |
| Content root leaf | `EternalCore:ContentLeaf:v1` |
| Content root internal node | `EternalCore:ContentNode:v1` |
| Empty content root | `EternalCore:ContentEmpty:v1` |
| ContentManifest payload | `EternalCore:ContentManifest:v1` |
| ObjectVersion payload | `EternalCore:ObjectVersion:v1` |
| RepoCommit payload | `EternalCore:RepoCommit:v1` |
| RefUpdate payload | `EternalCore:RefUpdate:v1` |
| ObjectId SMT key | `EternalCore:ObjectKey:v1` |
| SMT empty leaf | `EternalCore:SMTEmptyLeaf:v1` |
| SMT populated leaf | `EternalCore:SMTLeaf:v1` |
| SMT internal node | `EternalCore:SMTInternal:v1` |
| TransactionEnd payload | `EternalCore:TransactionEnd:v1` |
| Transaction record-ID batch | `EternalCore:TransactionBatch:v1` |
| Chunk AEAD AAD | `EternalCore:ChunkAAD:v1` |
| Wrapped-key AEAD AAD | `EternalCore:KeyWrapAAD:v1` |
| Pack checksum | `EternalCore:Pack:v1` |
| Pack-index checksum | `EternalCore:PackIndex:v1` |
| StoreManifest payload | `EternalCore:StoreManifest:v1` |

A v1 implementation MUST compare tags exactly, including case.

### 5.4 Signed payload IDs

```text
RepositoryGenesisId = DomainHash(RepositoryGenesis tag, canonical payload)
PolicyId            = DomainHash(PolicyRecord tag, canonical payload)
KeyringId           = DomainHash(KeyringRecord tag, canonical payload)
VersionId           = DomainHash(ObjectVersion tag, canonical payload)
RepoCommitId        = DomainHash(RepoCommit tag, canonical payload)
RefUpdateId         = DomainHash(RefUpdate tag, canonical payload)
```

The detached Ed25519 signature signs the resulting 32 bytes directly, not their hexadecimal text and not the complete envelope.

## 6. Names and identifier strings

### 6.1 ObjectId

An ObjectId:

- is 1 through 1024 UTF-8 bytes;
- in v4 contains only `A-Z`, `a-z`, `0-9`, `_`, `-`, `.`, and `/`;
- does not begin or end with `/`;
- contains no empty path segment;
- contains no `.` or `..` segment.

ObjectId canonical bytes are its exact UTF-8 bytes.

```text
ObjectKey = DomainHash("EternalCore:ObjectKey:v1", object_id_utf8)
```

### 6.2 Ref name

A ref name is 1 through 1024 ASCII bytes and MUST begin with one of:

- `refs/heads/`
- `refs/tags/`
- `refs/pins/`
- `refs/merge-requests/`

The suffix follows ObjectId path-segment rules. A ref name MUST NOT end in `.lock`, contain `//`, contain `@{`, or contain a backslash.

### 6.3 RefPattern

A policy ref pattern is either:

- an exact valid ref name; or
- a valid namespace prefix ending in `/**`, for example `refs/heads/contributors/**`.

`/**` matches zero or more complete suffix path segments. No other wildcard is valid. Exact matches take precedence; otherwise the longest matching prefix controls.

### 6.4 Other constrained text

- `data_type`: 1..256 UTF-8 bytes, no control characters.
- `relation_type`: 1..256 UTF-8 bytes, no control characters.
- commit message: 0..1,048,576 UTF-8 bytes.
- key-slot label: 1..128 UTF-8 bytes, no control characters.

## 7. Fixed FastCDC-v1 chunking profile

### 7.1 Parameters

| Parameter | Value |
|---|---:|
| algorithm ID | 1 |
| algorithm version | 1 |
| minimum chunk size | 1,048,576 bytes |
| average chunk size | 4,194,304 bytes |
| maximum chunk size | 8,388,608 bytes |
| average bits | 22 |
| normalization level | 2 |
| before-average mask | `0x0000000000ffffff` |
| after-average mask | `0x00000000000fffff` |

### 7.2 Gear table derivation

The 256-entry table is fixed without embedding architecture-dependent source literals:

```text
for b in 0..255:
    h = DomainHash("EternalCore:FastCDCGear:v1", one_byte(b))
    gear[b] = u64_le(h[0..8])

gear_table_bytes = concat(u64_le(gear[0]), ..., u64_le(gear[255]))
gear_table_id = DomainHash("EternalCore:FastCDCGearTable:v1", gear_table_bytes)
```

The normative table ID is given in Section 21.

### 7.3 Cut algorithm

The rolling state is unsigned wrapping `u64` arithmetic.

```text
find_cut(input):
    n = len(input)
    if n <= MIN:
        return n

    fp = 0
    i = MIN
    normal_end = min(n, AVG)

    while i < normal_end:
        fp = (fp << 1) + gear[input[i]]       // wrapping u64
        if (fp & BEFORE_MASK) == 0:
            return i + 1
        i += 1

    hard_end = min(n, MAX)
    while i < hard_end:
        fp = (fp << 1) + gear[input[i]]       // wrapping u64
        if (fp & AFTER_MASK) == 0:
            return i + 1
        i += 1

    return hard_end
```

Chunking repeats from the returned boundary with `fp = 0`. A final remainder of any size, including less than MIN, forms the final chunk.

Empty content produces zero chunks. A zero-length chunk is invalid.

### 7.4 ChunkingDescriptor

| Key | Field | Type | Value |
|---:|---|---|---|
| 0 | algorithm | uint | 1 |
| 1 | version | uint | 1 |
| 2 | minimum_size | uint | 1048576 |
| 3 | average_size | uint | 4194304 |
| 4 | maximum_size | uint | 8388608 |
| 5 | normalization | uint | 2 |
| 6 | gear_table_id | bytes(32) | fixed v1 table ID |

Any other descriptor is unsupported in v4 core.

## 8. Chunk identity, codec, and encryption descriptors

### 8.1 Public ChunkId

```text
ChunkId = DomainHash("EternalCore:PublicChunk:v1", raw_chunk_bytes)
```

### 8.2 Private ChunkId

For encrypted/private content:

```text
private_preimage =
    u16_le(len("EternalCore:PrivateChunk:v1")) ||
    "EternalCore:PrivateChunk:v1" ||
    u64_le(len(raw_chunk_bytes)) ||
    raw_chunk_bytes

ChunkId = HMAC-SHA256(ContentIdKey, private_preimage)
```

`ContentIdKey` is exactly 32 bytes. The public hash of plaintext MUST NOT be stored alongside a private ChunkId.

### 8.3 CodecDescriptor

Codec descriptor is a map.

For no compression:

| Key | Field | Type | Value |
|---:|---|---|---|
| 0 | algorithm | uint | 0 |

For zstd:

| Key | Field | Type | Requirement |
|---:|---|---|---|
| 0 | algorithm | uint | 1 |
| 1 | level | int | -5 through 22 |
| 2 | profile | uint | 1 |

Zstd profile 1 means:

- no external dictionary;
- content size included when known;
- dictionary ID disabled;
- frame checksum enabled;
- single-threaded frame construction;
- one independent zstd frame per chunk.

Different conforming zstd library releases MAY produce different encoded bytes. This is valid because `EncodedChunkRecordId` identifies actual encoded bytes, while logical chunk and manifest IDs remain unchanged.

### 8.4 EncryptionDescriptor

No encryption is CBOR `null`.

XChaCha20-Poly1305 descriptor:

| Key | Field | Type | Requirement |
|---:|---|---|---|
| 0 | algorithm | uint | 1 |
| 1 | key_epoch | uint | nonzero u64 |
| 2 | nonce | bytes(24) | random, unique for the DEK with overwhelming probability |
| 3 | aad_profile | uint | 1 |

`encoded_bytes` contains ciphertext followed by the 16-byte Poly1305 tag, as emitted by a high-level XChaCha20-Poly1305 AEAD API.

### 8.5 Chunk AEAD AAD

AAD profile 1 is the DomainHash preimage—not the hash output—of the deterministic CBOR map below:

| Key | Field |
|---:|---|
| 0 | repository_id |
| 1 | format_version |
| 2 | chunk_id |
| 3 | plaintext_length |
| 4 | codec descriptor |
| 5 | encryption algorithm ID |
| 6 | key_epoch |

```text
aad_payload = deterministic_cbor(aad_map)
aad = u16_le(len("EternalCore:ChunkAAD:v1")) ||
      "EternalCore:ChunkAAD:v1" ||
      u64_le(len(aad_payload)) ||
      aad_payload
```

Compression occurs before encryption. Reading performs authentication, then decompression, then ChunkId verification.

## 9. Logical record schemas

Unless stated otherwise, every record payload is a fixed-key deterministic CBOR map. All IDs are 32-byte byte strings and all UUIDs are 16-byte byte strings.

### 9.1 RepositoryGenesisPayload — record type 1, signed

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | federation_id | bytes(16) | UUID |
| 3 | creator_key_id | bytes(32) | Ed25519 KeyId |
| 4 | creator_public_key | bytes(32) | raw Ed25519 public key |
| 5 | initial_policy_id | bytes(32) | PolicyId |
| 6 | initial_keyring_id | bytes(32) | KeyringId |
| 7 | created_at_ns | int | i64 |

Validation MUST recompute `creator_key_id` from algorithm ID 1 and `creator_public_key`.

### 9.2 PublicKeyEntry

A PolicyRecord introduces public keys through this map:

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | key_id | bytes(32) | recomputed fingerprint |
| 1 | algorithm | uint | 1 Ed25519, 2 X25519 |
| 2 | public_key | bytes(32) | raw key |
| 3 | label | text | 0..128 bytes |

Entries are sorted by `key_id` and unique. A key ID already introduced in an ancestor policy MUST NOT be reintroduced with different bytes or algorithm.

### 9.3 RefPermissionEntry

| Key | Field | Type |
|---:|---|---|
| 0 | pattern | text RefPattern |
| 1 | writers | array of bytes(32) |

Entries are sorted by pattern UTF-8 bytes. Writer IDs are sorted and unique.

### 9.4 PolicyRecordPayload — record type 2, signed

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | previous_policy_id | null or bytes(32) | null only for initial policy |
| 3 | policy_sequence | uint | starts at 1, increments by 1 |
| 4 | introduced_keys | array of PublicKeyEntry | sorted, unique |
| 5 | administrators | array of bytes(32) | sorted set of Ed25519 KeyIds |
| 6 | writers | array of bytes(32) | sorted set of Ed25519 KeyIds |
| 7 | per_ref_permissions | array of RefPermissionEntry | sorted, unique patterns |
| 8 | tag_creators | array of bytes(32) | sorted set |
| 9 | revoked_keys | array of bytes(32) | sorted cumulative set |
| 10 | created_at_ns | int | i64 |
| 11 | author_key_id | bytes(32) | Ed25519 KeyId |

The effective public-key registry is the union of `introduced_keys` along the policy ancestry. Keys are never removed from that historical registry. Revocation controls future authorization, not historical signature validity.

### 9.5 PasswordKdfDescriptor

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | algorithm | uint | 1 = Argon2id |
| 1 | version | uint | 0x13 |
| 2 | salt | bytes | 16..64 bytes |
| 3 | memory_kib | uint | at least 65536 |
| 4 | iterations | uint | at least 1 |
| 5 | parallelism | uint | 1..255 |

### 9.6 KeySlot

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | slot_id | bytes(16) | UUID |
| 1 | slot_kind | uint | 1 password, 2 X25519 recipient, 3 recovery recipient |
| 2 | label | text | 1..128 bytes |
| 3 | password_kdf | null or PasswordKdfDescriptor | required only for kind 1 |
| 4 | recipient_key_id | null or bytes(32) | required for kinds 2 and 3 |
| 5 | ephemeral_public_key | null or bytes(32) | X25519, required for kinds 2 and 3 |
| 6 | wrap_algorithm | uint | 1 = XChaCha20-Poly1305 |
| 7 | wrap_nonce | bytes(24) | random |
| 8 | wrapped_secret | bytes | ciphertext plus 16-byte tag |
| 9 | created_at_ns | int | i64 |

Key-slot AAD profile 1 is the framed deterministic CBOR encoding of:

| Key | Field |
|---:|---|
| 0 | repository_id |
| 1 | slot_id |
| 2 | slot_kind |
| 3 | secret_kind: 1 ContentIdKey, 2 DEK |
| 4 | key_epoch: 0 for ContentIdKey, DEK epoch otherwise |
| 5 | recipient_key_id or null |

The framing tag is `EternalCore:KeyWrapAAD:v1`, using the same length framing as DomainHash but passing the framed bytes as AEAD AAD.

### 9.7 WrappedDek

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | key_epoch | uint | nonzero, unique |
| 1 | dek_id | bytes(16) | UUID |
| 2 | slots | array of KeySlot | sorted by slot_id, non-empty |

### 9.8 KeyringRecordPayload — record type 3, signed

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | previous_keyring_id | null or bytes(32) | null only for initial keyring |
| 3 | key_epoch | uint | highest active DEK epoch, 0 if none |
| 4 | content_id_key_slots | array of KeySlot | sorted by slot_id; empty when encryption unavailable |
| 5 | dek_slots | array of WrappedDek | sorted by key_epoch |
| 6 | retired_key_epochs | array of uint | sorted unique |
| 7 | created_at_ns | int | i64 |
| 8 | author_key_id | bytes(32) | Ed25519 KeyId |

A content-ID slot wraps the same repository ContentIdKey. A DEK slot wraps exactly the DEK identified by its enclosing `WrappedDek`.

### 9.9 EncodedChunkPayload — record type 4, unsigned

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | chunk_id | bytes(32) | public or private ChunkId |
| 3 | plaintext_length | uint | 1..8388608 |
| 4 | codec | CodecDescriptor | Section 8.3 |
| 5 | encryption | null or EncryptionDescriptor | Section 8.4 |
| 6 | encoded_bytes | bytes | non-empty, within record limit |

```text
EncodedChunkRecordId = DomainHash(
    "EternalCore:EncodedChunk:v1",
    deterministic_cbor(payload)
)
```

For codec `none` and encryption `null`, `encoded_bytes` equals raw chunk bytes. `EncodedChunkRecordId` is still distinct from `ChunkId`.

### 9.10 ContentManifest chunk entry

| Key | Field | Type |
|---:|---|---|
| 0 | chunk_id | bytes(32) |
| 1 | plaintext_length | uint |

Order is content order and MUST NOT be sorted.

### 9.11 Content root

For each ordered chunk entry:

```text
leaf = DomainHash(
    "EternalCore:ContentLeaf:v1",
    chunk_id || u64_le(plaintext_length)
)
```

If there are no chunks:

```text
content_root = DomainHash("EternalCore:ContentEmpty:v1", empty)
```

Otherwise, repeatedly hash adjacent nodes:

```text
parent = DomainHash("EternalCore:ContentNode:v1", left || right)
```

When a level has an odd final node, duplicate it as both left and right. A single leaf is itself the root.

### 9.12 ContentManifestPayload — record type 5, unsigned

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | chunking_scheme | ChunkingDescriptor | fixed v1 descriptor |
| 3 | total_size | uint | sum of entry lengths |
| 4 | chunks | array of chunk entries | content order |
| 5 | content_root | bytes(32) | recomputed root |

Empty content has `total_size = 0`, `chunks = []`, and the fixed empty root.

```text
ContentManifestId = DomainHash(
    "EternalCore:ContentManifest:v1",
    deterministic_cbor(payload)
)
```

### 9.13 Relation

| Key | Field | Type |
|---:|---|---|
| 0 | target_object_id | text ObjectId |
| 1 | relation_type | text |

Relations are sorted by `(target_object_id UTF-8 bytes, relation_type UTF-8 bytes)` and exact duplicates are invalid.

### 9.14 ObjectVersionPayload — record type 6, signed

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | object_id | text ObjectId | valid canonical ID |
| 3 | content_manifest_id | null or bytes(32) | null iff tombstone |
| 4 | parents | array of bytes(32) | 0..64, no duplicates |
| 5 | data_type | text | Section 6.4 |
| 6 | metadata | CanonicalValue | Section 4.5 |
| 7 | relations | array of Relation | sorted, unique |
| 8 | tombstone | bool | consistency with field 3 |
| 9 | created_at_ns | int | i64 |
| 10 | author_key_id | bytes(32) | signer KeyId |

Parent order is semantic. For ordinary updates, the sole parent is the current version. For conflict resolution, parent 0 is the local/current version and additional parent IDs are sorted lexicographically.

### 9.15 SMT leaf payload — record type 7, unsigned semantic ID

| Key | Field | Type |
|---:|---|---|
| 0 | format_version | uint = 1 |
| 1 | object_key | bytes(32) |
| 2 | version_id | bytes(32) |

The frame RecordId is not the hash of CBOR bytes. It is:

```text
RecordId = DomainHash("EternalCore:SMTLeaf:v1", object_key || version_id)
```

### 9.16 SMT internal payload — record type 8, unsigned semantic ID

| Key | Field | Type |
|---:|---|---|
| 0 | format_version | uint = 1 |
| 1 | left_child | bytes(32) |
| 2 | right_child | bytes(32) |

```text
RecordId = DomainHash("EternalCore:SMTInternal:v1", left_child || right_child)
```

Default/empty nodes are not stored as records.

### 9.17 ObjectChange

| Key | Field | Type |
|---:|---|---|
| 0 | object_id | text ObjectId |
| 1 | old_version_id | null or bytes(32) |
| 2 | new_version_id | bytes(32) |

Changes are sorted by ObjectId UTF-8 bytes and ObjectId is unique within a commit.

### 9.18 RepoCommitPayload — record type 9, signed

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | parents | array of bytes(32) | 0..64, no duplicates |
| 3 | changes | array of ObjectChange | sorted, unique IDs |
| 4 | object_state_root | bytes(32) | recomputed SMT root |
| 5 | policy_id | bytes(32) | PolicyId |
| 6 | keyring_id | bytes(32) | KeyringId |
| 7 | created_at_ns | int | i64 |
| 8 | message | text | Section 6.4 |
| 9 | author_key_id | bytes(32) | signer KeyId |

For multiple parents, parent 0 is the state baseline; remaining parents are sorted lexicographically. Parent order is therefore deterministic and preserves baseline semantics.

### 9.19 RefUpdatePayload — record type 10, signed

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | ref_name | text | valid ref name |
| 3 | previous_ref_update_id | null or bytes(32) | predecessor |
| 4 | target_commit_id | null or bytes(32) | null means deleted ref |
| 5 | sequence | uint | starts 1, increments exactly |
| 6 | created_at_ns | int | i64 |
| 7 | author_key_id | bytes(32) | signer KeyId |

A tag update MUST have non-null target, no predecessor, and sequence 1. Tags are immutable after creation in v4 core.

For a branch deletion, the ref pointer file remains present and points to the deletion RefUpdate. A deleted branch is therefore distinguishable from a never-created branch and may be recreated only by extending the deletion update with the next sequence.

### 9.20 TransactionEndPayload — record type 11, unsigned, segment-only

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | transaction_id | bytes(16) | UUID |
| 3 | first_frame_offset | uint | offset of first covered frame |
| 4 | end_frame_offset | uint | exclusive end of last covered frame; start of this TransactionEnd frame |
| 5 | record_count | uint | number of covered non-end frames |
| 6 | record_ids_root | bytes(32) | Section 9.21 |

```text
TransactionEndId = DomainHash(
    "EternalCore:TransactionEnd:v1",
    deterministic_cbor(payload)
)
```

A TransactionEnd covers immediately preceding frames in the same segment whose count, offsets, and IDs match. It is never a logical root and MUST NOT be copied into a sealed pack.

### 9.21 Transaction record-ID root

For record IDs in physical append order:

```text
record_ids_root = DomainHash(
    "EternalCore:TransactionBatch:v1",
    record_id[0] || ... || record_id[n-1]
)
```

For zero records, the payload is empty. A normal logical transaction has at least one record.

## 10. Sparse Merkle Tree format

### 10.1 Bit order

The path is the 256 bits of `ObjectKey`, most-significant bit first. Depth 0 consumes bit 7 of byte 0; depth 255 consumes bit 0 of byte 31.

Bit 0 selects the left child. Bit 1 selects the right child.

### 10.2 Empty hashes

```text
empty[256] = DomainHash("EternalCore:SMTEmptyLeaf:v1", empty)
for d from 255 down to 0:
    empty[d] = DomainHash(
        "EternalCore:SMTInternal:v1",
        empty[d+1] || empty[d+1]
    )
```

The empty tree root is `empty[0]`.

### 10.3 Populated leaf

```text
leaf = DomainHash("EternalCore:SMTLeaf:v1", ObjectKey || VersionId)
```

### 10.4 Internal node

```text
node = DomainHash("EternalCore:SMTInternal:v1", left || right)
```

### 10.5 Storage rule

Only non-default leaf and internal nodes are stored. A child hash equal to the expected `empty[d]` is resolved algorithmically and requires no record.

A stored SMT payload whose semantic RecordId does not match its frame RecordId is invalid.

### 10.6 Proof encoding

An SMT proof is a protocol/application object, not an object-store record. Its deterministic CBOR schema is:

| Key | Field | Type |
|---:|---|---|
| 0 | format_version | uint = 1 |
| 1 | root | bytes(32) |
| 2 | object_key | bytes(32) |
| 3 | version_id | null or bytes(32) |
| 4 | siblings | array of exactly 256 bytes(32), leaf-to-root order |

Proof verification reconstructs from depth 255 down to 0. For non-membership, the starting node is `empty[256]`.

## 11. StoreManifest schema

### 11.1 SegmentDescriptor

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | store_generation | uint | equals manifest generation |
| 1 | segment_id | bytes(16) | UUID |
| 2 | relative_path | text | normalized path below `.eternal/` |

The v1 path is `objects/active/segment-<generation>-<uuid>.seg`.

### 11.2 PackDescriptor

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | pack_checksum | bytes(32) | matches pack filename/content |
| 1 | index_checksum | bytes(32) | matches index content |
| 2 | pack_relative_path | text | normalized below `.eternal/` |
| 3 | index_relative_path | text | normalized below `.eternal/` |
| 4 | record_count | uint | matches pack and index |

Pack descriptors are sorted by `pack_checksum` and unique.

### 11.3 StoreManifestPayload

| Key | Field | Type | Constraint |
|---:|---|---|---|
| 0 | format_version | uint | 1 |
| 1 | repository_id | bytes(16) | UUID |
| 2 | repository_genesis_id | bytes(32) | fixed for all generations |
| 3 | generation | uint | starts at 1, increments exactly |
| 4 | previous_manifest_id | null or bytes(32) | null for generation 1 |
| 5 | active_segment | SegmentDescriptor | exactly one |
| 6 | sealed_packs | array of PackDescriptor | sorted |
| 7 | created_at_ns | int | i64 |

```text
StoreManifestId = DomainHash(
    "EternalCore:StoreManifest:v1",
    deterministic_cbor(payload)
)
```

Filename:

```text
manifests/store-<generation>-<StoreManifestId lowercase hex>.cbor
```

The file contains exactly the canonical CBOR payload and no trailing byte.

## 12. Physical record type codes

| Code | Type | Signed | Allowed in active segment | Allowed in sealed pack |
|---:|---|---:|---:|---:|
| 1 | RepositoryGenesis | yes | yes | yes |
| 2 | PolicyRecord | yes | yes | yes |
| 3 | KeyringRecord | yes | yes | yes |
| 4 | EncodedChunk | no | yes | yes |
| 5 | ContentManifest | no | yes | yes |
| 6 | ObjectVersion | yes | yes | yes |
| 7 | SMT leaf | no | yes | yes |
| 8 | SMT internal node | no | yes | yes |
| 9 | RepoCommit | yes | yes | yes |
| 10 | RefUpdate | yes | yes | yes |
| 11 | TransactionEnd | no | yes | no |

Record type 0 and 12..255 are invalid in physical format version 1.

## 13. CRC-32C

EternalCore uses CRC-32C/Castagnoli with:

- reflected polynomial: `0x82f63b78`;
- initial value: `0xffffffff`;
- input and output reflected;
- final XOR: `0xffffffff`;
- no appended zero bytes.

The check value for ASCII `123456789` is `0xe3069283`.

CRC provides corruption detection only and is not an authenticity mechanism.

## 14. Active segment format

### 14.1 Filename

```text
objects/active/segment-<generation>-<UUID lowercase>.seg
```

### 14.2 Fixed header

Total size: 62 bytes.

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 8 | magic | bytes `45 54 53 45 47 00 00 00` (`ETSEG\0\0\0`) |
| 8 | 2 | format_version | u16 LE = 1 |
| 10 | 16 | repository_id | UUID bytes |
| 26 | 16 | segment_id | UUID bytes |
| 42 | 8 | store_generation | u64 LE |
| 50 | 8 | created_at_ns | i64 LE |
| 58 | 4 | header_crc32c | u32 LE |

`header_crc32c` covers bytes 0 through 57.

### 14.3 Frame

A frame begins immediately after the header or previous complete frame.

| Relative offset | Size | Field |
|---:|---:|---|
| 0 | 1 | record_type |
| 1 | 32 | record_id |
| 33 | 8 | payload_length u64 LE |
| 41 | payload_length | payload bytes |
| 41 + payload_length | 4 | frame_crc32c u32 LE |

CRC input is the exact bytes from `record_type` through the end of payload, including the little-endian length field.

### 14.4 Tail handling

At EOF:

- fewer than 41 bytes remaining: incomplete tail, ignore;
- declared payload exceeds configured limit: corruption/resource error;
- full payload but fewer than 4 CRC bytes: incomplete tail, ignore;
- full frame with CRC mismatch: corruption, except that recovery MAY truncate this frame and everything after it only when it is the final frame and writer lock is held;
- a valid frame after an invalid frame is never searched for heuristically.

### 14.5 Record-ID validation

- signed record: parse envelope, canonical-verify envelope and inner payload, recompute payload ID;
- EncodedChunk, ContentManifest, TransactionEnd: DomainHash canonical payload;
- SMT records: semantic hash defined in Section 9.15/9.16.

The payload's canonical re-encoding MUST equal the original payload byte-for-byte.

## 15. Sealed pack format

### 15.1 Filename

```text
objects/packs/pack-<pack_checksum lowercase hex>.pack
```

### 15.2 Header

Total size: 34 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | magic | `45 54 50 41 43 4b 00 00` (`ETPACK\0\0`) |
| 8 | 2 | format_version | u16 LE = 1 |
| 10 | 16 | repository_id | UUID bytes |
| 26 | 8 | record_count | u64 LE, greater than 0 |

### 15.3 Frames

Pack frames use exactly the frame layout in Section 14.3. Record type 11 is forbidden.

Frames MAY be in any order. A pack MUST NOT contain the same RecordId twice.

### 15.4 Trailer and checksum

The trailer is exactly 32 bytes and contains `pack_checksum`.

To calculate it:

1. construct the complete pack with the final 32 bytes set to zero;
2. compute `DomainHash("EternalCore:Pack:v1", complete_zeroed_pack_bytes)`;
3. write that 32-byte result into the trailer.

The filename checksum MUST equal the trailer and recomputed checksum.

There is no data after the trailer.

## 16. External pack index format

### 16.1 Filename

The index has the same checksum stem as the pack:

```text
objects/packs/pack-<pack_checksum lowercase hex>.idx
```

### 16.2 Layout

Let `N = record_count`. The file is:

| Order | Size | Field |
|---:|---:|---|
| 1 | 8 | magic `45 54 49 44 58 00 00 00` (`ETIDX\0\0\0`) |
| 2 | 2 | format_version u16 LE = 1 |
| 3 | 16 | repository_id |
| 4 | 32 | pack_checksum |
| 5 | 8 | record_count u64 LE |
| 6 | 2048 | fanout: 256 cumulative u64 LE values |
| 7 | 32*N | sorted_record_ids |
| 8 | N | record_types |
| 9 | 8*N | offsets u64 LE |
| 10 | 8*N | payload_lengths u64 LE |
| 11 | 4*N | frame_crc32c u32 LE |
| 12 | 32 | index_checksum |

Total length is `2146 + 53*N` bytes.

### 16.3 Ordering and fanout

`sorted_record_ids` are strictly increasing in unsigned bytewise lexicographic order.

`fanout[i]` is the number of IDs whose first byte is less than or equal to `i`.

Therefore:

- fanout is nondecreasing;
- `fanout[255] == N`;
- bucket `b` occupies entries `[fanout[b-1], fanout[b])`, with lower bound 0 for `b = 0`.

The type, offset, length, and CRC arrays are parallel to sorted IDs, not pack frame order.

### 16.4 Offsets

An offset points to the frame's `record_type` byte in the pack. It MUST be at least 34 and must leave enough bytes before the 32-byte trailer for the indexed frame.

The indexed frame's ID, type, payload length, and CRC MUST equal the parallel index values.

### 16.5 Index checksum

Set the final 32 bytes to zero and calculate:

```text
index_checksum = DomainHash(
    "EternalCore:PackIndex:v1",
    complete_zeroed_index_bytes
)
```

The embedded `pack_checksum` binds the index to one pack.

## 17. Mutable pointer files

Mutable pointer files are ASCII, LF-terminated, contain no leading/trailing spaces, and have no extra line.

### 17.1 CURRENT

Content:

```text
manifests/store-<generation>-<StoreManifestId>.cbor\n
```

The path is relative to `.eternal/`. It MUST pass path normalization and MUST name a manifest whose computed ID and generation match its filename.

### 17.2 HEAD

Content:

```text
refs/heads/<branch>\n
```

HEAD MUST name a valid `refs/heads/*` ref in v4.

### 17.3 Ref pointer

A ref file contains:

```text
<RefUpdateId lowercase hex>\n
```

The pointed RefUpdate's `ref_name` MUST exactly equal the ref file's repository-relative path.

A null target means the ref is logically deleted. The file remains as the CAS/tombstone pointer. User-facing ref listing hides deleted refs unless explicitly requested.

### 17.4 Pin and merge-request refs

`refs/pins/*` and `refs/merge-requests/*` use the same pointer file format. Their authorization semantics are defined by policy.

## 18. Store opening and physical discovery

A reader opens a repository in this order:

1. read and validate `CURRENT` syntax;
2. read the named StoreManifest file;
3. require canonical CBOR and recompute its StoreManifestId;
4. validate generation and filename;
5. open only the active segment and packs/indexes named by that manifest;
6. locate `repository_genesis_id` in those files;
7. validate RepositoryGenesis and obtain authoritative repository/federation identity;
8. require every physical file and logical record to carry the same repository ID;
9. read HEAD and the named ref pointer;
10. resolve and validate the RefUpdate/RepoCommit/SMT graph.

Files not referenced by the active StoreManifest are ignored during ordinary opening and index rebuild.

## 19. Compatibility and rejection rules

### 19.1 Versioning

Every logical payload has `format_version = 1`. Physical headers have version 1.

A reader that does not support the exact version MUST reject the item. It MUST NOT guess compatibility based on field similarity.

### 19.2 Unknown fields

No v1 core payload has an extension map. Unknown map keys are invalid. Future optional extension mechanisms require a new format version or a field explicitly defined by a later specification.

### 19.3 Duplicate records

The same immutable RecordId MAY appear in multiple StoreManifest generations or packs during compaction, but:

- payload bytes and record type MUST be identical;
- a single pack MUST NOT contain duplicate IDs;
- if two reachable physical copies with the same ID differ, verification fails loudly.

### 19.4 Algorithm agility

Unknown codec, encryption, KDF, wrapping, signature, chunking, or key-algorithm IDs are unsupported, not equivalent to `none`.

## 20. Normative resource limits

These are v1 absolute decoding maxima. Implementations MAY configure lower operational limits but MUST expose a clear `ResourceLimitExceeded` error rather than misparse data.

| Item | Maximum |
|---|---:|
| logical/physical record payload | 67,108,864 bytes (64 MiB) |
| encoded chunk plaintext length | 8,388,608 bytes |
| CanonicalValue nesting depth | 64 |
| CanonicalValue total nodes | 1,000,000 |
| encoded metadata bytes | 16,777,216 bytes |
| ObjectVersion parents | 64 |
| RepoCommit parents | 64 |
| relations per ObjectVersion | 100,000 |
| changes per RepoCommit | 1,000,000 |
| public keys introduced per policy | 100,000 |
| policy ref permission entries | 100,000 |
| key slots per keyring | 100,000 |
| manifest chunks | 16,777,216 |
| pack record count | 1,000,000,000 |
| pack file size | 17,592,186,044,416 bytes (16 TiB) |
| segment file size before sealing | implementation target 64 MiB; hard maximum 4 GiB |
| string length unless narrower above | 1,048,576 bytes |

A decoder MUST check multiplication and addition overflow before calculating array sizes or offsets.

Decompression MUST enforce both the declared `plaintext_length` and an implementation compression-expansion ceiling. Output longer or shorter than `plaintext_length` is corruption.

## 21. Normative golden vectors

All hexadecimal is lowercase. Test vectors use:

```text
repository_id = 000102030405060708090a0b0c0d0e0f
federation_id = 101112131415161718191a1b1c1d1e1f
Ed25519 private seed = 0000000000000000000000000000000000000000000000000000000000000000
Ed25519 public key = 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
Ed25519 KeyId = 4b03e0e78b0994370a31bae8c31269f6b22f08f45c1f2952fa4002ae16cbd3a9
```

### 21.1 Deterministic CBOR

Value:

```text
{0: 1, 1: repository_id, 2: "alpha", 3: [1, -1, true, null, h'00ff']}
```

Canonical bytes:

```text
a400010150000102030405060708090a0b0c0d0e0f0265616c70686103850120f5f64200ff
```

### 21.2 Empty-payload domain vectors

| Domain tag | DomainHash(tag, empty) |
|---|---|
| `EternalCore:RepositoryGenesis:v1` | `7ee4e846cb224f3a0a2bcde4052467bd28e5eeb736aeefd7ff1696feeb6253ae` |
| `EternalCore:PolicyRecord:v1` | `cdb782e077d59dcddf69b990da0e5a90e4074100452456029f73d3bc7b05dff3` |
| `EternalCore:KeyringRecord:v1` | `c08f39bc9cf3eafbfa2e5bd43d2800c1c177df16cf24143af8173fa315b3c010` |
| `EternalCore:KeyFingerprint:v1` | `320c73031d0a4ed6dc5db85ba0becd6691f66fdbdf16d89adab4244c82f6d5d4` |
| `EternalCore:PublicChunk:v1` | `a02b8ade69ee6ea88ffc2c3ccb22917d7fc40fbf47dd8998fd04fc2232705fa9` |
| `EternalCore:PrivateChunk:v1` | `3c6b278475bf2d7287494ba733c83c30269b9486b999ede1942c9b3fab9d38bf` |
| `EternalCore:FastCDCGear:v1` | `10512bf484a3cdbf3ce846a7d5855549045538c06e24ddd44d36e274d619439c` |
| `EternalCore:FastCDCGearTable:v1` | `f4f1c73625305266dad28fe5b7f80d80bdf52a5ede9625d94b3a6617ab28d6dc` |
| `EternalCore:EncodedChunk:v1` | `fc7fb49a95ef280a4ab0a5feb14b22999b7559ab8edf7a646757c3758ebe6389` |
| `EternalCore:ContentLeaf:v1` | `29c4ab4fc450ef67804923c6ad60b1665c76969b3181965ae9d96d7ba41f65b3` |
| `EternalCore:ContentNode:v1` | `22c6d4041f06f2c083cba398daab414a8a6724cce72e8790258f5b29b06d835a` |
| `EternalCore:ContentEmpty:v1` | `2949e6a6a99918c69427cae45aa851ca682e5483ed57a892fc065c2b4842e157` |
| `EternalCore:ContentManifest:v1` | `f8f4cd8f263a7b39e9cabe8afc9b85e16ba7c9a4e51b5bf414e1f9459dee742f` |
| `EternalCore:ObjectVersion:v1` | `29bd73bb42756738301485d9139dafde5082a6cfaa20d3d3fa0fb6ff950c0786` |
| `EternalCore:RepoCommit:v1` | `68f03768f1c2b756f9e7cecdea0b07e3a25f138f20d3d761842c6abdb356dc80` |
| `EternalCore:RefUpdate:v1` | `f85ba7cd4e917be5b190d70883447660de6bff164f083fb56bc6ce8dc60171ea` |
| `EternalCore:ObjectKey:v1` | `cf6d21316d5e84ba0dd82f2f0dcba3e2cf484ef801ed10524d89947c7c57e644` |
| `EternalCore:SMTEmptyLeaf:v1` | `3730f3604e9a92b7ec14886c12aebac2aa4435f02d56356469c94daf1e16c36d` |
| `EternalCore:SMTLeaf:v1` | `a3174c1e463f7423c0053ab19ed5f8fa2cb17db21e7f8a6c0fe9a5627fa8cc66` |
| `EternalCore:SMTInternal:v1` | `3d430cfa6301b4164857a468f82bbf0c8bf8ee01cb0d280912c1e5ba95d1aec6` |
| `EternalCore:TransactionEnd:v1` | `192155bad083dba7131f06e4edd6c7b58bd51e2038304b36c6bbce3c619a4f03` |
| `EternalCore:TransactionBatch:v1` | `eb1dde91cfb504f6c4654cab7b8775e7981b655887180c6a47544c852bccd386` |
| `EternalCore:Pack:v1` | `7b7eef24532e168e73b02ba4bce15dee50f5ee8866c5f3d8d620c0e46ab0f312` |
| `EternalCore:PackIndex:v1` | `69020a3473f2bfed1da8aff4dcb7907bf26377699a2982842804e5dbabf2d668` |
| `EternalCore:StoreManifest:v1` | `b0d3980926a29eb26a2042236832ed90ee9ec6c575024fb724197ceab39816df` |
| `EternalCore:ChunkAAD:v1` | `aeca49aa1ca60e5b48aed5bd91412ec42592f6bf71da84a027ba11417f5365cd` |
| `EternalCore:KeyWrapAAD:v1` | `9f98b759211e437b96e52b574c53634b15e23bb74f87d93a3f1dcd9fc06875f0` |

### 21.3 FastCDC table

```text
gear_table_id = 7ccfcc31cb8fa9c9e77c5b46c6137935c4c04ac18ffb2dad4a1b26bf504c3530
first eight gear u64 values, displayed as 16-digit hex numeric values:
ab71e3687fc9b9ee 8f91b76a09514811 97d86add42f37770 affa0ddc11ec7961 c7de9acdc61c7847 c67c41b0a2d55650 c4ce50ebc2abffab 9c2e6e005129825a
```

### 21.3.1 FastCDC boundary vectors

Input generators:

- `zero(n)`: `n` zero bytes.
- `incrementing(n)`: byte at offset `i` is `i mod 256`.
- `sha_stream(seed, n)`: concatenate `SHA-256(u64_le(seed) || u64_le(counter))` for counters starting at zero, then truncate to `n` bytes.

Normative first-cut offsets:

| Input | Input length | First cut |
|---|---:|---:|
| `zero(MIN-1)` | 1,048,575 | 1,048,575 |
| `zero(MIN)` | 1,048,576 | 1,048,576 |
| `zero(MIN+1)` | 1,048,577 | 1,048,577 |
| `incrementing(AVG)` | 4,194,304 | 4,194,304 |
| `incrementing(MAX+1)` | 8,388,609 | 8,388,608 |
| `sha_stream(5, MAX+1)` | 8,388,609 | 3,994,732 |
| `sha_stream(0, MAX+1)` | 8,388,609 | 4,208,426 |

### 21.4 SignedRecord envelope

RefUpdate payload canonical bytes:

```text
a800010150000102030405060708090a0b0c0d0e0f026f726566732f68656164732f6d61696e03f60458204444444444444444444444444444444444444444444444444444444444444444050106000758204b03e0e78b0994370a31bae8c31269f6b22f08f45c1f2952fa4002ae16cbd3a9
```

```text
RefUpdateId = 7dea7eee1b4158006eda482d51e7c70e80e35da194aff957736cf1492c60166d
signature   = b834c21ac47a566b9193c906a43151beac6ea8318c7eb7fe04b2699fd6bc7d59dcb82a392a0a83c33308d049d7dc500be26bd95ce984ef56cdaed042b53fb40e
```

Full deterministic SignedRecord envelope:

```text
a5000101a800010150000102030405060708090a0b0c0d0e0f026f726566732f68656164732f6d61696e03f60458204444444444444444444444444444444444444444444444444444444444444444050106000758204b03e0e78b0994370a31bae8c31269f6b22f08f45c1f2952fa4002ae16cbd3a90258207dea7eee1b4158006eda482d51e7c70e80e35da194aff957736cf1492c60166d0358204b03e0e78b0994370a31bae8c31269f6b22f08f45c1f2952fa4002ae16cbd3a9045840b834c21ac47a566b9193c906a43151beac6ea8318c7eb7fe04b2699fd6bc7d59dcb82a392a0a83c33308d049d7dc500be26bd95ce984ef56cdaed042b53fb40e
```

### 21.5 Public content and manifest

For raw bytes `616263` (`abc`):

```text
ChunkId            = 5b113d932452b8def94c6d476512586334b743a3b6bf0f475b23c8028b35b0b8
content leaf/root   = 139b6a4742f0744bd63e1d1d8558ce5118e97ed7cfaba2b0300c40f068255cc1
empty content root = 2949e6a6a99918c69427cae45aa851ca682e5483ed57a892fc065c2b4842e157
ContentManifest canonical bytes = a600010150000102030405060708090a0b0c0d0e0f02a700010101021a00100000031a00400000041a0080000005020658207ccfcc31cb8fa9c9e77c5b46c6137935c4c04ac18ffb2dad4a1b26bf504c353003030481a20058205b113d932452b8def94c6d476512586334b743a3b6bf0f475b23c8028b35b0b80103055820139b6a4742f0744bd63e1d1d8558ce5118e97ed7cfaba2b0300c40f068255cc1
ContentManifestId  = 82e7a89be4027272587e2be2d62df0660e2fed5e646369e9d29ed74379de9527
```

### 21.6 Sparse Merkle Tree

```text
empty[256] = 3730f3604e9a92b7ec14886c12aebac2aa4435f02d56356469c94daf1e16c36d
empty[255] = 727a8c6816064c6d91959939d1375d1bfe4d9648ef800296d199fa7f1bfb5484
empty[128] = e5f9a50364ccda354700de0c1ad387a4de745150ef5f2c72bdb17284fd64b042
empty[0]   = ba3b1941797330129480ad4bd156c3a43470f78a64887a490140282324c9174f
```

For `ObjectId = "a"` and `VersionId = 11` repeated 32 bytes:

```text
ObjectKey = 8eff98cc3232ebc0cc1129d0b201279939ff3966b08a68d269cf575d8270b8c9
leaf      = a98a52601b1b1c76ef018627f29416fcd7103815d7f5948d31fccbd4351cb3f0
root      = f28a2bfa6165d6f75d6ffa797d9f2bf289996ae434498d86af588581b50f9f8d
```

The corresponding membership proof has sibling `empty[d+1]` at each path depth `d`.

### 21.7 RepoCommit transition

Genesis-state commit payload canonical bytes:

```text
aa00010150000102030405060708090a0b0c0d0e0f02800381a300616101f60258201111111111111111111111111111111111111111111111111111111111111111045820f28a2bfa6165d6f75d6ffa797d9f2bf289996ae434498d86af588581b50f9f8d05582022222222222222222222222222222222222222222222222222222222222222220658203333333333333333333333333333333333333333333333333333333333333333070008600958204b03e0e78b0994370a31bae8c31269f6b22f08f45c1f2952fa4002ae16cbd3a9
```

```text
RepoCommitId = 0d19d99e8640b5e7caf03d2ee64e0fcb609553de1c1e2fbf046028f13e532870
signature    = 7a7c693ca7205b9920b0fa8004d295f3223e22cf63ac0758f4dc2d997d020fa7003953c098518ec389d8442054dd2c6c85a8920090ec14f88e784ac0a27fa004
```

Applying its sole change to `empty[0]` produces the one-leaf root in Section 21.6.

### 21.8 RefUpdate chain

```text
first RefUpdateId  = 5af839435afd649ff394dd8a1918061746e92fb42bf9935910d7d5950051be76
second RefUpdateId = c201b7feddf869c798a4e2ed83390ffb89fa0561309b140e0d5228316540d692
```

The second payload names the first ID as predecessor and has sequence 2.

### 21.9 XChaCha20-Poly1305 EncodedChunk

```text
ContentIdKey = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
DEK          = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
nonce        = 000102030405060708090a0b0c0d0e0f1011121314151617
raw bytes    = 616263
private ChunkId = 77737b66a73a871945adaf4b250bf158787aa02bc60b7139e14ecb00e350b8eb
AAD payload canonical bytes = a70050000102030405060708090a0b0c0d0e0f010102582077737b66a73a871945adaf4b250bf158787aa02bc60b7139e14ecb00e350b8eb030304a1000005010607
AAD framed bytes            = 1700457465726e616c436f72653a4368756e6b4141443a76314200000000000000a70050000102030405060708090a0b0c0d0e0f010102582077737b66a73a871945adaf4b250bf158787aa02bc60b7139e14ecb00e350b8eb030304a1000005010607
ciphertext || tag           = d66be7787aea0afa69ff6e584fd9dc9a88e380
EncodedChunk canonical bytes = a700010150000102030405060708090a0b0c0d0e0f02582077737b66a73a871945adaf4b250bf158787aa02bc60b7139e14ecb00e350b8eb030304a1000005a400010107025818000102030405060708090a0b0c0d0e0f101112131415161703010653d66be7787aea0afa69ff6e584fd9dc9a88e380
EncodedChunkRecordId         = 906b402a5344630ff9de40dcb5eb736564c2b2a6741a4f86cbcf304d3afadde0
```

### 21.10 Active-segment header

For segment UUID `00112233-4455-6677-8899-aabbccddeeff`, generation 1, and timestamp 0:

```text
header CRC32C = c3fc8b61
header bytes  = 45545345470000000100000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff01000000000000000000000000000000618bfcc3
```

### 21.11 One-record pack and index

The pack contains the EncodedChunk from Section 21.9.

```text
frame CRC32C  = 9c3d3276
frame offset  = 34
pack checksum = 6790a31c4a14e4e79faed72d0c38b1cdb8ff8234a3698b492164b3a68916ec26
pack bytes    = 45545041434b00000100000102030405060708090a0b0c0d0e0f010000000000000004906b402a5344630ff9de40dcb5eb736564c2b2a6741a4f86cbcf304d3afadde07600000000000000a700010150000102030405060708090a0b0c0d0e0f02582077737b66a73a871945adaf4b250bf158787aa02bc60b7139e14ecb00e350b8eb030304a1000005a400010107025818000102030405060708090a0b0c0d0e0f101112131415161703010653d66be7787aea0afa69ff6e584fd9dc9a88e38076323d9c6790a31c4a14e4e79faed72d0c38b1cdb8ff8234a3698b492164b3a68916ec26
index checksum = 3051b321eb8354dc0f11de02a5b6ee3439c0bd00cf0d7100076e88b422727e77
index byte length = 2199
```

The full index byte vector is maintained as a machine-readable test fixture because its 256-entry fanout table is intentionally verbose. Its construction MUST exactly follow Section 16.

### 21.12 StoreManifest

The vector StoreManifest references the pack above, segment UUID `00112233-4455-6677-8899-aabbccddeeff`, generation 1, and a test genesis ID of `aa` repeated 32 bytes.

```text
canonical bytes  = a800010150000102030405060708090a0b0c0d0e0f025820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa030104f605a30001015000112233445566778899aabbccddeeff0278416f626a656374732f6163746976652f7365676d656e742d312d30303131323233332d343435352d363637372d383839392d6161626263636464656566662e7365670681a50058206790a31c4a14e4e79faed72d0c38b1cdb8ff8234a3698b492164b3a68916ec260158203051b321eb8354dc0f11de02a5b6ee3439c0bd00cf0d7100076e88b422727e770278586f626a656374732f7061636b732f7061636b2d363739306133316334613134653465373966616564373264306333386231636462386666383233346133363938623439323136346233613638393136656332362e7061636b0378576f626a656374732f7061636b732f7061636b2d363739306133316334613134653465373966616564373264306333386231636462386666383233346133363938623439323136346233613638393136656332362e69647804010700
StoreManifestId  = ade6809438dcfb396d7ab5540ef329478921d77374bf4f7c1ecbf9cd42bf71ca
```

## 22. Required implementation fixtures

The repository MUST contain machine-readable fixtures generated independently of production serializers:

```text
tests/vectors/format-v1.json
tests/vectors/pack-v1.pack
tests/vectors/pack-v1.idx
tests/vectors/segment-header-v1.bin
tests/vectors/store-manifest-v1.cbor
```

Tests MUST compare complete bytes, not only decoded values.

At least one implementation test MUST decode every fixture, re-encode it, and require byte identity. Another MUST mutate each byte range and verify that CRC, checksum, canonical encoding, identifier, or signature validation rejects the corruption at the appropriate layer.

## 23. Parser order

To minimize denial-of-service and parser-confusion risk, parsers MUST validate in this order where applicable:

1. fixed magic and format version;
2. fixed-size header and header CRC;
3. length arithmetic with checked operations;
4. configured resource limits;
5. complete byte availability;
6. frame CRC or file checksum;
7. deterministic CBOR well-formedness;
8. exact schema and enum validation;
9. canonical byte-for-byte re-encoding;
10. record ID recomputation;
11. signature validation;
12. repository identity validation;
13. policy/state-transition validation.

A lower-layer successful check never substitutes for a higher-layer check. In particular, CRC success is not RecordId validation, storage-hash success is not plaintext audit, and signature validity is not authorization.

## 24. Final global format completion criteria

This section defines the final global format-v1 completion gate. It is
not the same gate as the earlier Phase F3 record/fixture subset freeze
defined by `PLAN.md` F3.11/G3.

Earlier phase gates may freeze explicitly scoped subsets of format-v1
artifacts that are already implemented and required by downstream work.
A subset freeze MUST state its scope and MUST NOT claim final global
format-v1 completion.

Format version 1 is globally complete only when:

- all vectors in Section 21 are committed as files;
- FastCDC boundary vectors cover inputs around MIN, AVG, and MAX;
- canonical metadata vectors cover every CanonicalValue variant;
- both public and private ChunkId modes have vectors;
- every signed record type has a valid and tampered fixture;
- SMT membership and non-membership fixtures are committed;
- pack/index mismatch fixtures are committed;
- crash tests truncate segment files at every byte boundary of a complete transaction;
- the Rust encoder output matches an independent reference generator byte-for-byte.
