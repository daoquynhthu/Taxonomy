# EternalCore v4 Cryptography and Key Management

> Status: implementation baseline
>
> This document defines the cryptographic suite, key hierarchy, cryptographic validation rules, secret-handling requirements, and key lifecycle for EternalCore format version 1. It is subordinate to `ARCHITECTURE.md` for system boundaries, to `FORMAT.md` for canonical bytes and identifiers, and to `TRANSACTIONS.md` for publication and durability ordering. Where an older design note conflicts with this document, this document wins.

## 1. Scope and authority

This document specifies:

- the fixed cryptographic suite for EternalCore v4 format version 1;
- domain-separated hashing and keyed content identifiers;
- Ed25519 signing and strict verification;
- X25519 recipient key agreement and wrap-key derivation;
- XChaCha20-Poly1305 encryption for chunks and wrapped secrets;
- Argon2id password-slot derivation and calibration;
- the `ContentIdKey`, DEK, key-epoch, and key-slot hierarchy;
- signing-key, recipient-key, password-slot, and recovery-slot lifecycle;
- encryption, decryption, rewrapping, re-encryption, and retirement rules;
- random-number generation and nonce requirements;
- secret-memory handling and local private-key storage;
- cryptographic audit behavior, failure handling, and required tests.

This document does not redefine:

- CBOR field numbers or canonical encodings fixed by `FORMAT.md`;
- record identifiers or on-disk frame layouts;
- authorization decisions fixed by `POLICY.md`;
- filesystem transaction ordering fixed by `TRANSACTIONS.md`;
- transport session security fixed by `SYNC.md`.

Cryptographic validity and authorization are distinct:

```text
valid signature + known public key != authorized state transition
```

A cryptographically valid record becomes authoritative only when it is reachable through a valid repository graph and authorized under the governing policy.

## 2. Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

A format-v1 writer MUST emit only the algorithms and parameter profiles defined here. A reader MUST reject unknown algorithm identifiers. It MUST NOT silently substitute another primitive, truncate a key, reinterpret a nonce, or treat an unsupported algorithm as `none`.

A lower-layer cryptographic success MUST NOT substitute for a higher-layer check:

- CRC success is not a record-hash check;
- a RecordId match is not a signature check;
- signature validity is not authorization;
- ciphertext authentication is not logical ChunkId verification;
- logical ChunkId verification is not repository-state authorization.

## 3. Threat model

### 3.1 Adversary capabilities

The baseline adversary may:

- read, copy, delete, reorder, truncate, and modify repository files;
- inject arbitrary records, packs, indexes, refs, or synchronization messages;
- operate a malicious peer with valid or invalid repository metadata;
- replay historical valid records and keyring states;
- choose object content, metadata, relation values, ref names, and commit messages;
- observe object sizes, chunk boundaries, access patterns, ref names, metadata, and synchronization timing;
- steal an encrypted repository, including all historical KeyringRecords and wrapped-key slots;
- crash the process at any transaction failpoint;
- obtain a previously used password after that password slot has been removed from the current keyring;
- compromise a signing or recipient key and continue using it until an authorized policy transition revokes it.

### 3.2 Assumptions

The baseline design assumes:

- SHA-256, HMAC-SHA-256, Ed25519, X25519, HKDF-SHA-256, Argon2id, and XChaCha20-Poly1305 remain cryptographically secure for their assigned purposes;
- the operating-system cryptographic random source is not maliciously controlled;
- the implementation uses maintained, constant-time, high-level cryptographic libraries;
- an attacker who reads unlocked process memory, captures the entered password, controls the operating system, or controls a hardware key provider can recover the secrets available to that process;
- authorization policy administrators are trusted to publish correct policy and keyring transitions.

### 3.3 Security goals

The cryptographic design provides:

- integrity and identity of immutable records through deterministic domain-separated identifiers;
- authenticated authorship of logical records through Ed25519 signatures;
- repository binding of signed records through signed `repository_id` fields;
- payload confidentiality and integrity for private chunks through XChaCha20-Poly1305;
- password-hardening through Argon2id;
- recipient wrapping through ephemeral X25519 and HKDF-SHA-256;
- deterministic private chunk deduplication without storing a public plaintext hash;
- historical signature verification after key rotation or revocation;
- independent DEK rotation without changing logical content identifiers.

### 3.4 Explicit non-goals

EternalCore v4 does not provide:

- confidentiality for ObjectIds, ObjectVersion metadata, relations, commit topology, refs, policy records, keyring structure, chunk counts, or content lengths;
- protection after the password, ContentIdKey, DEK, recipient private key, signing private key, or unlocked process memory is compromised;
- trusted time or proof that a signed `created_at_ns` value is accurate;
- detection of complete repository rollback when the attacker can replace the repository and every external trust anchor;
- guaranteed secure deletion on SSDs, copy-on-write filesystems, snapshots, backups, or remote replicas;
- post-quantum confidentiality or signatures;
- deniable encryption;
- traffic-analysis resistance;
- revocation of knowledge already revealed by an immutable historical key slot.

## 4. Fixed cryptographic suite

Format version 1 uses exactly this suite:

| Purpose | Algorithm |
|---|---|
| Record and structural hash | SHA-256 |
| Message authentication / private ChunkId | HMAC-SHA-256 |
| Signed logical records | Ed25519 |
| Recipient key agreement | X25519 |
| Recipient wrap-key derivation | HKDF-SHA-256 |
| Password KEK derivation | Argon2id version 1.3 (`0x13`) |
| Chunk and secret wrapping AEAD | XChaCha20-Poly1305, 256-bit key, 192-bit nonce |
| Secret comparison | constant-time byte equality |
| Random generation | host operating-system CSPRNG |

Algorithm agility is not negotiated inside format version 1. A future primitive requires a new explicitly specified algorithm identifier and, where bytes or identifiers change, a new format or record version.

Implementations MUST NOT:

- implement these primitives manually;
- use Ed25519 keys for X25519 by conversion;
- reuse one private key for signing and encryption;
- use unauthenticated ChaCha20;
- use a truncated Poly1305 tag;
- replace XChaCha20-Poly1305 with IETF ChaCha20-Poly1305 while retaining algorithm ID 1;
- replace Argon2id with Argon2i, Argon2d, PBKDF2, scrypt, or a platform KDF while retaining KDF algorithm ID 1;
- replace SHA-256 with BLAKE3 or another digest under an existing domain tag.

## 5. Domain separation and hash use

### 5.1 Generic DomainHash

All unkeyed protocol hashes use the exact construction in `FORMAT.md`:

```text
DomainHash(tag, payload) = SHA-256(
    u16_le(byte_length(tag_utf8)) ||
    tag_utf8 ||
    u64_le(byte_length(payload)) ||
    payload
)
```

The framing bytes are part of the hash preimage. Implementations MUST NOT hash hexadecimal text, a Rust debug representation, an in-memory struct layout, or non-canonical CBOR.

### 5.2 Hash output handling

Hash outputs are raw 32-byte values. Hexadecimal is an external textual representation only.

Comparisons involving authenticated identifiers SHOULD use constant-time equality whenever the compared value may be influenced by secret-dependent computation. Ordinary lookup-table ordering may use lexicographic comparison because the identifiers themselves are public.

### 5.3 HMAC private ChunkId

For private content, the logical chunk identifier is:

```text
private_preimage =
    u16_le(len("EternalCore:PrivateChunk:v1")) ||
    "EternalCore:PrivateChunk:v1" ||
    u64_le(len(raw_chunk_bytes)) ||
    raw_chunk_bytes

ChunkId = HMAC-SHA-256(ContentIdKey, private_preimage)
```

The `ContentIdKey` is exactly 32 random bytes.

The implementation MUST NOT store any of the following beside a private ChunkId:

- SHA-256 of the raw plaintext;
- a public ContentLeaf derived from a public plaintext hash;
- a deterministic unkeyed checksum of the entire plaintext;
- a filename or sidecar whose value reveals the public plaintext digest.

CRC values and physical RecordIds over ciphertext are permitted because they do not expose a plaintext equality oracle.

### 5.4 Public ChunkId

For public content:

```text
ChunkId = DomainHash("EternalCore:PublicChunk:v1", raw_chunk_bytes)
```

Public and private ChunkIds share the same 32-byte representation but are not interchangeable semantically. Their validation mode is determined by the EncodedChunk representation:

- an unencrypted EncodedChunk validates only by the public ChunkId construction;
- an encrypted EncodedChunk validates only by the private HMAC construction after decryption.

An implementation MUST reject an encoding that authenticates and decompresses successfully but whose expected ChunkId does not match the correct construction for its encryption mode.

## 6. Ed25519 signing

### 6.1 Key representation

An Ed25519 public key is exactly 32 raw bytes. A format-level signature is exactly 64 raw bytes.

`KeyId` is computed exactly as specified in `FORMAT.md` using algorithm ID 1 and the raw public-key bytes.

A private signing key is generated from 32 bytes obtained directly from the operating-system CSPRNG or from an approved hardware key provider. A writer MUST NOT derive signing keys from repository passwords, ContentIdKeys, DEKs, object content, UUIDs, timestamps, or deterministic repository state.

### 6.2 Signed message

For every `SignedRecord<P>`:

```text
record_id = DomainHash(record_domain, deterministic_cbor(payload))
signature = Ed25519.Sign(private_key, record_id)
```

The signed message is exactly the 32 raw bytes of `record_id`.

It is not:

- the hexadecimal RecordId;
- the complete SignedRecord envelope;
- the raw payload without domain separation;
- a second SHA-256 digest of RecordId;
- a concatenation chosen by the implementation.

### 6.3 Signing invariants

Before signing, a writer MUST verify:

1. payload CBOR is deterministic and schema-valid;
2. payload `repository_id` equals the opened repository identity;
3. payload `author_key_id` or `creator_key_id` equals the signing key's computed KeyId;
4. every identifier embedded in the payload has the correct typed domain;
5. the signing key is authorized for the intended transition under `POLICY.md`;
6. all transaction dependencies required by `TRANSACTIONS.md` remain valid at publication.

Signature generation alone MUST NOT be treated as publication authorization.

### 6.4 Strict verification

Verification MUST use a high-level Ed25519 implementation with strict verification behavior.

A verifier MUST reject:

- a public key with invalid encoding;
- a signature whose scalar is non-canonical;
- a signature or point encoding rejected by the library's strict verifier;
- a signature that verifies only under a permissive or legacy equation;
- an envelope whose recomputed RecordId differs;
- a signer KeyId that does not match the public key;
- a payload author KeyId that differs from the envelope signer KeyId.

The verifier MUST NOT attempt alternate signature interpretations after strict verification fails.

### 6.5 Public-key resolution

Public keys are resolved from:

1. the creator key embedded in `RepositoryGenesis`; and
2. `introduced_keys` in the immutable PolicyRecord ancestry.

A public key is historical evidence and is never deleted from the logical registry. Policy removal or revocation affects future authorization, not the mathematical validity of old signatures.

### 6.6 Signature validation order

For a signed record, use this order:

1. enforce input size limits;
2. parse the deterministic SignedRecord envelope;
3. parse and validate the payload schema;
4. recompute the typed RecordId;
5. compare it to the envelope RecordId;
6. require payload author/creator KeyId to equal envelope signer KeyId;
7. resolve the exact public key from genesis/policy history;
8. recompute and verify the KeyId;
9. perform strict Ed25519 verification;
10. evaluate policy authorization and state-transition rules.

A missing public key is `UnknownSigningKey`, not `BadSignature`. A known key with a failing signature is `SignatureInvalid`. A valid signature without authority is `AuthorizationDenied`.

### 6.7 Key rotation and revocation

Signing-key rotation is a policy transition:

1. introduce the new Ed25519 public key in a PolicyRecord;
2. authorize it for the required roles or refs;
3. publish that policy through an authorized RepoCommit and RefUpdate;
4. only then use the new key for later records.

Revocation is not retroactive. A historical record remains cryptographically valid and historically authorized if it was valid under the policy governing its publication.

Because timestamps are untrusted, a record signed by a later-revoked key is not accepted merely because its claimed timestamp predates revocation. It must be linked into the authorized commit/ref sequence at a point where the key was permitted.

If the only administrator private key is lost before another administrator is authorized, the repository has no cryptographic recovery mechanism. Implementations MUST NOT invent a replacement administrator from local configuration.

## 7. X25519 recipient keys

### 7.1 Key separation

X25519 recipient keys are independent from Ed25519 signing keys.

Implementations MUST NOT:

- convert an Ed25519 key into X25519 for a recipient slot;
- fingerprint an X25519 public key using Ed25519 algorithm ID 1;
- sign records with an X25519 key;
- use an X25519 static private key as a DEK or ContentIdKey.

### 7.2 Stored public keys

An X25519 public key is 32 raw bytes and uses KeyId algorithm ID 2.

Stored recipient public keys MUST use a canonical encoding accepted by the EternalCore validator. The top unused bit MUST be clear, and the encoded field element MUST be canonical. Non-canonical encodings that would map to an equivalent X25519 input are rejected to preserve one public-key byte string per KeyId.

### 7.3 Ephemeral-static agreement

Each recipient or recovery KeySlot uses a fresh ephemeral X25519 keypair:

```text
ephemeral_private <- OS CSPRNG
ephemeral_public  = X25519.public(ephemeral_private)
shared_secret     = X25519(ephemeral_private, recipient_public)
```

The ephemeral private key is never stored and is zeroized immediately after deriving the wrap key.

The recipient computes the same shared secret using its static recipient private key and the slot's stored `ephemeral_public_key`.

The implementation MUST reject an all-zero shared secret in constant time. It MUST NOT continue to HKDF after this check fails.

### 7.4 X25519 wrap-key derivation

Recipient and recovery slots derive a 32-byte KEK using HKDF-SHA-256 according to RFC 5869.

Define the deterministic context map:

| Key | Field |
|---:|---|
| 0 | repository_id |
| 1 | slot_id |
| 2 | slot_kind |
| 3 | secret_kind |
| 4 | key_epoch |
| 5 | recipient_key_id |
| 6 | ephemeral_public_key |

Then:

```text
context_payload = deterministic_cbor(context_map)

salt = DomainHash(
    "EternalCore:X25519WrapSalt:v1",
    repository_id || slot_id || recipient_key_id
)

info =
    u16_le(len("EternalCore:X25519WrapInfo:v1")) ||
    "EternalCore:X25519WrapInfo:v1" ||
    u64_le(len(context_payload)) ||
    context_payload

prk = HKDF-Extract-SHA256(salt, shared_secret)
kek = HKDF-Expand-SHA256(prk, info, 32)
```

`secret_kind` and `key_epoch` are obtained from the KeySlot's enclosing KeyringRecord position exactly as defined by `FORMAT.md`.

The following context strings are normative cryptographic constants:

```text
EternalCore:X25519WrapSalt:v1
EternalCore:X25519WrapInfo:v1
```

They do not create new on-disk fields.

### 7.5 Recovery recipients

A recovery slot uses the same X25519 and HKDF construction as a normal recipient slot but has `slot_kind = 3`.

A recovery private key SHOULD be generated and stored offline on a separate device or medium. The online repository requires only its public key.

Recovery status does not grant signing or policy authority. Possession of a recovery private key enables decryption only for secrets actually wrapped to that recipient.

## 8. Password slots and Argon2id

### 8.1 Password bytes

The KDF input is a byte string.

For the CLI's interactive text mode:

- input is encoded as UTF-8 exactly as entered;
- no Unicode normalization, trimming, case folding, newline inclusion, or locale transformation occurs;
- an empty password is rejected;
- the implementation SHOULD accept at least 1024 bytes;
- input exceeding the configured safety limit is rejected, not truncated.

A protected file-descriptor mode MAY supply arbitrary bytes. Environment variables MUST NOT be the default password input because they may leak through process inspection, shell history, diagnostics, or child-process environments.

### 8.2 Argon2id profile

Password slots use Argon2id version `0x13` and produce exactly 32 output bytes.

A writer creating a new password slot MUST use:

- salt length: at least 16 random bytes;
- memory: at least 64 MiB;
- iterations: at least 3 when memory is below 2 GiB;
- parallelism: at least 1 and no more than the available safe worker count;
- output length: exactly 32 bytes.

The baseline calibrator SHOULD:

1. begin with 256 MiB memory, 3 iterations, and parallelism `min(4, available_parallelism)`;
2. target approximately 500 ms on the current machine;
3. increase memory before increasing iterations, up to the configured local memory ceiling;
4. never reduce below 64 MiB and 3 iterations;
5. persist the exact resulting parameters in the slot.

A constrained implementation that cannot allocate 64 MiB MUST refuse to create or unlock password slots. It may still operate on repositories through recipient or hardware-backed slots.

### 8.3 Password KEK

For a password slot:

```text
kek = Argon2id(
    password_bytes,
    slot.password_kdf.salt,
    version = 0x13,
    memory_kib,
    iterations,
    parallelism,
    output_length = 32
)
```

The raw Argon2id output is the XChaCha20-Poly1305 wrapping key. No truncation, hexadecimal encoding, or additional password-dependent transformation is applied.

Slot isolation is provided by a unique random salt, a unique slot UUID, a unique wrap nonce, and the KeyWrap AAD.

### 8.4 Weak historical slots

A reader may encounter a format-valid historical slot with parameters weaker than current creation policy.

It MAY attempt to unlock such a slot only when explicitly permitted by the caller. It MUST report `WeakPasswordKdfParameters` and MUST NOT copy those parameters into a new slot.

All newly written password slots must meet the current requirements in this document.

### 8.5 Password handling

Passwords and derived KEKs:

- MUST never be logged;
- MUST not implement `Debug` or ordinary serialization;
- MUST be zeroized after use;
- SHOULD be held in guarded or locked memory where available;
- MUST not be cached beyond the explicitly configured unlock session;
- MUST not be included in panic messages, crash reports, metrics, traces, or error chains.

A password mismatch and a corrupted wrapped secret SHOULD produce the same public error class, `KeySlotUnlockFailed`, to avoid exposing a password oracle through detailed error text.

## 9. Secret hierarchy

### 9.1 Secret types

EternalCore uses these independent secret types:

| Secret | Size | Scope | Purpose |
|---|---:|---|---|
| Ed25519 private key | implementation key form | author identity | sign logical records |
| X25519 recipient private key | 32 bytes | recipient identity | unwrap key slots |
| Password-derived KEK | 32 bytes | one unlock attempt / session | unwrap one KeySlot |
| Recipient-derived KEK | 32 bytes | one KeySlot | unwrap one KeySlot |
| ContentIdKey | 32 bytes | entire repository lifetime | private ChunkIds |
| DEK | 32 bytes | one key epoch | encrypt encoded chunks |

No secret may be reused for another row's purpose.

### 9.2 ContentIdKey

The ContentIdKey is generated once from the operating-system CSPRNG when private/encrypted content support is initialized.

It is repository-wide and stable for the lifetime of `repository_id`.

It is used only as the HMAC-SHA-256 key for private ChunkIds. It MUST NOT be used:

- directly as an AEAD key;
- as a password KEK;
- as an HKDF salt;
- to encrypt metadata;
- to derive signing or recipient keys;
- as a DEK.

### 9.3 ContentIdKey rotation prohibition

The ContentIdKey MUST NOT be rotated in place within one repository identity.

Changing it changes every private ChunkId, ContentManifestId, ObjectVersionId, SMT root, and RepoCommitId that depends on private content. Calling such an operation “key rotation” would silently rewrite logical history.

If the ContentIdKey is believed compromised, the supported response is:

1. create a new repository with a new `repository_id` and new ContentIdKey;
2. explicitly import and re-encrypt desired logical content;
3. create new ObjectVersions and commits in the destination repository;
4. retire the old repository operationally.

The destination records are new records and do not preserve source identifiers.

### 9.4 Data-encryption keys

Each DEK is 32 random bytes and belongs to one nonzero `key_epoch`.

The active write epoch is exactly `KeyringRecord.key_epoch`. New encrypted EncodedChunks MUST use that epoch and its corresponding DEK.

A DEK is used only for XChaCha20-Poly1305 encryption of EncodedChunk compressed bytes. It MUST NOT wrap another DEK or ContentIdKey directly; KeySlots perform wrapping with a KEK.

### 9.5 Keyring slot consistency

Every KeySlot under `content_id_key_slots` wraps the same repository ContentIdKey.

Every KeySlot inside one `WrappedDek` wraps the same DEK named by that enclosing `(key_epoch, dek_id)`.

When two different slots can be unlocked locally, the implementation MUST compare the recovered secret in constant time. A mismatch is `KeyringSecretMismatch` and indicates corruption or a malicious keyring transition.

A locked verifier that cannot unwrap a slot cannot prove secret continuity. It may validate the KeyringRecord signature and structure but must report the cryptographic content as locked.

## 10. KeySlot wrapping

### 10.1 Wrapped plaintext

A KeySlot wraps exactly one 32-byte secret:

- `secret_kind = 1`: ContentIdKey, with `key_epoch = 0`;
- `secret_kind = 2`: DEK, with the enclosing nonzero key epoch.

No internal header is added to the 32-byte plaintext because its type and epoch are authenticated by AAD.

Therefore:

```text
len(wrapped_secret) = 32-byte ciphertext + 16-byte tag = 48 bytes
```

A KeySlot whose `wrapped_secret` length is not 48 bytes is invalid in format version 1.

### 10.2 Wrapping AAD

The KeyWrap AAD is exactly the framed deterministic CBOR value defined in `FORMAT.md`:

```text
repository_id
slot_id
slot_kind
secret_kind
key_epoch
recipient_key_id or null
```

The AAD framing tag is:

```text
EternalCore:KeyWrapAAD:v1
```

The AAD bytes, not their hash, are passed to XChaCha20-Poly1305.

### 10.3 Wrap nonce

Every KeySlot uses a fresh random 24-byte nonce generated from the operating-system CSPRNG.

Nonce uniqueness is required per KEK. Writers MUST generate a new nonce whenever a secret is rewrapped, even if the secret, slot label, password, recipient, and AAD are unchanged.

A KeySlot update MUST NOT copy an old `(KEK, nonce)` pair with changed plaintext or AAD.

### 10.4 Wrap operation

```text
wrapped_secret = XChaCha20Poly1305.Seal(
    key = kek,
    nonce = wrap_nonce,
    plaintext = secret_32,
    aad = key_wrap_aad
)
```

### 10.5 Unwrap operation

```text
secret_32 = XChaCha20Poly1305.Open(
    key = kek,
    nonce = wrap_nonce,
    ciphertext_and_tag = wrapped_secret,
    aad = key_wrap_aad
)
```

Authentication failure is terminal for that slot. The implementation MUST NOT return unauthenticated plaintext, attempt decompression, or fall back to another interpretation of the same slot.

Other independent slots MAY still be attempted according to caller policy.

## 11. Chunk encryption

### 11.1 Encryption pipeline

For private content, process one raw chunk as follows:

1. compute the private ChunkId with the ContentIdKey;
2. encode/compress the raw chunk according to its CodecDescriptor;
3. choose the active DEK and key epoch from the governing KeyringRecord;
4. generate a fresh random 24-byte nonce;
5. construct Chunk AAD profile 1 exactly as defined in `FORMAT.md`;
6. encrypt the compressed bytes with XChaCha20-Poly1305;
7. construct `EncodedChunkPayload` with the private ChunkId, original plaintext length, codec, encryption descriptor, and ciphertext-plus-tag;
8. compute the EncodedChunkRecordId over deterministic CBOR.

Compression MUST occur before encryption.

### 11.2 Chunk AAD

The AEAD AAD binds:

- repository ID;
- format version;
- ChunkId;
- plaintext length;
- complete codec descriptor;
- encryption algorithm ID;
- key epoch.

The nonce is already an input to the AEAD and is included in the signed/hashed EncodedChunk payload. It is not repeated inside AAD profile 1.

Changing any bound field without re-encryption MUST cause AEAD authentication failure.

### 11.3 Chunk nonce

Each encrypted EncodedChunk uses a fresh 192-bit random nonce under its DEK.

The writer MUST:

- obtain all 24 bytes from the operating-system CSPRNG;
- reject random-source failure;
- reject an all-zero nonce if generated;
- maintain an in-process set of nonces generated for the same DEK during the current operation and regenerate on repetition;
- never derive the nonce from ChunkId, content bytes, object ID, chunk index, timestamp, UUID, counter stored in metadata, or RecordId.

A repository-wide nonce database is not required for 192-bit random nonces, but an implementation MAY detect observed duplicate `(key_epoch, nonce)` pairs during audit and MUST report them as `AeadNonceReuse`.

### 11.4 Message size

One AEAD message is one compressed chunk and is bounded by the chunk and resource limits in `FORMAT.md`. Implementations MUST NOT use one AEAD message for an entire multi-gigabyte object.

### 11.5 Decryption pipeline

For an encrypted EncodedChunk:

1. validate the deterministic payload and RecordId;
2. require XChaCha20-Poly1305 algorithm ID 1 and AAD profile 1;
3. resolve the exact DEK epoch through the keyring applicable to the selected repository state;
4. reconstruct AAD exactly;
5. authenticate and decrypt ciphertext;
6. only after successful AEAD authentication, decompress under bounded output limits;
7. require decompressed length to equal `plaintext_length`;
8. recompute the private ChunkId using ContentIdKey;
9. compare it to the payload ChunkId in constant time;
10. release plaintext to the reader only after all checks succeed.

No plaintext bytes may be exposed before AEAD authentication succeeds. Streaming to the caller occurs at chunk granularity after each chunk is fully authenticated, decompressed, length-checked, and ChunkId-checked.

### 11.6 Public chunk decoding

For an unencrypted EncodedChunk:

1. verify RecordId;
2. decompress under bounded limits if required;
3. verify plaintext length;
4. compute the public ChunkId;
5. compare to the payload ChunkId;
6. release plaintext.

An unencrypted representation whose ChunkId validates only under the private HMAC construction is invalid because the verifier has no authenticated encrypted path for that representation.

### 11.7 Candidate encoding selection

A `ChunkId` may have multiple EncodedChunk representations.

For a state governed by one KeyringRecord, the reader chooses in this order:

1. authenticated encoding under the current active epoch;
2. authenticated encoding under another available non-retired epoch;
3. authenticated encoding under a retained retired epoch;
4. for public chunks only, a valid unencrypted encoding.

Every chosen candidate must pass the complete validation pipeline. Cache order is only a hint.

If no candidate can be validated:

- return `ContentLocked` if suitable encrypted candidates exist but no key can be unlocked;
- return `PromisedContentMissing` if the chunk is explicitly promised;
- return `ChunkEncodingUnavailable` if no representation exists;
- return the appropriate corruption error when representations exist but fail validation.

The reader MUST NOT downgrade a private chunk to unauthenticated plaintext.

## 12. Keyring lifecycle

### 12.1 Initial keyring

Every repository has an initial signed KeyringRecord.

For a repository with encryption unavailable:

- `key_epoch = 0`;
- `content_id_key_slots = []`;
- `dek_slots = []`;
- `retired_key_epochs = []`.

Before the first private object is written, an authorized keyring transition creates:

- one random ContentIdKey;
- at least one slot wrapping it;
- DEK epoch 1;
- at least one slot wrapping that DEK;
- a new signed KeyringRecord and administrative RepoCommit.

A repository MUST NOT create private content unless both ContentIdKey and active DEK can be resolved.

### 12.2 Keyring transition authorization

A new KeyringRecord is signed by an authorized Ed25519 administrator or key manager as defined by `POLICY.md`.

Its transition is authorized against the policy of the first parent commit, never against a new policy or keyring being introduced by the same commit.

A keyring transition uses `SerializableBranch` isolation under `TRANSACTIONS.md`.

### 12.3 Adding a password or recipient slot

Adding access to a secret:

1. unlock the source secret through an existing slot or secure key provider;
2. create a new slot UUID;
3. derive a new password or recipient KEK;
4. generate a new wrap nonce;
5. wrap the same 32-byte secret under the new slot AAD;
6. create a new KeyringRecord containing the new slot and required existing slots;
7. publish it through an administrative RepoCommit.

Adding a slot does not change any ChunkId, EncodedChunk, ContentManifest, ObjectVersion, or object-state root.

### 12.4 Removing a slot

Removing a slot creates a new KeyringRecord that omits the slot.

It does not erase the historical KeyringRecord that contained it. Anyone who possesses:

- the historical repository bytes; and
- the password or recipient private key for that historical slot

can still recover the secret wrapped by that historical slot.

Therefore slot removal is access-policy maintenance, not retroactive cryptographic revocation.

### 12.5 Password change

Changing a password means:

1. unlock each affected secret;
2. create replacement password slots with new salts, KDF parameters, slot UUIDs, and nonces;
3. remove the old slots from the new KeyringRecord;
4. publish the new KeyringRecord.

It does not change ContentIdKey or DEKs and does not re-encrypt chunks.

A password change does not protect against an attacker who already knows the old password and can access a historical KeyringRecord containing the old slot.

If the old password is suspected compromised, a password change alone is insufficient.

### 12.6 DEK rotation

DEK rotation is the supported in-repository confidentiality-key rotation.

Normative sequence:

1. generate a fresh random 32-byte DEK;
2. allocate `new_epoch = previous_highest_epoch + 1`;
3. create at least one KeySlot for the new DEK;
4. create and durably store a new KeyringRecord naming the new active epoch while retaining the old DEKs needed to read reachable encodings, but do not yet move a ref to it;
5. create and durably store new encrypted EncodedChunk records for reachable private ChunkIds using the new epoch;
6. authenticate, decrypt, decompress, and ChunkId-check each new encoding before considering migration complete;
7. publish an administrative RepoCommit with unchanged object state and the new keyring ID;
8. after policy-defined retention and successful storage verification, compact away obsolete old-epoch EncodedChunks;
9. only after no current-state content requires an old epoch may a later KeyringRecord omit its slots and list the epoch as retired.

Re-encryption MUST NOT create new ContentManifests or ObjectVersions.

### 12.7 Retired epochs

`retired_key_epochs` is a cumulative sorted set.

A retired epoch:

- MUST NOT be used for new encryption;
- MAY remain decryptable for historical or not-yet-compacted content;
- remains interpretable through historical KeyringRecords;
- is not proof that physical ciphertext has been erased.

The current `key_epoch` MUST be nonzero and MUST NOT appear in `retired_key_epochs`.

### 12.8 Compromise response

| Compromised item | Required response |
|---|---|
| signing key | publish authorized policy revocation; rotate signing authority |
| X25519 recipient private key | remove recipient slots; rotate every DEK exposed by historical slots if future ciphertext protection is required |
| password | replace slots; rotate exposed DEKs; recognize historical slots remain decryptable with the old password |
| DEK | create a new epoch and re-encrypt reachable chunks |
| ContentIdKey | migrate content to a new repository identity |
| unlocked process memory / OS | treat all loaded secrets as compromised and perform the corresponding rotations or migration |

Because historical keyrings are immutable, rotating a DEK protects newly re-encrypted/current ciphertext from a previously exposed old DEK, but it cannot make already copied old ciphertext secret again.

## 13. Private signing-key storage

### 13.1 Backend priority

The preferred signing-key backends are:

1. operating-system or platform secure key store;
2. hardware-backed provider with a non-exportable Ed25519 key;
3. local encrypted key file.

Unencrypted private-key files are not permitted by default.

### 13.2 Platform key store

A platform key-store backend stores only a provider reference in local configuration. Repository data MUST NOT depend on a provider-specific key serialization.

The backend MUST verify that the provider's public key computes to the expected KeyId before every signing session.

### 13.3 Hardware provider

A hardware provider may require user presence. `TRANSACTIONS.md` forbids waiting for user interaction while holding the writer lock.

A hardware signing workflow therefore MUST:

1. prepare the exact candidate signed payload outside the writer lock where possible;
2. obtain required user presence and signature outside the lock;
3. acquire the writer lock and revalidate the publication base;
4. publish only if the payload remains valid;
5. otherwise discard the signature and repeat with a newly derived payload.

For payloads whose final bytes can only be determined under the lock, the implementation must use a provider session that is already unlocked and guaranteed non-interactive for the bounded signing call, or fail before acquiring the lock.

### 13.4 Encrypted local key file

A local file backend stores an RFC 8410-compatible PKCS#8 Ed25519 private-key payload inside an implementation-defined local encrypted container using:

- Argon2id under the password-slot requirements of this document;
- a random 24-byte XChaCha20-Poly1305 nonce;
- a local file-specific AAD containing file format version, expected public KeyId, and key purpose;
- restrictive host permissions or ACLs.

This local container is not part of the synchronized repository format and MUST NOT be copied into immutable object storage.

The decrypted PKCS#8 payload and derived KEK MUST be zeroized after loading the key into the signing backend.

### 13.5 Public key export

Ed25519 public keys may be exported as:

- raw 32-byte form;
- OpenSSH public-key text for operator convenience;
- standards-compliant SubjectPublicKeyInfo where supported.

OpenSSH text is not PEM. Parsing a public-key file must result in exactly one supported public key and must recompute its KeyId.

## 14. Randomness

### 14.1 Source

All cryptographic randomness MUST come from the host operating-system CSPRNG through a maintained Rust interface such as `getrandom`/`OsRng`.

Randomness is required for:

- Ed25519 private-key generation;
- X25519 static private-key generation;
- X25519 ephemeral private keys;
- ContentIdKey generation;
- DEK generation;
- Argon2 salts;
- KeySlot UUIDs;
- keyring DEK UUIDs;
- XChaCha20-Poly1305 nonces;
- transaction and temporary identifiers where unpredictability is relied upon.

### 14.2 Failure behavior

Random-source failure is fatal to the operation. The implementation MUST NOT:

- retry using timestamps or counters as entropy;
- use a deterministic fallback;
- seed a userspace PRNG from process ID, clock, object content, or repository state;
- continue with zero-filled bytes;
- silently reduce key or nonce length.

### 14.3 Fork safety

The implementation SHOULD obtain fresh operating-system randomness after process fork and SHOULD avoid long-lived user-space RNG state for key and nonce generation.

### 14.4 Random UUIDs

UUID fields used as cryptographic slot or DEK identifiers do not provide security by themselves. They are labels. Their randomness prevents accidental collision but does not replace key entropy, nonce entropy, signatures, or CAS sequence validation.

## 15. Secret memory and process hygiene

### 15.1 Secret types in Rust

Secret-bearing Rust types MUST:

- implement zeroization on drop;
- avoid `Copy` and uncontrolled `Clone`;
- avoid `Debug`, `Display`, `Serialize`, and ordinary logging traits;
- expose secret bytes only through narrowly scoped closures or guarded references;
- avoid storing secrets in immutable `String` objects;
- minimize reallocations and temporary copies.

### 15.2 Memory locking

Implementations SHOULD request locked/guarded memory for passwords, ContentIdKeys, DEKs, KEKs, and private keys where supported.

Failure to lock memory MAY be tolerated only if the caller's security policy allows it and the implementation reports the degraded state. Memory locking is defense in depth and is not claimed as protection from a hostile operating system.

### 15.3 Core dumps and diagnostics

Processes that load secrets SHOULD disable core dumps or mark secret mappings non-dumpable where supported.

Panic hooks, crash reporters, telemetry, and tracing MUST NOT capture secret buffers or decrypted content by default.

### 15.4 Temporary plaintext

Chunk encryption and decryption SHOULD use bounded chunk buffers. Temporary plaintext files are forbidden unless the caller explicitly requests export to a path.

If an external command or plugin requires plaintext materialization, that operation is outside the transparent security guarantee and must be explicit.

### 15.5 Cache policy

Unlocked ContentIdKeys and DEKs MAY be cached only inside an explicit unlock session with a configured expiration or process lifetime.

Cache eviction zeroizes secret material. A background daemon MUST provide an immediate lock operation that clears all unlocked secrets.

## 16. Validation of KeyringRecords

### 16.1 Structural checks

Before cryptographic use, validate:

- deterministic CBOR and KeyringId;
- strict signature;
- repository ID;
- predecessor chain;
- monotonic keyring transition rules from `POLICY.md`;
- sorted unique slot IDs;
- valid slot kinds and field presence;
- unique nonzero DEK epochs;
- unique DEK UUIDs;
- current `key_epoch` consistency;
- cumulative sorted retired epochs;
- exact nonce and wrapped-secret lengths;
- KDF parameter bounds;
- recipient KeyId and public-key algorithm.

### 16.2 Slot field matrix

| slot_kind | password_kdf | recipient_key_id | ephemeral_public_key |
|---:|---|---|---|
| 1 password | required | null | null |
| 2 recipient | null | required X25519 | required |
| 3 recovery recipient | null | required X25519 | required |

Any other combination is invalid.

### 16.3 Secret continuity

When unlocked, a keyring transition MUST verify:

- all accessible ContentIdKey slots recover the same ContentIdKey;
- the recovered ContentIdKey matches the previous keyring's ContentIdKey;
- all accessible slots under one WrappedDek recover the same DEK;
- a carried-forward DEK epoch recovers the same DEK as in the predecessor keyring;
- a new DEK epoch is not equal to any accessible prior DEK.

These checks use constant-time equality.

A locked validator records `SecretContinuityNotAudited` rather than claiming continuity.

### 16.4 Keyring selection by state

A reader resolves encryption keys from the `keyring_id` embedded in the RepoCommit defining the selected state.

It MUST NOT automatically substitute an unrelated local “latest keyring” when auditing an old commit.

A newer keyring may provide additional physical encodings for unchanged logical chunks only when the operation explicitly reads under that newer administrative commit or when a local availability layer proves the encoding's epoch is authorized and the logical ChunkId remains unchanged. Historical audit uses the historical commit's keyring chain.

## 17. Cryptographic verification levels

### 17.1 Metadata verification

`verify_metadata` checks cryptographic structure without reading all payload bytes:

- typed identifier lengths;
- KeyId/public-key consistency where records are loaded;
- signature envelope structure;
- algorithm IDs and parameter bounds;
- keyring and policy references;
- pointer and manifest integrity.

It does not claim signature completeness unless all signed records are loaded and verified.

### 17.2 Storage verification

`verify_storage` additionally checks:

- frame and pack RecordIds;
- physical checksums and CRCs;
- deterministic payload re-encoding where required;
- EncodedChunk ciphertext RecordIds.

It does not decrypt content and therefore does not prove private ChunkIds or plaintext content roots.

### 17.3 Full cryptographic audit

`audit_content` performs:

- strict signature verification for all reachable signed records;
- genesis trust bootstrap validation;
- policy-chain and authorization validation;
- keyring-chain validation;
- slot unlock and secret-continuity checks when keys are available;
- AEAD authentication;
- decompression under resource limits;
- public or private ChunkId recomputation;
- ContentManifest root recomputation;
- nonce-reuse detection within each DEK epoch where the scanned data permits;
- validation that current private content has at least one usable encrypted representation.

If required secrets are unavailable, the result is `content_not_audited_locked`. It MUST NOT be reported as full success.

## 18. Error handling and oracle resistance

Implementations SHOULD expose distinct internal errors but SHOULD reduce externally observable detail where it would create a password or recipient oracle.

Recommended public errors include:

- `UnknownSigningKey`;
- `SignatureInvalid`;
- `AuthorizationDenied`;
- `UnsupportedCryptoAlgorithm`;
- `WeakPasswordKdfParameters`;
- `KeySlotUnlockFailed`;
- `RecipientKeyUnavailable`;
- `X25519AllZeroSharedSecret`;
- `KeyringSecretMismatch`;
- `SecretContinuityNotAudited`;
- `ContentLocked`;
- `AeadAuthenticationFailed`;
- `AeadNonceReuse`;
- `ChunkIdentityMismatch`;
- `ContentRootMismatch`;
- `RandomSourceUnavailable`;
- `PrivateKeyUnavailable`;
- `PrivateKeyStorageDegraded`.

The CLI MUST NOT reveal whether a password was “almost correct,” whether Poly1305 failed before or after another check, or which secret bytes differed.

Repeated password unlock attempts SHOULD support caller-configurable rate limiting. The repository format itself does not provide online attempt counters.

## 19. Library and implementation requirements

### 19.1 High-level primitives

The Rust implementation SHOULD use maintained high-level crates with audited interfaces, for example:

- `sha2` for SHA-256;
- `hmac` for HMAC-SHA-256;
- `hkdf` for HKDF-SHA-256;
- `ed25519-dalek` or an equivalent strict Ed25519 implementation;
- `x25519-dalek` or an equivalent X25519 implementation;
- `chacha20poly1305::XChaCha20Poly1305` for AEAD;
- `argon2` for Argon2id;
- `getrandom` or `rand_core::OsRng` for operating-system randomness;
- `zeroize` and secret-wrapper types for memory cleanup;
- `subtle` or equivalent constant-time comparison where not provided by the primitive library.

Exact dependencies may change, but the primitive semantics may not.

### 19.2 Forbidden implementation patterns

The implementation MUST NOT:

- call low-level ChaCha20 and Poly1305 primitives separately to assemble AEAD;
- implement curve arithmetic in EternalCore;
- accept unauthenticated plaintext after an AEAD failure;
- compare passwords or secret keys with ordinary early-exit equality;
- reuse a nonce after retrying a failed write;
- derive cryptographic keys from UUIDs;
- serialize a secret through JSON/TOML logs;
- trust a KeyId without recomputing it from the public key;
- trust an EncodedChunkRecordId without recomputing it from canonical bytes;
- decrypt content before verifying the relevant keyring and repository binding.

### 19.3 Dependency discipline

The project MUST:

- commit `Cargo.lock` for released binaries;
- pin minimum-supported versions that provide the required strict behavior;
- run vulnerability and license audits in CI;
- include cross-platform golden-vector tests;
- document any library change that affects canonical parsing, strict signature verification, KDF behavior, or AEAD output.

A dependency upgrade that changes a normative golden vector is a format/protocol change, not a routine refactor.

## 20. Required cryptographic tests

### 20.1 Hash and HMAC

Tests MUST cover:

- every DomainHash golden vector in `FORMAT.md`;
- exact length framing and little-endian encoding;
- private ChunkId vectors using fixed ContentIdKey and payload;
- public/private ChunkId distinction;
- zero-length and maximum-sized chunk inputs;
- rejection of accidental hashing of hexadecimal text.

### 20.2 Ed25519

Tests MUST cover:

- RepositoryGenesis, PolicyRecord, KeyringRecord, ObjectVersion, RepoCommit, and RefUpdate signatures;
- strict rejection of modified payload, RecordId, signer KeyId, and signature;
- rejection of non-canonical signatures accepted by any permissive test implementation;
- historical verification after policy revocation;
- authorization failure despite a valid signature;
- mismatch between envelope signer and payload author.

### 20.3 X25519 and HKDF

Tests MUST cover:

- RFC 7748 X25519 vectors;
- RFC 5869 HKDF-SHA-256 vectors;
- the EternalCore recipient-wrap KDF context;
- recipient and recovery slot round trips;
- all-zero shared-secret rejection;
- wrong repository ID, slot ID, secret kind, epoch, recipient KeyId, or ephemeral public key producing a different KEK or failed unwrap;
- canonical public-key validation.

### 20.4 Argon2id

Tests MUST cover:

- RFC 9106 / Argon2 version 1.3 known-answer vectors;
- persisted parameter round trip;
- salt uniqueness in generated slots;
- exact 32-byte output;
- rejection of below-policy parameters for new slots;
- unlock of explicitly permitted weak historical slots with warning;
- password byte preservation without normalization.

### 20.5 Key wrapping

Tests MUST cover:

- password, recipient, and recovery slots;
- exact 48-byte wrapped secret;
- AAD mutation for every field;
- nonce mutation;
- ciphertext and tag mutation;
- wrong password or recipient key;
- multiple slots recovering exactly the same secret;
- detection of a malicious KeyringRecord whose slots recover different secrets.

### 20.6 Chunk AEAD

Tests MUST cover:

- the XChaCha20-Poly1305 golden vector in `FORMAT.md`;
- compression-before-encryption;
- all Chunk AAD fields;
- authentication before decompression;
- decompression-limit enforcement;
- plaintext-length mismatch;
- private ChunkId mismatch after successful AEAD;
- multiple encodings of one ChunkId;
- DEK rotation preserving ContentManifestId, VersionId, and object-state root;
- detection of repeated `(key_epoch, nonce)` pairs.

### 20.7 Lifecycle tests

Tests MUST cover:

- adding and removing slots;
- password change behavior;
- proof that an old password plus historical KeyringRecord can still unwrap the old slot;
- signing-key rotation and revocation;
- recipient-key compromise response;
- DEK rotation and old-encoding retirement;
- prohibition of ContentIdKey rotation;
- locked audit reporting;
- keyring change during prepared encrypted transactions returning `KeyringChanged`.

### 20.8 Fuzzing

Fuzz targets MUST include:

- SignedRecord parsing and strict verification dispatch;
- PublicKeyEntry and KeySlot parsing;
- malformed Argon2 parameter sets;
- malformed X25519 keys;
- KeyringRecord transition validation;
- EncodedChunk encryption descriptors and AAD reconstruction;
- decryption/decompression parser boundaries.

Fuzzing MUST NOT log generated secret material.

## 21. Operational procedures

### 21.1 Repository encryption setup

A secure setup procedure:

1. unlock an authorized signing key;
2. generate ContentIdKey and DEK epoch 1 from OS randomness;
3. create at least two independent access paths where operationally appropriate, such as one password slot and one offline recovery recipient;
4. verify every slot by immediately unwrapping and comparing the recovered secret;
5. create and sign the KeyringRecord;
6. publish it through an administrative transaction;
7. export and verify recovery material offline;
8. clear all temporary secret buffers.

The setup command MUST NOT claim success before the KeyringRecord's RepoCommit and RefUpdate are durable.

### 21.2 Backup

A usable encrypted backup requires:

- the immutable repository data;
- ref and StoreManifest state;
- at least one usable ContentIdKey slot;
- at least one usable slot for every DEK needed by desired content;
- the corresponding password, recipient private key, or recovery private key;
- public policy history for signature verification.

Backing up only ciphertext without recovery credentials may be intentional but is not a recoverable backup.

### 21.3 Recovery verification

Recovery material SHOULD be tested periodically by:

1. opening a read-only isolated copy;
2. unlocking through the recovery slot;
3. decrypting and auditing a representative set or full repository;
4. confirming the recovery key does not possess signing authority;
5. recording the test without recording secrets.

### 21.4 Locking the process

A user-requested lock operation:

- zeroizes ContentIdKey, DEKs, KEKs, private keys, and passwords held by the process;
- terminates active plaintext readers;
- clears decrypted-content caches;
- preserves public metadata and structural-read capability.

### 21.5 Export and import

Plaintext export is an explicit decryption boundary. The destination path, archive, or pipe is outside EternalCore's at-rest protection.

Cross-repository import decrypts source content and creates new destination ChunkIds, manifests, versions, and commits under the destination repository identity and ContentIdKey.

## 22. Standards basis

The v1 suite is based on:

- RFC 8032 for Ed25519;
- RFC 7748 for X25519;
- RFC 5869 for HKDF;
- RFC 9106 for Argon2id version 1.3 and parameter guidance;
- RFC 8439 for ChaCha20-Poly1305 component semantics;
- `draft-irtf-cfrg-xchacha-03` for the XChaCha20-Poly1305 construction;
- RFC 8410 for Ed25519/X25519 key encodings used by PKCS#8 and SubjectPublicKeyInfo.

Where those specifications permit multiple valid protocol choices, the narrower rules in this document define the EternalCore format-v1 profile.

## 23. Completion criteria

The cryptographic implementation is not complete until:

1. every fixed primitive is provided by a maintained high-level library;
2. all FORMAT golden vectors pass byte-for-byte;
3. recipient-wrap HKDF and private ChunkId vectors are added to the fixture set;
4. strict Ed25519 negative tests pass;
5. X25519 all-zero and non-canonical input tests pass;
6. password, recipient, and recovery KeySlots interoperate across supported platforms;
7. DEK rotation preserves all logical identifiers required by the architecture;
8. ContentIdKey rotation is rejected;
9. locked audit never reports plaintext verification success;
10. secret-bearing types pass logging and zeroization review;
11. transaction failpoint tests prove no ref exposes records requiring an unpublished keyring;
12. an independent implementation can decrypt the fixed key-wrap and chunk fixtures from the published bytes alone.

