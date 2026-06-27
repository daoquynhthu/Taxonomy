use crate::canonical::{
    CanonicalDecoder, CanonicalValue, DecodeError, Value, canonical_value_from_value,
    value_from_canonical_value,
};
use crate::domain::{DomainHashError, domain_hash};
use crate::ids::{
    ChunkId, ContentManifestId, DataType, EncodedChunkRecordId, KeyId, KeySlotLabel, KeyringId,
    ObjectId, ObjectKey, PolicyId, RecordId, RefName, RefPattern, RefUpdateId, RelationType,
    RepoCommitId, RepositoryGenesisId, Signature, SmtInternalId, SmtLeafId, SmtRoot,
    StoreManifestId, TransactionEndId, VersionId,
};
use crate::limits::FormatLimits;

// ---------------------------------------------------------------------------
// Payload validation error
// ---------------------------------------------------------------------------

/// Validation error for record payload construction or decoding.
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadError {
    /// A field has an unexpected CBOR type.
    FieldType { key: u64, expected: &'static str },
    /// A required field is missing.
    MissingField(u64),
    /// An unsupported field value.
    UnsupportedValue { key: u64, detail: String },
    /// A byte-string field has the wrong length.
    WrongLength {
        key: u64,
        expected: usize,
        actual: usize,
    },
    /// A text field violates constrained-text rules.
    InvalidText { key: u64, detail: String },
    /// An array field is not sorted or contains duplicates.
    UnsortedOrDuplicate { key: u64 },
    /// An array is empty when it should be non-empty.
    EmptyArray { key: u64 },
    /// An unknown field number for a fixed-schema payload.
    UnknownField(u64),
    /// The payload value is not a CBOR map.
    NotAMap,
    /// Wrapped CBOR decode error.
    Decode(DecodeError),
}

// ---------------------------------------------------------------------------
// Shared CBOR field-extraction helpers for record payload decoding
// ---------------------------------------------------------------------------

fn parse_fields(pairs: &[(Value, Value)], count: usize) -> Vec<Option<&Value>> {
    let mut fields = vec![None; count];
    for (k, v) in pairs {
        if let Value::U64(idx) = k
            && let Ok(idx_u) = usize::try_from(*idx)
            && idx_u < count
        {
            fields[idx_u] = Some(v);
        }
    }
    fields
}

fn field_uint(fields: &[Option<&Value>], key: usize) -> Result<u64, PayloadError> {
    match fields.get(key).and_then(|f| *f) {
        Some(Value::U64(v)) => Ok(*v),
        Some(_) => Err(PayloadError::FieldType {
            key: key as u64,
            expected: "uint",
        }),
        None => Err(PayloadError::MissingField(key as u64)),
    }
}

fn field_int(fields: &[Option<&Value>], key: usize) -> Result<i64, PayloadError> {
    match fields.get(key).and_then(|f| *f) {
        Some(Value::I64(v)) => Ok(*v),
        Some(Value::U64(v)) if *v <= i64::MAX as u64 => Ok(*v as i64),
        Some(Value::U64(_)) => Err(PayloadError::UnsupportedValue {
            key: key as u64,
            detail: "positive int exceeds i64::MAX".into(),
        }),
        Some(_) => Err(PayloadError::FieldType {
            key: key as u64,
            expected: "int",
        }),
        None => Err(PayloadError::MissingField(key as u64)),
    }
}

fn field_bytes(fields: &[Option<&Value>], key: usize) -> Result<Vec<u8>, PayloadError> {
    match fields.get(key).and_then(|f| *f) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(PayloadError::FieldType {
            key: key as u64,
            expected: "bytes",
        }),
        None => Err(PayloadError::MissingField(key as u64)),
    }
}

fn field_bytes_exact<const N: usize>(
    fields: &[Option<&Value>],
    key: usize,
) -> Result<[u8; N], PayloadError> {
    let b = field_bytes(fields, key)?;
    let actual = b.len();
    let arr: [u8; N] = b.try_into().map_err(|_| PayloadError::WrongLength {
        key: key as u64,
        expected: N,
        actual,
    })?;
    Ok(arr)
}

fn field_text(fields: &[Option<&Value>], key: usize) -> Result<String, PayloadError> {
    match fields.get(key).and_then(|f| *f) {
        Some(Value::Text(s)) => Ok(s.clone()),
        Some(_) => Err(PayloadError::FieldType {
            key: key as u64,
            expected: "text",
        }),
        None => Err(PayloadError::MissingField(key as u64)),
    }
}

fn field_nullable_bytes(
    fields: &[Option<&Value>],
    key: usize,
) -> Result<Option<Vec<u8>>, PayloadError> {
    match fields.get(key).and_then(|f| *f) {
        Some(Value::Null) => Ok(None),
        Some(Value::Bytes(b)) => Ok(Some(b.clone())),
        Some(_) => Err(PayloadError::FieldType {
            key: key as u64,
            expected: "null or bytes",
        }),
        None => Err(PayloadError::MissingField(key as u64)),
    }
}

fn field_nullable_bytes_exact<const N: usize>(
    fields: &[Option<&Value>],
    key: usize,
) -> Result<Option<[u8; N]>, PayloadError> {
    match field_nullable_bytes(fields, key)? {
        None => Ok(None),
        Some(b) => {
            let actual = b.len();
            let arr: [u8; N] = b.try_into().map_err(|_| PayloadError::WrongLength {
                key: key as u64,
                expected: N,
                actual,
            })?;
            Ok(Some(arr))
        }
    }
}

fn check_sorted_unique_bytes(items: &[Vec<u8>], key: u64) -> Result<(), PayloadError> {
    for w in items.windows(2) {
        if w[0] >= w[1] {
            return Err(PayloadError::UnsortedOrDuplicate { key });
        }
    }
    Ok(())
}

fn check_sorted_unique_u64(items: &[u64], key: u64) -> Result<(), PayloadError> {
    for w in items.windows(2) {
        if w[0] >= w[1] {
            return Err(PayloadError::UnsortedOrDuplicate { key });
        }
    }
    Ok(())
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn reject_unknown_keys(pairs: &[(Value, Value)], count: usize) -> Result<(), PayloadError> {
    for (k, _) in pairs {
        match k {
            Value::U64(idx) if usize::try_from(*idx).is_ok_and(|i| i < count) => {}
            Value::U64(idx) => return Err(PayloadError::UnknownField(*idx)),
            _ => return Err(PayloadError::UnknownField(u64::MAX)),
        }
    }
    Ok(())
}

fn bytes_array_field(fields: &[Option<&Value>], key: usize) -> Result<Vec<Vec<u8>>, PayloadError> {
    match fields.get(key).and_then(|f| *f) {
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| match v {
                Value::Bytes(b) => Ok(b.clone()),
                _ => Err(PayloadError::FieldType {
                    key: key as u64,
                    expected: "array of bytes",
                }),
            })
            .collect(),
        Some(_) => Err(PayloadError::FieldType {
            key: key as u64,
            expected: "array",
        }),
        None => Err(PayloadError::MissingField(key as u64)),
    }
}

// ---------------------------------------------------------------------------
// SignedRecord envelope (FORMAT.md §4.6 / ARCHITECTURE.md §4.3)
// ---------------------------------------------------------------------------

/// A signed-record envelope with detached signature.
///
/// The envelope is a deterministic CBOR map with 5 entries (keys 0–4):
///  0 = envelope_version (must be 1)
///  1 = payload (record-specific map)
///  2 = record_id      (32 bytes — ID of canonical payload)
///  3 = signer_key_id  (32 bytes — signer fingerprint)
///  4 = signature      (64 bytes — Ed25519 signature over record_id)
///
/// The payload is stored as [`Value::Map`] so that unsigned integer field
/// keys (used by all v1 record payload schemas) are preserved through
/// encode–decode roundtrips.  No cryptographic verification is performed
/// at this layer.  Type parameter `P` defaults to `Value`; typed payload
/// schemas (F3.2+) convert to/from `Value` externally.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedRecord<P = Value> {
    payload: P,
    record_id: RecordId,
    signer_key_id: KeyId,
    signature: Signature,
}

impl<P> SignedRecord<P> {
    pub fn new(
        payload: P,
        record_id: RecordId,
        signer_key_id: KeyId,
        signature: Signature,
    ) -> Self {
        Self {
            payload,
            record_id,
            signer_key_id,
            signature,
        }
    }

    pub fn payload(&self) -> &P {
        &self.payload
    }

    pub fn record_id(&self) -> &RecordId {
        &self.record_id
    }

    pub fn signer_key_id(&self) -> &KeyId {
        &self.signer_key_id
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// Error returned by [`SignedRecord::decode`] and [`SignedRecord::encode`].
#[derive(Debug, Clone, PartialEq)]
pub enum SignedRecordError {
    /// The decoded value was not a CBOR map with 5 entries.
    NotA5FieldMap,
    /// A required field (key 0–4) was missing.
    MissingField(u64),
    /// Field 0 (envelope_version) was not exactly 1.
    UnsupportedEnvelopeVersion(u64),
    /// A field had an unexpected CBOR type.
    FieldTypeMismatch { key: u64, expected: &'static str },
    /// A byte-string field had the wrong length.
    WrongFieldLength {
        key: u64,
        expected: usize,
        actual: usize,
    },
    /// The payload field (key 1) is not a CBOR map.
    PayloadNotAMap,
    /// The payload map contains duplicate keys after sorting.
    DuplicatePayloadKey,
    /// Wrapped underlying decoder error.
    Decode(DecodeError),
    /// The encoded envelope exceeds `max_metadata_bytes`.
    EnvelopeTooLarge { actual: u64, max: u64 },
}

// ---------------------------------------------------------------------------
// PasswordKdfDescriptor (FORMAT.md §9.5)
// ---------------------------------------------------------------------------

/// Argon2id KDF parameters embedded in a KeySlot.
#[derive(Clone, Debug, PartialEq)]
pub struct PasswordKdfDescriptor {
    algorithm: u64,
    version: u64,
    salt: Vec<u8>,
    memory_kib: u64,
    iterations: u64,
    parallelism: u64,
}

impl PasswordKdfDescriptor {
    pub fn new(
        algorithm: u64,
        version: u64,
        salt: Vec<u8>,
        memory_kib: u64,
        iterations: u64,
        parallelism: u64,
    ) -> Result<Self, PayloadError> {
        if algorithm != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("expected 1 (Argon2id), got {algorithm}"),
            });
        }
        if version != 0x13 {
            return Err(PayloadError::UnsupportedValue {
                key: 1,
                detail: format!("expected 0x13, got {version}"),
            });
        }
        if salt.len() < 16 || salt.len() > 64 {
            let detail = if salt.len() < 16 {
                format!("salt too short: {} < 16", salt.len())
            } else {
                format!("salt too long: {} > 64", salt.len())
            };
            return Err(PayloadError::UnsupportedValue { key: 2, detail });
        }
        if memory_kib < 65536 {
            return Err(PayloadError::UnsupportedValue {
                key: 3,
                detail: format!("minimum 65536 KiB, got {memory_kib}"),
            });
        }
        if iterations < 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 4,
                detail: format!("minimum 1, got {iterations}"),
            });
        }
        if !(1..=255).contains(&parallelism) {
            return Err(PayloadError::UnsupportedValue {
                key: 5,
                detail: format!("must be 1..255, got {parallelism}"),
            });
        }
        Ok(Self {
            algorithm,
            version,
            salt,
            memory_kib,
            iterations,
            parallelism,
        })
    }

    pub fn algorithm(&self) -> u64 {
        self.algorithm
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
    pub fn memory_kib(&self) -> u64 {
        self.memory_kib
    }
    pub fn iterations(&self) -> u64 {
        self.iterations
    }
    pub fn parallelism(&self) -> u64 {
        self.parallelism
    }
}

impl From<&PasswordKdfDescriptor> for Value {
    fn from(p: &PasswordKdfDescriptor) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.algorithm)),
            (Value::U64(1), Value::U64(p.version)),
            (Value::U64(2), Value::Bytes(p.salt.clone())),
            (Value::U64(3), Value::U64(p.memory_kib)),
            (Value::U64(4), Value::U64(p.iterations)),
            (Value::U64(5), Value::U64(p.parallelism)),
        ])
    }
}

impl TryFrom<Value> for PasswordKdfDescriptor {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 6)?;
        let fields = parse_fields(pairs, 6);
        Self::new(
            field_uint(&fields, 0)?,
            field_uint(&fields, 1)?,
            field_bytes(&fields, 2)?,
            field_uint(&fields, 3)?,
            field_uint(&fields, 4)?,
            field_uint(&fields, 5)?,
        )
    }
}

// ---------------------------------------------------------------------------
// PublicKeyEntry (FORMAT.md §9.2)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKeyEntry {
    key_id: [u8; 32],
    algorithm: u64,
    public_key: [u8; 32],
    label: String,
}

impl PublicKeyEntry {
    pub fn new(
        key_id: [u8; 32],
        algorithm: u64,
        public_key: [u8; 32],
        label: String,
    ) -> Result<Self, PayloadError> {
        if algorithm != 1 && algorithm != 2 {
            return Err(PayloadError::UnsupportedValue {
                key: 1,
                detail: format!("expected 1 (Ed25519) or 2 (X25519), got {algorithm}"),
            });
        }
        if label.len() > 128 {
            return Err(PayloadError::InvalidText {
                key: 3,
                detail: format!("label too long: {} > 128", label.len()),
            });
        }
        let algorithm_u8: u8 = match u8::try_from(algorithm) {
            Ok(a) => a,
            Err(_) => {
                return Err(PayloadError::UnsupportedValue {
                    key: 1,
                    detail: format!("algorithm {algorithm} out of range"),
                });
            }
        };
        let mut fprint_payload = Vec::with_capacity(33);
        fprint_payload.push(algorithm_u8);
        fprint_payload.extend_from_slice(&public_key);
        let expected =
            domain_hash("EternalCore:KeyFingerprint:v1", &fprint_payload).map_err(|_| {
                PayloadError::UnsupportedValue {
                    key: 0,
                    detail: "domain hash tag too long (infallible)".into(),
                }
            })?;
        if key_id != expected {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!(
                    "key_id {}... does not match computed fingerprint {}...",
                    hex_prefix(&key_id),
                    hex_prefix(&expected)
                ),
            });
        }
        Ok(Self {
            key_id,
            algorithm,
            public_key,
            label,
        })
    }

    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }
    pub fn algorithm(&self) -> u64 {
        self.algorithm
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl From<&PublicKeyEntry> for Value {
    fn from(p: &PublicKeyEntry) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::Bytes(p.key_id.to_vec())),
            (Value::U64(1), Value::U64(p.algorithm)),
            (Value::U64(2), Value::Bytes(p.public_key.to_vec())),
            (Value::U64(3), Value::Text(p.label.clone())),
        ])
    }
}

impl TryFrom<Value> for PublicKeyEntry {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 4)?;
        let fields = parse_fields(pairs, 4);
        Self::new(
            field_bytes_exact::<32>(&fields, 0)?,
            field_uint(&fields, 1)?,
            field_bytes_exact::<32>(&fields, 2)?,
            field_text(&fields, 3)?,
        )
    }
}

// ---------------------------------------------------------------------------
// RefPermissionEntry (FORMAT.md §9.3)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct RefPermissionEntry {
    pattern: RefPattern,
    writers: Vec<[u8; 32]>,
}

impl RefPermissionEntry {
    pub fn new(pattern: RefPattern, writers: Vec<[u8; 32]>) -> Result<Self, PayloadError> {
        if writers.is_empty() {
            return Err(PayloadError::EmptyArray { key: 1 });
        }
        let raw: Vec<Vec<u8>> = writers.iter().map(|w| w.to_vec()).collect();
        check_sorted_unique_bytes(&raw, 1)?;
        Ok(Self { pattern, writers })
    }

    pub fn pattern(&self) -> &RefPattern {
        &self.pattern
    }
    pub fn writers(&self) -> &[[u8; 32]] {
        &self.writers
    }
}

impl From<&RefPermissionEntry> for Value {
    fn from(p: &RefPermissionEntry) -> Self {
        let writers: Vec<Value> = p.writers.iter().map(|w| Value::Bytes(w.to_vec())).collect();
        Value::Map(vec![
            (Value::U64(0), Value::Text(p.pattern.to_string())),
            (Value::U64(1), Value::Array(writers)),
        ])
    }
}

impl TryFrom<Value> for RefPermissionEntry {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 2)?;
        let fields = parse_fields(pairs, 2);
        let pattern_str = field_text(&fields, 0)?;
        let pattern = RefPattern::new(&pattern_str).map_err(|e| PayloadError::InvalidText {
            key: 0,
            detail: e.to_string(),
        })?;
        let raw_writers = bytes_array_field(&fields, 1)?;
        let writers: Vec<[u8; 32]> = raw_writers
            .iter()
            .map(|b| {
                let mut arr = [0u8; 32];
                if b.len() != 32 {
                    return Err(PayloadError::WrongLength {
                        key: 1,
                        expected: 32,
                        actual: b.len(),
                    });
                }
                arr.copy_from_slice(b);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(pattern, writers)
    }
}

// ---------------------------------------------------------------------------
// RepositoryGenesisPayload (FORMAT.md §9.1)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct RepositoryGenesisPayload {
    format_version: u64,
    repository_id: [u8; 16],
    federation_id: [u8; 16],
    creator_key_id: [u8; 32],
    creator_public_key: [u8; 32],
    initial_policy_id: [u8; 32],
    initial_keyring_id: [u8; 32],
    created_at_ns: i64,
}

impl RepositoryGenesisPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        federation_id: [u8; 16],
        creator_key_id: [u8; 32],
        creator_public_key: [u8; 32],
        initial_policy_id: [u8; 32],
        initial_keyring_id: [u8; 32],
        created_at_ns: i64,
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("expected 1, got {format_version}"),
            });
        }
        let mut fprint_payload = Vec::with_capacity(33);
        fprint_payload.push(1u8);
        fprint_payload.extend_from_slice(&creator_public_key);
        let expected =
            domain_hash("EternalCore:KeyFingerprint:v1", &fprint_payload).map_err(|_| {
                PayloadError::UnsupportedValue {
                    key: 3,
                    detail: "domain hash tag too long (infallible)".into(),
                }
            })?;
        if creator_key_id != expected {
            return Err(PayloadError::UnsupportedValue {
                key: 3,
                detail: format!(
                    "creator_key_id {}... does not match computed fingerprint {}...",
                    hex_prefix(&creator_key_id),
                    hex_prefix(&expected)
                ),
            });
        }
        Ok(Self {
            format_version,
            repository_id,
            federation_id,
            creator_key_id,
            creator_public_key,
            initial_policy_id,
            initial_keyring_id,
            created_at_ns,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }
    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }
    pub fn federation_id(&self) -> &[u8; 16] {
        &self.federation_id
    }
    pub fn creator_key_id(&self) -> &[u8; 32] {
        &self.creator_key_id
    }
    pub fn creator_public_key(&self) -> &[u8; 32] {
        &self.creator_public_key
    }
    pub fn initial_policy_id(&self) -> &[u8; 32] {
        &self.initial_policy_id
    }
    pub fn initial_keyring_id(&self) -> &[u8; 32] {
        &self.initial_keyring_id
    }
    pub fn created_at_ns(&self) -> i64 {
        self.created_at_ns
    }
}

impl From<&RepositoryGenesisPayload> for Value {
    fn from(p: &RepositoryGenesisPayload) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), Value::Bytes(p.federation_id.to_vec())),
            (Value::U64(3), Value::Bytes(p.creator_key_id.to_vec())),
            (Value::U64(4), Value::Bytes(p.creator_public_key.to_vec())),
            (Value::U64(5), Value::Bytes(p.initial_policy_id.to_vec())),
            (Value::U64(6), Value::Bytes(p.initial_keyring_id.to_vec())),
            (Value::U64(7), Value::I64(p.created_at_ns)),
        ])
    }
}

impl TryFrom<Value> for RepositoryGenesisPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 8)?;
        let fields = parse_fields(pairs, 8);
        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            field_bytes_exact::<16>(&fields, 2)?,
            field_bytes_exact::<32>(&fields, 3)?,
            field_bytes_exact::<32>(&fields, 4)?,
            field_bytes_exact::<32>(&fields, 5)?,
            field_bytes_exact::<32>(&fields, 6)?,
            field_int(&fields, 7)?,
        )
    }
}

// ---------------------------------------------------------------------------
// PolicyRecordPayload (FORMAT.md §9.4)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct PolicyRecordPayload {
    format_version: u64,
    repository_id: [u8; 16],
    previous_policy_id: Option<[u8; 32]>,
    policy_sequence: u64,
    introduced_keys: Vec<PublicKeyEntry>,
    administrators: Vec<[u8; 32]>,
    writers: Vec<[u8; 32]>,
    per_ref_permissions: Vec<RefPermissionEntry>,
    tag_creators: Vec<[u8; 32]>,
    revoked_keys: Vec<[u8; 32]>,
    created_at_ns: i64,
    author_key_id: [u8; 32],
}

impl PolicyRecordPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        previous_policy_id: Option<[u8; 32]>,
        policy_sequence: u64,
        introduced_keys: Vec<PublicKeyEntry>,
        administrators: Vec<[u8; 32]>,
        writers: Vec<[u8; 32]>,
        per_ref_permissions: Vec<RefPermissionEntry>,
        tag_creators: Vec<[u8; 32]>,
        revoked_keys: Vec<[u8; 32]>,
        created_at_ns: i64,
        author_key_id: [u8; 32],
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("expected 1, got {format_version}"),
            });
        }
        if policy_sequence < 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 3,
                detail: format!("minimum 1, got {policy_sequence}"),
            });
        }
        // Validate introduced_keys sorted by key_id
        for w in introduced_keys.windows(2) {
            if w[0].key_id() >= w[1].key_id() {
                return Err(PayloadError::UnsortedOrDuplicate { key: 4 });
            }
        }
        // Validate sorted-unique byte arrays
        let admins_raw: Vec<Vec<u8>> = administrators.iter().map(|a| a.to_vec()).collect();
        check_sorted_unique_bytes(&admins_raw, 5)?;
        let writers_raw: Vec<Vec<u8>> = writers.iter().map(|w| w.to_vec()).collect();
        check_sorted_unique_bytes(&writers_raw, 6)?;
        // Validate per_ref_permissions sorted by pattern string
        for w in per_ref_permissions.windows(2) {
            if w[0].pattern().to_string() >= w[1].pattern().to_string() {
                return Err(PayloadError::UnsortedOrDuplicate { key: 7 });
            }
        }
        let tag_raw: Vec<Vec<u8>> = tag_creators.iter().map(|t| t.to_vec()).collect();
        check_sorted_unique_bytes(&tag_raw, 8)?;
        let revoked_raw: Vec<Vec<u8>> = revoked_keys.iter().map(|r| r.to_vec()).collect();
        check_sorted_unique_bytes(&revoked_raw, 9)?;
        Ok(Self {
            format_version,
            repository_id,
            previous_policy_id,
            policy_sequence,
            introduced_keys,
            administrators,
            writers,
            per_ref_permissions,
            tag_creators,
            revoked_keys,
            created_at_ns,
            author_key_id,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }
    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }
    pub fn previous_policy_id(&self) -> Option<&[u8; 32]> {
        self.previous_policy_id.as_ref()
    }
    pub fn policy_sequence(&self) -> u64 {
        self.policy_sequence
    }
    pub fn introduced_keys(&self) -> &[PublicKeyEntry] {
        &self.introduced_keys
    }
    pub fn administrators(&self) -> &[[u8; 32]] {
        &self.administrators
    }
    pub fn writers(&self) -> &[[u8; 32]] {
        &self.writers
    }
    pub fn per_ref_permissions(&self) -> &[RefPermissionEntry] {
        &self.per_ref_permissions
    }
    pub fn tag_creators(&self) -> &[[u8; 32]] {
        &self.tag_creators
    }
    pub fn revoked_keys(&self) -> &[[u8; 32]] {
        &self.revoked_keys
    }
    pub fn created_at_ns(&self) -> i64 {
        self.created_at_ns
    }
    pub fn author_key_id(&self) -> &[u8; 32] {
        &self.author_key_id
    }
}

impl From<&PolicyRecordPayload> for Value {
    fn from(p: &PolicyRecordPayload) -> Self {
        let introduced: Vec<Value> = p.introduced_keys.iter().map(Value::from).collect();
        let admins: Vec<Value> = p
            .administrators
            .iter()
            .map(|a| Value::Bytes(a.to_vec()))
            .collect();
        let writers: Vec<Value> = p.writers.iter().map(|w| Value::Bytes(w.to_vec())).collect();
        let permissions: Vec<Value> = p.per_ref_permissions.iter().map(Value::from).collect();
        let tags: Vec<Value> = p
            .tag_creators
            .iter()
            .map(|t| Value::Bytes(t.to_vec()))
            .collect();
        let revoked: Vec<Value> = p
            .revoked_keys
            .iter()
            .map(|r| Value::Bytes(r.to_vec()))
            .collect();
        let prev = match &p.previous_policy_id {
            Some(id) => Value::Bytes(id.to_vec()),
            None => Value::Null,
        };
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), prev),
            (Value::U64(3), Value::U64(p.policy_sequence)),
            (Value::U64(4), Value::Array(introduced)),
            (Value::U64(5), Value::Array(admins)),
            (Value::U64(6), Value::Array(writers)),
            (Value::U64(7), Value::Array(permissions)),
            (Value::U64(8), Value::Array(tags)),
            (Value::U64(9), Value::Array(revoked)),
            (Value::U64(10), Value::I64(p.created_at_ns)),
            (Value::U64(11), Value::Bytes(p.author_key_id.to_vec())),
        ])
    }
}

impl TryFrom<Value> for PolicyRecordPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 12)?;
        let fields = parse_fields(pairs, 12);

        let previous_policy_id = field_nullable_bytes_exact::<32>(&fields, 2)?;

        // Parse introduced_keys array
        let introduced_keys = match fields.get(4).and_then(|f| *f) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(|v| PublicKeyEntry::try_from(v.clone()))
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 4,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(4)),
        };

        // Parse administrators
        let admins_raw = bytes_array_field(&fields, 5)?;
        let administrators: Vec<[u8; 32]> = admins_raw
            .iter()
            .map(|b| {
                let mut arr = [0u8; 32];
                if b.len() != 32 {
                    return Err(PayloadError::WrongLength {
                        key: 5,
                        expected: 32,
                        actual: b.len(),
                    });
                }
                arr.copy_from_slice(b);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Parse writers
        let writers_raw = bytes_array_field(&fields, 6)?;
        let writers: Vec<[u8; 32]> = writers_raw
            .iter()
            .map(|b| {
                let mut arr = [0u8; 32];
                if b.len() != 32 {
                    return Err(PayloadError::WrongLength {
                        key: 6,
                        expected: 32,
                        actual: b.len(),
                    });
                }
                arr.copy_from_slice(b);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Parse per_ref_permissions
        let per_ref_permissions = match fields.get(7).and_then(|f| *f) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(|v| RefPermissionEntry::try_from(v.clone()))
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 7,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(7)),
        };

        // Parse tag_creators
        let tags_raw = bytes_array_field(&fields, 8)?;
        let tag_creators: Vec<[u8; 32]> = tags_raw
            .iter()
            .map(|b| {
                let mut arr = [0u8; 32];
                if b.len() != 32 {
                    return Err(PayloadError::WrongLength {
                        key: 8,
                        expected: 32,
                        actual: b.len(),
                    });
                }
                arr.copy_from_slice(b);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Parse revoked_keys
        let revoked_raw = bytes_array_field(&fields, 9)?;
        let revoked_keys: Vec<[u8; 32]> = revoked_raw
            .iter()
            .map(|b| {
                let mut arr = [0u8; 32];
                if b.len() != 32 {
                    return Err(PayloadError::WrongLength {
                        key: 9,
                        expected: 32,
                        actual: b.len(),
                    });
                }
                arr.copy_from_slice(b);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            previous_policy_id,
            field_uint(&fields, 3)?,
            introduced_keys,
            administrators,
            writers,
            per_ref_permissions,
            tag_creators,
            revoked_keys,
            field_int(&fields, 10)?,
            field_bytes_exact::<32>(&fields, 11)?,
        )
    }
}

// ---------------------------------------------------------------------------
// KeySlot (FORMAT.md §9.6)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct KeySlot {
    slot_id: [u8; 16],
    slot_kind: u64,
    label: String,
    password_kdf: Option<PasswordKdfDescriptor>,
    recipient_key_id: Option<[u8; 32]>,
    ephemeral_public_key: Option<[u8; 32]>,
    wrap_algorithm: u64,
    wrap_nonce: [u8; 24],
    wrapped_secret: Vec<u8>,
    created_at_ns: i64,
}

impl KeySlot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slot_id: [u8; 16],
        slot_kind: u64,
        label: String,
        password_kdf: Option<PasswordKdfDescriptor>,
        recipient_key_id: Option<[u8; 32]>,
        ephemeral_public_key: Option<[u8; 32]>,
        wrap_algorithm: u64,
        wrap_nonce: [u8; 24],
        wrapped_secret: Vec<u8>,
        created_at_ns: i64,
    ) -> Result<Self, PayloadError> {
        if !(1..=3).contains(&slot_kind) {
            return Err(PayloadError::UnsupportedValue {
                key: 1,
                detail: format!("expected 1, 2, or 3, got {slot_kind}"),
            });
        }
        KeySlotLabel::new(&label).map_err(|e| PayloadError::InvalidText {
            key: 2,
            detail: e.to_string(),
        })?;
        if wrap_algorithm != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 6,
                detail: format!("expected 1 (XChaCha20-Poly1305), got {wrap_algorithm}"),
            });
        }
        match slot_kind {
            1 => {
                if password_kdf.is_none() {
                    return Err(PayloadError::MissingField(3));
                }
                if recipient_key_id.is_some() {
                    return Err(PayloadError::UnsupportedValue {
                        key: 4,
                        detail: "recipient_key_id must be null for password slots".into(),
                    });
                }
                if ephemeral_public_key.is_some() {
                    return Err(PayloadError::UnsupportedValue {
                        key: 5,
                        detail: "ephemeral_public_key must be null for password slots".into(),
                    });
                }
            }
            2 | 3 => {
                if password_kdf.is_some() {
                    return Err(PayloadError::UnsupportedValue {
                        key: 3,
                        detail: "password_kdf must be null for recipient slots".into(),
                    });
                }
                if recipient_key_id.is_none() {
                    return Err(PayloadError::MissingField(4));
                }
                if ephemeral_public_key.is_none() {
                    return Err(PayloadError::MissingField(5));
                }
            }
            _ => unreachable!(),
        }
        if wrapped_secret.len() != 48 {
            return Err(PayloadError::WrongLength {
                key: 8,
                expected: 48,
                actual: wrapped_secret.len(),
            });
        }
        Ok(Self {
            slot_id,
            slot_kind,
            label,
            password_kdf,
            recipient_key_id,
            ephemeral_public_key,
            wrap_algorithm,
            wrap_nonce,
            wrapped_secret,
            created_at_ns,
        })
    }

    pub fn slot_id(&self) -> &[u8; 16] {
        &self.slot_id
    }
    pub fn slot_kind(&self) -> u64 {
        self.slot_kind
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn password_kdf(&self) -> Option<&PasswordKdfDescriptor> {
        self.password_kdf.as_ref()
    }
    pub fn recipient_key_id(&self) -> Option<&[u8; 32]> {
        self.recipient_key_id.as_ref()
    }
    pub fn ephemeral_public_key(&self) -> Option<&[u8; 32]> {
        self.ephemeral_public_key.as_ref()
    }
    pub fn wrap_algorithm(&self) -> u64 {
        self.wrap_algorithm
    }
    pub fn wrap_nonce(&self) -> &[u8; 24] {
        &self.wrap_nonce
    }
    pub fn wrapped_secret(&self) -> &[u8] {
        &self.wrapped_secret
    }
    pub fn created_at_ns(&self) -> i64 {
        self.created_at_ns
    }
}

impl From<&KeySlot> for Value {
    fn from(s: &KeySlot) -> Self {
        let kdf: Value = match &s.password_kdf {
            Some(k) => Value::from(k),
            None => Value::Null,
        };
        let recipient: Value = match &s.recipient_key_id {
            Some(id) => Value::Bytes(id.to_vec()),
            None => Value::Null,
        };
        let ephemeral: Value = match &s.ephemeral_public_key {
            Some(k) => Value::Bytes(k.to_vec()),
            None => Value::Null,
        };
        Value::Map(vec![
            (Value::U64(0), Value::Bytes(s.slot_id.to_vec())),
            (Value::U64(1), Value::U64(s.slot_kind)),
            (Value::U64(2), Value::Text(s.label.clone())),
            (Value::U64(3), kdf),
            (Value::U64(4), recipient),
            (Value::U64(5), ephemeral),
            (Value::U64(6), Value::U64(s.wrap_algorithm)),
            (Value::U64(7), Value::Bytes(s.wrap_nonce.to_vec())),
            (Value::U64(8), Value::Bytes(s.wrapped_secret.clone())),
            (Value::U64(9), Value::I64(s.created_at_ns)),
        ])
    }
}

impl TryFrom<Value> for KeySlot {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 10)?;
        let fields = parse_fields(pairs, 10);

        let password_kdf = match fields.get(3).and_then(|f| *f) {
            Some(Value::Map(pairs)) => {
                Some(PasswordKdfDescriptor::try_from(Value::Map(pairs.clone()))?)
            }
            Some(Value::Null) => None,
            None => return Err(PayloadError::MissingField(3)),
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 3,
                    expected: "null or map",
                });
            }
        };
        let recipient_key_id = field_nullable_bytes_exact::<32>(&fields, 4)?;
        let ephemeral_public_key = field_nullable_bytes_exact::<32>(&fields, 5)?;

        Self::new(
            field_bytes_exact::<16>(&fields, 0)?,
            field_uint(&fields, 1)?,
            field_text(&fields, 2)?,
            password_kdf,
            recipient_key_id,
            ephemeral_public_key,
            field_uint(&fields, 6)?,
            field_bytes_exact::<24>(&fields, 7)?,
            field_bytes(&fields, 8)?,
            field_int(&fields, 9)?,
        )
    }
}

// ---------------------------------------------------------------------------
// WrappedDek (FORMAT.md §9.7)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct WrappedDek {
    key_epoch: u64,
    dek_id: [u8; 16],
    slots: Vec<KeySlot>,
}

impl WrappedDek {
    pub fn new(
        key_epoch: u64,
        dek_id: [u8; 16],
        slots: Vec<KeySlot>,
    ) -> Result<Self, PayloadError> {
        if key_epoch == 0 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: "key_epoch must be nonzero".into(),
            });
        }
        if slots.is_empty() {
            return Err(PayloadError::EmptyArray { key: 2 });
        }
        // Validate slots sorted by slot_id
        for w in slots.windows(2) {
            if w[0].slot_id() >= w[1].slot_id() {
                return Err(PayloadError::UnsortedOrDuplicate { key: 2 });
            }
        }
        Ok(Self {
            key_epoch,
            dek_id,
            slots,
        })
    }

    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn dek_id(&self) -> &[u8; 16] {
        &self.dek_id
    }
    pub fn slots(&self) -> &[KeySlot] {
        &self.slots
    }
}

impl From<&WrappedDek> for Value {
    fn from(w: &WrappedDek) -> Self {
        let slots: Vec<Value> = w.slots.iter().map(Value::from).collect();
        Value::Map(vec![
            (Value::U64(0), Value::U64(w.key_epoch)),
            (Value::U64(1), Value::Bytes(w.dek_id.to_vec())),
            (Value::U64(2), Value::Array(slots)),
        ])
    }
}

impl TryFrom<Value> for WrappedDek {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 3)?;
        let fields = parse_fields(pairs, 3);

        let slots = match fields.get(2).and_then(|f| *f) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(|v| KeySlot::try_from(v.clone()))
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 2,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(2)),
        };

        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            slots,
        )
    }
}

// ---------------------------------------------------------------------------
// KeyringRecordPayload (FORMAT.md §9.8)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct KeyringRecordPayload {
    format_version: u64,
    repository_id: [u8; 16],
    previous_keyring_id: Option<[u8; 32]>,
    key_epoch: u64,
    content_id_key_slots: Vec<KeySlot>,
    dek_slots: Vec<WrappedDek>,
    retired_key_epochs: Vec<u64>,
    created_at_ns: i64,
    author_key_id: [u8; 32],
}

impl KeyringRecordPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        previous_keyring_id: Option<[u8; 32]>,
        key_epoch: u64,
        content_id_key_slots: Vec<KeySlot>,
        dek_slots: Vec<WrappedDek>,
        retired_key_epochs: Vec<u64>,
        created_at_ns: i64,
        author_key_id: [u8; 32],
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("expected 1, got {format_version}"),
            });
        }
        // Validate content_id_key_slots sorted by slot_id
        for w in content_id_key_slots.windows(2) {
            if w[0].slot_id() >= w[1].slot_id() {
                return Err(PayloadError::UnsortedOrDuplicate { key: 4 });
            }
        }
        // Validate dek_slots sorted by key_epoch
        for w in dek_slots.windows(2) {
            if w[0].key_epoch() >= w[1].key_epoch() {
                return Err(PayloadError::UnsortedOrDuplicate { key: 5 });
            }
        }
        // Validate retired_key_epochs sorted unique
        check_sorted_unique_u64(&retired_key_epochs, 6)?;
        Ok(Self {
            format_version,
            repository_id,
            previous_keyring_id,
            key_epoch,
            content_id_key_slots,
            dek_slots,
            retired_key_epochs,
            created_at_ns,
            author_key_id,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }
    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }
    pub fn previous_keyring_id(&self) -> Option<&[u8; 32]> {
        self.previous_keyring_id.as_ref()
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn content_id_key_slots(&self) -> &[KeySlot] {
        &self.content_id_key_slots
    }
    pub fn dek_slots(&self) -> &[WrappedDek] {
        &self.dek_slots
    }
    pub fn retired_key_epochs(&self) -> &[u64] {
        &self.retired_key_epochs
    }
    pub fn created_at_ns(&self) -> i64 {
        self.created_at_ns
    }
    pub fn author_key_id(&self) -> &[u8; 32] {
        &self.author_key_id
    }
}

impl From<&KeyringRecordPayload> for Value {
    fn from(p: &KeyringRecordPayload) -> Self {
        let cik_slots: Vec<Value> = p.content_id_key_slots.iter().map(Value::from).collect();
        let dek_slots: Vec<Value> = p.dek_slots.iter().map(Value::from).collect();
        let retired: Vec<Value> = p
            .retired_key_epochs
            .iter()
            .map(|e| Value::U64(*e))
            .collect();
        let prev = match &p.previous_keyring_id {
            Some(id) => Value::Bytes(id.to_vec()),
            None => Value::Null,
        };
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), prev),
            (Value::U64(3), Value::U64(p.key_epoch)),
            (Value::U64(4), Value::Array(cik_slots)),
            (Value::U64(5), Value::Array(dek_slots)),
            (Value::U64(6), Value::Array(retired)),
            (Value::U64(7), Value::I64(p.created_at_ns)),
            (Value::U64(8), Value::Bytes(p.author_key_id.to_vec())),
        ])
    }
}

impl TryFrom<Value> for KeyringRecordPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 9)?;
        let fields = parse_fields(pairs, 9);

        let previous_keyring_id = field_nullable_bytes_exact::<32>(&fields, 2)?;

        let content_id_key_slots = match fields.get(4).and_then(|f| *f) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(|v| KeySlot::try_from(v.clone()))
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 4,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(4)),
        };

        let dek_slots = match fields.get(5).and_then(|f| *f) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(|v| WrappedDek::try_from(v.clone()))
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 5,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(5)),
        };

        let retired_key_epochs = match fields.get(6).and_then(|f| *f) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(|v| match v {
                    Value::U64(e) => Ok(*e),
                    _ => Err(PayloadError::FieldType {
                        key: 6,
                        expected: "array of uint",
                    }),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 6,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(6)),
        };

        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            previous_keyring_id,
            field_uint(&fields, 3)?,
            content_id_key_slots,
            dek_slots,
            retired_key_epochs,
            field_int(&fields, 7)?,
            field_bytes_exact::<32>(&fields, 8)?,
        )
    }
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

impl SignedRecord<Value> {
    /// Encode the envelope as deterministic CBOR per FORMAT.md §4.6.
    ///
    /// The payload is embedded as a nested CBOR value (not wrapped in bytes).
    /// The output is checked against `limits.max_metadata_bytes()`.
    pub fn encode(&self, limits: &FormatLimits) -> Result<Vec<u8>, SignedRecordError> {
        // Canonicalize payload map: sort keys, reject duplicates
        let mut pairs = match self.payload.clone() {
            Value::Map(pairs) => pairs,
            _ => return Err(SignedRecordError::PayloadNotAMap),
        };
        pairs.sort_by_key(|a| a.0.reencode());
        for w in pairs.windows(2) {
            if w[0].0.reencode() == w[1].0.reencode() {
                return Err(SignedRecordError::DuplicatePayloadKey);
            }
        }
        let envelope = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),     // envelope_version
            (Value::U64(1), Value::Map(pairs)), // payload (canonical)
            (
                Value::U64(2),
                Value::Bytes(self.record_id.as_bytes().to_vec()),
            ), // record_id
            (
                Value::U64(3),
                Value::Bytes(self.signer_key_id.as_bytes().to_vec()),
            ), // signer_key_id
            (
                Value::U64(4),
                Value::Bytes(self.signature.as_bytes().to_vec()),
            ), // signature
        ]);
        let bytes = envelope.reencode();
        let len = bytes.len() as u64;
        if len > limits.max_metadata_bytes() {
            return Err(SignedRecordError::EnvelopeTooLarge {
                actual: len,
                max: limits.max_metadata_bytes(),
            });
        }
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

impl SignedRecord<Value> {
    /// Decode a SignedRecord from deterministic CBOR bytes.
    ///
    /// Validates:
    /// - the outer structure is a 5-entry map with keys 0–4;
    /// - field 0 (envelope_version) is exactly 1;
    /// - field 2 (record_id) is exactly 32 bytes;
    /// - field 3 (signer_key_id) is exactly 32 bytes;
    /// - field 4 (signature) is exactly 64 bytes;
    /// - field 1 (payload) is a CBOR map.
    ///
    /// The payload is returned as [`Value::Map`] — callers (F3.2+) convert
    /// to typed payload schemas from this representation.
    pub fn decode(input: &[u8], limits: &FormatLimits) -> Result<Self, SignedRecordError> {
        let value = CanonicalDecoder::from_limits(input, limits)
            .decode()
            .map_err(SignedRecordError::Decode)?;

        let pairs = match &value {
            Value::Map(pairs) if pairs.len() == 5 => pairs,
            Value::Map(_) => return Err(SignedRecordError::NotA5FieldMap),
            _ => return Err(SignedRecordError::NotA5FieldMap),
        };

        // Lookup key 0..=4
        let mut fields: [Option<&Value>; 5] = [None, None, None, None, None];
        for (k, v) in pairs {
            match k {
                Value::U64(0) => fields[0] = Some(v),
                Value::U64(1) => fields[1] = Some(v),
                Value::U64(2) => fields[2] = Some(v),
                Value::U64(3) => fields[3] = Some(v),
                Value::U64(4) => fields[4] = Some(v),
                _ => {
                    return Err(SignedRecordError::MissingField(match k {
                        Value::U64(n) => *n,
                        _ => u64::MAX,
                    }));
                }
            }
        }

        for (key, field) in fields.iter().enumerate() {
            if field.is_none() {
                return Err(SignedRecordError::MissingField(key as u64));
            }
        }

        let version = match fields[0] {
            Some(Value::U64(v)) => *v,
            Some(_) => {
                return Err(SignedRecordError::FieldTypeMismatch {
                    key: 0,
                    expected: "uint",
                });
            }
            None => unreachable!(),
        };
        if version != 1 {
            return Err(SignedRecordError::UnsupportedEnvelopeVersion(version));
        }

        let payload = match fields[1] {
            Some(v @ Value::Map(_)) => v.clone(),
            Some(_) => return Err(SignedRecordError::PayloadNotAMap),
            None => unreachable!(),
        };

        let record_id = match fields[2] {
            Some(Value::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                RecordId::new(arr)
            }
            Some(Value::Bytes(b)) => {
                return Err(SignedRecordError::WrongFieldLength {
                    key: 2,
                    expected: 32,
                    actual: b.len(),
                });
            }
            Some(_) => {
                return Err(SignedRecordError::FieldTypeMismatch {
                    key: 2,
                    expected: "bytes(32)",
                });
            }
            None => unreachable!(),
        };

        let signer_key_id = match fields[3] {
            Some(Value::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                KeyId::new(arr)
            }
            Some(Value::Bytes(b)) => {
                return Err(SignedRecordError::WrongFieldLength {
                    key: 3,
                    expected: 32,
                    actual: b.len(),
                });
            }
            Some(_) => {
                return Err(SignedRecordError::FieldTypeMismatch {
                    key: 3,
                    expected: "bytes(32)",
                });
            }
            None => unreachable!(),
        };

        let signature = match fields[4] {
            Some(Value::Bytes(b)) if b.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(b);
                Signature::new(arr)
            }
            Some(Value::Bytes(b)) => {
                return Err(SignedRecordError::WrongFieldLength {
                    key: 4,
                    expected: 64,
                    actual: b.len(),
                });
            }
            Some(_) => {
                return Err(SignedRecordError::FieldTypeMismatch {
                    key: 4,
                    expected: "bytes(64)",
                });
            }
            None => unreachable!(),
        };

        Ok(Self {
            payload,
            record_id,
            signer_key_id,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// CodecDescriptor (FORMAT.md §8.3)
// ---------------------------------------------------------------------------

/// Compression applied to chunk plaintext before optional encryption.
#[derive(Clone, Debug, PartialEq)]
pub struct CodecDescriptor {
    algorithm: u64,
    level: Option<i64>,
    profile: Option<u64>,
}

impl CodecDescriptor {
    pub fn new(
        algorithm: u64,
        level: Option<i64>,
        profile: Option<u64>,
    ) -> Result<Self, PayloadError> {
        match algorithm {
            0 => {
                // No compression: only algorithm field, level and profile omitted
                if level.is_some() {
                    return Err(PayloadError::UnsupportedValue {
                        key: 1,
                        detail: "level must be absent for algorithm 0".into(),
                    });
                }
                if profile.is_some() {
                    return Err(PayloadError::UnsupportedValue {
                        key: 2,
                        detail: "profile must be absent for algorithm 0".into(),
                    });
                }
            }
            1 => {
                // zstd: level and profile required
                let lvl = level.ok_or(PayloadError::MissingField(1))?;
                if !(-5..=22).contains(&lvl) {
                    return Err(PayloadError::UnsupportedValue {
                        key: 1,
                        detail: format!("zstd level {lvl} out of range -5..22"),
                    });
                }
                if profile != Some(1) {
                    return Err(PayloadError::UnsupportedValue {
                        key: 2,
                        detail: "only profile 1 supported".into(),
                    });
                }
            }
            _ => {
                return Err(PayloadError::UnsupportedValue {
                    key: 0,
                    detail: format!("unknown codec algorithm {algorithm}"),
                });
            }
        }
        Ok(Self {
            algorithm,
            level,
            profile,
        })
    }

    pub fn algorithm(&self) -> u64 {
        self.algorithm
    }
    pub fn level(&self) -> Option<i64> {
        self.level
    }
    pub fn profile(&self) -> Option<u64> {
        self.profile
    }
}

impl TryFrom<Value> for CodecDescriptor {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        // Read algorithm first to determine valid field set for this algorithm
        let algorithm = field_uint(&parse_fields(pairs, 1), 0)?;
        match algorithm {
            0 => reject_unknown_keys(pairs, 1)?,
            _ => reject_unknown_keys(pairs, 3)?,
        };
        let fields = parse_fields(pairs, 3);
        let level = match algorithm {
            0 => None,
            _ => Some(field_int(&fields, 1)?),
        };
        let profile = match algorithm {
            0 => None,
            _ => Some(field_uint(&fields, 2)?),
        };
        Self::new(algorithm, level, profile)
    }
}

impl From<&CodecDescriptor> for Value {
    fn from(c: &CodecDescriptor) -> Self {
        match c.algorithm {
            0 => Value::Map(vec![(Value::U64(0), Value::U64(0))]),
            _ => Value::Map(vec![
                (Value::U64(0), Value::U64(c.algorithm)),
                (Value::U64(1), Value::I64(c.level.unwrap_or(0))),
                (Value::U64(2), Value::U64(c.profile.unwrap_or(0))),
            ]),
        }
    }
}

// ---------------------------------------------------------------------------
// EncryptionDescriptor (FORMAT.md §8.4)
// ---------------------------------------------------------------------------

/// Encryption applied to encoded chunk bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionDescriptor {
    algorithm: u64,
    key_epoch: u64,
    nonce: [u8; 24],
    aad_profile: u64,
}

impl EncryptionDescriptor {
    pub fn new(
        algorithm: u64,
        key_epoch: u64,
        nonce: [u8; 24],
        aad_profile: u64,
    ) -> Result<Self, PayloadError> {
        if algorithm != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unknown encryption algorithm {algorithm}"),
            });
        }
        if key_epoch == 0 {
            return Err(PayloadError::UnsupportedValue {
                key: 1,
                detail: "key_epoch must be nonzero".into(),
            });
        }
        if aad_profile != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 3,
                detail: "only aad_profile 1 supported".into(),
            });
        }
        Ok(Self {
            algorithm,
            key_epoch,
            nonce,
            aad_profile,
        })
    }

    pub fn algorithm(&self) -> u64 {
        self.algorithm
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }
    pub fn aad_profile(&self) -> u64 {
        self.aad_profile
    }
}

impl TryFrom<Value> for EncryptionDescriptor {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 4)?;
        let fields = parse_fields(pairs, 4);
        Self::new(
            field_uint(&fields, 0)?,
            field_uint(&fields, 1)?,
            field_bytes_exact::<24>(&fields, 2)?,
            field_uint(&fields, 3)?,
        )
    }
}

impl From<&EncryptionDescriptor> for Value {
    fn from(e: &EncryptionDescriptor) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::U64(e.algorithm)),
            (Value::U64(1), Value::U64(e.key_epoch)),
            (Value::U64(2), Value::Bytes(e.nonce.to_vec())),
            (Value::U64(3), Value::U64(e.aad_profile)),
        ])
    }
}

// ---------------------------------------------------------------------------
// ChunkingDescriptor (FORMAT.md §7.4)
// ---------------------------------------------------------------------------

/// Fixed v1 chunking parameters.
#[derive(Clone, Debug, PartialEq)]
pub struct ChunkingDescriptor {
    algorithm: u64,
    version: u64,
    minimum_size: u64,
    average_size: u64,
    maximum_size: u64,
    normalization: u64,
    gear_table_id: [u8; 32],
}

/// Normative FastCDC v1 gear table ID per FORMAT.md §7.4.
pub const FASTCDC_V1_GEAR_TABLE_ID: [u8; 32] = [
    0x7c, 0xcf, 0xcc, 0x31, 0xcb, 0x8f, 0xa9, 0xc9, 0xe7, 0x7c, 0x5b, 0x46, 0xc6, 0x13, 0x79, 0x35,
    0xc4, 0xc0, 0x4a, 0xc1, 0x8f, 0xfb, 0x2d, 0xad, 0x4a, 0x1b, 0x26, 0xbf, 0x50, 0x4c, 0x35, 0x30,
];

impl ChunkingDescriptor {
    pub fn new_v1() -> Self {
        Self {
            algorithm: 1,
            version: 1,
            minimum_size: 1_048_576,
            average_size: 4_194_304,
            maximum_size: 8_388_608,
            normalization: 2,
            gear_table_id: FASTCDC_V1_GEAR_TABLE_ID,
        }
    }

    pub fn new(
        algorithm: u64,
        version: u64,
        minimum_size: u64,
        average_size: u64,
        maximum_size: u64,
        normalization: u64,
        gear_table_id: [u8; 32],
    ) -> Result<Self, PayloadError> {
        if algorithm != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unknown chunking algorithm {algorithm}"),
            });
        }
        if version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 1,
                detail: format!("unknown chunking version {version}"),
            });
        }
        if minimum_size != 1_048_576 {
            return Err(PayloadError::UnsupportedValue {
                key: 2,
                detail: format!("fixed minimum_size must be 1048576, got {minimum_size}"),
            });
        }
        if average_size != 4_194_304 {
            return Err(PayloadError::UnsupportedValue {
                key: 3,
                detail: format!("fixed average_size must be 4194304, got {average_size}"),
            });
        }
        if maximum_size != 8_388_608 {
            return Err(PayloadError::UnsupportedValue {
                key: 4,
                detail: format!("fixed maximum_size must be 8388608, got {maximum_size}"),
            });
        }
        if normalization != 2 {
            return Err(PayloadError::UnsupportedValue {
                key: 5,
                detail: format!("fixed normalization must be 2, got {normalization}"),
            });
        }
        if gear_table_id != FASTCDC_V1_GEAR_TABLE_ID {
            return Err(PayloadError::UnsupportedValue {
                key: 6,
                detail: "fixed gear_table_id must be the normative FastCDC v1 table ID".into(),
            });
        }
        Ok(Self {
            algorithm,
            version,
            minimum_size,
            average_size,
            maximum_size,
            normalization,
            gear_table_id,
        })
    }

    pub fn algorithm(&self) -> u64 {
        self.algorithm
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn minimum_size(&self) -> u64 {
        self.minimum_size
    }
    pub fn average_size(&self) -> u64 {
        self.average_size
    }
    pub fn maximum_size(&self) -> u64 {
        self.maximum_size
    }
    pub fn normalization(&self) -> u64 {
        self.normalization
    }
    pub fn gear_table_id(&self) -> &[u8; 32] {
        &self.gear_table_id
    }
}

impl TryFrom<Value> for ChunkingDescriptor {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 7)?;
        let fields = parse_fields(pairs, 7);
        Self::new(
            field_uint(&fields, 0)?,
            field_uint(&fields, 1)?,
            field_uint(&fields, 2)?,
            field_uint(&fields, 3)?,
            field_uint(&fields, 4)?,
            field_uint(&fields, 5)?,
            field_bytes_exact::<32>(&fields, 6)?,
        )
    }
}

impl From<&ChunkingDescriptor> for Value {
    fn from(c: &ChunkingDescriptor) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::U64(c.algorithm)),
            (Value::U64(1), Value::U64(c.version)),
            (Value::U64(2), Value::U64(c.minimum_size)),
            (Value::U64(3), Value::U64(c.average_size)),
            (Value::U64(4), Value::U64(c.maximum_size)),
            (Value::U64(5), Value::U64(c.normalization)),
            (Value::U64(6), Value::Bytes(c.gear_table_id.to_vec())),
        ])
    }
}

// ---------------------------------------------------------------------------
// ContentManifestChunkEntry (FORMAT.md §9.10)
// ---------------------------------------------------------------------------

/// A single chunk entry within a ContentManifestPayload.
#[derive(Clone, Debug, PartialEq)]
pub struct ContentManifestChunkEntry {
    chunk_id: ChunkId,
    plaintext_length: u64,
}

impl ContentManifestChunkEntry {
    pub fn new(chunk_id: ChunkId, plaintext_length: u64) -> Result<Self, PayloadError> {
        if plaintext_length == 0 {
            return Err(PayloadError::UnsupportedValue {
                key: 1,
                detail: "chunk plaintext_length must be nonzero".into(),
            });
        }
        Ok(Self {
            chunk_id,
            plaintext_length,
        })
    }

    pub fn chunk_id(&self) -> &ChunkId {
        &self.chunk_id
    }
    pub fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }
}

impl TryFrom<Value> for ContentManifestChunkEntry {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 2)?;
        let fields = parse_fields(pairs, 2);
        Self::new(
            ChunkId::new(field_bytes_exact::<32>(&fields, 0)?),
            field_uint(&fields, 1)?,
        )
    }
}

impl From<&ContentManifestChunkEntry> for Value {
    fn from(e: &ContentManifestChunkEntry) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::Bytes(e.chunk_id.as_bytes().to_vec())),
            (Value::U64(1), Value::U64(e.plaintext_length)),
        ])
    }
}

// ---------------------------------------------------------------------------
// EncodedChunkPayload (FORMAT.md §9.9 — record type 4, unsigned)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct EncodedChunkPayload {
    format_version: u64,
    repository_id: [u8; 16],
    chunk_id: ChunkId,
    plaintext_length: u64,
    codec: CodecDescriptor,
    encryption: Option<EncryptionDescriptor>,
    encoded_bytes: Vec<u8>,
}

impl EncodedChunkPayload {
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        chunk_id: ChunkId,
        plaintext_length: u64,
        codec: CodecDescriptor,
        encryption: Option<EncryptionDescriptor>,
        encoded_bytes: Vec<u8>,
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        if !(1..=8_388_608).contains(&plaintext_length) {
            return Err(PayloadError::UnsupportedValue {
                key: 3,
                detail: format!("plaintext_length {plaintext_length} out of range 1..8388608"),
            });
        }
        if encoded_bytes.is_empty() {
            return Err(PayloadError::EmptyArray { key: 6 });
        }
        // For codec none and encryption null, encoded_bytes must equal plaintext length
        if codec.algorithm() == 0
            && encryption.is_none()
            && encoded_bytes.len() != plaintext_length as usize
        {
            return Err(PayloadError::UnsupportedValue {
                key: 6,
                detail: format!(
                    "encoded_bytes length {} does not match plaintext_length {plaintext_length} for codec none + no encryption",
                    encoded_bytes.len(),
                ),
            });
        }
        Ok(Self {
            format_version,
            repository_id,
            chunk_id,
            plaintext_length,
            codec,
            encryption,
            encoded_bytes,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }
    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }
    pub fn chunk_id(&self) -> &ChunkId {
        &self.chunk_id
    }
    pub fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }
    pub fn codec(&self) -> &CodecDescriptor {
        &self.codec
    }
    pub fn encryption(&self) -> Option<&EncryptionDescriptor> {
        self.encryption.as_ref()
    }
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.encoded_bytes
    }

    /// Compute the record ID (DomainHash of deterministic CBOR payload).
    pub fn record_id(&self) -> Result<EncodedChunkRecordId, DomainHashError> {
        let value = Value::from(self);
        let cbor = value.reencode();
        let hash = domain_hash("EternalCore:EncodedChunk:v1", &cbor)?;
        Ok(EncodedChunkRecordId::new(hash))
    }
}

impl TryFrom<Value> for EncodedChunkPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 7)?;
        let fields = parse_fields(pairs, 7);
        let codec = match fields.get(4).and_then(|f| *f) {
            Some(Value::Map(pairs)) => CodecDescriptor::try_from(Value::Map(pairs.clone()))?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 4,
                    expected: "map",
                });
            }
            None => return Err(PayloadError::MissingField(4)),
        };
        let encryption = match fields.get(5).and_then(|f| *f) {
            Some(Value::Map(pairs)) => {
                Some(EncryptionDescriptor::try_from(Value::Map(pairs.clone()))?)
            }
            Some(Value::Null) => None,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 5,
                    expected: "null or map",
                });
            }
            None => return Err(PayloadError::MissingField(5)),
        };
        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            ChunkId::new(field_bytes_exact::<32>(&fields, 2)?),
            field_uint(&fields, 3)?,
            codec,
            encryption,
            field_bytes(&fields, 6)?,
        )
    }
}

impl From<&EncodedChunkPayload> for Value {
    fn from(p: &EncodedChunkPayload) -> Self {
        let enc: Value = match &p.encryption {
            Some(e) => Value::from(e),
            None => Value::Null,
        };
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), Value::Bytes(p.chunk_id.as_bytes().to_vec())),
            (Value::U64(3), Value::U64(p.plaintext_length)),
            (Value::U64(4), Value::from(&p.codec)),
            (Value::U64(5), enc),
            (Value::U64(6), Value::Bytes(p.encoded_bytes.clone())),
        ])
    }
}

// ---------------------------------------------------------------------------
// Content root computation (FORMAT.md §9.11)
// ---------------------------------------------------------------------------

pub fn compute_content_root(
    chunks: &[ContentManifestChunkEntry],
) -> Result<[u8; 32], DomainHashError> {
    if chunks.is_empty() {
        return domain_hash("EternalCore:ContentEmpty:v1", &[]);
    }
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(chunks.len());
    for entry in chunks {
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(entry.chunk_id.as_bytes());
        preimage.extend_from_slice(&entry.plaintext_length.to_le_bytes());
        let leaf = domain_hash("EternalCore:ContentLeaf:v1", &preimage)?;
        level.push(leaf);
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            let mut preimage = Vec::with_capacity(64);
            preimage.extend_from_slice(left);
            preimage.extend_from_slice(right);
            let parent = domain_hash("EternalCore:ContentNode:v1", &preimage)?;
            next.push(parent);
        }
        level = next;
    }
    Ok(level[0])
}

// ---------------------------------------------------------------------------
// ContentManifestPayload (FORMAT.md §9.12 — record type 5, unsigned)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct ContentManifestPayload {
    format_version: u64,
    repository_id: [u8; 16],
    chunking_scheme: ChunkingDescriptor,
    total_size: u64,
    chunks: Vec<ContentManifestChunkEntry>,
    content_root: [u8; 32],
}

impl ContentManifestPayload {
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        chunking_scheme: ChunkingDescriptor,
        total_size: u64,
        chunks: Vec<ContentManifestChunkEntry>,
        content_root: [u8; 32],
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        let computed_total: u64 = chunks
            .iter()
            .try_fold(0u64, |acc, e| acc.checked_add(e.plaintext_length))
            .ok_or(PayloadError::UnsupportedValue {
                key: 3,
                detail: "total_size overflow".into(),
            })?;
        if total_size != computed_total {
            return Err(PayloadError::UnsupportedValue {
                key: 3,
                detail: format!(
                    "total_size {total_size} does not match sum of chunk lengths {computed_total}"
                ),
            });
        }
        let computed_root =
            compute_content_root(&chunks).map_err(|_| PayloadError::UnsupportedValue {
                key: 5,
                detail: "content_root computation failed".into(),
            })?;
        if content_root != computed_root {
            return Err(PayloadError::UnsupportedValue {
                key: 5,
                detail: "content_root does not match recomputed root".into(),
            });
        }
        Ok(Self {
            format_version,
            repository_id,
            chunking_scheme,
            total_size,
            chunks,
            content_root,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }
    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }
    pub fn chunking_scheme(&self) -> &ChunkingDescriptor {
        &self.chunking_scheme
    }
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
    pub fn chunks(&self) -> &[ContentManifestChunkEntry] {
        &self.chunks
    }
    pub fn content_root(&self) -> &[u8; 32] {
        &self.content_root
    }

    /// Compute the record ID (DomainHash of deterministic CBOR payload).
    pub fn record_id(&self) -> Result<ContentManifestId, DomainHashError> {
        let value = Value::from(self);
        let cbor = value.reencode();
        let hash = domain_hash("EternalCore:ContentManifest:v1", &cbor)?;
        Ok(ContentManifestId::new(hash))
    }
}

impl TryFrom<Value> for ContentManifestPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 6)?;
        let fields = parse_fields(pairs, 6);
        let chunking_scheme = match fields.get(2).and_then(|f| *f) {
            Some(Value::Map(pairs)) => ChunkingDescriptor::try_from(Value::Map(pairs.clone()))?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 2,
                    expected: "map",
                });
            }
            None => return Err(PayloadError::MissingField(2)),
        };
        let chunks = match fields.get(4).and_then(|f| *f) {
            Some(Value::Array(items)) => {
                let mut entries = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::Map(pairs) => {
                            entries.push(ContentManifestChunkEntry::try_from(Value::Map(
                                pairs.clone(),
                            ))?);
                        }
                        _ => {
                            return Err(PayloadError::FieldType {
                                key: 4,
                                expected: "array of maps",
                            });
                        }
                    }
                }
                entries
            }
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 4,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(4)),
        };
        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            chunking_scheme,
            field_uint(&fields, 3)?,
            chunks,
            field_bytes_exact::<32>(&fields, 5)?,
        )
    }
}

impl From<&ContentManifestPayload> for Value {
    fn from(p: &ContentManifestPayload) -> Self {
        let chunks: Vec<Value> = p.chunks.iter().map(Value::from).collect();
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), Value::from(&p.chunking_scheme)),
            (Value::U64(3), Value::U64(p.total_size)),
            (Value::U64(4), Value::Array(chunks)),
            (Value::U64(5), Value::Bytes(p.content_root.to_vec())),
        ])
    }
}

// ---------------------------------------------------------------------------
// Relation (FORMAT.md §9.13) — inline struct in ObjectVersionPayload
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Relation {
    target_object_id: ObjectId,
    relation_type: RelationType,
}

impl Relation {
    pub fn new(target_object_id: ObjectId, relation_type: RelationType) -> Self {
        Self {
            target_object_id,
            relation_type,
        }
    }

    pub fn target_object_id(&self) -> &ObjectId {
        &self.target_object_id
    }

    pub fn relation_type(&self) -> &RelationType {
        &self.relation_type
    }
}

impl TryFrom<Value> for Relation {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 2)?;
        let fields = parse_fields(pairs, 2);
        let target_str = field_text(&fields, 0)?;
        let target = ObjectId::new(&target_str).map_err(|e| PayloadError::InvalidText {
            key: 0,
            detail: e.to_string(),
        })?;
        let rel_str = field_text(&fields, 1)?;
        let rel = RelationType::new(&rel_str).map_err(|e| PayloadError::InvalidText {
            key: 1,
            detail: e.to_string(),
        })?;
        Ok(Self::new(target, rel))
    }
}

impl From<&Relation> for Value {
    fn from(r: &Relation) -> Self {
        Value::Map(vec![
            (
                Value::U64(0),
                Value::Text(r.target_object_id.as_str().to_string()),
            ),
            (
                Value::U64(1),
                Value::Text(r.relation_type.as_str().to_string()),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// ObjectVersionPayload (FORMAT.md §9.14 — record type 6, signed)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct ObjectVersionPayload {
    format_version: u64,
    repository_id: [u8; 16],
    object_id: ObjectId,
    content_manifest_id: Option<ContentManifestId>,
    parents: Vec<VersionId>,
    data_type: DataType,
    metadata: CanonicalValue,
    relations: Vec<Relation>,
    tombstone: bool,
    created_at_ns: i64,
    author_key_id: [u8; 32],
}

impl ObjectVersionPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        object_id: ObjectId,
        content_manifest_id: Option<ContentManifestId>,
        parents: Vec<VersionId>,
        data_type: DataType,
        metadata: CanonicalValue,
        relations: Vec<Relation>,
        tombstone: bool,
        created_at_ns: i64,
        author_key_id: [u8; 32],
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        // tombstone consistency: null content_manifest_id iff tombstone
        match (&content_manifest_id, tombstone) {
            (None, false) => {
                return Err(PayloadError::UnsupportedValue {
                    key: 3,
                    detail: "non-tombstone version must have content_manifest_id".into(),
                });
            }
            (Some(_), true) => {
                return Err(PayloadError::UnsupportedValue {
                    key: 8,
                    detail: "tombstone version must not have content_manifest_id".into(),
                });
            }
            _ => {}
        }
        // parent count limit (0..ABSOLUTE_MAX)
        let max_parents = FormatLimits::ABSOLUTE_MAX_OBJECT_VERSION_PARENTS as usize;
        if parents.len() > max_parents {
            return Err(PayloadError::UnsupportedValue {
                key: 4,
                detail: format!(
                    "parent count {} exceeds maximum {}",
                    parents.len(),
                    max_parents,
                ),
            });
        }
        // parent duplicates
        {
            let mut seen = std::collections::HashSet::new();
            for p in &parents {
                if !seen.insert(p.as_bytes()) {
                    return Err(PayloadError::UnsortedOrDuplicate { key: 4 });
                }
            }
        }
        // additional parents (index 1..) must be lexicographically sorted
        if parents.len() > 2 {
            for w in parents[1..].windows(2) {
                if w[0].as_bytes() >= w[1].as_bytes() {
                    return Err(PayloadError::UnsortedOrDuplicate { key: 4 });
                }
            }
        }
        // relation count limit
        let max_relations = FormatLimits::ABSOLUTE_MAX_RELATIONS as usize;
        if relations.len() > max_relations {
            return Err(PayloadError::UnsupportedValue {
                key: 7,
                detail: format!(
                    "relation count {} exceeds maximum {}",
                    relations.len(),
                    max_relations,
                ),
            });
        }
        // relations sorted and unique by (target_object_id, relation_type)
        check_relations_sorted_unique(&relations)?;
        Ok(Self {
            format_version,
            repository_id,
            object_id,
            content_manifest_id,
            parents,
            data_type,
            metadata,
            relations,
            tombstone,
            created_at_ns,
            author_key_id,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }
    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }
    pub fn object_id(&self) -> &ObjectId {
        &self.object_id
    }
    pub fn content_manifest_id(&self) -> Option<&ContentManifestId> {
        self.content_manifest_id.as_ref()
    }
    pub fn parents(&self) -> &[VersionId] {
        &self.parents
    }
    pub fn data_type(&self) -> &DataType {
        &self.data_type
    }
    pub fn metadata(&self) -> &CanonicalValue {
        &self.metadata
    }
    pub fn relations(&self) -> &[Relation] {
        &self.relations
    }
    pub fn tombstone(&self) -> bool {
        self.tombstone
    }
    pub fn created_at_ns(&self) -> i64 {
        self.created_at_ns
    }
    pub fn author_key_id(&self) -> &[u8; 32] {
        &self.author_key_id
    }

    pub fn record_id(&self) -> Result<VersionId, DomainHashError> {
        let value = Value::from(self);
        let cbor = value.reencode();
        let hash = domain_hash("EternalCore:ObjectVersion:v1", &cbor)?;
        Ok(VersionId::new(hash))
    }
}

impl TryFrom<Value> for ObjectVersionPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 11)?;
        let fields = parse_fields(pairs, 11);
        let object_str = field_text(&fields, 2)?;
        let object_id = ObjectId::new(&object_str).map_err(|e| PayloadError::InvalidText {
            key: 2,
            detail: e.to_string(),
        })?;
        let content_manifest_id =
            field_nullable_bytes_exact::<32>(&fields, 3)?.map(ContentManifestId::new);
        let parents: Vec<VersionId> = {
            let parent_bytes = bytes_array_field(&fields, 4)?;
            parent_bytes
                .into_iter()
                .map(|b| {
                    let actual = b.len();
                    let arr: [u8; 32] = b.try_into().map_err(|_| PayloadError::WrongLength {
                        key: 4,
                        expected: 32,
                        actual,
                    })?;
                    Ok(VersionId::new(arr))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let data_str = field_text(&fields, 5)?;
        let data_type = DataType::new(&data_str).map_err(|e| PayloadError::InvalidText {
            key: 5,
            detail: e.to_string(),
        })?;
        let metadata = match fields.get(6).and_then(|f| *f) {
            Some(v) => {
                let limits = FormatLimits::default();
                let mut nodes = 0;
                canonical_value_from_value(v, 0, &mut nodes, &limits).map_err(|_| {
                    PayloadError::Decode(DecodeError::InvalidCanonicalValueStructure)
                })?
            }
            None => return Err(PayloadError::MissingField(6)),
        };
        let relations = match fields.get(7).and_then(|f| *f) {
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| Relation::try_from(v.clone()))
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 7,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(7)),
        };
        let tombstone = match fields.get(8).and_then(|f| *f) {
            Some(Value::Boolean(b)) => *b,
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 8,
                    expected: "bool",
                });
            }
            None => return Err(PayloadError::MissingField(8)),
        };
        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            object_id,
            content_manifest_id,
            parents,
            data_type,
            metadata,
            relations,
            tombstone,
            field_int(&fields, 9)?,
            field_bytes_exact::<32>(&fields, 10)?,
        )
    }
}

impl From<&ObjectVersionPayload> for Value {
    fn from(p: &ObjectVersionPayload) -> Self {
        let content_manifest: Value = match &p.content_manifest_id {
            Some(id) => Value::Bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        let parents: Vec<Value> = p
            .parents
            .iter()
            .map(|id| Value::Bytes(id.as_bytes().to_vec()))
            .collect();
        let relations: Vec<Value> = p.relations.iter().map(Value::from).collect();
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), Value::Text(p.object_id.as_str().to_string())),
            (Value::U64(3), content_manifest),
            (Value::U64(4), Value::Array(parents)),
            (Value::U64(5), Value::Text(p.data_type.as_str().to_string())),
            (Value::U64(6), value_from_canonical_value(&p.metadata)),
            (Value::U64(7), Value::Array(relations)),
            (Value::U64(8), Value::Boolean(p.tombstone)),
            (Value::U64(9), Value::I64(p.created_at_ns)),
            (Value::U64(10), Value::Bytes(p.author_key_id.to_vec())),
        ])
    }
}

fn check_relations_sorted_unique(relations: &[Relation]) -> Result<(), PayloadError> {
    for w in relations.windows(2) {
        let a_key = (w[0].target_object_id.as_str(), w[0].relation_type.as_str());
        let b_key = (w[1].target_object_id.as_str(), w[1].relation_type.as_str());
        if a_key >= b_key {
            return Err(PayloadError::UnsortedOrDuplicate { key: 7 });
        }
    }
    Ok(())
}

/// Extract a single bit from an [`ObjectKey`] at the given SMT depth.
///
/// Per FORMAT.md §10.1:
/// - The path is the 256 bits of `ObjectKey`, most-significant bit first.
/// - Depth 0 consumes bit 7 of byte 0; depth 255 consumes bit 0 of byte 31.
/// - Bit 0 selects the left child. Bit 1 selects the right child.
///
/// Returns `None` when `depth >= 256`.
pub fn object_key_bit(object_key: &ObjectKey, depth: usize) -> Option<u8> {
    if depth >= 256 {
        return None;
    }
    let byte_index = depth / 8;
    let bit_position = 7 - (depth % 8);
    Some((object_key.as_bytes()[byte_index] >> bit_position) & 1)
}

// ---------------------------------------------------------------------------
// SMTLeafPayload (FORMAT.md §9.15 — record type 7, unsigned semantic ID)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct SMTLeafPayload {
    format_version: u64,
    object_key: ObjectKey,
    version_id: VersionId,
}

impl SMTLeafPayload {
    pub fn new(
        format_version: u64,
        object_key: ObjectKey,
        version_id: VersionId,
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        Ok(Self {
            format_version,
            object_key,
            version_id,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }

    pub fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }

    pub fn version_id(&self) -> &VersionId {
        &self.version_id
    }

    pub fn record_id(&self) -> Result<SmtLeafId, DomainHashError> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(self.object_key.as_bytes());
        payload.extend_from_slice(self.version_id.as_bytes());
        let hash = domain_hash("EternalCore:SMTLeaf:v1", &payload)?;
        Ok(SmtLeafId::new(hash))
    }
}

impl TryFrom<Value> for SMTLeafPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 3)?;
        let fields = parse_fields(pairs, 3);
        let object_key_bytes = field_bytes_exact::<32>(&fields, 1)?;
        let version_id_bytes = field_bytes_exact::<32>(&fields, 2)?;
        Self::new(
            field_uint(&fields, 0)?,
            ObjectKey::new(object_key_bytes),
            VersionId::new(version_id_bytes),
        )
    }
}

impl From<&SMTLeafPayload> for Value {
    fn from(p: &SMTLeafPayload) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (
                Value::U64(1),
                Value::Bytes(p.object_key.as_bytes().to_vec()),
            ),
            (
                Value::U64(2),
                Value::Bytes(p.version_id.as_bytes().to_vec()),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// SMTInternalPayload (FORMAT.md §9.16 — record type 8, unsigned semantic ID)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct SMTInternalPayload {
    format_version: u64,
    left_child: [u8; 32],
    right_child: [u8; 32],
}

impl SMTInternalPayload {
    pub fn new(
        format_version: u64,
        left_child: [u8; 32],
        right_child: [u8; 32],
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        Ok(Self {
            format_version,
            left_child,
            right_child,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }

    pub fn left_child(&self) -> &[u8; 32] {
        &self.left_child
    }

    pub fn right_child(&self) -> &[u8; 32] {
        &self.right_child
    }

    pub fn record_id(&self) -> Result<SmtInternalId, DomainHashError> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.left_child);
        payload.extend_from_slice(&self.right_child);
        let hash = domain_hash("EternalCore:SMTInternal:v1", &payload)?;
        Ok(SmtInternalId::new(hash))
    }
}

impl TryFrom<Value> for SMTInternalPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 3)?;
        let fields = parse_fields(pairs, 3);
        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<32>(&fields, 1)?,
            field_bytes_exact::<32>(&fields, 2)?,
        )
    }
}

impl From<&SMTInternalPayload> for Value {
    fn from(p: &SMTInternalPayload) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.left_child.to_vec())),
            (Value::U64(2), Value::Bytes(p.right_child.to_vec())),
        ])
    }
}

// ---------------------------------------------------------------------------
// SMTProof (FORMAT.md §10.6 — protocol object, not a stored record)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct SMTProof {
    format_version: u64,
    root: SmtRoot,
    object_key: ObjectKey,
    version_id: Option<VersionId>,
    siblings: Vec<[u8; 32]>,
}

impl SMTProof {
    pub fn new(
        format_version: u64,
        root: SmtRoot,
        object_key: ObjectKey,
        version_id: Option<VersionId>,
        siblings: Vec<[u8; 32]>,
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        if siblings.len() != 256 {
            return Err(PayloadError::UnsupportedValue {
                key: 4,
                detail: format!(
                    "siblings count {} does not match required 256",
                    siblings.len(),
                ),
            });
        }
        Ok(Self {
            format_version,
            root,
            object_key,
            version_id,
            siblings,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }

    pub fn root(&self) -> &SmtRoot {
        &self.root
    }

    pub fn object_key(&self) -> &ObjectKey {
        &self.object_key
    }

    pub fn version_id(&self) -> Option<&VersionId> {
        self.version_id.as_ref()
    }

    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }
}

impl TryFrom<Value> for SMTProof {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 5)?;
        let fields = parse_fields(pairs, 5);
        let root_bytes = field_bytes_exact::<32>(&fields, 1)?;
        let object_key_bytes = field_bytes_exact::<32>(&fields, 2)?;
        let version_id = field_nullable_bytes_exact::<32>(&fields, 3)?.map(VersionId::new);
        let siblings = match fields.get(4).and_then(|f| *f) {
            Some(Value::Array(items)) => {
                if items.len() != 256 {
                    return Err(PayloadError::UnsupportedValue {
                        key: 4,
                        detail: format!(
                            "siblings count {} does not match required 256",
                            items.len(),
                        ),
                    });
                }
                items
                    .iter()
                    .map(|v| {
                        let b = match v {
                            Value::Bytes(b) => b.clone(),
                            _ => {
                                return Err(PayloadError::FieldType {
                                    key: 4,
                                    expected: "array of bytes(32)",
                                });
                            }
                        };
                        let actual = b.len();
                        <[u8; 32]>::try_from(b).map_err(|_| PayloadError::WrongLength {
                            key: 4,
                            expected: 32,
                            actual,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 4,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(4)),
        };
        Self::new(
            field_uint(&fields, 0)?,
            SmtRoot::new(root_bytes),
            ObjectKey::new(object_key_bytes),
            version_id,
            siblings,
        )
    }
}

impl From<&SMTProof> for Value {
    fn from(p: &SMTProof) -> Self {
        let version_value = match &p.version_id {
            Some(id) => Value::Bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        let sibling_values: Vec<Value> = p
            .siblings
            .iter()
            .map(|b| Value::Bytes(b.to_vec()))
            .collect();
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.root.as_bytes().to_vec())),
            (
                Value::U64(2),
                Value::Bytes(p.object_key.as_bytes().to_vec()),
            ),
            (Value::U64(3), version_value),
            (Value::U64(4), Value::Array(sibling_values)),
        ])
    }
}

// ---------------------------------------------------------------------------
// ObjectChange (§9.17)
// ---------------------------------------------------------------------------

/// A single object change within a RepoCommit.
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectChange {
    object_id: ObjectId,
    old_version_id: Option<VersionId>,
    new_version_id: VersionId,
}

impl ObjectChange {
    pub fn new(
        object_id: ObjectId,
        old_version_id: Option<VersionId>,
        new_version_id: VersionId,
    ) -> Self {
        Self {
            object_id,
            old_version_id,
            new_version_id,
        }
    }

    pub fn object_id(&self) -> &ObjectId {
        &self.object_id
    }

    pub fn old_version_id(&self) -> Option<&VersionId> {
        self.old_version_id.as_ref()
    }

    pub fn new_version_id(&self) -> &VersionId {
        &self.new_version_id
    }
}

impl TryFrom<Value> for ObjectChange {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 3)?;
        let fields = parse_fields(pairs, 3);
        Ok(Self {
            object_id: {
                let text = field_text(&fields, 0)?;
                ObjectId::new(&text).map_err(|e| PayloadError::InvalidText {
                    key: 0,
                    detail: e.to_string(),
                })?
            },
            old_version_id: field_nullable_bytes_exact::<32>(&fields, 1)?.map(VersionId::new),
            new_version_id: VersionId::new(field_bytes_exact::<32>(&fields, 2)?),
        })
    }
}

impl From<&ObjectChange> for Value {
    fn from(c: &ObjectChange) -> Self {
        let old_value = match &c.old_version_id {
            Some(id) => Value::Bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        Value::Map(vec![
            (Value::U64(0), Value::Text(c.object_id.as_str().to_string())),
            (Value::U64(1), old_value),
            (
                Value::U64(2),
                Value::Bytes(c.new_version_id.as_bytes().to_vec()),
            ),
        ])
    }
}

/// Validate that a slice of ObjectChange entries is sorted by ObjectId and has no duplicates.
pub fn check_changes_sorted_unique(changes: &[ObjectChange]) -> Result<(), PayloadError> {
    for window in changes.windows(2) {
        let a = window[0].object_id.as_str().as_bytes();
        let b = window[1].object_id.as_str().as_bytes();
        if a >= b {
            return Err(PayloadError::UnsortedOrDuplicate { key: 3 });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RepoCommitPayload (§9.18, signed record type 9)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct RepoCommitPayload {
    format_version: u64,
    repository_id: [u8; 16],
    parents: Vec<RepoCommitId>,
    changes: Vec<ObjectChange>,
    object_state_root: SmtRoot,
    policy_id: PolicyId,
    keyring_id: KeyringId,
    created_at_ns: i64,
    message: String,
    author_key_id: KeyId,
}

impl RepoCommitPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        parents: Vec<RepoCommitId>,
        changes: Vec<ObjectChange>,
        object_state_root: SmtRoot,
        policy_id: PolicyId,
        keyring_id: KeyringId,
        created_at_ns: i64,
        message: String,
        author_key_id: KeyId,
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        if parents.len() > 64 {
            return Err(PayloadError::UnsupportedValue {
                key: 2,
                detail: format!("parent count {} exceeds 64", parents.len()),
            });
        }
        // parent 0 is the state baseline; remaining parents must be sorted
        let mut seen = std::collections::HashSet::new();
        for p in &parents {
            if !seen.insert(p.as_bytes()) {
                return Err(PayloadError::UnsortedOrDuplicate { key: 2 });
            }
        }
        if parents.len() > 2 {
            for window in parents[1..].windows(2) {
                if window[0].as_bytes() >= window[1].as_bytes() {
                    return Err(PayloadError::UnsortedOrDuplicate { key: 2 });
                }
            }
        }
        check_changes_sorted_unique(&changes)?;
        Ok(Self {
            format_version,
            repository_id,
            parents,
            changes,
            object_state_root,
            policy_id,
            keyring_id,
            created_at_ns,
            message,
            author_key_id,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }

    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }

    pub fn parents(&self) -> &[RepoCommitId] {
        &self.parents
    }

    pub fn changes(&self) -> &[ObjectChange] {
        &self.changes
    }

    pub fn object_state_root(&self) -> &SmtRoot {
        &self.object_state_root
    }

    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    pub fn keyring_id(&self) -> &KeyringId {
        &self.keyring_id
    }

    pub fn created_at_ns(&self) -> i64 {
        self.created_at_ns
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn author_key_id(&self) -> &KeyId {
        &self.author_key_id
    }

    pub fn record_id(&self) -> Result<RepoCommitId, DomainHashError> {
        let value = Value::from(self);
        let cbor = value.reencode();
        let hash = domain_hash("EternalCore:RepoCommit:v1", &cbor)?;
        Ok(RepoCommitId::new(hash))
    }
}

impl TryFrom<Value> for RepoCommitPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 10)?;
        let fields = parse_fields(pairs, 10);

        let parents = match fields.get(2).and_then(|f| *f) {
            Some(Value::Array(items)) => {
                let mut v = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::Bytes(b) if b.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(b);
                            v.push(RepoCommitId::new(arr));
                        }
                        _ => {
                            return Err(PayloadError::FieldType {
                                key: 2,
                                expected: "array of bytes(32)",
                            });
                        }
                    }
                }
                v
            }
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 2,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(2)),
        };

        let changes = match fields.get(3).and_then(|f| *f) {
            Some(Value::Array(items)) => {
                let mut v = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::Map(_) => {
                            v.push(ObjectChange::try_from(item.clone())?);
                        }
                        _ => {
                            return Err(PayloadError::FieldType {
                                key: 3,
                                expected: "array of ObjectChange maps",
                            });
                        }
                    }
                }
                v
            }
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 3,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(3)),
        };

        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            parents,
            changes,
            SmtRoot::new(field_bytes_exact::<32>(&fields, 4)?),
            PolicyId::new(field_bytes_exact::<32>(&fields, 5)?),
            KeyringId::new(field_bytes_exact::<32>(&fields, 6)?),
            field_int(&fields, 7)?,
            field_text(&fields, 8)?,
            KeyId::new(field_bytes_exact::<32>(&fields, 9)?),
        )
    }
}

impl From<&RepoCommitPayload> for Value {
    fn from(p: &RepoCommitPayload) -> Self {
        let parent_values: Vec<Value> = p
            .parents
            .iter()
            .map(|id| Value::Bytes(id.as_bytes().to_vec()))
            .collect();
        let change_values: Vec<Value> = p.changes.iter().map(Value::from).collect();
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), Value::Array(parent_values)),
            (Value::U64(3), Value::Array(change_values)),
            (
                Value::U64(4),
                Value::Bytes(p.object_state_root.as_bytes().to_vec()),
            ),
            (Value::U64(5), Value::Bytes(p.policy_id.as_bytes().to_vec())),
            (
                Value::U64(6),
                Value::Bytes(p.keyring_id.as_bytes().to_vec()),
            ),
            (Value::U64(7), Value::I64(p.created_at_ns)),
            (Value::U64(8), Value::Text(p.message.clone())),
            (
                Value::U64(9),
                Value::Bytes(p.author_key_id.as_bytes().to_vec()),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// RefUpdatePayload (§9.19, signed record type 10)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct RefUpdatePayload {
    format_version: u64,
    repository_id: [u8; 16],
    ref_name: RefName,
    previous_ref_update_id: Option<RefUpdateId>,
    target_commit_id: Option<RepoCommitId>,
    sequence: u64,
    created_at_ns: i64,
    author_key_id: KeyId,
}

impl RefUpdatePayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        ref_name: RefName,
        previous_ref_update_id: Option<RefUpdateId>,
        target_commit_id: Option<RepoCommitId>,
        sequence: u64,
        created_at_ns: i64,
        author_key_id: KeyId,
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        if sequence < 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 5,
                detail: format!("sequence must be >= 1, got {sequence}"),
            });
        }
        // Tag update MUST have non-null target, no predecessor, and sequence 1.
        if ref_name.as_str().starts_with("refs/tags/") {
            if target_commit_id.is_none() {
                return Err(PayloadError::UnsupportedValue {
                    key: 4,
                    detail: "tag update must have a non-null target commit".to_string(),
                });
            }
            if previous_ref_update_id.is_some() {
                return Err(PayloadError::UnsupportedValue {
                    key: 3,
                    detail: "tag update must have no predecessor".to_string(),
                });
            }
            if sequence != 1 {
                return Err(PayloadError::UnsupportedValue {
                    key: 5,
                    detail: format!("tag update sequence must be 1, got {sequence}"),
                });
            }
        }
        Ok(Self {
            format_version,
            repository_id,
            ref_name,
            previous_ref_update_id,
            target_commit_id,
            sequence,
            created_at_ns,
            author_key_id,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }

    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }

    pub fn ref_name(&self) -> &RefName {
        &self.ref_name
    }

    pub fn previous_ref_update_id(&self) -> Option<&RefUpdateId> {
        self.previous_ref_update_id.as_ref()
    }

    pub fn target_commit_id(&self) -> Option<&RepoCommitId> {
        self.target_commit_id.as_ref()
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn created_at_ns(&self) -> i64 {
        self.created_at_ns
    }

    pub fn author_key_id(&self) -> &KeyId {
        &self.author_key_id
    }

    pub fn record_id(&self) -> Result<RefUpdateId, DomainHashError> {
        let value = Value::from(self);
        let cbor = value.reencode();
        let hash = domain_hash("EternalCore:RefUpdate:v1", &cbor)?;
        Ok(RefUpdateId::new(hash))
    }
}

impl TryFrom<Value> for RefUpdatePayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 8)?;
        let fields = parse_fields(pairs, 8);

        let ref_name = {
            let text = field_text(&fields, 2)?;
            RefName::new(&text).map_err(|e| PayloadError::InvalidText {
                key: 2,
                detail: e.to_string(),
            })?
        };

        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            ref_name,
            field_nullable_bytes_exact::<32>(&fields, 3)?.map(RefUpdateId::new),
            field_nullable_bytes_exact::<32>(&fields, 4)?.map(RepoCommitId::new),
            field_uint(&fields, 5)?,
            field_int(&fields, 6)?,
            KeyId::new(field_bytes_exact::<32>(&fields, 7)?),
        )
    }
}

impl From<&RefUpdatePayload> for Value {
    fn from(p: &RefUpdatePayload) -> Self {
        let prev_value = match &p.previous_ref_update_id {
            Some(id) => Value::Bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        let target_value = match &p.target_commit_id {
            Some(id) => Value::Bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), Value::Text(p.ref_name.as_str().to_string())),
            (Value::U64(3), prev_value),
            (Value::U64(4), target_value),
            (Value::U64(5), Value::U64(p.sequence)),
            (Value::U64(6), Value::I64(p.created_at_ns)),
            (
                Value::U64(7),
                Value::Bytes(p.author_key_id.as_bytes().to_vec()),
            ),
        ])
    }
}

// ---------------------------------------------------------------------------
// TransactionEndPayload (§9.20, unsigned record type 11, segment-only)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct TransactionEndPayload {
    format_version: u64,
    repository_id: [u8; 16],
    transaction_id: [u8; 16],
    first_frame_offset: u64,
    end_frame_offset: u64,
    record_count: u64,
    record_ids_root: [u8; 32],
}

impl TransactionEndPayload {
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        transaction_id: [u8; 16],
        first_frame_offset: u64,
        end_frame_offset: u64,
        record_count: u64,
        record_ids_root: [u8; 32],
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        if end_frame_offset < first_frame_offset {
            return Err(PayloadError::UnsupportedValue {
                key: 4,
                detail: format!(
                    "end_frame_offset {} must be >= first_frame_offset {}",
                    end_frame_offset, first_frame_offset,
                ),
            });
        }
        Ok(Self {
            format_version,
            repository_id,
            transaction_id,
            first_frame_offset,
            end_frame_offset,
            record_count,
            record_ids_root,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }

    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }

    pub fn transaction_id(&self) -> &[u8; 16] {
        &self.transaction_id
    }

    pub fn first_frame_offset(&self) -> u64 {
        self.first_frame_offset
    }

    pub fn end_frame_offset(&self) -> u64 {
        self.end_frame_offset
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn record_ids_root(&self) -> &[u8; 32] {
        &self.record_ids_root
    }

    pub fn record_id(&self) -> Result<TransactionEndId, DomainHashError> {
        let value = Value::from(self);
        let cbor = value.reencode();
        let hash = domain_hash("EternalCore:TransactionEnd:v1", &cbor)?;
        Ok(TransactionEndId::new(hash))
    }
}

impl TryFrom<Value> for TransactionEndPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 7)?;
        let fields = parse_fields(pairs, 7);
        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            field_bytes_exact::<16>(&fields, 2)?,
            field_uint(&fields, 3)?,
            field_uint(&fields, 4)?,
            field_uint(&fields, 5)?,
            field_bytes_exact::<32>(&fields, 6)?,
        )
    }
}

impl From<&TransactionEndPayload> for Value {
    fn from(p: &TransactionEndPayload) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (Value::U64(2), Value::Bytes(p.transaction_id.to_vec())),
            (Value::U64(3), Value::U64(p.first_frame_offset)),
            (Value::U64(4), Value::U64(p.end_frame_offset)),
            (Value::U64(5), Value::U64(p.record_count)),
            (Value::U64(6), Value::Bytes(p.record_ids_root.to_vec())),
        ])
    }
}

// ---------------------------------------------------------------------------
// record_ids_root (§9.21)
// ---------------------------------------------------------------------------

/// Compute the root hash of a list of record IDs in physical append order.
pub fn record_ids_root(record_ids: &[RecordId]) -> Result<[u8; 32], DomainHashError> {
    let mut payload = Vec::with_capacity(record_ids.len() * 32);
    for id in record_ids {
        payload.extend_from_slice(id.as_bytes());
    }
    domain_hash("EternalCore:TransactionBatch:v1", &payload)
}

// ---------------------------------------------------------------------------
// StoreManifest schemas (§11)
// ---------------------------------------------------------------------------

fn validate_normalized_path(path: &str, key: u64) -> Result<(), PayloadError> {
    if path.is_empty() {
        return Err(PayloadError::InvalidText {
            key,
            detail: "path is empty".to_string(),
        });
    }
    if path.as_bytes()[0] == b'/' {
        return Err(PayloadError::InvalidText {
            key,
            detail: "path must not be absolute".to_string(),
        });
    }
    if path.as_bytes()[path.len() - 1] == b'/' {
        return Err(PayloadError::InvalidText {
            key,
            detail: "path must not end with '/'".to_string(),
        });
    }
    for (i, &b) in path.as_bytes().iter().enumerate() {
        if b <= 0x1f || b == 0x7f {
            return Err(PayloadError::InvalidText {
                key,
                detail: format!("control character at position {i}"),
            });
        }
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(PayloadError::InvalidText {
                key,
                detail: "path contains empty segment".to_string(),
            });
        }
        if segment == "." {
            return Err(PayloadError::InvalidText {
                key,
                detail: "path contains '.' segment".to_string(),
            });
        }
        if segment == ".." {
            return Err(PayloadError::InvalidText {
                key,
                detail: "path contains '..' segment".to_string(),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SegmentDescriptor (§11.1)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct SegmentDescriptor {
    store_generation: u64,
    segment_id: [u8; 16],
    relative_path: String,
}

fn uuid_to_hex(id: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id[0],
        id[1],
        id[2],
        id[3],
        id[4],
        id[5],
        id[6],
        id[7],
        id[8],
        id[9],
        id[10],
        id[11],
        id[12],
        id[13],
        id[14],
        id[15],
    )
}

impl SegmentDescriptor {
    pub fn new(
        store_generation: u64,
        segment_id: [u8; 16],
        relative_path: String,
    ) -> Result<Self, PayloadError> {
        validate_normalized_path(&relative_path, 2)?;
        // Enforce v1 path pattern: objects/active/segment-<generation>-<uuid>.seg
        let prefix = "objects/active/";
        if !relative_path.starts_with(prefix) {
            return Err(PayloadError::InvalidText {
                key: 2,
                detail: format!("v1 path must start with '{prefix}'"),
            });
        }
        let filename = &relative_path[prefix.len()..];
        let expected_prefix = format!("segment-{store_generation}-");
        if !filename.starts_with(&expected_prefix) {
            return Err(PayloadError::InvalidText {
                key: 2,
                detail: format!("v1 filename must start with 'segment-{store_generation}-'"),
            });
        }
        if !filename.ends_with(".seg") {
            return Err(PayloadError::InvalidText {
                key: 2,
                detail: "v1 filename must end with '.seg'".to_string(),
            });
        }
        let uuid_part = &filename[expected_prefix.len()..filename.len() - 4];
        let expected_hex = uuid_to_hex(&segment_id);
        if uuid_part != expected_hex {
            return Err(PayloadError::InvalidText {
                key: 2,
                detail: "v1 filename uuid does not match segment_id".to_string(),
            });
        }
        Ok(Self {
            store_generation,
            segment_id,
            relative_path,
        })
    }

    pub fn store_generation(&self) -> u64 {
        self.store_generation
    }

    pub fn segment_id(&self) -> &[u8; 16] {
        &self.segment_id
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

impl TryFrom<Value> for SegmentDescriptor {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 3)?;
        let fields = parse_fields(pairs, 3);
        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            field_text(&fields, 2)?,
        )
    }
}

impl From<&SegmentDescriptor> for Value {
    fn from(d: &SegmentDescriptor) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::U64(d.store_generation)),
            (Value::U64(1), Value::Bytes(d.segment_id.to_vec())),
            (Value::U64(2), Value::Text(d.relative_path.clone())),
        ])
    }
}

// ---------------------------------------------------------------------------
// PackDescriptor (§11.2)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct PackDescriptor {
    pack_checksum: [u8; 32],
    index_checksum: [u8; 32],
    pack_relative_path: String,
    index_relative_path: String,
    record_count: u64,
}

impl PackDescriptor {
    pub fn new(
        pack_checksum: [u8; 32],
        index_checksum: [u8; 32],
        pack_relative_path: String,
        index_relative_path: String,
        record_count: u64,
    ) -> Result<Self, PayloadError> {
        validate_normalized_path(&pack_relative_path, 2)?;
        validate_normalized_path(&index_relative_path, 3)?;
        Ok(Self {
            pack_checksum,
            index_checksum,
            pack_relative_path,
            index_relative_path,
            record_count,
        })
    }

    pub fn pack_checksum(&self) -> &[u8; 32] {
        &self.pack_checksum
    }

    pub fn index_checksum(&self) -> &[u8; 32] {
        &self.index_checksum
    }

    pub fn pack_relative_path(&self) -> &str {
        &self.pack_relative_path
    }

    pub fn index_relative_path(&self) -> &str {
        &self.index_relative_path
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }
}

impl TryFrom<Value> for PackDescriptor {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 5)?;
        let fields = parse_fields(pairs, 5);
        Self::new(
            field_bytes_exact::<32>(&fields, 0)?,
            field_bytes_exact::<32>(&fields, 1)?,
            field_text(&fields, 2)?,
            field_text(&fields, 3)?,
            field_uint(&fields, 4)?,
        )
    }
}

impl From<&PackDescriptor> for Value {
    fn from(d: &PackDescriptor) -> Self {
        Value::Map(vec![
            (Value::U64(0), Value::Bytes(d.pack_checksum.to_vec())),
            (Value::U64(1), Value::Bytes(d.index_checksum.to_vec())),
            (Value::U64(2), Value::Text(d.pack_relative_path.clone())),
            (Value::U64(3), Value::Text(d.index_relative_path.clone())),
            (Value::U64(4), Value::U64(d.record_count)),
        ])
    }
}

/// Validate that a slice of PackDescriptor entries is sorted by pack_checksum
/// and contains no duplicates.
pub fn check_pack_descriptors_sorted_unique(
    descriptors: &[PackDescriptor],
) -> Result<(), PayloadError> {
    for window in descriptors.windows(2) {
        let a = &window[0].pack_checksum;
        let b = &window[1].pack_checksum;
        if a >= b {
            return Err(PayloadError::UnsortedOrDuplicate { key: 6 });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// StoreManifestPayload (§11.3, unsigned record type — physical, not logical)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct StoreManifestPayload {
    format_version: u64,
    repository_id: [u8; 16],
    repository_genesis_id: RepositoryGenesisId,
    generation: u64,
    previous_manifest_id: Option<StoreManifestId>,
    active_segment: SegmentDescriptor,
    sealed_packs: Vec<PackDescriptor>,
    created_at_ns: i64,
}

impl StoreManifestPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        format_version: u64,
        repository_id: [u8; 16],
        repository_genesis_id: RepositoryGenesisId,
        generation: u64,
        previous_manifest_id: Option<StoreManifestId>,
        active_segment: SegmentDescriptor,
        sealed_packs: Vec<PackDescriptor>,
        created_at_ns: i64,
    ) -> Result<Self, PayloadError> {
        if format_version != 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 0,
                detail: format!("unsupported format_version {format_version}"),
            });
        }
        if generation < 1 {
            return Err(PayloadError::UnsupportedValue {
                key: 3,
                detail: format!("generation must be >= 1, got {generation}"),
            });
        }
        // Generation 1 MUST have no predecessor; generation > 1 MUST have one.
        match (generation, &previous_manifest_id) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(PayloadError::UnsupportedValue {
                    key: 4,
                    detail: "generation 1 must have null previous_manifest_id".to_string(),
                });
            }
            (_, None) => {
                return Err(PayloadError::UnsupportedValue {
                    key: 4,
                    detail: format!("generation {generation} must have a previous_manifest_id"),
                });
            }
            _ => {}
        }
        // Active segment store_generation must match manifest generation.
        if active_segment.store_generation != generation {
            return Err(PayloadError::UnsupportedValue {
                key: 5,
                detail: format!(
                    "active_segment store_generation {} != manifest generation {}",
                    active_segment.store_generation, generation,
                ),
            });
        }
        check_pack_descriptors_sorted_unique(&sealed_packs)?;
        Ok(Self {
            format_version,
            repository_id,
            repository_genesis_id,
            generation,
            previous_manifest_id,
            active_segment,
            sealed_packs,
            created_at_ns,
        })
    }

    pub fn format_version(&self) -> u64 {
        self.format_version
    }

    pub fn repository_id(&self) -> &[u8; 16] {
        &self.repository_id
    }

    pub fn repository_genesis_id(&self) -> &RepositoryGenesisId {
        &self.repository_genesis_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn previous_manifest_id(&self) -> Option<&StoreManifestId> {
        self.previous_manifest_id.as_ref()
    }

    pub fn active_segment(&self) -> &SegmentDescriptor {
        &self.active_segment
    }

    pub fn sealed_packs(&self) -> &[PackDescriptor] {
        &self.sealed_packs
    }

    pub fn created_at_ns(&self) -> i64 {
        self.created_at_ns
    }

    pub fn record_id(&self) -> Result<StoreManifestId, DomainHashError> {
        let value = Value::from(self);
        let cbor = value.reencode();
        let hash = domain_hash("EternalCore:StoreManifest:v1", &cbor)?;
        Ok(StoreManifestId::new(hash))
    }
}

impl TryFrom<Value> for StoreManifestPayload {
    type Error = PayloadError;
    fn try_from(value: Value) -> Result<Self, PayloadError> {
        let pairs = match &value {
            Value::Map(pairs) => pairs,
            _ => return Err(PayloadError::NotAMap),
        };
        reject_unknown_keys(pairs, 8)?;
        let fields = parse_fields(pairs, 8);

        let active_segment = match fields.get(5) {
            Some(Some(Value::Map(m))) => SegmentDescriptor::try_from(Value::Map(m.clone()))?,
            Some(Some(_)) => {
                return Err(PayloadError::FieldType {
                    key: 5,
                    expected: "SegmentDescriptor map",
                });
            }
            Some(None) | None => return Err(PayloadError::MissingField(5)),
        };

        let sealed_packs = match fields.get(6).and_then(|f| *f) {
            Some(Value::Array(items)) => {
                let mut v = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::Map(_) => v.push(PackDescriptor::try_from(item.clone())?),
                        _ => {
                            return Err(PayloadError::FieldType {
                                key: 6,
                                expected: "array of PackDescriptor maps",
                            });
                        }
                    }
                }
                v
            }
            Some(_) => {
                return Err(PayloadError::FieldType {
                    key: 6,
                    expected: "array",
                });
            }
            None => return Err(PayloadError::MissingField(6)),
        };

        Self::new(
            field_uint(&fields, 0)?,
            field_bytes_exact::<16>(&fields, 1)?,
            RepositoryGenesisId::new(field_bytes_exact::<32>(&fields, 2)?),
            field_uint(&fields, 3)?,
            field_nullable_bytes_exact::<32>(&fields, 4)?.map(StoreManifestId::new),
            active_segment,
            sealed_packs,
            field_int(&fields, 7)?,
        )
    }
}

impl From<&StoreManifestPayload> for Value {
    fn from(p: &StoreManifestPayload) -> Self {
        let prev_value = match &p.previous_manifest_id {
            Some(id) => Value::Bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        let pack_values: Vec<Value> = p.sealed_packs.iter().map(Value::from).collect();
        Value::Map(vec![
            (Value::U64(0), Value::U64(p.format_version)),
            (Value::U64(1), Value::Bytes(p.repository_id.to_vec())),
            (
                Value::U64(2),
                Value::Bytes(p.repository_genesis_id.as_bytes().to_vec()),
            ),
            (Value::U64(3), Value::U64(p.generation)),
            (Value::U64(4), prev_value),
            (Value::U64(5), Value::from(&p.active_segment)),
            (Value::U64(6), Value::Array(pack_values)),
            (Value::U64(7), Value::I64(p.created_at_ns)),
        ])
    }
}

// ---------------------------------------------------------------------------
// Type registry (§21, record type → physical container mapping)
// ---------------------------------------------------------------------------

/// Physical container where records of a given type may be stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalContainer {
    /// Active segment only (e.g., TransactionEnd, type 11).
    Segment,
    /// Both active segment and sealed pack.
    Any,
}

/// Returns the allowed physical container for a record type code.
///
/// Returns `None` for unknown type codes (which will be resolved in F3.8).
pub fn type_allowed_container(type_code: u64) -> Option<PhysicalContainer> {
    match type_code {
        11 => Some(PhysicalContainer::Segment),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A minimal record payload map that uses unsigned integer keys
    /// (matching the pattern used by all v1 record schemas in F3.2+).
    fn make_integer_key_payload() -> Value {
        Value::Map(vec![
            (Value::U64(0), Value::U64(1)),                  // version
            (Value::U64(1), Value::Bytes(vec![0x99u8; 32])), // identifier
            (Value::U64(2), Value::U64(42)),                 // some count
        ])
    }

    fn make_test_record() -> SignedRecord<Value> {
        let payload = make_integer_key_payload();
        let record_id = RecordId::new([0x11u8; 32]);
        let signer_key_id = KeyId::new([0x22u8; 32]);
        let signature = Signature::new([0x33u8; 64]);
        SignedRecord::new(payload, record_id, signer_key_id, signature)
    }

    #[test]
    fn signed_record_encode_decode_roundtrip() {
        let limits = FormatLimits::default();
        let record = make_test_record();
        let encoded = record.encode(&limits).expect("encode");
        let decoded = SignedRecord::<Value>::decode(&encoded, &limits).expect("decode");
        assert_eq!(decoded, record);
    }

    #[test]
    fn signed_record_reencodes_identically() {
        let limits = FormatLimits::default();
        let record = make_test_record();
        let bytes_a = record.encode(&limits).expect("encode a");
        let bytes_b = record.encode(&limits).expect("encode b");
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn signed_record_decode_roundtrip_byte_stable() {
        let limits = FormatLimits::default();
        let record = make_test_record();
        let encoded = record.encode(&limits).expect("encode");
        let decoded = SignedRecord::<Value>::decode(&encoded, &limits).expect("decode");
        let reencoded = decoded.encode(&limits).expect("re-encode");
        assert_eq!(encoded, reencoded);
    }

    #[test]
    fn signed_record_unsigned_integer_payload_keys_roundtrip() {
        // Prove that a payload with unsigned integer field keys survives
        // encode–decode–re-encode identically.  This is a hard requirement
        // for F3.2+ record schemas which use fixed uint field numbers.
        let limits = FormatLimits::default();
        let payload = make_integer_key_payload();

        // Confirm the payload map uses unsigned integer keys
        match &payload {
            Value::Map(pairs) => {
                assert!(pairs.iter().all(|(k, _)| matches!(k, Value::U64(_))));
            }
            _ => panic!("payload must be a map"),
        }

        let record = SignedRecord::new(
            payload,
            RecordId::new([0x11u8; 32]),
            KeyId::new([0x22u8; 32]),
            Signature::new([0x33u8; 64]),
        );
        let encoded = record.encode(&limits).expect("encode");
        let decoded = SignedRecord::<Value>::decode(&encoded, &limits).expect("decode");

        // Verify the decoded payload still has unsigned integer keys
        match decoded.payload() {
            Value::Map(pairs) => {
                assert!(
                    pairs.iter().all(|(k, _)| matches!(k, Value::U64(_))),
                    "payload keys must still be unsigned integers after decode"
                );
                assert_eq!(pairs.len(), 3);
                assert_eq!(pairs[0], (Value::U64(0), Value::U64(1)));
                assert_eq!(pairs[1], (Value::U64(1), Value::Bytes(vec![0x99u8; 32])));
                assert_eq!(pairs[2], (Value::U64(2), Value::U64(42)));
            }
            _ => panic!("decoded payload must be a map"),
        }

        // Full equality (includes payload key type preservation)
        assert_eq!(decoded, record);
    }

    #[test]
    fn signed_record_rejects_wrong_record_id_length() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x44u8; 33])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 32])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 64])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(
            result,
            Err(SignedRecordError::WrongFieldLength {
                key: 2,
                expected: 32,
                actual: 33
            })
        );
    }

    #[test]
    fn signed_record_rejects_wrong_signer_key_id_length() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 31])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 64])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(
            result,
            Err(SignedRecordError::WrongFieldLength {
                key: 3,
                expected: 32,
                actual: 31
            })
        );
    }

    #[test]
    fn signed_record_rejects_wrong_signature_length() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 32])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 65])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(
            result,
            Err(SignedRecordError::WrongFieldLength {
                key: 4,
                expected: 64,
                actual: 65
            })
        );
    }

    #[test]
    fn signed_record_rejects_non_map_payload() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::U64(42)),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 32])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 64])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(result, Err(SignedRecordError::PayloadNotAMap));
    }

    #[test]
    fn signed_record_rejects_wrong_version() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(2)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 32])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 64])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(
            result,
            Err(SignedRecordError::UnsupportedEnvelopeVersion(2))
        );
    }

    #[test]
    fn signed_record_rejects_missing_fields() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(result, Err(SignedRecordError::NotA5FieldMap));
    }

    #[test]
    fn signed_record_rejects_empty_input() {
        let limits = FormatLimits::default();
        let result = SignedRecord::<Value>::decode(&[], &limits);
        assert!(matches!(result, Err(SignedRecordError::Decode(_))));
    }

    #[test]
    fn signed_record_payload_id_excludes_signature() {
        let limits = FormatLimits::default();
        let payload = make_integer_key_payload();
        let record_id = RecordId::new([0x11u8; 32]);
        let signer_key_id = KeyId::new([0x22u8; 32]);
        let sig_a = Signature::new([0x33u8; 64]);
        let sig_b = Signature::new([0x44u8; 64]);

        let rec_a = SignedRecord::new(payload.clone(), record_id, signer_key_id, sig_a);
        let rec_b = SignedRecord::new(payload, record_id, signer_key_id, sig_b);

        let enc_a = rec_a.encode(&limits).expect("encode a");
        let enc_b = rec_b.encode(&limits).expect("encode b");
        assert_ne!(enc_a, enc_b, "different signatures must change bytes");

        let dec_a = SignedRecord::<Value>::decode(&enc_a, &limits).unwrap();
        let dec_b = SignedRecord::<Value>::decode(&enc_b, &limits).unwrap();
        assert_eq!(
            dec_a.record_id(),
            dec_b.record_id(),
            "record_id must not depend on signature"
        );
        assert_eq!(*dec_a.record_id(), record_id);
    }

    #[test]
    fn signed_record_encode_rejects_oversized_payload() {
        // Encode a payload that exceeds the metadata limit.
        let limits = FormatLimits::default()
            .with_max_metadata_bytes(100)
            .expect("valid limit");

        let huge_key = "x".repeat(200);
        let big_payload = Value::Map(vec![(Value::U64(0), Value::Text(huge_key))]);

        let record = SignedRecord::new(
            big_payload,
            RecordId::new([0x11u8; 32]),
            KeyId::new([0x22u8; 32]),
            Signature::new([0x33u8; 64]),
        );
        let result = record.encode(&limits);
        assert!(matches!(
            result,
            Err(SignedRecordError::EnvelopeTooLarge { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // field_int direct unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn field_int_accepts_u64_zero() {
        let v = Value::U64(0);
        let fields = [Some(&v)];
        assert_eq!(field_int(&fields, 0).unwrap(), 0i64);
    }

    #[test]
    fn field_int_accepts_u64_positive() {
        let v = Value::U64(42);
        let fields = [Some(&v)];
        assert_eq!(field_int(&fields, 0).unwrap(), 42i64);
    }

    #[test]
    fn field_int_accepts_u64_at_i64_max() {
        let v = Value::U64(i64::MAX as u64);
        let fields = [Some(&v)];
        assert_eq!(field_int(&fields, 0).unwrap(), i64::MAX);
    }

    #[test]
    fn field_int_rejects_u64_above_i64_max() {
        let v = Value::U64(i64::MAX as u64 + 1);
        let fields = [Some(&v)];
        let err = field_int(&fields, 0).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn field_int_accepts_i64_negative() {
        let v = Value::I64(-1);
        let fields = [Some(&v)];
        assert_eq!(field_int(&fields, 0).unwrap(), -1i64);
    }

    #[test]
    fn field_int_rejects_non_int_type() {
        let v = Value::Text("boom".into());
        let fields = [Some(&v)];
        let err = field_int(&fields, 0).unwrap_err();
        assert!(matches!(err, PayloadError::FieldType { key: 0, .. }));
    }

    #[test]
    fn field_int_rejects_missing_field() {
        let fields: [Option<&Value>; 1] = [None];
        let err = field_int(&fields, 0).unwrap_err();
        assert_eq!(err, PayloadError::MissingField(0));
    }

    // -----------------------------------------------------------------------
    // SignedRecord::encode canonicalization tests
    // -----------------------------------------------------------------------

    #[test]
    fn encode_canonicalizes_unsorted_payload_keys() {
        let limits = FormatLimits::default();
        // Payload with keys in reverse order
        let payload = Value::Map(vec![
            (Value::U64(2), Value::U64(42)),
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes(vec![0x99u8; 32])),
        ]);
        let record = SignedRecord::new(
            payload,
            RecordId::new([0x11u8; 32]),
            KeyId::new([0x22u8; 32]),
            Signature::new([0x33u8; 64]),
        );
        let encoded = record.encode(&limits).expect("encode");
        let decoded = SignedRecord::<Value>::decode(&encoded, &limits).expect("decode");
        // After encode→decode the payload keys should be in sorted order
        match decoded.payload() {
            Value::Map(pairs) => {
                assert_eq!(pairs[0].0, Value::U64(0));
                assert_eq!(pairs[1].0, Value::U64(1));
                assert_eq!(pairs[2].0, Value::U64(2));
            }
            _ => panic!("payload must be a map"),
        }
    }

    #[test]
    fn encode_rejects_duplicate_payload_keys() {
        let limits = FormatLimits::default();
        let payload = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(0), Value::U64(99)), // duplicate key
        ]);
        let record = SignedRecord::new(
            payload,
            RecordId::new([0x11u8; 32]),
            KeyId::new([0x22u8; 32]),
            Signature::new([0x33u8; 64]),
        );
        let result = record.encode(&limits);
        assert_eq!(result, Err(SignedRecordError::DuplicatePayloadKey));
    }

    // -----------------------------------------------------------------------
    // CBOR byte roundtrip helper
    // -----------------------------------------------------------------------

    /// Roundtrip a typed payload through Value → CBOR bytes → CanonicalDecoder → Value → TryFrom.
    /// This catches `field_int` rejecting `Value::U64` produced by CBOR decode of a non-negative i64.
    fn cbor_roundtrip<T>(make: impl Fn() -> T) -> T
    where
        T: Clone + PartialEq + std::fmt::Debug,
        for<'a> Value: From<&'a T>,
        T: TryFrom<Value, Error = PayloadError>,
    {
        let original = make();
        let value: Value = Value::from(&original);
        let cbor = value.reencode();
        let decoded_value = CanonicalDecoder::from_limits(&cbor, &FormatLimits::default())
            .decode()
            .expect("CBOR decode");
        let typed = T::try_from(decoded_value).expect("typed decode");
        assert_eq!(typed, original);
        typed
    }

    // -----------------------------------------------------------------------
    // KeySlot CBOR roundtrip (covers field_int via created_at_ns)
    // -----------------------------------------------------------------------

    #[test]
    fn key_slot_cbor_roundtrip_created_at_ns_zero() {
        cbor_roundtrip(|| {
            KeySlot::new(
                [0x01u8; 16],
                1,
                "test".into(),
                Some(make_password_kdf()),
                None,
                None,
                1,
                [0x10u8; 24],
                vec![0xAAu8; 48],
                0,
            )
            .unwrap()
        });
    }

    #[test]
    fn key_slot_cbor_roundtrip_created_at_ns_positive() {
        cbor_roundtrip(|| {
            KeySlot::new(
                [0x01u8; 16],
                1,
                "positive".into(),
                Some(make_password_kdf()),
                None,
                None,
                1,
                [0x10u8; 24],
                vec![0xAAu8; 48],
                42,
            )
            .unwrap()
        });
    }

    #[test]
    fn key_slot_cbor_roundtrip_created_at_ns_negative() {
        cbor_roundtrip(|| {
            KeySlot::new(
                [0x01u8; 16],
                1,
                "negative".into(),
                Some(make_password_kdf()),
                None,
                None,
                1,
                [0x10u8; 24],
                vec![0xAAu8; 48],
                -1,
            )
            .unwrap()
        });
    }

    // -----------------------------------------------------------------------
    // PolicyRecordPayload CBOR roundtrip (covers field_int via created_at_ns)
    // -----------------------------------------------------------------------

    fn genesis_key_id() -> [u8; 32] {
        compute_key_id(1, &[0x04u8; 32])
    }

    fn make_genesis_with_ns(ns: i64) -> RepositoryGenesisPayload {
        RepositoryGenesisPayload::new(
            1,
            [0x01u8; 16],
            [0x02u8; 16],
            genesis_key_id(),
            [0x04u8; 32],
            [0x05u8; 32],
            [0x06u8; 32],
            ns,
        )
        .unwrap()
    }

    #[test]
    fn genesis_cbor_roundtrip_ns_zero() {
        cbor_roundtrip(|| make_genesis_with_ns(0));
    }

    #[test]
    fn genesis_cbor_roundtrip_ns_positive() {
        cbor_roundtrip(|| make_genesis_with_ns(42));
    }

    #[test]
    fn genesis_cbor_roundtrip_ns_negative() {
        cbor_roundtrip(|| make_genesis_with_ns(-1));
    }

    // -----------------------------------------------------------------------
    // PolicyRecordPayload CBOR roundtrip (covers field_int via created_at_ns)
    // -----------------------------------------------------------------------

    fn make_policy_with_ns(ns: i64) -> PolicyRecordPayload {
        let k1_key_id = compute_key_id(1, &[0x20u8; 32]);
        let k2_key_id = compute_key_id(2, &[0x21u8; 32]);
        PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            Some([0xAAu8; 32]),
            3,
            vec![
                PublicKeyEntry::new(k1_key_id, 1, [0x20u8; 32], "key1".into()).unwrap(),
                PublicKeyEntry::new(k2_key_id, 2, [0x21u8; 32], "key2".into()).unwrap(),
            ],
            vec![[0xA0u8; 32], [0xA1u8; 32]],
            vec![[0xB0u8; 32], [0xB1u8; 32]],
            vec![
                RefPermissionEntry::new(
                    RefPattern::new("refs/heads/a").unwrap(),
                    vec![[0xC0u8; 32]],
                )
                .unwrap(),
                RefPermissionEntry::new(
                    RefPattern::new("refs/heads/b").unwrap(),
                    vec![[0xC1u8; 32]],
                )
                .unwrap(),
            ],
            vec![[0xD0u8; 32]],
            vec![[0xE0u8; 32]],
            ns,
            [0xFFu8; 32],
        )
        .unwrap()
    }

    #[test]
    fn policy_cbor_roundtrip_ns_zero() {
        cbor_roundtrip(|| make_policy_with_ns(0));
    }

    #[test]
    fn policy_cbor_roundtrip_ns_positive() {
        cbor_roundtrip(|| make_policy_with_ns(42));
    }

    #[test]
    fn policy_cbor_roundtrip_ns_negative() {
        cbor_roundtrip(|| make_policy_with_ns(-1));
    }

    // -----------------------------------------------------------------------
    // KeyringRecordPayload CBOR roundtrip (covers field_int via created_at_ns)
    // -----------------------------------------------------------------------

    fn make_keyring_with_ns(ns: i64) -> KeyringRecordPayload {
        KeyringRecordPayload::new(
            1,
            [0x01u8; 16],
            Some([0xAAu8; 32]),
            5,
            vec![make_key_slot_password()],
            vec![make_wrapped_dek()],
            vec![1, 3],
            ns,
            [0xFFu8; 32],
        )
        .unwrap()
    }

    #[test]
    fn keyring_cbor_roundtrip_ns_zero() {
        cbor_roundtrip(|| make_keyring_with_ns(0));
    }

    #[test]
    fn keyring_cbor_roundtrip_ns_positive() {
        cbor_roundtrip(|| make_keyring_with_ns(42));
    }

    #[test]
    fn keyring_cbor_roundtrip_ns_negative() {
        cbor_roundtrip(|| make_keyring_with_ns(-1));
    }

    fn compute_key_id(algorithm: u8, public_key: &[u8; 32]) -> [u8; 32] {
        let mut payload = Vec::with_capacity(33);
        payload.push(algorithm);
        payload.extend_from_slice(public_key);
        domain_hash("EternalCore:KeyFingerprint:v1", &payload).unwrap()
    }

    // -----------------------------------------------------------------------
    // PasswordKdfDescriptor tests
    // -----------------------------------------------------------------------

    fn make_password_kdf() -> PasswordKdfDescriptor {
        PasswordKdfDescriptor::new(1, 0x13, FASTCDC_V1_GEAR_TABLE_ID.to_vec(), 65536, 3, 1).unwrap()
    }

    #[test]
    fn password_kdf_roundtrip() {
        let kdf = make_password_kdf();
        let decoded = PasswordKdfDescriptor::try_from(Value::from(&kdf)).unwrap();
        assert_eq!(decoded, kdf);
    }

    #[test]
    fn password_kdf_field_numbers() {
        let pairs = match Value::from(&make_password_kdf()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 6);
        assert_eq!(pairs[0].0, Value::U64(0));
        assert_eq!(pairs[1].0, Value::U64(1));
        assert_eq!(pairs[2].0, Value::U64(2));
        assert_eq!(pairs[3].0, Value::U64(3));
        assert_eq!(pairs[4].0, Value::U64(4));
        assert_eq!(pairs[5].0, Value::U64(5));
    }

    #[test]
    fn password_kdf_rejects_bad_algorithm() {
        let err =
            PasswordKdfDescriptor::new(2, 0x13, FASTCDC_V1_GEAR_TABLE_ID.to_vec(), 65536, 3, 1)
                .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn password_kdf_rejects_bad_version() {
        let err = PasswordKdfDescriptor::new(1, 10, FASTCDC_V1_GEAR_TABLE_ID.to_vec(), 65536, 3, 1)
            .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn password_kdf_rejects_short_salt() {
        let err = PasswordKdfDescriptor::new(1, 0x13, vec![0xABu8; 15], 65536, 3, 1).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 2, .. }));
    }

    #[test]
    fn password_kdf_rejects_low_memory() {
        let err =
            PasswordKdfDescriptor::new(1, 0x13, FASTCDC_V1_GEAR_TABLE_ID.to_vec(), 65535, 3, 1)
                .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn password_kdf_rejects_zero_iterations() {
        let err =
            PasswordKdfDescriptor::new(1, 0x13, FASTCDC_V1_GEAR_TABLE_ID.to_vec(), 65536, 0, 1)
                .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn password_kdf_rejects_bad_parallelism() {
        let err =
            PasswordKdfDescriptor::new(1, 0x13, FASTCDC_V1_GEAR_TABLE_ID.to_vec(), 65536, 3, 0)
                .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 5, .. }));
    }

    #[test]
    fn password_kdf_rejects_not_a_map() {
        let err = PasswordKdfDescriptor::try_from(Value::U64(42)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn password_kdf_rejects_wrong_field_type() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Text("x".into())),
            (Value::U64(1), Value::U64(0x13)),
            (
                Value::U64(2),
                Value::Bytes(FASTCDC_V1_GEAR_TABLE_ID.to_vec()),
            ),
            (Value::U64(3), Value::U64(65536)),
            (Value::U64(4), Value::U64(3)),
            (Value::U64(5), Value::U64(1)),
        ]);
        let err = PasswordKdfDescriptor::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::FieldType { key: 0, .. }));
    }

    #[test]
    fn password_kdf_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::U64(0x13)),
            (
                Value::U64(2),
                Value::Bytes(FASTCDC_V1_GEAR_TABLE_ID.to_vec()),
            ),
            (Value::U64(3), Value::U64(65536)),
            (Value::U64(4), Value::U64(3)),
            (Value::U64(5), Value::U64(1)),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = PasswordKdfDescriptor::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // PublicKeyEntry tests
    // -----------------------------------------------------------------------

    fn make_public_key_entry() -> PublicKeyEntry {
        let key_id = compute_key_id(1, &[0xBBu8; 32]);
        PublicKeyEntry::new(key_id, 1, [0xBBu8; 32], "test key".into()).unwrap()
    }

    #[test]
    fn public_key_entry_roundtrip() {
        let entry = make_public_key_entry();
        let decoded = PublicKeyEntry::try_from(Value::from(&entry)).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn public_key_entry_field_numbers() {
        let pairs = match Value::from(&make_public_key_entry()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0].0, Value::U64(0)); // key_id
        assert_eq!(pairs[1].0, Value::U64(1)); // algorithm
        assert_eq!(pairs[2].0, Value::U64(2)); // public_key
        assert_eq!(pairs[3].0, Value::U64(3)); // label
    }

    #[test]
    fn public_key_entry_rejects_bad_algorithm() {
        let err = PublicKeyEntry::new([0xAAu8; 32], 3, [0xBBu8; 32], "test".into()).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn public_key_entry_rejects_long_label() {
        let err = PublicKeyEntry::new([0xAAu8; 32], 1, [0xBBu8; 32], "x".repeat(129)).unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 3, .. }));
    }

    #[test]
    fn public_key_entry_rejects_not_a_map() {
        let err = PublicKeyEntry::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn public_key_entry_rejects_wrong_key_id_length() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Bytes(vec![0xAAu8; 31])),
            (Value::U64(1), Value::U64(1)),
            (Value::U64(2), Value::Bytes(vec![0xBBu8; 32])),
            (Value::U64(3), Value::Text("test".into())),
        ]);
        let err = PublicKeyEntry::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::WrongLength { key: 0, .. }));
    }

    #[test]
    fn public_key_entry_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Bytes(vec![0xAAu8; 32])),
            (Value::U64(1), Value::U64(1)),
            (Value::U64(2), Value::Bytes(vec![0xBBu8; 32])),
            (Value::U64(3), Value::Text("test".into())),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = PublicKeyEntry::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn public_key_entry_rejects_key_id_mismatch() {
        let err = PublicKeyEntry::new([0xAAu8; 32], 1, [0xBBu8; 32], "test".into()).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    // -----------------------------------------------------------------------
    // RefPermissionEntry tests
    // -----------------------------------------------------------------------

    fn make_ref_permission_entry() -> RefPermissionEntry {
        RefPermissionEntry::new(
            RefPattern::new("refs/heads/main").unwrap(),
            vec![[0xCCu8; 32], [0xDDu8; 32]],
        )
        .unwrap()
    }

    #[test]
    fn ref_permission_entry_roundtrip() {
        let entry = make_ref_permission_entry();
        let decoded = RefPermissionEntry::try_from(Value::from(&entry)).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn ref_permission_entry_field_numbers() {
        let pairs = match Value::from(&make_ref_permission_entry()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, Value::U64(0)); // pattern
        assert_eq!(pairs[1].0, Value::U64(1)); // writers
    }

    #[test]
    fn ref_permission_entry_rejects_empty_writers() {
        let err = RefPermissionEntry::new(RefPattern::new("refs/heads/main").unwrap(), vec![])
            .unwrap_err();
        assert!(matches!(err, PayloadError::EmptyArray { key: 1 }));
    }

    #[test]
    fn ref_permission_entry_rejects_unsorted_writers() {
        let err = RefPermissionEntry::new(
            RefPattern::new("refs/heads/main").unwrap(),
            vec![[0xDDu8; 32], [0xCCu8; 32]],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 1 }));
    }

    #[test]
    fn ref_permission_entry_rejects_duplicate_writers() {
        let err = RefPermissionEntry::new(
            RefPattern::new("refs/heads/main").unwrap(),
            vec![[0xCCu8; 32], [0xCCu8; 32]],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 1 }));
    }

    #[test]
    fn ref_permission_entry_rejects_wrong_writer_length() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Text("refs/heads/main".into())),
            (
                Value::U64(1),
                Value::Array(vec![Value::Bytes(vec![0xCCu8; 31])]),
            ),
        ]);
        let err = RefPermissionEntry::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::WrongLength { key: 1, .. }));
    }

    #[test]
    fn ref_permission_entry_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Text("refs/heads/main".into())),
            (
                Value::U64(1),
                Value::Array(vec![Value::Bytes(vec![0xCCu8; 32])]),
            ),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = RefPermissionEntry::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // RepositoryGenesisPayload tests
    // -----------------------------------------------------------------------

    fn make_genesis_payload() -> RepositoryGenesisPayload {
        let creator_key_id = compute_key_id(1, &[0x04u8; 32]);
        RepositoryGenesisPayload::new(
            1,
            [0x01u8; 16],
            [0x02u8; 16],
            creator_key_id,
            [0x04u8; 32],
            [0x05u8; 32],
            [0x06u8; 32],
            1_000_000,
        )
        .unwrap()
    }

    #[test]
    fn genesis_roundtrip() {
        let payload = make_genesis_payload();
        let decoded = RepositoryGenesisPayload::try_from(Value::from(&payload)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn genesis_field_numbers() {
        let pairs = match Value::from(&make_genesis_payload()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 8);
        assert_eq!(pairs[0].0, Value::U64(0)); // format_version
        assert_eq!(pairs[1].0, Value::U64(1)); // repository_id
        assert_eq!(pairs[2].0, Value::U64(2)); // federation_id
        assert_eq!(pairs[3].0, Value::U64(3)); // creator_key_id
        assert_eq!(pairs[4].0, Value::U64(4)); // creator_public_key
        assert_eq!(pairs[5].0, Value::U64(5)); // initial_policy_id
        assert_eq!(pairs[6].0, Value::U64(6)); // initial_keyring_id
        assert_eq!(pairs[7].0, Value::U64(7)); // created_at_ns
    }

    #[test]
    fn genesis_rejects_bad_format_version() {
        let err = RepositoryGenesisPayload::new(
            2,
            [0x01u8; 16],
            [0x02u8; 16],
            [0x03u8; 32],
            [0x04u8; 32],
            [0x05u8; 32],
            [0x06u8; 32],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn genesis_rejects_not_a_map() {
        let err = RepositoryGenesisPayload::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn genesis_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 16].to_vec())),
            (Value::U64(2), Value::Bytes([0x02u8; 16].to_vec())),
            (Value::U64(3), Value::Bytes([0x03u8; 32].to_vec())),
            (Value::U64(4), Value::Bytes([0x04u8; 32].to_vec())),
            (Value::U64(5), Value::Bytes([0x05u8; 32].to_vec())),
            (Value::U64(6), Value::Bytes([0x06u8; 32].to_vec())),
            (Value::U64(7), Value::I64(1_000_000)),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = RepositoryGenesisPayload::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn genesis_rejects_creator_key_id_mismatch() {
        let err = RepositoryGenesisPayload::new(
            1,
            [0x01u8; 16],
            [0x02u8; 16],
            [0xAAu8; 32],
            [0x04u8; 32],
            [0x05u8; 32],
            [0x06u8; 32],
            1_000_000,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    // -----------------------------------------------------------------------
    // PolicyRecordPayload tests
    // -----------------------------------------------------------------------

    fn make_policy_payload() -> PolicyRecordPayload {
        let k1_key_id = compute_key_id(1, &[0x20u8; 32]);
        let k2_key_id = compute_key_id(2, &[0x21u8; 32]);
        PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            Some([0xAAu8; 32]),
            3,
            vec![
                PublicKeyEntry::new(k1_key_id, 1, [0x20u8; 32], "key1".into()).unwrap(),
                PublicKeyEntry::new(k2_key_id, 2, [0x21u8; 32], "key2".into()).unwrap(),
            ],
            vec![[0xA0u8; 32], [0xA1u8; 32]],
            vec![[0xB0u8; 32], [0xB1u8; 32]],
            vec![
                RefPermissionEntry::new(
                    RefPattern::new("refs/heads/a").unwrap(),
                    vec![[0xC0u8; 32]],
                )
                .unwrap(),
                RefPermissionEntry::new(
                    RefPattern::new("refs/heads/b").unwrap(),
                    vec![[0xC1u8; 32]],
                )
                .unwrap(),
            ],
            vec![[0xD0u8; 32]],
            vec![[0xE0u8; 32]],
            2_000_000,
            [0xFFu8; 32],
        )
        .unwrap()
    }

    #[test]
    fn policy_roundtrip() {
        let payload = make_policy_payload();
        let decoded = PolicyRecordPayload::try_from(Value::from(&payload)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn policy_field_numbers() {
        let pairs = match Value::from(&make_policy_payload()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 12);
        for (i, pair) in pairs.iter().enumerate() {
            assert_eq!(pair.0, Value::U64(i as u64), "field {i} key mismatch");
        }
    }

    #[test]
    fn policy_rejects_bad_format_version() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(2)),
            (Value::U64(1), Value::Bytes([0x01u8; 16].to_vec())),
            (Value::U64(2), Value::Null),
            (Value::U64(3), Value::U64(1)),
            (Value::U64(4), Value::Array(vec![])),
            (Value::U64(5), Value::Array(vec![])),
            (Value::U64(6), Value::Array(vec![])),
            (Value::U64(7), Value::Array(vec![])),
            (Value::U64(8), Value::Array(vec![])),
            (Value::U64(9), Value::Array(vec![])),
            (Value::U64(10), Value::I64(0)),
            (Value::U64(11), Value::Bytes([0xFFu8; 32].to_vec())),
        ]);
        let err = PolicyRecordPayload::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn policy_rejects_zero_sequence() {
        let err = PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            0,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn policy_rejects_unsorted_introduced_keys() {
        // Reverse the correct order from make_policy_payload for unsorted test
        let k1_key_id = compute_key_id(1, &[0x20u8; 32]);
        let k2_key_id = compute_key_id(1, &[0x21u8; 32]);
        let err = PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            1,
            vec![
                PublicKeyEntry::new(k1_key_id, 1, [0x20u8; 32], "b".into()).unwrap(),
                PublicKeyEntry::new(k2_key_id, 1, [0x21u8; 32], "a".into()).unwrap(),
            ],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 4 }));
    }

    #[test]
    fn policy_rejects_unsorted_administrators() {
        let err = PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            1,
            vec![],
            vec![[0xA1u8; 32], [0xA0u8; 32]],
            vec![],
            vec![],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 5 }));
    }

    #[test]
    fn policy_rejects_unsorted_writers() {
        let err = PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            1,
            vec![],
            vec![],
            vec![[0xB1u8; 32], [0xB0u8; 32]],
            vec![],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 6 }));
    }

    #[test]
    fn policy_rejects_unsorted_permissions() {
        let err = PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            1,
            vec![],
            vec![],
            vec![],
            vec![
                RefPermissionEntry::new(
                    RefPattern::new("refs/heads/z").unwrap(),
                    vec![[0xC0u8; 32]],
                )
                .unwrap(),
                RefPermissionEntry::new(
                    RefPattern::new("refs/heads/a").unwrap(),
                    vec![[0xC1u8; 32]],
                )
                .unwrap(),
            ],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 7 }));
    }

    #[test]
    fn policy_rejects_unsorted_tag_creators() {
        let err = PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            1,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![[0xD1u8; 32], [0xD0u8; 32]],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 8 }));
    }

    #[test]
    fn policy_rejects_unsorted_revoked_keys() {
        let err = PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            1,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![[0xE1u8; 32], [0xE0u8; 32]],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 9 }));
    }

    #[test]
    fn policy_accepts_null_previous_policy_id() {
        let payload = PolicyRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            1,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap();
        let decoded = PolicyRecordPayload::try_from(Value::from(&payload)).unwrap();
        assert!(decoded.previous_policy_id.is_none());
    }

    #[test]
    fn policy_rejects_not_a_map() {
        let err = PolicyRecordPayload::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn policy_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 16].to_vec())),
            (Value::U64(2), Value::Null),
            (Value::U64(3), Value::U64(1)),
            (Value::U64(4), Value::Array(vec![])),
            (Value::U64(5), Value::Array(vec![])),
            (Value::U64(6), Value::Array(vec![])),
            (Value::U64(7), Value::Array(vec![])),
            (Value::U64(8), Value::Array(vec![])),
            (Value::U64(9), Value::Array(vec![])),
            (Value::U64(10), Value::I64(0)),
            (Value::U64(11), Value::Bytes([0xFFu8; 32].to_vec())),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = PolicyRecordPayload::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // KeySlot tests
    // -----------------------------------------------------------------------

    fn make_key_slot_password() -> KeySlot {
        KeySlot::new(
            [0x01u8; 16],
            1,
            "password slot".into(),
            Some(make_password_kdf()),
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            1_000_000,
        )
        .unwrap()
    }

    fn make_key_slot_recipient() -> KeySlot {
        KeySlot::new(
            [0x02u8; 16],
            2,
            "recipient slot".into(),
            None,
            Some([0x20u8; 32]),
            Some([0x30u8; 32]),
            1,
            [0x11u8; 24],
            vec![0xBBu8; 48],
            2_000_000,
        )
        .unwrap()
    }

    #[test]
    fn key_slot_password_roundtrip() {
        let slot = make_key_slot_password();
        let decoded = KeySlot::try_from(Value::from(&slot)).unwrap();
        assert_eq!(decoded, slot);
    }

    #[test]
    fn key_slot_recipient_roundtrip() {
        let slot = make_key_slot_recipient();
        let decoded = KeySlot::try_from(Value::from(&slot)).unwrap();
        assert_eq!(decoded, slot);
    }

    #[test]
    fn key_slot_field_numbers() {
        let pairs = match Value::from(&make_key_slot_password()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 10);
        for (i, pair) in pairs.iter().enumerate() {
            assert_eq!(pair.0, Value::U64(i as u64), "field {i} key mismatch");
        }
    }

    #[test]
    fn key_slot_rejects_bad_slot_kind() {
        let err = KeySlot::new(
            [0x01u8; 16],
            0,
            "slot".into(),
            None,
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn key_slot_rejects_empty_label() {
        let err = KeySlot::new(
            [0x01u8; 16],
            1,
            "".into(),
            Some(make_password_kdf()),
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn key_slot_rejects_password_without_kdf() {
        let err = KeySlot::new(
            [0x01u8; 16],
            1,
            "slot".into(),
            None,
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::MissingField(3)));
    }

    #[test]
    fn key_slot_rejects_password_with_recipient_key() {
        let err = KeySlot::new(
            [0x01u8; 16],
            1,
            "slot".into(),
            Some(make_password_kdf()),
            Some([0x20u8; 32]),
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn key_slot_rejects_recipient_without_key() {
        let err = KeySlot::new(
            [0x01u8; 16],
            2,
            "slot".into(),
            None,
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::MissingField(4)));
    }

    #[test]
    fn key_slot_rejects_recipient_without_ephemeral() {
        let err = KeySlot::new(
            [0x01u8; 16],
            2,
            "slot".into(),
            None,
            Some([0x20u8; 32]),
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::MissingField(5)));
    }

    #[test]
    fn key_slot_rejects_recipient_with_kdf() {
        let err = KeySlot::new(
            [0x01u8; 16],
            2,
            "slot".into(),
            Some(make_password_kdf()),
            Some([0x20u8; 32]),
            Some([0x30u8; 32]),
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn key_slot_rejects_bad_wrap_algorithm() {
        let err = KeySlot::new(
            [0x01u8; 16],
            1,
            "slot".into(),
            Some(make_password_kdf()),
            None,
            None,
            2,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 6, .. }));
    }

    #[test]
    fn key_slot_rejects_not_a_map() {
        let err = KeySlot::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn key_slot_rejects_unknown_field() {
        let kdf = make_password_kdf();
        let value = Value::Map(vec![
            (Value::U64(0), Value::Bytes([0x01u8; 16].to_vec())),
            (Value::U64(1), Value::U64(1)),
            (Value::U64(2), Value::Text("test".into())),
            (Value::U64(3), Value::from(&kdf)),
            (Value::U64(4), Value::Null),
            (Value::U64(5), Value::Null),
            (Value::U64(6), Value::U64(1)),
            (Value::U64(7), Value::Bytes([0x10u8; 24].to_vec())),
            (Value::U64(8), Value::Bytes(vec![0xAAu8; 48])),
            (Value::U64(9), Value::I64(0)),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = KeySlot::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn key_slot_rejects_control_char_in_label() {
        let err = KeySlot::new(
            [0x01u8; 16],
            1,
            "test\x00label".into(),
            Some(make_password_kdf()),
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 48],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn key_slot_rejects_missing_password_kdf_key() {
        // Key 3 (password_kdf) is missing from the map entirely
        let value = Value::Map(vec![
            (Value::U64(0), Value::Bytes([0x01u8; 16].to_vec())),
            (Value::U64(1), Value::U64(1)),
            (Value::U64(2), Value::Text("test".into())),
            // key 3 omitted
            (Value::U64(4), Value::Null),
            (Value::U64(5), Value::Null),
            (Value::U64(6), Value::U64(1)),
            (Value::U64(7), Value::Bytes([0x10u8; 24].to_vec())),
            (Value::U64(8), Value::Bytes(vec![0xAAu8; 48])),
            (Value::U64(9), Value::I64(0)),
        ]);
        let err = KeySlot::try_from(value).unwrap_err();
        assert_eq!(err, PayloadError::MissingField(3));
    }

    #[test]
    fn key_slot_rejects_short_wrapped_secret() {
        let err = KeySlot::new(
            [0x01u8; 16],
            1,
            "test".into(),
            Some(make_password_kdf()),
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 0],
            0,
        )
        .unwrap_err();
        assert_eq!(
            err,
            PayloadError::WrongLength {
                key: 8,
                expected: 48,
                actual: 0
            }
        );
    }

    #[test]
    fn key_slot_rejects_too_short_wrapped_secret() {
        let err = KeySlot::new(
            [0x01u8; 16],
            1,
            "test".into(),
            Some(make_password_kdf()),
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 47],
            0,
        )
        .unwrap_err();
        assert_eq!(
            err,
            PayloadError::WrongLength {
                key: 8,
                expected: 48,
                actual: 47
            }
        );
    }

    #[test]
    fn key_slot_rejects_too_long_wrapped_secret() {
        let err = KeySlot::new(
            [0x01u8; 16],
            1,
            "test".into(),
            Some(make_password_kdf()),
            None,
            None,
            1,
            [0x10u8; 24],
            vec![0xAAu8; 49],
            0,
        )
        .unwrap_err();
        assert_eq!(
            err,
            PayloadError::WrongLength {
                key: 8,
                expected: 48,
                actual: 49
            }
        );
    }

    // -----------------------------------------------------------------------
    // WrappedDek tests
    // -----------------------------------------------------------------------

    fn make_wrapped_dek() -> WrappedDek {
        WrappedDek::new(
            1,
            [0x01u8; 16],
            vec![make_key_slot_password(), make_key_slot_recipient()],
        )
        .unwrap()
    }

    #[test]
    fn wrapped_dek_roundtrip() {
        let wd = make_wrapped_dek();
        let decoded = WrappedDek::try_from(Value::from(&wd)).unwrap();
        assert_eq!(decoded, wd);
    }

    #[test]
    fn wrapped_dek_field_numbers() {
        let pairs = match Value::from(&make_wrapped_dek()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].0, Value::U64(0)); // key_epoch
        assert_eq!(pairs[1].0, Value::U64(1)); // dek_id
        assert_eq!(pairs[2].0, Value::U64(2)); // slots
    }

    #[test]
    fn wrapped_dek_rejects_zero_epoch() {
        let err = WrappedDek::new(0, [0x01u8; 16], vec![make_key_slot_password()]).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn wrapped_dek_rejects_empty_slots() {
        let err = WrappedDek::new(1, [0x01u8; 16], vec![]).unwrap_err();
        assert!(matches!(err, PayloadError::EmptyArray { key: 2 }));
    }

    #[test]
    fn wrapped_dek_rejects_unsorted_slots() {
        let slot_b = make_key_slot_recipient(); // slot_id = [0x02; 16]
        let slot_a = make_key_slot_password(); // slot_id = [0x01; 16]
        let err = WrappedDek::new(1, [0x01u8; 16], vec![slot_b, slot_a]).unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 2 }));
    }

    #[test]
    fn wrapped_dek_rejects_not_a_map() {
        let err = WrappedDek::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn wrapped_dek_rejects_unknown_field() {
        let slot = make_key_slot_password();
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 16].to_vec())),
            (Value::U64(2), Value::Array(vec![Value::from(&slot)])),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = WrappedDek::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // KeyringRecordPayload tests
    // -----------------------------------------------------------------------

    fn make_keyring_payload() -> KeyringRecordPayload {
        KeyringRecordPayload::new(
            1,
            [0x01u8; 16],
            Some([0xAAu8; 32]),
            5,
            vec![make_key_slot_password()],
            vec![make_wrapped_dek()],
            vec![1, 3],
            3_000_000,
            [0xFFu8; 32],
        )
        .unwrap()
    }

    #[test]
    fn keyring_roundtrip() {
        let payload = make_keyring_payload();
        let decoded = KeyringRecordPayload::try_from(Value::from(&payload)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn keyring_field_numbers() {
        let pairs = match Value::from(&make_keyring_payload()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 9);
        for (i, pair) in pairs.iter().enumerate() {
            assert_eq!(pair.0, Value::U64(i as u64), "field {i} key mismatch");
        }
    }

    #[test]
    fn keyring_rejects_bad_format_version() {
        let err = KeyringRecordPayload::new(
            2,
            [0x01u8; 16],
            None,
            0,
            vec![],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn keyring_rejects_unsorted_content_id_key_slots() {
        let slot_a = make_key_slot_recipient(); // slot_id = [0x02; 16]
        let slot_b = make_key_slot_password(); // slot_id = [0x01; 16]
        let err = KeyringRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            0,
            vec![slot_a, slot_b],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 4 }));
    }

    #[test]
    fn keyring_rejects_unsorted_dek_slots() {
        let dek_1 = WrappedDek::new(2, [0x01u8; 16], vec![make_key_slot_password()]).unwrap();
        let dek_2 = WrappedDek::new(1, [0x02u8; 16], vec![make_key_slot_recipient()]).unwrap();
        let err = KeyringRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            0,
            vec![],
            vec![dek_1, dek_2],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 5 }));
    }

    #[test]
    fn keyring_rejects_unsorted_retired_epochs() {
        let err = KeyringRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            0,
            vec![],
            vec![],
            vec![3, 1],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 6 }));
    }

    #[test]
    fn keyring_rejects_duplicate_retired_epochs() {
        let err = KeyringRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            0,
            vec![],
            vec![],
            vec![1, 1],
            0,
            [0xFFu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 6 }));
    }

    #[test]
    fn keyring_accepts_null_previous_keyring_id() {
        let payload = KeyringRecordPayload::new(
            1,
            [0x01u8; 16],
            None,
            0,
            vec![],
            vec![],
            vec![],
            0,
            [0xFFu8; 32],
        )
        .unwrap();
        let decoded = KeyringRecordPayload::try_from(Value::from(&payload)).unwrap();
        assert!(decoded.previous_keyring_id().is_none());
    }

    #[test]
    fn keyring_rejects_not_a_map() {
        let err = KeyringRecordPayload::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn keyring_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 16].to_vec())),
            (Value::U64(2), Value::Null),
            (Value::U64(3), Value::U64(1)),
            (Value::U64(4), Value::Array(vec![])),
            (Value::U64(5), Value::Array(vec![])),
            (Value::U64(6), Value::Array(vec![])),
            (Value::U64(7), Value::I64(0)),
            (Value::U64(8), Value::Bytes([0xFFu8; 32].to_vec())),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = KeyringRecordPayload::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // CodecDescriptor tests
    // -----------------------------------------------------------------------

    fn make_codec_none() -> CodecDescriptor {
        CodecDescriptor::new(0, None, None).unwrap()
    }

    fn make_codec_zstd() -> CodecDescriptor {
        CodecDescriptor::new(1, Some(3), Some(1)).unwrap()
    }

    #[test]
    fn codec_descriptor_none_roundtrip() {
        let c = make_codec_none();
        let decoded = CodecDescriptor::try_from(Value::from(&c)).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn codec_descriptor_zstd_roundtrip() {
        let c = make_codec_zstd();
        let decoded = CodecDescriptor::try_from(Value::from(&c)).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn codec_descriptor_rejects_unknown_algorithm() {
        let err = CodecDescriptor::new(99, None, None).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn codec_descriptor_rejects_level_for_none() {
        let err = CodecDescriptor::new(0, Some(3), None).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn codec_descriptor_rejects_bad_level() {
        let err = CodecDescriptor::new(1, Some(99), Some(1)).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn codec_descriptor_rejects_bad_profile() {
        let err = CodecDescriptor::new(1, Some(3), Some(99)).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 2, .. }));
    }

    #[test]
    fn codec_descriptor_rejects_not_a_map() {
        let err = CodecDescriptor::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn codec_descriptor_field_numbers_none() {
        let pairs = match Value::from(&make_codec_none()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, Value::U64(0));
    }

    #[test]
    fn codec_descriptor_field_numbers_zstd() {
        let pairs = match Value::from(&make_codec_zstd()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].0, Value::U64(0));
        assert_eq!(pairs[1].0, Value::U64(1));
        assert_eq!(pairs[2].0, Value::U64(2));
    }

    #[test]
    fn codec_descriptor_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(0)),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = CodecDescriptor::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // EncryptionDescriptor tests
    // -----------------------------------------------------------------------

    fn make_encryption() -> EncryptionDescriptor {
        EncryptionDescriptor::new(1, 7, [0x10u8; 24], 1).unwrap()
    }

    #[test]
    fn encryption_descriptor_roundtrip() {
        let e = make_encryption();
        let decoded = EncryptionDescriptor::try_from(Value::from(&e)).unwrap();
        assert_eq!(decoded, e);
    }

    #[test]
    fn encryption_descriptor_rejects_unknown_algorithm() {
        let err = EncryptionDescriptor::new(99, 7, [0x10u8; 24], 1).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn encryption_descriptor_rejects_zero_key_epoch() {
        let err = EncryptionDescriptor::new(1, 0, [0x10u8; 24], 1).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn encryption_descriptor_rejects_bad_aad_profile() {
        let err = EncryptionDescriptor::new(1, 7, [0x10u8; 24], 99).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn encryption_descriptor_field_numbers() {
        let pairs = match Value::from(&make_encryption()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0].0, Value::U64(0));
        assert_eq!(pairs[1].0, Value::U64(1));
        assert_eq!(pairs[2].0, Value::U64(2));
        assert_eq!(pairs[3].0, Value::U64(3));
    }

    #[test]
    fn encryption_descriptor_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::U64(7)),
            (Value::U64(2), Value::Bytes([0x10u8; 24].to_vec())),
            (Value::U64(3), Value::U64(1)),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = EncryptionDescriptor::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // ChunkingDescriptor tests
    // -----------------------------------------------------------------------

    fn make_chunking_v1() -> ChunkingDescriptor {
        ChunkingDescriptor::new_v1()
    }

    #[test]
    fn chunking_descriptor_roundtrip() {
        let c = make_chunking_v1();
        let decoded = ChunkingDescriptor::try_from(Value::from(&c)).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn chunking_descriptor_new_v1_matches_defaults() {
        let c = make_chunking_v1();
        assert_eq!(c.algorithm(), 1);
        assert_eq!(c.version(), 1);
        assert_eq!(c.minimum_size(), 1_048_576);
        assert_eq!(c.average_size(), 4_194_304);
        assert_eq!(c.maximum_size(), 8_388_608);
        assert_eq!(c.normalization(), 2);
    }

    #[test]
    fn chunking_descriptor_rejects_unknown_algorithm() {
        let err = ChunkingDescriptor::new(
            99,
            1,
            1048576,
            4194304,
            8388608,
            2,
            FASTCDC_V1_GEAR_TABLE_ID,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn chunking_descriptor_rejects_unknown_version() {
        let err = ChunkingDescriptor::new(
            1,
            99,
            1048576,
            4194304,
            8388608,
            2,
            FASTCDC_V1_GEAR_TABLE_ID,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn chunking_descriptor_field_numbers() {
        let pairs = match Value::from(&make_chunking_v1()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 7);
        for i in 0..7 {
            assert_eq!(pairs[i as usize].0, Value::U64(i));
        }
    }

    #[test]
    fn chunking_descriptor_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::U64(1)),
            (Value::U64(2), Value::U64(1048576)),
            (Value::U64(3), Value::U64(4194304)),
            (Value::U64(4), Value::U64(8388608)),
            (Value::U64(5), Value::U64(2)),
            (
                Value::U64(6),
                Value::Bytes(FASTCDC_V1_GEAR_TABLE_ID.to_vec()),
            ),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = ChunkingDescriptor::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // ContentManifestChunkEntry tests
    // -----------------------------------------------------------------------

    fn make_chunk_entry() -> ContentManifestChunkEntry {
        ContentManifestChunkEntry::new(ChunkId::new([0xCCu8; 32]), 65536).unwrap()
    }

    #[test]
    fn chunk_entry_roundtrip() {
        let e = make_chunk_entry();
        let decoded = ContentManifestChunkEntry::try_from(Value::from(&e)).unwrap();
        assert_eq!(decoded, e);
    }

    #[test]
    fn chunk_entry_field_numbers() {
        let pairs = match Value::from(&make_chunk_entry()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, Value::U64(0));
        assert_eq!(pairs[1].0, Value::U64(1));
    }

    #[test]
    fn chunk_entry_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Bytes([0xCCu8; 32].to_vec())),
            (Value::U64(1), Value::U64(65536)),
            (Value::U64(99), Value::U64(0)),
        ]);
        let err = ContentManifestChunkEntry::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    // -----------------------------------------------------------------------
    // EncodedChunkPayload tests
    // -----------------------------------------------------------------------

    fn make_encoded_chunk() -> EncodedChunkPayload {
        EncodedChunkPayload::new(
            1,
            [0x01u8; 16],
            ChunkId::new([0x02u8; 32]),
            1024,
            make_codec_none(),
            None,
            vec![0xAAu8; 1024],
        )
        .unwrap()
    }

    fn make_encoded_chunk_encrypted() -> EncodedChunkPayload {
        EncodedChunkPayload::new(
            1,
            [0x01u8; 16],
            ChunkId::new([0x02u8; 32]),
            1024,
            make_codec_zstd(),
            Some(make_encryption()),
            vec![0xBBu8; 1024],
        )
        .unwrap()
    }

    #[test]
    fn encoded_chunk_roundtrip() {
        let p = make_encoded_chunk();
        let decoded = EncodedChunkPayload::try_from(Value::from(&p)).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn encoded_chunk_roundtrip_with_encryption() {
        let p = make_encoded_chunk_encrypted();
        let decoded = EncodedChunkPayload::try_from(Value::from(&p)).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn encoded_chunk_rejects_bad_format_version() {
        let err = EncodedChunkPayload::new(
            99,
            [0x01u8; 16],
            ChunkId::new([0x02u8; 32]),
            1024,
            make_codec_none(),
            None,
            vec![0xAAu8; 1024],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn encoded_chunk_rejects_empty_encoded_bytes() {
        let err = EncodedChunkPayload::new(
            1,
            [0x01u8; 16],
            ChunkId::new([0x02u8; 32]),
            1024,
            make_codec_none(),
            None,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::EmptyArray { key: 6 }));
    }

    #[test]
    fn encoded_chunk_rejects_zero_plaintext_length() {
        let err = EncodedChunkPayload::new(
            1,
            [0x01u8; 16],
            ChunkId::new([0x02u8; 32]),
            0,
            make_codec_none(),
            None,
            vec![0xAAu8; 1024],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn encoded_chunk_rejects_oversized_plaintext_length() {
        let err = EncodedChunkPayload::new(
            1,
            [0x01u8; 16],
            ChunkId::new([0x02u8; 32]),
            8_388_609,
            make_codec_none(),
            None,
            vec![0xAAu8; 1024],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn encoded_chunk_field_numbers() {
        let pairs = match Value::from(&make_encoded_chunk()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 7);
        for i in 0..7 {
            assert_eq!(pairs[i as usize].0, Value::U64(i));
        }
    }

    #[test]
    fn encoded_chunk_rejects_unknown_field() {
        let p = make_encoded_chunk();
        let mut pairs = match Value::from(&p) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        pairs.push((Value::U64(99), Value::U64(0)));
        let value = Value::Map(pairs);
        let err = EncodedChunkPayload::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn encoded_chunk_rejects_not_a_map() {
        let err = EncodedChunkPayload::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn encoded_chunk_record_id_distinct_from_chunk_id() {
        let p = make_encoded_chunk();
        let rid = p.record_id().expect("record_id");
        // RecordId is 32 bytes, distinct from ChunkId in derivation
        assert_ne!(rid.as_bytes(), p.chunk_id().as_bytes());
    }

    // -----------------------------------------------------------------------
    // Content root computation tests
    // -----------------------------------------------------------------------

    #[test]
    fn compute_content_root_empty() {
        let root = compute_content_root(&[]).unwrap();
        let expected = domain_hash("EternalCore:ContentEmpty:v1", &[]).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn compute_content_root_single_leaf() {
        let entry = ContentManifestChunkEntry::new(ChunkId::new([0xCCu8; 32]), 65536).unwrap();
        let root = compute_content_root(&[entry]).unwrap();
        // Single leaf: leaf is the root
        let mut preimage = Vec::with_capacity(40);
        preimage.extend_from_slice(&[0xCCu8; 32]);
        preimage.extend_from_slice(&65536u64.to_le_bytes());
        let expected = domain_hash("EternalCore:ContentLeaf:v1", &preimage).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn compute_content_root_two_leaves() {
        let e1 = ContentManifestChunkEntry::new(ChunkId::new([0xCCu8; 32]), 65536).unwrap();
        let e2 = ContentManifestChunkEntry::new(ChunkId::new([0xDDu8; 32]), 131072).unwrap();
        let root = compute_content_root(&[e1, e2]).unwrap();
        // Two leaves produce a parent node
        let mut preimage1 = Vec::with_capacity(40);
        preimage1.extend_from_slice(&[0xCCu8; 32]);
        preimage1.extend_from_slice(&65536u64.to_le_bytes());
        let leaf1 = domain_hash("EternalCore:ContentLeaf:v1", &preimage1).unwrap();
        let mut preimage2 = Vec::with_capacity(40);
        preimage2.extend_from_slice(&[0xDDu8; 32]);
        preimage2.extend_from_slice(&131072u64.to_le_bytes());
        let leaf2 = domain_hash("EternalCore:ContentLeaf:v1", &preimage2).unwrap();
        let mut parent_preimage = Vec::with_capacity(64);
        parent_preimage.extend_from_slice(&leaf1);
        parent_preimage.extend_from_slice(&leaf2);
        let expected = domain_hash("EternalCore:ContentNode:v1", &parent_preimage).unwrap();
        assert_eq!(root, expected);
    }

    // -----------------------------------------------------------------------
    // ContentManifestPayload tests
    // -----------------------------------------------------------------------

    fn make_manifest_empty() -> ContentManifestPayload {
        let root = compute_content_root(&[]).unwrap();
        ContentManifestPayload::new(1, [0x01u8; 16], make_chunking_v1(), 0, vec![], root).unwrap()
    }

    fn make_manifest_with_chunks() -> ContentManifestPayload {
        let chunks = vec![
            ContentManifestChunkEntry::new(ChunkId::new([0xCCu8; 32]), 65536).unwrap(),
            ContentManifestChunkEntry::new(ChunkId::new([0xDDu8; 32]), 131072).unwrap(),
        ];
        let root = compute_content_root(&chunks).unwrap();
        ContentManifestPayload::new(
            1,
            [0x01u8; 16],
            make_chunking_v1(),
            65536 + 131072,
            chunks,
            root,
        )
        .unwrap()
    }

    #[test]
    fn content_manifest_empty_roundtrip() {
        let p = make_manifest_empty();
        let decoded = ContentManifestPayload::try_from(Value::from(&p)).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn content_manifest_with_chunks_roundtrip() {
        let p = make_manifest_with_chunks();
        let decoded = ContentManifestPayload::try_from(Value::from(&p)).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn content_manifest_rejects_bad_format_version() {
        let root = compute_content_root(&[]).unwrap();
        let err =
            ContentManifestPayload::new(99, [0x01u8; 16], make_chunking_v1(), 0, vec![], root)
                .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn content_manifest_rejects_bad_total_size() {
        let err = ContentManifestPayload::new(
            1,
            [0x01u8; 16],
            make_chunking_v1(),
            42,
            vec![],
            compute_content_root(&[]).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn content_manifest_rejects_bad_content_root() {
        let chunks =
            vec![ContentManifestChunkEntry::new(ChunkId::new([0xCCu8; 32]), 65536).unwrap()];
        let err = ContentManifestPayload::new(
            1,
            [0x01u8; 16],
            make_chunking_v1(),
            65536,
            chunks,
            [0x00u8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 5, .. }));
    }

    #[test]
    fn content_manifest_field_numbers() {
        let pairs = match Value::from(&make_manifest_with_chunks()) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 6);
        for i in 0..6 {
            assert_eq!(pairs[i as usize].0, Value::U64(i));
        }
    }

    #[test]
    fn content_manifest_rejects_unknown_field() {
        let p = make_manifest_empty();
        let mut pairs = match Value::from(&p) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        pairs.push((Value::U64(99), Value::U64(0)));
        let value = Value::Map(pairs);
        let err = ContentManifestPayload::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn content_manifest_rejects_not_a_map() {
        let err = ContentManifestPayload::try_from(Value::U64(0)).unwrap_err();
        assert_eq!(err, PayloadError::NotAMap);
    }

    #[test]
    fn content_manifest_record_id_distinct() {
        let p = make_manifest_empty();
        let mid = p.record_id().expect("record_id");
        assert_eq!(mid.as_bytes().len(), 32);
    }

    // -----------------------------------------------------------------------
    // ISSUE-0015 regression tests
    // -----------------------------------------------------------------------

    #[test]
    fn codec_descriptor_algorithm0_rejects_zstd_fields_via_decoder() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::U64(0)),
            (Value::U64(1), Value::I64(3)),
            (Value::U64(2), Value::U64(1)),
        ]);
        let err = CodecDescriptor::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(1)));
    }

    #[test]
    fn chunking_descriptor_rejects_wrong_minimum_size() {
        let err =
            ChunkingDescriptor::new(1, 1, 1, 4_194_304, 8_388_608, 2, FASTCDC_V1_GEAR_TABLE_ID)
                .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 2, .. }));
    }

    #[test]
    fn chunking_descriptor_rejects_wrong_average_size() {
        let err =
            ChunkingDescriptor::new(1, 1, 1_048_576, 2, 8_388_608, 2, FASTCDC_V1_GEAR_TABLE_ID)
                .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn chunking_descriptor_rejects_wrong_maximum_size() {
        let err =
            ChunkingDescriptor::new(1, 1, 1_048_576, 4_194_304, 3, 2, FASTCDC_V1_GEAR_TABLE_ID)
                .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn chunking_descriptor_rejects_wrong_normalization() {
        let err = ChunkingDescriptor::new(
            1,
            1,
            1_048_576,
            4_194_304,
            8_388_608,
            99,
            FASTCDC_V1_GEAR_TABLE_ID,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 5, .. }));
    }

    #[test]
    fn chunking_descriptor_rejects_wrong_gear_table_id() {
        let err = ChunkingDescriptor::new(1, 1, 1_048_576, 4_194_304, 8_388_608, 2, [0xABu8; 32])
            .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 6, .. }));
    }

    #[test]
    fn chunking_descriptor_new_v1_uses_normative_gear_table_id() {
        let c = ChunkingDescriptor::new_v1();
        assert_eq!(c.gear_table_id(), &FASTCDC_V1_GEAR_TABLE_ID);
        // Verify it matches the normative fixture value
        let expected: [u8; 32] = [
            0x7c, 0xcf, 0xcc, 0x31, 0xcb, 0x8f, 0xa9, 0xc9, 0xe7, 0x7c, 0x5b, 0x46, 0xc6, 0x13,
            0x79, 0x35, 0xc4, 0xc0, 0x4a, 0xc1, 0x8f, 0xfb, 0x2d, 0xad, 0x4a, 0x1b, 0x26, 0xbf,
            0x50, 0x4c, 0x35, 0x30,
        ];
        assert_eq!(*c.gear_table_id(), expected);
    }

    #[test]
    fn chunk_entry_rejects_zero_plaintext_length() {
        let err = ContentManifestChunkEntry::new(ChunkId::new([0xCCu8; 32]), 0).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn encoded_chunk_rejects_mismatched_encoded_bytes_codec_none_no_encryption() {
        let err = EncodedChunkPayload::new(
            1,
            [0x01u8; 16],
            ChunkId::new([0x02u8; 32]),
            1024,
            make_codec_none(),
            None,
            vec![0xAAu8; 512], // 512 != 1024
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 6, .. }));
    }

    #[test]
    fn encoded_chunk_accepts_matching_encoded_bytes_codec_none_no_encryption() {
        let p = EncodedChunkPayload::new(
            1,
            [0x01u8; 16],
            ChunkId::new([0x02u8; 32]),
            1024,
            make_codec_none(),
            None,
            vec![0xAAu8; 1024],
        )
        .unwrap();
        assert_eq!(p.plaintext_length(), 1024);
        assert_eq!(p.encoded_bytes().len(), 1024);
        // chunk_id is now ChunkId distinct from EncodedChunkRecordId
        let _: &ChunkId = p.chunk_id();
        let rid = p.record_id().unwrap();
        assert_ne!(rid.as_bytes(), p.chunk_id().as_bytes());
    }

    // -----------------------------------------------------------------------
    // F3.4 — Relation helpers
    // -----------------------------------------------------------------------

    fn make_relation(target: &str, rel: &str) -> Relation {
        Relation::new(
            ObjectId::new(target).unwrap(),
            RelationType::new(rel).unwrap(),
        )
    }

    #[test]
    fn relation_roundtrip() {
        let r = make_relation("a/b/c", "related");
        let decoded = Relation::try_from(Value::from(&r)).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn relation_field_numbers() {
        let pairs = match Value::from(&make_relation("a/b/c", "related")) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 2);
        for (i, pair) in pairs.iter().enumerate() {
            assert_eq!(pair.0, Value::U64(i as u64), "field {i} key mismatch");
        }
    }

    #[test]
    fn relation_rejects_unknown_field() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Text("a".into())),
            (Value::U64(1), Value::Text("b".into())),
            (Value::U64(2), Value::U64(99)),
        ]);
        let err = Relation::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(2)));
    }

    #[test]
    fn relation_rejects_not_a_map() {
        let err = Relation::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn relation_rejects_empty_object_id() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Text("".into())),
            (Value::U64(1), Value::Text("rel".into())),
        ]);
        let err = Relation::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 0, .. }));
    }

    #[test]
    fn relation_rejects_empty_relation_type() {
        let value = Value::Map(vec![
            (Value::U64(0), Value::Text("a".into())),
            (Value::U64(1), Value::Text("".into())),
        ]);
        let err = Relation::try_from(value).unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 1, .. }));
    }

    // -----------------------------------------------------------------------
    // F3.4 — ObjectVersionPayload helpers
    // -----------------------------------------------------------------------

    fn make_object_version_payload(
        tombstone: bool,
        content_manifest: Option<bool>,
    ) -> ObjectVersionPayload {
        let cm_id = if content_manifest.unwrap_or(!tombstone) {
            Some(ContentManifestId::new([0xAAu8; 32]))
        } else {
            None
        };
        ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("path/to/obj").unwrap(),
            cm_id,
            vec![VersionId::new([0xBBu8; 32])],
            DataType::new("text/plain").unwrap(),
            CanonicalValue::U64(42),
            vec![make_relation("a/b/c", "related")],
            tombstone,
            -1_234_567_890,
            [0xCCu8; 32],
        )
        .unwrap()
    }

    #[test]
    fn object_version_roundtrip_normal() {
        let p = make_object_version_payload(false, None);
        let decoded = ObjectVersionPayload::try_from(Value::from(&p)).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn object_version_roundtrip_tombstone() {
        let p = make_object_version_payload(true, Some(false));
        let decoded = ObjectVersionPayload::try_from(Value::from(&p)).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn object_version_roundtrip_with_many_parents() {
        let parents: Vec<VersionId> = (0..5).map(|i| VersionId::new([i as u8; 32])).collect();
        let p = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("path").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            parents,
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap();
        let decoded = ObjectVersionPayload::try_from(Value::from(&p)).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn object_version_field_numbers() {
        let pairs = match Value::from(&make_object_version_payload(false, None)) {
            Value::Map(pairs) => pairs,
            _ => panic!("not a map"),
        };
        assert_eq!(pairs.len(), 11);
        for (i, pair) in pairs.iter().enumerate() {
            assert_eq!(pair.0, Value::U64(i as u64), "field {i} key mismatch");
        }
    }

    #[test]
    fn object_version_rejects_unknown_field() {
        let mut pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes(vec![0x11u8; 16])),
            (Value::U64(2), Value::Text("obj".into())),
            (Value::U64(3), Value::Bytes(vec![0xAAu8; 32])),
            (Value::U64(4), Value::Array(vec![])),
            (Value::U64(5), Value::Text("t".into())),
            (Value::U64(6), Value::Array(vec![Value::U64(0)])), // CanonicalValue::Null
            (Value::U64(7), Value::Array(vec![])),
            (Value::U64(8), Value::Boolean(false)),
            (Value::U64(9), Value::I64(0)),
            (Value::U64(10), Value::Bytes(vec![0xCCu8; 32])),
        ];
        pairs.push((Value::U64(11), Value::U64(99)));
        let err = ObjectVersionPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(11)));
    }

    #[test]
    fn object_version_rejects_not_a_map() {
        let err = ObjectVersionPayload::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn object_version_rejects_bad_format_version() {
        let err = ObjectVersionPayload::new(
            2,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn object_version_rejects_tombstone_with_content_manifest() {
        let err = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            true,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 8, .. }));
    }

    #[test]
    fn object_version_rejects_non_tombstone_without_content_manifest() {
        let err = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            None,
            vec![],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn object_version_rejects_too_many_parents() {
        let parents: Vec<VersionId> = (0..65).map(|i| VersionId::new([i as u8; 32])).collect();
        let err = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            parents,
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn object_version_rejects_duplicate_parents() {
        let dup_id = VersionId::new([0xBBu8; 32]);
        let err = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![dup_id, dup_id],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 4 }));
    }

    #[test]
    fn object_version_rejects_unsorted_relations() {
        let err = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![make_relation("z", "later"), make_relation("a", "first")],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 7 }));
    }

    #[test]
    fn object_version_rejects_duplicate_relations() {
        let err = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![make_relation("a", "x"), make_relation("a", "x")],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 7 }));
    }

    #[test]
    fn object_version_record_id_distinct_from_content_manifest() {
        let p = make_object_version_payload(false, None);
        let vid = p.record_id().unwrap();
        // VersionId should differ from ContentManifestId even when using
        // the same underlying content_manifest_id bytes
        assert_ne!(vid.as_bytes(), p.content_manifest_id().unwrap().as_bytes());
    }

    #[test]
    fn object_version_accepts_no_parents() {
        let mut metadata_map = std::collections::BTreeMap::new();
        metadata_map.insert("key".to_string(), CanonicalValue::U64(1));
        let p = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("genesis").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![],
            DataType::new("text").unwrap(),
            CanonicalValue::Map(metadata_map),
            vec![],
            false,
            99_999,
            [0xCCu8; 32],
        )
        .unwrap();
        assert!(p.parents().is_empty());
        assert_eq!(p.created_at_ns(), 99_999);
        // metadata retains map type
        assert!(matches!(p.metadata(), CanonicalValue::Map(_)));
    }

    #[test]
    fn object_version_rejects_raw_value_as_metadata() {
        // Field 6 must be CanonicalValue tagged-array, not raw Value::U64
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes(vec![0x11u8; 16])),
            (Value::U64(2), Value::Text("obj".into())),
            (Value::U64(3), Value::Bytes(vec![0xAAu8; 32])),
            (Value::U64(4), Value::Array(vec![])),
            (Value::U64(5), Value::Text("t".into())),
            (Value::U64(6), Value::U64(999)),
            (Value::U64(7), Value::Array(vec![])),
            (Value::U64(8), Value::Boolean(false)),
            (Value::U64(9), Value::I64(0)),
            (Value::U64(10), Value::Bytes(vec![0xCCu8; 32])),
        ];
        let err = ObjectVersionPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(
            err,
            PayloadError::Decode(DecodeError::InvalidCanonicalValueStructure)
        ));
    }

    #[test]
    fn object_version_rejects_raw_map_as_metadata() {
        // Field 6 as raw CBOR map (not CanonicalValue tagged-array) must fail
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes(vec![0x11u8; 16])),
            (Value::U64(2), Value::Text("obj".into())),
            (Value::U64(3), Value::Bytes(vec![0xAAu8; 32])),
            (Value::U64(4), Value::Array(vec![])),
            (Value::U64(5), Value::Text("t".into())),
            (
                Value::U64(6),
                Value::Map(vec![(Value::Text("k".into()), Value::U64(1))]),
            ),
            (Value::U64(7), Value::Array(vec![])),
            (Value::U64(8), Value::Boolean(false)),
            (Value::U64(9), Value::I64(0)),
            (Value::U64(10), Value::Bytes(vec![0xCCu8; 32])),
        ];
        let err = ObjectVersionPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(
            err,
            PayloadError::Decode(DecodeError::InvalidCanonicalValueStructure)
        ));
    }

    #[test]
    fn object_version_rejects_unsorted_canonical_metadata_map() {
        // Field 6 as CanonicalValue::Map with unsorted keys must be rejected.
        // Tagged-array [7, [["b", null], ["a", null]]] — keys "b" then "a".
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes(vec![0x11u8; 16])),
            (Value::U64(2), Value::Text("obj".into())),
            (Value::U64(3), Value::Bytes(vec![0xAAu8; 32])),
            (Value::U64(4), Value::Array(vec![])),
            (Value::U64(5), Value::Text("t".into())),
            (
                Value::U64(6),
                Value::Array(vec![
                    Value::U64(7),
                    Value::Array(vec![
                        Value::Array(vec![
                            Value::Text("b".into()),
                            Value::Array(vec![Value::U64(0)]),
                        ]),
                        Value::Array(vec![
                            Value::Text("a".into()),
                            Value::Array(vec![Value::U64(0)]),
                        ]),
                    ]),
                ]),
            ),
            (Value::U64(7), Value::Array(vec![])),
            (Value::U64(8), Value::Boolean(false)),
            (Value::U64(9), Value::I64(0)),
            (Value::U64(10), Value::Bytes(vec![0xCCu8; 32])),
        ];
        let err = ObjectVersionPayload::try_from(Value::Map(pairs)).unwrap_err();
        // Currently ObjectVersionPayload wraps all CanonicalValue decode errors
        // as InvalidCanonicalValueStructure. When the inner canonical_value_from_value
        // rejects unsorted entries, this propagates as InvalidCanonicalValueStructure.
        assert!(matches!(
            err,
            PayloadError::Decode(DecodeError::InvalidCanonicalValueStructure)
        ));
    }

    #[test]
    fn object_version_rejects_too_many_relations() {
        let relations: Vec<Relation> = (0..100_001)
            .map(|i| make_relation(&format!("o/{i}"), "t"))
            .collect();
        let err = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            relations,
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 7, .. }));
    }

    #[test]
    fn object_version_rejects_unsorted_additional_parents() {
        // parents[1..] must be lexicographically sorted
        let err = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![
                VersionId::new([0x01u8; 32]), // local parent (index 0)
                VersionId::new([0xFFu8; 32]), // should be 'b', not 'z'
                VersionId::new([0xAAu8; 32]), // 'a' < 'z' but after index 1
            ],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 4 }));
    }

    #[test]
    fn object_version_accepts_sorted_additional_parents() {
        let p = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![
                VersionId::new([0x01u8; 32]), // local parent (index 0)
                VersionId::new([0xAAu8; 32]), // 'a'
                VersionId::new([0xFFu8; 32]), // 'b' > 'a'
            ],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap();
        assert_eq!(p.parents().len(), 3);
    }

    #[test]
    fn object_version_accepts_single_parent() {
        let p = ObjectVersionPayload::new(
            1,
            [0x11u8; 16],
            ObjectId::new("obj").unwrap(),
            Some(ContentManifestId::new([0xAAu8; 32])),
            vec![VersionId::new([0xBBu8; 32])],
            DataType::new("text").unwrap(),
            CanonicalValue::Null,
            vec![],
            false,
            0,
            [0xCCu8; 32],
        )
        .unwrap();
        assert_eq!(p.parents().len(), 1);
    }

    // -----------------------------------------------------------------------
    // SMT leaf payload tests (§9.15)
    // -----------------------------------------------------------------------

    #[test]
    fn smt_leaf_field_numbers() {
        let p = SMTLeafPayload::new(
            1,
            ObjectKey::new([0x01u8; 32]),
            VersionId::new([0x02u8; 32]),
        )
        .unwrap();
        let value = Value::from(&p);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 2, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        // Verify roundtrip
        let decoded = SMTLeafPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn smt_leaf_roundtrip() {
        let p = SMTLeafPayload::new(
            1,
            ObjectKey::new([0xABu8; 32]),
            VersionId::new([0xCDu8; 32]),
        )
        .unwrap();
        let value = Value::from(&p);
        let decoded = SMTLeafPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn smt_leaf_rejects_unknown_field() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 32].to_vec())),
            (Value::U64(2), Value::Bytes([0x02u8; 32].to_vec())),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = SMTLeafPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn smt_leaf_rejects_not_a_map() {
        let err = SMTLeafPayload::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn smt_leaf_rejects_bad_format_version() {
        let err = SMTLeafPayload::new(
            0,
            ObjectKey::new([0x01u8; 32]),
            VersionId::new([0x02u8; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn smt_leaf_record_id() {
        let p = SMTLeafPayload::new(
            1,
            ObjectKey::new([0xABu8; 32]),
            VersionId::new([0xCDu8; 32]),
        )
        .unwrap();
        let rid = p.record_id().unwrap();
        // Check non-zero and deterministic
        assert_ne!(rid.as_bytes(), &[0u8; 32]);
        let rid2 = p.record_id().unwrap();
        assert_eq!(rid, rid2);
    }

    // -----------------------------------------------------------------------
    // SMT internal payload tests (§9.16)
    // -----------------------------------------------------------------------

    #[test]
    fn smt_internal_field_numbers() {
        let p = SMTInternalPayload::new(1, [0x01u8; 32], [0x02u8; 32]).unwrap();
        let value = Value::from(&p);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 2, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = SMTInternalPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn smt_internal_roundtrip() {
        let p = SMTInternalPayload::new(1, [0x11u8; 32], [0x22u8; 32]).unwrap();
        let value = Value::from(&p);
        let decoded = SMTInternalPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn smt_internal_rejects_unknown_field() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 32].to_vec())),
            (Value::U64(2), Value::Bytes([0x02u8; 32].to_vec())),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = SMTInternalPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn smt_internal_rejects_not_a_map() {
        let err = SMTInternalPayload::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn smt_internal_rejects_bad_format_version() {
        let err = SMTInternalPayload::new(0, [0x01u8; 32], [0x02u8; 32]).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn smt_internal_record_id() {
        let p = SMTInternalPayload::new(1, [0xABu8; 32], [0xCDu8; 32]).unwrap();
        let rid = p.record_id().unwrap();
        assert_ne!(rid.as_bytes(), &[0u8; 32]);
        let rid2 = p.record_id().unwrap();
        assert_eq!(rid, rid2);
    }

    // -----------------------------------------------------------------------
    // SMT proof tests (§10.6)
    // -----------------------------------------------------------------------

    fn make_256_siblings() -> Vec<[u8; 32]> {
        (0..256).map(|i| [i as u8; 32]).collect()
    }

    #[test]
    fn smt_proof_field_numbers() {
        let siblings = make_256_siblings();
        let p = SMTProof::new(
            1,
            SmtRoot::new([0x01u8; 32]),
            ObjectKey::new([0x02u8; 32]),
            Some(VersionId::new([0x03u8; 32])),
            siblings,
        )
        .unwrap();
        let value = Value::from(&p);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 4, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = SMTProof::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn smt_proof_roundtrip_with_version() {
        let siblings = make_256_siblings();
        let p = SMTProof::new(
            1,
            SmtRoot::new([0x11u8; 32]),
            ObjectKey::new([0x22u8; 32]),
            Some(VersionId::new([0x33u8; 32])),
            siblings,
        )
        .unwrap();
        let value = Value::from(&p);
        let decoded = SMTProof::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn smt_proof_roundtrip_null_version() {
        let siblings = make_256_siblings();
        let p = SMTProof::new(
            1,
            SmtRoot::new([0x44u8; 32]),
            ObjectKey::new([0x55u8; 32]),
            None,
            siblings,
        )
        .unwrap();
        let value = Value::from(&p);
        let decoded = SMTProof::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn smt_proof_rejects_unknown_field() {
        let siblings = make_256_siblings();
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 32].to_vec())),
            (Value::U64(2), Value::Bytes([0x02u8; 32].to_vec())),
            (Value::U64(3), Value::Null),
            (
                Value::U64(4),
                Value::Array(siblings.iter().map(|b| Value::Bytes(b.to_vec())).collect()),
            ),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = SMTProof::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn smt_proof_rejects_not_a_map() {
        let err = SMTProof::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn smt_proof_rejects_bad_format_version() {
        let siblings = make_256_siblings();
        let err = SMTProof::new(
            0,
            SmtRoot::new([0x01u8; 32]),
            ObjectKey::new([0x02u8; 32]),
            None,
            siblings,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn smt_proof_rejects_too_few_siblings() {
        let err = SMTProof::new(
            1,
            SmtRoot::new([0x01u8; 32]),
            ObjectKey::new([0x02u8; 32]),
            None,
            vec![[0x00u8; 32]; 255],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn smt_proof_rejects_too_many_siblings() {
        let err = SMTProof::new(
            1,
            SmtRoot::new([0x01u8; 32]),
            ObjectKey::new([0x02u8; 32]),
            None,
            vec![[0x00u8; 32]; 257],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn smt_proof_rejects_zero_siblings() {
        let err = SMTProof::new(
            1,
            SmtRoot::new([0x01u8; 32]),
            ObjectKey::new([0x02u8; 32]),
            None,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn smt_proof_decoder_rejects_wrong_sibling_count() {
        let siblings: Vec<Value> = (0..255)
            .map(|i| Value::Bytes([i as u8; 32].to_vec()))
            .collect();
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 32].to_vec())),
            (Value::U64(2), Value::Bytes([0x02u8; 32].to_vec())),
            (Value::U64(3), Value::Null),
            (Value::U64(4), Value::Array(siblings)),
        ];
        let err = SMTProof::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn smt_proof_decoder_rejects_wrong_sibling_bytes_length() {
        let siblings = vec![
            Value::Bytes([0x01u8; 32].to_vec()),
            Value::Bytes([0x02u8; 16].to_vec()), // 16 bytes, not 32
        ];
        let remaining = (2..256)
            .map(|i| Value::Bytes([i as u8; 32].to_vec()))
            .collect::<Vec<_>>();
        let mut all_siblings = siblings;
        all_siblings.extend(remaining);
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x01u8; 32].to_vec())),
            (Value::U64(2), Value::Bytes([0x02u8; 32].to_vec())),
            (Value::U64(3), Value::Null),
            (Value::U64(4), Value::Array(all_siblings)),
        ];
        let err = SMTProof::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::WrongLength { key: 4, .. }));
    }

    // -----------------------------------------------------------------------
    // SMT bit-order tests (FORMAT.md §10.1)
    // -----------------------------------------------------------------------

    #[test]
    fn object_key_bit_depth0() {
        // ObjectKey: [0x80, 0x00, ...] → bit 7 of byte 0 = 1 (MSB)
        let key = ObjectKey::new([0x80u8; 32]);
        // Depth 0 = bit 7 of byte 0 = 1
        assert_eq!(object_key_bit(&key, 0), Some(1));
        // Depth 1 = bit 6 of byte 0 = 0 (0x80 = 1000_0000)
        assert_eq!(object_key_bit(&key, 1), Some(0));
    }

    #[test]
    fn object_key_bit_depth1() {
        // ObjectKey: [0x40, ...] → bit 6 of byte 0 = 1
        let key = ObjectKey::new([0x40u8; 32]);
        assert_eq!(object_key_bit(&key, 0), Some(0)); // bit 7 = 0
        assert_eq!(object_key_bit(&key, 1), Some(1)); // bit 6 = 1
    }

    #[test]
    fn object_key_bit_depth7() {
        // ObjectKey: [0x01, ...] → bit 0 of byte 0 = 1
        let key = ObjectKey::new([0x01u8; 32]);
        assert_eq!(object_key_bit(&key, 7), Some(1)); // bit 0 = 1
        assert_eq!(object_key_bit(&key, 6), Some(0)); // bit 1 = 0
    }

    #[test]
    fn object_key_bit_depth8() {
        // ObjectKey: [0x00, 0x80, ...] → bit 7 of byte 1 = 1
        let mut bytes = [0u8; 32];
        bytes[1] = 0x80;
        let key = ObjectKey::new(bytes);
        assert_eq!(object_key_bit(&key, 8), Some(1)); // bit 7 of byte 1 = 1
        assert_eq!(object_key_bit(&key, 15), Some(0)); // bit 0 of byte 1 = 0
    }

    #[test]
    fn object_key_bit_depth255() {
        // ObjectKey: [..., 0x01] → bit 0 of byte 31 = 1
        let mut bytes = [0u8; 32];
        bytes[31] = 0x01;
        let key = ObjectKey::new(bytes);
        assert_eq!(object_key_bit(&key, 255), Some(1)); // bit 0 of byte 31 = 1
        assert_eq!(object_key_bit(&key, 254), Some(0)); // bit 1 of byte 31 = 0
    }

    #[test]
    fn object_key_bit_out_of_range() {
        let key = ObjectKey::new([0u8; 32]);
        assert_eq!(object_key_bit(&key, 256), None);
    }

    fn hex_to_arr32(s: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    }

    #[test]
    fn object_key_bit_known_fixture() {
        // ObjectKey from FORMAT.md §21.6 for ObjectId "a":
        // 8eff98cc3232ebc0cc1129d0b201279939ff3966b08a68d269cf575d8270b8c9
        let arr = hex_to_arr32("8eff98cc3232ebc0cc1129d0b201279939ff3966b08a68d269cf575d8270b8c9");
        let key = ObjectKey::new(arr);
        // Depth 0: byte 0 = 0x8e = 1000_1110, bit 7 = 1
        assert_eq!(object_key_bit(&key, 0), Some(1));
        // Depth 1: bit 6 = 0
        assert_eq!(object_key_bit(&key, 1), Some(0));
        // Depth 4: bit 3 = 1 (1000_1110 >> 3 = 0001_0001 = 1)
        assert_eq!(object_key_bit(&key, 4), Some(1));
        // Depth 7: bit 0 = 0 (1000_1110, LSB = 0)
        assert_eq!(object_key_bit(&key, 7), Some(0));
        // Depth 8: byte 1 = 0x98 = 1001_1000, bit 7 = 1
        assert_eq!(object_key_bit(&key, 8), Some(1));
    }

    // -----------------------------------------------------------------------
    // SMT proof fixture tests (FORMAT.md §10.6)
    // -----------------------------------------------------------------------

    #[test]
    fn smt_proof_golden_fixture() {
        // Construct a known SMTProof with deterministic data,
        // reencode to CBOR, and verify the exact bytes match a golden vector.
        let siblings: Vec<[u8; 32]> = (0..256).map(|i| [i as u8; 32]).collect();
        let proof = SMTProof::new(
            1,
            SmtRoot::new([0x01u8; 32]),
            ObjectKey::new([0x02u8; 32]),
            Some(VersionId::new([0x03u8; 32])),
            siblings,
        )
        .unwrap();
        let value = Value::from(&proof);
        let encoded = value.reencode();

        // 1. Determinism check
        assert_eq!(
            encoded,
            value.reencode(),
            "SMTProof CBOR must be deterministic"
        );

        // 2. Golden fixture: compare against known-good CBOR bytes
        let golden = include_bytes!("../tests/fixtures/golden_smt_proof.bin");
        assert_eq!(
            encoded.as_slice(),
            golden.as_slice(),
            "SMTProof CBOR must match golden fixture"
        );

        // 3. Decode CBOR bytes back to Value and verify structural invariants
        let mut dec = CanonicalDecoder::from_limits(&encoded, &FormatLimits::default());
        let decoded = dec.decode().expect("valid CBOR");
        match &decoded {
            Value::Map(pairs) => {
                // Must have 5 entries (keys 0..4)
                assert_eq!(pairs.len(), 5, "SMTProof must have 5 map entries");
                for (k, v) in pairs {
                    match k {
                        Value::U64(0) => assert_eq!(v, &Value::U64(1), "format_version must be 1"),
                        Value::U64(4) => {
                            match v {
                                Value::Array(items) => {
                                    assert_eq!(items.len(), 256, "siblings must have 256 entries");
                                    // sibling 0 = leaf-depth (depth 255), sibling 255 = root-depth (depth 0)
                                    assert_eq!(
                                        items[0],
                                        Value::Bytes(vec![0x00u8; 32]),
                                        "sibling[0] must be [0x00; 32]"
                                    );
                                    assert_eq!(
                                        items[255],
                                        Value::Bytes(vec![0xFFu8; 32]),
                                        "sibling[255] must be [0xFF; 32]"
                                    );
                                }
                                _ => panic!("key 4 must be array"),
                            }
                        }
                        Value::U64(1) => {
                            assert_eq!(
                                v,
                                &Value::Bytes(vec![0x01u8; 32]),
                                "root must be [0x01; 32]"
                            )
                        }
                        Value::U64(2) => {
                            assert_eq!(
                                v,
                                &Value::Bytes(vec![0x02u8; 32]),
                                "object_key must be [0x02; 32]"
                            )
                        }
                        Value::U64(3) => {
                            assert_eq!(
                                v,
                                &Value::Bytes(vec![0x03u8; 32]),
                                "version_id must be [0x03; 32]"
                            )
                        }
                        _ => panic!("unexpected key {k:?}"),
                    }
                }
            }
            _ => panic!("SMTProof CBOR must be a map"),
        }
    }

    // -------------------------------------------------------------------
    // ObjectChange tests (§9.17)
    // -------------------------------------------------------------------

    #[test]
    fn object_change_field_numbers() {
        let c = ObjectChange::new(
            ObjectId::new("obj").unwrap(),
            Some(VersionId::new([0xaa; 32])),
            VersionId::new([0xbb; 32]),
        );
        let value = Value::from(&c);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 2, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = ObjectChange::try_from(value).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn object_change_roundtrip() {
        let c = ObjectChange::new(
            ObjectId::new("some/path").unwrap(),
            None,
            VersionId::new([0xcc; 32]),
        );
        let value = Value::from(&c);
        let decoded = ObjectChange::try_from(value).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn object_change_rejects_not_a_map() {
        let err = ObjectChange::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn object_change_rejects_unknown_field() {
        let pairs = vec![
            (Value::U64(0), Value::Text("obj".to_string())),
            (Value::U64(1), Value::Null),
            (Value::U64(2), Value::Bytes([0xbb; 32].to_vec())),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = ObjectChange::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn object_change_rejects_invalid_object_id() {
        let pairs = vec![
            (Value::U64(0), Value::Text("".to_string())),
            (Value::U64(1), Value::Null),
            (Value::U64(2), Value::Bytes([0xbb; 32].to_vec())),
        ];
        let err = ObjectChange::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 0, .. }));
    }

    // -------------------------------------------------------------------
    // RepoCommitPayload tests (§9.18)
    // -------------------------------------------------------------------

    fn make_repo_commit() -> RepoCommitPayload {
        let change = ObjectChange::new(
            ObjectId::new("obj").unwrap(),
            None,
            VersionId::new([0xcc; 32]),
        );
        RepoCommitPayload::new(
            1,
            [0x11; 16],
            vec![],
            vec![change],
            SmtRoot::new([0x22; 32]),
            PolicyId::new([0x33; 32]),
            KeyringId::new([0x44; 32]),
            42,
            "test commit".to_string(),
            KeyId::new([0x55; 32]),
        )
        .unwrap()
    }

    #[test]
    fn repo_commit_payload_field_numbers() {
        let p = make_repo_commit();
        let value = Value::from(&p);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 9, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = RepoCommitPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn repo_commit_payload_roundtrip() {
        let p = make_repo_commit();
        let value = Value::from(&p);
        let decoded = RepoCommitPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn repo_commit_payload_roundtrip_with_parents() {
        let change = ObjectChange::new(
            ObjectId::new("obj").unwrap(),
            None,
            VersionId::new([0xcc; 32]),
        );
        let p = RepoCommitPayload::new(
            1,
            [0x11; 16],
            vec![RepoCommitId::new([0xaa; 32]), RepoCommitId::new([0xbb; 32])],
            vec![change],
            SmtRoot::new([0x22; 32]),
            PolicyId::new([0x33; 32]),
            KeyringId::new([0x44; 32]),
            42,
            "merge commit".to_string(),
            KeyId::new([0x55; 32]),
        )
        .unwrap();
        let value = Value::from(&p);
        let decoded = RepoCommitPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn repo_commit_payload_rejects_not_a_map() {
        let err = RepoCommitPayload::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn repo_commit_payload_rejects_unknown_field() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x11; 16].to_vec())),
            (Value::U64(2), Value::Array(vec![])),
            (Value::U64(3), Value::Array(vec![])),
            (Value::U64(4), Value::Bytes([0x22; 32].to_vec())),
            (Value::U64(5), Value::Bytes([0x33; 32].to_vec())),
            (Value::U64(6), Value::Bytes([0x44; 32].to_vec())),
            (Value::U64(7), Value::I64(42)),
            (Value::U64(8), Value::Text("msg".to_string())),
            (Value::U64(9), Value::Bytes([0x55; 32].to_vec())),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = RepoCommitPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn repo_commit_payload_rejects_bad_format_version() {
        let err = RepoCommitPayload::new(
            0,
            [0x11; 16],
            vec![],
            vec![],
            SmtRoot::new([0x22; 32]),
            PolicyId::new([0x33; 32]),
            KeyringId::new([0x44; 32]),
            0,
            "bad version".to_string(),
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn repo_commit_payload_rejects_too_many_parents() {
        let parents = vec![RepoCommitId::new([0x00; 32]); 65];
        let change = ObjectChange::new(
            ObjectId::new("obj").unwrap(),
            None,
            VersionId::new([0xcc; 32]),
        );
        let err = RepoCommitPayload::new(
            1,
            [0x11; 16],
            parents,
            vec![change],
            SmtRoot::new([0x22; 32]),
            PolicyId::new([0x33; 32]),
            KeyringId::new([0x44; 32]),
            0,
            "too many parents".to_string(),
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 2, .. }));
    }

    #[test]
    fn repo_commit_payload_rejects_unsorted_parents() {
        // parent[0] is the baseline (no sort requirement); parents[1..] must be sorted.
        // With 3 parents, parents[1..] = [0xcc, 0xaa], which is unsorted.
        let parents = vec![
            RepoCommitId::new([0x00; 32]),
            RepoCommitId::new([0xcc; 32]),
            RepoCommitId::new([0xaa; 32]),
        ];
        let change = ObjectChange::new(
            ObjectId::new("obj").unwrap(),
            None,
            VersionId::new([0xcc; 32]),
        );
        let err = RepoCommitPayload::new(
            1,
            [0x11; 16],
            parents,
            vec![change],
            SmtRoot::new([0x22; 32]),
            PolicyId::new([0x33; 32]),
            KeyringId::new([0x44; 32]),
            0,
            "unsorted parents".to_string(),
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 2 }));
    }

    #[test]
    fn repo_commit_payload_rejects_unsorted_changes() {
        let change_b = ObjectChange::new(
            ObjectId::new("b").unwrap(),
            None,
            VersionId::new([0xcc; 32]),
        );
        let change_a = ObjectChange::new(
            ObjectId::new("a").unwrap(),
            None,
            VersionId::new([0xdd; 32]),
        );
        let err = RepoCommitPayload::new(
            1,
            [0x11; 16],
            vec![],
            vec![change_b, change_a],
            SmtRoot::new([0x22; 32]),
            PolicyId::new([0x33; 32]),
            KeyringId::new([0x44; 32]),
            0,
            "unsorted changes".to_string(),
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 3 }));
    }

    #[test]
    fn repo_commit_payload_rejects_missing_parents() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x11; 16].to_vec())),
            // field 2 (parents) omitted
            (Value::U64(3), Value::Array(vec![])),
            (Value::U64(4), Value::Bytes([0x22; 32].to_vec())),
            (Value::U64(5), Value::Bytes([0x33; 32].to_vec())),
            (Value::U64(6), Value::Bytes([0x44; 32].to_vec())),
            (Value::U64(7), Value::I64(42)),
            (Value::U64(8), Value::Text("msg".to_string())),
            (Value::U64(9), Value::Bytes([0x55; 32].to_vec())),
        ];
        let err = RepoCommitPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::MissingField(2)));
    }

    #[test]
    fn repo_commit_payload_rejects_missing_changes() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x11; 16].to_vec())),
            (Value::U64(2), Value::Array(vec![])),
            // field 3 (changes) omitted
            (Value::U64(4), Value::Bytes([0x22; 32].to_vec())),
            (Value::U64(5), Value::Bytes([0x33; 32].to_vec())),
            (Value::U64(6), Value::Bytes([0x44; 32].to_vec())),
            (Value::U64(7), Value::I64(42)),
            (Value::U64(8), Value::Text("msg".to_string())),
            (Value::U64(9), Value::Bytes([0x55; 32].to_vec())),
        ];
        let err = RepoCommitPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::MissingField(3)));
    }

    #[test]
    fn repo_commit_record_id_is_deterministic() {
        let p = make_repo_commit();
        assert_eq!(p.record_id().unwrap(), p.record_id().unwrap());
    }

    // -------------------------------------------------------------------
    // RefUpdatePayload tests (§9.19)
    // -------------------------------------------------------------------

    fn make_ref_update() -> RefUpdatePayload {
        RefUpdatePayload::new(
            1,
            [0x11; 16],
            RefName::new("refs/heads/main").unwrap(),
            None,
            Some(RepoCommitId::new([0xaa; 32])),
            1,
            99,
            KeyId::new([0x55; 32]),
        )
        .unwrap()
    }

    #[test]
    fn ref_update_payload_field_numbers() {
        let p = make_ref_update();
        let value = Value::from(&p);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 7, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = RefUpdatePayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn ref_update_payload_roundtrip() {
        let p = make_ref_update();
        let value = Value::from(&p);
        let decoded = RefUpdatePayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn ref_update_payload_roundtrip_null_target() {
        // A branch deletion: null target_commit_id
        let p = RefUpdatePayload::new(
            1,
            [0x11; 16],
            RefName::new("refs/heads/feature").unwrap(),
            Some(RefUpdateId::new([0xcc; 32])),
            None,
            2,
            99,
            KeyId::new([0x55; 32]),
        )
        .unwrap();
        let value = Value::from(&p);
        // Verify target_commit_id is encoded as null
        match &value {
            Value::Map(pairs) => {
                for (k, v) in pairs {
                    if let Value::U64(4) = k {
                        assert_eq!(v, &Value::Null, "deletion target must be null");
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = RefUpdatePayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
        assert!(decoded.target_commit_id().is_none());
    }

    #[test]
    fn ref_update_payload_rejects_not_a_map() {
        let err = RefUpdatePayload::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn ref_update_payload_rejects_unknown_field() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x11; 16].to_vec())),
            (Value::U64(2), Value::Text("refs/heads/main".to_string())),
            (Value::U64(3), Value::Null),
            (Value::U64(4), Value::Bytes([0xaa; 32].to_vec())),
            (Value::U64(5), Value::U64(1)),
            (Value::U64(6), Value::I64(99)),
            (Value::U64(7), Value::Bytes([0x55; 32].to_vec())),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = RefUpdatePayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn ref_update_payload_rejects_bad_format_version() {
        let err = RefUpdatePayload::new(
            0,
            [0x11; 16],
            RefName::new("refs/heads/main").unwrap(),
            None,
            Some(RepoCommitId::new([0xaa; 32])),
            1,
            0,
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn ref_update_payload_rejects_zero_sequence() {
        let err = RefUpdatePayload::new(
            1,
            [0x11; 16],
            RefName::new("refs/heads/main").unwrap(),
            None,
            Some(RepoCommitId::new([0xaa; 32])),
            0,
            0,
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 5, .. }));
    }

    #[test]
    fn ref_update_payload_rejects_invalid_ref_name() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x11; 16].to_vec())),
            (Value::U64(2), Value::Text("".to_string())),
            (Value::U64(3), Value::Null),
            (Value::U64(4), Value::Bytes([0xaa; 32].to_vec())),
            (Value::U64(5), Value::U64(1)),
            (Value::U64(6), Value::I64(99)),
            (Value::U64(7), Value::Bytes([0x55; 32].to_vec())),
        ];
        let err = RefUpdatePayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn ref_update_payload_rejects_tag_null_target() {
        let err = RefUpdatePayload::new(
            1,
            [0x11; 16],
            RefName::new("refs/tags/v1.0").unwrap(),
            None,
            None,
            1,
            99,
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn ref_update_payload_rejects_tag_with_predecessor() {
        let err = RefUpdatePayload::new(
            1,
            [0x11; 16],
            RefName::new("refs/tags/v1.0").unwrap(),
            Some(RefUpdateId::new([0xcc; 32])),
            Some(RepoCommitId::new([0xaa; 32])),
            1,
            99,
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn ref_update_payload_rejects_tag_wrong_sequence() {
        let err = RefUpdatePayload::new(
            1,
            [0x11; 16],
            RefName::new("refs/tags/v1.0").unwrap(),
            None,
            Some(RepoCommitId::new([0xaa; 32])),
            2,
            99,
            KeyId::new([0x55; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 5, .. }));
    }

    #[test]
    fn ref_update_record_id_is_deterministic() {
        let p = make_ref_update();
        assert_eq!(p.record_id().unwrap(), p.record_id().unwrap());
    }

    // -------------------------------------------------------------------
    // TransactionEndPayload tests (§9.20)
    // -------------------------------------------------------------------

    fn make_transaction_end() -> TransactionEndPayload {
        TransactionEndPayload::new(1, [0x11; 16], [0x22; 16], 0, 1000, 5, [0x99; 32]).unwrap()
    }

    #[test]
    fn transaction_end_payload_field_numbers() {
        let p = make_transaction_end();
        let value = Value::from(&p);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 6, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = TransactionEndPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn transaction_end_payload_roundtrip() {
        let p = make_transaction_end();
        let value = Value::from(&p);
        let decoded = TransactionEndPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn transaction_end_payload_rejects_not_a_map() {
        let err = TransactionEndPayload::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn transaction_end_payload_rejects_end_offset_before_first_offset() {
        let err = TransactionEndPayload::new(1, [0x11; 16], [0x22; 16], 1000, 999, 5, [0x99; 32])
            .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn transaction_end_payload_rejects_bad_format_version() {
        let err = TransactionEndPayload::new(0, [0x11; 16], [0x22; 16], 0, 1000, 5, [0x99; 32])
            .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn transaction_end_payload_rejects_unknown_field() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x11; 16].to_vec())),
            (Value::U64(2), Value::Bytes([0x22; 16].to_vec())),
            (Value::U64(3), Value::U64(0)),
            (Value::U64(4), Value::U64(1000)),
            (Value::U64(5), Value::U64(5)),
            (Value::U64(6), Value::Bytes([0x99; 32].to_vec())),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = TransactionEndPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn transaction_end_record_id_is_deterministic() {
        let p = make_transaction_end();
        assert_eq!(p.record_id().unwrap(), p.record_id().unwrap());
    }

    // -------------------------------------------------------------------
    // record_ids_root tests (§9.21)
    // -------------------------------------------------------------------

    #[test]
    fn record_ids_root_empty() {
        let root = record_ids_root(&[]).unwrap();
        let expected = domain_hash("EternalCore:TransactionBatch:v1", &[]).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn record_ids_root_one() {
        let id = RecordId::new([0xaa; 32]);
        let root = record_ids_root(&[id]).unwrap();
        let expected = domain_hash("EternalCore:TransactionBatch:v1", &[0xaa; 32]).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn record_ids_root_two() {
        let id_a = RecordId::new([0xaa; 32]);
        let id_b = RecordId::new([0xbb; 32]);
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&[0xaa; 32]);
        concat.extend_from_slice(&[0xbb; 32]);
        let root = record_ids_root(&[id_a, id_b]).unwrap();
        let expected = domain_hash("EternalCore:TransactionBatch:v1", &concat).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn record_ids_root_deterministic() {
        let id_a = RecordId::new([0xaa; 32]);
        let id_b = RecordId::new([0xbb; 32]);
        assert_eq!(
            record_ids_root(&[id_a, id_b]).unwrap(),
            record_ids_root(&[id_a, id_b]).unwrap(),
        );
    }

    // -------------------------------------------------------------------
    // Type registry tests (§21)
    // -------------------------------------------------------------------

    #[test]
    fn type_registry_transaction_end_is_segment_only() {
        assert_eq!(type_allowed_container(11), Some(PhysicalContainer::Segment),);
    }

    #[test]
    fn type_registry_unknown_code_returns_none() {
        assert_eq!(type_allowed_container(0), None);
        assert_eq!(type_allowed_container(99), None);
    }

    // -------------------------------------------------------------------
    // StoreManifest tests (§11)
    // -------------------------------------------------------------------

    fn make_segment_descriptor() -> SegmentDescriptor {
        SegmentDescriptor::new(
            1,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
            "objects/active/segment-1-00112233-4455-6677-8899-aabbccddeeff.seg".to_string(),
        )
        .unwrap()
    }

    fn make_pack_descriptor() -> PackDescriptor {
        PackDescriptor::new(
            [0x67, 0x90, 0xa3, 0x1c, 0x4a, 0x14, 0xe4, 0xe7, 0x9f, 0xae, 0xd7, 0x2d, 0x0c, 0x38, 0xb1, 0xcd, 0xb8, 0xff, 0x82, 0x34, 0xa3, 0x69, 0x8b, 0x49, 0x21, 0x64, 0xb3, 0xa6, 0x89, 0x16, 0xec, 0x26],
            [0x30, 0x51, 0xb3, 0x21, 0xeb, 0x83, 0x54, 0xdc, 0x0f, 0x11, 0xde, 0x02, 0xa5, 0xb6, 0xee, 0x34, 0x39, 0xc0, 0xbd, 0x00, 0xcf, 0x0d, 0x71, 0x00, 0x07, 0x6e, 0x88, 0xb4, 0x22, 0x72, 0x7e, 0x77],
            "objects/packs/pack-6790a31c4a14e4e79faed72d0c38b1cdb8ff8234a3698b492164b3a68916ec26.pack".to_string(),
            "objects/packs/pack-6790a31c4a14e4e79faed72d0c38b1cdb8ff8234a3698b492164b3a68916ec26.idx".to_string(),
            1,
        )
        .unwrap()
    }

    fn make_store_manifest() -> StoreManifestPayload {
        let segment = make_segment_descriptor();
        let pack = make_pack_descriptor();
        StoreManifestPayload::new(
            1,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            RepositoryGenesisId::new([0xaa; 32]),
            1,
            None,
            segment,
            vec![pack],
            0,
        )
        .unwrap()
    }

    #[test]
    fn segment_descriptor_field_numbers() {
        let d = make_segment_descriptor();
        let value = Value::from(&d);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 2, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = SegmentDescriptor::try_from(value).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn segment_descriptor_roundtrip() {
        let d = make_segment_descriptor();
        let value = Value::from(&d);
        let decoded = SegmentDescriptor::try_from(value).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn segment_descriptor_rejects_not_a_map() {
        let err = SegmentDescriptor::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn segment_descriptor_rejects_unknown_field() {
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x11; 16].to_vec())),
            (Value::U64(2), Value::Text("path".to_string())),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = SegmentDescriptor::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn segment_descriptor_rejects_absolute_path() {
        let err = SegmentDescriptor::new(1, [0x11; 16], "/absolute/path".to_string()).unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn segment_descriptor_rejects_dotdot_path() {
        let err =
            SegmentDescriptor::new(1, [0x11; 16], "objects/../active/segment.seg".to_string())
                .unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn segment_descriptor_rejects_non_v1_prefix() {
        let err = SegmentDescriptor::new(1, [0x11; 16], "objects/packs/some.seg".to_string())
            .unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn segment_descriptor_rejects_wrong_generation_in_path() {
        let err = SegmentDescriptor::new(
            1,
            [0x11; 16],
            "objects/active/segment-2-11111111-1111-1111-1111-111111111111.seg".to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn segment_descriptor_rejects_wrong_uuid_in_path() {
        let err = SegmentDescriptor::new(
            1,
            [0x11; 16],
            "objects/active/segment-1-00000000-0000-0000-0000-000000000000.seg".to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn segment_descriptor_rejects_missing_seg_extension() {
        let err = SegmentDescriptor::new(
            1,
            [0x11; 16],
            "objects/active/segment-1-11111111-1111-1111-1111-111111111111.dat".to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::InvalidText { key: 2, .. }));
    }

    #[test]
    fn pack_descriptor_field_numbers() {
        let d = make_pack_descriptor();
        let value = Value::from(&d);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 4, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = PackDescriptor::try_from(value).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn pack_descriptor_roundtrip() {
        let d = make_pack_descriptor();
        let value = Value::from(&d);
        let decoded = PackDescriptor::try_from(value).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn pack_descriptor_rejects_not_a_map() {
        let err = PackDescriptor::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn pack_descriptor_rejects_unknown_field() {
        let pairs = vec![
            (Value::U64(0), Value::Bytes([0xaa; 32].to_vec())),
            (Value::U64(1), Value::Bytes([0xbb; 32].to_vec())),
            (Value::U64(2), Value::Text("p.pack".to_string())),
            (Value::U64(3), Value::Text("p.idx".to_string())),
            (Value::U64(4), Value::U64(1)),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = PackDescriptor::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn check_pack_descriptors_sorted_unique_accepts_sorted() {
        let a = PackDescriptor::new(
            [0x00; 32],
            [0x00; 32],
            "a.pack".to_string(),
            "a.idx".to_string(),
            1,
        )
        .unwrap();
        let b = PackDescriptor::new(
            [0x01; 32],
            [0x01; 32],
            "b.pack".to_string(),
            "b.idx".to_string(),
            1,
        )
        .unwrap();
        assert!(check_pack_descriptors_sorted_unique(&[a, b]).is_ok());
    }

    #[test]
    fn check_pack_descriptors_sorted_unique_rejects_unsorted() {
        let a = PackDescriptor::new(
            [0x01; 32],
            [0x01; 32],
            "a.pack".to_string(),
            "a.idx".to_string(),
            1,
        )
        .unwrap();
        let b = PackDescriptor::new(
            [0x00; 32],
            [0x00; 32],
            "b.pack".to_string(),
            "b.idx".to_string(),
            1,
        )
        .unwrap();
        let err = check_pack_descriptors_sorted_unique(&[a, b]).unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 6 }));
    }

    #[test]
    fn check_pack_descriptors_sorted_unique_rejects_duplicate() {
        let a = PackDescriptor::new(
            [0x00; 32],
            [0x00; 32],
            "a.pack".to_string(),
            "a.idx".to_string(),
            1,
        )
        .unwrap();
        let b = PackDescriptor::new(
            [0x00; 32],
            [0x00; 32],
            "b.pack".to_string(),
            "b.idx".to_string(),
            1,
        )
        .unwrap();
        let err = check_pack_descriptors_sorted_unique(&[a, b]).unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 6 }));
    }

    #[test]
    fn store_manifest_payload_field_numbers() {
        let p = make_store_manifest();
        let value = Value::from(&p);
        match &value {
            Value::Map(pairs) => {
                for (k, _) in pairs {
                    match k {
                        Value::U64(n) => assert!(*n <= 7, "unexpected key {n}"),
                        _ => panic!("non-uint key"),
                    }
                }
            }
            _ => panic!("not a map"),
        }
        let decoded = StoreManifestPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn store_manifest_payload_roundtrip() {
        let p = make_store_manifest();
        let value = Value::from(&p);
        let decoded = StoreManifestPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn store_manifest_payload_rejects_not_a_map() {
        let err = StoreManifestPayload::try_from(Value::U64(0)).unwrap_err();
        assert!(matches!(err, PayloadError::NotAMap));
    }

    #[test]
    fn store_manifest_payload_rejects_unknown_field() {
        let seg = make_segment_descriptor();
        let seg_value = Value::from(&seg);
        let pack = make_pack_descriptor();
        let pack_value = Value::from(&pack);
        let pairs = vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::Bytes([0x11; 16].to_vec())),
            (Value::U64(2), Value::Bytes([0xaa; 32].to_vec())),
            (Value::U64(3), Value::U64(1)),
            (Value::U64(4), Value::Null),
            (Value::U64(5), seg_value),
            (Value::U64(6), Value::Array(vec![pack_value])),
            (Value::U64(7), Value::I64(0)),
            (Value::U64(99), Value::U64(0)),
        ];
        let err = StoreManifestPayload::try_from(Value::Map(pairs)).unwrap_err();
        assert!(matches!(err, PayloadError::UnknownField(99)));
    }

    #[test]
    fn store_manifest_payload_rejects_bad_format_version() {
        let err = StoreManifestPayload::new(
            0,
            [0x11; 16],
            RepositoryGenesisId::new([0xaa; 32]),
            1,
            None,
            make_segment_descriptor(),
            vec![],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn store_manifest_payload_rejects_zero_generation() {
        let err = StoreManifestPayload::new(
            1,
            [0x11; 16],
            RepositoryGenesisId::new([0xaa; 32]),
            0,
            None,
            make_segment_descriptor(),
            vec![],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn store_manifest_payload_rejects_generation1_with_predecessor() {
        let err = StoreManifestPayload::new(
            1,
            [0x11; 16],
            RepositoryGenesisId::new([0xaa; 32]),
            1,
            Some(StoreManifestId::new([0xbb; 32])),
            make_segment_descriptor(),
            vec![],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn store_manifest_payload_rejects_generation2_without_predecessor() {
        let mut seg = make_segment_descriptor();
        seg.store_generation = 2;
        let err = StoreManifestPayload::new(
            1,
            [0x11; 16],
            RepositoryGenesisId::new([0xaa; 32]),
            2,
            None,
            seg,
            vec![],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn store_manifest_payload_rejects_segment_generation_mismatch() {
        let mut seg = make_segment_descriptor();
        seg.store_generation = 2;
        let err = StoreManifestPayload::new(
            1,
            [0x11; 16],
            RepositoryGenesisId::new([0xaa; 32]),
            1,
            None,
            seg,
            vec![],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 5, .. }));
    }

    #[test]
    fn store_manifest_payload_rejects_duplicate_packs() {
        let pack = make_pack_descriptor();
        let err = StoreManifestPayload::new(
            1,
            [0x11; 16],
            RepositoryGenesisId::new([0xaa; 32]),
            1,
            None,
            make_segment_descriptor(),
            vec![pack.clone(), pack],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsortedOrDuplicate { key: 6 }));
    }

    #[test]
    fn store_manifest_payload_roundtrip_with_predecessor() {
        let seg = SegmentDescriptor::new(
            2,
            [0x11; 16],
            "objects/active/segment-2-11111111-1111-1111-1111-111111111111.seg".to_string(),
        )
        .unwrap();
        let p = StoreManifestPayload::new(
            1,
            [0x11; 16],
            RepositoryGenesisId::new([0xaa; 32]),
            2,
            Some(StoreManifestId::new([0xbb; 32])),
            seg,
            vec![],
            100,
        )
        .unwrap();
        let value = Value::from(&p);
        let decoded = StoreManifestPayload::try_from(value).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn store_manifest_record_id_is_deterministic() {
        let p = make_store_manifest();
        assert_eq!(p.record_id().unwrap(), p.record_id().unwrap());
    }
}
