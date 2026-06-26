use crate::canonical::{CanonicalDecoder, DecodeError, Value};
use crate::domain::domain_hash;
use crate::ids::{KeyId, KeySlotLabel, RecordId, RefPattern, Signature};
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
        if wrapped_secret.len() < 16 {
            return Err(PayloadError::UnsupportedValue {
                key: 8,
                detail: format!(
                    "wrapped_secret must be at least 16 bytes (AEAD tag), got {}",
                    wrapped_secret.len()
                ),
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
        if !matches!(self.payload, Value::Map(_)) {
            return Err(SignedRecordError::PayloadNotAMap);
        }
        let envelope = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),        // envelope_version
            (Value::U64(1), self.payload.clone()), // payload
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

    #[test]
    fn signed_record_encode_rejects_non_map_payload() {
        let limits = FormatLimits::default();
        let record = SignedRecord::new(
            Value::U64(42),
            RecordId::new([0x11u8; 32]),
            KeyId::new([0x22u8; 32]),
            Signature::new([0x33u8; 64]),
        );
        let result = record.encode(&limits);
        assert_eq!(result, Err(SignedRecordError::PayloadNotAMap));
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
        PasswordKdfDescriptor::new(1, 0x13, vec![0xABu8; 32], 65536, 3, 1).unwrap()
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
        let err = PasswordKdfDescriptor::new(2, 0x13, vec![0xABu8; 32], 65536, 3, 1).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 0, .. }));
    }

    #[test]
    fn password_kdf_rejects_bad_version() {
        let err = PasswordKdfDescriptor::new(1, 10, vec![0xABu8; 32], 65536, 3, 1).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 1, .. }));
    }

    #[test]
    fn password_kdf_rejects_short_salt() {
        let err = PasswordKdfDescriptor::new(1, 0x13, vec![0xABu8; 15], 65536, 3, 1).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 2, .. }));
    }

    #[test]
    fn password_kdf_rejects_low_memory() {
        let err = PasswordKdfDescriptor::new(1, 0x13, vec![0xABu8; 32], 65535, 3, 1).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 3, .. }));
    }

    #[test]
    fn password_kdf_rejects_zero_iterations() {
        let err = PasswordKdfDescriptor::new(1, 0x13, vec![0xABu8; 32], 65536, 0, 1).unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 4, .. }));
    }

    #[test]
    fn password_kdf_rejects_bad_parallelism() {
        let err = PasswordKdfDescriptor::new(1, 0x13, vec![0xABu8; 32], 65536, 3, 0).unwrap_err();
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
            (Value::U64(2), Value::Bytes(vec![0xABu8; 32])),
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
            (Value::U64(2), Value::Bytes(vec![0xABu8; 32])),
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
            vec![0xAAu8; 15], // only 15 bytes, less than 16-byte AEAD tag
            0,
        )
        .unwrap_err();
        assert!(matches!(err, PayloadError::UnsupportedValue { key: 8, .. }));
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
}
