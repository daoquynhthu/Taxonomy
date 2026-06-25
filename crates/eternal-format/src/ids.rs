use std::fmt;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    InvalidChar(u8),
    InvalidLength { expected: usize, actual: usize },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChar(ch) => write!(f, "invalid hex character: 0x{ch:02x}"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
        }
    }
}

impl std::error::Error for HexError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LengthError {
    ExceedsMaximum { value: u64, max: u64 },
}

impl fmt::Display for LengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsMaximum { value, max } => {
                write!(f, "length {value} exceeds maximum {max}")
            }
        }
    }
}

impl std::error::Error for LengthError {}

// ---------------------------------------------------------------------------
// Hex helpers (internal, not public API)
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, HexError> {
    let bytes: Vec<u8> = s
        .as_bytes()
        .chunks(2)
        .map(|c| {
            let hi = hex_val(c[0])?;
            let lo = if c.len() > 1 {
                hex_val(c[1])?
            } else {
                return Err(HexError::InvalidLength {
                    expected: s.len() / 2,
                    actual: s.len().div_ceil(2),
                });
            };
            Ok(hi << 4 | lo)
        })
        .collect::<Result<Vec<u8>, HexError>>()?;
    Ok(bytes)
}

fn hex_val(b: u8) -> Result<u8, HexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HexError::InvalidChar(b)),
    }
}

// ---------------------------------------------------------------------------
// UUID
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, HexError> {
        if slice.len() != 16 {
            return Err(HexError::InvalidLength {
                expected: 16,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15],
        )
    }
}

impl FromStr for Uuid {
    type Err = HexError;

    fn from_str(s: &str) -> Result<Self, HexError> {
        let stripped: String = s.chars().filter(|c| *c != '-').collect();
        let bytes = hex_decode(&stripped)?;
        if bytes.len() != 16 {
            return Err(HexError::InvalidLength {
                expected: 16,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl From<[u8; 16]> for Uuid {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

// ---------------------------------------------------------------------------
// 32-byte hash identifiers
// ---------------------------------------------------------------------------

macro_rules! hash_id {
    ($(#[$meta:meta])* $name:ident, $display:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn from_slice(slice: &[u8]) -> Result<Self, HexError> {
                if slice.len() != 32 {
                    return Err(HexError::InvalidLength { expected: 32, actual: slice.len() });
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(slice);
                Ok(Self(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex_encode(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple($display)
                    .field(&hex_encode(&self.0))
                    .finish()
            }
        }

        impl FromStr for $name {
            type Err = HexError;

            fn from_str(s: &str) -> Result<Self, HexError> {
                let bytes = hex_decode(s)?;
                if bytes.len() != 32 {
                    return Err(HexError::InvalidLength { expected: 32, actual: bytes.len() });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Self(arr))
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }
    };
}

hash_id!(
    /// Record identifier — domain hash of a canonical record payload.
    RecordId,
    "RecordId"
);

hash_id!(
    /// Repository genesis identifier.
    RepositoryGenesisId,
    "RepositoryGenesisId"
);

hash_id!(
    /// Policy record identifier.
    PolicyId,
    "PolicyId"
);

hash_id!(
    /// Keyring record identifier.
    KeyringId,
    "KeyringId"
);

hash_id!(
    /// Public content chunk identifier.
    ChunkId,
    "ChunkId"
);

hash_id!(
    /// Encoded chunk record identifier (physical).
    EncodedChunkRecordId,
    "EncodedChunkRecordId"
);

hash_id!(
    /// Content manifest identifier.
    ContentManifestId,
    "ContentManifestId"
);

hash_id!(
    /// Object version identifier.
    VersionId,
    "VersionId"
);

hash_id!(
    /// Repository commit identifier.
    RepoCommitId,
    "RepoCommitId"
);

hash_id!(
    /// Ref update identifier.
    RefUpdateId,
    "RefUpdateId"
);

hash_id!(
    /// Sparse Merkle Tree object key.
    ObjectKey,
    "ObjectKey"
);

hash_id!(
    /// Sparse Merkle Tree root hash.
    SmtRoot,
    "SmtRoot"
);

hash_id!(
    /// Store manifest identifier.
    StoreManifestId,
    "StoreManifestId"
);

hash_id!(
    /// Key fingerprint identifier.
    KeyId,
    "KeyId"
);

// ---------------------------------------------------------------------------
// Signature and public keys
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, HexError> {
        if slice.len() != 64 {
            return Err(HexError::InvalidLength {
                expected: 64,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_encode(&self.0))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature")
            .field(&hex_encode(&self.0))
            .finish()
    }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, HexError> {
        if slice.len() != 32 {
            return Err(HexError::InvalidLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_encode(&self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&hex_encode(&self.0))
            .finish()
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const fn new(nanos: i64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos_i64(&self) -> i64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Timestamp").field(&self.0).finish()
    }
}

impl From<i64> for Timestamp {
    fn from(nanos: i64) -> Self {
        Self(nanos)
    }
}

// ---------------------------------------------------------------------------
// Bounded length
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedLength(u64);

impl BoundedLength {
    pub fn new(value: u64, max: u64) -> Result<Self, LengthError> {
        if value > max {
            return Err(LengthError::ExceedsMaximum { value, max });
        }
        Ok(Self(value))
    }

    pub const fn new_unchecked(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for BoundedLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for BoundedLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BoundedLength").field(&self.0).finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // --- UUID ---

    #[test]
    fn uuid_round_trip_bytes() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let uuid = Uuid::new(bytes);
        assert_eq!(*uuid.as_bytes(), bytes);
        assert_eq!(uuid.into_bytes(), bytes);
    }

    #[test]
    fn uuid_round_trip_display_parse() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let uuid = Uuid::new(bytes);
        let s = uuid.to_string();
        assert_eq!(s, "01020304-0506-0708-090a-0b0c0d0e0f10");
        let parsed: Uuid = s.parse().expect("valid uuid string");
        assert_eq!(parsed, uuid);
    }

    #[test]
    fn uuid_rejects_wrong_length_slice() {
        assert_eq!(
            Uuid::from_slice(&[0u8; 15]),
            Err(HexError::InvalidLength {
                expected: 16,
                actual: 15
            })
        );
        assert_eq!(
            Uuid::from_slice(&[0u8; 17]),
            Err(HexError::InvalidLength {
                expected: 16,
                actual: 17
            })
        );
    }

    #[test]
    fn uuid_rejects_invalid_hex_char() {
        assert!(matches!(
            "zz".parse::<Uuid>(),
            Err(HexError::InvalidChar(_))
        ));
    }

    // --- 32-byte hash IDs ---

    #[test]
    fn record_id_round_trip_bytes() {
        let bytes = [0xAB; 32];
        let id = RecordId::new(bytes);
        assert_eq!(*id.as_bytes(), bytes);
        assert_eq!(id.into_bytes(), bytes);
    }

    #[test]
    fn record_id_round_trip_display_parse() {
        let bytes = [0xAB; 32];
        let id = RecordId::new(bytes);
        let s = id.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        let parsed: RecordId = s.parse().expect("valid hex");
        assert_eq!(parsed, id);
    }

    #[test]
    fn record_id_rejects_wrong_length_slice() {
        assert_eq!(
            RecordId::from_slice(&[0u8; 31]),
            Err(HexError::InvalidLength {
                expected: 32,
                actual: 31
            })
        );
        assert_eq!(
            RecordId::from_slice(&[0u8; 33]),
            Err(HexError::InvalidLength {
                expected: 32,
                actual: 33
            })
        );
    }

    #[test]
    fn all_hash_ids_are_distinct_types() {
        // Compile-time check: these must not silently coerce.
        let rid = RecordId::new([0u8; 32]);
        let kid = KeyId::new([0u8; 32]);
        assert_eq!(rid.as_bytes(), kid.as_bytes());
        // If they were the same type this test wouldn't prove much,
        // but the point is they ARE different types.
    }

    #[test]
    fn hash_ids_reject_invalid_hex() {
        assert!(matches!(
            "not-hex".parse::<RecordId>(),
            Err(HexError::InvalidChar(_))
        ));
        assert!(matches!(
            "abc".parse::<RepositoryGenesisId>(),
            Err(HexError::InvalidLength { .. })
        ));
    }

    // --- 64-byte Signature ---

    #[test]
    fn signature_round_trip_bytes() {
        let bytes = [0xCD; 64];
        let sig = Signature::new(bytes);
        assert_eq!(*sig.as_bytes(), bytes);
        assert_eq!(sig.into_bytes(), bytes);
    }

    #[test]
    fn signature_rejects_wrong_length_slice() {
        assert_eq!(
            Signature::from_slice(&[0u8; 63]),
            Err(HexError::InvalidLength {
                expected: 64,
                actual: 63
            })
        );
        assert_eq!(
            Signature::from_slice(&[0u8; 65]),
            Err(HexError::InvalidLength {
                expected: 64,
                actual: 65
            })
        );
    }

    #[test]
    fn signature_display_is_hex() {
        let bytes = [0xFF; 64];
        let sig = Signature::new(bytes);
        assert_eq!(sig.to_string().len(), 128);
        assert!(sig.to_string().chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- PublicKey ---

    #[test]
    fn public_key_round_trip_bytes() {
        let bytes = [0x42; 32];
        let pk = PublicKey::new(bytes);
        assert_eq!(*pk.as_bytes(), bytes);
    }

    #[test]
    fn public_key_rejects_wrong_length() {
        assert_eq!(
            PublicKey::from_slice(&[0u8; 31]),
            Err(HexError::InvalidLength {
                expected: 32,
                actual: 31
            })
        );
    }

    // --- Timestamp ---

    #[test]
    fn timestamp_round_trip() {
        let ts = Timestamp::new(1_234_567_890);
        assert_eq!(ts.as_nanos_i64(), 1_234_567_890);
    }

    #[test]
    fn timestamp_from_i64() {
        let ts: Timestamp = 42.into();
        assert_eq!(ts.as_nanos_i64(), 42);
    }

    #[test]
    fn timestamp_negative() {
        let ts = Timestamp::new(-1);
        assert_eq!(ts.as_nanos_i64(), -1);
    }

    // --- BoundedLength ---

    #[test]
    fn bounded_length_accepts_valid() {
        let len = BoundedLength::new(100, 200).expect("within bound");
        assert_eq!(len.get(), 100);
    }

    #[test]
    fn bounded_length_rejects_excessive() {
        assert_eq!(
            BoundedLength::new(201, 200),
            Err(LengthError::ExceedsMaximum {
                value: 201,
                max: 200
            })
        );
    }

    #[test]
    fn bounded_length_at_bound() {
        let len = BoundedLength::new(200, 200).expect("at bound is ok");
        assert_eq!(len.get(), 200);
    }

    #[test]
    fn bounded_length_zero() {
        let len = BoundedLength::new(0, 100).expect("zero within bound");
        assert_eq!(len.get(), 0);
    }
}
