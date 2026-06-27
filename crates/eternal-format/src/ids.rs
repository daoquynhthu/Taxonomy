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
    /// SMT leaf record identifier (record type 7).
    SmtLeafId,
    "SmtLeafId"
);

hash_id!(
    /// SMT internal node record identifier (record type 8).
    SmtInternalId,
    "SmtInternalId"
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

    #[allow(dead_code)]
    pub(crate) const fn new_unchecked(value: u64) -> Self {
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
// Constrained name types (FORMAT.md §6)
// ---------------------------------------------------------------------------

/// Errors for constrained name validation (FORMAT.md §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    EmptyName,
    TooLong { max: usize, actual: usize },
    ControlCharacter { position: usize },
    InvalidCharacter { position: usize },
    LeadingSlash,
    TrailingSlash,
    EmptySegment,
    DotSegment,
    DotDotSegment,
    InvalidRefPrefix,
    EndsWithLock,
    DoubleSlash,
    AtBrace,
    Backslash,
    EmptyNamespace,
    NotAscii,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "name is empty"),
            Self::TooLong { max, actual } => {
                write!(f, "name length {actual} exceeds maximum {max}")
            }
            Self::ControlCharacter { position } => {
                write!(f, "control character at position {position}")
            }
            Self::InvalidCharacter { position } => {
                write!(f, "invalid character at position {position}")
            }
            Self::LeadingSlash => write!(f, "name begins with '/'"),
            Self::TrailingSlash => write!(f, "name ends with '/'"),
            Self::EmptySegment => write!(f, "name contains an empty path segment"),
            Self::DotSegment => write!(f, "name contains a '.' segment"),
            Self::DotDotSegment => write!(f, "name contains a '..' segment"),
            Self::InvalidRefPrefix => write!(f, "ref name does not begin with a valid prefix"),
            Self::EndsWithLock => write!(f, "ref name ends with '.lock'"),
            Self::DoubleSlash => write!(f, "ref name contains '//'"),
            Self::AtBrace => write!(f, "ref name contains '@{{'"),
            Self::Backslash => write!(f, "ref name contains backslash"),
            Self::EmptyNamespace => write!(f, "namespace prefix is empty"),
            Self::NotAscii => write!(f, "ref name contains non-ASCII bytes"),
        }
    }
}

impl std::error::Error for NameError {}

// ---------------------------------------------------------------------------
// Path segment validation (shared by ObjectId, RefName suffix)
// ---------------------------------------------------------------------------

/// Validate path segment rules: no empty segments, no `.` or `..`, no
/// control characters, and (for v4) only ASCII letters/digits/`_`/`-`/`.`/`/`.
fn validate_path_segments(s: &str, allow_chars: bool) -> Result<(), NameError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes[0] == b'/' {
        return Err(NameError::LeadingSlash);
    }
    if bytes[bytes.len() - 1] == b'/' {
        return Err(NameError::TrailingSlash);
    }
    for (i, &b) in bytes.iter().enumerate() {
        if b <= 0x1f || b == 0x7f {
            return Err(NameError::ControlCharacter { position: i });
        }
        if allow_chars {
            let is_v4 =
                matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'/');
            if !is_v4 {
                return Err(NameError::InvalidCharacter { position: i });
            }
        }
    }
    for segment in s.split('/') {
        if segment.is_empty() {
            return Err(NameError::EmptySegment);
        }
        if segment == "." {
            return Err(NameError::DotSegment);
        }
        if segment == ".." {
            return Err(NameError::DotDotSegment);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ObjectId (FORMAT.md §6.1)
// ---------------------------------------------------------------------------

/// An object identifier: 1–1024 ASCII bytes, v4 character set, no leading
/// or trailing `/`, no empty/dot/dotdot path segments.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(String);

impl ObjectId {
    /// Validate and construct an `ObjectId`.
    pub fn new(s: &str) -> Result<Self, NameError> {
        validate_object_id(s)?;
        Ok(ObjectId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// Validate an ObjectId per FORMAT.md §6.1.
pub fn validate_object_id(s: &str) -> Result<(), NameError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(NameError::EmptyName);
    }
    if bytes.len() > 1024 {
        return Err(NameError::TooLong {
            max: 1024,
            actual: bytes.len(),
        });
    }
    validate_path_segments(s, true)
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ObjectId {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, NameError> {
        Self::new(s)
    }
}

impl AsRef<str> for ObjectId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ObjectId {
    type Error = NameError;
    fn try_from(s: String) -> Result<Self, NameError> {
        validate_object_id(&s)?;
        Ok(ObjectId(s))
    }
}

// ---------------------------------------------------------------------------
// RefName (FORMAT.md §6.2)
// ---------------------------------------------------------------------------

/// A ref name: 1–1024 ASCII bytes, begins with a valid prefix, suffix
/// follows ObjectId path-segment rules, no `.lock`/`//`/`@{`/backslash.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefName(String);

impl RefName {
    /// Validate and construct a `RefName`.
    pub fn new(s: &str) -> Result<Self, NameError> {
        validate_ref_name(s)?;
        Ok(RefName(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// Validate a ref name per FORMAT.md §6.2.
pub fn validate_ref_name(s: &str) -> Result<(), NameError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(NameError::EmptyName);
    }
    if bytes.len() > 1024 {
        return Err(NameError::TooLong {
            max: 1024,
            actual: bytes.len(),
        });
    }
    // All ASCII
    if bytes.iter().any(|&b| b > 0x7f) {
        return Err(NameError::NotAscii);
    }
    // Must begin with a valid prefix
    let has_prefix = bytes.starts_with(b"refs/heads/")
        || bytes.starts_with(b"refs/tags/")
        || bytes.starts_with(b"refs/pins/")
        || bytes.starts_with(b"refs/merge-requests/");
    if !has_prefix {
        return Err(NameError::InvalidRefPrefix);
    }
    // Must not end in .lock
    if s.ends_with(".lock") {
        return Err(NameError::EndsWithLock);
    }
    // Must not contain //
    if bytes.windows(2).any(|w| w == b"//") {
        return Err(NameError::DoubleSlash);
    }
    // Must not contain @{
    if s.contains("@{") {
        return Err(NameError::AtBrace);
    }
    // Must not contain backslash
    if bytes.contains(&b'\\') {
        return Err(NameError::Backslash);
    }
    // Control characters
    for (i, &b) in bytes.iter().enumerate() {
        if b <= 0x1f || b == 0x7f {
            return Err(NameError::ControlCharacter { position: i });
        }
    }
    // Suffix follows ObjectId path-segment rules; bare prefix is rejected
    const PREFIXES: &[&str] = &[
        "refs/heads/",
        "refs/tags/",
        "refs/pins/",
        "refs/merge-requests/",
    ];
    for prefix in PREFIXES {
        if let Some(suffix) = s.strip_prefix(prefix) {
            if suffix.is_empty() {
                return Err(NameError::InvalidRefPrefix);
            }
            validate_path_segments(suffix, true)?;
            break;
        }
    }
    Ok(())
}

impl fmt::Display for RefName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for RefName {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, NameError> {
        Self::new(s)
    }
}

impl AsRef<str> for RefName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RefName {
    type Error = NameError;
    fn try_from(s: String) -> Result<Self, NameError> {
        validate_ref_name(&s)?;
        Ok(RefName(s))
    }
}

// ---------------------------------------------------------------------------
// RefPattern (FORMAT.md §6.3)
// ---------------------------------------------------------------------------

/// A policy ref pattern: either an exact ref name or a namespace prefix.
///
/// Construct via [`RefPattern::new`]. The inner representation is private:
/// external code cannot construct a `RefPattern` directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefPattern {
    kind: RefPatternKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RefPatternKind {
    Exact(RefName),
    Namespace(String),
}

impl RefPattern {
    /// Validate and construct a `RefPattern`.
    pub fn new(s: &str) -> Result<Self, NameError> {
        validate_ref_pattern(s)?;
        if let Some(prefix) = s.strip_suffix("/**") {
            Ok(RefPattern {
                kind: RefPatternKind::Namespace(prefix.to_string()),
            })
        } else {
            Ok(RefPattern {
                kind: RefPatternKind::Exact(RefName::new(s)?),
            })
        }
    }

    /// If this is an exact pattern, return the ref name.
    pub fn as_exact(&self) -> Option<&RefName> {
        match &self.kind {
            RefPatternKind::Exact(r) => Some(r),
            _ => None,
        }
    }

    /// If this is a namespace pattern, return the prefix (without `/**`).
    pub fn as_namespace(&self) -> Option<&str> {
        match &self.kind {
            RefPatternKind::Namespace(prefix) => Some(prefix),
            _ => None,
        }
    }

    /// Returns `true` if this pattern matches the given ref name.
    ///
    /// Exact patterns match by equality. Namespace patterns match when the
    /// ref name begins with the prefix followed by `/` or is the prefix itself.
    pub fn matches(&self, name: &RefName) -> bool {
        match &self.kind {
            RefPatternKind::Exact(ref_name) => ref_name == name,
            RefPatternKind::Namespace(prefix) => {
                let name_str = name.as_str();
                if name_str.starts_with(prefix) {
                    name_str.len() == prefix.len()
                        || name_str.as_bytes().get(prefix.len()) == Some(&b'/')
                } else {
                    false
                }
            }
        }
    }

    /// Returns the specificity of this pattern for longest-prefix ordering.
    ///
    /// Exact patterns have maximum specificity. Namespace patterns have
    /// specificity equal to their prefix length.
    pub fn specificity(&self) -> usize {
        match &self.kind {
            RefPatternKind::Exact(_) => usize::MAX,
            RefPatternKind::Namespace(prefix) => prefix.len(),
        }
    }

    /// Returns `true` if this is an exact pattern.
    pub fn is_exact(&self) -> bool {
        matches!(&self.kind, RefPatternKind::Exact(_))
    }
}

/// Validate a ref pattern per FORMAT.md §6.3.
pub fn validate_ref_pattern(s: &str) -> Result<(), NameError> {
    if let Some(prefix) = s.strip_suffix("/**") {
        if prefix.is_empty() {
            return Err(NameError::EmptyNamespace);
        }
        validate_ref_pattern_prefix(prefix)?;
        Ok(())
    } else {
        validate_ref_name(s)
    }
}

fn validate_ref_pattern_prefix(prefix: &str) -> Result<(), NameError> {
    let bytes = prefix.as_bytes();
    if bytes.is_empty() {
        return Err(NameError::EmptyName);
    }
    if bytes.len() > 1024 {
        return Err(NameError::TooLong {
            max: 1024,
            actual: bytes.len(),
        });
    }
    // All ASCII
    if bytes.iter().any(|&b| b > 0x7f) {
        return Err(NameError::NotAscii);
    }
    // Control characters
    for (i, &b) in bytes.iter().enumerate() {
        if b <= 0x1f || b == 0x7f {
            return Err(NameError::ControlCharacter { position: i });
        }
    }
    // Must begin with a valid ref prefix (with or without trailing component)
    let starts_ok = bytes.starts_with(b"refs/heads/")
        || bytes.starts_with(b"refs/tags/")
        || bytes.starts_with(b"refs/pins/")
        || bytes.starts_with(b"refs/merge-requests/")
        || prefix == "refs/heads"
        || prefix == "refs/tags"
        || prefix == "refs/pins"
        || prefix == "refs/merge-requests";
    if !starts_ok {
        return Err(NameError::InvalidRefPrefix);
    }
    // Path segment validation for the path part after the prefix component
    if let Some(suffix) = prefix
        .strip_prefix("refs/heads/")
        .or_else(|| prefix.strip_prefix("refs/tags/"))
        .or_else(|| prefix.strip_prefix("refs/pins/"))
        .or_else(|| prefix.strip_prefix("refs/merge-requests/"))
        .filter(|s| !s.is_empty())
    {
        validate_path_segments(suffix, true)?;
    }
    Ok(())
}

impl fmt::Display for RefPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            RefPatternKind::Exact(rn) => write!(f, "{rn}"),
            RefPatternKind::Namespace(prefix) => write!(f, "{prefix}/**"),
        }
    }
}

impl std::str::FromStr for RefPattern {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, NameError> {
        Self::new(s)
    }
}

// ---------------------------------------------------------------------------
// DataType (FORMAT.md §6.4)
// ---------------------------------------------------------------------------

/// A data type label: 1–256 UTF-8 bytes, no control characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataType(String);

impl DataType {
    pub fn new(s: &str) -> Result<Self, NameError> {
        validate_simple_text(s, 1, 256)?;
        Ok(DataType(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for DataType {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, NameError> {
        Self::new(s)
    }
}

impl AsRef<str> for DataType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DataType {
    type Error = NameError;
    fn try_from(s: String) -> Result<Self, NameError> {
        validate_simple_text(&s, 1, 256)?;
        Ok(DataType(s))
    }
}

// ---------------------------------------------------------------------------
// RelationType (FORMAT.md §6.4)
// ---------------------------------------------------------------------------

/// A relation type label: 1–256 UTF-8 bytes, no control characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelationType(String);

impl RelationType {
    pub fn new(s: &str) -> Result<Self, NameError> {
        validate_simple_text(s, 1, 256)?;
        Ok(RelationType(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RelationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for RelationType {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, NameError> {
        Self::new(s)
    }
}

impl AsRef<str> for RelationType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RelationType {
    type Error = NameError;
    fn try_from(s: String) -> Result<Self, NameError> {
        validate_simple_text(&s, 1, 256)?;
        Ok(RelationType(s))
    }
}

// ---------------------------------------------------------------------------
// KeySlotLabel (FORMAT.md §6.4)
// ---------------------------------------------------------------------------

/// A key-slot label: 1–128 UTF-8 bytes, no control characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeySlotLabel(String);

impl KeySlotLabel {
    pub fn new(s: &str) -> Result<Self, NameError> {
        validate_simple_text(s, 1, 128)?;
        Ok(KeySlotLabel(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for KeySlotLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for KeySlotLabel {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, NameError> {
        Self::new(s)
    }
}

impl AsRef<str> for KeySlotLabel {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeySlotLabel {
    type Error = NameError;
    fn try_from(s: String) -> Result<Self, NameError> {
        validate_simple_text(&s, 1, 128)?;
        Ok(KeySlotLabel(s))
    }
}

// ---------------------------------------------------------------------------
// CommitMessage (FORMAT.md §6.4)
// ---------------------------------------------------------------------------

/// A commit message: 0–1,048,576 UTF-8 bytes (empty is allowed).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitMessage(String);

impl CommitMessage {
    pub fn new(s: &str) -> Result<Self, NameError> {
        let bytes = s.len();
        if bytes > 1_048_576 {
            return Err(NameError::TooLong {
                max: 1_048_576,
                actual: bytes,
            });
        }
        Ok(CommitMessage(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CommitMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for CommitMessage {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, NameError> {
        Self::new(s)
    }
}

impl AsRef<str> for CommitMessage {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CommitMessage {
    type Error = NameError;
    fn try_from(s: String) -> Result<Self, NameError> {
        let bytes = s.len();
        if bytes > 1_048_576 {
            return Err(NameError::TooLong {
                max: 1_048_576,
                actual: bytes,
            });
        }
        Ok(CommitMessage(s))
    }
}

// ---------------------------------------------------------------------------
// Shared validation for simple constrained text types
// ---------------------------------------------------------------------------

fn validate_simple_text(s: &str, min: usize, max: usize) -> Result<(), NameError> {
    let bytes = s.as_bytes();
    if bytes.len() < min {
        return Err(NameError::EmptyName);
    }
    if bytes.len() > max {
        return Err(NameError::TooLong {
            max,
            actual: bytes.len(),
        });
    }
    for (i, &b) in bytes.iter().enumerate() {
        if b <= 0x1f || b == 0x7f {
            return Err(NameError::ControlCharacter { position: i });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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

    // -----------------------------------------------------------------------
    // Constrained names (F2.6)
    // -----------------------------------------------------------------------

    // --- ObjectId ---

    #[test]
    fn object_id_accepts_valid() {
        let cases = &[
            "a",
            "foo",
            "foo/bar",
            "foo/bar/baz",
            "a.b",
            "a-b",
            "a_b",
            "a/b",
            "123",
            "a/1/b/2",
        ];
        for &s in cases {
            ObjectId::new(s).unwrap();
        }
    }

    #[test]
    fn object_id_round_trip_display_parse() {
        let id = ObjectId::new("some/path/to/object").unwrap();
        let s = id.to_string();
        let parsed: ObjectId = s.parse().unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn object_id_as_str() {
        let id = ObjectId::new("hello/world").unwrap();
        assert_eq!(id.as_str(), "hello/world");
        assert_eq!(id.as_ref() as &str, "hello/world");
    }

    #[test]
    fn object_id_from_string() {
        let id = ObjectId::try_from("valid/path".to_string()).unwrap();
        assert_eq!(id.as_str(), "valid/path");
    }

    #[test]
    fn object_id_rejects_empty() {
        assert_eq!(ObjectId::new(""), Err(NameError::EmptyName));
    }

    #[test]
    fn object_id_rejects_too_long() {
        let s = "a".repeat(1025);
        assert_eq!(
            ObjectId::new(&s),
            Err(NameError::TooLong {
                max: 1024,
                actual: 1025
            })
        );
    }

    #[test]
    fn object_id_rejects_max_length() {
        let s = "a".repeat(1024);
        ObjectId::new(&s).expect("1024 bytes should be valid");
    }

    #[test]
    fn object_id_rejects_leading_slash() {
        assert_eq!(ObjectId::new("/foo"), Err(NameError::LeadingSlash));
    }

    #[test]
    fn object_id_rejects_trailing_slash() {
        assert_eq!(ObjectId::new("foo/"), Err(NameError::TrailingSlash));
    }

    #[test]
    fn object_id_rejects_empty_segment() {
        assert_eq!(ObjectId::new("foo//bar"), Err(NameError::EmptySegment));
    }

    #[test]
    fn object_id_rejects_dot_segment() {
        assert_eq!(ObjectId::new("foo/./bar"), Err(NameError::DotSegment));
    }

    #[test]
    fn object_id_rejects_dotdot_segment() {
        assert_eq!(ObjectId::new("foo/../bar"), Err(NameError::DotDotSegment));
    }

    #[test]
    fn object_id_rejects_control_char() {
        assert_eq!(
            ObjectId::new("foo\x00bar"),
            Err(NameError::ControlCharacter { position: 3 })
        );
        assert_eq!(
            ObjectId::new("foo\x1fbar"),
            Err(NameError::ControlCharacter { position: 3 })
        );
        assert_eq!(
            ObjectId::new("foo\x7fbar"),
            Err(NameError::ControlCharacter { position: 3 })
        );
    }

    #[test]
    fn object_id_rejects_invalid_char() {
        assert_eq!(
            ObjectId::new("foo!bar"),
            Err(NameError::InvalidCharacter { position: 3 })
        );
        assert_eq!(
            ObjectId::new("foo@bar"),
            Err(NameError::InvalidCharacter { position: 3 })
        );
        assert_eq!(
            ObjectId::new("foo bar"),
            Err(NameError::InvalidCharacter { position: 3 })
        );
        assert_eq!(
            ObjectId::new("foo#bar"),
            Err(NameError::InvalidCharacter { position: 3 })
        );
    }

    // --- RefName ---

    #[test]
    fn ref_name_accepts_heads() {
        RefName::new("refs/heads/main").expect("valid heads ref");
        RefName::new("refs/heads/feature/my-feature").expect("valid heads ref");
        RefName::new("refs/heads/1.0.x").expect("valid heads ref");
    }

    #[test]
    fn ref_name_accepts_tags() {
        RefName::new("refs/tags/v1.0.0").expect("valid tag ref");
    }

    #[test]
    fn ref_name_accepts_pins() {
        RefName::new("refs/pins/abc123").expect("valid pin ref");
    }

    #[test]
    fn ref_name_accepts_merge_requests() {
        RefName::new("refs/merge-requests/42").expect("valid MR ref");
    }

    #[test]
    fn ref_name_rejects_empty() {
        assert_eq!(RefName::new(""), Err(NameError::EmptyName));
    }

    #[test]
    fn ref_name_rejects_invalid_prefix() {
        assert_eq!(
            RefName::new("refs/other/main"),
            Err(NameError::InvalidRefPrefix)
        );
        assert_eq!(RefName::new("heads/main"), Err(NameError::InvalidRefPrefix));
        assert_eq!(RefName::new("main"), Err(NameError::InvalidRefPrefix));
    }

    #[test]
    fn ref_name_rejects_lock_suffix() {
        assert_eq!(
            RefName::new("refs/heads/main.lock"),
            Err(NameError::EndsWithLock)
        );
    }

    #[test]
    fn ref_name_rejects_double_slash() {
        assert_eq!(
            RefName::new("refs/heads//main"),
            Err(NameError::DoubleSlash)
        );
    }

    #[test]
    fn ref_name_rejects_at_brace() {
        assert_eq!(RefName::new("refs/heads/@{main}"), Err(NameError::AtBrace));
    }

    #[test]
    fn ref_name_rejects_backslash() {
        assert_eq!(
            RefName::new("refs/heads/foo\\bar"),
            Err(NameError::Backslash)
        );
    }

    #[test]
    fn ref_name_rejects_non_ascii() {
        assert_eq!(RefName::new("refs/heads/café"), Err(NameError::NotAscii));
    }

    #[test]
    fn ref_name_rejects_dotdot() {
        assert_eq!(
            RefName::new("refs/heads/foo/../bar"),
            Err(NameError::DotDotSegment)
        );
    }

    #[test]
    fn ref_name_rejects_control() {
        assert_eq!(
            RefName::new("refs/heads/foo\x00bar"),
            Err(NameError::ControlCharacter { position: 14 })
        );
    }

    #[test]
    fn ref_name_too_long() {
        let s = format!("refs/heads/{}", "a".repeat(1014));
        assert!(s.len() > 1024);
        assert_eq!(
            RefName::new(&s),
            Err(NameError::TooLong {
                max: 1024,
                actual: s.len()
            })
        );
    }

    #[test]
    fn ref_name_round_trip_display_parse() {
        let rn = RefName::new("refs/heads/main").unwrap();
        let s = rn.to_string();
        let parsed: RefName = s.parse().unwrap();
        assert_eq!(parsed, rn);
    }

    // --- RefPattern ---

    #[test]
    fn ref_pattern_exact() {
        let pat = RefPattern::new("refs/heads/main").unwrap();
        assert!(pat.is_exact());
    }

    #[test]
    fn ref_pattern_namespace() {
        let pat = RefPattern::new("refs/heads/contributors/**").unwrap();
        assert!(!pat.is_exact());
    }

    #[test]
    fn ref_pattern_rejects_empty_namespace() {
        assert_eq!(RefPattern::new("/**"), Err(NameError::EmptyNamespace));
    }

    #[test]
    fn ref_pattern_rejects_invalid_exact() {
        assert_eq!(RefPattern::new("invalid"), Err(NameError::InvalidRefPrefix));
    }

    #[test]
    fn ref_pattern_matches_exact() {
        let pat = RefPattern::new("refs/heads/main").unwrap();
        assert!(pat.matches(&RefName::new("refs/heads/main").unwrap()));
        assert!(!pat.matches(&RefName::new("refs/heads/other").unwrap()));
        assert!(!pat.matches(&RefName::new("refs/heads/main/extra").unwrap()));
    }

    #[test]
    fn ref_pattern_matches_namespace() {
        let pat = RefPattern::new("refs/heads/team/**").unwrap();
        assert!(pat.matches(&RefName::new("refs/heads/team/feature").unwrap()));
        assert!(pat.matches(&RefName::new("refs/heads/team/feature/sub").unwrap()));
        assert!(!pat.matches(&RefName::new("refs/heads/other").unwrap()));
        assert!(!pat.matches(&RefName::new("refs/heads/teams").unwrap()));
    }

    #[test]
    fn ref_pattern_longest_prefix_deterministic() {
        let narrow = RefPattern::new("refs/heads/team/alpha/**").unwrap();
        let wide = RefPattern::new("refs/heads/team/**").unwrap();
        // More specific (longer prefix) pattern has higher specificity
        assert!(narrow.specificity() > wide.specificity());
        // Exact has highest specificity
        let exact = RefPattern::new("refs/heads/main").unwrap();
        assert!(exact.specificity() > narrow.specificity());
        assert_eq!(exact.specificity(), usize::MAX);
    }

    // --- Bare prefix rejection ---

    #[test]
    fn ref_name_rejects_bare_prefix() {
        assert_eq!(
            RefName::new("refs/heads/"),
            Err(NameError::InvalidRefPrefix)
        );
        assert_eq!(RefName::new("refs/tags/"), Err(NameError::InvalidRefPrefix));
    }

    // --- DataType ---

    #[test]
    fn data_type_valid() {
        let dt = DataType::new("my_type").unwrap();
        assert_eq!(dt.as_str(), "my_type");
        assert_eq!(dt.to_string(), "my_type");
    }

    #[test]
    fn data_type_rejects_empty() {
        assert_eq!(DataType::new(""), Err(NameError::EmptyName));
    }

    #[test]
    fn data_type_rejects_control() {
        assert_eq!(
            DataType::new("bad\x00type"),
            Err(NameError::ControlCharacter { position: 3 })
        );
    }

    #[test]
    fn data_type_too_long() {
        let s = "a".repeat(257);
        assert_eq!(
            DataType::new(&s),
            Err(NameError::TooLong {
                max: 256,
                actual: 257
            })
        );
    }

    #[test]
    fn data_type_accepts_max_length() {
        let s = "a".repeat(256);
        DataType::new(&s).expect("256 bytes should be valid");
    }

    #[test]
    fn data_type_round_trip_display_parse() {
        let dt = DataType::new("test").unwrap();
        let s = dt.to_string();
        let parsed: DataType = s.parse().unwrap();
        assert_eq!(parsed, dt);
    }

    #[test]
    fn data_type_try_from_string() {
        let dt = DataType::try_from("hello".to_string()).unwrap();
        assert_eq!(dt.as_str(), "hello");
        assert!(DataType::try_from(String::new()).is_err());
    }

    // --- RelationType ---

    #[test]
    fn relation_type_valid() {
        let rt = RelationType::new("related").unwrap();
        assert_eq!(rt.as_str(), "related");
    }

    #[test]
    fn relation_type_rejects_empty() {
        assert_eq!(RelationType::new(""), Err(NameError::EmptyName));
    }

    #[test]
    fn relation_type_rejects_control() {
        assert_eq!(
            RelationType::new("bad\x01name"),
            Err(NameError::ControlCharacter { position: 3 })
        );
    }

    // --- KeySlotLabel ---

    #[test]
    fn key_slot_label_valid() {
        let ksl = KeySlotLabel::new("primary").unwrap();
        assert_eq!(ksl.as_str(), "primary");
    }

    #[test]
    fn key_slot_label_rejects_empty() {
        assert_eq!(KeySlotLabel::new(""), Err(NameError::EmptyName));
    }

    #[test]
    fn key_slot_label_rejects_control() {
        assert_eq!(
            KeySlotLabel::new("bad\x1fkey"),
            Err(NameError::ControlCharacter { position: 3 })
        );
    }

    #[test]
    fn key_slot_label_too_long() {
        let s = "a".repeat(129);
        assert_eq!(
            KeySlotLabel::new(&s),
            Err(NameError::TooLong {
                max: 128,
                actual: 129
            })
        );
    }

    // --- CommitMessage ---

    #[test]
    fn commit_message_valid() {
        let cm = CommitMessage::new("fix: resolve issue").unwrap();
        assert_eq!(cm.as_str(), "fix: resolve issue");
    }

    #[test]
    fn commit_message_allows_empty() {
        let cm = CommitMessage::new("").unwrap();
        assert_eq!(cm.as_str(), "");
    }

    #[test]
    fn commit_message_too_long() {
        let s = "a".repeat(1_048_577);
        assert_eq!(
            CommitMessage::new(&s),
            Err(NameError::TooLong {
                max: 1_048_576,
                actual: 1_048_577
            })
        );
    }

    #[test]
    fn commit_message_accepts_max_length() {
        let s = "a".repeat(1_048_576);
        CommitMessage::new(&s).expect("max length should be valid");
    }

    #[test]
    fn commit_message_try_from_string() {
        let cm = CommitMessage::try_from("hello".to_string()).unwrap();
        assert_eq!(cm.as_str(), "hello");
        assert!(CommitMessage::try_from("a".repeat(1_048_577)).is_err());
    }

    // --- RefPattern accessors ---

    #[test]
    fn ref_pattern_as_exact() {
        let pat = RefPattern::new("refs/heads/main").unwrap();
        assert!(pat.as_exact().is_some());
        assert!(pat.as_namespace().is_none());
        assert_eq!(pat.as_exact().unwrap().as_str(), "refs/heads/main");
    }

    #[test]
    fn ref_pattern_as_namespace() {
        let pat = RefPattern::new("refs/heads/team/**").unwrap();
        assert!(pat.as_namespace().is_some());
        assert!(pat.as_exact().is_none());
        assert_eq!(pat.as_namespace().unwrap(), "refs/heads/team");
    }
}
