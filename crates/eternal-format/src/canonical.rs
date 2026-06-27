// Deterministic CBOR encoder (RFC 8949 core profile with EternalCore restrictions).
//
// Only the permitted subset is exposed:
// - unsigned integers (major 0)
// - negative integers (major 1)
// - byte strings (major 2)
// - text strings (major 3)
// - arrays (major 4)
// - maps (major 5)
// - simple values: false, true, null (major 7)
//
// Not exposed (forbidden by FORMAT.md §4):
// - indefinite-length items
// - floating-point values
// - CBOR tags
// - undefined or other simple values

// ---------------------------------------------------------------------------
// Low-level head encoding
// ---------------------------------------------------------------------------
fn encode_head(buf: &mut Vec<u8>, major: u8, value: u64) {
    let mt = major << 5;
    match value {
        0..=23 => buf.push(mt | value as u8),
        24..=0xff => {
            buf.push(mt | 24);
            buf.push(value as u8);
        }
        0x100..=0xffff => {
            buf.push(mt | 25);
            buf.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            buf.push(mt | 26);
            buf.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            buf.push(mt | 27);
            buf.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// A deterministic CBOR encoder that writes to an internal `Vec<u8>`.
pub struct CanonicalEncoder {
    buf: Vec<u8>,
}

impl CanonicalEncoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create an encoder with a pre-allocated output buffer of `capacity` bytes.
    /// Used by `encode_canonical_value` after pre-computing the exact size.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Encode an unsigned 64-bit integer (major type 0).
    pub fn u64(&mut self, v: u64) {
        encode_head(&mut self.buf, 0, v);
    }

    /// Encode a signed 64-bit integer.
    ///
    /// Positive values use major type 0. Negative values use major type 1
    /// where the encoded value is `-(v + 1)`.
    pub fn i64(&mut self, v: i64) {
        if v >= 0 {
            self.u64(v as u64);
        } else {
            // For negative v, encoded = -(v + 1) = -1 - v, which is always non-negative
            encode_head(&mut self.buf, 1, (-1i64 - v) as u64);
        }
    }

    /// Encode a byte string (major type 2) with shortest length encoding.
    pub fn bytes(&mut self, v: &[u8]) {
        encode_head(&mut self.buf, 2, v.len() as u64);
        self.buf.extend_from_slice(v);
    }

    /// Encode a UTF-8 text string (major type 3) with shortest length encoding.
    pub fn text(&mut self, v: &str) {
        encode_head(&mut self.buf, 3, v.len() as u64);
        self.buf.extend_from_slice(v.as_bytes());
    }

    /// Begin an array of `len` items (major type 4).
    ///
    /// The caller MUST write exactly `len` subsequent data items.
    pub fn begin_array(&mut self, len: u64) {
        encode_head(&mut self.buf, 4, len);
    }

    /// Begin a map of `len` key-value pairs (major type 5).
    ///
    /// The caller MUST write exactly `len` pairs, each as a data item
    /// followed by its value, and MUST write keys in ascending order of
    /// their deterministic CBOR encodings.
    pub fn begin_map(&mut self, len: u64) {
        encode_head(&mut self.buf, 5, len);
    }

    /// Encode a boolean as CBOR simple value (major type 7).
    pub fn boolean(&mut self, v: bool) {
        self.buf.push(if v { 0xf5 } else { 0xf4 });
    }

    /// Encode CBOR `null` (major type 7, additional 22).
    pub fn null(&mut self) {
        self.buf.push(0xf6);
    }

    /// Encode a `CanonicalValue` in the tagged-array format (FORMAT.md §4.5).
    #[allow(dead_code)]
    pub(crate) fn canonical_value(&mut self, value: &CanonicalValue) {
        match value {
            CanonicalValue::Null => {
                self.begin_array(1);
                self.u64(0);
            }
            CanonicalValue::Bool(v) => {
                self.begin_array(2);
                self.u64(1);
                self.boolean(*v);
            }
            CanonicalValue::I64(v) => {
                self.begin_array(2);
                self.u64(2);
                self.i64(*v);
            }
            CanonicalValue::U64(v) => {
                self.begin_array(2);
                self.u64(3);
                self.u64(*v);
            }
            CanonicalValue::Text(v) => {
                self.begin_array(2);
                self.u64(4);
                self.text(v);
            }
            CanonicalValue::Bytes(v) => {
                self.begin_array(2);
                self.u64(5);
                self.bytes(v);
            }
            CanonicalValue::Array(items) => {
                self.begin_array(2);
                self.u64(6);
                self.begin_array(items.len() as u64);
                for item in items {
                    self.canonical_value(item);
                }
            }
            CanonicalValue::Map(entries) => {
                self.begin_array(2);
                self.u64(7);
                self.begin_array(entries.len() as u64);
                for (key, value) in entries {
                    self.begin_array(2);
                    self.text(key);
                    self.canonical_value(value);
                }
            }
        }
    }
}

impl Default for CanonicalEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Exact-size pre-computation helpers
// ---------------------------------------------------------------------------

/// Returns the exact number of bytes in a CBOR head for the given unsigned
/// value using the shortest encoding (RFC 8949 §3).
fn cbor_head_size(value: u64) -> u64 {
    if value <= 23 {
        1
    } else if value <= 0xff {
        2
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// Pre-compute the exact CBOR encoded byte count for `value` without
/// allocating an output buffer.  Validates all encode-time limits (depth,
/// node count, string byte length, NUL content) and returns the exact
/// number of bytes the encoder will produce.
///
/// On overflow during checked arithmetic the function returns
/// `InputTooLarge` immediately — the size would exceed every possible
/// limit.
fn compute_encoded_size(
    value: &CanonicalValue,
    depth: u64,
    node_count: &mut u64,
    limits: &FormatLimits,
) -> Result<u64, CanonicalEncodeError> {
    if depth > limits.max_depth() {
        return Err(CanonicalEncodeError::DepthExceeded);
    }
    *node_count = node_count
        .checked_add(1)
        .ok_or(CanonicalEncodeError::NodeCountExceeded {
            max: limits.max_nodes(),
        })?;
    if *node_count > limits.max_nodes() {
        return Err(CanonicalEncodeError::NodeCountExceeded {
            max: limits.max_nodes(),
        });
    }
    let max_limit = limits.max_metadata_bytes();
    use CanonicalEncodeError::InputTooLarge;
    macro_rules! add {
        ($a:expr, $b:expr) => {
            $a.checked_add($b).ok_or(InputTooLarge {
                max: max_limit,
                actual: u64::MAX,
            })?
        };
    }
    match value {
        CanonicalValue::Null => {
            // array(1) + u64(0) = 1 + 1 = 2 bytes
            Ok(2)
        }
        CanonicalValue::Bool(_) => {
            // array(2) + u64(1) + simple(1) = 1 + 1 + 1 = 3 bytes
            Ok(3)
        }
        CanonicalValue::I64(v) => {
            let inner = if *v >= 0 {
                cbor_head_size(*v as u64)
            } else {
                cbor_head_size((-1i64 - *v) as u64)
            };
            // array(2) + u64(2) + inner
            Ok(add!(2u64, inner))
        }
        CanonicalValue::U64(v) => {
            // array(2) + u64(3) + u64(v)
            Ok(add!(2u64, cbor_head_size(*v)))
        }
        CanonicalValue::Text(s) => {
            if s.contains('\0') {
                return Err(CanonicalEncodeError::TextContainsNul);
            }
            let len = s.len() as u64;
            if len > limits.max_string_bytes() {
                return Err(CanonicalEncodeError::StringTooLong {
                    max: limits.max_string_bytes(),
                    actual: len,
                });
            }
            // array(2) + u64(4) + head(3, len) + payload
            let mut t = 2u64;
            t = add!(t, cbor_head_size(len));
            t = add!(t, len);
            Ok(t)
        }
        CanonicalValue::Bytes(b) => {
            let len = b.len() as u64;
            if len > limits.max_string_bytes() {
                return Err(CanonicalEncodeError::StringTooLong {
                    max: limits.max_string_bytes(),
                    actual: len,
                });
            }
            // array(2) + u64(5) + head(2, len) + payload
            let mut t = 2u64;
            t = add!(t, cbor_head_size(len));
            t = add!(t, len);
            Ok(t)
        }
        CanonicalValue::Array(items) => {
            // array(2) + u64(6) + head(4, len) + children
            let mut t = 2u64;
            t = add!(t, cbor_head_size(items.len() as u64));
            for item in items {
                t = add!(
                    t,
                    compute_encoded_size(item, depth + 1, node_count, limits)?
                );
            }
            Ok(t)
        }
        CanonicalValue::Map(entries) => {
            // array(2) + u64(7) + head(4, len) + per-entry
            let mut t = 2u64;
            t = add!(t, cbor_head_size(entries.len() as u64));
            for (key, value) in entries {
                if key.contains('\0') {
                    return Err(CanonicalEncodeError::TextContainsNul);
                }
                let key_len = key.len() as u64;
                if key_len > limits.max_string_bytes() {
                    return Err(CanonicalEncodeError::StringTooLong {
                        max: limits.max_string_bytes(),
                        actual: key_len,
                    });
                }
                // per-entry: array(2) + head(3, key_len) + key_payload + child
                let mut e = 1u64; // array(2) head
                e = add!(e, cbor_head_size(key_len));
                e = add!(e, key_len);
                e = add!(
                    e,
                    compute_encoded_size(value, depth + 1, node_count, limits)?
                );
                t = add!(t, e);
            }
            Ok(t)
        }
    }
}

// ---------------------------------------------------------------------------
// Bounded CanonicalValue encoder
// ---------------------------------------------------------------------------

/// Encode a `CanonicalValue` into canonical CBOR bytes with resource limits.
///
/// Enforces FORMAT.md §20 limits:
/// - `max_depth` — maximum nesting of arrays/maps (default: 64)
/// - `max_nodes` — maximum total `CanonicalValue` nodes (default: 1_000_000)
/// - `max_string_bytes` — maximum byte length for Text/Bytes (default: 1_048_576)
/// - `max_metadata_bytes` — maximum total CBOR encoded output (default: 16_777_216)
///
/// Text values and map keys containing NUL (`\0`) are rejected.
///
/// ## Allocation order
///
/// 1. Pre-compute exact encoded size (zero output allocation).
/// 2. Reject if size exceeds `max_metadata_bytes`.
/// 3. Allocate exact-capacity output buffer and encode.
pub fn encode_canonical_value(
    value: &CanonicalValue,
    limits: &FormatLimits,
) -> Result<Vec<u8>, CanonicalEncodeError> {
    // Phase 1: pre-compute exact size with all limit checks (no output buffer).
    let mut node_count = 0u64;
    let size = compute_encoded_size(value, 0, &mut node_count, limits)?;
    // Phase 2: check total output length BEFORE any output buffer allocation.
    if size > limits.max_metadata_bytes() {
        return Err(CanonicalEncodeError::InputTooLarge {
            max: limits.max_metadata_bytes(),
            actual: size,
        });
    }
    // Phase 3: allocate exact-capacity output buffer and encode.
    let mut encoder = CanonicalEncoder::with_capacity(size as usize);
    node_count = 0;
    validate_encode_value(&mut encoder, value, 0, &mut node_count, limits)?;
    debug_assert_eq!(encoder.as_bytes().len() as u64, size);
    Ok(encoder.into_bytes())
}

/// Single-pass validation + encoding.
/// Checks depth, node count (with `checked_add`), string length,
/// and NUL-free text before/during encoding.
fn validate_encode_value(
    encoder: &mut CanonicalEncoder,
    value: &CanonicalValue,
    depth: u64,
    node_count: &mut u64,
    limits: &FormatLimits,
) -> Result<(), CanonicalEncodeError> {
    if depth > limits.max_depth() {
        return Err(CanonicalEncodeError::DepthExceeded);
    }
    *node_count = node_count
        .checked_add(1)
        .ok_or(CanonicalEncodeError::NodeCountExceeded {
            max: limits.max_nodes(),
        })?;
    if *node_count > limits.max_nodes() {
        return Err(CanonicalEncodeError::NodeCountExceeded {
            max: limits.max_nodes(),
        });
    }
    match value {
        CanonicalValue::Text(s) => {
            if s.contains('\0') {
                return Err(CanonicalEncodeError::TextContainsNul);
            }
            let len = s.len() as u64;
            if len > limits.max_string_bytes() {
                return Err(CanonicalEncodeError::StringTooLong {
                    max: limits.max_string_bytes(),
                    actual: len,
                });
            }
            encoder.begin_array(2);
            encoder.u64(4);
            encoder.text(s);
        }
        CanonicalValue::Bytes(b) => {
            let len = b.len() as u64;
            if len > limits.max_string_bytes() {
                return Err(CanonicalEncodeError::StringTooLong {
                    max: limits.max_string_bytes(),
                    actual: len,
                });
            }
            encoder.begin_array(2);
            encoder.u64(5);
            encoder.bytes(b);
        }
        CanonicalValue::Null => {
            encoder.begin_array(1);
            encoder.u64(0);
        }
        CanonicalValue::Bool(v) => {
            encoder.begin_array(2);
            encoder.u64(1);
            encoder.boolean(*v);
        }
        CanonicalValue::I64(v) => {
            encoder.begin_array(2);
            encoder.u64(2);
            encoder.i64(*v);
        }
        CanonicalValue::U64(v) => {
            encoder.begin_array(2);
            encoder.u64(3);
            encoder.u64(*v);
        }
        CanonicalValue::Array(items) => {
            encoder.begin_array(2);
            encoder.u64(6);
            encoder.begin_array(items.len() as u64);
            for item in items {
                validate_encode_value(encoder, item, depth + 1, node_count, limits)?;
            }
        }
        CanonicalValue::Map(entries) => {
            encoder.begin_array(2);
            encoder.u64(7);
            encoder.begin_array(entries.len() as u64);
            for (key, value) in entries {
                if key.contains('\0') {
                    return Err(CanonicalEncodeError::TextContainsNul);
                }
                let len = key.len() as u64;
                if len > limits.max_string_bytes() {
                    return Err(CanonicalEncodeError::StringTooLong {
                        max: limits.max_string_bytes(),
                        actual: len,
                    });
                }
                encoder.begin_array(2);
                encoder.text(key);
                validate_encode_value(encoder, value, depth + 1, node_count, limits)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sorted map builder
// ---------------------------------------------------------------------------

/// Builds a deterministic CBOR map by collecting entries and sorting their
/// encoded keys before writing.
pub(crate) struct CanonicalSortedMap {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalEncodeError {
    DuplicateMapKey,
    DuplicateTextKey {
        key: String,
    },
    DepthExceeded,
    NodeCountExceeded {
        max: u64,
    },
    StringTooLong {
        max: u64,
        actual: u64,
    },
    TextContainsNul,
    FloatUnsupported,
    NumberOutOfRange,
    Limits(LimitsError),
    JsonSyntax {
        message: String,
        line: usize,
        column: usize,
    },
    TrailingData,
    InputTooLarge {
        max: u64,
        actual: u64,
    },
}

impl CanonicalSortedMap {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a key-value pair. Both key and value are pre-encoded CBOR bytes.
    #[allow(dead_code)]
    pub(crate) fn insert_raw(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.entries.push((key, value));
    }

    /// Encode a key using the encoder, then insert the pre-encoded value.
    /// This is a convenience wrapper for integer keys.
    #[allow(dead_code)]
    pub(crate) fn insert_u64(&mut self, key: u64, value: Vec<u8>) {
        let mut key_buf = Vec::new();
        encode_head(&mut key_buf, 0, key);
        self.entries.push((key_buf, value));
    }

    /// Finalize the map: sort entries by encoded key, then write to `encoder`.
    /// Returns an error if duplicate keys are detected.
    #[allow(dead_code)]
    pub fn finish(self, encoder: &mut CanonicalEncoder) -> Result<(), CanonicalEncodeError> {
        let mut entries = self.entries;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for pair in entries.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(CanonicalEncodeError::DuplicateMapKey);
            }
        }
        encoder.begin_map(entries.len() as u64);
        for (key, value) in entries {
            encoder.buf.extend_from_slice(&key);
            encoder.buf.extend_from_slice(&value);
        }
        Ok(())
    }
}

impl Default for CanonicalSortedMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Decoded CBOR value
// ---------------------------------------------------------------------------

/// A decoded CBOR data item.
///
/// This is an intermediate representation distinct from `CanonicalValue` (F2.5).
/// It preserves the full CBOR value space for the permitted subset.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    U64(u64),
    I64(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Map entries stored in canonical (encoded-key sorted) order.
    Map(Vec<(Value, Value)>),
    Boolean(bool),
    Null,
}

impl Value {
    /// Re-encode this value with the canonical encoder.
    /// For canonical input this produces identical bytes.
    pub fn reencode(&self) -> Vec<u8> {
        let mut enc = CanonicalEncoder::new();
        self.encode_to(&mut enc);
        enc.into_bytes()
    }

    fn encode_to(&self, enc: &mut CanonicalEncoder) {
        match self {
            Value::U64(v) => enc.u64(*v),
            Value::I64(v) => enc.i64(*v),
            Value::Bytes(v) => enc.bytes(v),
            Value::Text(v) => enc.text(v),
            Value::Array(items) => {
                enc.begin_array(items.len() as u64);
                for item in items {
                    item.encode_to(enc);
                }
            }
            Value::Map(pairs) => {
                enc.begin_map(pairs.len() as u64);
                for (k, v) in pairs {
                    k.encode_to(enc);
                    v.encode_to(enc);
                }
            }
            Value::Boolean(v) => enc.boolean(*v),
            Value::Null => enc.null(),
        }
    }
}

// ---------------------------------------------------------------------------
// CanonicalValue — tagged union for user metadata
// ---------------------------------------------------------------------------

/// The explicitly tagged union for user metadata (FORMAT.md §4.5).
///
/// Positive `I64` and `U64` values remain distinguishable. Map keys are
/// always text strings; maps are stored sorted by raw UTF-8 key bytes.
#[derive(Clone, Debug, PartialEq)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<CanonicalValue>),
    Map(std::collections::BTreeMap<String, CanonicalValue>),
}

// ---------------------------------------------------------------------------
// JSON conversion
// ---------------------------------------------------------------------------

impl CanonicalValue {
    /// Convert a `serde_json::Value` into `CanonicalValue` with the given limits.
    pub fn from_json_value(
        value: serde_json::Value,
        limits: &FormatLimits,
    ) -> Result<Self, CanonicalEncodeError> {
        let mut nodes = 0u64;
        cv_from_json(&value, 0, &mut nodes, limits)
    }
}

impl TryFrom<serde_json::Value> for CanonicalValue {
    type Error = CanonicalEncodeError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        Self::from_json_value(value, &FormatLimits::default())
    }
}

/// Convert a `serde_json::Value` into `CanonicalValue` with resource limits.
///
/// NOTE: This entry does NOT detect duplicate textual keys because
/// `serde_json::Value::Object` already deduplicates them. For authoritative
/// duplicate-key detection use `canonical_value_from_json_slice()`.
fn cv_from_json(
    value: &serde_json::Value,
    depth: u64,
    nodes: &mut u64,
    limits: &FormatLimits,
) -> Result<CanonicalValue, CanonicalEncodeError> {
    if depth > limits.max_depth() {
        return Err(CanonicalEncodeError::DepthExceeded);
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or(CanonicalEncodeError::NodeCountExceeded {
            max: limits.max_nodes(),
        })?;
    if *nodes > limits.max_nodes() {
        return Err(CanonicalEncodeError::NodeCountExceeded {
            max: limits.max_nodes(),
        });
    }
    match value {
        serde_json::Value::Null => Ok(CanonicalValue::Null),
        serde_json::Value::Bool(b) => Ok(CanonicalValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            if n.is_f64() {
                return Err(CanonicalEncodeError::FloatUnsupported);
            }
            if let Some(v) = n.as_i64() {
                return Ok(CanonicalValue::I64(v));
            }
            if let Some(v) = n.as_u64() {
                return Ok(CanonicalValue::U64(v));
            }
            Err(CanonicalEncodeError::NumberOutOfRange)
        }
        serde_json::Value::String(s) => {
            if s.contains('\0') {
                return Err(CanonicalEncodeError::TextContainsNul);
            }
            let len = s.len() as u64;
            if len > limits.max_string_bytes() {
                return Err(CanonicalEncodeError::StringTooLong {
                    max: limits.max_string_bytes(),
                    actual: len,
                });
            }
            Ok(CanonicalValue::Text(s.clone()))
        }
        serde_json::Value::Array(arr) => {
            let mut items = Vec::with_capacity(arr.len());
            for item in arr {
                items.push(cv_from_json(item, depth + 1, nodes, limits)?);
            }
            Ok(CanonicalValue::Array(items))
        }
        serde_json::Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let mut map = std::collections::BTreeMap::new();
            for k in keys {
                if k.contains('\0') {
                    return Err(CanonicalEncodeError::TextContainsNul);
                }
                let len = k.len() as u64;
                if len > limits.max_string_bytes() {
                    return Err(CanonicalEncodeError::StringTooLong {
                        max: limits.max_string_bytes(),
                        actual: len,
                    });
                }
                let val = cv_from_json(&obj[k], depth + 1, nodes, limits)?;
                map.insert(k.clone(), val);
            }
            Ok(CanonicalValue::Map(map))
        }
    }
}

/// Authoritative JSON-to-CanonicalValue conversion with resource limits
/// and duplicate textual key detection.
///
/// Unlike `TryFrom<serde_json::Value>`, this parses raw JSON bytes using
/// `serde_json::Deserializer` with a custom `de::Visitor` so that duplicate
/// keys in the input (e.g. `{"a":1,"a":2}`) are detected before deduplication.
///
/// Limits (depth, node count, string length, NUL rejection) are enforced
/// during visitor callbacks. The raw input is limited to 16 MiB.
pub fn canonical_value_from_json_slice(
    input: &[u8],
    limits: &FormatLimits,
) -> Result<CanonicalValue, CanonicalEncodeError> {
    if input.len() as u64 > limits.max_metadata_bytes() {
        return Err(CanonicalEncodeError::InputTooLarge {
            max: limits.max_metadata_bytes(),
            actual: input.len() as u64,
        });
    }

    let nodes = std::cell::Cell::new(0u64);
    let captured = std::cell::Cell::new(None::<CanonicalEncodeError>);
    let mut de = serde_json::Deserializer::from_slice(input);
    let visitor = CanonicalValueVisitor {
        depth: 0,
        nodes: &nodes,
        limits,
        captured: &captured,
    };
    let result = de.deserialize_any(visitor);
    match result {
        Ok(cv) => {
            if de.end().is_err() {
                return Err(CanonicalEncodeError::TrailingData);
            }
            Ok(cv)
        }
        Err(e) => match captured.into_inner() {
            Some(ce) => Err(ce),
            None => Err(CanonicalEncodeError::JsonSyntax {
                message: e.to_string(),
                line: e.line(),
                column: e.column(),
            }),
        },
    }
}

// ---------------------------------------------------------------------------
// serde DeserializeError impl for CanonicalEncodeError
// ---------------------------------------------------------------------------

impl serde::de::Error for CanonicalEncodeError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        CanonicalEncodeError::JsonSyntax {
            message: msg.to_string(),
            line: 0,
            column: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Custom serde::de::Visitor for canonical_value_from_json_slice
// ---------------------------------------------------------------------------

use serde::de::Deserializer as SerdeDeserializer;
use std::collections::btree_map::Entry;

use crate::limits::{FormatLimits, LimitsError};

impl std::fmt::Display for CanonicalEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateMapKey => write!(f, "duplicate map key"),
            Self::DuplicateTextKey { key } => {
                write!(f, "duplicate textual key: {key:?}")
            }
            Self::DepthExceeded => write!(f, "depth exceeded"),
            Self::NodeCountExceeded { max } => write!(f, "node count exceeded (max {max})"),
            Self::StringTooLong { max, actual } => {
                write!(f, "string too long (max {max}, actual {actual})")
            }
            Self::TextContainsNul => write!(f, "text contains NUL"),
            Self::FloatUnsupported => write!(f, "float not supported"),
            Self::NumberOutOfRange => write!(f, "number out of range"),
            Self::Limits(inner) => write!(f, "{inner}"),
            Self::JsonSyntax {
                message,
                line,
                column,
            } => write!(
                f,
                "JSON syntax error at line {line}, column {column}: {message}"
            ),
            Self::TrailingData => write!(f, "trailing data after JSON value"),
            Self::InputTooLarge { max, actual } => {
                write!(f, "input too large (max {max}, actual {actual})")
            }
        }
    }
}

impl std::error::Error for CanonicalEncodeError {}

impl From<serde_json::Error> for CanonicalEncodeError {
    fn from(e: serde_json::Error) -> Self {
        CanonicalEncodeError::JsonSyntax {
            message: e.to_string(),
            line: e.line(),
            column: e.column(),
        }
    }
}

impl From<LimitsError> for CanonicalEncodeError {
    fn from(e: LimitsError) -> Self {
        Self::Limits(e)
    }
}

struct CanonicalValueVisitor<'a> {
    depth: u64,
    nodes: &'a std::cell::Cell<u64>,
    limits: &'a FormatLimits,
    captured: &'a std::cell::Cell<Option<CanonicalEncodeError>>,
}

impl<'a> CanonicalValueVisitor<'a> {
    fn capture<E: serde::de::Error>(&self, ce: CanonicalEncodeError) -> E {
        self.captured.set(Some(ce));
        serde::de::Error::custom("")
    }

    fn check_depth<E: serde::de::Error>(&self) -> Result<(), E> {
        if self.depth > self.limits.max_depth() {
            return Err(self.capture(CanonicalEncodeError::DepthExceeded));
        }
        Ok(())
    }

    fn count_node<E: serde::de::Error>(&self) -> Result<(), E> {
        let current = self.nodes.get();
        let next = current.checked_add(1).ok_or_else(|| {
            self.capture(CanonicalEncodeError::NodeCountExceeded {
                max: self.limits.max_nodes(),
            })
        })?;
        if next > self.limits.max_nodes() {
            return Err(self.capture(CanonicalEncodeError::NodeCountExceeded {
                max: self.limits.max_nodes(),
            }));
        }
        self.nodes.set(next);
        Ok(())
    }

    fn check_string<E: serde::de::Error>(&self, s: &str) -> Result<(), E> {
        if s.contains('\0') {
            return Err(self.capture(CanonicalEncodeError::TextContainsNul));
        }
        Ok(())
    }
}

impl<'de, 'a> serde::de::Visitor<'de> for CanonicalValueVisitor<'a> {
    type Value = CanonicalValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<CanonicalValue, E> {
        self.count_node()?;
        Ok(CanonicalValue::Bool(v))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<CanonicalValue, E> {
        self.count_node()?;
        Ok(CanonicalValue::I64(v))
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<CanonicalValue, E> {
        self.count_node()?;
        // Unify with TryFrom<serde_json::Value>: values in i64 range → I64
        if v <= i64::MAX as u64 {
            Ok(CanonicalValue::I64(v as i64))
        } else {
            Ok(CanonicalValue::U64(v))
        }
    }

    fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<CanonicalValue, E> {
        Err(self.capture(CanonicalEncodeError::FloatUnsupported))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<CanonicalValue, E> {
        self.check_string(v)?;
        if (v.len() as u64) > self.limits.max_string_bytes() {
            return Err(self.capture(CanonicalEncodeError::StringTooLong {
                max: self.limits.max_string_bytes(),
                actual: v.len() as u64,
            }));
        }
        self.count_node()?;
        Ok(CanonicalValue::Text(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<CanonicalValue, E> {
        self.check_string(&v)?;
        if (v.len() as u64) > self.limits.max_string_bytes() {
            return Err(self.capture(CanonicalEncodeError::StringTooLong {
                max: self.limits.max_string_bytes(),
                actual: v.len() as u64,
            }));
        }
        self.count_node()?;
        Ok(CanonicalValue::Text(v))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<CanonicalValue, E> {
        self.count_node()?;
        Ok(CanonicalValue::Null)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> Result<CanonicalValue, A::Error> {
        self.count_node()?;
        let mut items = Vec::new();
        while let Some(val) = seq.next_element_seed(CanonicalValueSeed {
            depth: self.depth + 1,
            nodes: self.nodes,
            limits: self.limits,
            captured: self.captured,
        })? {
            items.push(val);
        }
        Ok(CanonicalValue::Array(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> Result<CanonicalValue, A::Error> {
        self.count_node()?;
        let mut btree = std::collections::BTreeMap::new();
        while let Some(key) = map.next_key_seed(CanonicalValueStringSeed)? {
            self.check_string(&key)?;
            if (key.len() as u64) > self.limits.max_string_bytes() {
                return Err(self.capture(CanonicalEncodeError::StringTooLong {
                    max: self.limits.max_string_bytes(),
                    actual: key.len() as u64,
                }));
            }
            match btree.entry(key) {
                Entry::Occupied(e) => {
                    return Err(self.capture(CanonicalEncodeError::DuplicateTextKey {
                        key: e.key().clone(),
                    }));
                }
                Entry::Vacant(e) => {
                    let val = map.next_value_seed(CanonicalValueSeed {
                        depth: self.depth + 1,
                        nodes: self.nodes,
                        limits: self.limits,
                        captured: self.captured,
                    })?;
                    e.insert(val);
                }
            }
        }
        Ok(CanonicalValue::Map(btree))
    }
}

// ---------------------------------------------------------------------------
// CanonicalValueSeed — enables recursive deserialization inside seq/map
// ---------------------------------------------------------------------------

struct CanonicalValueSeed<'a> {
    depth: u64,
    nodes: &'a std::cell::Cell<u64>,
    limits: &'a FormatLimits,
    captured: &'a std::cell::Cell<Option<CanonicalEncodeError>>,
}

impl<'de, 'a> serde::de::DeserializeSeed<'de> for CanonicalValueSeed<'a> {
    type Value = CanonicalValue;

    fn deserialize<D: serde::de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        let viz = CanonicalValueVisitor {
            depth: self.depth,
            nodes: self.nodes,
            limits: self.limits,
            captured: self.captured,
        };
        viz.check_depth()?;
        deserializer.deserialize_any(viz)
    }
}

// ---------------------------------------------------------------------------
// CanonicalValueStringSeed — extracts a String key for map access
// ---------------------------------------------------------------------------

struct CanonicalValueStringSeed;

impl<'de> serde::de::DeserializeSeed<'de> for CanonicalValueStringSeed {
    type Value = String;

    fn deserialize<D: serde::de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_string(CanonicalValueStringVisitor)
    }
}

struct CanonicalValueStringVisitor;

impl<'de> serde::de::Visitor<'de> for CanonicalValueStringVisitor {
    type Value = String;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<String, E> {
        Ok(v.to_owned())
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<String, E> {
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Value → CanonicalValue conversion (from decoded CBOR Value)
// ---------------------------------------------------------------------------

/// Convert a decoded `Value` into a `CanonicalValue`, validating the
/// tagged-array format per FORMAT.md §4.5 and enforcing resource limits.
pub fn canonical_value_from_value(
    value: &Value,
    depth: u64,
    nodes: &mut u64,
    limits: &FormatLimits,
) -> Result<CanonicalValue, DecodeError> {
    if depth > limits.max_depth() {
        return Err(DecodeError::DepthExceeded);
    }
    *nodes = nodes.checked_add(1).ok_or(DecodeError::ValueTooLarge {
        requested: u64::MAX,
        max: limits.max_nodes(),
    })?;
    if *nodes > limits.max_nodes() {
        return Err(DecodeError::ValueTooLarge {
            requested: *nodes,
            max: limits.max_nodes(),
        });
    }
    let arr = match value {
        Value::Array(arr) => arr,
        _ => return Err(DecodeError::InvalidCanonicalValueStructure),
    };
    let disc = match arr.first() {
        Some(Value::U64(d)) => *d,
        _ => return Err(DecodeError::InvalidCanonicalValueStructure),
    };
    match disc {
        0 => {
            if arr.len() != 1 {
                return Err(DecodeError::InvalidCanonicalValueStructure);
            }
            Ok(CanonicalValue::Null)
        }
        1 => {
            if arr.len() != 2 {
                return Err(DecodeError::InvalidCanonicalValueStructure);
            }
            match &arr[1] {
                Value::Boolean(b) => Ok(CanonicalValue::Bool(*b)),
                _ => Err(DecodeError::InvalidCanonicalValueStructure),
            }
        }
        2 => {
            if arr.len() != 2 {
                return Err(DecodeError::InvalidCanonicalValueStructure);
            }
            match &arr[1] {
                Value::I64(v) => Ok(CanonicalValue::I64(*v)),
                Value::U64(v) if *v <= i64::MAX as u64 => Ok(CanonicalValue::I64(*v as i64)),
                _ => Err(DecodeError::InvalidCanonicalValueStructure),
            }
        }
        3 => {
            if arr.len() != 2 {
                return Err(DecodeError::InvalidCanonicalValueStructure);
            }
            match &arr[1] {
                Value::U64(v) => Ok(CanonicalValue::U64(*v)),
                Value::I64(v) if *v >= 0 => Ok(CanonicalValue::U64(*v as u64)),
                _ => Err(DecodeError::InvalidCanonicalValueStructure),
            }
        }
        4 => {
            if arr.len() != 2 {
                return Err(DecodeError::InvalidCanonicalValueStructure);
            }
            match &arr[1] {
                Value::Text(s) => Ok(CanonicalValue::Text(s.clone())),
                _ => Err(DecodeError::InvalidCanonicalValueStructure),
            }
        }
        5 => {
            if arr.len() != 2 {
                return Err(DecodeError::InvalidCanonicalValueStructure);
            }
            match &arr[1] {
                Value::Bytes(b) => Ok(CanonicalValue::Bytes(b.clone())),
                _ => Err(DecodeError::InvalidCanonicalValueStructure),
            }
        }
        6 => {
            if arr.len() != 2 {
                return Err(DecodeError::InvalidCanonicalValueStructure);
            }
            let items = match &arr[1] {
                Value::Array(items) => items,
                _ => return Err(DecodeError::InvalidCanonicalValueStructure),
            };
            let mut result = Vec::with_capacity(items.len());
            for item in items {
                result.push(canonical_value_from_value(item, depth + 1, nodes, limits)?);
            }
            Ok(CanonicalValue::Array(result))
        }
        7 => {
            if arr.len() != 2 {
                return Err(DecodeError::InvalidCanonicalValueStructure);
            }
            let entries = match &arr[1] {
                Value::Array(entries) => entries,
                _ => return Err(DecodeError::InvalidCanonicalValueStructure),
            };
            let mut map = std::collections::BTreeMap::new();
            for entry in entries {
                let pair = match entry {
                    Value::Array(pair) => pair,
                    _ => return Err(DecodeError::InvalidCanonicalValueStructure),
                };
                if pair.len() != 2 {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let key = match &pair[0] {
                    Value::Text(k) => k.clone(),
                    _ => return Err(DecodeError::CanonicalMapKeyNotText),
                };
                let val = canonical_value_from_value(&pair[1], depth + 1, nodes, limits)?;
                if map.insert(key.clone(), val).is_some() {
                    return Err(DecodeError::DuplicateMapKey);
                }
            }
            Ok(CanonicalValue::Map(map))
        }
        _ => Err(DecodeError::InvalidCanonicalValueDiscriminant(disc)),
    }
}

/// Convert a `CanonicalValue` into a `Value` for CBOR encoding.
pub fn value_from_canonical_value(value: &CanonicalValue) -> Value {
    match value {
        CanonicalValue::Null => Value::Array(vec![Value::U64(0)]),
        CanonicalValue::Bool(b) => Value::Array(vec![Value::U64(1), Value::Boolean(*b)]),
        CanonicalValue::I64(v) => Value::Array(vec![Value::U64(2), Value::I64(*v)]),
        CanonicalValue::U64(v) => Value::Array(vec![Value::U64(3), Value::U64(*v)]),
        CanonicalValue::Text(s) => Value::Array(vec![Value::U64(4), Value::Text(s.clone())]),
        CanonicalValue::Bytes(b) => Value::Array(vec![Value::U64(5), Value::Bytes(b.clone())]),
        CanonicalValue::Array(items) => {
            let inner: Vec<Value> = items.iter().map(value_from_canonical_value).collect();
            Value::Array(vec![Value::U64(6), Value::Array(inner)])
        }
        CanonicalValue::Map(entries) => {
            let pairs: Vec<Value> = entries
                .iter()
                .map(|(k, v)| {
                    Value::Array(vec![Value::Text(k.clone()), value_from_canonical_value(v)])
                })
                .collect();
            Value::Array(vec![Value::U64(7), Value::Array(pairs)])
        }
    }
}

impl From<CanonicalValue> for Value {
    fn from(cv: CanonicalValue) -> Self {
        value_from_canonical_value(&cv)
    }
}

// ---------------------------------------------------------------------------
// Decode error types
// ---------------------------------------------------------------------------

/// Errors that can occur during CBOR decoding.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodeError {
    UnexpectedEof,
    NonShortestInteger,
    ReservedAdditionalInfo(u8),
    FloatUnsupported,
    IndefiniteLengthUnsupported,
    TagUnsupported,
    SimpleValueUnsupported(u8),
    InvalidUtf8,
    DepthExceeded,
    ValueTooLarge {
        requested: u64,
        max: u64,
    },
    DuplicateMapKey,
    UnsortedMapKey,
    TrailingData,
    /// The CBOR value is not a valid CanonicalValue wrapper array.
    InvalidCanonicalValueStructure,
    /// A CanonicalValue discriminant is out of the valid 0..=7 range.
    InvalidCanonicalValueDiscriminant(u64),
    /// A CanonicalValue::Map key is not a CBOR text string.
    CanonicalMapKeyNotText,
}

// ---------------------------------------------------------------------------
// Bounded deterministic CBOR decoder
// ---------------------------------------------------------------------------

/// A bounded, non-recursive (iterative depth-checked) CBOR decoder that rejects
/// all non-canonical encodings per FORMAT.md §4.
pub struct CanonicalDecoder<'a> {
    input: &'a [u8],
    pos: usize,
    max_depth: usize,
    max_item_count: u64,
    max_string_bytes: u64,
    max_metadata_bytes: u64,
}

impl<'a> CanonicalDecoder<'a> {
    /// Create a decoder from a `FormatLimits` reference.
    /// The decoder enforces the same depth, node count, string byte, and
    /// total metadata byte limits.
    pub fn from_limits(input: &'a [u8], limits: &FormatLimits) -> Self {
        Self {
            input,
            pos: 0,
            max_depth: limits.max_depth() as usize,
            max_item_count: limits.max_nodes(),
            max_string_bytes: limits.max_string_bytes(),
            max_metadata_bytes: limits.max_metadata_bytes(),
        }
    }

    /// Convert a `u64` to `usize` with overflow checking.
    /// Returns `ValueTooLarge` on 32-bit platforms if the value exceeds `usize::MAX`.
    fn usize_from_u64(&self, val: u64) -> Result<usize, DecodeError> {
        usize::try_from(val).map_err(|_| DecodeError::ValueTooLarge {
            requested: val,
            max: usize::MAX as u64,
        })
    }

    /// Decode a single CBOR data item.
    ///
    /// Returns an error if:
    /// - any non-canonical encoding is detected
    /// - limits are exceeded
    /// - trailing data remains after the item
    pub fn decode(&mut self) -> Result<Value, DecodeError> {
        let val = self.decode_value(0)?;
        if self.pos != self.input.len() {
            return Err(DecodeError::TrailingData);
        }
        Ok(val)
    }

    fn decode_value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > self.max_depth {
            return Err(DecodeError::DepthExceeded);
        }
        let byte = self.read_byte()?;
        let major = byte >> 5;
        let addl = byte & 0x1f;
        if addl == 31 {
            return Err(DecodeError::IndefiniteLengthUnsupported);
        }

        match major {
            0 => {
                let val = self.decode_head(byte)?;
                Ok(Value::U64(val))
            }
            1 => {
                let val = self.decode_head(byte)?;
                let n = i64::try_from(val)
                    .ok()
                    .and_then(|v| {
                        let r = (-1i64).checked_sub(v)?;
                        Some(r)
                    })
                    .ok_or(DecodeError::ValueTooLarge {
                        requested: val,
                        max: i64::MAX as u64,
                    })?;
                Ok(Value::I64(n))
            }
            2 => {
                let len = self.decode_head(byte)?;
                if len > self.max_string_bytes {
                    return Err(DecodeError::ValueTooLarge {
                        requested: len,
                        max: self.max_string_bytes,
                    });
                }
                let bytes = self.read_bytes(self.usize_from_u64(len)?)?;
                Ok(Value::Bytes(bytes.to_vec()))
            }
            3 => {
                let len = self.decode_head(byte)?;
                if len > self.max_string_bytes {
                    return Err(DecodeError::ValueTooLarge {
                        requested: len,
                        max: self.max_string_bytes,
                    });
                }
                let raw = self.read_bytes(self.usize_from_u64(len)?)?;
                let s = std::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8)?;
                Ok(Value::Text(s.to_string()))
            }
            4 => {
                let len = self.decode_head(byte)?;
                if len > self.max_item_count {
                    return Err(DecodeError::ValueTooLarge {
                        requested: len,
                        max: self.max_item_count,
                    });
                }
                let mut items = Vec::with_capacity(self.usize_from_u64(len.min(1024))?);
                for _ in 0..len {
                    items.push(self.decode_value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = self.decode_head(byte)?;
                if len > self.max_item_count {
                    return Err(DecodeError::ValueTooLarge {
                        requested: len,
                        max: self.max_item_count,
                    });
                }
                let count = self.usize_from_u64(len)?;
                let mut pairs = Vec::with_capacity(count.min(1024));
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..count {
                    let key_start = self.pos;
                    let key = self.decode_value(depth + 1)?;
                    let key_raw = self.input[key_start..self.pos].to_vec();

                    if let Some(ref prev) = prev_key {
                        match prev.as_slice().cmp(&key_raw) {
                            std::cmp::Ordering::Less => {}
                            std::cmp::Ordering::Equal => {
                                return Err(DecodeError::DuplicateMapKey);
                            }
                            std::cmp::Ordering::Greater => {
                                return Err(DecodeError::UnsortedMapKey);
                            }
                        }
                    }
                    prev_key = Some(key_raw);

                    let value = self.decode_value(depth + 1)?;
                    pairs.push((key, value));
                }
                Ok(Value::Map(pairs))
            }
            6 => Err(DecodeError::TagUnsupported),
            7 => self.decode_simple(byte),
            _ => unreachable!(),
        }
    }

    /// Decode an integer/head value with non-shortest-form validation.
    fn decode_head(&mut self, first: u8) -> Result<u64, DecodeError> {
        let addl = (first & 0x1f) as u64;
        match addl {
            0..=23 => Ok(addl),
            24 => {
                let v = self.read_byte()? as u64;
                if v < 24 {
                    return Err(DecodeError::NonShortestInteger);
                }
                Ok(v)
            }
            25 => {
                let v = self.read_u16()? as u64;
                if v < 256 {
                    return Err(DecodeError::NonShortestInteger);
                }
                Ok(v)
            }
            26 => {
                let v = self.read_u32()? as u64;
                if v < 65_536 {
                    return Err(DecodeError::NonShortestInteger);
                }
                Ok(v)
            }
            27 => {
                let v = self.read_u64()?;
                if v < 4_294_967_296 {
                    return Err(DecodeError::NonShortestInteger);
                }
                Ok(v)
            }
            28..=31 => Err(DecodeError::ReservedAdditionalInfo(addl as u8)),
            _ => Err(DecodeError::ReservedAdditionalInfo(addl as u8)),
        }
    }

    fn decode_simple(&mut self, first: u8) -> Result<Value, DecodeError> {
        let addl = first & 0x1f;
        match addl {
            20 => Ok(Value::Boolean(false)),
            21 => Ok(Value::Boolean(true)),
            22 => Ok(Value::Null),
            23 => Err(DecodeError::SimpleValueUnsupported(23)), // undefined
            24 => {
                let v = self.read_byte()?;
                Err(DecodeError::SimpleValueUnsupported(v))
            }
            25..=27 => Err(DecodeError::FloatUnsupported),
            28..=31 => Err(DecodeError::ReservedAdditionalInfo(addl)),
            _ => Err(DecodeError::ReservedAdditionalInfo(addl)),
        }
    }

    // -- low-level I/O --

    fn read_byte(&mut self) -> Result<u8, DecodeError> {
        if self.pos >= self.input.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let b = self.input[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&[u8], DecodeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(DecodeError::UnexpectedEof)?;
        if end > self.input.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    // -----------------------------------------------------------------------
    // CanonicalValue decoder (FORMAT.md §4.5)
    // -----------------------------------------------------------------------

    /// Decode a single `CanonicalValue` from the input.
    ///
    /// Checks for trailing data after the top-level value.
    /// Uses `max_depth` for CanonicalValue nesting and a 1,000,000 node
    /// count limit per FORMAT.md §20.
    pub fn decode_canonical_value(&mut self) -> Result<CanonicalValue, DecodeError> {
        let input_len = self.input.len() as u64;
        if input_len > self.max_metadata_bytes {
            return Err(DecodeError::ValueTooLarge {
                requested: input_len,
                max: self.max_metadata_bytes,
            });
        }
        let mut node_count = 0u64;
        let result = self.decode_cv_inner(0, &mut node_count)?;
        if self.pos != self.input.len() {
            return Err(DecodeError::TrailingData);
        }
        Ok(result)
    }

    fn decode_cv_inner(
        &mut self,
        depth: usize,
        node_count: &mut u64,
    ) -> Result<CanonicalValue, DecodeError> {
        if depth > self.max_depth {
            return Err(DecodeError::DepthExceeded);
        }
        *node_count = node_count
            .checked_add(1)
            .ok_or(DecodeError::ValueTooLarge {
                requested: u64::MAX,
                max: self.max_item_count,
            })?;

        // The outer structure is always a CBOR array
        let byte = self.read_byte()?;
        let major = byte >> 5;
        let addl = byte & 0x1f;
        if addl == 31 {
            return Err(DecodeError::IndefiniteLengthUnsupported);
        }
        if major != 4 {
            return Err(DecodeError::InvalidCanonicalValueStructure);
        }
        let outer_len = self.decode_head(byte)?;
        if outer_len == 0 || outer_len > 2 {
            return Err(DecodeError::InvalidCanonicalValueStructure);
        }
        let has_payload = outer_len == 2;

        // Decode discriminant (first element of outer array)
        let disc_byte = self.read_byte()?;
        let disc_major = disc_byte >> 5;
        let disc_addl = disc_byte & 0x1f;
        if disc_addl == 31 {
            return Err(DecodeError::IndefiniteLengthUnsupported);
        }
        if disc_major != 0 {
            return Err(DecodeError::InvalidCanonicalValueStructure);
        }
        let disc = self.decode_head(disc_byte)?;
        if disc > 7 {
            return Err(DecodeError::InvalidCanonicalValueDiscriminant(disc));
        }

        match disc {
            0 => {
                if has_payload {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                Ok(CanonicalValue::Null)
            }
            1 => {
                if !has_payload {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let inner = self.decode_value(depth)?;
                match inner {
                    Value::Boolean(v) => Ok(CanonicalValue::Bool(v)),
                    _ => Err(DecodeError::InvalidCanonicalValueStructure),
                }
            }
            2 => {
                if !has_payload {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let inner = self.decode_value(depth)?;
                match inner {
                    Value::I64(v) => Ok(CanonicalValue::I64(v)),
                    // Positive i64 values encode as CBOR unsigned (major 0)
                    Value::U64(v) if v <= i64::MAX as u64 => Ok(CanonicalValue::I64(v as i64)),
                    _ => Err(DecodeError::InvalidCanonicalValueStructure),
                }
            }
            3 => {
                if !has_payload {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let inner = self.decode_value(depth)?;
                match inner {
                    Value::U64(v) => Ok(CanonicalValue::U64(v)),
                    _ => Err(DecodeError::InvalidCanonicalValueStructure),
                }
            }
            4 => {
                if !has_payload {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let inner = self.decode_value(depth)?;
                match inner {
                    Value::Text(v) => Ok(CanonicalValue::Text(v)),
                    _ => Err(DecodeError::InvalidCanonicalValueStructure),
                }
            }
            5 => {
                if !has_payload {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let inner = self.decode_value(depth)?;
                match inner {
                    Value::Bytes(v) => Ok(CanonicalValue::Bytes(v)),
                    _ => Err(DecodeError::InvalidCanonicalValueStructure),
                }
            }
            6 => {
                if !has_payload {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let arr_byte = self.read_byte()?;
                let arr_major = arr_byte >> 5;
                let arr_addl = arr_byte & 0x1f;
                if arr_addl == 31 {
                    return Err(DecodeError::IndefiniteLengthUnsupported);
                }
                if arr_major != 4 {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let item_count = self.decode_head(arr_byte)?;
                if item_count > self.max_item_count {
                    return Err(DecodeError::ValueTooLarge {
                        requested: item_count,
                        max: self.max_item_count,
                    });
                }
                let mut items = Vec::with_capacity(self.usize_from_u64(item_count.min(1024))?);
                for _ in 0..item_count {
                    items.push(self.decode_cv_inner(depth + 1, node_count)?);
                }
                Ok(CanonicalValue::Array(items))
            }
            7 => {
                if !has_payload {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let arr_byte = self.read_byte()?;
                let arr_major = arr_byte >> 5;
                let arr_addl = arr_byte & 0x1f;
                if arr_addl == 31 {
                    return Err(DecodeError::IndefiniteLengthUnsupported);
                }
                if arr_major != 4 {
                    return Err(DecodeError::InvalidCanonicalValueStructure);
                }
                let pair_count = self.decode_head(arr_byte)?;
                if pair_count > self.max_item_count {
                    return Err(DecodeError::ValueTooLarge {
                        requested: pair_count,
                        max: self.max_item_count,
                    });
                }

                let mut entries: Vec<(String, CanonicalValue)> =
                    Vec::with_capacity(self.usize_from_u64(pair_count.min(1024))?);
                let mut prev_key: Option<String> = None;

                for _ in 0..pair_count {
                    let pair_byte = self.read_byte()?;
                    let pair_major = pair_byte >> 5;
                    let pair_addl = pair_byte & 0x1f;
                    if pair_addl == 31 {
                        return Err(DecodeError::IndefiniteLengthUnsupported);
                    }
                    if pair_major != 4 {
                        return Err(DecodeError::InvalidCanonicalValueStructure);
                    }
                    let pair_len = self.decode_head(pair_byte)?;
                    if pair_len != 2 {
                        return Err(DecodeError::InvalidCanonicalValueStructure);
                    }

                    // Key must be text
                    let key_inner = self.decode_value(depth)?;
                    let key = match key_inner {
                        Value::Text(s) => s,
                        _ => return Err(DecodeError::CanonicalMapKeyNotText),
                    };

                    // Check sorted order and duplicates
                    if let Some(ref prev) = prev_key {
                        match prev.as_str().cmp(&key) {
                            std::cmp::Ordering::Less => {}
                            std::cmp::Ordering::Equal => {
                                return Err(DecodeError::DuplicateMapKey);
                            }
                            std::cmp::Ordering::Greater => {
                                return Err(DecodeError::UnsortedMapKey);
                            }
                        }
                    }
                    prev_key = Some(key.clone());

                    let value = self.decode_cv_inner(depth + 1, node_count)?;
                    entries.push((key, value));
                }

                Ok(CanonicalValue::Map(entries.into_iter().collect()))
            }
            _ => Err(DecodeError::InvalidCanonicalValueDiscriminant(disc)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // --- FORMAT.md §21.1 golden vector ---

    #[test]
    fn matches_format_md_golden_vector() {
        let repository_id: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let mut enc = CanonicalEncoder::new();
        enc.begin_map(4);
        // Keys must be in encoded-key order (0 < 1 < 2 < 3 for CBOR uint keys)
        enc.u64(0);
        enc.u64(1);
        enc.u64(1);
        enc.bytes(&repository_id);
        enc.u64(2);
        enc.text("alpha");
        enc.u64(3);
        enc.begin_array(5);
        enc.u64(1);
        enc.i64(-1);
        enc.boolean(true);
        enc.null();
        enc.bytes(&[0x00, 0xff]);

        let expected = "a400010150000102030405060708090a0b0c0d0e0f0265616c70686103850120f5f64200ff";
        assert_eq!(hex(&enc.into_bytes()), expected);
    }

    // --- Shortest integer encoding ---

    #[test]
    fn shortest_unsigned_integers() {
        let test_cases: Vec<(u64, &str)> = vec![
            (0, "00"),
            (1, "01"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65535, "19ffff"),
            (65536, "1a00010000"),
            (0xffff_ffff, "1affffffff"),
            (0x1_0000_0000, "1b0000000100000000"),
            (u64::MAX, "1bffffffffffffffff"),
        ];

        for (val, expected_hex) in test_cases {
            let mut enc = CanonicalEncoder::new();
            enc.u64(val);
            assert_eq!(hex(&enc.into_bytes()), expected_hex, "u64({val}) failed");
        }
    }

    #[test]
    fn shortest_negative_integers() {
        let cases: Vec<(i64, &str)> = vec![
            (-1, "20"),
            (-24, "37"),
            (-25, "3818"),
            (-256, "38ff"),
            (-257, "390100"),
            (-65536, "39ffff"),
            (-65537, "3a00010000"),
            (i64::MIN, "3b7fffffffffffffff"),
        ];

        for (val, expected_hex) in cases {
            let mut enc = CanonicalEncoder::new();
            enc.i64(val);
            assert_eq!(hex(&enc.into_bytes()), expected_hex, "i64({val}) failed");
        }
    }

    #[test]
    fn positive_i64_uses_unsigned_encoding() {
        let mut enc = CanonicalEncoder::new();
        enc.i64(42);
        assert_eq!(hex(&enc.into_bytes()), "182a");
    }

    // --- String / bytestring length encoding ---

    #[test]
    fn text_shortest_length() {
        let mut enc = CanonicalEncoder::new();
        enc.text(""); // length 0
        assert_eq!(hex(&enc.into_bytes()), "60");
    }

    #[test]
    fn text_longer_than_23() {
        let s = "x".repeat(24);
        let mut enc = CanonicalEncoder::new();
        enc.text(&s);
        let bytes = enc.into_bytes();
        // Should be 0x78 (major 3 | 24) + 1 byte length + 24 bytes of "x"*24
        assert_eq!(bytes[0], 0x78);
        assert_eq!(bytes[1], 24);
        assert_eq!(&bytes[2..], s.as_bytes());
    }

    #[test]
    fn bytes_empty() {
        let mut enc = CanonicalEncoder::new();
        enc.bytes(&[]);
        assert_eq!(hex(&enc.into_bytes()), "40");
    }

    // --- Simple values ---

    #[test]
    fn boolean_true() {
        let mut enc = CanonicalEncoder::new();
        enc.boolean(true);
        assert_eq!(hex(&enc.into_bytes()), "f5");
    }

    #[test]
    fn boolean_false() {
        let mut enc = CanonicalEncoder::new();
        enc.boolean(false);
        assert_eq!(hex(&enc.into_bytes()), "f4");
    }

    #[test]
    fn encode_null() {
        let mut enc = CanonicalEncoder::new();
        enc.null();
        assert_eq!(hex(&enc.into_bytes()), "f6");
    }

    // --- Arrays ---

    #[test]
    fn empty_array() {
        let mut enc = CanonicalEncoder::new();
        enc.begin_array(0);
        assert_eq!(hex(&enc.into_bytes()), "80");
    }

    #[test]
    fn nested_array() {
        let mut enc = CanonicalEncoder::new();
        enc.begin_array(2);
        enc.u64(1);
        enc.begin_array(1);
        enc.u64(2);
        let bytes = enc.into_bytes();
        // [1, [2]] = 0x82 0x01 0x81 0x02
        assert_eq!(bytes, &[0x82, 0x01, 0x81, 0x02]);
    }

    // --- Map sorting ---

    #[test]
    fn sorted_map_out_of_order_keys() {
        // Insert keys 3, 1, 2 (out of order) and verify they come out sorted
        let mut map = CanonicalSortedMap::new();

        let mut ev = CanonicalEncoder::new();
        ev.u64(3);
        map.insert_u64(3, ev.into_bytes());

        let mut ev = CanonicalEncoder::new();
        ev.u64(1);
        map.insert_u64(1, ev.into_bytes());

        let mut ev = CanonicalEncoder::new();
        ev.u64(2);
        map.insert_u64(2, ev.into_bytes());

        let mut enc = CanonicalEncoder::new();
        map.finish(&mut enc).unwrap();
        let bytes = enc.into_bytes();

        // Expected: sorted by key encoding: 0x01 (key 1), 0x02 (key 2), 0x03 (key 3)
        // map(3) = 0xa3, then:
        //   0x01 0x01  (key 1, value 1)
        //   0x02 0x02  (key 2, value 2)
        //   0x03 0x03  (key 3, value 3)
        assert_eq!(hex(&bytes), "a3010102020303");
    }

    // --- Determinism ---

    #[test]
    fn encoding_is_deterministic() {
        let mut enc1 = CanonicalEncoder::new();
        enc1.begin_array(3);
        enc1.u64(100);
        enc1.text("hello");
        enc1.boolean(false);

        let mut enc2 = CanonicalEncoder::new();
        enc2.begin_array(3);
        enc2.u64(100);
        enc2.text("hello");
        enc2.boolean(false);

        assert_eq!(enc1.into_bytes(), enc2.into_bytes());
    }

    // -----------------------------------------------------------------------
    // Decoder
    // -----------------------------------------------------------------------

    fn decode_ok(input: &[u8]) -> Value {
        let mut dec = CanonicalDecoder::from_limits(input, &FormatLimits::default());
        dec.decode().expect("decode should succeed")
    }

    fn decode_err(input: &[u8]) -> DecodeError {
        let mut dec = CanonicalDecoder::from_limits(input, &FormatLimits::default());
        dec.decode().expect_err("decode should fail")
    }

    fn roundtrip(v: &Value) {
        let encoded = v.reencode();
        let decoded = decode_ok(&encoded);
        assert_eq!(&decoded, v, "roundtrip failed for {v:?}");
    }

    // --- Happy path: re-encode canonical input ---

    #[test]
    fn decode_reencodes_golden_vector() {
        let hex_input =
            "a400010150000102030405060708090a0b0c0d0e0f0265616c70686103850120f5f64200ff";
        let input: Vec<u8> = (0..hex_input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_input[i..i + 2], 16).unwrap())
            .collect();
        let val = decode_ok(&input);
        let reencoded = val.reencode();
        assert_eq!(reencoded, input, "re-encode must be identical");
    }

    #[test]
    fn decode_u64_roundtrip() {
        roundtrip(&Value::U64(0));
        roundtrip(&Value::U64(23));
        roundtrip(&Value::U64(24));
        roundtrip(&Value::U64(255));
        roundtrip(&Value::U64(256));
        roundtrip(&Value::U64(u64::MAX));
    }

    #[test]
    fn decode_i64_roundtrip() {
        roundtrip(&Value::I64(-1));
        roundtrip(&Value::I64(-24));
        roundtrip(&Value::I64(-25));
        roundtrip(&Value::I64(i64::MIN));
    }

    #[test]
    fn decode_bytes_roundtrip() {
        roundtrip(&Value::Bytes(vec![]));
        roundtrip(&Value::Bytes(vec![0x00]));
        roundtrip(&Value::Bytes(vec![0xAB; 100]));
    }

    #[test]
    fn decode_text_roundtrip() {
        roundtrip(&Value::Text("".to_string()));
        roundtrip(&Value::Text("hello".to_string()));
        roundtrip(&Value::Text("héllo wörld ⚡".to_string()));
    }

    #[test]
    fn decode_array_roundtrip() {
        roundtrip(&Value::Array(vec![]));
        roundtrip(&Value::Array(vec![Value::U64(1), Value::U64(2)]));
    }

    #[test]
    fn decode_map_roundtrip() {
        let pairs = vec![
            (Value::U64(0), Value::Text("zero".to_string())),
            (Value::U64(1), Value::Text("one".to_string())),
            (Value::U64(2), Value::Null),
        ];
        roundtrip(&Value::Map(pairs));
    }

    #[test]
    fn decode_boolean_roundtrip() {
        roundtrip(&Value::Boolean(true));
        roundtrip(&Value::Boolean(false));
    }

    #[test]
    fn decode_null_roundtrip() {
        roundtrip(&Value::Null);
    }

    // --- Rejection cases ---

    #[test]
    fn rejects_trailing_data() {
        let mut enc = CanonicalEncoder::new();
        enc.u64(42);
        let mut bytes = enc.into_bytes();
        bytes.push(0x00); // trailing byte
        assert_eq!(decode_err(&bytes), DecodeError::TrailingData);
    }

    #[test]
    fn rejects_non_shortest_u24_as_2byte() {
        // 24 encoded as 0x190018 (2-byte uint with value 24) instead of 0x1818
        assert_eq!(
            decode_err(&[0x19, 0x00, 0x18]),
            DecodeError::NonShortestInteger
        );
    }

    #[test]
    fn rejects_non_shortest_u256_as_4byte() {
        // 256 encoded as 0x1a00000100 (4-byte) instead of 0x190100 (2-byte)
        assert_eq!(
            decode_err(&[0x1a, 0x00, 0x00, 0x01, 0x00]),
            DecodeError::NonShortestInteger
        );
    }

    #[test]
    fn rejects_non_shortest_u65536_as_8byte() {
        // 65536 encoded as 0x1b0000000000010000 (8-byte) instead of 0x1a00010000
        assert_eq!(
            decode_err(&[0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
            DecodeError::NonShortestInteger
        );
    }

    #[test]
    fn rejects_negative_non_shortest() {
        // -25 encoded as 0x390018 (2-byte) instead of 0x3818
        assert_eq!(
            decode_err(&[0x39, 0x00, 0x18]),
            DecodeError::NonShortestInteger
        );
    }

    #[test]
    fn rejects_indefinite_array() {
        // 0x9f = indefinite-length array
        assert_eq!(
            decode_err(&[0x9f]),
            DecodeError::IndefiniteLengthUnsupported
        );
    }

    #[test]
    fn rejects_indefinite_map() {
        // 0xbf = indefinite-length map
        assert_eq!(
            decode_err(&[0xbf]),
            DecodeError::IndefiniteLengthUnsupported
        );
    }

    #[test]
    fn rejects_indefinite_bytes() {
        // 0x5f = indefinite-length byte string
        assert_eq!(
            decode_err(&[0x5f]),
            DecodeError::IndefiniteLengthUnsupported
        );
    }

    #[test]
    fn rejects_indefinite_text() {
        // 0x7f = indefinite-length text string
        assert_eq!(
            decode_err(&[0x7f]),
            DecodeError::IndefiniteLengthUnsupported
        );
    }

    #[test]
    fn rejects_float16() {
        assert_eq!(
            decode_err(&[0xf9, 0x00, 0x00]),
            DecodeError::FloatUnsupported
        );
    }

    #[test]
    fn rejects_float32() {
        assert_eq!(
            decode_err(&[0xfa, 0x00, 0x00, 0x00, 0x00]),
            DecodeError::FloatUnsupported
        );
    }

    #[test]
    fn rejects_float64() {
        assert_eq!(
            decode_err(&[0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            DecodeError::FloatUnsupported
        );
    }

    #[test]
    fn rejects_undefined() {
        // 0xf7 = undefined
        assert_eq!(decode_err(&[0xf7]), DecodeError::SimpleValueUnsupported(23));
    }

    #[test]
    fn rejects_simple_value_24() {
        // 0xf8 0x18 = simple value 24
        assert_eq!(
            decode_err(&[0xf8, 0x18]),
            DecodeError::SimpleValueUnsupported(24)
        );
    }

    #[test]
    fn rejects_tag() {
        // 0xc0 = tag 0 (major type 6)
        assert_eq!(decode_err(&[0xc0, 0x00]), DecodeError::TagUnsupported);
    }

    #[test]
    fn rejects_invalid_utf8() {
        // 0x62 = text string length 2, followed by invalid UTF-8 bytes 0xFF 0xFE
        assert_eq!(decode_err(&[0x62, 0xff, 0xfe]), DecodeError::InvalidUtf8);
    }

    #[test]
    fn rejects_duplicate_map_key() {
        // Map with two entries both having key 0: {0: 1, 0: 2}
        let bytes = [0xa2, 0x00, 0x01, 0x00, 0x02];
        assert_eq!(decode_err(&bytes), DecodeError::DuplicateMapKey);
    }

    #[test]
    fn rejects_unsorted_map_key() {
        // Map with keys 1, 0 (out of order): {1: 1, 0: 2}
        let bytes = [0xa2, 0x01, 0x01, 0x00, 0x02];
        assert_eq!(decode_err(&bytes), DecodeError::UnsortedMapKey);
    }

    #[test]
    fn rejects_depth_exceeded() {
        // Build a deeply nested array: [[[[...[1]...]]]]
        // Depth 65, max_depth is 64
        let mut inner = vec![0x01]; // uint 1
        for _ in 0..65 {
            let mut outer = vec![0x81]; // array(1)
            outer.extend_from_slice(&inner);
            inner = outer;
        }
        assert_eq!(decode_err(&inner), DecodeError::DepthExceeded);
    }

    #[test]
    fn rejects_oversized_string() {
        // text string with length exceeding max_string_bytes (1_048_576)
        let mut bytes = vec![0x7a, 0x00, 0x20, 0x00, 0x00]; // major 3, addl 26, length as u32 = 0x200000 > 1_048_576
        bytes.extend(std::iter::repeat_n(0x61, 100)); // enough bytes to reach length check
        assert_eq!(
            decode_err(&bytes),
            DecodeError::ValueTooLarge {
                requested: 0x200000,
                max: 1_048_576
            }
        );
    }

    #[test]
    fn rejects_unexpected_eof() {
        assert_eq!(decode_err(&[]), DecodeError::UnexpectedEof);
        assert_eq!(decode_err(&[0x18]), DecodeError::UnexpectedEof); // uint expects 1 more byte
    }

    // --- Complex nested decode ---

    #[test]
    fn decode_nested_structure() {
        // nested array + map
        let mut enc = CanonicalEncoder::new();
        enc.begin_array(2);
        enc.begin_map(1);
        enc.u64(10);
        enc.text("ten");
        enc.begin_array(2);
        enc.boolean(true);
        enc.null();
        let bytes = enc.into_bytes();
        let val = decode_ok(&bytes);
        let re = val.reencode();
        assert_eq!(re, bytes);
    }

    #[test]
    fn decode_map_with_text_keys() {
        let mut enc = CanonicalEncoder::new();
        enc.begin_map(2);
        enc.text("a");
        enc.u64(1);
        enc.text("b");
        enc.u64(2);
        let bytes = enc.into_bytes();
        let val = decode_ok(&bytes);
        let re = val.reencode();
        assert_eq!(re, bytes);
    }

    // -----------------------------------------------------------------------
    // CanonicalValue tests
    // -----------------------------------------------------------------------

    fn cv_ok(input: &[u8]) -> CanonicalValue {
        let mut dec = CanonicalDecoder::from_limits(input, &FormatLimits::default());
        dec.decode_canonical_value()
            .expect("cv decode should succeed")
    }

    fn cv_err(input: &[u8]) -> DecodeError {
        let mut dec = CanonicalDecoder::from_limits(input, &FormatLimits::default());
        dec.decode_canonical_value()
            .expect_err("cv decode should fail")
    }

    fn cv_roundtrip(v: &CanonicalValue) {
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(v);
        let bytes = enc.into_bytes();
        let decoded = cv_ok(&bytes);
        assert_eq!(&decoded, v, "cv roundtrip failed for {v:?}");
    }

    #[test]
    fn cv_null_roundtrip() {
        cv_roundtrip(&CanonicalValue::Null);
    }

    #[test]
    fn cv_bool_roundtrip() {
        cv_roundtrip(&CanonicalValue::Bool(true));
        cv_roundtrip(&CanonicalValue::Bool(false));
    }

    #[test]
    fn cv_i64_roundtrip() {
        cv_roundtrip(&CanonicalValue::I64(0));
        cv_roundtrip(&CanonicalValue::I64(-1));
        cv_roundtrip(&CanonicalValue::I64(i64::MIN));
        cv_roundtrip(&CanonicalValue::I64(i64::MAX));
    }

    #[test]
    fn cv_u64_roundtrip() {
        cv_roundtrip(&CanonicalValue::U64(0));
        cv_roundtrip(&CanonicalValue::U64(u64::MAX));
    }

    #[test]
    fn cv_text_roundtrip() {
        cv_roundtrip(&CanonicalValue::Text("".into()));
        cv_roundtrip(&CanonicalValue::Text("hello".into()));
        cv_roundtrip(&CanonicalValue::Text("héllo wörld ⚡".into()));
    }

    #[test]
    fn cv_bytes_roundtrip() {
        cv_roundtrip(&CanonicalValue::Bytes(vec![]));
        cv_roundtrip(&CanonicalValue::Bytes(vec![0x00, 0xff]));
    }

    #[test]
    fn cv_array_roundtrip() {
        cv_roundtrip(&CanonicalValue::Array(vec![]));
        cv_roundtrip(&CanonicalValue::Array(vec![
            CanonicalValue::Null,
            CanonicalValue::Bool(true),
        ]));
        cv_roundtrip(&CanonicalValue::Array(vec![
            CanonicalValue::I64(42),
            CanonicalValue::U64(100),
            CanonicalValue::Text("x".into()),
            CanonicalValue::Bytes(vec![0xab]),
        ]));
    }

    #[test]
    fn cv_map_roundtrip() {
        use std::collections::BTreeMap;
        let mut m = BTreeMap::new();
        m.insert("a".into(), CanonicalValue::U64(1));
        m.insert("b".into(), CanonicalValue::Text("two".into()));
        cv_roundtrip(&CanonicalValue::Map(m));
    }

    #[test]
    fn cv_nested_array_map_roundtrip() {
        use std::collections::BTreeMap;
        let mut inner = BTreeMap::new();
        inner.insert(
            "key".into(),
            CanonicalValue::Array(vec![CanonicalValue::U64(1), CanonicalValue::U64(2)]),
        );
        let outer = CanonicalValue::Array(vec![CanonicalValue::Null, CanonicalValue::Map(inner)]);
        cv_roundtrip(&outer);
    }

    #[test]
    fn cv_rejects_non_array_outer() {
        // Just a bare u64 0 — not an array wrapper
        assert_eq!(cv_err(&[0x00]), DecodeError::InvalidCanonicalValueStructure);
    }

    #[test]
    fn cv_rejects_wrong_array_length() {
        // Empty array instead of [0] for Null
        assert_eq!(cv_err(&[0x80]), DecodeError::InvalidCanonicalValueStructure);
        // Array of length 3
        assert_eq!(
            cv_err(&[0x83, 0x00, 0x00, 0x00]),
            DecodeError::InvalidCanonicalValueStructure
        );
    }

    #[test]
    fn cv_rejects_discriminant_not_uint() {
        // Array [null, ...] — null is not a uint discriminant
        assert_eq!(
            cv_err(&[0x82, 0xf6, 0x00]),
            DecodeError::InvalidCanonicalValueStructure
        );
    }

    #[test]
    fn cv_rejects_discriminant_out_of_range() {
        // Array [8, ...] — discriminant 8 > 7
        assert_eq!(
            cv_err(&[0x82, 0x08, 0x00]),
            DecodeError::InvalidCanonicalValueDiscriminant(8)
        );
    }

    #[test]
    fn cv_rejects_wrong_bool_payload() {
        // [1, 42] — discriminant 1 (Bool) but payload is u64 42, not boolean
        let bytes = vec![0x82, 0x01, 0x18, 0x2a];
        assert_eq!(cv_err(&bytes), DecodeError::InvalidCanonicalValueStructure);
    }

    #[test]
    fn cv_rejects_wrong_i64_payload() {
        // [2, "hello"] — discriminant 2 (I64) but payload is text
        let bytes = vec![0x82, 0x02, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f];
        assert_eq!(cv_err(&bytes), DecodeError::InvalidCanonicalValueStructure);
    }

    #[test]
    fn cv_rejects_wrong_u64_payload() {
        // [3, true] — discriminant 3 (U64) but payload is boolean
        let bytes = vec![0x82, 0x03, 0xf5];
        assert_eq!(cv_err(&bytes), DecodeError::InvalidCanonicalValueStructure);
    }

    #[test]
    fn cv_rejects_wrong_text_payload() {
        // [4, null] — discriminant 4 (Text) but payload is null
        let bytes = vec![0x82, 0x04, 0xf6];
        assert_eq!(cv_err(&bytes), DecodeError::InvalidCanonicalValueStructure);
    }

    #[test]
    fn cv_rejects_wrong_bytes_payload() {
        // [5, []] — discriminant 5 (Bytes) but payload is array
        let bytes = vec![0x82, 0x05, 0x80];
        assert_eq!(cv_err(&bytes), DecodeError::InvalidCanonicalValueStructure);
    }

    #[test]
    fn cv_rejects_non_text_map_key() {
        // [7, [[0, null]]] — key is u64 0, not text
        let bytes = vec![
            0x82, 0x07, // outer [7, ...]
            0x81, // inner array of 1 pair
            0x82, 0x00, 0xf6, // pair [0, null] — key 0 is u64, not text
        ];
        assert_eq!(cv_err(&bytes), DecodeError::CanonicalMapKeyNotText);
    }

    #[test]
    fn cv_rejects_duplicate_map_keys() {
        // [7, [["a", null], ["a", null]]] — duplicate key "a"
        // Encode directly (BTreeMap silently deduplicates)
        let mut enc = CanonicalEncoder::new();
        enc.begin_array(2);
        enc.u64(7);
        enc.begin_array(2);
        enc.begin_array(2);
        enc.text("a");
        enc.canonical_value(&CanonicalValue::Null);
        enc.begin_array(2);
        enc.text("a");
        enc.canonical_value(&CanonicalValue::Null);
        let bytes = enc.into_bytes();
        assert_eq!(cv_err(&bytes), DecodeError::DuplicateMapKey);
    }

    #[test]
    fn cv_rejects_unsorted_map_keys() {
        // Encode map with keys "b", "a" (unsorted)
        let mut enc = CanonicalEncoder::new();
        enc.begin_array(2);
        enc.u64(7);
        enc.begin_array(2);
        // pair ["b", null]
        enc.begin_array(2);
        enc.text("b");
        enc.canonical_value(&CanonicalValue::Null);
        // pair ["a", null]
        enc.begin_array(2);
        enc.text("a");
        enc.canonical_value(&CanonicalValue::Null);
        let bytes = enc.into_bytes();
        assert_eq!(cv_err(&bytes), DecodeError::UnsortedMapKey);
    }

    #[test]
    fn cv_rejects_float_in_payload() {
        // [2, 1.5] — discriminant 2 (I64) but payload is float
        let bytes = vec![
            0x82, 0x02, // outer [2, ...]
            0xf9, 0x3e, 0x00, // half-precision 1.5
        ];
        assert_eq!(cv_err(&bytes), DecodeError::FloatUnsupported);
    }

    #[test]
    fn cv_rejects_trailing_data() {
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(&CanonicalValue::Null);
        let mut bytes = enc.into_bytes();
        bytes.push(0x00);
        assert_eq!(cv_err(&bytes), DecodeError::TrailingData);
    }

    #[test]
    fn cv_rejects_depth_exceeded() {
        // Build deeply nested Array: Array(Array(Array(...(Null)...)))
        // Depth 65, max_depth is 64
        let mut inner = CanonicalValue::Null;
        for _ in 0..65 {
            inner = CanonicalValue::Array(vec![inner]);
        }
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(&inner);
        let bytes = enc.into_bytes();
        assert_eq!(cv_err(&bytes), DecodeError::DepthExceeded);
    }

    #[test]
    fn cv_rejects_node_count_exceeded() {
        // Array with 1_000_001 nulls exceeds 1_000_000 node limit
        let cv = CanonicalValue::Array(vec![CanonicalValue::Null; 1_000_001]);
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(&cv);
        let bytes = enc.into_bytes();
        assert_eq!(
            cv_err(&bytes),
            DecodeError::ValueTooLarge {
                requested: 1_000_001, // outer Array counts as 1st node, then 1_000_000 Nulls fit, 1_000_001st Null exceeds
                max: 1_000_000,
            }
        );
    }

    // --- JSON conversion ---

    #[test]
    fn json_null() {
        let cv: CanonicalValue = serde_json::json!(null).try_into().unwrap();
        assert_eq!(cv, CanonicalValue::Null);
    }

    #[test]
    fn json_bool() {
        let t: CanonicalValue = serde_json::json!(true).try_into().unwrap();
        assert_eq!(t, CanonicalValue::Bool(true));
        let f: CanonicalValue = serde_json::json!(false).try_into().unwrap();
        assert_eq!(f, CanonicalValue::Bool(false));
    }

    #[test]
    fn json_integer() {
        let cv: CanonicalValue = serde_json::json!(42).try_into().unwrap();
        assert_eq!(cv, CanonicalValue::I64(42));
        let cv: CanonicalValue = serde_json::json!(-1).try_into().unwrap();
        assert_eq!(cv, CanonicalValue::I64(-1));
        let cv: CanonicalValue = serde_json::json!(i64::MAX).try_into().unwrap();
        assert_eq!(cv, CanonicalValue::I64(i64::MAX));
        // u64::MAX is too large for i64, so it maps to U64
        let cv: CanonicalValue = serde_json::json!(u64::MAX).try_into().unwrap();
        assert_eq!(cv, CanonicalValue::U64(u64::MAX));
    }

    #[test]
    fn json_string() {
        let cv: CanonicalValue = serde_json::json!("hello").try_into().unwrap();
        assert_eq!(cv, CanonicalValue::Text("hello".to_string()));
    }

    #[test]
    fn json_array() {
        let cv: CanonicalValue = serde_json::json!([1, "two", null]).try_into().unwrap();
        assert_eq!(
            cv,
            CanonicalValue::Array(vec![
                CanonicalValue::I64(1),
                CanonicalValue::Text("two".to_string()),
                CanonicalValue::Null,
            ])
        );
    }

    #[test]
    fn json_object() {
        let cv: CanonicalValue = serde_json::json!({"b": 2, "a": 1}).try_into().unwrap();
        let mut expected = std::collections::BTreeMap::new();
        expected.insert("a".to_string(), CanonicalValue::I64(1));
        expected.insert("b".to_string(), CanonicalValue::I64(2));
        assert_eq!(cv, CanonicalValue::Map(expected));
    }

    #[test]
    fn json_rejects_float() {
        let result: Result<CanonicalValue, _> = serde_json::json!(1.5).try_into();
        assert_eq!(result, Err(CanonicalEncodeError::FloatUnsupported));
    }

    #[test]
    fn json_rejects_nested_float() {
        let result: Result<CanonicalValue, _> = serde_json::json!({"a": [1, 2.5]}).try_into();
        assert_eq!(result, Err(CanonicalEncodeError::FloatUnsupported));
    }

    #[test]
    fn json_rejects_depth_exceeded() {
        // Build a JSON array nested 65 levels deep (limit is 64)
        let mut val: serde_json::Value = serde_json::json!(null);
        for _ in 0..65 {
            val = serde_json::json!([val]);
        }
        let result: Result<CanonicalValue, _> = val.try_into();
        assert_eq!(result, Err(CanonicalEncodeError::DepthExceeded));
    }

    #[test]
    fn json_round_trip() {
        let json_val = serde_json::json!({
            "name": "test",
            "count": 100,
            "active": true,
            "tags": ["a", "b"],
            "meta": {"x": null},
        });
        let cv: CanonicalValue = json_val.try_into().unwrap();
        // Re-encode to CBOR and back
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(&cv);
        let bytes = enc.into_bytes();
        let custom = FormatLimits::default().with_max_depth(32).unwrap();
        let mut dec = CanonicalDecoder::from_limits(&bytes, &custom);
        let decoded = dec.decode_canonical_value().unwrap();
        assert_eq!(cv, decoded);
    }

    // -----------------------------------------------------------------------
    // Bounded encoder tests
    // -----------------------------------------------------------------------

    #[test]
    fn bounded_encode_simple_value() {
        let cv = CanonicalValue::I64(42);
        let bytes = encode_canonical_value(&cv, &FormatLimits::default()).unwrap();
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(&cv);
        assert_eq!(bytes, enc.into_bytes());
    }

    #[test]
    fn bounded_encode_nested_at_depth_64() {
        let mut inner = CanonicalValue::Null;
        for _ in 0..64 {
            inner = CanonicalValue::Array(vec![inner]);
        }
        let bytes = encode_canonical_value(&inner, &FormatLimits::default());
        assert!(bytes.is_ok());
    }

    #[test]
    fn bounded_encode_rejects_depth_65() {
        let mut inner = CanonicalValue::Null;
        for _ in 0..65 {
            inner = CanonicalValue::Array(vec![inner]);
        }
        let result = encode_canonical_value(&inner, &FormatLimits::default());
        assert_eq!(result, Err(CanonicalEncodeError::DepthExceeded));
    }

    #[test]
    fn bounded_encode_rejects_node_count_exceeded() {
        let items: Vec<CanonicalValue> = (0..1_000_001).map(|_| CanonicalValue::Null).collect();
        let cv = CanonicalValue::Array(items);
        let limits = FormatLimits::default();
        // 1_000_001 items + 1 Array node = 1_000_002 > 1_000_000
        let result = encode_canonical_value(&cv, &limits);
        assert_eq!(
            result,
            Err(CanonicalEncodeError::NodeCountExceeded {
                max: FormatLimits::ABSOLUTE_MAX_NODES
            })
        );
    }

    #[test]
    fn bounded_encode_rejects_long_string() {
        let s = "x".repeat(1_048_577);
        let cv = CanonicalValue::Text(s);
        let limits = FormatLimits::default();
        let result = encode_canonical_value(&cv, &limits);
        assert_eq!(
            result,
            Err(CanonicalEncodeError::StringTooLong {
                max: FormatLimits::ABSOLUTE_MAX_STRING_BYTES,
                actual: 1_048_577
            })
        );
    }

    #[test]
    fn bounded_encode_accepts_max_string() {
        let s = "x".repeat(1_048_576);
        let cv = CanonicalValue::Text(s.clone());
        let result = encode_canonical_value(&cv, &FormatLimits::default()).unwrap();
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(&CanonicalValue::Text(s));
        assert_eq!(result, enc.into_bytes());
    }

    #[test]
    fn bounded_encode_rejects_nul_in_text() {
        let cv = CanonicalValue::Text("hello\0world".to_string());
        let result = encode_canonical_value(&cv, &FormatLimits::default());
        assert_eq!(result, Err(CanonicalEncodeError::TextContainsNul));
    }

    #[test]
    fn bounded_encode_rejects_nul_in_map_key() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("bad\0key".to_string(), CanonicalValue::U64(1));
        let cv = CanonicalValue::Map(map);
        let result = encode_canonical_value(&cv, &FormatLimits::default());
        assert_eq!(result, Err(CanonicalEncodeError::TextContainsNul));
    }

    #[test]
    fn bounded_encode_rejects_bytes_above_limit() {
        let b = vec![0u8; 1_048_577];
        let cv = CanonicalValue::Bytes(b);
        let limits = FormatLimits::default();
        let result = encode_canonical_value(&cv, &limits);
        assert_eq!(
            result,
            Err(CanonicalEncodeError::StringTooLong {
                max: FormatLimits::ABSOLUTE_MAX_STRING_BYTES,
                actual: 1_048_577
            })
        );
    }

    #[test]
    fn json_rejects_nul_in_text() {
        let result: Result<CanonicalValue, _> = serde_json::json!("hello\0world").try_into();
        assert_eq!(result, Err(CanonicalEncodeError::TextContainsNul));
    }

    #[test]
    fn json_rejects_nul_in_map_key() {
        let result: Result<CanonicalValue, _> = serde_json::json!({"bad\0key": 1}).try_into();
        assert_eq!(result, Err(CanonicalEncodeError::TextContainsNul));
    }

    #[test]
    fn json_rejects_long_string() {
        let s = "x".repeat(1_048_577);
        let result: Result<CanonicalValue, _> = serde_json::Value::String(s).try_into();
        assert_eq!(
            result,
            Err(CanonicalEncodeError::StringTooLong {
                max: FormatLimits::ABSOLUTE_MAX_STRING_BYTES,
                actual: 1_048_577
            })
        );
    }

    #[test]
    fn json_slice_basic() {
        let cv = canonical_value_from_json_slice(b"{\"a\":1,\"b\":2}", &FormatLimits::default())
            .unwrap();
        let mut expected = std::collections::BTreeMap::new();
        expected.insert("a".to_string(), CanonicalValue::I64(1));
        expected.insert("b".to_string(), CanonicalValue::I64(2));
        assert_eq!(cv, CanonicalValue::Map(expected));
    }

    #[test]
    fn json_slice_rejects_duplicate_keys() {
        let result =
            canonical_value_from_json_slice(b"{\"a\":1,\"a\":2}", &FormatLimits::default());
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::DuplicateTextKey { .. })
        ));
    }

    #[test]
    fn json_slice_rejects_nested_duplicate_keys() {
        let result =
            canonical_value_from_json_slice(b"{\"x\":{\"a\":1,\"a\":2}}", &FormatLimits::default());
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::DuplicateTextKey { .. })
        ));
    }

    #[test]
    fn json_slice_rejects_float() {
        let result = canonical_value_from_json_slice(b"1.5", &FormatLimits::default());
        assert_eq!(result, Err(CanonicalEncodeError::FloatUnsupported));
    }

    #[test]
    fn json_slice_rejects_nul() {
        let result = canonical_value_from_json_slice(
            b"\"hello\\u0000world\"", // JSON escape for NUL
            &FormatLimits::default(),
        );
        assert_eq!(result, Err(CanonicalEncodeError::TextContainsNul));
    }

    #[test]
    fn json_slice_node_limit() {
        // A flat array of 10 nodes with a custom limit of 5 should fail
        let limits = FormatLimits::default().with_max_nodes(5).unwrap();
        let result = canonical_value_from_json_slice(b"[1,2,3,4,5,6,7,8,9,10]", &limits);
        assert_eq!(
            result,
            Err(CanonicalEncodeError::NodeCountExceeded { max: 5 })
        );
    }

    #[test]
    fn decoder_from_limits_accepts_limits_reference() {
        let limits = FormatLimits::default()
            .with_max_depth(16)
            .unwrap()
            .with_max_nodes(100)
            .unwrap()
            .with_max_string_bytes(1024)
            .unwrap();
        let cv = CanonicalValue::Array(vec![CanonicalValue::Null; 10]);
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(&cv);
        let bytes = enc.into_bytes();

        let mut dec = CanonicalDecoder::from_limits(&bytes, &limits);
        let decoded = dec.decode_canonical_value().unwrap();
        assert_eq!(decoded, cv);
    }

    #[test]
    fn decoder_from_limits_enforces_custom_node_limit() {
        let limits = FormatLimits::default()
            .with_max_depth(16)
            .unwrap()
            .with_max_nodes(5)
            .unwrap();
        let cv = CanonicalValue::Array(vec![CanonicalValue::Null; 10]);
        let mut enc = CanonicalEncoder::new();
        enc.canonical_value(&cv);
        let bytes = enc.into_bytes();

        let mut dec = CanonicalDecoder::from_limits(&bytes, &limits);
        let err = dec
            .decode_canonical_value()
            .expect_err("should exceed node limit");
        assert!(matches!(err, DecodeError::ValueTooLarge { .. }));
    }

    #[test]
    fn from_json_value_accepts_limits_reference() {
        let limits = FormatLimits::default()
            .with_max_depth(16)
            .unwrap()
            .with_max_nodes(100)
            .unwrap()
            .with_max_string_bytes(1024)
            .unwrap();
        let value = serde_json::json!([1, 2, 3]);
        let cv = CanonicalValue::from_json_value(value, &limits).unwrap();
        assert_eq!(
            cv,
            CanonicalValue::Array(vec![
                CanonicalValue::I64(1),
                CanonicalValue::I64(2),
                CanonicalValue::I64(3),
            ])
        );
    }

    #[test]
    fn from_json_value_enforces_custom_node_limit() {
        let limits = FormatLimits::default()
            .with_max_depth(16)
            .unwrap()
            .with_max_nodes(3)
            .unwrap();
        let value = serde_json::json!([1, 2, 3, 4, 5]);
        let result = CanonicalValue::from_json_value(value, &limits);
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::NodeCountExceeded { .. })
        ));
    }

    #[test]
    fn encode_canonical_value_rejects_zero_limit() {
        let limits = FormatLimits::default();
        // Encoding with default limits must succeed for a simple value.
        let cv = CanonicalValue::Null;
        assert!(encode_canonical_value(&cv, &limits).is_ok());

        // Allocation checks happen before allocation: node count exceeding
        // limit must be rejected before any output buffer is written.
        let tight = FormatLimits::default().with_max_nodes(1).unwrap();
        let arr = CanonicalValue::Array(vec![CanonicalValue::Null, CanonicalValue::Null]);
        let result = encode_canonical_value(&arr, &tight);
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::NodeCountExceeded { .. })
        ));
    }

    // --- Allocation-before-check proof tests ---
    // These prove that limits are checked BEFORE reading payload data,
    // not after a full allocation has already occurred.

    #[test]
    fn oversized_string_header_rejected_before_read() {
        // CBOR byte string header with length > max_string_bytes but NO payload.
        // Must return ValueTooLarge, not UnexpectedEof.
        // Major 2, addl 26 (4-byte length), length = 2_000_000 > 1_048_576
        let bytes = vec![0x5a, 0x00, 0x1e, 0x84, 0x80];
        let err = decode_err(&bytes);
        assert_eq!(
            err,
            DecodeError::ValueTooLarge {
                requested: 2_000_000,
                max: 1_048_576
            }
        );
    }

    #[test]
    fn oversized_array_count_rejected_before_read() {
        // CBOR array header with count > max_item_count but NO elements.
        // Must return ValueTooLarge, not UnexpectedEof.
        // Major 4, addl 26 (4-byte count), count = 2_000_000 > 1_000_000
        let bytes = vec![0x9a, 0x00, 0x1e, 0x84, 0x80];
        let err = decode_err(&bytes);
        assert_eq!(
            err,
            DecodeError::ValueTooLarge {
                requested: 2_000_000,
                max: 1_000_000
            }
        );
    }

    #[test]
    fn oversized_text_header_rejected_before_read() {
        // CBOR text string header with length > max_string_bytes but NO payload.
        // Must return ValueTooLarge, not UnexpectedEof.
        // Major 3, addl 26 (4-byte length), length = 2_000_000 > 1_048_576
        let bytes = vec![0x7a, 0x00, 0x1e, 0x84, 0x80];
        let err = decode_err(&bytes);
        assert_eq!(
            err,
            DecodeError::ValueTooLarge {
                requested: 2_000_000,
                max: 1_048_576
            }
        );
    }

    #[test]
    fn oversized_map_count_rejected_before_read() {
        // CBOR map header with count > max_item_count but NO pairs.
        // Must return ValueTooLarge, not UnexpectedEof.
        // Major 5, addl 26 (4-byte count), count = 2_000_000 > 1_000_000
        let bytes = vec![0xba, 0x00, 0x1e, 0x84, 0x80];
        let err = decode_err(&bytes);
        assert_eq!(
            err,
            DecodeError::ValueTooLarge {
                requested: 2_000_000,
                max: 1_000_000
            }
        );
    }

    #[test]
    fn json_input_exceeds_metadata_limit() {
        // JSON input exceeding max_metadata_bytes must be rejected before
        // parsing begins.
        let tight = FormatLimits::default().with_max_metadata_bytes(8).unwrap();
        let input = b"\"too long for 8-byte limit\"";
        let result = canonical_value_from_json_slice(input, &tight);
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn precomputed_size_matches_actual_for_each_variant() {
        // Prove that compute_encoded_size returns the exact encoded byte count
        // for every CanonicalValue variant by comparing against actual encoding.
        let default = FormatLimits::default();
        let cases: Vec<CanonicalValue> = vec![
            CanonicalValue::Null,
            CanonicalValue::Bool(true),
            CanonicalValue::Bool(false),
            CanonicalValue::I64(0),
            CanonicalValue::I64(-1),
            CanonicalValue::I64(1 << 20),
            CanonicalValue::I64(-(1 << 20)),
            CanonicalValue::U64(0),
            CanonicalValue::U64(255),
            CanonicalValue::U64(1 << 24),
            CanonicalValue::U64(1 << 40),
            CanonicalValue::Text("hello".to_string()),
            CanonicalValue::Text("".to_string()),
            CanonicalValue::Bytes(vec![0x00; 100]),
            CanonicalValue::Bytes(vec![]),
            CanonicalValue::Array(vec![CanonicalValue::Null, CanonicalValue::Null]),
            CanonicalValue::Array(vec![
                CanonicalValue::I64(1),
                CanonicalValue::I64(2),
                CanonicalValue::I64(3),
            ]),
            CanonicalValue::Array(vec![
                CanonicalValue::Text("abc".to_string()),
                CanonicalValue::Text("defg".to_string()),
            ]),
        ];
        for cv in &cases {
            let mut nc = 0u64;
            let size = compute_encoded_size(cv, 0, &mut nc, &default).unwrap();
            let encoded = encode_canonical_value(cv, &default).unwrap();
            assert_eq!(
                size,
                encoded.len() as u64,
                "size mismatch for {:?}: computed {} != actual {}",
                cv,
                size,
                encoded.len()
            );
        }
    }

    #[test]
    fn precomputed_size_matches_actual_for_map() {
        // Separate test for Map because it's the most complex variant.
        let default = FormatLimits::default();
        let mut map = std::collections::BTreeMap::new();
        map.insert("key1".to_string(), CanonicalValue::Null);
        map.insert("key2".to_string(), CanonicalValue::Bool(true));
        map.insert("key3".to_string(), CanonicalValue::U64(42));
        let cv = CanonicalValue::Map(map);

        let mut nc = 0u64;
        let size = compute_encoded_size(&cv, 0, &mut nc, &default).unwrap();
        let encoded = encode_canonical_value(&cv, &default).unwrap();
        assert_eq!(size, encoded.len() as u64);
    }

    #[test]
    fn encode_rejects_one_byte_over_metadata_limit() {
        // Pre-computed size = 2 for Null. Set limit to 1 → rejection.
        let tight = FormatLimits::default().with_max_metadata_bytes(1).unwrap();
        let cv = CanonicalValue::Null;
        let result = encode_canonical_value(&cv, &tight);
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn encode_accepts_metadata_at_exact_limit() {
        // Null encodes as [0] = 2 bytes. Set limit to 2 → acceptance.
        let tight = FormatLimits::default().with_max_metadata_bytes(2).unwrap();
        let cv = CanonicalValue::Null;
        let result = encode_canonical_value(&cv, &tight);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x81, 0x00]);
    }

    #[test]
    fn decode_rejects_input_exceeding_metadata_limit() {
        // CBOR input exceeding max_metadata_bytes must be rejected before parsing.
        let tight = FormatLimits::default().with_max_metadata_bytes(2).unwrap();
        // Null encodes as [0] = 0x81 0x00 = 2 bytes — within limit
        let bytes = vec![0x81, 0x00];
        let mut dec = CanonicalDecoder::from_limits(&bytes, &tight);
        assert!(dec.decode_canonical_value().is_ok());

        // 3 bytes exceeds metadata limit of 2
        let too_big = vec![0x82, 0x00, 0x00];
        let mut dec = CanonicalDecoder::from_limits(&too_big, &tight);
        let err = dec
            .decode_canonical_value()
            .expect_err("should exceed metadata limit");
        assert!(matches!(err, DecodeError::ValueTooLarge { .. }));
    }

    #[test]
    fn encode_rejects_small_strings_summing_over_metadata_limit() {
        // Multiple individually-valid small strings that together exceed
        // max_metadata_bytes must be rejected before allocation.
        // Each text "aaaaaa" = array(2) + u64(4) + head(3,6) + 6 = 9 bytes.
        // Three texts + outer array(2) + u64(6) + head(4,3) = 2 + 27 = 29 bytes.
        // With max_metadata_bytes=16, the 29-byte value must be rejected.
        let tight = FormatLimits::default().with_max_metadata_bytes(16).unwrap();
        let cv = CanonicalValue::Array(vec![
            CanonicalValue::Text("aaaaaa".to_string()),
            CanonicalValue::Text("bbbbbb".to_string()),
            CanonicalValue::Text("cccccc".to_string()),
        ]);
        // Prove pre-computed size exceeds limit
        let mut nc = 0u64;
        let size = compute_encoded_size(&cv, 0, &mut nc, &tight).unwrap();
        assert!(size > 16, "computed size {} should exceed limit 16", size);
        // Prove encoding returns InputTooLarge
        let result = encode_canonical_value(&cv, &tight);
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn encode_rejects_map_exceeding_metadata_limit() {
        // Map with enough entries to exceed a tight metadata limit.
        let tight = FormatLimits::default().with_max_metadata_bytes(10).unwrap();
        let mut map = std::collections::BTreeMap::new();
        map.insert("k1".to_string(), CanonicalValue::Null);
        map.insert("k2".to_string(), CanonicalValue::Null);
        let cv = CanonicalValue::Map(map);
        let result = encode_canonical_value(&cv, &tight);
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn encode_rejects_nested_array_over_metadata_limit() {
        // Deeply nested array that exceeds a tight metadata limit.
        // Each nesting adds: array(2) + u64(6) + array(1) = ~3 bytes overhead.
        // With limit=5, more than 1 level of nesting should be rejected.
        let tight = FormatLimits::default().with_max_metadata_bytes(5).unwrap();
        let cv = CanonicalValue::Array(vec![CanonicalValue::Array(vec![CanonicalValue::Null])]);
        let result = encode_canonical_value(&cv, &tight);
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn json_slice_raw_utf8() {
        let cv =
            canonical_value_from_json_slice(b"\"\xc3\xa9\"", &FormatLimits::default()).unwrap();
        assert_eq!(cv, CanonicalValue::Text("é".to_string()));
    }

    #[test]
    fn json_slice_escaped_unicode() {
        let cv = canonical_value_from_json_slice(b"\"\\u00e9\"", &FormatLimits::default()).unwrap();
        assert_eq!(cv, CanonicalValue::Text("é".to_string()));
    }

    #[test]
    fn json_slice_dup_unicode_key() {
        let result = canonical_value_from_json_slice(
            b"{\"\xc3\xa9\":1,\"\\u00e9\":2}",
            &FormatLimits::default(),
        );
        assert!(matches!(
            result,
            Err(CanonicalEncodeError::DuplicateTextKey { .. })
        ));
    }

    #[test]
    fn json_slice_surrogate_pair() {
        let cv = canonical_value_from_json_slice(b"\"\\uD83D\\uDE00\"", &FormatLimits::default())
            .unwrap();
        assert_eq!(cv, CanonicalValue::Text("😀".to_string()));
    }

    #[test]
    fn json_slice_rejects_isolated_surrogate() {
        let result = canonical_value_from_json_slice(b"\"\\uD83D\"", &FormatLimits::default());
        assert!(result.is_err());
    }

    #[test]
    fn json_slice_rejects_illegal_whitespace() {
        let result = canonical_value_from_json_slice(b"\x0b1", &FormatLimits::default());
        assert!(result.is_err());
    }

    #[test]
    fn json_slice_accepts_max_string() {
        let s = "x".repeat(1_048_576);
        let input = format!("\"{s}\"");
        let cv =
            canonical_value_from_json_slice(input.as_bytes(), &FormatLimits::default()).unwrap();
        assert_eq!(cv, CanonicalValue::Text(s));
    }

    #[test]
    fn json_slice_rejects_oversized_string() {
        let s = "x".repeat(1_048_577);
        let input = format!("\"{s}\"");
        let result = canonical_value_from_json_slice(input.as_bytes(), &FormatLimits::default());
        assert_eq!(
            result,
            Err(CanonicalEncodeError::StringTooLong {
                max: FormatLimits::ABSOLUTE_MAX_STRING_BYTES,
                actual: 1_048_577,
            })
        );
    }

    #[test]
    fn json_slice_rejects_invalid_utf8_byte() {
        let result = canonical_value_from_json_slice(b"\"\xff\"", &FormatLimits::default());
        assert!(result.is_err());
    }

    #[test]
    fn json_slice_rejects_escaped_oversized_string() {
        // Build a JSON string with \u00e9 escapes that decodes to > 1 MiB
        // Each \u00e9 = 6 JSON bytes input → 2 UTF-8 bytes decoded
        // Raw input: 524_289 * 6 = 3_145_734 (< 16 MiB limit)
        // Decoded:   524_289 * 2 = 1_048_578 (> 1 MiB limit)
        let escape = b"\\u00e9";
        let mut raw = Vec::with_capacity(3_200_000);
        raw.push(b'"');
        for _ in 0..524_289 {
            raw.extend_from_slice(escape);
        }
        raw.push(b'"');
        let result = canonical_value_from_json_slice(&raw, &FormatLimits::default());
        assert_eq!(
            result,
            Err(CanonicalEncodeError::StringTooLong {
                max: FormatLimits::ABSOLUTE_MAX_STRING_BYTES,
                actual: 1_048_578,
            })
        );
    }

    #[test]
    fn json_slice_rejects_trailing_data() {
        let result = canonical_value_from_json_slice(b"1 2", &FormatLimits::default());
        assert_eq!(result, Err(CanonicalEncodeError::TrailingData));
    }

    #[test]
    fn json_slice_rejects_trailing_null_true() {
        let result = canonical_value_from_json_slice(b"null true", &FormatLimits::default());
        assert_eq!(result, Err(CanonicalEncodeError::TrailingData));
    }

    #[test]
    fn json_slice_accepts_trailing_newline_tab() {
        let cv = canonical_value_from_json_slice(b"1 \n\t", &FormatLimits::default()).unwrap();
        assert_eq!(cv, CanonicalValue::I64(1));
    }

    #[test]
    fn json_slice_negative_integer() {
        let cv = canonical_value_from_json_slice(b"-1", &FormatLimits::default()).unwrap();
        assert_eq!(cv, CanonicalValue::I64(-1));
    }

    #[test]
    fn json_slice_positive_integer_is_i64() {
        let cv = canonical_value_from_json_slice(b"42", &FormatLimits::default()).unwrap();
        assert_eq!(cv, CanonicalValue::I64(42));
    }

    #[test]
    fn json_slice_u64_max_i64() {
        // i64::MAX as raw JSON integer
        let cv = canonical_value_from_json_slice(b"9223372036854775807", &FormatLimits::default())
            .unwrap();
        assert_eq!(cv, CanonicalValue::I64(i64::MAX));
    }

    #[test]
    fn json_slice_u64_above_i64_max() {
        let cv = canonical_value_from_json_slice(b"9223372036854775808", &FormatLimits::default())
            .unwrap();
        assert_eq!(cv, CanonicalValue::U64(i64::MAX as u64 + 1));
    }

    #[test]
    fn json_slice_zero_is_i64() {
        let cv = canonical_value_from_json_slice(b"0", &FormatLimits::default()).unwrap();
        assert_eq!(cv, CanonicalValue::I64(0));
    }

    #[test]
    fn json_two_entries_agree_on_integers() {
        let cases = [
            "0",
            "1",
            "-1",
            "42",
            "9223372036854775807",
            "9223372036854775808",
        ];
        for raw in &cases {
            let from_slice =
                canonical_value_from_json_slice(raw.as_bytes(), &FormatLimits::default()).unwrap();
            let from_value: CanonicalValue = serde_json::from_str::<serde_json::Value>(raw)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(from_slice, from_value, "CanonicalValue mismatch for {raw}");
            let bytes_slice =
                encode_canonical_value(&from_slice, &FormatLimits::default()).unwrap();
            let bytes_value =
                encode_canonical_value(&from_value, &FormatLimits::default()).unwrap();
            assert_eq!(bytes_slice, bytes_value, "CBOR bytes mismatch for {raw}");
        }
    }

    #[test]
    fn json_two_entries_agree_on_objects() {
        let raw = r#"{"a":1,"b":-2,"c":9223372036854775808}"#;
        let from_slice =
            canonical_value_from_json_slice(raw.as_bytes(), &FormatLimits::default()).unwrap();
        let from_value: CanonicalValue = serde_json::from_str::<serde_json::Value>(raw)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(from_slice, from_value, "CanonicalValue mismatch for object");
        let bytes_slice = encode_canonical_value(&from_slice, &FormatLimits::default()).unwrap();
        let bytes_value = encode_canonical_value(&from_value, &FormatLimits::default()).unwrap();
        assert_eq!(bytes_slice, bytes_value, "CBOR bytes mismatch for object");
    }

    #[test]
    fn json_two_entries_agree_on_array() {
        let raw = r#"[-1,0,1,9223372036854775808]"#;
        let from_slice =
            canonical_value_from_json_slice(raw.as_bytes(), &FormatLimits::default()).unwrap();
        let from_value: CanonicalValue = serde_json::from_str::<serde_json::Value>(raw)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(from_slice, from_value, "CanonicalValue mismatch for array");
        let bytes_slice = encode_canonical_value(&from_slice, &FormatLimits::default()).unwrap();
        let bytes_value = encode_canonical_value(&from_value, &FormatLimits::default()).unwrap();
        assert_eq!(bytes_slice, bytes_value, "CBOR bytes mismatch for array");
    }

    // -------------------------------------------------------------------
    // G2: Freeze format primitives — Hard Gate G2
    // -------------------------------------------------------------------

    #[test]
    fn g2_encoder_byte_stability() {
        // Encode the same logical data twice — must produce identical bytes
        let limits = FormatLimits::default();

        let cv = CanonicalValue::Map({
            let mut m = std::collections::BTreeMap::new();
            m.insert("number".into(), CanonicalValue::I64(-42));
            m.insert("text".into(), CanonicalValue::Text("hello".into()));
            m.insert("bytes".into(), CanonicalValue::Bytes(vec![0xde, 0xad]));
            m.insert(
                "nested".into(),
                CanonicalValue::Array(vec![
                    CanonicalValue::Null,
                    CanonicalValue::Bool(true),
                    CanonicalValue::U64(u64::MAX),
                ]),
            );
            m
        });

        let bytes_a = encode_canonical_value(&cv, &limits).unwrap();
        let bytes_b = encode_canonical_value(&cv, &limits).unwrap();
        assert_eq!(
            bytes_a, bytes_b,
            "encode_canonical_value must be byte-stable"
        );
    }

    #[test]
    fn g2_rejects_all_non_canonical_cbor() {
        // Comprehensive rejection suite matching FORMAT.md §4.
        // Every test in this function checks that the decoder rejects a
        // specific non-canonical encoding that the spec forbids.
        let limits = FormatLimits::default();

        // Non-shortest integer: 0 encoded as 0x18 0x00 (1-byte uint) instead of 0x00
        assert_eq!(
            CanonicalDecoder::from_limits(&[0x18, 0x00], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::NonShortestInteger
        );

        // Non-shortest negative: -1 encoded as 0x38 0x00 (1-byte) instead of 0x20
        assert_eq!(
            CanonicalDecoder::from_limits(&[0x38, 0x00], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::NonShortestInteger
        );

        // Indefinite-length array
        assert_eq!(
            CanonicalDecoder::from_limits(&[0x9f], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::IndefiniteLengthUnsupported
        );

        // Indefinite-length map
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xbf], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::IndefiniteLengthUnsupported
        );

        // Indefinite-length byte string
        assert_eq!(
            CanonicalDecoder::from_limits(&[0x5f], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::IndefiniteLengthUnsupported
        );

        // Indefinite-length text string
        assert_eq!(
            CanonicalDecoder::from_limits(&[0x7f], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::IndefiniteLengthUnsupported
        );

        // Float16
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xf9, 0x00, 0x00], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::FloatUnsupported
        );

        // Float32
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xfa, 0x00, 0x00, 0x00, 0x00], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::FloatUnsupported
        );

        // Float64
        assert_eq!(
            CanonicalDecoder::from_limits(
                &[0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                &limits
            )
            .decode()
            .unwrap_err(),
            DecodeError::FloatUnsupported
        );

        // CBOR tag
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xc0, 0x00], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::TagUnsupported
        );

        // Undefined
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xf7], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::SimpleValueUnsupported(23)
        );

        // Simple value 24 (not false/true/null)
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xf8, 0x18], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::SimpleValueUnsupported(24)
        );

        // Non-shortest simple value: false encoded as 0xf8 0x14 instead of 0xf4
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xf8, 0x14], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::SimpleValueUnsupported(20)
        );

        // Non-shortest simple value: true encoded as 0xf8 0x15 instead of 0xf5
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xf8, 0x15], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::SimpleValueUnsupported(21)
        );

        // Non-shortest simple value: null encoded as 0xf8 0x16 instead of 0xf6
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xf8, 0x16], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::SimpleValueUnsupported(22)
        );

        // Reserved additional info 16 (major 7, addl 0–19 reserved)
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xf0], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::ReservedAdditionalInfo(16)
        );

        // Reserved additional info 19
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xf3], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::ReservedAdditionalInfo(19)
        );

        // Invalid UTF-8
        assert_eq!(
            CanonicalDecoder::from_limits(&[0x62, 0xff, 0xfe], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::InvalidUtf8
        );

        // Duplicate map key
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xa2, 0x00, 0x01, 0x00, 0x02], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::DuplicateMapKey
        );

        // Unsorted map key
        assert_eq!(
            CanonicalDecoder::from_limits(&[0xa2, 0x01, 0x01, 0x00, 0x02], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::UnsortedMapKey
        );

        // Depth exceeded (65 nested arrays, max_depth=64)
        {
            let mut inner = vec![0x01u8];
            for _ in 0..65 {
                let mut outer = vec![0x81u8];
                outer.extend_from_slice(&inner);
                inner = outer;
            }
            assert_eq!(
                CanonicalDecoder::from_limits(&inner, &limits)
                    .decode()
                    .unwrap_err(),
                DecodeError::DepthExceeded
            );
        }

        // Oversized string
        {
            let mut bytes = vec![0x7au8, 0x00, 0x20, 0x00, 0x00];
            bytes.extend(std::iter::repeat_n(0x61u8, 100));
            assert_eq!(
                CanonicalDecoder::from_limits(&bytes, &limits)
                    .decode()
                    .unwrap_err(),
                DecodeError::ValueTooLarge {
                    requested: 0x200000,
                    max: 1_048_576
                }
            );
        }

        // Unexpected EOF
        assert_eq!(
            CanonicalDecoder::from_limits(&[], &limits)
                .decode()
                .unwrap_err(),
            DecodeError::UnexpectedEof
        );

        // Trailing data
        {
            let mut enc = CanonicalEncoder::new();
            enc.u64(42);
            let mut bytes = enc.into_bytes();
            bytes.push(0x00);
            assert_eq!(
                CanonicalDecoder::from_limits(&bytes, &limits)
                    .decode()
                    .unwrap_err(),
                DecodeError::TrailingData
            );
        }
    }

    #[test]
    fn g2_encode_canonical_value_is_deterministic() {
        let limits = FormatLimits::default();
        let cv = CanonicalValue::Array(vec![
            CanonicalValue::I64(-1),
            CanonicalValue::U64(0),
            CanonicalValue::Text("hello".into()),
            CanonicalValue::Bytes(vec![0xff]),
            CanonicalValue::Null,
            CanonicalValue::Bool(true),
        ]);
        let bytes_a = encode_canonical_value(&cv, &limits).unwrap();
        let bytes_b = encode_canonical_value(&cv, &limits).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }
}
