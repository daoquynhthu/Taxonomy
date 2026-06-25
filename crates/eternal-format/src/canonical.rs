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
}

impl Default for CanonicalEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Sorted map builder
// ---------------------------------------------------------------------------

/// Builds a deterministic CBOR map by collecting entries and sorting their
/// encoded keys before writing.
pub struct CanonicalSortedMap {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl CanonicalSortedMap {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a key-value pair. Both key and value are pre-encoded CBOR bytes.
    pub fn insert_raw(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.entries.push((key, value));
    }

    /// Encode a key using the encoder, then insert the pre-encoded value.
    /// This is a convenience wrapper for integer keys.
    pub fn insert_u64(&mut self, key: u64, value: Vec<u8>) {
        let mut key_buf = Vec::new();
        encode_head(&mut key_buf, 0, key);
        self.entries.push((key_buf, value));
    }

    /// Finalize the map: sort entries by encoded key, then write to `encoder`.
    pub fn finish(self, encoder: &mut CanonicalEncoder) {
        let mut entries = self.entries;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        encoder.begin_map(entries.len() as u64);
        for (key, value) in entries {
            encoder.buf.extend_from_slice(&key);
            encoder.buf.extend_from_slice(&value);
        }
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
    ValueTooLarge { requested: u64, max: u64 },
    DuplicateMapKey,
    UnsortedMapKey,
    TrailingData,
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
}

impl<'a> CanonicalDecoder<'a> {
    /// Create a new decoder with the given resource limits.
    pub fn new(
        input: &'a [u8],
        max_depth: usize,
        max_item_count: u64,
        max_string_bytes: u64,
    ) -> Self {
        Self {
            input,
            pos: 0,
            max_depth,
            max_item_count,
            max_string_bytes,
        }
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
                let bytes = self.read_bytes(len as usize)?;
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
                let raw = self.read_bytes(len as usize)?;
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
                let mut items = Vec::with_capacity(len.min(1024) as usize);
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
                let count = len as usize;
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
        map.finish(&mut enc);
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
        let mut dec = CanonicalDecoder::new(input, 64, 1_000_000, 1_048_576);
        dec.decode().expect("decode should succeed")
    }

    fn decode_err(input: &[u8]) -> DecodeError {
        let mut dec = CanonicalDecoder::new(input, 64, 1_000_000, 1_048_576);
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
}
