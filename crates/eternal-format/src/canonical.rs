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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
}
