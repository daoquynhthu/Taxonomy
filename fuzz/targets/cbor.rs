#![no_main]

use libfuzzer_sys::fuzz_target;
use eternal_format::canonical::{CanonicalDecoder, encode_canonical_value};
use eternal_format::limits::FormatLimits;

// Fuzz target: decode arbitrary bytes through both CBOR entry points
// (FORMAT.md §4):
//
// 1. `decode()`           — low-level deterministic CBOR decoder
// 2. `decode_canonical_value()` — CanonicalValue tagged-array decoder
//
// When decoding succeeds the value is re-encoded and compared byte-for-byte
// with the original input to detect encoder/decoder asymmetry.  Both
// `decode()` and `decode_canonical_value()` reject trailing data, so a
// successful return means the entire input was consumed.
//
// The decoder enforces FormatLimits (depth, node count, string length,
// metadata bytes).  Any returned error is acceptable; the target verifies
// that no panic, timeout, or unbounded allocation occurs.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let limits = FormatLimits::default();

    // --- low-level CBOR decode + re-encode round-trip ---
    let mut dec = CanonicalDecoder::from_limits(data, &limits);
    if let Ok(value) = dec.decode() {
        let reencoded = value.reencode();
        // decode() rejects trailing data → entire input consumed.
        debug_assert_eq!(reencoded, data);
    }

    // --- CanonicalValue tagged-array decode ---
    let mut dec2 = CanonicalDecoder::from_limits(data, &limits);
    if let Ok(cv) = dec2.decode_canonical_value() {
        if let Ok(reencoded) = encode_canonical_value(&cv, &limits) {
            // decode_canonical_value() rejects trailing data → entire input consumed.
            debug_assert_eq!(reencoded, data);
        }
    }
});
