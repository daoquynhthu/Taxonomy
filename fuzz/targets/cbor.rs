#![no_main]

use libfuzzer_sys::fuzz_target;
use eternal_format::canonical::CanonicalDecoder;
use eternal_format::limits::FormatLimits;

// Fuzz target: decode arbitrary bytes as deterministic CBOR (FORMAT.md §4).
// The decoder is bounded by FormatLimits (depth, node count, string length,
// metadata bytes).  Any returned error is acceptable; the target verifies
// that no panic, timeout, or unbounded allocation occurs for any input.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let limits = FormatLimits::default();
    let mut decoder = CanonicalDecoder::from_limits(data, &limits);
    let _ = decoder.decode_canonical_value();
});
