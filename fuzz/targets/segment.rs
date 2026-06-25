#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz target: parse arbitrary bytes as an active segment.
// Phase 0: specification pending.
fuzz_target!(|data: &[u8]| {
    // let _ = eternal_store::segment::parse(data);
});
