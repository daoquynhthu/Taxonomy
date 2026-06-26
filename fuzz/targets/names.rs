#![no_main]

use libfuzzer_sys::fuzz_target;
use eternal_format::ids::{
    ObjectId, RefName, RefPattern, DataType, RelationType, KeySlotLabel, CommitMessage,
};

// Fuzz target: parse arbitrary bytes (interpreted as lossy UTF‑8) through
// every constrained‑name validator (FORMAT.md §6).
// Every constructor returns a Result; the target verifies that no input
// causes a panic, timeout, or unbounded allocation.
fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = ObjectId::new(&s);
    let _ = RefName::new(&s);
    let _ = RefPattern::new(&s);
    let _ = DataType::new(&s);
    let _ = RelationType::new(&s);
    let _ = KeySlotLabel::new(&s);
    let _ = CommitMessage::new(&s);
});
