#![no_main]

use libfuzzer_sys::fuzz_target;
use eternal_format::ids::{
    ObjectId, RefName, RefPattern, DataType, RelationType, KeySlotLabel, CommitMessage,
};

// Fuzz target: parse arbitrary bytes (strict UTF‑8 only) through every
// constrained‑name validator (FORMAT.md §6).  Inputs that decode as valid
// UTF‑8 are tested against every constructor; those that don't are
// correctly rejected by `std::str::from_utf8`.
//
// When parsing succeeds the Display → FromStr round-trip is verified.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // ObjectId
    if let Ok(v) = ObjectId::new(s) {
        let reparsed: ObjectId = v.to_string().parse().unwrap();
        debug_assert_eq!(v, reparsed);
    }

    // RefName
    if let Ok(v) = RefName::new(s) {
        let reparsed: RefName = v.to_string().parse().unwrap();
        debug_assert_eq!(v, reparsed);
    }

    // RefPattern
    if let Ok(v) = RefPattern::new(s) {
        let reparsed: RefPattern = v.to_string().parse().unwrap();
        debug_assert_eq!(v, reparsed);
    }

    // DataType
    if let Ok(v) = DataType::new(s) {
        let reparsed: DataType = v.to_string().parse().unwrap();
        debug_assert_eq!(v, reparsed);
    }

    // RelationType
    if let Ok(v) = RelationType::new(s) {
        let reparsed: RelationType = v.to_string().parse().unwrap();
        debug_assert_eq!(v, reparsed);
    }

    // KeySlotLabel
    if let Ok(v) = KeySlotLabel::new(s) {
        let reparsed: KeySlotLabel = v.to_string().parse().unwrap();
        debug_assert_eq!(v, reparsed);
    }

    // CommitMessage
    if let Ok(v) = CommitMessage::new(s) {
        let reparsed: CommitMessage = v.to_string().parse().unwrap();
        debug_assert_eq!(v, reparsed);
    }
});
