#![no_main]

use libfuzzer_sys::fuzz_target;
use eternal_format::canonical::{CanonicalDecoder, Value};
use eternal_format::limits::FormatLimits;
use eternal_format::record::{
    ChunkingDescriptor,
    CodecDescriptor,
    ContentManifestChunkEntry,
    ContentManifestPayload,
    EncodedChunkPayload,
    EncryptionDescriptor,
    KeySlot,
    KeyringRecordPayload,
    ObjectChange,
    ObjectVersionPayload,
    PackDescriptor,
    PasswordKdfDescriptor,
    PolicyRecordPayload,
    PublicKeyEntry,
    RefPermissionEntry,
    Relation,
    RepoCommitPayload,
    RefUpdatePayload,
    RepositoryGenesisPayload,
    SegmentDescriptor,
    SignedRecord,
    SMTInternalPayload,
    SMTLeafPayload,
    SMTProof,
    StoreManifestPayload,
    TransactionEndPayload,
    WrappedDek,
};

// Fuzz target: exercise every record decoder and resource limit
// (PLAN.md F3.10).
//
// Strategy: decode arbitrary bytes as CBOR, then attempt every
// TryFrom<Value> payload decoder + SignedRecord envelope decoder.
// Any structured error is acceptable; the target verifies no panic,
// timeout, or unbounded allocation occurs.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let limits = FormatLimits::default();

    // 1. SignedRecord envelope decoder (raw bytes → CBOR → envelope)
    let _ = SignedRecord::<Value>::decode(data, &limits);

    // 2. Decode CBOR bytes → Value
    let mut dec = CanonicalDecoder::from_limits(data, &limits);
    let Ok(value) = dec.decode() else { return };

    // 3. Try every payload decoder over this Value.
    //    Each call returns Err(...) when the bytes don't match the expected
    //    schema — that is the intended rejection path.
    //    Non-map inputs (array, bytes, text, int, null, bool) exercise the
    //    decoder's NotAMap / field-type rejection paths.
    invoke_all_decoders(value);
});

#[inline(never)]
fn invoke_all_decoders(value: Value) {
    // F3.2 — Repository authority payload schemas
    let _ = PasswordKdfDescriptor::try_from(value.clone());
    let _ = PublicKeyEntry::try_from(value.clone());
    let _ = RefPermissionEntry::try_from(value.clone());
    let _ = RepositoryGenesisPayload::try_from(value.clone());
    let _ = PolicyRecordPayload::try_from(value.clone());
    let _ = KeySlot::try_from(value.clone());
    let _ = WrappedDek::try_from(value.clone());
    let _ = KeyringRecordPayload::try_from(value.clone());

    // F3.3 — Content payload schemas
    let _ = CodecDescriptor::try_from(value.clone());
    let _ = EncryptionDescriptor::try_from(value.clone());
    let _ = ChunkingDescriptor::try_from(value.clone());
    let _ = ContentManifestChunkEntry::try_from(value.clone());
    let _ = EncodedChunkPayload::try_from(value.clone());
    let _ = ContentManifestPayload::try_from(value.clone());

    // F3.4 — Object payload schemas
    let _ = Relation::try_from(value.clone());
    let _ = ObjectVersionPayload::try_from(value.clone());

    // F3.5 — SMT payload and proof schemas
    let _ = SMTLeafPayload::try_from(value.clone());
    let _ = SMTInternalPayload::try_from(value.clone());
    let _ = SMTProof::try_from(value.clone());

    // F3.6 — State and ref payload schemas
    let _ = ObjectChange::try_from(value.clone());
    let _ = RepoCommitPayload::try_from(value.clone());
    let _ = RefUpdatePayload::try_from(value.clone());
    let _ = TransactionEndPayload::try_from(value.clone());

    // F3.7 — StoreManifest schemas
    let _ = SegmentDescriptor::try_from(value.clone());
    let _ = PackDescriptor::try_from(value.clone());
    let _ = StoreManifestPayload::try_from(value);
}
