use crate::canonical::{CanonicalDecoder, DecodeError, Value};
use crate::ids::{KeyId, RecordId, Signature};
use crate::limits::FormatLimits;

// ---------------------------------------------------------------------------
// SignedRecord envelope (FORMAT.md §4.6 / ARCHITECTURE.md §4.3)
// ---------------------------------------------------------------------------

/// A signed-record envelope with detached signature.
///
/// The envelope is a deterministic CBOR map with 5 entries (keys 0–4):
///  0 = envelope_version (must be 1)
///  1 = payload (record-specific map)
///  2 = record_id      (32 bytes — ID of canonical payload)
///  3 = signer_key_id  (32 bytes — signer fingerprint)
///  4 = signature      (64 bytes — Ed25519 signature over record_id)
///
/// The payload is stored as [`Value::Map`] so that unsigned integer field
/// keys (used by all v1 record payload schemas) are preserved through
/// encode–decode roundtrips.  No cryptographic verification is performed
/// at this layer.  Type parameter `P` defaults to `Value`; typed payload
/// schemas (F3.2+) convert to/from `Value` externally.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedRecord<P = Value> {
    pub payload: P,
    pub record_id: RecordId,
    pub signer_key_id: KeyId,
    pub signature: Signature,
}

impl<P> SignedRecord<P> {
    pub fn new(
        payload: P,
        record_id: RecordId,
        signer_key_id: KeyId,
        signature: Signature,
    ) -> Self {
        Self {
            payload,
            record_id,
            signer_key_id,
            signature,
        }
    }
}

/// Error returned by [`SignedRecord::decode`] and [`SignedRecord::encode`].
#[derive(Debug, Clone, PartialEq)]
pub enum SignedRecordError {
    /// The decoded value was not a CBOR map with 5 entries.
    NotA5FieldMap,
    /// A required field (key 0–4) was missing.
    MissingField(u64),
    /// Field 0 (envelope_version) was not exactly 1.
    UnsupportedEnvelopeVersion(u64),
    /// A field had an unexpected CBOR type.
    FieldTypeMismatch { key: u64, expected: &'static str },
    /// A byte-string field had the wrong length.
    WrongFieldLength {
        key: u64,
        expected: usize,
        actual: usize,
    },
    /// The payload field (key 1) is not a CBOR map.
    PayloadNotAMap,
    /// Wrapped underlying decoder error.
    Decode(DecodeError),
    /// The encoded envelope exceeds `max_metadata_bytes`.
    EnvelopeTooLarge { actual: u64, max: u64 },
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

impl SignedRecord<Value> {
    /// Encode the envelope as deterministic CBOR per FORMAT.md §4.6.
    ///
    /// The payload is embedded as a nested CBOR value (not wrapped in bytes).
    /// The output is checked against `limits.max_metadata_bytes()`.
    pub fn encode(&self, limits: &FormatLimits) -> Result<Vec<u8>, SignedRecordError> {
        let envelope = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),        // envelope_version
            (Value::U64(1), self.payload.clone()), // payload (any CBOR value)
            (
                Value::U64(2),
                Value::Bytes(self.record_id.as_bytes().to_vec()),
            ), // record_id
            (
                Value::U64(3),
                Value::Bytes(self.signer_key_id.as_bytes().to_vec()),
            ), // signer_key_id
            (
                Value::U64(4),
                Value::Bytes(self.signature.as_bytes().to_vec()),
            ), // signature
        ]);
        let bytes = envelope.reencode();
        let len = bytes.len() as u64;
        if len > limits.max_metadata_bytes() {
            return Err(SignedRecordError::EnvelopeTooLarge {
                actual: len,
                max: limits.max_metadata_bytes(),
            });
        }
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

impl SignedRecord<Value> {
    /// Decode a SignedRecord from deterministic CBOR bytes.
    ///
    /// Validates:
    /// - the outer structure is a 5-entry map with keys 0–4;
    /// - field 0 (envelope_version) is exactly 1;
    /// - field 2 (record_id) is exactly 32 bytes;
    /// - field 3 (signer_key_id) is exactly 32 bytes;
    /// - field 4 (signature) is exactly 64 bytes;
    /// - field 1 (payload) is a CBOR map.
    ///
    /// The payload is returned as [`Value::Map`] — callers (F3.2+) convert
    /// to typed payload schemas from this representation.
    pub fn decode(input: &[u8], limits: &FormatLimits) -> Result<Self, SignedRecordError> {
        let value = CanonicalDecoder::from_limits(input, limits)
            .decode()
            .map_err(SignedRecordError::Decode)?;

        let pairs = match &value {
            Value::Map(pairs) if pairs.len() == 5 => pairs,
            Value::Map(_) => return Err(SignedRecordError::NotA5FieldMap),
            _ => return Err(SignedRecordError::NotA5FieldMap),
        };

        // Lookup key 0..=4
        let mut fields: [Option<&Value>; 5] = [None, None, None, None, None];
        for (k, v) in pairs {
            match k {
                Value::U64(0) => fields[0] = Some(v),
                Value::U64(1) => fields[1] = Some(v),
                Value::U64(2) => fields[2] = Some(v),
                Value::U64(3) => fields[3] = Some(v),
                Value::U64(4) => fields[4] = Some(v),
                _ => {
                    return Err(SignedRecordError::MissingField(match k {
                        Value::U64(n) => *n,
                        _ => u64::MAX,
                    }));
                }
            }
        }

        for (key, field) in fields.iter().enumerate() {
            if field.is_none() {
                return Err(SignedRecordError::MissingField(key as u64));
            }
        }

        let version = match fields[0] {
            Some(Value::U64(v)) => *v,
            Some(_) => {
                return Err(SignedRecordError::FieldTypeMismatch {
                    key: 0,
                    expected: "uint",
                });
            }
            None => unreachable!(),
        };
        if version != 1 {
            return Err(SignedRecordError::UnsupportedEnvelopeVersion(version));
        }

        let payload = match fields[1] {
            Some(v @ Value::Map(_)) => v.clone(),
            Some(_) => return Err(SignedRecordError::PayloadNotAMap),
            None => unreachable!(),
        };

        let record_id = match fields[2] {
            Some(Value::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                RecordId::new(arr)
            }
            Some(Value::Bytes(b)) => {
                return Err(SignedRecordError::WrongFieldLength {
                    key: 2,
                    expected: 32,
                    actual: b.len(),
                });
            }
            Some(_) => {
                return Err(SignedRecordError::FieldTypeMismatch {
                    key: 2,
                    expected: "bytes(32)",
                });
            }
            None => unreachable!(),
        };

        let signer_key_id = match fields[3] {
            Some(Value::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                KeyId::new(arr)
            }
            Some(Value::Bytes(b)) => {
                return Err(SignedRecordError::WrongFieldLength {
                    key: 3,
                    expected: 32,
                    actual: b.len(),
                });
            }
            Some(_) => {
                return Err(SignedRecordError::FieldTypeMismatch {
                    key: 3,
                    expected: "bytes(32)",
                });
            }
            None => unreachable!(),
        };

        let signature = match fields[4] {
            Some(Value::Bytes(b)) if b.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(b);
                Signature::new(arr)
            }
            Some(Value::Bytes(b)) => {
                return Err(SignedRecordError::WrongFieldLength {
                    key: 4,
                    expected: 64,
                    actual: b.len(),
                });
            }
            Some(_) => {
                return Err(SignedRecordError::FieldTypeMismatch {
                    key: 4,
                    expected: "bytes(64)",
                });
            }
            None => unreachable!(),
        };

        Ok(Self {
            payload,
            record_id,
            signer_key_id,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A minimal record payload map that uses unsigned integer keys
    /// (matching the pattern used by all v1 record schemas in F3.2+).
    fn make_integer_key_payload() -> Value {
        Value::Map(vec![
            (Value::U64(0), Value::U64(1)),                  // version
            (Value::U64(1), Value::Bytes(vec![0x99u8; 32])), // identifier
            (Value::U64(2), Value::U64(42)),                 // some count
        ])
    }

    fn make_test_record() -> SignedRecord<Value> {
        let payload = make_integer_key_payload();
        let record_id = RecordId::new([0x11u8; 32]);
        let signer_key_id = KeyId::new([0x22u8; 32]);
        let signature = Signature::new([0x33u8; 64]);
        SignedRecord::new(payload, record_id, signer_key_id, signature)
    }

    #[test]
    fn signed_record_encode_decode_roundtrip() {
        let limits = FormatLimits::default();
        let record = make_test_record();
        let encoded = record.encode(&limits).expect("encode");
        let decoded = SignedRecord::<Value>::decode(&encoded, &limits).expect("decode");
        assert_eq!(decoded, record);
    }

    #[test]
    fn signed_record_reencodes_identically() {
        let limits = FormatLimits::default();
        let record = make_test_record();
        let bytes_a = record.encode(&limits).expect("encode a");
        let bytes_b = record.encode(&limits).expect("encode b");
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn signed_record_decode_roundtrip_byte_stable() {
        let limits = FormatLimits::default();
        let record = make_test_record();
        let encoded = record.encode(&limits).expect("encode");
        let decoded = SignedRecord::<Value>::decode(&encoded, &limits).expect("decode");
        let reencoded = decoded.encode(&limits).expect("re-encode");
        assert_eq!(encoded, reencoded);
    }

    #[test]
    fn signed_record_unsigned_integer_payload_keys_roundtrip() {
        // Prove that a payload with unsigned integer field keys survives
        // encode–decode–re-encode identically.  This is a hard requirement
        // for F3.2+ record schemas which use fixed uint field numbers.
        let limits = FormatLimits::default();
        let payload = make_integer_key_payload();

        // Confirm the payload map uses unsigned integer keys
        match &payload {
            Value::Map(pairs) => {
                assert!(pairs.iter().all(|(k, _)| matches!(k, Value::U64(_))));
            }
            _ => panic!("payload must be a map"),
        }

        let record = SignedRecord::new(
            payload,
            RecordId::new([0x11u8; 32]),
            KeyId::new([0x22u8; 32]),
            Signature::new([0x33u8; 64]),
        );
        let encoded = record.encode(&limits).expect("encode");
        let decoded = SignedRecord::<Value>::decode(&encoded, &limits).expect("decode");

        // Verify the decoded payload still has unsigned integer keys
        match &decoded.payload {
            Value::Map(pairs) => {
                assert!(
                    pairs.iter().all(|(k, _)| matches!(k, Value::U64(_))),
                    "payload keys must still be unsigned integers after decode"
                );
                assert_eq!(pairs.len(), 3);
                assert_eq!(pairs[0], (Value::U64(0), Value::U64(1)));
                assert_eq!(pairs[1], (Value::U64(1), Value::Bytes(vec![0x99u8; 32])));
                assert_eq!(pairs[2], (Value::U64(2), Value::U64(42)));
            }
            _ => panic!("decoded payload must be a map"),
        }

        // Full equality (includes payload key type preservation)
        assert_eq!(decoded, record);
    }

    #[test]
    fn signed_record_rejects_wrong_record_id_length() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x44u8; 33])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 32])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 64])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(
            result,
            Err(SignedRecordError::WrongFieldLength {
                key: 2,
                expected: 32,
                actual: 33
            })
        );
    }

    #[test]
    fn signed_record_rejects_wrong_signer_key_id_length() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 31])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 64])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(
            result,
            Err(SignedRecordError::WrongFieldLength {
                key: 3,
                expected: 32,
                actual: 31
            })
        );
    }

    #[test]
    fn signed_record_rejects_wrong_signature_length() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 32])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 65])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(
            result,
            Err(SignedRecordError::WrongFieldLength {
                key: 4,
                expected: 64,
                actual: 65
            })
        );
    }

    #[test]
    fn signed_record_rejects_non_map_payload() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), Value::U64(42)),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 32])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 64])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(result, Err(SignedRecordError::PayloadNotAMap));
    }

    #[test]
    fn signed_record_rejects_wrong_version() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(2)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
            (Value::U64(3), Value::Bytes(vec![0x22u8; 32])),
            (Value::U64(4), Value::Bytes(vec![0x33u8; 64])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(
            result,
            Err(SignedRecordError::UnsupportedEnvelopeVersion(2))
        );
    }

    #[test]
    fn signed_record_rejects_missing_fields() {
        let limits = FormatLimits::default();
        let bad = Value::Map(vec![
            (Value::U64(0), Value::U64(1)),
            (Value::U64(1), make_integer_key_payload()),
            (Value::U64(2), Value::Bytes(vec![0x11u8; 32])),
        ]);
        let bytes = bad.reencode();
        let result = SignedRecord::<Value>::decode(&bytes, &limits);
        assert_eq!(result, Err(SignedRecordError::NotA5FieldMap));
    }

    #[test]
    fn signed_record_rejects_empty_input() {
        let limits = FormatLimits::default();
        let result = SignedRecord::<Value>::decode(&[], &limits);
        assert!(matches!(result, Err(SignedRecordError::Decode(_))));
    }

    #[test]
    fn signed_record_payload_id_excludes_signature() {
        let limits = FormatLimits::default();
        let payload = make_integer_key_payload();
        let record_id = RecordId::new([0x11u8; 32]);
        let signer_key_id = KeyId::new([0x22u8; 32]);
        let sig_a = Signature::new([0x33u8; 64]);
        let sig_b = Signature::new([0x44u8; 64]);

        let rec_a = SignedRecord::new(payload.clone(), record_id, signer_key_id, sig_a);
        let rec_b = SignedRecord::new(payload, record_id, signer_key_id, sig_b);

        let enc_a = rec_a.encode(&limits).expect("encode a");
        let enc_b = rec_b.encode(&limits).expect("encode b");
        assert_ne!(enc_a, enc_b, "different signatures must change bytes");

        let dec_a = SignedRecord::<Value>::decode(&enc_a, &limits).unwrap();
        let dec_b = SignedRecord::<Value>::decode(&enc_b, &limits).unwrap();
        assert_eq!(
            dec_a.record_id, dec_b.record_id,
            "record_id must not depend on signature"
        );
        assert_eq!(dec_a.record_id, record_id);
    }

    #[test]
    fn signed_record_encode_rejects_oversized_payload() {
        // Encode a payload that exceeds the metadata limit.
        let limits = FormatLimits::default()
            .with_max_metadata_bytes(100)
            .expect("valid limit");

        let huge_key = "x".repeat(200);
        let big_payload = Value::Map(vec![(Value::U64(0), Value::Text(huge_key))]);

        let record = SignedRecord::new(
            big_payload,
            RecordId::new([0x11u8; 32]),
            KeyId::new([0x22u8; 32]),
            Signature::new([0x33u8; 64]),
        );
        let result = record.encode(&limits);
        assert!(matches!(
            result,
            Err(SignedRecordError::EnvelopeTooLarge { .. })
        ));
    }
}
