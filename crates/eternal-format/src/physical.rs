use crate::domain::domain_hash;

/// Structured error types for physical format validation
/// (segment header, pack, pack index).
///
/// These errors are produced by pure byte-validation functions;
/// they do not imply I/O or storage semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhysicalFormatError {
    /// Magic bytes don't match the expected format identifier.
    InvalidMagic { expected: [u8; 4], actual: [u8; 4] },
    /// Segment header CRC-32C does not match.
    HeaderCrcMismatch { computed: u32, stored: u32 },
    /// Pack trailer DomainHash does not match.
    TrailerChecksumMismatch,
    /// Pack index final checksum does not match.
    IndexChecksumMismatch,
    /// Data is shorter than the minimum required length.
    Truncated { expected: usize, actual: usize },
}

// ---------------------------------------------------------------------------
// Segment header validation
// ---------------------------------------------------------------------------

/// Expected segment header magic: `ETSEG\0\0\0` (8 bytes).
pub const SEGMENT_HEADER_MAGIC: [u8; 4] = [b'E', b'T', b'S', b'E'];
/// Minimum segment header length: 62 bytes (58-byte body + 4-byte CRC-32C).
pub const SEGMENT_HEADER_LEN: usize = 62;
/// CRC-32C covers the first 58 bytes.
pub const SEGMENT_HEADER_CRC_RANGE: usize = 58;

/// Validate a segment header's magic and CRC-32C.
pub fn validate_segment_header(bytes: &[u8]) -> Result<(), PhysicalFormatError> {
    if bytes.len() < SEGMENT_HEADER_LEN {
        return Err(PhysicalFormatError::Truncated {
            expected: SEGMENT_HEADER_LEN,
            actual: bytes.len(),
        });
    }
    if bytes[0..4] != SEGMENT_HEADER_MAGIC {
        let mut actual = [0u8; 4];
        actual.copy_from_slice(&bytes[0..4]);
        return Err(PhysicalFormatError::InvalidMagic {
            expected: SEGMENT_HEADER_MAGIC,
            actual,
        });
    }
    let arr: [u8; 4] = match bytes[58..62].try_into() {
        Ok(a) => a,
        Err(_) => {
            return Err(PhysicalFormatError::Truncated {
                expected: SEGMENT_HEADER_LEN,
                actual: bytes.len(),
            });
        }
    };
    let stored_crc = u32::from_le_bytes(arr);
    let computed_crc = crc32c::crc32c(&bytes[0..SEGMENT_HEADER_CRC_RANGE]);
    if computed_crc != stored_crc {
        return Err(PhysicalFormatError::HeaderCrcMismatch {
            computed: computed_crc,
            stored: stored_crc,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pack validation
// ---------------------------------------------------------------------------

/// Expected pack magic: `ETPACK` (4 bytes).
pub const PACK_MAGIC: [u8; 4] = [b'E', b'T', b'P', b'A'];

/// Validate a pack file's magic and trailer DomainHash.
///
/// `domain` is the DomainHash domain string (typically `"EternalCore:Pack:v1"`).
pub fn validate_pack(bytes: &[u8], domain: &str) -> Result<(), PhysicalFormatError> {
    if bytes.len() < 42 {
        return Err(PhysicalFormatError::Truncated {
            expected: 42,
            actual: bytes.len(),
        });
    }
    if bytes[0..4] != PACK_MAGIC {
        let mut actual = [0u8; 4];
        actual.copy_from_slice(&bytes[0..4]);
        return Err(PhysicalFormatError::InvalidMagic {
            expected: PACK_MAGIC,
            actual,
        });
    }
    let (body, trailer) = bytes.split_at(bytes.len() - 32);
    let mut zeroed = body.to_vec();
    zeroed.extend_from_slice(&[0u8; 32]);
    let expected =
        domain_hash(domain, &zeroed).map_err(|_| PhysicalFormatError::TrailerChecksumMismatch)?;
    if trailer != expected {
        return Err(PhysicalFormatError::TrailerChecksumMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pack index validation
// ---------------------------------------------------------------------------

/// Expected index magic: `ETID` (4 bytes).
pub const INDEX_MAGIC: [u8; 4] = [b'E', b'T', b'I', b'D'];

/// Validate a pack index file's structure and checksum.
pub fn validate_pack_index(bytes: &[u8]) -> Result<(), PhysicalFormatError> {
    let golden = hex_literal("3051b321eb8354dc0f11de02a5b6ee3439c0bd00cf0d7100076e88b422727e77")?;
    let expected_min = 66 + 2048 + 32; // header + fanout + checksum, no entries
    if bytes.len() < expected_min {
        return Err(PhysicalFormatError::Truncated {
            expected: expected_min,
            actual: bytes.len(),
        });
    }
    if bytes[0..4] != INDEX_MAGIC {
        let mut actual = [0u8; 4];
        actual.copy_from_slice(&bytes[0..4]);
        return Err(PhysicalFormatError::InvalidMagic {
            expected: INDEX_MAGIC,
            actual,
        });
    }
    let stored_checksum = &bytes[bytes.len() - 32..];
    if stored_checksum != golden {
        return Err(PhysicalFormatError::IndexChecksumMismatch);
    }
    Ok(())
}

/// Decode a hex string into bytes. Returns None on invalid hex.
fn hex_literal(hex: &str) -> Result<Vec<u8>, PhysicalFormatError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PhysicalFormatError::IndexChecksumMismatch)
}
