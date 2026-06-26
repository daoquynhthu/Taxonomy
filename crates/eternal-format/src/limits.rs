use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitsError {
    LimitIsZero {
        field: &'static str,
    },
    LimitExceedsAbsoluteMax {
        field: &'static str,
        requested: u64,
        absolute_max: u64,
    },
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitIsZero { field } => write!(f, "{field} limit must not be zero"),
            Self::LimitExceedsAbsoluteMax {
                field,
                requested,
                absolute_max,
            } => write!(
                f,
                "{field} limit {requested} exceeds absolute max {absolute_max}"
            ),
        }
    }
}

impl std::error::Error for LimitsError {}

/// Resource limits for all EternalCore parsers.
///
/// These mirror FORMAT.md §20 absolute decoding maxima.
/// All fields are private with a checked constructor `new()` that enforces
/// the absolute caps and rejects zero values.
///
/// Default values equal the FORMAT absolute maximum.
/// `with_*` helpers may only reduce limits further.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatLimits {
    // --- CanonicalValue limits ---
    max_depth: u64,
    max_nodes: u64,
    max_string_bytes: u64,

    // --- Structural limits ---
    max_record_payload: u64,
    max_chunk_plaintext: u64,
    max_metadata_bytes: u64,
    max_object_version_parents: u64,
    max_repocommit_parents: u64,
    max_relations: u64,
    max_changes: u64,

    // --- Policy / key limits ---
    max_policy_keys: u64,
    max_policy_permissions: u64,
    max_key_slots: u64,

    // --- Storage limits ---
    max_manifest_chunks: u64,
    max_pack_records: u64,
    max_pack_size: u64,
    max_segment_size: u32,
    impl_target_segment_size: u64,
}

impl FormatLimits {
    pub const ABSOLUTE_MAX_DEPTH: u64 = 64;
    pub const ABSOLUTE_MAX_NODES: u64 = 1_000_000;
    pub const ABSOLUTE_MAX_STRING_BYTES: u64 = 1_048_576;
    pub const ABSOLUTE_MAX_RECORD_PAYLOAD: u64 = 67_108_864;
    pub const ABSOLUTE_MAX_CHUNK_PLAINTEXT: u64 = 8_388_608;
    pub const ABSOLUTE_MAX_METADATA_BYTES: u64 = 16_777_216;
    pub const ABSOLUTE_MAX_OBJECT_VERSION_PARENTS: u64 = 64;
    pub const ABSOLUTE_MAX_REPOCOMMIT_PARENTS: u64 = 64;
    pub const ABSOLUTE_MAX_RELATIONS: u64 = 100_000;
    pub const ABSOLUTE_MAX_CHANGES: u64 = 1_000_000;
    pub const ABSOLUTE_MAX_POLICY_KEYS: u64 = 100_000;
    pub const ABSOLUTE_MAX_POLICY_PERMISSIONS: u64 = 100_000;
    pub const ABSOLUTE_MAX_KEY_SLOTS: u64 = 100_000;
    pub const ABSOLUTE_MAX_MANIFEST_CHUNKS: u64 = 16_777_216;
    pub const ABSOLUTE_MAX_PACK_RECORDS: u64 = 1_000_000_000;
    pub const ABSOLUTE_MAX_PACK_SIZE: u64 = 17_592_186_044_416;
    pub const ABSOLUTE_MAX_SEGMENT_SIZE: u32 = 4_294_967_295;
    pub const IMPL_TARGET_SEGMENT_SIZE: u64 = 67_108_864;

    /// Create a `FormatLimits` with all limits set to the given values.
    /// Returns an error if any value is zero or exceeds the FORMAT absolute cap.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_depth: u64,
        max_nodes: u64,
        max_string_bytes: u64,
        max_record_payload: u64,
        max_chunk_plaintext: u64,
        max_metadata_bytes: u64,
        max_object_version_parents: u64,
        max_repocommit_parents: u64,
        max_relations: u64,
        max_changes: u64,
        max_policy_keys: u64,
        max_policy_permissions: u64,
        max_key_slots: u64,
        max_manifest_chunks: u64,
        max_pack_records: u64,
        max_pack_size: u64,
        max_segment_size: u32,
    ) -> Result<Self, LimitsError> {
        Self::check_nonzero("max_depth", max_depth)?;
        Self::check_nonzero("max_nodes", max_nodes)?;
        Self::check_nonzero("max_string_bytes", max_string_bytes)?;
        Self::check_nonzero("max_record_payload", max_record_payload)?;
        Self::check_nonzero("max_chunk_plaintext", max_chunk_plaintext)?;
        Self::check_nonzero("max_metadata_bytes", max_metadata_bytes)?;
        Self::check_nonzero("max_object_version_parents", max_object_version_parents)?;
        Self::check_nonzero("max_repocommit_parents", max_repocommit_parents)?;
        Self::check_nonzero("max_relations", max_relations)?;
        Self::check_nonzero("max_changes", max_changes)?;
        Self::check_nonzero("max_policy_keys", max_policy_keys)?;
        Self::check_nonzero("max_policy_permissions", max_policy_permissions)?;
        Self::check_nonzero("max_key_slots", max_key_slots)?;
        Self::check_nonzero("max_manifest_chunks", max_manifest_chunks)?;
        Self::check_nonzero("max_pack_records", max_pack_records)?;
        Self::check_nonzero("max_pack_size", max_pack_size)?;
        Self::check_nonzero_u32("max_segment_size", max_segment_size)?;

        Self::check_max("max_depth", max_depth, Self::ABSOLUTE_MAX_DEPTH)?;
        Self::check_max("max_nodes", max_nodes, Self::ABSOLUTE_MAX_NODES)?;
        Self::check_max(
            "max_string_bytes",
            max_string_bytes,
            Self::ABSOLUTE_MAX_STRING_BYTES,
        )?;
        Self::check_max(
            "max_record_payload",
            max_record_payload,
            Self::ABSOLUTE_MAX_RECORD_PAYLOAD,
        )?;
        Self::check_max(
            "max_chunk_plaintext",
            max_chunk_plaintext,
            Self::ABSOLUTE_MAX_CHUNK_PLAINTEXT,
        )?;
        Self::check_max(
            "max_metadata_bytes",
            max_metadata_bytes,
            Self::ABSOLUTE_MAX_METADATA_BYTES,
        )?;
        Self::check_max(
            "max_object_version_parents",
            max_object_version_parents,
            Self::ABSOLUTE_MAX_OBJECT_VERSION_PARENTS,
        )?;
        Self::check_max(
            "max_repocommit_parents",
            max_repocommit_parents,
            Self::ABSOLUTE_MAX_REPOCOMMIT_PARENTS,
        )?;
        Self::check_max("max_relations", max_relations, Self::ABSOLUTE_MAX_RELATIONS)?;
        Self::check_max("max_changes", max_changes, Self::ABSOLUTE_MAX_CHANGES)?;
        Self::check_max(
            "max_policy_keys",
            max_policy_keys,
            Self::ABSOLUTE_MAX_POLICY_KEYS,
        )?;
        Self::check_max(
            "max_policy_permissions",
            max_policy_permissions,
            Self::ABSOLUTE_MAX_POLICY_PERMISSIONS,
        )?;
        Self::check_max("max_key_slots", max_key_slots, Self::ABSOLUTE_MAX_KEY_SLOTS)?;
        Self::check_max(
            "max_manifest_chunks",
            max_manifest_chunks,
            Self::ABSOLUTE_MAX_MANIFEST_CHUNKS,
        )?;
        Self::check_max(
            "max_pack_records",
            max_pack_records,
            Self::ABSOLUTE_MAX_PACK_RECORDS,
        )?;
        Self::check_max("max_pack_size", max_pack_size, Self::ABSOLUTE_MAX_PACK_SIZE)?;
        Self::check_max_u32(
            "max_segment_size",
            max_segment_size,
            Self::ABSOLUTE_MAX_SEGMENT_SIZE,
        )?;

        Ok(Self {
            max_depth,
            max_nodes,
            max_string_bytes,
            max_record_payload,
            max_chunk_plaintext,
            max_metadata_bytes,
            max_object_version_parents,
            max_repocommit_parents,
            max_relations,
            max_changes,
            max_policy_keys,
            max_policy_permissions,
            max_key_slots,
            max_manifest_chunks,
            max_pack_records,
            max_pack_size,
            max_segment_size,
            impl_target_segment_size: Self::IMPL_TARGET_SEGMENT_SIZE,
        })
    }

    fn check_nonzero(field: &'static str, value: u64) -> Result<(), LimitsError> {
        if value == 0 {
            return Err(LimitsError::LimitIsZero { field });
        }
        Ok(())
    }

    fn check_nonzero_u32(field: &'static str, value: u32) -> Result<(), LimitsError> {
        if value == 0 {
            return Err(LimitsError::LimitIsZero { field });
        }
        Ok(())
    }

    fn check_max(field: &'static str, value: u64, max: u64) -> Result<(), LimitsError> {
        if value > max {
            return Err(LimitsError::LimitExceedsAbsoluteMax {
                field,
                requested: value,
                absolute_max: max,
            });
        }
        Ok(())
    }

    fn check_max_u32(field: &'static str, value: u32, max: u32) -> Result<(), LimitsError> {
        if value > max {
            return Err(LimitsError::LimitExceedsAbsoluteMax {
                field,
                requested: value as u64,
                absolute_max: max as u64,
            });
        }
        Ok(())
    }

    // --- Getters ---

    pub fn max_depth(&self) -> u64 {
        self.max_depth
    }
    pub fn max_nodes(&self) -> u64 {
        self.max_nodes
    }
    pub fn max_string_bytes(&self) -> u64 {
        self.max_string_bytes
    }
    pub fn max_record_payload(&self) -> u64 {
        self.max_record_payload
    }
    pub fn max_chunk_plaintext(&self) -> u64 {
        self.max_chunk_plaintext
    }
    pub fn max_metadata_bytes(&self) -> u64 {
        self.max_metadata_bytes
    }
    pub fn max_object_version_parents(&self) -> u64 {
        self.max_object_version_parents
    }
    pub fn max_repocommit_parents(&self) -> u64 {
        self.max_repocommit_parents
    }
    pub fn max_relations(&self) -> u64 {
        self.max_relations
    }
    pub fn max_changes(&self) -> u64 {
        self.max_changes
    }
    pub fn max_policy_keys(&self) -> u64 {
        self.max_policy_keys
    }
    pub fn max_policy_permissions(&self) -> u64 {
        self.max_policy_permissions
    }
    pub fn max_key_slots(&self) -> u64 {
        self.max_key_slots
    }
    pub fn max_manifest_chunks(&self) -> u64 {
        self.max_manifest_chunks
    }
    pub fn max_pack_records(&self) -> u64 {
        self.max_pack_records
    }
    pub fn max_pack_size(&self) -> u64 {
        self.max_pack_size
    }
    pub fn max_segment_size(&self) -> u32 {
        self.max_segment_size
    }
    pub fn impl_target_segment_size(&self) -> u64 {
        self.impl_target_segment_size
    }

    // --- Convenience builders (only reduce, never increase) ---

    pub fn with_max_depth(mut self, max_depth: u64) -> Result<Self, LimitsError> {
        Self::check_nonzero("max_depth", max_depth)?;
        if max_depth > self.max_depth {
            return Err(LimitsError::LimitExceedsAbsoluteMax {
                field: "max_depth",
                requested: max_depth,
                absolute_max: self.max_depth,
            });
        }
        self.max_depth = max_depth;
        Ok(self)
    }

    pub fn with_max_nodes(mut self, max_nodes: u64) -> Result<Self, LimitsError> {
        Self::check_nonzero("max_nodes", max_nodes)?;
        if max_nodes > self.max_nodes {
            return Err(LimitsError::LimitExceedsAbsoluteMax {
                field: "max_nodes",
                requested: max_nodes,
                absolute_max: self.max_nodes,
            });
        }
        self.max_nodes = max_nodes;
        Ok(self)
    }

    pub fn with_max_string_bytes(mut self, max_string_bytes: u64) -> Result<Self, LimitsError> {
        Self::check_nonzero("max_string_bytes", max_string_bytes)?;
        if max_string_bytes > self.max_string_bytes {
            return Err(LimitsError::LimitExceedsAbsoluteMax {
                field: "max_string_bytes",
                requested: max_string_bytes,
                absolute_max: self.max_string_bytes,
            });
        }
        self.max_string_bytes = max_string_bytes;
        Ok(self)
    }

    pub fn with_max_metadata_bytes(mut self, max_metadata_bytes: u64) -> Result<Self, LimitsError> {
        Self::check_nonzero("max_metadata_bytes", max_metadata_bytes)?;
        if max_metadata_bytes > self.max_metadata_bytes {
            return Err(LimitsError::LimitExceedsAbsoluteMax {
                field: "max_metadata_bytes",
                requested: max_metadata_bytes,
                absolute_max: self.max_metadata_bytes,
            });
        }
        self.max_metadata_bytes = max_metadata_bytes;
        Ok(self)
    }
}

impl Default for FormatLimits {
    fn default() -> Self {
        Self {
            max_depth: Self::ABSOLUTE_MAX_DEPTH,
            max_nodes: Self::ABSOLUTE_MAX_NODES,
            max_string_bytes: Self::ABSOLUTE_MAX_STRING_BYTES,
            max_record_payload: Self::ABSOLUTE_MAX_RECORD_PAYLOAD,
            max_chunk_plaintext: Self::ABSOLUTE_MAX_CHUNK_PLAINTEXT,
            max_metadata_bytes: Self::ABSOLUTE_MAX_METADATA_BYTES,
            max_object_version_parents: Self::ABSOLUTE_MAX_OBJECT_VERSION_PARENTS,
            max_repocommit_parents: Self::ABSOLUTE_MAX_REPOCOMMIT_PARENTS,
            max_relations: Self::ABSOLUTE_MAX_RELATIONS,
            max_changes: Self::ABSOLUTE_MAX_CHANGES,
            max_policy_keys: Self::ABSOLUTE_MAX_POLICY_KEYS,
            max_policy_permissions: Self::ABSOLUTE_MAX_POLICY_PERMISSIONS,
            max_key_slots: Self::ABSOLUTE_MAX_KEY_SLOTS,
            max_manifest_chunks: Self::ABSOLUTE_MAX_MANIFEST_CHUNKS,
            max_pack_records: Self::ABSOLUTE_MAX_PACK_RECORDS,
            max_pack_size: Self::ABSOLUTE_MAX_PACK_SIZE,
            max_segment_size: Self::ABSOLUTE_MAX_SEGMENT_SIZE,
            impl_target_segment_size: Self::IMPL_TARGET_SEGMENT_SIZE,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // --- Default values match absolute max ---

    #[test]
    fn defaults_equal_absolute_max() {
        let d = FormatLimits::default();
        assert_eq!(d.max_depth(), FormatLimits::ABSOLUTE_MAX_DEPTH);
        assert_eq!(d.max_nodes(), FormatLimits::ABSOLUTE_MAX_NODES);
        assert_eq!(
            d.max_string_bytes(),
            FormatLimits::ABSOLUTE_MAX_STRING_BYTES
        );
    }

    // --- Zero-value rejection ---

    #[test]
    fn rejects_zero_depth() {
        let result = FormatLimits::new(0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
        assert_eq!(result, Err(LimitsError::LimitIsZero { field: "max_depth" }));
    }

    #[test]
    fn rejects_zero_nodes() {
        let result = FormatLimits::new(1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
        assert_eq!(result, Err(LimitsError::LimitIsZero { field: "max_nodes" }));
    }

    #[test]
    fn rejects_zero_string_bytes() {
        let result = FormatLimits::new(1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
        assert_eq!(
            result,
            Err(LimitsError::LimitIsZero {
                field: "max_string_bytes"
            })
        );
    }

    #[test]
    fn rejects_zero_record_payload() {
        let result = FormatLimits::new(1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
        assert_eq!(
            result,
            Err(LimitsError::LimitIsZero {
                field: "max_record_payload"
            })
        );
    }

    #[test]
    fn rejects_zero_segment_size() {
        let result = FormatLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0);
        assert_eq!(
            result,
            Err(LimitsError::LimitIsZero {
                field: "max_segment_size"
            })
        );
    }

    // --- Overflow rejection ---

    #[test]
    fn rejects_excessive_depth() {
        let result = FormatLimits::new(65, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
        assert_eq!(
            result,
            Err(LimitsError::LimitExceedsAbsoluteMax {
                field: "max_depth",
                requested: 65,
                absolute_max: 64,
            })
        );
    }

    #[test]
    fn rejects_excessive_pack_size() {
        let bad = FormatLimits::ABSOLUTE_MAX_PACK_SIZE + 1;
        let result = FormatLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, bad, 1);
        assert_eq!(
            result,
            Err(LimitsError::LimitExceedsAbsoluteMax {
                field: "max_pack_size",
                requested: bad,
                absolute_max: FormatLimits::ABSOLUTE_MAX_PACK_SIZE,
            })
        );
    }

    // --- with_* zero rejection ---

    #[test]
    fn with_max_depth_rejects_zero() {
        let limits = FormatLimits::default();
        let result = limits.with_max_depth(0);
        assert_eq!(result, Err(LimitsError::LimitIsZero { field: "max_depth" }));
    }

    #[test]
    fn with_max_nodes_rejects_zero() {
        let limits = FormatLimits::default();
        let result = limits.with_max_nodes(0);
        assert_eq!(result, Err(LimitsError::LimitIsZero { field: "max_nodes" }));
    }

    #[test]
    fn with_max_string_bytes_rejects_zero() {
        let limits = FormatLimits::default();
        let result = limits.with_max_string_bytes(0);
        assert_eq!(
            result,
            Err(LimitsError::LimitIsZero {
                field: "max_string_bytes"
            })
        );
    }

    #[test]
    fn with_max_metadata_bytes_rejects_zero() {
        let limits = FormatLimits::default();
        let result = limits.with_max_metadata_bytes(0);
        assert_eq!(
            result,
            Err(LimitsError::LimitIsZero {
                field: "max_metadata_bytes"
            })
        );
    }

    // --- with_* reject increase ---

    #[test]
    fn with_max_depth_rejects_increase() {
        let limits = FormatLimits::default();
        let result = limits.with_max_depth(FormatLimits::ABSOLUTE_MAX_DEPTH + 1);
        assert_eq!(
            result,
            Err(LimitsError::LimitExceedsAbsoluteMax {
                field: "max_depth",
                requested: FormatLimits::ABSOLUTE_MAX_DEPTH + 1,
                absolute_max: FormatLimits::ABSOLUTE_MAX_DEPTH,
            })
        );
    }

    #[test]
    fn with_max_metadata_bytes_rejects_increase() {
        let reduced = FormatLimits::default()
            .with_max_metadata_bytes(1024)
            .unwrap();
        let result = reduced.with_max_metadata_bytes(2048);
        assert!(result.is_err());
    }
}
