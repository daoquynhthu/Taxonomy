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
    max_segment_size: u64,
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
    pub const ABSOLUTE_MAX_SEGMENT_SIZE: u64 = 4_294_967_296;

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
        max_segment_size: u64,
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
        Self::check_nonzero("max_segment_size", max_segment_size)?;

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
        Self::check_max(
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
        })
    }

    fn check_nonzero(field: &'static str, value: u64) -> Result<(), LimitsError> {
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
    pub fn max_segment_size(&self) -> u64 {
        self.max_segment_size
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
        assert_eq!(
            d.max_record_payload(),
            FormatLimits::ABSOLUTE_MAX_RECORD_PAYLOAD
        );
        assert_eq!(
            d.max_chunk_plaintext(),
            FormatLimits::ABSOLUTE_MAX_CHUNK_PLAINTEXT
        );
        assert_eq!(
            d.max_metadata_bytes(),
            FormatLimits::ABSOLUTE_MAX_METADATA_BYTES
        );
        assert_eq!(
            d.max_object_version_parents(),
            FormatLimits::ABSOLUTE_MAX_OBJECT_VERSION_PARENTS
        );
        assert_eq!(
            d.max_repocommit_parents(),
            FormatLimits::ABSOLUTE_MAX_REPOCOMMIT_PARENTS
        );
        assert_eq!(d.max_relations(), FormatLimits::ABSOLUTE_MAX_RELATIONS);
        assert_eq!(d.max_changes(), FormatLimits::ABSOLUTE_MAX_CHANGES);
        assert_eq!(d.max_policy_keys(), FormatLimits::ABSOLUTE_MAX_POLICY_KEYS);
        assert_eq!(
            d.max_policy_permissions(),
            FormatLimits::ABSOLUTE_MAX_POLICY_PERMISSIONS
        );
        assert_eq!(d.max_key_slots(), FormatLimits::ABSOLUTE_MAX_KEY_SLOTS);
        assert_eq!(
            d.max_manifest_chunks(),
            FormatLimits::ABSOLUTE_MAX_MANIFEST_CHUNKS
        );
        assert_eq!(
            d.max_pack_records(),
            FormatLimits::ABSOLUTE_MAX_PACK_RECORDS
        );
        assert_eq!(d.max_pack_size(), FormatLimits::ABSOLUTE_MAX_PACK_SIZE);
        assert_eq!(
            d.max_segment_size(),
            FormatLimits::ABSOLUTE_MAX_SEGMENT_SIZE
        );
    }

    /// Helper: a single valid limits instance for zero-test parameter positions.
    const VALID_ARG: u64 = 1;

    #[test]
    fn rejects_each_zero_by_position() {
        let fields = [
            ("max_depth", 0, 1usize),
            ("max_nodes", 1, 0usize),
            ("max_string_bytes", 2, 0usize),
            ("max_record_payload", 3, 0usize),
            ("max_chunk_plaintext", 4, 0usize),
            ("max_metadata_bytes", 5, 0usize),
            ("max_object_version_parents", 6, 0usize),
            ("max_repocommit_parents", 7, 0usize),
            ("max_relations", 8, 0usize),
            ("max_changes", 9, 0usize),
            ("max_policy_keys", 10, 0usize),
            ("max_policy_permissions", 11, 0usize),
            ("max_key_slots", 12, 0usize),
            ("max_manifest_chunks", 13, 0usize),
            ("max_pack_records", 14, 0usize),
            ("max_pack_size", 15, 0usize),
            ("max_segment_size", 16, 0usize),
        ];
        for &(field, zero_pos, _) in &fields {
            let args = (0..17)
                .map(|i| if i == zero_pos { 0u64 } else { VALID_ARG })
                .collect::<Vec<_>>();
            let result = FormatLimits::new(
                args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
                args[9], args[10], args[11], args[12], args[13], args[14], args[15], args[16],
            );
            assert_eq!(
                result,
                Err(LimitsError::LimitIsZero { field }),
                "expected LimitIsZero for {field} at position {zero_pos}",
            );
        }
    }

    #[test]
    fn rejects_each_excessive_by_position() {
        let fields: [(&str, usize, u64, u64); 17] = [
            ("max_depth", 0, 65, FormatLimits::ABSOLUTE_MAX_DEPTH),
            (
                "max_nodes",
                1,
                FormatLimits::ABSOLUTE_MAX_NODES + 1,
                FormatLimits::ABSOLUTE_MAX_NODES,
            ),
            (
                "max_string_bytes",
                2,
                FormatLimits::ABSOLUTE_MAX_STRING_BYTES + 1,
                FormatLimits::ABSOLUTE_MAX_STRING_BYTES,
            ),
            (
                "max_record_payload",
                3,
                FormatLimits::ABSOLUTE_MAX_RECORD_PAYLOAD + 1,
                FormatLimits::ABSOLUTE_MAX_RECORD_PAYLOAD,
            ),
            (
                "max_chunk_plaintext",
                4,
                FormatLimits::ABSOLUTE_MAX_CHUNK_PLAINTEXT + 1,
                FormatLimits::ABSOLUTE_MAX_CHUNK_PLAINTEXT,
            ),
            (
                "max_metadata_bytes",
                5,
                FormatLimits::ABSOLUTE_MAX_METADATA_BYTES + 1,
                FormatLimits::ABSOLUTE_MAX_METADATA_BYTES,
            ),
            (
                "max_object_version_parents",
                6,
                FormatLimits::ABSOLUTE_MAX_OBJECT_VERSION_PARENTS + 1,
                FormatLimits::ABSOLUTE_MAX_OBJECT_VERSION_PARENTS,
            ),
            (
                "max_repocommit_parents",
                7,
                FormatLimits::ABSOLUTE_MAX_REPOCOMMIT_PARENTS + 1,
                FormatLimits::ABSOLUTE_MAX_REPOCOMMIT_PARENTS,
            ),
            (
                "max_relations",
                8,
                FormatLimits::ABSOLUTE_MAX_RELATIONS + 1,
                FormatLimits::ABSOLUTE_MAX_RELATIONS,
            ),
            (
                "max_changes",
                9,
                FormatLimits::ABSOLUTE_MAX_CHANGES + 1,
                FormatLimits::ABSOLUTE_MAX_CHANGES,
            ),
            (
                "max_policy_keys",
                10,
                FormatLimits::ABSOLUTE_MAX_POLICY_KEYS + 1,
                FormatLimits::ABSOLUTE_MAX_POLICY_KEYS,
            ),
            (
                "max_policy_permissions",
                11,
                FormatLimits::ABSOLUTE_MAX_POLICY_PERMISSIONS + 1,
                FormatLimits::ABSOLUTE_MAX_POLICY_PERMISSIONS,
            ),
            (
                "max_key_slots",
                12,
                FormatLimits::ABSOLUTE_MAX_KEY_SLOTS + 1,
                FormatLimits::ABSOLUTE_MAX_KEY_SLOTS,
            ),
            (
                "max_manifest_chunks",
                13,
                FormatLimits::ABSOLUTE_MAX_MANIFEST_CHUNKS + 1,
                FormatLimits::ABSOLUTE_MAX_MANIFEST_CHUNKS,
            ),
            (
                "max_pack_records",
                14,
                FormatLimits::ABSOLUTE_MAX_PACK_RECORDS + 1,
                FormatLimits::ABSOLUTE_MAX_PACK_RECORDS,
            ),
            (
                "max_pack_size",
                15,
                FormatLimits::ABSOLUTE_MAX_PACK_SIZE + 1,
                FormatLimits::ABSOLUTE_MAX_PACK_SIZE,
            ),
            (
                "max_segment_size",
                16,
                FormatLimits::ABSOLUTE_MAX_SEGMENT_SIZE + 1,
                FormatLimits::ABSOLUTE_MAX_SEGMENT_SIZE,
            ),
        ];
        for &(field, pos, bad_val, abs_max) in &fields {
            let args = (0..17)
                .map(|i| if i == pos { bad_val } else { VALID_ARG })
                .collect::<Vec<_>>();
            let result = FormatLimits::new(
                args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
                args[9], args[10], args[11], args[12], args[13], args[14], args[15], args[16],
            );
            assert_eq!(
                result,
                Err(LimitsError::LimitExceedsAbsoluteMax {
                    field,
                    requested: bad_val,
                    absolute_max: abs_max,
                }),
                "expected LimitExceedsAbsoluteMax for {field} with value {bad_val}",
            );
        }
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
