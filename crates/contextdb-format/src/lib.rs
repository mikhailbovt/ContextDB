//! Versioned physical framing for ContextDB durable records.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ContextDB journal frame magic.
pub const MAGIC: [u8; 4] = *b"CTXJ";
/// Byte length of the fixed, endian-explicit envelope.
pub const HEADER_LEN: usize = 32;

/// Schema identifier for standalone durable-format manifests.
pub const FORMAT_MANIFEST_SCHEMA_V1: &str = "contextdb.format-manifest/v1";

/// A stored database's physical-format identity and required reader features.
///
/// This value is deliberately smaller than a release version manifest. It is
/// safe to persist beside primary state and contains no deployment identity or
/// authority material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFormatManifest {
    /// Stable lowercase format family, for example `storage` or `graph_segment`.
    pub family: String,
    /// Physical writer version that created the active generation.
    pub writer: u32,
    /// Durable features that a reader must understand before opening state.
    #[serde(default)]
    pub required_features: BTreeSet<String>,
}

impl StoredFormatManifest {
    /// Constructs and validates one stored-format manifest.
    pub fn new(
        family: impl Into<String>,
        writer: u32,
        required_features: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let manifest = Self {
            family: family.into(),
            writer,
            required_features: required_features.into_iter().map(Into::into).collect(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates family and feature identifiers without opening payload data.
    pub fn validate(&self) -> Result<()> {
        validate_identifier("format family", &self.family)?;
        for feature in &self.required_features {
            validate_identifier("required format feature", feature)?;
        }
        Ok(())
    }
}

/// Inclusive reader compatibility and explicitly supported durable features.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderCapability {
    /// Oldest physical writer version this reader accepts.
    pub read_min: u32,
    /// Newest physical writer version this reader accepts.
    pub read_max: u32,
    /// Durable required features implemented by this reader.
    #[serde(default)]
    pub supported_features: BTreeSet<String>,
}

impl ReaderCapability {
    /// Constructs and validates one reader capability.
    pub fn new(
        read_min: u32,
        read_max: u32,
        supported_features: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let capability = Self {
            read_min,
            read_max,
            supported_features: supported_features.into_iter().map(Into::into).collect(),
        };
        capability.validate()?;
        Ok(capability)
    }

    /// Validates the inclusive reader range and feature identifiers.
    pub fn validate(&self) -> Result<()> {
        if self.read_min > self.read_max {
            return Err(FormatError::InvalidReaderRange {
                read_min: self.read_min,
                read_max: self.read_max,
            });
        }
        for feature in &self.supported_features {
            validate_identifier("supported format feature", feature)?;
        }
        Ok(())
    }

    /// Fails closed unless this reader can safely open the stored generation.
    pub fn ensure_can_read(&self, stored: &StoredFormatManifest) -> Result<()> {
        self.validate()?;
        stored.validate()?;
        if !(self.read_min..=self.read_max).contains(&stored.writer) {
            return Err(FormatError::UnsupportedWriterVersion {
                family: stored.family.clone(),
                writer: stored.writer,
                read_min: self.read_min,
                read_max: self.read_max,
            });
        }
        if let Some(feature) = stored
            .required_features
            .difference(&self.supported_features)
            .next()
        {
            return Err(FormatError::UnknownRequiredFeature {
                family: stored.family.clone(),
                feature: feature.clone(),
            });
        }
        Ok(())
    }
}

/// Migration execution class from RFC 25.34.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationKind {
    /// Additive metadata update that can run while readers remain active.
    OnlineMetadata,
    /// Resumable rewrite of immutable derived segments.
    BackgroundSegmentRewrite,
    /// Build and verify a new generation before atomic activation.
    SideBySideGeneration,
    /// Offline major-version migration into a separate target.
    OfflineMajor,
    /// Canonical logical export followed by verified import.
    LogicalExportImport,
}

/// Declared rollback behavior for one migration edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackPolicy {
    /// Switch the supervisor back to the unchanged source generation.
    SwitchToUntouchedSource,
    /// A separately registered and verified reverse migration exists.
    VerifiedReverseMigration,
    /// Activation is one-way; the planner must surface that fact.
    Unsupported,
}

/// Conservative free-space estimator for a migration edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeSpaceRequirement {
    /// Fixed metadata, journal and manifest allowance.
    pub fixed_bytes: u64,
    /// Numerator of the source-size multiplier.
    pub source_multiplier_numerator: u32,
    /// Denominator of the source-size multiplier.
    pub source_multiplier_denominator: u32,
}

impl FreeSpaceRequirement {
    /// A zero-allocation estimator for migrations that need no extra space.
    pub const NONE: Self = Self {
        fixed_bytes: 0,
        source_multiplier_numerator: 0,
        source_multiplier_denominator: 1,
    };

    /// Estimates required bytes, rounding fractional source bytes upward.
    pub fn estimate(self, source_bytes: u64) -> Result<u64> {
        if self.source_multiplier_denominator == 0 {
            return Err(FormatError::InvalidFreeSpaceRequirement);
        }
        let numerator = u128::from(source_bytes)
            .checked_mul(u128::from(self.source_multiplier_numerator))
            .ok_or(FormatError::FreeSpaceEstimateOverflow)?;
        let denominator = u128::from(self.source_multiplier_denominator);
        let scaled = numerator
            .checked_add(denominator.saturating_sub(1))
            .ok_or(FormatError::FreeSpaceEstimateOverflow)?
            / denominator;
        let total = scaled
            .checked_add(u128::from(self.fixed_bytes))
            .ok_or(FormatError::FreeSpaceEstimateOverflow)?;
        u64::try_from(total).map_err(|_| FormatError::FreeSpaceEstimateOverflow)
    }
}

/// One registered, directional physical-format migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationDescriptor {
    /// Stable receipt identifier, for example `STORAGE-0001`.
    pub migration_id: String,
    /// Stable lowercase format family.
    pub family: String,
    /// Accepted source writer version.
    pub from_writer: u32,
    /// Produced target writer version.
    pub to_writer: u32,
    /// Execution class.
    pub kind: MigrationKind,
    /// Exact rollback declaration.
    pub rollback: RollbackPolicy,
    /// Conservative extra-space formula.
    pub required_free_space: FreeSpaceRequirement,
    /// Stable checksum/verification plan identifier.
    pub checksum_plan: String,
}

impl MigrationDescriptor {
    /// Validates identifiers, direction and estimator parameters.
    pub fn validate(&self) -> Result<()> {
        validate_migration_id(&self.migration_id)?;
        validate_identifier("format family", &self.family)?;
        validate_identifier("checksum plan", &self.checksum_plan)?;
        if self.from_writer == self.to_writer {
            return Err(FormatError::IdentityMigration {
                family: self.family.clone(),
                writer: self.from_writer,
            });
        }
        self.required_free_space.estimate(0).map(|_| ())
    }
}

/// Deterministic, preflight-only migration plan. It never mutates source data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    /// Stable format family.
    pub family: String,
    /// Active source writer version.
    pub from_writer: u32,
    /// Requested target writer version.
    pub to_writer: u32,
    /// Ordered migration edges.
    pub steps: Vec<MigrationDescriptor>,
    /// Maximum conservative scratch-space requirement across all steps.
    pub required_free_space_bytes: u64,
    /// Whether every edge has an explicit rollback route.
    pub rollback_supported: bool,
}

/// Runtime registry of reader capabilities and explicit migration edges.
#[derive(Debug, Clone, Default)]
pub struct FormatRegistry {
    readers: BTreeMap<String, ReaderCapability>,
    migrations: BTreeMap<String, MigrationDescriptor>,
}

impl FormatRegistry {
    /// Creates an empty fail-closed registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            readers: BTreeMap::new(),
            migrations: BTreeMap::new(),
        }
    }

    /// Registers exactly one reader capability for a format family.
    pub fn register_reader(
        &mut self,
        family: impl Into<String>,
        capability: ReaderCapability,
    ) -> Result<()> {
        let family = family.into();
        validate_identifier("format family", &family)?;
        capability.validate()?;
        if self.readers.insert(family.clone(), capability).is_some() {
            return Err(FormatError::DuplicateReader { family });
        }
        Ok(())
    }

    /// Registers a directional migration descriptor with a globally unique ID.
    pub fn register_migration(&mut self, migration: MigrationDescriptor) -> Result<()> {
        migration.validate()?;
        if self.migrations.contains_key(&migration.migration_id) {
            return Err(FormatError::DuplicateMigration {
                migration_id: migration.migration_id,
            });
        }
        if self.migrations.values().any(|existing| {
            existing.family == migration.family
                && existing.from_writer == migration.from_writer
                && existing.to_writer == migration.to_writer
        }) {
            return Err(FormatError::DuplicateMigrationEdge {
                family: migration.family,
                from_writer: migration.from_writer,
                to_writer: migration.to_writer,
            });
        }
        self.migrations
            .insert(migration.migration_id.clone(), migration);
        Ok(())
    }

    /// Verifies that the registered reader for this family can open the state.
    pub fn ensure_readable(&self, stored: &StoredFormatManifest) -> Result<()> {
        stored.validate()?;
        let reader =
            self.readers
                .get(&stored.family)
                .ok_or_else(|| FormatError::UnknownFormatFamily {
                    family: stored.family.clone(),
                })?;
        reader.ensure_can_read(stored)
    }

    /// Builds the shortest deterministic migration chain and checks free space.
    ///
    /// Planning is side-effect free. Callers must still checkpoint, execute,
    /// verify and atomically activate each descriptor with the declared host
    /// authority.
    pub fn plan_migration(
        &self,
        family: &str,
        from_writer: u32,
        to_writer: u32,
        source_bytes: u64,
        available_free_space: u64,
    ) -> Result<MigrationPlan> {
        validate_identifier("format family", family)?;
        if from_writer == to_writer {
            return Ok(MigrationPlan {
                family: family.to_owned(),
                from_writer,
                to_writer,
                steps: Vec::new(),
                required_free_space_bytes: 0,
                rollback_supported: true,
            });
        }

        let mut queue = VecDeque::from([(from_writer, Vec::<String>::new())]);
        let mut visited = BTreeSet::from([from_writer]);
        let mut selected = None;
        while let Some((writer, path)) = queue.pop_front() {
            let mut outgoing: Vec<_> = self
                .migrations
                .values()
                .filter(|migration| migration.family == family && migration.from_writer == writer)
                .collect();
            outgoing.sort_by(|left, right| {
                left.to_writer
                    .cmp(&right.to_writer)
                    .then_with(|| left.migration_id.cmp(&right.migration_id))
            });
            for migration in outgoing {
                if !visited.insert(migration.to_writer) {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(migration.migration_id.clone());
                if migration.to_writer == to_writer {
                    selected = Some(next_path);
                    break;
                }
                queue.push_back((migration.to_writer, next_path));
            }
            if selected.is_some() {
                break;
            }
        }

        let migration_ids = selected.ok_or_else(|| FormatError::MigrationPathUnavailable {
            family: family.to_owned(),
            from_writer,
            to_writer,
        })?;
        let steps: Vec<_> = migration_ids
            .iter()
            .filter_map(|id| self.migrations.get(id).cloned())
            .collect();
        let mut required_free_space_bytes = 0_u64;
        for step in &steps {
            required_free_space_bytes =
                required_free_space_bytes.max(step.required_free_space.estimate(source_bytes)?);
        }
        if available_free_space < required_free_space_bytes {
            return Err(FormatError::InsufficientMigrationSpace {
                required: required_free_space_bytes,
                available: available_free_space,
            });
        }
        let rollback_supported = steps
            .iter()
            .all(|step| step.rollback != RollbackPolicy::Unsupported);
        Ok(MigrationPlan {
            family: family.to_owned(),
            from_writer,
            to_writer,
            steps,
            required_free_space_bytes,
            rollback_supported,
        })
    }
}

/// Stable physical record categories. Unknown numeric values remain parseable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordKind {
    /// Immutable source observation accepted to the journal.
    Observation = 1,
    /// Exact validated semantic mutation proposal selected for publication.
    SemanticMutation = 2,
    /// Deterministic semantic publication receipt.
    SemanticPublication = 3,
    /// Policy mutation independent from semantic content.
    PolicyMutation = 4,
    /// Atomic derived-index work descriptor.
    Outbox = 5,
    /// Logical snapshot/checkpoint record.
    Snapshot = 6,
    /// Non-content deletion proof.
    DeletionProof = 7,
    /// Exact validated policy or maintenance mutation.
    MaintenanceMutation = 8,
    /// Atomic publication record for a maintenance mutation.
    MaintenancePublication = 9,
}

impl From<RecordKind> for u16 {
    fn from(value: RecordKind) -> Self {
        value as Self
    }
}

/// Parsed envelope metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordEnvelope {
    /// Numeric kind. Readers preserve unknown additive kinds.
    pub record_kind: u16,
    /// Schema version of the payload for this kind.
    pub schema_version: u16,
    /// Kind-specific feature flags.
    pub flags: u32,
    /// Monotonic ContextDB publication sequence.
    pub commit_seq: u64,
    /// Payload byte length.
    pub payload_len: u32,
    /// First 64 bits of the payload BLAKE3 digest, interpreted big-endian.
    pub payload_checksum: u64,
}

/// Borrowed validated frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedRecord<'a> {
    /// Parsed envelope.
    pub envelope: RecordEnvelope,
    /// Payload whose length and checksum were validated.
    pub payload: &'a [u8],
}

impl RecordEnvelope {
    /// Encodes an envelope and payload into one canonical frame.
    pub fn encode(
        record_kind: impl Into<u16>,
        schema_version: u16,
        flags: u32,
        commit_seq: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| FormatError::PayloadTooLarge {
                length: payload.len(),
            })?;
        let payload_checksum = checksum(payload);
        let mut frame = Vec::with_capacity(HEADER_LEN.saturating_add(payload.len()));
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&record_kind.into().to_be_bytes());
        frame.extend_from_slice(&schema_version.to_be_bytes());
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(&commit_seq.to_be_bytes());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&payload_checksum.to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    /// Parses and verifies exactly one frame. Trailing bytes are rejected.
    pub fn decode(frame: &[u8]) -> Result<DecodedRecord<'_>> {
        if frame.len() < HEADER_LEN {
            return Err(FormatError::TruncatedHeader {
                actual: frame.len(),
            });
        }
        if frame.get(0..4) != Some(MAGIC.as_slice()) {
            return Err(FormatError::BadMagic);
        }
        let record_kind = read_u16(frame, 4)?;
        let schema_version = read_u16(frame, 6)?;
        let flags = read_u32(frame, 8)?;
        let commit_seq = read_u64(frame, 12)?;
        let payload_len = read_u32(frame, 20)?;
        let payload_checksum = read_u64(frame, 24)?;
        let expected_len = HEADER_LEN
            .checked_add(usize::try_from(payload_len).map_err(|_| FormatError::InvalidLength)?)
            .ok_or(FormatError::InvalidLength)?;
        if frame.len() != expected_len {
            return Err(FormatError::LengthMismatch {
                declared: payload_len,
                actual: frame.len().saturating_sub(HEADER_LEN),
            });
        }
        let payload = frame.get(HEADER_LEN..).ok_or(FormatError::InvalidLength)?;
        let actual_checksum = checksum(payload);
        if payload_checksum != actual_checksum {
            return Err(FormatError::ChecksumMismatch {
                expected: payload_checksum,
                actual: actual_checksum,
            });
        }
        Ok(DecodedRecord {
            envelope: RecordEnvelope {
                record_kind,
                schema_version,
                flags,
                commit_seq,
                payload_len,
                payload_checksum,
            },
            payload,
        })
    }
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(FormatError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
        });
    };
    if !first.is_ascii_lowercase()
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(FormatError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_migration_id(value: &str) -> Result<()> {
    let Some((prefix, sequence)) = value.rsplit_once('-') else {
        return Err(FormatError::InvalidMigrationId(value.to_owned()));
    };
    if prefix.is_empty()
        || !prefix.bytes().all(|byte| byte.is_ascii_uppercase())
        || sequence.len() < 4
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(FormatError::InvalidMigrationId(value.to_owned()));
    }
    Ok(())
}

fn checksum(payload: &[u8]) -> u64 {
    let digest = blake3::hash(payload);
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(prefix)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or(FormatError::InvalidLength)?
        .try_into()
        .map_err(|_| FormatError::InvalidLength)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(FormatError::InvalidLength)?
        .try_into()
        .map_err(|_| FormatError::InvalidLength)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or(FormatError::InvalidLength)?
        .try_into()
        .map_err(|_| FormatError::InvalidLength)?;
    Ok(u64::from_be_bytes(value))
}

/// Record framing failures. Errors never include payload bytes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    /// A family, feature or checksum-plan identifier is not canonical.
    #[error("invalid {kind} identifier `{value}`")]
    InvalidIdentifier {
        /// Identifier category.
        kind: &'static str,
        /// Rejected value; identifiers never contain payload content.
        value: String,
    },
    /// A migration receipt ID is not canonical.
    #[error("invalid migration ID `{0}`")]
    InvalidMigrationId(String),
    /// Inclusive reader range is reversed.
    #[error("invalid reader range {read_min}..={read_max}")]
    InvalidReaderRange {
        /// Declared minimum.
        read_min: u32,
        /// Declared maximum.
        read_max: u32,
    },
    /// Stored writer version is outside the reader's explicit range.
    #[error(
        "format family `{family}` writer {writer} is outside reader range {read_min}..={read_max}"
    )]
    UnsupportedWriterVersion {
        /// Stored family.
        family: String,
        /// Stored writer.
        writer: u32,
        /// Reader minimum.
        read_min: u32,
        /// Reader maximum.
        read_max: u32,
    },
    /// Stored primary state requires a feature unknown to this reader.
    #[error("format family `{family}` requires unsupported feature `{feature}`")]
    UnknownRequiredFeature {
        /// Stored family.
        family: String,
        /// First unsupported feature in canonical order.
        feature: String,
    },
    /// No reader was registered for this durable family.
    #[error("no reader registered for format family `{family}`")]
    UnknownFormatFamily {
        /// Requested family.
        family: String,
    },
    /// A family already has an explicit reader registration.
    #[error("reader already registered for format family `{family}`")]
    DuplicateReader {
        /// Duplicate family.
        family: String,
    },
    /// Migration IDs are globally unique receipt identifiers.
    #[error("migration ID `{migration_id}` is already registered")]
    DuplicateMigration {
        /// Duplicate ID.
        migration_id: String,
    },
    /// Only one deterministic migration may own an exact edge.
    #[error("migration edge `{family}` {from_writer}->{to_writer} is already registered")]
    DuplicateMigrationEdge {
        /// Format family.
        family: String,
        /// Source writer.
        from_writer: u32,
        /// Target writer.
        to_writer: u32,
    },
    /// Migration descriptors must advance or deliberately downgrade a version.
    #[error("identity migration for `{family}` writer {writer} is invalid")]
    IdentityMigration {
        /// Format family.
        family: String,
        /// Identical source and target writer.
        writer: u32,
    },
    /// Free-space multiplier denominator must be non-zero.
    #[error("migration free-space denominator must be non-zero")]
    InvalidFreeSpaceRequirement,
    /// Free-space arithmetic cannot be represented safely.
    #[error("migration free-space estimate overflow")]
    FreeSpaceEstimateOverflow,
    /// No registered directional chain reaches the requested version.
    #[error("no migration path for `{family}` {from_writer}->{to_writer}")]
    MigrationPathUnavailable {
        /// Format family.
        family: String,
        /// Source writer.
        from_writer: u32,
        /// Target writer.
        to_writer: u32,
    },
    /// Preflight refuses to begin when conservative scratch space is absent.
    #[error("migration requires {required} free bytes but only {available} are available")]
    InsufficientMigrationSpace {
        /// Required bytes.
        required: u64,
        /// Available bytes.
        available: u64,
    },
    /// Payload cannot be represented in the fixed header.
    #[error("payload length {length} exceeds the v1 envelope limit")]
    PayloadTooLarge {
        /// Actual payload length.
        length: usize,
    },
    /// Fewer than [`HEADER_LEN`] bytes were supplied.
    #[error("truncated record header: got {actual} bytes")]
    TruncatedHeader {
        /// Available byte count.
        actual: usize,
    },
    /// Magic does not identify a ContextDB record.
    #[error("invalid record magic")]
    BadMagic,
    /// Declared and actual payload lengths differ.
    #[error("payload length mismatch: declared {declared}, actual {actual}")]
    LengthMismatch {
        /// Header-declared length.
        declared: u32,
        /// Actual bytes after the header.
        actual: usize,
    },
    /// Header offsets or arithmetic are invalid.
    #[error("invalid record length")]
    InvalidLength,
    /// Payload digest does not match the envelope.
    #[error("payload checksum mismatch: expected {expected:016x}, actual {actual:016x}")]
    ChecksumMismatch {
        /// Header checksum.
        expected: u64,
        /// Computed checksum.
        actual: u64,
    },
}

/// Format result type.
pub type Result<T> = std::result::Result<T, FormatError>;

#[cfg(test)]
mod tests {
    use super::{
        FormatError, FormatRegistry, FreeSpaceRequirement, HEADER_LEN, MigrationDescriptor,
        MigrationKind, ReaderCapability, RecordEnvelope, RecordKind, RollbackPolicy,
        StoredFormatManifest,
    };

    #[test]
    fn round_trip_preserves_unknown_safe_metadata() {
        let frame = RecordEnvelope::encode(65_000_u16, 9, 0xA5, 42, b"payload");
        assert!(frame.is_ok());
        let decoded = frame.and_then(|bytes| {
            let record = RecordEnvelope::decode(&bytes)?;
            assert_eq!(record.envelope.record_kind, 65_000);
            assert_eq!(record.envelope.schema_version, 9);
            assert_eq!(record.envelope.flags, 0xA5);
            assert_eq!(record.envelope.commit_seq, 42);
            assert_eq!(record.payload, b"payload");
            Ok(())
        });
        assert!(decoded.is_ok());
    }

    #[test]
    fn corruption_is_detected_without_materializing_content() {
        let mut frame = RecordEnvelope::encode(RecordKind::Observation, 1, 0, 1, b"evidence")
            .unwrap_or_default();
        if let Some(byte) = frame.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(matches!(
            RecordEnvelope::decode(&frame),
            Err(FormatError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn truncation_and_trailing_bytes_fail_closed() {
        assert!(matches!(
            RecordEnvelope::decode(&[0; HEADER_LEN - 1]),
            Err(FormatError::TruncatedHeader { .. })
        ));
        let mut frame =
            RecordEnvelope::encode(RecordKind::Outbox, 1, 0, 4, b"x").unwrap_or_default();
        frame.push(0);
        assert!(matches!(
            RecordEnvelope::decode(&frame),
            Err(FormatError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn numeric_fields_are_big_endian_and_portable() {
        let frame =
            RecordEnvelope::encode(0x0102_u16, 0x0304, 0x0506_0708, 0x090A_0B0C_0D0E_0F10, &[])
                .unwrap_or_default();
        assert_eq!(frame.get(4..8), Some([1, 2, 3, 4].as_slice()));
        assert_eq!(frame.get(8..12), Some([5, 6, 7, 8].as_slice()));
        assert_eq!(
            frame.get(12..20),
            Some([9, 10, 11, 12, 13, 14, 15, 16].as_slice())
        );
    }

    #[test]
    fn reader_range_and_required_features_fail_closed_before_payload_access() {
        let reader = ReaderCapability::new(1, 2, ["content_indirection", "paged_graph"])
            .expect("valid reader");
        let readable = StoredFormatManifest::new("storage", 2, ["paged_graph"])
            .expect("valid stored manifest");
        reader.ensure_can_read(&readable).expect("known feature");

        let future = StoredFormatManifest::new("storage", 3, ["paged_graph"])
            .expect("valid future manifest");
        assert!(matches!(
            reader.ensure_can_read(&future),
            Err(FormatError::UnsupportedWriterVersion { writer: 3, .. })
        ));

        let unknown = StoredFormatManifest::new("storage", 2, ["provider_side_copy"])
            .expect("valid unknown feature name");
        assert!(matches!(
            reader.ensure_can_read(&unknown),
            Err(FormatError::UnknownRequiredFeature { feature, .. })
                if feature == "provider_side_copy"
        ));
    }

    #[test]
    fn registry_plans_shortest_deterministic_side_by_side_chain() {
        let mut registry = FormatRegistry::new();
        registry
            .register_reader(
                "storage",
                ReaderCapability::new(1, 3, ["content_indirection"]).expect("reader"),
            )
            .expect("register reader");
        registry
            .ensure_readable(
                &StoredFormatManifest::new("storage", 1, std::iter::empty::<String>())
                    .expect("stored"),
            )
            .expect("registered reader opens v1");

        for migration in [
            MigrationDescriptor {
                migration_id: "STORAGE-0001".to_owned(),
                family: "storage".to_owned(),
                from_writer: 1,
                to_writer: 2,
                kind: MigrationKind::SideBySideGeneration,
                rollback: RollbackPolicy::SwitchToUntouchedSource,
                required_free_space: FreeSpaceRequirement {
                    fixed_bytes: 64,
                    source_multiplier_numerator: 1,
                    source_multiplier_denominator: 1,
                },
                checksum_plan: "logical_root_v1".to_owned(),
            },
            MigrationDescriptor {
                migration_id: "STORAGE-0002".to_owned(),
                family: "storage".to_owned(),
                from_writer: 2,
                to_writer: 3,
                kind: MigrationKind::BackgroundSegmentRewrite,
                rollback: RollbackPolicy::VerifiedReverseMigration,
                required_free_space: FreeSpaceRequirement {
                    fixed_bytes: 0,
                    source_multiplier_numerator: 1,
                    source_multiplier_denominator: 2,
                },
                checksum_plan: "component_roots_v1".to_owned(),
            },
        ] {
            registry
                .register_migration(migration)
                .expect("register migration");
        }

        let plan = registry
            .plan_migration("storage", 1, 3, 1_000, 1_064)
            .expect("migration plan");
        assert_eq!(
            plan.steps
                .iter()
                .map(|step| step.migration_id.as_str())
                .collect::<Vec<_>>(),
            ["STORAGE-0001", "STORAGE-0002"]
        );
        assert_eq!(plan.required_free_space_bytes, 1_064);
        assert!(plan.rollback_supported);
    }

    #[test]
    fn migration_preflight_rejects_insufficient_space_without_a_plan() {
        let mut registry = FormatRegistry::new();
        registry
            .register_migration(MigrationDescriptor {
                migration_id: "STORAGE-0042".to_owned(),
                family: "storage".to_owned(),
                from_writer: 1,
                to_writer: 2,
                kind: MigrationKind::OfflineMajor,
                rollback: RollbackPolicy::Unsupported,
                required_free_space: FreeSpaceRequirement {
                    fixed_bytes: 128,
                    source_multiplier_numerator: 3,
                    source_multiplier_denominator: 2,
                },
                checksum_plan: "canonical_archive_v1".to_owned(),
            })
            .expect("migration");
        assert!(matches!(
            registry.plan_migration("storage", 1, 2, 1_001, 1_629),
            Err(FormatError::InsufficientMigrationSpace {
                required: 1_630,
                available: 1_629
            })
        ));
    }

    #[test]
    fn stored_manifest_json_rejects_unknown_fields_and_noncanonical_names() {
        let unknown_field = r#"{
            "family":"storage",
            "writer":1,
            "required_features":[],
            "authority":"must-not-be-here"
        }"#;
        assert!(serde_json::from_str::<StoredFormatManifest>(unknown_field).is_err());
        assert!(matches!(
            StoredFormatManifest::new("Storage", 1, std::iter::empty::<String>()),
            Err(FormatError::InvalidIdentifier { .. })
        ));
    }
}
