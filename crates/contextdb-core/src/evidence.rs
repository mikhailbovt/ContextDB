use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    ActorId, ArtifactId, CommitRange, ContentBlockId, EpisodeViewId, EvidenceId, MemorySpaceId,
    NonEmptyVec, ObservationId, RevisionNumber, SemanticEnvelope, SourceId, StreamId, TimeRange,
    TimestampMicros, TrustClass, Validate, ValidationError, ValidationResult, WorkspaceId,
};

/// Stable 256-bit content digest serialized as lowercase hexadecimal.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Constructs a digest from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContentDigest")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ContentDigest {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(ValidationError::InvalidState {
                reason: "content digest must contain 64 hexadecimal characters",
            });
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let encoded =
                std::str::from_utf8(chunk).map_err(|_| ValidationError::InvalidState {
                    reason: "content digest is not valid UTF-8 hexadecimal",
                })?;
            bytes[index] =
                u8::from_str_radix(encoded, 16).map_err(|_| ValidationError::InvalidState {
                    reason: "content digest contains a non-hexadecimal character",
                })?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for ContentDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Physical or logical origin category.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Conversation,
    Document,
    Image,
    Audio,
    Video,
    Tool,
    Api,
    Git,
    Sensor,
    Import,
    Other(String),
}

/// Source identity and trust classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: SourceId,
    pub workspace_id: WorkspaceId,
    pub kind: SourceKind,
    pub native_locator: String,
    pub owner_actor: Option<ActorId>,
    pub owner_subject: Option<crate::MemorySubjectId>,
    pub trust: TrustClass,
    pub ingestion_policy: crate::PolicyId,
    pub content_fingerprint: Option<ContentDigest>,
}

impl Validate for Source {
    fn validate(&self) -> ValidationResult {
        if let SourceKind::Other(label) = &self.kind {
            crate::provenance::validate_non_blank(label, "source.kind")?;
        }
        crate::provenance::validate_non_blank(&self.native_locator, "source.native_locator")
    }
}

/// Ordered position inside a source-native stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamPosition {
    pub stream_id: StreamId,
    pub ordinal: u64,
    pub native_revision: Option<String>,
    pub wall_time: Option<TimestampMicros>,
}

impl Validate for StreamPosition {
    fn validate(&self) -> ValidationResult {
        if let Some(revision) = &self.native_revision {
            crate::provenance::validate_non_blank(revision, "stream.native_revision")?;
        }
        Ok(())
    }
}

/// Content modality preserved independently from derived representations.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Text,
    Image,
    Audio,
    Video,
    Structured,
    Code,
    Sensor,
    Other(String),
}

/// How a referenced content block is encoded.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentEncoding {
    Utf8,
    Binary,
    Json,
    Other(String),
}

/// Compression applied to a referenced content block.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    None,
    Gzip,
    Zstd,
    Other(String),
}

/// Storage-neutral blob locator. Its scheme is interpreted outside this crate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlobLocator(pub String);

/// Content-addressed block kept outside hot semantic graph metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentBlock {
    pub id: ContentBlockId,
    pub media_type: String,
    pub encoding: ContentEncoding,
    pub compression: Compression,
    pub byte_length: u64,
    pub blob_locator: BlobLocator,
    pub content_hash: ContentDigest,
}

impl Validate for ContentBlock {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.media_type, "content_block.media_type")?;
        crate::provenance::validate_non_blank(&self.blob_locator.0, "content_block.blob_locator")?;
        validate_other_label(&self.encoding, "content_block.encoding")?;
        validate_compression(&self.compression)
    }
}

/// Immutable source artifact of any modality.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub id: ArtifactId,
    pub source_id: SourceId,
    pub modality: Modality,
    pub media_type: String,
    pub native_locator: Option<String>,
    pub content_blocks: NonEmptyVec<ContentBlockId>,
    pub content_hash: ContentDigest,
    pub created_at: Option<TimestampMicros>,
    pub ingested_at: TimestampMicros,
    pub envelope: SemanticEnvelope,
}

impl Validate for Artifact {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.media_type, "artifact.media_type")?;
        if let Some(locator) = &self.native_locator {
            crate::provenance::validate_non_blank(locator, "artifact.native_locator")?;
        }
        if let Modality::Other(label) = &self.modality {
            crate::provenance::validate_non_blank(label, "artifact.modality")?;
        }
        self.envelope.validate()
    }
}

/// Stable, modality-aware selector into an immutable content block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceSelector {
    Whole,
    ByteRange {
        start: u64,
        end: u64,
    },
    CharacterRange {
        start: u64,
        end: u64,
    },
    JsonPointer {
        pointer: String,
    },
    LineRange {
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    },
    DocumentHeading {
        path: NonEmptyVec<String>,
    },
    AstNode {
        language: String,
        node_path: String,
    },
    GitDiffHunk {
        path: String,
        old_start: u32,
        new_start: u32,
    },
    ImageRegion {
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    },
    MediaTimeRange {
        start_millis: u64,
        end_millis: u64,
    },
    SpeakerSegment {
        speaker: String,
        start_millis: u64,
        end_millis: u64,
    },
    ToolResultField {
        json_pointer: String,
    },
    SensorInterval {
        interval: TimeRange,
    },
}

impl Validate for EvidenceSelector {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::Whole => Ok(()),
            Self::ByteRange { start, end } | Self::CharacterRange { start, end } => {
                require_ordered(*start, *end, "range must be non-empty")
            }
            Self::JsonPointer { pointer }
            | Self::ToolResultField {
                json_pointer: pointer,
            } => {
                if pointer.is_empty() || !pointer.starts_with('/') {
                    return Err(ValidationError::InvalidEvidenceSelector {
                        reason: "JSON Pointer must start with '/'",
                    });
                }
                Ok(())
            }
            Self::LineRange {
                start_line,
                start_column,
                end_line,
                end_column,
            } => {
                if *start_line == 0
                    || *end_line == 0
                    || (*start_line, *start_column) >= (*end_line, *end_column)
                {
                    return Err(ValidationError::InvalidEvidenceSelector {
                        reason: "line range must use one-based lines and be non-empty",
                    });
                }
                Ok(())
            }
            Self::DocumentHeading { path } => {
                for heading in path {
                    crate::provenance::validate_non_blank(heading, "selector.heading")?;
                }
                Ok(())
            }
            Self::AstNode {
                language,
                node_path,
            } => {
                crate::provenance::validate_non_blank(language, "selector.language")?;
                crate::provenance::validate_non_blank(node_path, "selector.node_path")
            }
            Self::GitDiffHunk { path, .. } => {
                crate::provenance::validate_non_blank(path, "selector.path")
            }
            Self::ImageRegion { width, height, .. } => {
                if *width == 0 || *height == 0 {
                    return Err(ValidationError::InvalidEvidenceSelector {
                        reason: "image region must have positive width and height",
                    });
                }
                Ok(())
            }
            Self::MediaTimeRange {
                start_millis,
                end_millis,
            } => require_ordered(*start_millis, *end_millis, "media range must be non-empty"),
            Self::SpeakerSegment {
                speaker,
                start_millis,
                end_millis,
            } => {
                crate::provenance::validate_non_blank(speaker, "selector.speaker")?;
                require_ordered(
                    *start_millis,
                    *end_millis,
                    "speaker range must be non-empty",
                )
            }
            Self::SensorInterval { interval } => interval.validate(),
        }
    }
}

/// Exact source support for a semantic item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpan {
    pub id: EvidenceId,
    pub observation_id: ObservationId,
    pub artifact_id: Option<ArtifactId>,
    pub content_block_id: ContentBlockId,
    pub selector: EvidenceSelector,
    pub quote_hash: ContentDigest,
    pub extracted_text: Option<String>,
    pub trust: TrustClass,
    pub derivation: Option<crate::DerivationRef>,
}

impl Validate for EvidenceSpan {
    fn validate(&self) -> ValidationResult {
        self.selector.validate()?;
        if let Some(text) = &self.extracted_text
            && text.is_empty()
        {
            return Err(ValidationError::BlankText {
                field: "evidence.extracted_text",
            });
        }
        if let Some(derivation) = &self.derivation {
            derivation.validate()?;
        }
        Ok(())
    }
}

/// Immutable atomic observation. Episode grouping is intentionally separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationUnit {
    pub id: ObservationId,
    pub workspace_id: WorkspaceId,
    pub memory_spaces: NonEmptyVec<MemorySpaceId>,
    pub source_id: SourceId,
    pub stream_position: Option<StreamPosition>,
    pub participants: NonEmptyVec<ActorId>,
    pub occurred_at: TimeRange,
    pub observed_at: TimestampMicros,
    pub recorded_at: TimestampMicros,
    pub artifact_refs: Vec<ArtifactId>,
    pub content_block_refs: Vec<ContentBlockId>,
    pub content_hash: ContentDigest,
    pub envelope: SemanticEnvelope,
}

impl ObservationUnit {
    /// Creates an immutable observation after validating all local invariants.
    pub fn try_new(value: Self) -> ValidationResult<Self> {
        value.validate()?;
        Ok(value)
    }
}

impl Validate for ObservationUnit {
    fn validate(&self) -> ValidationResult {
        if self.artifact_refs.is_empty() && self.content_block_refs.is_empty() {
            return Err(ValidationError::MissingObservationContent);
        }
        self.occurred_at.validate()?;
        if let Some(position) = &self.stream_position {
            position.validate()?;
        }
        self.envelope.validate()
    }
}

/// Why immutable observations were grouped into one episode view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeBoundary {
    SourceNative,
    TurnPair,
    Topic,
    TaskPhase,
    TemporalGap,
    ToolCallResult,
    Checkpoint,
    Explicit,
    ModelAssisted { pipeline: crate::PipelineIdentity },
}

/// Versioned grouping over immutable observations. Re-segmentation creates a new revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeView {
    pub id: EpisodeViewId,
    pub revision: RevisionNumber,
    pub workspace_id: WorkspaceId,
    pub observation_ids: NonEmptyVec<ObservationId>,
    pub occurred_at: TimeRange,
    pub transaction_time: CommitRange,
    pub boundary: EpisodeBoundary,
    pub envelope: SemanticEnvelope,
}

impl Validate for EpisodeView {
    fn validate(&self) -> ValidationResult {
        self.occurred_at.validate()?;
        self.transaction_time.validate()?;
        if let EpisodeBoundary::ModelAssisted { pipeline } = &self.boundary {
            pipeline.validate()?;
        }
        let observations: std::collections::BTreeSet<_> =
            self.observation_ids.iter().copied().collect();
        if observations.len() != self.observation_ids.len() {
            return Err(ValidationError::DuplicateIdentifier {
                field: "episode_view.observation_ids",
            });
        }
        self.envelope.validate()
    }
}

fn require_ordered(start: u64, end: u64, reason: &'static str) -> ValidationResult {
    if start >= end {
        return Err(ValidationError::InvalidEvidenceSelector { reason });
    }
    Ok(())
}

fn validate_other_label(encoding: &ContentEncoding, field: &'static str) -> ValidationResult {
    if let ContentEncoding::Other(label) = encoding {
        crate::provenance::validate_non_blank(label, field)?;
    }
    Ok(())
}

fn validate_compression(compression: &Compression) -> ValidationResult {
    if let Compression::Other(label) = compression {
        crate::provenance::validate_non_blank(label, "content_block.compression")?;
    }
    Ok(())
}
