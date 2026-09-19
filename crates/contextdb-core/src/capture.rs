//! Immutable payload and adapter provenance contracts.

use serde::{Deserialize, Serialize};

use crate::{ArtifactId, ContentBlockId, ContentDigest, ModelCallId, ObservationId, ToolCallId};

/// A durably staged original, isolated by its own source policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalPayloadRef {
    /// Immutable content block identity.
    pub block_id: ContentBlockId,
    /// BLAKE3 of the full original bytes.
    pub digest: ContentDigest,
    /// Exact uncompressed byte length.
    pub byte_length: u64,
    /// Digest binding the ordered immutable storage chunks.
    pub manifest_digest: ContentDigest,
}

/// Byte-exact source span in an immutable captured original.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalSourceSpan {
    /// Original event. Audit spans of request echoes cannot be independent roots.
    pub event_id: ObservationId,
    /// Digest of that event's complete original.
    pub payload_digest: ContentDigest,
    /// Inclusive byte start.
    pub start: u64,
    /// Exclusive byte end.
    pub end: u64,
    /// Digest of the selected bytes.
    pub span_digest: ContentDigest,
}

/// Ordered wire bytes retained without duplicating retrieved source evidence.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestPart {
    /// Previously captured source bytes, checked under their own current ACL.
    Source { span: OriginalSourceSpan },
    /// New wire bytes, including exact renderer/protocol delimiters.
    Novel { bytes: Vec<u8> },
    /// Large novel wire bytes retained as a policy-bound durable block.
    StoredNovel { payload: OriginalPayloadRef },
}

impl std::fmt::Debug for RequestPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source { span } => f.debug_tuple("Source").field(span).finish(),
            Self::Novel { bytes } => f
                .debug_struct("Novel")
                .field("byte_length", &bytes.len())
                .finish(),
            Self::StoredNovel { payload } => f.debug_tuple("StoredNovel").field(payload).finish(),
        }
    }
}

/// Exact ordered request representation; it makes no semantic independence claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequestManifest {
    /// Stable model call occurrence.
    pub model_call_id: ModelCallId,
    /// Host renderer/version binding.
    pub renderer: String,
    /// Exact serialized wire digest.
    pub wire_digest: ContentDigest,
    /// Exact serialized wire length.
    pub byte_length: u64,
    /// Ordered source references and novel bytes.
    pub parts: Vec<RequestPart>,
}

/// Adapter-specific attribution, separate from payload and authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventProvenance {
    /// Tool request/outcome bound to exactly one action's bytes.
    Tool {
        /// Stable invocation ID used by target idempotency/reconciliation.
        call_id: ToolCallId,
        /// Immutable dispatch-intent event.
        request_event_id: ObservationId,
        /// Digest binding the requested operation and arguments.
        action_digest: ContentDigest,
    },
    /// Immutable artifact version or explicit gap rescan.
    Artifact {
        /// Stable artifact identity, retained across versions.
        artifact_id: ArtifactId,
        /// Expected predecessor bytes, absent for the first observation.
        base_digest: Option<ContentDigest>,
        /// Full new source bytes, absent for an observed deletion.
        new_digest: Option<ContentDigest>,
        /// A fresh snapshot after a watcher gap; never an invented missing diff.
        rescan_after_gap: bool,
    },
}
