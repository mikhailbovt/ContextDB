//! Immutable observed events, independent of extraction and semantic publication.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    AgentRunId, ContentDigest, ModelCallId, ObservationId, ScopeId, SessionId, SourceId, StreamId,
    TaskId, TimestampMicros, Validate, ValidationError, ValidationResult, WorkspaceId,
};

/// Version of the storage-neutral event envelope.
pub const EVENT_ENVELOPE_VERSION: u16 = 1;

/// What the adapter observed. An assertion/resolution event does not authorize publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EventKind {
    /// A newly observed message.
    #[serde(rename = "message.created")]
    MessageCreated,
    /// An edit with an immutable predecessor.
    #[serde(rename = "message.edited")]
    MessageEdited,
    /// An observed message deletion, not physical payload erasure.
    #[serde(rename = "message.deleted")]
    MessageDeleted,
    /// An outgoing model request occurrence.
    #[serde(rename = "model.requested")]
    ModelRequested,
    /// A durable chunk of a visible model response.
    #[serde(rename = "model.response_chunk")]
    ModelResponseChunk,
    /// A completed response or terminal stream manifest.
    #[serde(rename = "model.response_completed")]
    ModelResponseCompleted,
    /// A cancelled or interrupted response.
    #[serde(rename = "model.response_aborted")]
    ModelResponseAborted,
    /// Tool dispatch intent.
    #[serde(rename = "tool.requested")]
    ToolRequested,
    /// Observed successful tool result.
    #[serde(rename = "tool.completed")]
    ToolCompleted,
    /// Observed failed tool result.
    #[serde(rename = "tool.failed")]
    ToolFailed,
    /// A tool was requested but its effect is not yet known.
    #[serde(rename = "tool.outcome_unknown")]
    ToolOutcomeUnknown,
    /// Observed artifact version.
    #[serde(rename = "artifact.observed")]
    ArtifactObserved,
    /// Observed artifact change.
    #[serde(rename = "artifact.changed")]
    ArtifactChanged,
    /// Observed artifact deletion.
    #[serde(rename = "artifact.deleted")]
    ArtifactDeleted,
    /// An attributed assertion occurrence.
    #[serde(rename = "assertion.recorded")]
    AssertionRecorded,
    /// Observation of a separately authorized resolution.
    #[serde(rename = "resolution.committed")]
    ResolutionCommitted,
    /// Run lifecycle start.
    #[serde(rename = "run.started")]
    RunStarted,
    /// Operational checkpoint, not hidden reasoning.
    #[serde(rename = "run.checkpointed")]
    RunCheckpointed,
    /// Operational resume.
    #[serde(rename = "run.resumed")]
    RunResumed,
    /// Run cancellation.
    #[serde(rename = "run.cancelled")]
    RunCancelled,
    /// Known missing observations.
    #[serde(rename = "capture.gap")]
    CaptureGap,
    /// Observation of a policy change; enforcement is a separate host operation.
    #[serde(rename = "policy.changed")]
    PolicyChanged,
    /// Observation of retention deletion.
    #[serde(rename = "retention.deleted")]
    RetentionDeleted,
}

/// Adapter-reported source role. The capture host authenticates the adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventRole {
    /// User input observed by the host.
    User,
    /// Visible assistant output.
    Assistant,
    /// Tool output.
    Tool,
    /// Host lifecycle event.
    Host,
    /// An external source observation.
    ExternalSource,
    /// An imported legacy observation.
    Import,
}

/// Why an original payload is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadOmission {
    /// The custody policy excludes these bytes.
    PolicyExcluded,
    /// The upstream adapter never exposed the bytes.
    NotExposedByUpstream,
    /// A legacy derived record has no original.
    LegacyMissing,
    /// Payload was explicitly erased under a retention policy.
    ExplicitlyDeleted,
    /// The observed source was deleted; prior captured versions remain historical.
    SourceDeleted,
}

/// Original bytes. Digest verification belongs to the capture/materialization boundary.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventPayload {
    /// Exact UTF-8, including whitespace and Unicode normalization form.
    InlineUtf8 {
        /// Original text.
        text: String,
        /// BLAKE3-256 of the original UTF-8 bytes.
        digest: ContentDigest,
    },
    /// Bounded non-text payload in the same atomic publication.
    InlineBytes {
        /// Original bytes.
        bytes: Vec<u8>,
        /// Declared content media type.
        media_type: String,
        /// BLAKE3-256 of the original bytes.
        digest: ContentDigest,
    },
    /// A complete durable original larger than the inline capture limit.
    Staged {
        /// Policy-bound original block.
        reference: crate::OriginalPayloadRef,
        /// Source media type.
        media_type: String,
    },
    /// Exact model-request occurrence represented by ordered source references.
    Assembly {
        /// Wire replay and provenance manifest.
        manifest: crate::ModelRequestManifest,
    },
    /// An explicit lack of original bytes, never an invented quotation.
    Omitted {
        /// Custody or upstream limitation.
        reason: PayloadOmission,
    },
}

impl std::fmt::Debug for EventPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Staged { reference, .. } => f.debug_tuple("Staged").field(reference).finish(),
            Self::Assembly { manifest } => f.debug_tuple("Assembly").field(manifest).finish(),
            Self::InlineUtf8 { text, digest } => f
                .debug_struct("InlineUtf8")
                .field("byte_length", &text.len())
                .field("digest", digest)
                .finish(),
            Self::InlineBytes { bytes, digest, .. } => f
                .debug_struct("InlineBytes")
                .field("byte_length", &bytes.len())
                .field("digest", digest)
                .finish(),
            Self::Omitted { reason } => f.debug_struct("Omitted").field("reason", reason).finish(),
        }
    }
}

impl EventPayload {
    /// Borrows the original bytes without normalizing or serializing the payload.
    #[must_use]
    pub fn original_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::InlineUtf8 { text, .. } => Some(text.as_bytes()),
            Self::InlineBytes { bytes, .. } => Some(bytes),
            Self::Omitted { .. } | Self::Staged { .. } | Self::Assembly { .. } => None,
        }
    }

    /// The supplied original digest, verified by the host before acknowledgement.
    #[must_use]
    pub const fn digest(&self) -> Option<ContentDigest> {
        match self {
            Self::Staged { reference, .. } => Some(reference.digest),
            Self::Assembly { manifest } => Some(manifest.wire_digest),
            Self::InlineUtf8 { digest, .. } | Self::InlineBytes { digest, .. } => Some(*digest),
            Self::Omitted { .. } => None,
        }
    }
}

/// Capture coverage of this occurrence, separate from interpretation/index coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCoverage {
    /// The adapter supplied the complete observation.
    CompleteObservation,
    /// The adapter supplied only part of an observation.
    PartialObservation,
    /// A known observation gap.
    Gap,
}

/// Ordered visible output chunks and their terminal manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseStream {
    /// A zero-based chunk index in one model response.
    Chunk {
        /// Stable model call identity.
        response_id: ModelCallId,
        /// Contiguous index, starting at zero.
        index: u32,
    },
    /// Terminal manifest; the event kind distinguishes completed and aborted.
    Finished {
        /// Stable model call identity.
        response_id: ModelCallId,
        /// Number of durably accepted chunks in this response.
        chunk_count: u32,
    },
}

/// Host-captured immutable event. Policy and authenticated actor are bound by the service.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    /// Event contract version.
    pub version: u16,
    /// Existing stable observation identity, also used by evidence references.
    pub event_id: ObservationId,
    /// Stable workspace identity.
    pub workspace_id: WorkspaceId,
    /// Nonempty authorized source scopes.
    pub scope_ids: BTreeSet<ScopeId>,
    /// Host producer stream identity.
    pub producer_id: StreamId,
    /// Positive producer sequence; arrival order need not be contiguous.
    pub producer_sequence: u64,
    /// Observed occurrence type.
    pub kind: EventKind,
    /// Time recorded by the capture host.
    pub recorded_at: TimestampMicros,
    /// Optional source-reported time; not a causal order.
    pub observed_at: Option<TimestampMicros>,
    /// Original source identity.
    pub source_id: SourceId,
    /// Optional external source revision.
    pub source_version: Option<String>,
    /// Authenticated host adapter name.
    pub adapter_id: String,
    /// Observed source role; does not grant semantic authority.
    pub role: EventRole,
    /// Optional conversation session.
    pub session_id: Option<SessionId>,
    /// Optional owned runtime identity.
    pub run_id: Option<AgentRunId>,
    /// Optional scoped task.
    pub task_id: Option<TaskId>,
    /// Immutable causal/source links, not timestamp-derived causality.
    pub parent_event_ids: BTreeSet<ObservationId>,
    /// Immutable predecessor for an edit or source deletion.
    pub supersedes_event_id: Option<ObservationId>,
    /// Original payload or explicit omission.
    pub payload: EventPayload,
    /// Capture completeness.
    pub coverage: EventCoverage,
    /// Whether the upstream already truncated the observation.
    pub upstream_truncated: bool,
    /// Required explanation for a gap.
    pub gap_reason: Option<String>,
    /// Optional durable response stream position/terminal manifest.
    pub response_stream: Option<ResponseStream>,
    /// Typed host attribution for tool and artifact adapters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::EventProvenance>,
}

impl Validate for EventEnvelope {
    fn validate(&self) -> ValidationResult {
        let invalid = |reason| ValidationError::InvalidState { reason };
        if self.version != EVENT_ENVELOPE_VERSION {
            return Err(invalid("unsupported event envelope version"));
        }
        if self.scope_ids.is_empty() || self.scope_ids.len() > 32 || self.producer_sequence == 0 {
            return Err(invalid(
                "event requires bounded scopes and a positive producer sequence",
            ));
        }
        if self.parent_event_ids.len() > 64
            || self.parent_event_ids.contains(&self.event_id)
            || self.supersedes_event_id == Some(self.event_id)
        {
            return Err(invalid("event lineage is invalid"));
        }
        if matches!(
            self.kind,
            EventKind::MessageEdited | EventKind::MessageDeleted
        ) && self.supersedes_event_id.is_none()
        {
            return Err(invalid("message edit or deletion requires its predecessor"));
        }
        for text in std::iter::once(&self.adapter_id)
            .chain(self.source_version.iter())
            .chain(self.gap_reason.iter())
        {
            if text.trim().is_empty() || text.len() > 2048 || text.contains('\0') {
                return Err(invalid("event metadata is invalid"));
            }
        }
        if let EventPayload::InlineBytes { media_type, .. }
        | EventPayload::Staged { media_type, .. } = &self.payload
            && (media_type.trim().is_empty() || media_type.len() > 256)
        {
            return Err(invalid("event media type is invalid"));
        }
        if (self.upstream_truncated || matches!(self.payload, EventPayload::Omitted { .. }))
            && self.coverage == EventCoverage::CompleteObservation
        {
            return Err(invalid(
                "omitted or truncated payload cannot claim complete capture",
            ));
        }
        if self.coverage == EventCoverage::Gap && self.gap_reason.is_none() {
            return Err(invalid("capture gap requires a reason"));
        }
        if self.kind == EventKind::CaptureGap && self.coverage != EventCoverage::Gap {
            return Err(invalid("capture gap kind requires gap coverage"));
        }
        match (&self.kind, &self.response_stream) {
            (EventKind::ModelResponseChunk, Some(ResponseStream::Chunk { .. })) => {}
            (EventKind::ModelResponseChunk, _) | (_, Some(ResponseStream::Chunk { .. })) => {
                return Err(invalid("chunk kind and stream position disagree"));
            }
            (EventKind::ModelResponseCompleted | EventKind::ModelResponseAborted, _) => {}
            (_, Some(ResponseStream::Finished { .. })) => {
                return Err(invalid("terminal stream manifest has a nonterminal kind"));
            }
            _ => {}
        }
        if self.kind == EventKind::ModelResponseAborted
            && self.coverage == EventCoverage::CompleteObservation
        {
            return Err(invalid("aborted response must report partial capture"));
        }
        if matches!(self.payload, EventPayload::Assembly { .. })
            && (self.kind != EventKind::ModelRequested
                || self.coverage != EventCoverage::CompleteObservation)
        {
            return Err(invalid(
                "assembly requires a complete model request occurrence",
            ));
        }
        match &self.provenance {
            Some(crate::EventProvenance::Tool {
                request_event_id,
                action_digest,
                ..
            }) => match self.kind {
                EventKind::ToolRequested
                    if *request_event_id == self.event_id
                        && self.payload.digest() == Some(*action_digest) => {}
                EventKind::ToolCompleted
                | EventKind::ToolFailed
                | EventKind::ToolOutcomeUnknown
                    if self.parent_event_ids.contains(request_event_id) => {}
                _ => return Err(invalid("tool provenance does not bind its dispatch intent")),
            },
            Some(crate::EventProvenance::Artifact {
                base_digest,
                new_digest,
                ..
            }) if !matches!(
                self.kind,
                EventKind::ArtifactObserved
                    | EventKind::ArtifactChanged
                    | EventKind::ArtifactDeleted
            ) || (self.kind != EventKind::ArtifactDeleted
                && *new_digest != self.payload.digest())
                || (self.kind == EventKind::ArtifactDeleted && new_digest.is_some())
                || (base_digest.is_some() && self.supersedes_event_id.is_none()) =>
            {
                return Err(invalid(
                    "artifact provenance differs from its source version",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}
