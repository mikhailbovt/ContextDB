//! Original-source addressing; these objects confer no semantic authority.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ContentDigest, EventCoverage, EventEnvelope, EventKind, EventPayload, EventRole, ObservationId,
    PayloadOmission, SessionId, SourceId, TimeRange, TimestampMicros,
};

/// Source selection, intersected with current authorization by the host.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawFilter {
    /// Empty selects all identities admitted by the other filters.
    pub event_ids: BTreeSet<ObservationId>,
    /// Stable upstream source, across all captured versions.
    pub source_id: Option<SourceId>,
    /// Conversation session.
    pub session_id: Option<SessionId>,
    /// Half-open host-recorded time range, not semantic valid time.
    pub recorded_range: Option<TimeRange>,
    /// Include model-request occurrences for audit; they remain dependent echoes.
    pub include_request_occurrences: bool,
}

impl RawFilter {
    /// Applies metadata predicates after the host has authorized the source.
    #[must_use]
    pub fn matches(&self, source: &RawSource) -> bool {
        (self.event_ids.is_empty() || self.event_ids.contains(&source.event_id))
            && self.source_id.is_none_or(|id| id == source.source_id)
            && self
                .session_id
                .is_none_or(|id| Some(id) == source.session_id)
            && self
                .recorded_range
                .is_none_or(|range| range.contains(source.recorded_at))
            && (self.include_request_occurrences || source.independent_source)
    }
}

/// Lexical matching against original UTF-8, without semantic extraction.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "text",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RawTextQuery {
    /// All Unicode alphanumeric/underscore tokens, case-insensitive.
    AllTerms(String),
    /// Exact case-sensitive UTF-8 substring; punctuation and whitespace matter.
    ExactPhrase(String),
}

impl std::fmt::Debug for RawTextQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (mode, text) = match self {
            Self::AllTerms(text) => ("AllTerms", text),
            Self::ExactPhrase(text) => ("ExactPhrase", text),
        };
        f.debug_struct(mode)
            .field("byte_length", &text.len())
            .finish()
    }
}

/// Non-text source attribution returned separately from materialized bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSource {
    /// Immutable observed event.
    pub event_id: ObservationId,
    /// Upstream source identity.
    pub source_id: SourceId,
    /// Upstream version, if supplied by the adapter.
    pub source_version: Option<String>,
    /// Original conversation session.
    pub session_id: Option<SessionId>,
    /// Observed occurrence kind.
    pub kind: EventKind,
    /// Host-attributed role; this is not a resolution grant.
    pub role: EventRole,
    /// Host-recorded timestamp.
    pub recorded_at: TimestampMicros,
    /// Immutable predecessor; historical originals are not hidden by corrections.
    pub supersedes_event_id: Option<ObservationId>,
    /// Exact original version, absent for explicit omissions.
    pub payload_digest: Option<ContentDigest>,
    /// Available original length, absent for explicit omissions.
    pub byte_length: Option<u64>,
    /// Why the original is unavailable, if applicable.
    pub omission: Option<PayloadOmission>,
    /// Completeness of the observed source, not of semantic interpretation.
    pub coverage: EventCoverage,
    /// Whether upstream omitted bytes before capture.
    pub upstream_truncated: bool,
    /// False for model-request occurrences, including opaque legacy requests.
    pub independent_source: bool,
}

impl From<&EventEnvelope> for RawSource {
    fn from(event: &EventEnvelope) -> Self {
        let (byte_length, omission) = match &event.payload {
            EventPayload::InlineUtf8 { text, .. } => (Some(text.len() as u64), None),
            EventPayload::InlineBytes { bytes, .. } => (Some(bytes.len() as u64), None),
            EventPayload::Staged { reference, .. } => (Some(reference.byte_length), None),
            EventPayload::Assembly { manifest } => (Some(manifest.byte_length), None),
            EventPayload::Omitted { reason } => (None, Some(*reason)),
        };
        Self {
            event_id: event.event_id,
            source_id: event.source_id,
            source_version: event.source_version.clone(),
            session_id: event.session_id,
            kind: event.kind,
            role: event.role,
            recorded_at: event.recorded_at,
            supersedes_event_id: event.supersedes_event_id,
            payload_digest: event.payload.digest(),
            byte_length,
            omission,
            coverage: event.coverage,
            upstream_truncated: event.upstream_truncated,
            independent_source: event.kind != EventKind::ModelRequested
                && !matches!(event.payload, EventPayload::Assembly { .. }),
        }
    }
}
