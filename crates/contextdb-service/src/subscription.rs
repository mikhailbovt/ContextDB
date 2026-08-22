use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::AuthenticatedRequestContext;

/// Stable subscription event families defined by the v1 protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryEventKind {
    /// A stable node revision changed.
    NodeChanged,
    /// A claim revision changed.
    ClaimChanged,
    /// An open-loop trigger changed state.
    OpenLoopTriggered,
    /// An index watermark advanced.
    IndexWatermarkAdvanced,
    /// A conflict set was resolved or revised.
    ConflictResolved,
    /// A source revision was invalidated or replaced.
    SourceInvalidated,
    /// A long-running operation advanced.
    OperationProgress,
    /// A security-relevant lifecycle event occurred.
    SecurityEvent,
    /// An immutable observation was accepted.
    ObservationAccepted,
    /// Another authorized semantic record changed.
    RecordChanged,
}

/// Filtered subscription request. Empty filters mean every event family the
/// implementation can produce for the authorized principal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribeRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Requested event families.
    pub filters: BTreeSet<MemoryEventKind>,
    /// Opaque authenticated resume cursor.
    pub resume_cursor: Option<String>,
    /// Strict maximum events in this delivery page.
    pub max_events: u32,
}

/// Content-free at-least-once memory event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryEvent {
    /// Stable event identity used by clients for deduplication.
    pub event_id: String,
    /// Source journal commit sequence.
    pub commit_seq: u64,
    /// Stable ordinal within one journal record.
    pub ordinal: u32,
    /// Event family.
    pub kind: MemoryEventKind,
    /// Authorized object references only.
    pub object_refs: Vec<String>,
    /// Content-free event attributes.
    pub attributes: std::collections::BTreeMap<String, String>,
}

/// Finite reference delivery page. Streaming transports emit its events in
/// order and reconnect with the returned cursor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionPage {
    /// Ordered at-least-once event delivery.
    pub events: Vec<MemoryEvent>,
    /// Authenticated cursor after the last delivered event.
    pub resume_cursor: String,
    /// True when the page reached the captured journal head.
    pub caught_up: bool,
}
