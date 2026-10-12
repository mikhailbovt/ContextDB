//! Bounded, source-addressed checkpoints for the owned conversational runtime.
//! Validation is pure; only a publication owner can prove source durability.

use std::collections::BTreeSet;

use contextdb_context::{BlockId, ModelProfile, OutgoingRole};
use contextdb_core::{
    AgentRunId, ContentDigest, ModelCallId, ObservationId, OriginalSourceSpan, ScopeId, SessionId,
    StreamId, TimestampMicros, ToolCallId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::{ContinuityError, Result, canonical_digest, validate_text};

/// Maximum visible original bytes in one tool-result page.
pub const TOOL_RESULT_PAGE_BYTES: u32 = 4096;
/// Reserved pure operation for a source-bound original page.
pub const ORIGINAL_PAGE_OPERATION: &str = "contextdb.original.page";

/// Immutable full-original locator. A handle is a selector, never authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalPageHandle {
    /// Native database that acknowledged the original.
    pub database_id: String,
    /// Complete captured event identity.
    pub event_id: ObservationId,
    /// Digest of the complete original, not of its displayed page.
    pub payload_digest: ContentDigest,
    /// Complete archived byte length.
    pub byte_length: u64,
}
impl OriginalPageHandle {
    /// Validate bounded locator metadata; the owner must validate its truth.
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.database_id, "original database", 256)?;
        if self.byte_length == 0 || self.byte_length > 64 * 1024 * 1024 {
            return Err(invalid("original page handle exceeds capture bounds"));
        }
        Ok(())
    }
}

/// Model-proposed page selector, without context, permissions or processing grants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalPageArguments {
    /// Complete original locator obtained from an owned tool result.
    pub handle: OriginalPageHandle,
    /// Byte cursor within that immutable original.
    pub start: u64,
    /// Maximum requested original bytes, at most the fixed page ceiling.
    pub max_bytes: u32,
}
impl OriginalPageArguments {
    /// Validate the fixed selector bounds without asserting source access.
    pub fn validate(&self) -> Result<()> {
        self.handle.validate()?;
        if self.max_bytes == 0
            || self.max_bytes > TOOL_RESULT_PAGE_BYTES
            || self.start >= self.handle.byte_length
        {
            return Err(invalid(
                "original page selector exceeds its declared bounds",
            ));
        }
        Ok(())
    }

    /// Parse bounded selector JSON, rejecting unknown authorization-like fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > TOOL_RESULT_PAGE_BYTES as usize {
            return Err(invalid("original page selector JSON exceeds its bound"));
        }
        let selector: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("original page selector JSON is invalid"))?;
        selector.validate()?;
        Ok(selector)
    }
}

/// An explicit partial display of a fully retained tool original.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultPageView {
    /// Selector for the complete immutable original.
    pub handle: OriginalPageHandle,
    /// Exact visible original range, with its independently verified page digest.
    pub preview: OriginalSourceSpan,
}
impl ToolResultPageView {
    /// Validate the original/page relationship without asserting source access.
    pub fn validate(&self) -> Result<()> {
        self.handle.validate()?;
        validate_span(&self.preview)?;
        if self.preview.event_id != self.handle.event_id
            || self.preview.payload_digest != self.handle.payload_digest
            || self.preview.end > self.handle.byte_length
            || self.preview.end - self.preview.start > u64::from(TOOL_RESULT_PAGE_BYTES)
            || (self.preview.start == 0
                && self.preview.end == self.handle.byte_length
                && self.preview.span_digest != self.handle.payload_digest)
        {
            return Err(invalid("tool page differs from its full original locator"));
        }
        Ok(())
    }
}

/// Exact host identity; input text cannot expand these scopes or change its owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedRunIdentity {
    /// Native workspace.
    pub workspace_id: WorkspaceId,
    /// Stable conversation session.
    pub session_id: SessionId,
    /// One owned run within the session.
    pub run_id: AgentRunId,
    /// Accountable host actor.
    pub actor_id: String,
    /// Executing agent.
    pub agent_id: String,
    /// Continuity-bearing memory subject.
    pub subject_id: String,
    /// At most 32 explicit branch/task scopes.
    pub scopes: BTreeSet<ScopeId>,
}

/// A message locator, never a summary or independently published assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedMessage {
    /// Stable block identity, retained across rolling and model changes.
    pub id: BlockId,
    /// Exact visible original. Rehydration checks current source permissions.
    pub source: OriginalSourceSpan,
    /// Observed protocol role; system/developer roles are excluded.
    pub role: OutgoingRole,
    /// Assistant call IDs awaiting their result messages.
    pub tool_calls: Vec<String>,
    /// Tool call ID completed by this result message.
    pub tool_result: Option<String>,
    /// Optional explicit original-page view; ordinary messages retain their shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_page: Option<ToolResultPageView>,
}

/// An indivisible captured user/assistant/tool exchange.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionGroup {
    /// Monotonically increasing run-local exchange number.
    pub sequence: u64,
    /// At most 32 captured messages in protocol order.
    pub messages: Vec<CapturedMessage>,
    /// Only complete groups can leave the hot window.
    pub complete: bool,
}

/// Terminal obligations release their source pins, but their originals remain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    /// Applies to the current run.
    Open,
    /// The host confirmed completion.
    Completed,
    /// The host cancelled this obligation.
    Cancelled,
}

/// Explicit task state backed by a source. It cannot authorize a semantic write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedObligation {
    /// Stable obligation identity.
    pub id: String,
    /// One active run scope.
    pub scope: ScopeId,
    /// Exact original requirement; no hidden reasoning transcript.
    pub source: OriginalSourceSpan,
    /// Current lifecycle. Terminal items are excluded from pinned context.
    pub status: ObligationStatus,
}

/// Durable model intent. After a crash the outcome is unknown until reconciled;
/// the presence of this record never authorizes an automatic duplicate request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingModelCall {
    /// Stable provider attempt identity.
    pub call_id: ModelCallId,
    /// Reserved exact outgoing request occurrence. It must be durable before send.
    pub request_event: ObservationId,
    /// Exact wire binding once known; absence means preparation was still pending.
    pub wire_digest: Option<ContentDigest>,
    /// Captured interrupted output prevents claiming this attempt was never accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interrupted_output: Option<ObservationId>,
}

/// Sequential external action with stable intent and outcome capture positions.
/// Unknown outcomes reserve a new result slot only after reconciliation is needed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingToolInvocation {
    /// Immutable model proposal; it grants no execution authority.
    pub proposal: OriginalSourceSpan,
    /// Stable target invocation identity.
    pub call_id: ToolCallId,
    /// Digest of the exact canonical ToolAction.
    pub action_digest: ContentDigest,
    /// Reserved intent occurrence.
    pub request_event: ObservationId,
    /// Reserved producer position, retained on reconciliation.
    pub request_sequence: u64,
    /// Fixed host intent time for idempotent capture.
    pub request_recorded_at: TimestampMicros,
    /// Current immutable result slot; an unknown result is never overwritten.
    pub outcome_event: ObservationId,
    /// Current result's producer position.
    pub outcome_sequence: u64,
    /// Fixed host slot time, retained on uncertain acknowledgement.
    pub outcome_recorded_at: TimestampMicros,
}

/// Terminal runs cannot dispatch more model or tool work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedRunStatus {
    /// Accept input and continue at safe protocol boundaries.
    Active,
    /// Explicitly completed by the host.
    Completed,
    /// Explicitly cancelled by the host.
    Cancelled,
}

/// Operational checkpoint for the new runtime. The existing portable checkpoint
/// API continues to serve profile-based migrations; neither stores hidden thought.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedRunCheckpoint {
    /// Exact representation version.
    pub version: u16,
    /// Stable run identity and scope.
    pub identity: OwnedRunIdentity,
    /// Compare-and-publish run revision, starting at one.
    pub revision: u64,
    /// Capture producer shared by this run's events.
    pub producer_id: StreamId,
    /// Next producer position after this checkpoint event has been accepted.
    pub next_sequence: u64,
    /// Host observation time of this operational state.
    pub recorded_at: TimestampMicros,
    /// Declared current reader contract; changing it requires a fresh assembly.
    pub model_profile: ModelProfile,
    /// Bounded hot groups only. Evicted originals remain in the capture archive.
    pub groups: Vec<InteractionGroup>,
    /// At most 32 active plus 32 recent terminal obligations.
    pub obligations: Vec<ScopedObligation>,
    /// Unreconciled model attempt, if any.
    pub pending_model: Option<PendingModelCall>,
    /// At most one executing/reconciling tool; remaining calls stay in their group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_tool: Option<PendingToolInvocation>,
    /// Last complete model output, including a valid empty response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_model_output: Option<ObservationId>,
    /// Run lifecycle, independent of semantic assertion authority.
    pub status: OwnedRunStatus,
}

impl OwnedRunCheckpoint {
    /// Validate bounds, identity, immutable source addresses and protocol grouping.
    /// Source existence/ACL/receipts require publication-owner validation as well.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.revision == 0
            || self.next_sequence < 2
            || self.identity.scopes.is_empty()
            || self.identity.scopes.len() > 32
            || self.groups.len() > 64
            || self.obligations.len() > 64
            || self
                .obligations
                .iter()
                .filter(|item| item.status == ObligationStatus::Open)
                .count()
                > 32
        {
            return Err(invalid("checkpoint exceeds the supported bounded profile"));
        }
        for (name, value) in [
            ("actor", &self.identity.actor_id),
            ("agent", &self.identity.agent_id),
            ("subject", &self.identity.subject_id),
        ] {
            validate_text(value, name, 2048)?;
        }
        self.model_profile
            .validate()
            .map_err(|error| ContinuityError::InvalidInput(error.to_string()))?;
        let mut previous = 0;
        let mut messages = BTreeSet::new();
        let mut calls = BTreeSet::new();
        let mut source_bytes = 0_u64;
        for (index, group) in self.groups.iter().enumerate() {
            if group.sequence <= previous
                || group.messages.is_empty()
                || group.messages.len() > 32
                || (!group.complete && index + 1 != self.groups.len())
            {
                return Err(invalid(
                    "checkpoint interaction groups are incomplete or unordered",
                ));
            }
            previous = group.sequence;
            let mut outstanding = BTreeSet::new();
            for message in &group.messages {
                validate_span(&message.source)?;
                if let Some(page) = &message.tool_page {
                    page.validate()?;
                    if message.role != OutgoingRole::Tool
                        || message.tool_result.is_none()
                        || (message.source.event_id == page.preview.event_id
                            && message.source != page.preview)
                    {
                        return Err(invalid(
                            "original page lacks its authentic tool protocol anchor",
                        ));
                    }
                    if message.source != page.preview {
                        source_bytes =
                            source_bytes.saturating_add(page.preview.end - page.preview.start);
                    }
                }
                source_bytes =
                    source_bytes.saturating_add(message.source.end - message.source.start);
                if !messages.insert(&message.id)
                    || messages.len() > 256
                    || source_bytes > 8 * 1024 * 1024
                    || matches!(message.role, OutgoingRole::System | OutgoingRole::Developer)
                    || message.tool_calls.len() > 32
                    || (message.role == OutgoingRole::Tool) != message.tool_result.is_some()
                    || (!message.tool_calls.is_empty() && message.role != OutgoingRole::Assistant)
                {
                    return Err(invalid(
                        "checkpoint message role, identity or size is invalid",
                    ));
                }
                if let Some(result) = &message.tool_result {
                    if !outstanding.remove(result) {
                        return Err(invalid("orphan tool result"));
                    }
                } else if !outstanding.is_empty() {
                    return Err(invalid("tool result group is interrupted"));
                }
                for call in &message.tool_calls {
                    validate_text(call, "tool call", 256)?;
                    if !calls.insert(call) {
                        return Err(invalid("duplicate tool call identity"));
                    }
                    outstanding.insert(call);
                }
            }
            if group.complete && !outstanding.is_empty() {
                return Err(invalid("completed group still contains pending tool calls"));
            }
        }
        let mut obligations = BTreeSet::new();
        for item in &self.obligations {
            validate_text(&item.id, "obligation", 256)?;
            validate_span(&item.source)?;
            if !self.identity.scopes.contains(&item.scope) || !obligations.insert(&item.id) {
                return Err(invalid(
                    "obligation changes its scope or repeats an identity",
                ));
            }
            if item.status == ObligationStatus::Open {
                source_bytes = source_bytes.saturating_add(item.source.end - item.source.start);
                if source_bytes > 8 * 1024 * 1024 {
                    return Err(invalid("active checkpoint sources exceed 8 MiB"));
                }
            }
        }
        if self.status != OwnedRunStatus::Active
            && (self.pending_model.is_some()
                || self.pending_tool.is_some()
                || self
                    .obligations
                    .iter()
                    .any(|item| item.status == ObligationStatus::Open))
        {
            return Err(invalid("terminal run retains pending work"));
        }
        if let Some(tool) = &self.pending_tool {
            validate_span(&tool.proposal)?;
            crate::ensure_digest_nonzero(tool.action_digest, "tool action")?;
            if self.pending_model.is_some()
                || tool.request_sequence == 0
                || tool.request_sequence > self.next_sequence
                || tool.outcome_sequence <= tool.request_sequence
                || tool.outcome_sequence < self.next_sequence
                || !self.groups.last().is_some_and(|group| {
                    !group.complete
                        && group.messages.iter().any(|message| {
                            message.source == tool.proposal
                                && message.tool_calls.contains(&tool.call_id.to_string())
                        })
                })
            {
                return Err(invalid(
                    "pending tool differs from the current captured protocol",
                ));
            }
        }
        if let Some(digest) = self
            .pending_model
            .as_ref()
            .and_then(|call| call.wire_digest)
        {
            crate::ensure_digest_nonzero(digest, "model request wire")?;
        }
        if self
            .pending_model
            .as_ref()
            .is_some_and(|call| call.interrupted_output.is_some() && call.wire_digest.is_none())
        {
            return Err(invalid("interrupted output requires a captured request"));
        }
        Ok(())
    }

    /// Immutable source addresses that require fresh authorization before use.
    pub fn required_sources(&self) -> impl Iterator<Item = &OriginalSourceSpan> {
        self.groups
            .iter()
            .flat_map(|group| &group.messages)
            .flat_map(|message| {
                std::iter::once(&message.source).chain(
                    message
                        .tool_page
                        .as_ref()
                        .filter(|page| page.preview != message.source)
                        .map(|page| &page.preview),
                )
            })
            .chain(
                self.obligations
                    .iter()
                    .filter(|item| item.status == ObligationStatus::Open)
                    .map(|item| &item.source),
            )
    }

    /// Deterministic binding of operational state, excluding no hidden fields.
    pub fn digest(&self) -> Result<ContentDigest> {
        self.validate()?;
        canonical_digest(self)
    }

    /// Close an obligation without changing its source. A terminal item cannot
    /// silently become active again; renewed work needs an explicit new identity.
    pub fn close_obligation(&mut self, id: &str, status: ObligationStatus) -> Result<()> {
        if status == ObligationStatus::Open {
            return Err(invalid("terminal status required"));
        }
        let obligation = self
            .obligations
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| invalid("unknown obligation"))?;
        if obligation.status != ObligationStatus::Open && obligation.status != status {
            return Err(invalid("obligation terminal state cannot be rewritten"));
        }
        obligation.status = status;
        Ok(())
    }
}

fn validate_span(span: &OriginalSourceSpan) -> Result<()> {
    if span
        .end
        .checked_sub(span.start)
        .is_none_or(|size| size == 0 || size > 1024 * 1024)
    {
        return Err(invalid(
            "checkpoint source must be a nonempty bounded original span",
        ));
    }
    crate::ensure_digest_nonzero(span.payload_digest, "source version")?;
    crate::ensure_digest_nonzero(span.span_digest, "source range")
}
fn invalid(message: &str) -> ContinuityError {
    ContinuityError::InvalidInput(message.into())
}
