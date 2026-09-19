//! Bounded, source-addressed checkpoints for the owned conversational runtime.
//! Validation is pure; only a publication owner can prove source durability.

use std::collections::BTreeSet;

use contextdb_context::{BlockId, ModelProfile, OutgoingRole};
use contextdb_core::{
    AgentRunId, ContentDigest, ModelCallId, ObservationId, OriginalSourceSpan, ScopeId, SessionId,
    StreamId, TimestampMicros, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::{ContinuityError, Result, canonical_digest, validate_text};

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
                || self
                    .obligations
                    .iter()
                    .any(|item| item.status == ObligationStatus::Open))
        {
            return Err(invalid("terminal run retains pending work"));
        }
        if let Some(digest) = self
            .pending_model
            .as_ref()
            .and_then(|call| call.wire_digest)
        {
            crate::ensure_digest_nonzero(digest, "model request wire")?;
        }
        Ok(())
    }

    /// Immutable source addresses that require fresh authorization before use.
    pub fn required_sources(&self) -> impl Iterator<Item = &OriginalSourceSpan> {
        self.groups
            .iter()
            .flat_map(|group| &group.messages)
            .map(|message| &message.source)
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
