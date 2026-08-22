//! Durable user-control requests.

use std::fmt;

use contextdb_core::{ContentDigest, MemoryControlDirective, SessionId, TimestampMicros};
use serde::{Deserialize, Serialize};

use crate::{ChatIdempotencyKey, ControlJobId, ConversationPrincipal};

/// Durable lifecycle of a user memory-control request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlJobStatus {
    /// Destructive/broadening operation needs an explicit second action.
    AwaitingConfirmation,
    /// Confirmed and waiting for the host policy/mutation executor.
    PendingExecution,
    /// Host supplied an immutable success receipt digest.
    Applied,
    /// Host rejected the request under current policy.
    Rejected,
}

/// Request to enqueue an explicit core memory-control directive.
#[derive(Clone)]
pub struct EnqueueControlRequest {
    /// Session whose authorization and scope boundary applies.
    pub session_id: SessionId,
    /// Authenticated user principal.
    pub principal: ConversationPrincipal,
    /// Lost-response-safe key.
    pub idempotency_key: ChatIdempotencyKey,
    /// Typed control; natural-language classification happens before this API.
    pub directive: MemoryControlDirective,
    /// Wall-clock event time.
    pub requested_at: TimestampMicros,
}

impl fmt::Debug for EnqueueControlRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnqueueControlRequest")
            .field("session_id", &self.session_id)
            .field("principal", &self.principal)
            .field("idempotency_key", &self.idempotency_key)
            .field("directive_kind", &directive_kind(&self.directive))
            .field("requested_at", &self.requested_at)
            .finish()
    }
}

/// Payload-free control job view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlJobSummary {
    /// Stable job identity.
    pub id: ControlJobId,
    /// Owning session.
    pub session_id: SessionId,
    /// Directive category without replacement/audience payload.
    pub directive_kind: &'static str,
    /// Durable lifecycle state.
    pub status: ControlJobStatus,
    /// Host execution receipt digest after completion.
    pub executor_receipt_digest: Option<ContentDigest>,
    /// True for an idempotent repeat.
    pub replayed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredControlJob {
    pub id: ControlJobId,
    pub session_id: SessionId,
    pub request_digest: [u8; 32],
    pub directive: MemoryControlDirective,
    pub requested_at: TimestampMicros,
    pub status: ControlJobStatus,
    pub executor_receipt_digest: Option<ContentDigest>,
}

pub(crate) const fn requires_confirmation(directive: &MemoryControlDirective) -> bool {
    matches!(
        directive,
        MemoryControlDirective::Correct { .. }
            | MemoryControlDirective::Retract { .. }
            | MemoryControlDirective::Forget { .. }
            | MemoryControlDirective::MakePrivate { .. }
            | MemoryControlDirective::Share { .. }
    )
}

pub(crate) const fn directive_kind(directive: &MemoryControlDirective) -> &'static str {
    match directive {
        MemoryControlDirective::Remember { .. } => "remember",
        MemoryControlDirective::Correct { .. } => "correct",
        MemoryControlDirective::Retract { .. } => "retract",
        MemoryControlDirective::Forget { .. } => "forget",
        MemoryControlDirective::Pin { .. } => "pin",
        MemoryControlDirective::MakePrivate { .. } => "make_private",
        MemoryControlDirective::Share { .. } => "share",
        MemoryControlDirective::DoNotMention { .. } => "do_not_mention",
        MemoryControlDirective::TreatAsHypothetical { .. } => "treat_as_hypothetical",
    }
}

pub(crate) fn summary(job: &StoredControlJob, replayed: bool) -> ControlJobSummary {
    ControlJobSummary {
        id: job.id.clone(),
        session_id: job.session_id,
        directive_kind: directive_kind(&job.directive),
        status: job.status,
        executor_receipt_digest: job.executor_receipt_digest,
        replayed,
    }
}
