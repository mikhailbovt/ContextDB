//! Durable dispatch intent and conservative external outcome recovery.

use contextdb_core::{
    ContentDigest, EventCoverage, EventKind, EventPayload, EventProvenance, EventRole,
    ObservationId, PayloadOmission, ToolCallId,
};
use contextdb_service::{
    AuthenticatedRequestContext, CaptureReceipt, CaptureRequest, ErrorCode, PayloadPort,
    ReadOriginalRequest, ServiceError, ServiceResult,
};
use serde::{Deserialize, Serialize};

use crate::{CaptureHost, digest, invalid};

/// Exact owned tool protocol input. Preconditions are part of the action digest.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAction {
    /// Registered operation name; not a permission grant.
    pub operation: String,
    /// Exact input bytes handed to the external adapter.
    pub input: Vec<u8>,
    /// Target version/etag to compare atomically when supported.
    pub expected_target_version: Option<String>,
}

impl std::fmt::Debug for ToolAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolAction")
            .field("operation", &self.operation)
            .field("input_bytes", &self.input.len())
            .finish_non_exhaustive()
    }
}

/// External result known to the adapter, independent of local receipt durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolOutcome {
    /// The target confirmed completion.
    Completed,
    /// The target confirmed failure.
    Failed,
    /// Effect/result remains unknown and requires reconciliation.
    Unknown,
}

/// Complete available output; absent bytes are never fabricated.
#[derive(Clone)]
pub struct ToolObservation {
    /// Known external outcome.
    pub outcome: ToolOutcome,
    /// Full output exposed by the upstream adapter.
    pub bytes: Option<Vec<u8>>,
    /// Output media type.
    pub media_type: String,
    /// Whether upstream already discarded part of the result.
    pub upstream_truncated: bool,
}

impl std::fmt::Debug for ToolObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolObservation")
            .field("outcome", &self.outcome)
            .field("byte_length", &self.bytes.as_ref().map(Vec::len))
            .field("upstream_truncated", &self.upstream_truncated)
            .finish_non_exhaustive()
    }
}

/// Recovery protection actually enforced by the external target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolReplaySafety {
    /// Stable call IDs are durably deduplicated by the target.
    TargetIdempotency,
    /// The target atomically rejects a mismatched version/etag.
    VersionCompareAndSwap,
    /// An uncertain dispatch cannot be repeated automatically.
    NoAutomaticReplay,
}

/// An authoritative, action-bound target reconciliation result.
#[derive(Clone, Debug)]
pub enum ToolReconciliation {
    /// Known result for these exact action bytes.
    Observed {
        /// Digest reported by the target for the reconciled action.
        action_digest: ContentDigest,
        /// Complete result exposed by the target.
        observation: ToolObservation,
    },
    /// Target confirmed no effect, including its current version when available.
    NotApplied {
        /// Current target version needed for conditional retry.
        current_target_version: Option<String>,
    },
    /// Target cannot establish what happened.
    Unknown,
}

/// Host-owned execution capability. Implementations enforce their own allowed
/// operations, target authorization and advertised idempotency/CAS guarantees.
/// Receiving a ContextDB observation or recalled string does not grant this port.
pub trait ExternalTool: Send + Sync {
    /// Target guarantee verified by the host, never inferred from model output.
    fn replay_safety(&self) -> ToolReplaySafety;
    /// Execute with target-side idempotency or atomic preconditions as advertised.
    /// Return exposed partial bytes in an observation; an error means unknown
    /// effect with no available output and does not authorize blind repetition.
    fn execute(
        &self,
        context: &AuthenticatedRequestContext,
        call_id: ToolCallId,
        action: &ToolAction,
    ) -> ServiceResult<ToolObservation>;
    /// Check the target before considering repetition of an accepted intent.
    fn reconcile(
        &self,
        context: &AuthenticatedRequestContext,
        call_id: ToolCallId,
        action_digest: ContentDigest,
    ) -> ServiceResult<ToolReconciliation>;
}

/// Stable slot for one immutable observed outcome. A later resolution of an
/// unknown outcome uses a fresh slot while retaining the same call and intent.
#[derive(Clone, Debug)]
pub struct ToolOutcomeSlot {
    /// Stable capture identity retained across retries of this observation.
    pub event_id: ObservationId,
    /// Producer position allocated by the owned host.
    pub producer_sequence: u64,
    /// Host observation time, retained across retries.
    pub recorded_at: contextdb_core::TimestampMicros,
    /// Capture retry key for this outcome slot.
    pub idempotency_key: String,
}

/// Durable local view of one action/outcome pair.
#[derive(Clone, Debug)]
pub struct CapturedToolOutcome {
    /// Original dispatch-intent receipt.
    pub requested: CaptureReceipt,
    /// Observed outcome receipt, absent while an earlier dispatcher is unresolved.
    pub observed: Option<CaptureReceipt>,
    /// Explicit external effect state.
    pub outcome: ToolOutcome,
}

/// An observed result retained for capture retry without re-executing the tool.
#[derive(Clone, Debug)]
pub struct PendingToolCapture {
    /// Exact outcome event and retry identity.
    pub request: CaptureRequest,
    /// Full available output that must not be discarded before acknowledgement.
    pub observation: ToolObservation,
    /// Durable dispatch-intent receipt.
    pub requested: CaptureReceipt,
}

/// Capture failure, optionally carrying the complete still-unacknowledged output.
#[derive(Debug)]
pub struct ToolCaptureError {
    /// Sanitized native/host failure.
    pub error: ServiceError,
    /// Retry this capture directly; do not repeat the external action.
    pub pending: Option<Box<PendingToolCapture>>,
}

impl From<ServiceError> for ToolCaptureError {
    fn from(error: ServiceError) -> Self {
        Self {
            error,
            pending: None,
        }
    }
}

impl std::fmt::Display for ToolCaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tool capture failed ({:?})", self.error.code)
    }
}
impl std::error::Error for ToolCaptureError {}

impl<S: PayloadPort + ?Sized> CaptureHost<S> {
    /// Persist intent before dispatch; reconcile accepted intents after restart.
    /// A failed output capture pauses the host without repeating an external effect.
    pub fn run_tool<T: ExternalTool>(
        &self,
        mut request: CaptureRequest,
        call_id: ToolCallId,
        action: &ToolAction,
        slot: ToolOutcomeSlot,
        target: &T,
    ) -> Result<CapturedToolOutcome, ToolCaptureError> {
        request.context.validate_authentication()?;
        if ![
            contextdb_service::Capability::Observe,
            contextdb_service::Capability::ReadEvidence,
            contextdb_service::Capability::RawEvidence,
        ]
        .iter()
        .all(|capability| request.context.capability_grants.contains(capability))
        {
            return Err(ServiceError::new(
                ErrorCode::PermissionDenied,
                "tool capture requires observation and raw recovery grants",
                false,
            )
            .into());
        }
        if action.operation.trim().is_empty() || action.operation.len() > 256 {
            return Err(invalid("tool operation is invalid").into());
        }
        let action_bytes =
            serde_json::to_vec(action).map_err(|_| invalid("tool action cannot be encoded"))?;
        let action_digest = digest(&action_bytes);
        let provenance = EventProvenance::Tool {
            call_id,
            request_event_id: request.event.event_id,
            action_digest,
        };
        request.event.kind = EventKind::ToolRequested;
        request.event.role = EventRole::Host;
        request.event.provenance = Some(provenance.clone());
        let accepted =
            self.capture_bytes(request.clone(), action_bytes, "application/json".into())?;
        match self.owner.read_original(ReadOriginalRequest {
            context: request.context.clone(),
            event_id: slot.event_id,
            after_receipt: None,
        }) {
            Ok(existing) => {
                if existing.event.provenance != Some(provenance.clone()) {
                    return Err(invalid("outcome slot belongs to another action").into());
                }
                return Ok(CapturedToolOutcome {
                    requested: accepted.receipt,
                    observed: Some(existing.receipt),
                    outcome: outcome_from_kind(existing.event.kind)?,
                });
            }
            Err(error) if error.code == ErrorCode::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let observation = if accepted.newly_accepted {
            target
                .execute(&request.context, call_id, action)
                .unwrap_or_else(|_| unknown())
        } else {
            match target
                .reconcile(&request.context, call_id, action_digest)
                .unwrap_or(ToolReconciliation::Unknown)
            {
                ToolReconciliation::Observed {
                    action_digest: observed_digest,
                    observation,
                } => {
                    if observed_digest != action_digest {
                        return Err(invalid(
                            "reconciled outcome belongs to different action bytes",
                        )
                        .into());
                    }
                    observation
                }
                ToolReconciliation::NotApplied {
                    current_target_version,
                } => {
                    let safe = target.replay_safety() == ToolReplaySafety::TargetIdempotency
                        || (target.replay_safety() == ToolReplaySafety::VersionCompareAndSwap
                            && action.expected_target_version.is_some()
                            && action.expected_target_version == current_target_version);
                    if safe {
                        target
                            .execute(&request.context, call_id, action)
                            .unwrap_or_else(|_| unknown())
                    } else {
                        unknown()
                    }
                }
                ToolReconciliation::Unknown => unknown(),
            }
        };
        if !accepted.newly_accepted
            && observation.outcome == ToolOutcome::Unknown
            && observation.bytes.is_none()
        {
            // An unresolved duplicate must not take the first dispatcher's
            // outcome slot while that dispatcher may still be running.
            return Ok(CapturedToolOutcome {
                requested: accepted.receipt,
                observed: None,
                outcome: ToolOutcome::Unknown,
            });
        }
        let outcome = observation.outcome;
        let mut response = request;
        response.idempotency_key = slot.idempotency_key;
        response
            .event
            .parent_event_ids
            .insert(response.event.event_id);
        response.event.event_id = slot.event_id;
        response.event.producer_sequence = slot.producer_sequence;
        response.event.recorded_at = slot.recorded_at;
        response.event.kind = match outcome {
            ToolOutcome::Completed => EventKind::ToolCompleted,
            ToolOutcome::Failed => EventKind::ToolFailed,
            ToolOutcome::Unknown => EventKind::ToolOutcomeUnknown,
        };
        response.event.role = EventRole::Tool;
        response.event.upstream_truncated = observation.upstream_truncated;
        if observation.upstream_truncated
            || outcome == ToolOutcome::Unknown
            || observation.bytes.is_none()
        {
            response.event.coverage = EventCoverage::PartialObservation;
        }
        self.retry_tool_capture(PendingToolCapture {
            request: response,
            observation,
            requested: accepted.receipt,
        })
    }

    /// Retry only persistence of a retained result; this never calls the target.
    pub fn retry_tool_capture(
        &self,
        pending: PendingToolCapture,
    ) -> Result<CapturedToolOutcome, ToolCaptureError> {
        let result = match &pending.observation.bytes {
            Some(bytes) => self
                .capture_bytes(
                    pending.request.clone(),
                    bytes.clone(),
                    pending.observation.media_type.clone(),
                )
                .map(|value| value.receipt),
            None => {
                let mut request = pending.request.clone();
                request.event.payload = EventPayload::Omitted {
                    reason: PayloadOmission::NotExposedByUpstream,
                };
                self.owner.append_event(request)
            }
        };
        match result {
            Ok(observed) => Ok(CapturedToolOutcome {
                requested: pending.requested,
                observed: Some(observed),
                outcome: pending.observation.outcome,
            }),
            Err(error) => Err(ToolCaptureError {
                error,
                pending: Some(Box::new(pending)),
            }),
        }
    }
}

fn unknown() -> ToolObservation {
    ToolObservation {
        outcome: ToolOutcome::Unknown,
        bytes: None,
        media_type: "application/octet-stream".into(),
        upstream_truncated: false,
    }
}
fn outcome_from_kind(kind: EventKind) -> ServiceResult<ToolOutcome> {
    match kind {
        EventKind::ToolCompleted => Ok(ToolOutcome::Completed),
        EventKind::ToolFailed => Ok(ToolOutcome::Failed),
        EventKind::ToolOutcomeUnknown => Ok(ToolOutcome::Unknown),
        _ => Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "stored event is not a tool outcome",
            false,
        )),
    }
}
