//! Sequential captured tool protocol. External guarantees belong to the target.

use std::sync::Mutex;

use contextdb_capture::{
    CapturedToolOutcome, ExternalTool, ToolAction, ToolObservation, ToolOutcome, ToolOutcomeSlot,
    ToolReconciliation, ToolReplaySafety,
};

use super::*;
use crate::{RequestedTool, ToolDispatchFence};

/// One source-bound proposed action, without permission to execute it.
#[derive(Clone, Debug)]
pub struct QueuedTool {
    /// Exact observed tool operation and arguments.
    pub requested: RequestedTool,
    /// Captured protocol response containing this proposal.
    pub proposal: OriginalSourceSpan,
}

impl<S: OwnedRunPort + PrepareContextPort + PayloadPort + ?Sized> OwnedAgentRuntime<S> {
    pub(super) fn has_outstanding_tools(&self) -> bool {
        let Some(group) = self.state.groups.last() else {
            return false;
        };
        let completed = group
            .messages
            .iter()
            .filter_map(|item| item.tool_result.as_deref())
            .collect::<BTreeSet<_>>();
        group
            .messages
            .iter()
            .flat_map(|item| &item.tool_calls)
            .any(|call| !completed.contains(call.as_str()))
    }

    /// Inspect the next source-authorized call in protocol order. The registry
    /// must resolve its operation to a host-owned target before execution.
    pub fn next_tool(&self, budget: &mut QueryBudget) -> ServiceResult<Option<QueuedTool>> {
        let Some(group) = self.state.groups.last() else {
            return Ok(None);
        };
        let completed = group
            .messages
            .iter()
            .filter_map(|item| item.tool_result.as_deref())
            .collect::<BTreeSet<_>>();
        for message in &group.messages {
            let Some(id) = message
                .tool_calls
                .iter()
                .find(|call| !completed.contains(call.as_str()))
            else {
                continue;
            };
            charge(budget, 1, message.source.end - message.source.start)?;
            let bytes = self
                .owner
                .read_original_span(&self.context, &message.source)?;
            let response: ReaderReply = serde_json::from_slice(&bytes).map_err(|_| {
                invalid("captured tool proposal is not a supported protocol response")
            })?;
            if serde_json::to_vec(&response)
                .map_err(|_| invalid("tool proposal encoding failed"))?
                != bytes
                || response
                    .tool_calls
                    .iter()
                    .map(|tool| tool.call_id.to_string())
                    .collect::<Vec<_>>()
                    != message.tool_calls
            {
                return Err(invalid(
                    "captured tool proposal and checkpoint protocol differ",
                ));
            }
            let requested = response
                .tool_calls
                .into_iter()
                .find(|tool| tool.call_id.to_string() == *id)
                .ok_or_else(|| invalid("queued tool identity is absent from its original"))?;
            return Ok(Some(QueuedTool {
                requested,
                proposal: message.source.clone(),
            }));
        }
        Ok(None)
    }

    /// Execute or reconcile the next call through the registered target. Intent
    /// is durable before the fence and target; failed result capture retains bytes.
    pub fn execute_next_tool(
        &mut self,
        registered_operation: &str,
        target: &dyn ExternalTool,
        fence: &dyn ToolDispatchFence,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ToolOutcome> {
        self.ensure_active()?;
        if !matches!(self.phase, CallPhase::Ready) {
            return Err(invalid("model attempt is not at a tool boundary"));
        }
        let queued = self
            .next_tool(budget)?
            .ok_or_else(|| invalid("no pending tool call"))?;
        if queued.requested.action.operation != registered_operation {
            return Err(invalid("tool operation differs from the registered target"));
        }
        let action_bytes = serde_json::to_vec(&queued.requested.action)
            .map_err(|_| invalid("action encoding failed"))?;
        let digest = ContentDigest::from_bytes(*blake3::hash(&action_bytes).as_bytes());
        if self.state.pending_tool.is_none() {
            let request_sequence = self
                .state
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| exhausted("producer sequence exhausted"))?;
            self.state.pending_tool = Some(PendingToolInvocation {
                proposal: queued.proposal,
                call_id: queued.requested.call_id,
                action_digest: digest,
                request_event: ObservationId::new(),
                request_sequence,
                request_recorded_at: now,
                outcome_event: ObservationId::new(),
                outcome_sequence: request_sequence
                    .checked_add(1)
                    .ok_or_else(|| exhausted("producer sequence exhausted"))?,
                outcome_recorded_at: now,
            });
            self.save_checkpoint(now, budget)?;
        }
        let planned = self
            .state
            .pending_tool
            .as_ref()
            .ok_or_else(|| invalid("tool intent absent"))?
            .clone();
        if planned.call_id != queued.requested.call_id || planned.action_digest != digest {
            return Err(invalid(
                "pending tool action differs from its source proposal",
            ));
        }
        let mut request = self.event(
            EventKind::ToolRequested,
            EventRole::Host,
            String::new(),
            planned.request_recorded_at,
            planned.request_event,
        )?;
        request.event.producer_sequence = planned.request_sequence;
        request
            .event
            .parent_event_ids
            .insert(planned.proposal.event_id);
        let guarded = GuardedTool {
            target,
            fence,
            checkpoint: &self.checkpoint_receipt,
            planned: &planned,
            budget: Mutex::new(budget),
        };
        let result = CaptureHost::new(Arc::clone(&self.owner)).run_tool(
            request,
            planned.call_id,
            &queued.requested.action,
            ToolOutcomeSlot {
                event_id: planned.outcome_event,
                producer_sequence: planned.outcome_sequence,
                recorded_at: planned.outcome_recorded_at,
                idempotency_key: format!(
                    "run/{}/{}",
                    self.state.identity.run_id, planned.outcome_event
                ),
            },
            &guarded,
        );
        match result {
            Ok(result) => self.finish_tool_capture(result, now, budget),
            Err(error) => {
                self.pending_tool_capture = error.pending;
                Err(error.error)
            }
        }
    }

    pub(super) fn retry_tool_persistence(
        &mut self,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let pending = self
            .pending_tool_capture
            .as_ref()
            .ok_or_else(|| invalid("no retained tool output"))?
            .as_ref()
            .clone();
        match CaptureHost::new(Arc::clone(&self.owner)).retry_tool_capture(pending) {
            Ok(result) => {
                // Clear only after native acknowledgement. Further checkpoint failure
                // retains its own exact request and cannot repeat an external action.
                self.pending_tool_capture = None;
                self.finish_tool_capture(result, now, budget)?;
                Ok(())
            }
            Err(error) => {
                self.pending_tool_capture = error.pending;
                Err(error.error)
            }
        }
    }

    fn finish_tool_capture(
        &mut self,
        result: CapturedToolOutcome,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ToolOutcome> {
        for receipt in std::iter::once(&result.requested).chain(result.observed.iter()) {
            charge(budget, 1, 0)?;
            let original = self.owner.read_original(ReadOriginalRequest {
                context: self.context.clone(),
                event_id: receipt.event_id,
                after_receipt: Some(receipt.clone()),
            })?;
            if original.event.producer_sequence >= self.state.next_sequence {
                self.apply_original(&original)?;
            }
        }
        if self.checkpoint_position_available() {
            self.save_checkpoint(now, budget)?;
        }
        Ok(result.outcome)
    }

    pub(super) fn checkpoint_position_available(&self) -> bool {
        self.state
            .pending_tool
            .as_ref()
            .is_none_or(|tool| tool.outcome_sequence > self.state.next_sequence)
    }

    pub(super) fn apply_tool_event(
        &mut self,
        event: &EventEnvelope,
        metadata: &RawSource,
    ) -> ServiceResult<()> {
        let planned = self
            .state
            .pending_tool
            .as_ref()
            .ok_or_else(|| invalid("tool event has no checkpointed intent"))?;
        let Some(EventProvenance::Tool {
            call_id,
            request_event_id,
            action_digest,
        }) = event.provenance
        else {
            return Err(invalid("tool event has no exact action provenance"));
        };
        if call_id != planned.call_id
            || request_event_id != planned.request_event
            || action_digest != planned.action_digest
        {
            return Err(invalid("tool event belongs to another action"));
        }
        if event.kind == EventKind::ToolRequested {
            if event.event_id != planned.request_event
                || event.producer_sequence != planned.request_sequence
            {
                return Err(invalid("tool request slot differs"));
            }
            return Ok(());
        }
        if event.event_id != planned.outcome_event
            || event.producer_sequence != planned.outcome_sequence
        {
            return Err(invalid("tool result slot differs"));
        }
        if event.kind == EventKind::ToolOutcomeUnknown {
            let planned = self
                .state
                .pending_tool
                .as_mut()
                .ok_or_else(|| invalid("tool intent absent"))?;
            planned.outcome_event = ObservationId::new();
            // Leave one position for the checkpoint before the new observation slot.
            planned.outcome_sequence = event
                .producer_sequence
                .checked_add(2)
                .ok_or_else(|| exhausted("producer sequence exhausted"))?;
            planned.outcome_recorded_at = event.recorded_at;
        } else {
            let mut message = persistence::captured_message(metadata, OutgoingRole::Tool)?;
            message.tool_result = Some(planned.call_id.to_string());
            self.state
                .groups
                .last_mut()
                .ok_or_else(|| invalid("tool result has no group"))?
                .messages
                .push(message);
            self.state.pending_tool = None;
        }
        Ok(())
    }
}

struct GuardedTool<'a> {
    target: &'a dyn ExternalTool,
    fence: &'a dyn ToolDispatchFence,
    checkpoint: &'a CaptureReceipt,
    planned: &'a PendingToolInvocation,
    budget: Mutex<&'a mut QueryBudget>,
}
impl ExternalTool for GuardedTool<'_> {
    fn replay_safety(&self) -> ToolReplaySafety {
        self.target.replay_safety()
    }
    fn execute(
        &self,
        context: &AuthenticatedRequestContext,
        call_id: ToolCallId,
        action: &ToolAction,
    ) -> ServiceResult<ToolObservation> {
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| invalid("tool dispatch budget lock poisoned"))?;
        if let Err(error) =
            self.fence
                .before_tool(context, self.checkpoint, self.planned, action, &mut budget)
        {
            return Ok(ToolObservation {
                outcome: ToolOutcome::Failed,
                bytes: Some(
                    serde_json::to_vec(&error)
                        .map_err(|_| invalid("fence result encoding failed"))?,
                ),
                media_type: "application/json".into(),
                upstream_truncated: false,
            });
        }
        drop(budget);
        self.target.execute(context, call_id, action)
    }
    fn reconcile(
        &self,
        context: &AuthenticatedRequestContext,
        call_id: ToolCallId,
        action_digest: ContentDigest,
    ) -> ServiceResult<ToolReconciliation> {
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| invalid("tool recovery budget lock poisoned"))?;
        charge(&mut budget, 1, 0)?;
        drop(budget);
        self.target.reconcile(context, call_id, action_digest)
    }
}
