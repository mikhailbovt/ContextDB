//! Current run and exact action admission. No native writer is held over I/O to
//! a model or external target; target CAS/idempotency remains a separate contract.

use contextdb_continuity::OwnedRunCheckpoint;
use contextdb_core::{EventKind, EventPayload, EventProvenance};

use super::*;

impl NativeService {
    pub(super) fn admit_model_dispatch(
        &self,
        context: &AuthenticatedRequestContext,
        lease: &ContextLease,
        checkpoint: &CaptureReceipt,
        call: ModelCallId,
        request: &CaptureReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        require_capability(context, Capability::Runtime)?;
        let _publication = self.lock_index_publication(budget)?;
        let mut registry = self.lease_registry()?;
        let record = registry
            .entries
            .get(&lease.token)
            .ok_or_else(|| expired("model lease is no longer registered"))?;
        self.check_lease_principal(context, record)?;
        self.check_lease_clock(record)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.check_lease_policy(&snapshot, context, record, budget)?;
        if !self.lease_scopes_current(&snapshot, context, record, budget)? {
            return Err(changed("decision context changed before model handoff"));
        }
        budget.charge(2, 0).map_err(budget_error)?;
        let state = self.current_owned_checkpoint(&snapshot, context, checkpoint)?;
        self.authorized_capture_policy(&snapshot, context, request.event_id)?;
        self.authorize_capture_dependencies(&snapshot, context, request.event_id)?;
        let original = self.load_captured_original(&snapshot, request.event_id)?;
        let pending = state
            .pending_model
            .as_ref()
            .ok_or_else(|| invalid("run has no planned model attempt"))?;
        if original.receipt != *request
            || original.event.kind != EventKind::ModelRequested
            || original.event.run_id != Some(state.identity.run_id)
            || pending.call_id != call
            || pending.request_event != request.event_id
            || pending.wire_digest.is_some()
            || pending.interrupted_output.is_some()
            || original.event.producer_sequence != state.next_sequence
            || !matches!(&original.event.payload, EventPayload::Assembly { manifest }
                if manifest.model_call_id == call && manifest.wire_digest == record.seal.wire_digest
                    && manifest.byte_length == record.seal.wire_bytes)
        {
            return Err(invalid(
                "model dispatch differs from the checkpoint and sealed request",
            ));
        }
        if registry.entries.values().any(|entry| {
            entry
                .model
                .as_ref()
                .is_some_and(|admitted| admitted.request == request.event_id)
        }) {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "model request was already admitted; reconcile instead of sending again",
                false,
            ));
        }
        registry.entries.retain(|token, entry| {
            token == &lease.token
                || entry
                    .model
                    .as_ref()
                    .is_none_or(|admitted| admitted.run != state.identity.run_id)
        });
        registry
            .entries
            .get_mut(&lease.token)
            .ok_or_else(|| expired("model lease absent"))?
            .model = Some(ModelAdmission {
            request: request.event_id,
            call,
            run: state.identity.run_id,
            working_digest: decision_working_digest(&state, None)?,
        });
        Ok(())
    }

    pub(super) fn admit_tool_dispatch(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        planned: &PendingToolInvocation,
        action_digest: ContentDigest,
        class: ToolAdmissionClass,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        require_capability(context, Capability::Runtime)?;
        let _publication = self.lock_index_publication(budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        budget
            .charge(
                3,
                planned.proposal.end.saturating_sub(planned.proposal.start),
            )
            .map_err(budget_error)?;
        let state = self.current_owned_checkpoint(&snapshot, context, checkpoint)?;
        if state.pending_tool.as_ref() != Some(planned) || planned.action_digest != action_digest {
            return Err(invalid("tool action differs from the current owned intent"));
        }
        self.source_span(&snapshot, Some(context), &planned.proposal, true)?;
        let proposal = self.load_captured_original(&snapshot, planned.proposal.event_id)?;
        let Some(EventProvenance::ModelOutput {
            model_call_id,
            request_event_id,
            tool_calls,
            ..
        }) = &proposal.event.provenance
        else {
            return Err(invalid("tool proposal has no model origin"));
        };
        if proposal.event.kind != EventKind::ModelResponseCompleted
            || proposal.event.run_id != Some(state.identity.run_id)
            || !tool_calls.contains(&planned.call_id)
        {
            return Err(invalid(
                "tool proposal differs from its admitted model origin",
            ));
        }
        let registry = self.lease_registry()?;
        let record = registry
            .entries
            .values()
            .find(|entry| {
                entry.model.as_ref().is_some_and(|admitted| {
                    admitted.request == *request_event_id
                        && admitted.call == *model_call_id
                        && admitted.run == state.identity.run_id
                })
            })
            .ok_or_else(|| expired("proposal has no live decision lease; refresh and replan"))?;
        self.check_lease_principal(context, record)?;
        self.check_lease_clock(record)?;
        self.check_lease_policy(&snapshot, context, record, budget)?;
        if record
            .model
            .as_ref()
            .ok_or_else(|| invalid("model admission missing"))?
            .working_digest
            != decision_working_digest(&state, Some(planned.proposal.event_id))?
        {
            return Err(changed(
                "working obligations or resident decision context changed",
            ));
        }
        if !record.seal.current
            || (record.seal.pending_interpretation && class == ToolAdmissionClass::ExternalEffect)
        {
            return Err(changed(
                "external action requires established current constraints",
            ));
        }
        self.authorized_capture_policy(&snapshot, context, planned.request_event)?;
        let intent = self.load_captured_original(&snapshot, planned.request_event)?;
        if intent.event.kind != EventKind::ToolRequested
            || intent.event.run_id != Some(state.identity.run_id)
            || intent.event.producer_sequence != planned.request_sequence
            || !matches!(intent.event.provenance, Some(EventProvenance::Tool {
                call_id, request_event_id, action_digest: digest
            }) if call_id == planned.call_id && request_event_id == planned.request_event && digest == action_digest)
        {
            return Err(invalid(
                "captured tool intent differs from the fenced action",
            ));
        }
        if class == ToolAdmissionClass::MemoryExpansion {
            let action: serde_json::Value =
                serde_json::from_slice(intent.event.payload.original_bytes().ok_or_else(|| {
                    invalid("memory expansion action requires bounded inline JSON")
                })?)
                .map_err(|_| invalid("memory expansion action JSON invalid"))?;
            if action.get("operation").and_then(serde_json::Value::as_str)
                != Some("contextdb.memory.expand")
                || action
                    .get("expected_target_version")
                    .is_some_and(|value| !value.is_null())
            {
                return Err(invalid(
                    "pure expansion classification differs from the captured action",
                ));
            }
        }
        // The model's own proposal and native operational checkpoints cannot
        // authorize a new constraint. Revalidate only this exact bounded suffix;
        // user input, semantic publication and tool results always require replan.
        if !self.lease_scopes_current(&snapshot, context, record, budget)? {
            self.check_decision_suffix(&snapshot, context, record, &state, planned, budget)?;
        }
        Ok(())
    }

    fn check_decision_suffix<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        record: &LeaseRecord,
        state: &OwnedRunCheckpoint,
        planned: &PendingToolInvocation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let head = self
            .workspace_state(snapshot, &context.request.workspace_id)?
            .watermarks
            .journal;
        if head.saturating_sub(record.fence.known_at) > 64 {
            return Err(changed(
                "decision suffix exceeds bounded revalidation; replan",
            ));
        }
        let model = record
            .model
            .as_ref()
            .ok_or_else(|| invalid("model admission missing"))?;
        for commit in record.fence.known_at.saturating_add(1)..=head {
            budget.charge(1, 0).map_err(budget_error)?;
            let (global, _) =
                self.select_snapshot(snapshot, &context.request.workspace_id, Some(commit))?;
            let entry: StoredEvent = decode(
                &snapshot
                    .get(&self.keyspaces.events, &global.to_be_bytes())
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("decision suffix journal missing"))?,
                "decision journal",
            )?;
            if entry.operation == "stage_payload" && entry.accepted_payload.is_some() {
                continue;
            }
            let Some(work) = entry.accepted_original else {
                return Err(changed(
                    "a publication changed the proposal's decision context",
                ));
            };
            self.authorized_capture_policy(snapshot, context, work.event_id)?;
            let original = self.load_captured_original(snapshot, work.event_id)?;
            budget
                .charge(1, encode(&original.event)?.len() as u64)
                .map_err(budget_error)?;
            let event = &original.event;
            let allowed = event.run_id == Some(state.identity.run_id)
                && event.session_id == Some(state.identity.session_id)
                && match &event.provenance {
                    Some(EventProvenance::OwnedCheckpoint { .. }) => true,
                    Some(EventProvenance::ModelRequest { model_call_id }) => {
                        event.event_id == model.request && *model_call_id == model.call
                    }
                    Some(EventProvenance::ModelOutput {
                        model_call_id,
                        request_event_id,
                        ..
                    }) => {
                        event.event_id == planned.proposal.event_id
                            && *model_call_id == model.call
                            && *request_event_id == model.request
                            && event.kind == EventKind::ModelResponseCompleted
                    }
                    Some(EventProvenance::Tool {
                        call_id,
                        request_event_id,
                        action_digest,
                    }) => {
                        event.event_id == planned.request_event
                            && *call_id == planned.call_id
                            && *request_event_id == planned.request_event
                            && *action_digest == planned.action_digest
                            && event.kind == EventKind::ToolRequested
                    }
                    _ => false,
                };
            if !allowed {
                return Err(changed(
                    "a new observation requires refreshing the decision context",
                ));
            }
        }
        Ok(())
    }
}

fn decision_working_digest(
    state: &OwnedRunCheckpoint,
    proposal: Option<ObservationId>,
) -> ServiceResult<String> {
    let mut groups = state.groups.clone();
    if let Some(proposal) = proposal {
        let group = groups
            .last_mut()
            .ok_or_else(|| invalid("proposal has no current interaction"))?;
        let position = group
            .messages
            .iter()
            .position(|message| message.source.event_id == proposal)
            .ok_or_else(|| invalid("proposal is absent from the current interaction"))?;
        group.messages.truncate(position);
        group.complete = false;
    }
    canonical_digest(&(
        &state.identity,
        &state.model_profile,
        &state.obligations,
        groups,
    ))
}
