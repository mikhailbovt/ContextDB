//! Current run and exact action admission. No native writer is held over I/O to
//! a model or external target; target CAS/idempotency remains a separate contract.

use contextdb_continuity::OwnedRunCheckpoint;
use contextdb_core::{
    EventKind, EventPayload, EventProvenance, EventRole, ModelOutputFormat, ToolCallId,
};

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
        let state = self.current_owned_checkpoint(&snapshot, context, checkpoint, budget)?;
        self.authorized_capture_policy(&snapshot, context, request.event_id)?;
        self.authorize_capture_dependencies(&snapshot, context, request.event_id)?;
        let original = self.load_captured_original(&snapshot, request.event_id)?;
        let pending = state
            .pending_model
            .as_ref()
            .ok_or_else(|| invalid("run has no planned model attempt"))?;
        let trace_matches = match &original.event.payload {
            EventPayload::Assembly { manifest } => match (
                &manifest.router_trace,
                record.seal.trace_digest,
                record.seal.origin_digest,
                record.seal.trace_version,
            ) {
                (None, None, None, None) => true,
                (Some(trace), Some(digest), Some(origins), version) => {
                    trace.header.trace_digest == digest
                        && trace.header.origin_closure_digest == origins
                        && match version {
                            None => trace.header.version == contextdb_core::ROUTER_TRACE_VERSION,
                            Some(contextdb_core::ROUTER_REPLAY_TRACE_VERSION) => {
                                trace.header.version == contextdb_core::ROUTER_REPLAY_TRACE_VERSION
                            }
                            Some(_) => false,
                        }
                }
                _ => false,
            },
            _ => false,
        };
        if original.receipt != *request
            || !trace_matches
            || original.event.kind != EventKind::ModelRequested
            || original.event.run_id != Some(state.identity.run_id)
            || pending.call_id != call
            || pending.request_event != request.event_id
            || pending.wire_digest.is_some()
            || pending.interrupted_output.is_some()
            || original.event.producer_sequence != state.next_sequence
            || original.event.producer_id != state.producer_id
            || !matches!(&original.event.payload, EventPayload::Assembly { manifest }
                if manifest.model_call_id == call && manifest.wire_digest == record.seal.wire_digest
                    && manifest.byte_length == record.seal.wire_bytes
                    && manifest.original_page_recall == record.seal.original_page_recall)
        {
            return Err(invalid(
                "model dispatch differs from the checkpoint and sealed request",
            ));
        }
        if let Some(routed) = &record.routed {
            if checkpoint != &routed.checkpoint
                || call != routed.intent.call_id
                || request.event_id != routed.intent.request_event
                || routed.known_at.checked_add(1) != Some(request.workspace_commit)
                || state
                    .groups
                    .last()
                    .filter(|group| !group.complete)
                    .map(|group| group.sequence)
                    != Some(routed.intent.interaction_sequence)
            {
                return Err(changed(
                    "routed model handoff differs from its sealed current query",
                ));
            }
            self.check_routed_query_binding(&snapshot, context, &routed.roots, budget)?;
            budgeted::metadata(&snapshot, budget, |reader| {
                if self
                    .workspace_state(reader, &context.request.workspace_id)?
                    .watermarks
                    .journal
                    != request.workspace_commit
                {
                    return Err(changed(
                        "routed workspace advanced after its model request capture",
                    ));
                }
                Ok(())
            })?;
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
        let state = self.current_owned_checkpoint(&snapshot, context, checkpoint, budget)?;
        if state.pending_tool.as_ref() != Some(planned) || planned.action_digest != action_digest {
            return Err(invalid("tool action differs from the current owned intent"));
        }
        let proposal_bytes = if class == ToolAdmissionClass::OriginalPage {
            self.source_span_inner(
                &snapshot,
                Some(context),
                &planned.proposal,
                true,
                Some(budget),
            )?
        } else {
            self.source_span(&snapshot, Some(context), &planned.proposal, true)?
        };
        let proposal = if class == ToolAdmissionClass::OriginalPage {
            self.load_captured_original_with_budget(&snapshot, planned.proposal.event_id, budget)?
        } else {
            self.load_captured_original(&snapshot, planned.proposal.event_id)?
        };
        let Some(EventProvenance::ModelOutput {
            model_call_id,
            request_event_id,
            tool_calls,
            format,
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
        if class == ToolAdmissionClass::OriginalPage {
            // Pure reads can continue after restart, when the old process-local
            // decision lease is gone. Their source authorization is current;
            // this branch never reaches an external target or grants an effect.
            if proposal.event.role != EventRole::Assistant
                || proposal.event.session_id != Some(state.identity.session_id)
                || proposal.event.producer_id != state.producer_id
                || !proposal.event.parent_event_ids.contains(request_event_id)
                || *format != ModelOutputFormat::ProtocolJson
                || planned.proposal.start != 0
                || planned.proposal.end
                    != contextdb_core::RawSource::from(&proposal.event)
                        .byte_length
                        .unwrap_or(0)
            {
                return Err(invalid(
                    "original page proposal differs from its captured protocol",
                ));
            }
            self.authorized_capture_policy_with_budget(
                &snapshot,
                context,
                *request_event_id,
                budget,
            )?;
            self.authorize_derived_custody_with_budget(
                &snapshot,
                context,
                *request_event_id,
                budget,
            )?;
            let request =
                self.load_captured_original_with_budget(&snapshot, *request_event_id, budget)?;
            if request.event.kind != EventKind::ModelRequested
                || request.event.role != EventRole::Host
                || request.event.run_id != Some(state.identity.run_id)
                || request.event.session_id != Some(state.identity.session_id)
                || request.event.producer_id != state.producer_id
                || !matches!(request.event.provenance, Some(EventProvenance::ModelRequest { model_call_id: call }) if call == *model_call_id)
                || !matches!(&request.event.payload, EventPayload::Assembly { manifest } if manifest.model_call_id == *model_call_id)
            {
                return Err(invalid(
                    "original page proposal lacks its actual captured model request",
                ));
            }
            self.authorized_capture_policy_with_budget(
                &snapshot,
                context,
                planned.request_event,
                budget,
            )?;
            self.authorize_derived_custody_with_budget(
                &snapshot,
                context,
                planned.request_event,
                budget,
            )?;
            let intent =
                self.load_captured_original_with_budget(&snapshot, planned.request_event, budget)?;
            if intent.event.kind != EventKind::ToolRequested
                || intent.event.role != EventRole::Host
                || intent.event.run_id != Some(state.identity.run_id)
                || intent.event.session_id != Some(state.identity.session_id)
                || intent.event.producer_id != state.producer_id
                || intent.event.producer_sequence != planned.request_sequence
                || !intent
                    .event
                    .parent_event_ids
                    .contains(&planned.proposal.event_id)
                || !matches!(intent.event.provenance, Some(EventProvenance::Tool { call_id, request_event_id, action_digest: digest })
                    if call_id == planned.call_id && request_event_id == planned.request_event && digest == action_digest)
            {
                return Err(invalid(
                    "original page intent differs from the captured action",
                ));
            }
            let bytes = intent
                .event
                .payload
                .original_bytes()
                .ok_or_else(|| invalid("original page action requires bounded inline JSON"))?;
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
            let selector = owned::captured_original_page_arguments(bytes, action_digest)?;
            let reply: PageProposal = serde_json::from_slice(&proposal_bytes)
                .map_err(|_| invalid("original page proposal JSON is invalid"))?;
            if reply
                .tool_calls
                .iter()
                .map(|call| call.call_id)
                .collect::<Vec<_>>()
                != *tool_calls
                || reply.text.len() > 1024 * 1024
            {
                return Err(invalid(
                    "original page proposal call identities differ from its provenance",
                ));
            }
            let action: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|_| invalid("original page action JSON is invalid"))?;
            if reply
                .tool_calls
                .iter()
                .filter(|call| call.call_id == planned.call_id)
                .count()
                != 1
                || !reply
                    .tool_calls
                    .iter()
                    .any(|call| call.call_id == planned.call_id && call.action == action)
                || !intent
                    .event
                    .parent_event_ids
                    .contains(&selector.handle.event_id)
            {
                return Err(invalid(
                    "original page selector differs from the source proposal or owned locator",
                ));
            }
            if !state
                .groups
                .iter()
                .flat_map(|group| &group.messages)
                .any(|message| {
                    message
                        .tool_page
                        .as_ref()
                        .is_some_and(|page| page.handle == selector.handle)
                })
            {
                self.validate_original_page_disclosure_at(
                    &snapshot,
                    context,
                    &state,
                    &planned.proposal,
                    planned.call_id,
                    &selector,
                    budget,
                )?;
            }
            self.read_tool_original_page_at(
                &snapshot,
                contextdb_service::ReadOriginalPageRequest {
                    context: context.clone(),
                    handle: selector.handle,
                    start: selector.start,
                    max_bytes: selector.max_bytes,
                    external_processing: state.model_profile.external_processing,
                },
                budget,
            )?;
            return Ok(());
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageProposal {
    text: String,
    #[serde(default)]
    tool_calls: Vec<PageProposalCall>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageProposalCall {
    call_id: ToolCallId,
    action: serde_json::Value,
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
