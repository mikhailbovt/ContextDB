//! Actual captured-request source proof for an evicted tool-result selector.

use super::*;
use contextdb_continuity::{OriginalPageArguments, OwnedRunCheckpoint};
use contextdb_core::{EventProvenance, ModelOutputFormat, RequestPart, ToolCallId};
use serde::{Deserialize, Serialize};

impl NativeService {
    #[allow(
        clippy::too_many_arguments,
        reason = "one snapshot binds run, proposal, selector and budget"
    )]
    pub(crate) fn validate_original_page_disclosure_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        state: &OwnedRunCheckpoint,
        proposal: &OriginalSourceSpan,
        call_id: ToolCallId,
        selector: &OriginalPageArguments,
        budget: &mut PayloadBudget,
    ) -> ServiceResult<()> {
        for capability in [
            Capability::Runtime,
            Capability::ReadEvidence,
            Capability::RawEvidence,
        ] {
            require_capability(context, capability)?;
        }
        if state.model_profile.external_processing || self.preparation_scorer.is_some() {
            require_capability(context, Capability::ModelProcessing)?;
        }
        selector
            .validate()
            .map_err(|_| invalid("invalid disclosed page selector"))?;
        let group = state
            .groups
            .last()
            .filter(|group| !group.complete)
            .ok_or_else(|| invalid("page disclosure lacks a current protocol group"))?;
        let completed = group
            .messages
            .iter()
            .filter_map(|message| message.tool_result.as_deref())
            .collect::<BTreeSet<_>>();
        let next = group.messages.iter().find_map(|message| {
            message
                .tool_calls
                .iter()
                .find(|call| !completed.contains(call.as_str()))
                .map(|call| (&message.source, call))
        });
        if next != Some((proposal, &call_id.to_string())) {
            return Err(invalid(
                "page disclosure differs from the next current proposal",
            ));
        }
        self.validate_original_page_disclosure_origin_at(
            snapshot, context, state, proposal, call_id, selector, budget,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one snapshot binds captured origin, selector and budget"
    )]
    pub(crate) fn validate_original_page_disclosure_origin_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        state: &OwnedRunCheckpoint,
        proposal: &OriginalSourceSpan,
        call_id: ToolCallId,
        selector: &OriginalPageArguments,
        budget: &mut PayloadBudget,
    ) -> ServiceResult<()> {
        for capability in [
            Capability::Runtime,
            Capability::ReadEvidence,
            Capability::RawEvidence,
        ] {
            require_capability(context, capability)?;
        }
        if state.model_profile.external_processing || self.preparation_scorer.is_some() {
            require_capability(context, Capability::ModelProcessing)?;
        }
        selector
            .validate()
            .map_err(|_| invalid("invalid disclosed page selector"))?;
        let bytes =
            self.source_span_inner(snapshot, Some(context), proposal, true, Some(budget))?;
        let output =
            self.load_captured_original_with_budget(snapshot, proposal.event_id, budget)?;
        let Some(EventProvenance::ModelOutput {
            model_call_id,
            request_event_id,
            tool_calls,
            format,
        }) = &output.event.provenance
        else {
            return Err(invalid(
                "disclosed page proposal has no captured model origin",
            ));
        };
        if output.event.kind != EventKind::ModelResponseCompleted
            || output.event.role != EventRole::Assistant
            || output.event.run_id != Some(state.identity.run_id)
            || output.event.session_id != Some(state.identity.session_id)
            || output.event.producer_id != state.producer_id
            || output.event.workspace_id != state.identity.workspace_id
            || output.event.scope_ids != state.identity.scopes
            || !output.event.parent_event_ids.contains(request_event_id)
            || *format != ModelOutputFormat::ProtocolJson
            || proposal.start != 0
            || proposal.end != RawSource::from(&output.event).byte_length.unwrap_or(0)
        {
            return Err(invalid(
                "disclosed page proposal differs from the full captured protocol",
            ));
        }
        let reply: DisclosedPageProposal = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("disclosed page proposal JSON is invalid"))?;
        if reply.text.len() > 1024 * 1024
            || reply
                .tool_calls
                .iter()
                .map(|call| call.call_id)
                .collect::<Vec<_>>()
                != *tool_calls
            || encode(&reply)? != bytes
        {
            return Err(invalid(
                "disclosed page proposal protocol bytes or call order differ",
            ));
        }
        let call = reply
            .tool_calls
            .iter()
            .find(|call| call.call_id == call_id)
            .ok_or_else(|| invalid("disclosed page call is absent from its proposal"))?;
        let action = encode(&call.action)?;
        let action_digest = ContentDigest::from_bytes(*blake3::hash(&action).as_bytes());
        if super::super::super::owned::captured_original_page_arguments(&action, action_digest)?
            != *selector
        {
            return Err(invalid(
                "disclosed page selector differs from its actual proposed action",
            ));
        }
        self.authorized_capture_policy_with_budget(snapshot, context, *request_event_id, budget)?;
        self.authorize_derived_custody_with_budget(snapshot, context, *request_event_id, budget)?;
        let request =
            self.load_captured_original_with_budget(snapshot, *request_event_id, budget)?;
        let EventPayload::Assembly { manifest } = &request.event.payload else {
            return Err(invalid(
                "disclosed page proposal has no captured request manifest",
            ));
        };
        if request.event.kind != EventKind::ModelRequested
            || request.event.role != EventRole::Host
            || request.event.run_id != Some(state.identity.run_id)
            || request.event.session_id != Some(state.identity.session_id)
            || request.event.producer_id != state.producer_id
            || request.event.workspace_id != state.identity.workspace_id
            || request.event.scope_ids != state.identity.scopes
            || request.event.producer_sequence >= output.event.producer_sequence
            || manifest.model_call_id != *model_call_id
            || request.event.provenance
                != Some(EventProvenance::ModelRequest {
                    model_call_id: *model_call_id,
                })
            || !manifest.original_page_recall
        {
            return Err(invalid(
                "page disclosure requires its exact supported captured model request",
            ));
        }
        self.require_original_page_recall_feature(snapshot, budget)?;
        let original =
            self.validate_tool_page_original(snapshot, context, &selector.handle, budget)?;
        if !matches!(
            original.event.provenance,
            Some(EventProvenance::Tool { .. })
        ) || original.receipt.workspace_commit >= request.receipt.workspace_commit
        {
            return Err(invalid(
                "disclosed tool original lacks protocol origin or belongs to a future occurrence",
            ));
        }
        // Only a source part in the actual captured wire proves disclosure. A raw
        // hit, locator literal, omitted source or discarded router origin does not.
        let span = manifest
            .parts
            .iter()
            .filter_map(|part| match part {
                RequestPart::Source { span } | RequestPart::JsonStringSource { span, .. } => {
                    Some(span)
                }
                _ => None,
            })
            .find(|span| {
                span.event_id == selector.handle.event_id
                    && span.payload_digest == selector.handle.payload_digest
                    && span.end.checked_sub(span.start).is_some_and(|length| {
                        length > 0 && length <= u64::from(TOOL_RESULT_PAGE_BYTES)
                    })
                    && span.end <= selector.handle.byte_length
            })
            .ok_or_else(|| {
                invalid("tool original was not disclosed in this captured model request")
            })?;
        let page = self.read_tool_original_page_at(
            snapshot,
            ReadOriginalPageRequest {
                context: context.clone(),
                handle: selector.handle.clone(),
                start: span.start,
                max_bytes: (span.end - span.start) as u32,
                external_processing: state.model_profile.external_processing,
            },
            budget,
        )?;
        if page.view.preview != *span {
            return Err(invalid(
                "captured disclosed page differs from its authenticated original",
            ));
        }
        Ok(())
    }

    pub(crate) fn require_original_page_recall_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut PayloadBudget,
    ) -> ServiceResult<()> {
        let bytes = snapshot
            .get(&self.keyspaces.meta, META_MANIFEST_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| invalid("native manifest is absent"))?;
        if bytes.len() > super::super::super::MAX_JSON_BYTES {
            return Err(invalid("native manifest exceeds its metadata bound"));
        }
        budget
            .charge(1, bytes.len() as u64)
            .map_err(super::super::super::raw_index::budget_error)?;
        let manifest: Manifest = decode(&bytes, "native manifest")?;
        super::super::super::validate_manifest(&manifest, &self.database_id)?;
        if !manifest
            .features
            .contains(super::super::super::owned::PAGE_RECALL_FEATURE)
        {
            return Err(invalid("captured original-page recall feature is absent"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisclosedPageProposal {
    text: String,
    tool_calls: Vec<DisclosedPageCall>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisclosedPageCall {
    call_id: ToolCallId,
    action: DisclosedPageAction,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisclosedPageAction {
    operation: String,
    input: Vec<u8>,
    expected_target_version: Option<String>,
}
