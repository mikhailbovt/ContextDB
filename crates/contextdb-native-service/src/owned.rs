//! Atomic checkpoint capture and run-head publication, sharing native receipts.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::OutgoingRole;
use contextdb_continuity::{OwnedRunCheckpoint, OwnedRunIdentity, OwnedRunStatus};
use contextdb_core::{
    AgentRunId, ContentDigest, EVENT_ENVELOPE_VERSION, EventCoverage, EventEnvelope, EventKind,
    EventPayload, EventProvenance, EventRole, SourceId,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, Capability, CaptureReceipt, CaptureRequest, ErrorCode,
    OwnedRunPort, ProducerCoverage, RunCaptureTail, SaveRunCheckpointRequest, SavedRunCheckpoint,
    ServiceError, ServiceResult,
};
use contextdb_storage::{ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction};
use serde::{Deserialize, Serialize};

use super::raw_index::budget_error;
use super::{
    NativeService, decode, digest_bytes, encode, exhausted, integrity, invalid, permission_denied,
    require_capability, storage_error,
};

pub(super) const OWNED_FEATURE: &str = "continuous-owned-runtime-v1";
pub(super) const TOOL_PAGES_FEATURE: &str = "continuous-owned-tool-pages-v1";
pub(super) const PAGE_RECALL_FEATURE: &str = "continuous-owned-original-page-recall-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunHead {
    identity: OwnedRunIdentity,
    revision: u64,
    state_digest: ContentDigest,
    receipt: CaptureReceipt,
    producer_id: contextdb_core::StreamId,
    status: OwnedRunStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointControl {
    workspace_id: contextdb_core::WorkspaceId,
    run_id: AgentRunId,
    identity_digest: ContentDigest,
    expected_revision: u64,
    revision: u64,
    state_digest: ContentDigest,
    producer_id: contextdb_core::StreamId,
    next_sequence: u64,
    status: OwnedRunStatus,
    // This format requirement survives explicit removal of the checkpoint body.
    #[serde(default, skip_serializing_if = "is_false")]
    tool_pages: bool,
}

pub(super) struct RecoveredRunHead {
    control: CheckpointControl,
    receipt: CaptureReceipt,
}

impl OwnedRunPort for NativeService {
    fn recover_record_writes(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.recover_runtime_record_writes(context, budget)
    }

    fn save_run_checkpoint(
        &self,
        request: SaveRunCheckpointRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<SavedRunCheckpoint> {
        require_capability(&request.context, Capability::Runtime)?;
        check_identity(&request.context, &request.checkpoint.identity)?;
        request
            .checkpoint
            .validate()
            .map_err(|_| invalid("invalid owned checkpoint"))?;
        if request.expected_revision.checked_add(1) != Some(request.checkpoint.revision) {
            return Err(invalid(
                "checkpoint does not advance exactly one run revision",
            ));
        }
        let bytes = encode(&request.checkpoint)?;
        if bytes.len() > super::CAPTURE_MAX_INLINE_BYTES {
            return Err(exhausted(
                "operational checkpoint exceeds 256 KiB of source references",
            ));
        }
        let source_bytes = request
            .checkpoint
            .required_sources()
            .map(|span| span.end - span.start)
            .sum::<u64>();
        budget
            .charge(1, bytes.len() as u64 + source_bytes)
            .map_err(budget_error)?;
        let checkpoint = &request.checkpoint;
        let state_digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
        let event = EventEnvelope {
            version: EVENT_ENVELOPE_VERSION,
            event_id: request.event_id,
            workspace_id: checkpoint.identity.workspace_id,
            scope_ids: checkpoint.identity.scopes.clone(),
            producer_id: checkpoint.producer_id,
            producer_sequence: checkpoint.next_sequence - 1,
            kind: EventKind::RunCheckpointed,
            recorded_at: checkpoint.recorded_at,
            observed_at: None,
            source_id: SourceId::from_uuid(checkpoint.identity.run_id.as_uuid())
                .map_err(|_| invalid("run source identity invalid"))?,
            source_version: Some(checkpoint.revision.to_string()),
            adapter_id: OWNED_FEATURE.into(),
            role: EventRole::Host,
            session_id: Some(checkpoint.identity.session_id),
            run_id: Some(checkpoint.identity.run_id),
            task_id: None,
            parent_event_ids: BTreeSet::new(),
            supersedes_event_id: None,
            payload: EventPayload::InlineBytes {
                bytes,
                media_type: "application/json".into(),
                digest: state_digest,
            },
            coverage: EventCoverage::CompleteObservation,
            upstream_truncated: false,
            gap_reason: None,
            response_stream: None,
            provenance: Some(EventProvenance::OwnedCheckpoint {
                expected_revision: request.expected_revision,
                state_digest,
            }),
        };
        let receipt = self
            .append_owned_capture(
                CaptureRequest {
                    context: request.context.clone(),
                    idempotency_key: request.idempotency_key.clone(),
                    event,
                },
                Some(&request),
                Some(budget),
            )?
            .receipt;
        Ok(SavedRunCheckpoint {
            checkpoint: request.checkpoint,
            receipt,
        })
    }

    fn load_run_checkpoint(
        &self,
        context: &AuthenticatedRequestContext,
        run: AgentRunId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<SavedRunCheckpoint>> {
        require_capability(context, Capability::Runtime)?;
        require_capability(context, Capability::ReadEvidence)?;
        require_capability(context, Capability::RawEvidence)?;
        budget.charge(1, 0).map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let Some(bytes) = snapshot
            .get(
                &self.keyspaces.continuous,
                &head_key(&context.request.workspace_id, run),
            )
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let head: RunHead = decode(&bytes, "run head")?;
        check_identity(context, &head.identity)?;
        self.authorized_capture_policy(&snapshot, context, head.receipt.event_id)?;
        self.authorize_capture_dependencies(&snapshot, context, head.receipt.event_id)?;
        let original = self.load_captured_original(&snapshot, head.receipt.event_id)?;
        let checkpoint = decode_checkpoint(&original.event)?;
        budget
            .charge(1, encode(&checkpoint)?.len() as u64)
            .map_err(budget_error)?;
        if original.receipt != head.receipt
            || checkpoint.revision != head.revision
            || checkpoint.identity != head.identity
            || checkpoint.producer_id != head.producer_id
            || checkpoint.status != head.status
            || checkpoint
                .digest()
                .map_err(|_| integrity("run state invalid"))?
                != head.state_digest
        {
            return Err(integrity("run head differs from its captured checkpoint"));
        }
        self.validate_pending_model(&snapshot, context, &checkpoint)?;
        self.validate_persisted_tool_page_feature(&snapshot, &checkpoint, budget)?;
        self.validate_checkpoint_tool_pages(&snapshot, context, &checkpoint, budget)?;
        Ok(Some(SavedRunCheckpoint {
            checkpoint,
            receipt: head.receipt,
        }))
    }

    fn read_run_tail(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RunCaptureTail> {
        require_capability(context, Capability::Runtime)?;
        require_capability(context, Capability::ReadEvidence)?;
        require_capability(context, Capability::RawEvidence)?;
        budget.charge(1, 0).map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.authorized_capture_policy(&snapshot, context, checkpoint.event_id)?;
        self.authorize_capture_dependencies(&snapshot, context, checkpoint.event_id)?;
        let original = self.load_captured_original(&snapshot, checkpoint.event_id)?;
        if original.receipt != *checkpoint {
            return Err(invalid("checkpoint receipt differs"));
        }
        let state = decode_checkpoint(&original.event)?;
        check_identity(context, &state.identity)?;
        self.validate_persisted_tool_page_feature(&snapshot, &state, budget)?;
        let head: RunHead = decode(
            &snapshot
                .get(
                    &self.keyspaces.continuous,
                    &head_key(&context.request.workspace_id, state.identity.run_id),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("current run head is absent"))?,
            "run head",
        )?;
        if head.receipt != *checkpoint {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "run checkpoint changed before recovery",
                true,
            ));
        }
        let producer = super::capture::producer_key(context, state.producer_id)?;
        let coverage: ProducerCoverage = decode(
            &snapshot
                .get(
                    &self.keyspaces.continuous,
                    format!("producer/{producer}").as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("run producer is absent"))?,
            "run producer",
        )?;
        let mut events = Vec::new();
        let mut sequence = state.next_sequence;
        while sequence <= coverage.head && events.len() < 64 {
            budget.charge(1, 0).map_err(budget_error)?;
            let id: contextdb_core::ObservationId = decode(
                &snapshot
                    .get(
                        &self.keyspaces.continuous,
                        &super::capture::position_key(&producer, sequence),
                    )
                    .map_err(storage_error)?
                    .ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::IndexTooStale,
                            "run recovery contains an unresolved capture gap",
                            true,
                        )
                    })?,
                "run position",
            )?;
            self.authorized_capture_policy(&snapshot, context, id)?;
            self.authorize_capture_dependencies(&snapshot, context, id)?;
            let event = self.load_captured_original(&snapshot, id)?;
            if event.event.run_id != Some(state.identity.run_id)
                || event.event.session_id != Some(state.identity.session_id)
            {
                return Err(integrity("run producer contains another run's event"));
            }
            budget
                .charge(0, encode(&event)?.len() as u64)
                .map_err(budget_error)?;
            events.push(event);
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| exhausted("producer sequence exhausted"))?;
        }
        Ok(RunCaptureTail {
            events,
            more: sequence <= coverage.head,
        })
    }
}

impl NativeService {
    pub(super) fn current_owned_checkpoint<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        receipt: &CaptureReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<OwnedRunCheckpoint> {
        self.authorized_capture_policy(snapshot, context, receipt.event_id)?;
        self.authorize_capture_dependencies(snapshot, context, receipt.event_id)?;
        let original = self.load_captured_original(snapshot, receipt.event_id)?;
        let checkpoint = decode_checkpoint(&original.event)?;
        check_identity(context, &checkpoint.identity)?;
        let head: RunHead = decode(
            &snapshot
                .get(
                    &self.keyspaces.continuous,
                    &head_key(&context.request.workspace_id, checkpoint.identity.run_id),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("owned run head absent"))?,
            "run head",
        )?;
        if original.receipt != *receipt
            || head.receipt != *receipt
            || head.revision != checkpoint.revision
            || head.identity != checkpoint.identity
            || checkpoint.status != OwnedRunStatus::Active
            || head.state_digest
                != checkpoint
                    .digest()
                    .map_err(|_| integrity("run checkpoint invalid"))?
        {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "owned run changed before dispatch admission",
                true,
            ));
        }
        self.validate_persisted_tool_page_feature(snapshot, &checkpoint, budget)?;
        self.validate_checkpoint_tool_pages(snapshot, context, &checkpoint, budget)?;
        Ok(checkpoint)
    }

    fn validate_persisted_tool_page_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        checkpoint: &OwnedRunCheckpoint,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if !has_tool_pages(checkpoint) {
            return Ok(());
        }
        budget.charge(1, 0).map_err(budget_error)?;
        let bytes = snapshot
            .get(&self.keyspaces.meta, super::META_MANIFEST_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("native manifest absent"))?;
        if bytes.len() > super::MAX_JSON_BYTES {
            return Err(integrity("native manifest exceeds its metadata bound"));
        }
        budget.charge(0, bytes.len() as u64).map_err(budget_error)?;
        let manifest: super::Manifest = decode(&bytes, "native manifest")?;
        super::validate_manifest(&manifest, &self.database_id)?;
        require_tool_page_feature(checkpoint, &manifest.features)
    }

    pub(super) fn validate_checkpoint_publication<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        request: &SaveRunCheckpointRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        require_capability(&request.context, Capability::Runtime)?;
        require_capability(&request.context, Capability::ReadEvidence)?;
        require_capability(&request.context, Capability::RawEvidence)?;
        check_identity(&request.context, &request.checkpoint.identity)?;
        let previous = snapshot
            .get(
                &self.keyspaces.continuous,
                &head_key(
                    &request.context.request.workspace_id,
                    request.checkpoint.identity.run_id,
                ),
            )
            .map_err(storage_error)?
            .map(|bytes| decode::<RunHead>(&bytes, "run head"))
            .transpose()?;
        if let Some(head) = &previous {
            check_identity(&request.context, &head.identity)?;
            self.authorized_capture_policy(snapshot, &request.context, head.receipt.event_id)?;
            if head.status != OwnedRunStatus::Active
                || head.producer_id != request.checkpoint.producer_id
            {
                return Err(invalid(
                    "terminal runs cannot advance or change capture producer",
                ));
            }
        }
        if previous.as_ref().map_or(0, |head| head.revision) != request.expected_revision {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "owned run changed before checkpoint publication",
                true,
            ));
        }
        for source in request.checkpoint.required_sources() {
            let page_source = request
                .checkpoint
                .groups
                .iter()
                .flat_map(|group| &group.messages)
                .any(|message| {
                    message
                        .tool_page
                        .as_ref()
                        .is_some_and(|page| source == &message.source || source == &page.preview)
                });
            if !page_source {
                self.source_span(snapshot, Some(&request.context), source, true)?;
            }
        }
        self.validate_pending_model(snapshot, &request.context, &request.checkpoint)?;
        self.validate_checkpoint_tool_pages(
            snapshot,
            &request.context,
            &request.checkpoint,
            budget,
        )?;
        if let Some(id) = request.checkpoint.last_model_output {
            self.authorized_capture_policy(snapshot, &request.context, id)?;
            self.authorize_capture_dependencies(snapshot, &request.context, id)?;
            let original = self.load_captured_original(snapshot, id)?;
            if original.event.kind != EventKind::ModelResponseCompleted
                || original.event.run_id != Some(request.checkpoint.identity.run_id)
                || original.event.session_id != Some(request.checkpoint.identity.session_id)
                || !matches!(
                    original.event.provenance,
                    Some(EventProvenance::ModelOutput { .. })
                )
            {
                return Err(invalid(
                    "last model result belongs to another run or protocol",
                ));
            }
        }
        for message in request
            .checkpoint
            .groups
            .iter()
            .flat_map(|group| &group.messages)
        {
            let original = self.load_captured_original(snapshot, message.source.event_id)?;
            let expected_role = match message.role {
                OutgoingRole::User => EventRole::User,
                OutgoingRole::Assistant => EventRole::Assistant,
                OutgoingRole::Tool => EventRole::Tool,
                _ => {
                    return Err(invalid(
                        "captured conversation cannot introduce control roles",
                    ));
                }
            };
            if original.event.role != expected_role
                || original.event.session_id != Some(request.checkpoint.identity.session_id)
                || original.event.run_id != Some(request.checkpoint.identity.run_id)
            {
                return Err(invalid(
                    "checkpoint message role or run differs from its original",
                ));
            }
            let calls = match &original.event.provenance {
                Some(EventProvenance::ModelOutput { tool_calls, .. }) => tool_calls
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                _ => vec![],
            };
            let result = match &original.event.provenance {
                Some(EventProvenance::Tool { call_id, .. })
                    if original.event.role == EventRole::Tool =>
                {
                    Some(call_id.to_string())
                }
                _ => None,
            };
            if message.tool_calls != calls || message.tool_result != result {
                return Err(invalid(
                    "checkpoint tool protocol differs from its captured source",
                ));
            }
        }
        Ok(())
    }

    // This runs at publication, reopen and dispatch admission. A durable locator
    // never bypasses the current policy of either its protocol anchor or original.
    fn validate_checkpoint_tool_pages<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        checkpoint: &OwnedRunCheckpoint,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        use contextdb_continuity::{TOOL_RESULT_PAGE_BYTES, ToolResultPageView};
        for message in checkpoint.groups.iter().flat_map(|group| &group.messages) {
            let Some(page) = &message.tool_page else {
                continue;
            };
            page.validate()
                .map_err(|_| invalid("invalid checkpointed tool page"))?;
            let original =
                self.validate_tool_page_original(snapshot, context, &page.handle, budget)?;
            let original_in_run = original.event.run_id == Some(checkpoint.identity.run_id)
                && original.event.session_id == Some(checkpoint.identity.session_id);
            if !matches!(
                original.event.provenance,
                Some(EventProvenance::Tool { .. })
            ) {
                return Err(invalid(
                    "tool page original belongs to another run or protocol",
                ));
            }
            let preview = self.read_tool_original_page_at(
                snapshot,
                contextdb_service::ReadOriginalPageRequest {
                    context: context.clone(),
                    handle: page.handle.clone(),
                    start: page.preview.start,
                    max_bytes: u32::try_from(page.preview.end - page.preview.start)
                        .map_err(|_| invalid("page range size is invalid"))?,
                    external_processing: checkpoint.model_profile.external_processing,
                },
                budget,
            )?;
            if preview.view != *page
                || preview.bytes.len() as u64 != page.preview.end - page.preview.start
                || ContentDigest::from_bytes(*blake3::hash(&preview.bytes).as_bytes())
                    != page.preview.span_digest
            {
                return Err(invalid(
                    "checkpointed page differs from its authenticated bytes",
                ));
            }
            self.authorized_capture_policy_with_budget(
                snapshot,
                context,
                message.source.event_id,
                budget,
            )?;
            self.authorize_derived_custody_with_budget(
                snapshot,
                context,
                message.source.event_id,
                budget,
            )?;
            let anchor =
                self.load_captured_original_with_budget(snapshot, message.source.event_id, budget)?;
            let Some(EventProvenance::Tool {
                call_id,
                request_event_id,
                action_digest,
            }) = anchor.event.provenance
            else {
                return Err(invalid("tool page anchor has no captured call identity"));
            };
            if message.role != OutgoingRole::Tool
                || message.tool_result.as_deref() != Some(call_id.to_string().as_str())
                || !message.tool_calls.is_empty()
                || anchor.event.role != EventRole::Tool
                || anchor.event.run_id != Some(checkpoint.identity.run_id)
                || anchor.event.session_id != Some(checkpoint.identity.session_id)
            {
                return Err(invalid("tool page anchor differs from the owned protocol"));
            }
            if message.source == page.preview {
                if !original_in_run
                    || page.preview.start != 0
                    || page.handle.byte_length <= u64::from(TOOL_RESULT_PAGE_BYTES)
                {
                    return Err(invalid(
                        "initial tool preview does not describe an oversized original",
                    ));
                }
                continue;
            }
            if anchor.event.kind != EventKind::ToolCompleted
                || message.source.start != 0
                || message.source.end
                    != contextdb_core::RawSource::from(&anchor.event)
                        .byte_length
                        .unwrap_or(0)
                || message.source.end > u64::from(TOOL_RESULT_PAGE_BYTES)
            {
                return Err(invalid(
                    "tool page result metadata exceeds its bounded full anchor",
                ));
            }
            let metadata = self.read_tool_original_page_at(
                snapshot,
                contextdb_service::ReadOriginalPageRequest {
                    context: context.clone(),
                    handle: contextdb_continuity::OriginalPageHandle {
                        database_id: self.database_id.clone(),
                        event_id: message.source.event_id,
                        payload_digest: message.source.payload_digest,
                        byte_length: message.source.end,
                    },
                    start: 0,
                    max_bytes: u32::try_from(message.source.end)
                        .map_err(|_| invalid("page metadata size is invalid"))?,
                    external_processing: checkpoint.model_profile.external_processing,
                },
                budget,
            )?;
            if metadata.view.preview != message.source {
                return Err(invalid(
                    "page metadata anchor differs from its authenticated bytes",
                ));
            }
            let bytes = metadata.bytes;
            let actual: ToolResultPageView = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("page result anchor is not captured page metadata"))?;
            if actual != *page || encode(&actual)? != bytes {
                return Err(invalid(
                    "tool page differs from its exact captured metadata",
                ));
            }
            self.authorized_capture_policy_with_budget(
                snapshot,
                context,
                request_event_id,
                budget,
            )?;
            self.authorize_derived_custody_with_budget(
                snapshot,
                context,
                request_event_id,
                budget,
            )?;
            let request =
                self.load_captured_original_with_budget(snapshot, request_event_id, budget)?;
            if request.event.kind != EventKind::ToolRequested
                || request.event.role != EventRole::Host
                || request.event.run_id != Some(checkpoint.identity.run_id)
                || request.event.session_id != Some(checkpoint.identity.session_id)
                || request.event.provenance
                    != Some(EventProvenance::Tool {
                        call_id,
                        request_event_id,
                        action_digest,
                    })
                || !request
                    .event
                    .parent_event_ids
                    .contains(&page.handle.event_id)
            {
                return Err(invalid(
                    "page result lacks its captured original-dependent request",
                ));
            }
            let action_bytes = request
                .event
                .payload
                .original_bytes()
                .filter(|bytes| bytes.len() <= 16 * 1024)
                .ok_or_else(|| invalid("page action metadata is unavailable or oversized"))?;
            let selector = captured_original_page_arguments(action_bytes, action_digest)?;
            if selector.handle != page.handle
                || page.preview.start < selector.start
                || page.preview.start - selector.start > 3
                || page.preview.end
                    > selector
                        .start
                        .saturating_add(u64::from(selector.max_bytes))
                        .min(page.handle.byte_length)
            {
                return Err(invalid(
                    "page result range differs from its captured selector",
                ));
            }
            if !original_in_run {
                // A recalled original from another run remains a separate source.
                // Its current-run metadata anchor must descend from this actual
                // page proposal and its captured source-disclosing model request.
                let proposal = checkpoint
                    .groups
                    .iter()
                    .flat_map(|group| &group.messages)
                    .find(|message| {
                        message.role == OutgoingRole::Assistant
                            && message.tool_calls.contains(&call_id.to_string())
                    })
                    .ok_or_else(|| {
                        invalid("recalled tool page lacks its current captured proposal")
                    })?;
                if !request
                    .event
                    .parent_event_ids
                    .contains(&proposal.source.event_id)
                {
                    return Err(invalid(
                        "recalled tool page request lacks its actual proposal parent",
                    ));
                }
                self.validate_original_page_disclosure_origin_at(
                    snapshot,
                    context,
                    checkpoint,
                    &proposal.source,
                    call_id,
                    &selector,
                    budget,
                )?;
            }
        }
        Ok(())
    }

    fn validate_pending_model<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        checkpoint: &OwnedRunCheckpoint,
    ) -> ServiceResult<()> {
        let Some(call) = &checkpoint.pending_model else {
            return Ok(());
        };
        if let Some(wire) = call.wire_digest {
            self.authorized_capture_policy(snapshot, context, call.request_event)?;
            self.authorize_capture_dependencies(snapshot, context, call.request_event)?;
            let original = self.load_captured_original(snapshot, call.request_event)?;
            if original.event.run_id != Some(checkpoint.identity.run_id)
                || original.event.session_id != Some(checkpoint.identity.session_id)
                || !matches!(&original.event.payload, EventPayload::Assembly { manifest }
                    if manifest.model_call_id == call.call_id && manifest.wire_digest == wire)
            {
                return Err(invalid(
                    "pending model wire differs from its captured request",
                ));
            }
        }
        if let Some(id) = call.interrupted_output {
            self.authorized_capture_policy(snapshot, context, id)?;
            self.authorize_capture_dependencies(snapshot, context, id)?;
            let original = self.load_captured_original(snapshot, id)?;
            if original.event.kind != EventKind::ModelResponseAborted
                || original.event.run_id != Some(checkpoint.identity.run_id)
                || original.event.session_id != Some(checkpoint.identity.session_id)
                || !matches!(&original.event.provenance, Some(EventProvenance::ModelOutput {
                    model_call_id, request_event_id, tool_calls, ..
                }) if *model_call_id == call.call_id
                    && *request_event_id == call.request_event && tool_calls.is_empty())
            {
                return Err(invalid(
                    "interrupted output differs from the pending model attempt",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn publish_checkpoint_head<T: WriteTransaction>(
        &self,
        tx: &mut T,
        request: &SaveRunCheckpointRequest,
        receipt: &CaptureReceipt,
    ) -> ServiceResult<()> {
        self.enable_capture_extension(tx, OWNED_FEATURE)?;
        if has_tool_pages(&request.checkpoint) {
            // Never remove the requirement when the current hot window changes:
            // accepted historical checkpoints and recovery controls retain it.
            self.enable_capture_extension(tx, TOOL_PAGES_FEATURE)?;
        }
        let head = RunHead {
            identity: request.checkpoint.identity.clone(),
            revision: request.checkpoint.revision,
            state_digest: request
                .checkpoint
                .digest()
                .map_err(|_| invalid("checkpoint digest failed"))?,
            receipt: receipt.clone(),
            producer_id: request.checkpoint.producer_id,
            status: request.checkpoint.status,
        };
        tx.put(
            &self.keyspaces.continuous,
            head_key(&request.context.request.workspace_id, head.identity.run_id),
            encode(&head)?,
        )
        .map_err(storage_error)
    }

    pub(super) fn replay_checkpoint_control(
        &self,
        control: &CheckpointControl,
        receipt: &CaptureReceipt,
        heads: &mut BTreeMap<Vec<u8>, RecoveredRunHead>,
    ) -> ServiceResult<()> {
        if control.workspace_id != receipt.workspace_id
            || control.revision != control.expected_revision.saturating_add(1)
        {
            return Err(integrity(
                "checkpoint recovery identity or revision differs",
            ));
        }
        let key = head_key(&control.workspace_id.to_string(), control.run_id);
        let previous = heads.get(&key).map(|head| &head.control);
        if previous.map_or(0, |head| head.revision) != control.expected_revision
            || previous.is_some_and(|head| {
                head.identity_digest != control.identity_digest
                    || head.producer_id != control.producer_id
                    || head.status != OwnedRunStatus::Active
            })
        {
            return Err(integrity(
                "accepted checkpoint history forks or changes its owner",
            ));
        }
        heads.insert(
            key,
            RecoveredRunHead {
                control: control.clone(),
                receipt: receipt.clone(),
            },
        );
        Ok(())
    }

    pub(super) fn verify_replayed_checkpoint_heads<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        heads: BTreeMap<Vec<u8>, RecoveredRunHead>,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut rows = BTreeMap::new();
        for (key, expected) in heads {
            let actual: RunHead = decode(
                &snapshot
                    .get(&self.keyspaces.continuous, &key)
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("replayed checkpoint head is absent"))?,
                "replayed checkpoint head",
            )?;
            if identity_digest(&actual.identity)? != expected.control.identity_digest
                || actual.revision != expected.control.revision
                || actual.state_digest != expected.control.state_digest
                || actual.receipt != expected.receipt
                || actual.producer_id != expected.control.producer_id
                || actual.status != expected.control.status
            {
                return Err(integrity(
                    "checkpoint head differs from accepted control history",
                ));
            }
            rows.insert(key, encode(&actual)?);
        }
        Ok(rows)
    }
}

pub(crate) fn captured_original_page_arguments(
    bytes: &[u8],
    digest: ContentDigest,
) -> ServiceResult<contextdb_continuity::OriginalPageArguments> {
    if bytes.len() > 16 * 1024
        || ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()) != digest
    {
        return Err(invalid("page action binding differs from its capture"));
    }
    let action: PageAction =
        serde_json::from_slice(bytes).map_err(|_| invalid("page action metadata is invalid"))?;
    if action.operation != contextdb_continuity::ORIGINAL_PAGE_OPERATION
        || action.expected_target_version.is_some()
        || encode(&action)? != bytes
    {
        return Err(invalid(
            "original page classification differs from the captured action",
        ));
    }
    contextdb_continuity::OriginalPageArguments::from_json(&action.input)
        .map_err(|_| invalid("original page selector is invalid or exceeds its declared bounds"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageAction {
    operation: String,
    input: Vec<u8>,
    expected_target_version: Option<String>,
}

impl CheckpointControl {
    pub(super) fn requires_tool_pages(&self) -> bool {
        self.tool_pages
    }

    pub(super) fn from_event(event: &EventEnvelope) -> ServiceResult<Option<Self>> {
        let Some(EventProvenance::OwnedCheckpoint {
            expected_revision,
            state_digest,
        }) = event.provenance
        else {
            return Ok(None);
        };
        let checkpoint = decode_checkpoint(event)?;
        if checkpoint
            .digest()
            .map_err(|_| integrity("invalid accepted checkpoint"))?
            != state_digest
            || checkpoint.revision != expected_revision.saturating_add(1)
            || checkpoint.identity.workspace_id != event.workspace_id
            || Some(checkpoint.identity.session_id) != event.session_id
            || Some(checkpoint.identity.run_id) != event.run_id
            || checkpoint.identity.scopes != event.scope_ids
            || checkpoint.producer_id != event.producer_id
            || checkpoint.next_sequence != event.producer_sequence.saturating_add(1)
            || checkpoint.recorded_at != event.recorded_at
        {
            return Err(integrity("checkpoint event identity or provenance differs"));
        }
        Ok(Some(Self {
            workspace_id: checkpoint.identity.workspace_id,
            run_id: checkpoint.identity.run_id,
            identity_digest: identity_digest(&checkpoint.identity)?,
            expected_revision,
            revision: checkpoint.revision,
            state_digest,
            producer_id: checkpoint.producer_id,
            next_sequence: checkpoint.next_sequence,
            status: checkpoint.status,
            tool_pages: has_tool_pages(&checkpoint),
        }))
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn has_tool_pages(checkpoint: &OwnedRunCheckpoint) -> bool {
    checkpoint
        .groups
        .iter()
        .flat_map(|group| &group.messages)
        .any(|message| message.tool_page.is_some())
}

pub(super) fn require_tool_page_feature(
    checkpoint: &OwnedRunCheckpoint,
    features: &BTreeSet<String>,
) -> ServiceResult<()> {
    if has_tool_pages(checkpoint) && !features.contains(TOOL_PAGES_FEATURE) {
        return Err(integrity("checkpoint tool page format feature is absent"));
    }
    Ok(())
}

fn identity_digest(identity: &OwnedRunIdentity) -> ServiceResult<ContentDigest> {
    Ok(ContentDigest::from_bytes(
        *blake3::hash(&encode(identity)?).as_bytes(),
    ))
}

fn check_identity(
    context: &AuthenticatedRequestContext,
    identity: &OwnedRunIdentity,
) -> ServiceResult<()> {
    if context.request.workspace_id != identity.workspace_id.to_string()
        || context.session_id.as_deref() != Some(identity.session_id.to_string().as_str())
        || context.actor_id != identity.actor_id
        || context.agent_id != identity.agent_id
        || context.request.subject_id != identity.subject_id
        || context.request.scopes != identity.scopes.iter().map(ToString::to_string).collect()
    {
        return Err(permission_denied());
    }
    Ok(())
}
pub(super) fn decode_checkpoint(event: &EventEnvelope) -> ServiceResult<OwnedRunCheckpoint> {
    let bytes = event
        .payload
        .original_bytes()
        .ok_or_else(|| integrity("checkpoint source unavailable"))?;
    let checkpoint: OwnedRunCheckpoint = decode(bytes, "operational checkpoint")?;
    checkpoint
        .validate()
        .map_err(|_| integrity("operational checkpoint invariant failed"))?;
    if encode(&checkpoint)? != bytes {
        return Err(integrity("noncanonical checkpoint payload"));
    }
    Ok(checkpoint)
}
fn head_key(workspace: &str, run: AgentRunId) -> Vec<u8> {
    format!("runhead/{}/{run}", digest_bytes(workspace.as_bytes())).into_bytes()
}

#[cfg(test)]
mod tests;
