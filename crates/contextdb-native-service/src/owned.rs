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

impl OwnedRunPort for NativeService {
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
        let original = self.load_captured_original(&snapshot, checkpoint.event_id)?;
        if original.receipt != *checkpoint {
            return Err(invalid("checkpoint receipt differs"));
        }
        let state = decode_checkpoint(&original.event)?;
        check_identity(context, &state.identity)?;
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
    ) -> ServiceResult<OwnedRunCheckpoint> {
        self.authorized_capture_policy(snapshot, context, receipt.event_id)?;
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
        Ok(checkpoint)
    }

    pub(super) fn validate_checkpoint_publication<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        request: &SaveRunCheckpointRequest,
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
            self.source_span(snapshot, Some(&request.context), source, true)?;
        }
        self.validate_pending_model(snapshot, &request.context, &request.checkpoint)?;
        if let Some(id) = request.checkpoint.last_model_output {
            self.authorized_capture_policy(snapshot, &request.context, id)?;
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

    pub(super) fn replay_checkpoint_head(
        &self,
        event: &EventEnvelope,
        receipt: &CaptureReceipt,
        heads: &mut BTreeMap<Vec<u8>, RunHead>,
    ) -> ServiceResult<()> {
        let Some(EventProvenance::OwnedCheckpoint {
            expected_revision,
            state_digest,
        }) = event.provenance
        else {
            return Ok(());
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
        let key = head_key(&event.workspace_id.to_string(), checkpoint.identity.run_id);
        let previous = heads.get(&key);
        if previous.map_or(0, |head| head.revision) != expected_revision
            || previous.is_some_and(|head| {
                head.identity != checkpoint.identity
                    || head.producer_id != checkpoint.producer_id
                    || head.status != OwnedRunStatus::Active
            })
        {
            return Err(integrity(
                "accepted checkpoint history forks or changes its owner",
            ));
        }
        heads.insert(
            key,
            RunHead {
                identity: checkpoint.identity,
                revision: checkpoint.revision,
                state_digest,
                receipt: receipt.clone(),
                producer_id: checkpoint.producer_id,
                status: checkpoint.status,
            },
        );
        Ok(())
    }
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
fn decode_checkpoint(event: &EventEnvelope) -> ServiceResult<OwnedRunCheckpoint> {
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
