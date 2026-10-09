//! Current authorized reads of the existing accepted occurrence, without writes.

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::io;

use contextdb_context::router::{canonical_digest as router_digest, validate_router_material};
use contextdb_core::{ContentDigest, EventPayload, MAX_ROUTER_TRACE_BYTES};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AcceptedRouterTraceLineage, AcceptedRouterTracePort, AcceptedRouterTraceRead,
    AcceptedRouterTraceReadResult, AcceptedRouterTraceUnavailable, Capability, ErrorCode,
    NATIVE_CAPTURE_DOMAIN, ReadAcceptedRouterTraceRequest, ServiceError, ServiceResult,
};
use contextdb_storage::{ReadSnapshot, SnapshotSelector, StorageEngine};
use serde::Serialize;

use super::controls::RouterTraceControls;
use super::{decode_envelope, trace_error};
use crate::raw_index::budget_error;
use crate::{
    NativeService, StoredEvent, decode, digest_bytes, exhausted, integrity, require_capability,
    storage_error,
};

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_CAPTURE_CONTROL_BYTES: usize = 2 * 1024 * 1024;
const MAX_CAPTURE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = MAX_ROUTER_TRACE_BYTES + 128 * 1024;

impl AcceptedRouterTracePort for NativeService {
    fn read_accepted_router_trace(
        &self,
        request: ReadAcceptedRouterTraceRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AcceptedRouterTraceReadResult> {
        // These are the existing original-read and exact-receipt capabilities.
        // Admin alone supplies none of them and the caller's purpose is unchanged.
        for capability in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
        ] {
            require_capability(&request.context, capability)?;
        }
        budget.check().map_err(budget_error)?;
        let request_bytes = bounded_size(&request, MAX_REQUEST_BYTES)?;
        budget
            .charge(1, request_bytes as u64)
            .map_err(budget_error)?;
        let context = &request.context;
        let receipt = &request.receipt;
        if receipt.domain != NATIVE_CAPTURE_DOMAIN
            || receipt.database_id != self.database_id
            || receipt.workspace_id.to_string() != context.request.workspace_id
        {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "capture receipt belongs to another store or sequence domain",
                false,
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        budget.charge(1, 0).map_err(budget_error)?;
        let policy = self.authorized_capture_policy_with_budget(
            &snapshot,
            context,
            receipt.event_id,
            budget,
        )?;

        // Resolve the exact accepted publication at this same snapshot. This
        // metadata/journal path does not load original payload or trace pages.
        let metadata_key = format!("receipt/{}", receipt.event_id).into_bytes();
        budget.charge(1, 0).map_err(budget_error)?;
        let metadata = snapshot
            .get(&self.keyspaces.continuous, &metadata_key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("accepted trace capture metadata is absent"))?;
        if metadata.len() > MAX_CAPTURE_CONTROL_BYTES {
            return Err(integrity(
                "accepted trace capture metadata exceeds its bound",
            ));
        }
        budget
            .charge(1, metadata.len() as u64)
            .map_err(budget_error)?;
        let stored = self.captured_receipt_metadata(&snapshot, receipt.event_id)?;
        let (global, _) = self.select_snapshot(
            &snapshot,
            &context.request.workspace_id,
            Some(receipt.workspace_commit),
        )?;
        if stored != *receipt || global != policy.accepted_global_commit {
            return Err(crate::invalid(
                "capture receipt does not match its durable publication",
            ));
        }
        budget.charge(1, 0).map_err(budget_error)?;
        let journal_bytes = snapshot
            .get(&self.keyspaces.events, &global.to_be_bytes())
            .map_err(storage_error)?
            .ok_or_else(|| integrity("accepted trace capture journal is absent"))?;
        if journal_bytes.len() > MAX_CAPTURE_BODY_BYTES {
            return Err(integrity("accepted trace journal exceeds its bound"));
        }
        budget
            .charge(1, journal_bytes.len() as u64)
            .map_err(budget_error)?;
        let journal: StoredEvent = decode(&journal_bytes, "accepted trace journal")?;
        let work = self.capture_work_for_receipt(&snapshot, receipt)?;
        if journal.operation != "capture"
            || journal.global_commit != global
            || journal.workspace_commit != receipt.workspace_commit
            || journal.workspace_digest != digest_bytes(context.request.workspace_id.as_bytes())
            || journal.accepted_original.as_ref() != Some(&work)
            || journal.response_digest != crate::canonical_digest(receipt)?
            || journal.event_digest != crate::event_digest(&journal)?
        {
            return Err(integrity(
                "accepted trace receipt has no matching native journal",
            ));
        }
        self.verify_capture_journal_reference(&snapshot, &journal)?;
        let (metadata_receipt, recovery) =
            self.capture_recovery_metadata(&snapshot, receipt.event_id, budget)?;
        if metadata_receipt != *receipt {
            return Err(integrity("accepted trace recovery receipt differs"));
        }
        if recovery
            .as_ref()
            .is_some_and(|recovery| recovery.router_trace.is_some())
            && !self.engine.is_encrypted()
        {
            return Err(integrity(
                "accepted protected trace requires encrypted custody",
            ));
        }
        let controls = if let Some(recovery) = &recovery {
            self.authorize_derived_custody_with_inputs(
                &snapshot,
                context,
                receipt.event_id,
                &recovery.inputs,
                budget,
            )?
        } else {
            self.authorize_derived_custody_with_budget(
                &snapshot,
                context,
                receipt.event_id,
                budget,
            )?
        };

        // Conservative bounded admission precedes the owner's body decoder and
        // every response/header/lineage clone. Shared budget is never reset.
        budget
            .charge(1, (MAX_CAPTURE_BODY_BYTES + MAX_RESPONSE_BYTES) as u64)
            .map_err(budget_error)?;
        let body_key = digest_bytes(receipt.event_id.to_string().as_bytes());
        if let Some(bytes) = snapshot
            .get(&self.keyspaces.observations_content, body_key.as_bytes())
            .map_err(storage_error)?
            && bytes.len() > MAX_CAPTURE_BODY_BYTES
        {
            return Err(integrity(
                "accepted trace original exceeds its native row bound",
            ));
        }
        let control = self.verified_capture_control(&snapshot, receipt.event_id, budget)?;
        if control.receipt != *receipt {
            return Err(integrity(
                "accepted trace control differs from its exact receipt",
            ));
        }
        let Some(event) = control.original else {
            return Ok(AcceptedRouterTraceReadResult::Unavailable(
                AcceptedRouterTraceUnavailable::Pruned,
            ));
        };
        let Some(header) = control.recovery.router_trace else {
            return Ok(AcceptedRouterTraceReadResult::Unavailable(
                AcceptedRouterTraceUnavailable::LegacyOff,
            ));
        };
        if header.byte_length as usize > MAX_ROUTER_TRACE_BYTES {
            return Err(integrity("accepted trace envelope exceeds its profile"));
        }
        let controls =
            controls.ok_or_else(|| integrity("accepted trace lacks retained origin custody"))?;
        let EventPayload::Assembly { manifest } = &event.payload else {
            return Err(integrity(
                "accepted trace occurrence is not a model request assembly",
            ));
        };
        if manifest.router_trace.as_ref().map(|trace| &trace.header) != Some(&header) {
            return Err(integrity("accepted trace header differs from its original"));
        }
        let envelope = decode_envelope(&event, budget)?
            .ok_or_else(|| integrity("accepted trace pages are absent"))?;
        envelope
            .manifest
            .validate_observation(&envelope.request, &envelope.plan, budget)
            .map_err(|error| match error {
                contextdb_context::ContextError::BudgetExceeded(_) => trace_error(error),
                _ => integrity(
                    "accepted router manifest differs from retained compiler observations",
                ),
            })?;
        let verification = validate_router_material(&envelope.request, &envelope.materials, budget)
            .map_err(|error| match error {
                contextdb_context::ContextError::BudgetExceeded(_) => trace_error(error),
                _ => integrity("accepted router material differs from compiler commitments"),
            })?;
        let lineage = lineage(&controls, budget)?;
        let result = AcceptedRouterTraceRead {
            receipt: request.receipt,
            header,
            request: envelope.request,
            plan: envelope.plan,
            manifest: envelope.manifest,
            base: envelope.base,
            material: envelope.materials,
            replay_observation: envelope.replay_observation,
            verification,
            lineage,
        };
        bounded_size(&result, MAX_RESPONSE_BYTES)?;
        budget.check().map_err(budget_error)?;
        Ok(AcceptedRouterTraceReadResult::Complete(Box::new(result)))
    }
}

fn lineage(
    controls: &RouterTraceControls,
    budget: &mut QueryBudget,
) -> ServiceResult<AcceptedRouterTraceLineage> {
    Ok(AcceptedRouterTraceLineage {
        originals: controls.originals.clone(),
        record_versions: controls
            .records
            .iter()
            .map(|record| router_digest(record, budget).map_err(trace_error))
            .collect::<ServiceResult<BTreeSet<ContentDigest>>>()?,
        state_versions: controls
            .states
            .iter()
            .map(|state| router_digest(state, budget).map_err(trace_error))
            .collect::<ServiceResult<BTreeSet<ContentDigest>>>()?,
        custody_closure_digest: router_digest(controls, budget).map_err(trace_error)?,
    })
}

fn bounded_size(value: &impl Serialize, maximum: usize) -> ServiceResult<usize> {
    let mut count = Size { bytes: 0, maximum };
    serde_json::to_writer(&mut count, value)
        .map_err(|_| exhausted("accepted router trace read exceeds its bounded profile"))?;
    Ok(count.bytes)
}

struct Size {
    bytes: usize,
    maximum: usize,
}
impl io::Write for Size {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(bytes.len());
        if self.bytes > self.maximum {
            return Err(io::Error::other("accepted trace read byte ceiling"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
