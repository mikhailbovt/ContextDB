//! Whole accepted request bytes in the same current owner-authorized snapshot.

#[cfg(test)]
mod tests;

use contextdb_context::router::{RouterHistoricalReplayResult, RouterMaterialStatus};
use contextdb_context::{ContextCompiler, ContextError, RequestCountKind};
use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AcceptedRouterSourceWirePort, Capability, CurrentSourceWireStatus,
    CurrentSourceWireUnavailableReason, CurrentSourceWireVerification,
    CurrentSourceWireVerificationResult, ErrorCode, ReadAcceptedRouterTraceRequest,
    RouterSourceWireRuntime, ServiceError, ServiceResult,
};
use contextdb_storage::{ReadSnapshot, SnapshotSelector, StorageEngine};

use super::read::AcceptedRouterTraceAt;
use super::{router_digest, trace_error};
use crate::raw_index::budget_error;
use crate::{NativeService, integrity, require_capability, storage_error};

impl AcceptedRouterSourceWirePort for NativeService {
    fn verify_accepted_router_source_wire(
        &self,
        request: ReadAcceptedRouterTraceRequest,
        runtime: Option<RouterSourceWireRuntime<'_>>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CurrentSourceWireVerificationResult> {
        if runtime.is_some() {
            // Optional trusted integrations may process all retained text. The
            // existing host grant is required before any protected body load.
            require_capability(&request.context, Capability::ModelProcessing)?;
        }
        self.check_accepted_router_trace_request(&request, budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let loaded = match self.load_accepted_router_trace_at(&snapshot, &request, budget)? {
            AcceptedRouterTraceAt::Unavailable(reason) => {
                return Ok(CurrentSourceWireVerificationResult::Unavailable(reason));
            }
            AcceptedRouterTraceAt::Complete(loaded) => loaded,
        };
        let wire = self
            .assemble_request_with_budget(
                &snapshot,
                &request.context,
                &loaded.actual_model_request,
                budget,
            )
            .map_err(accepted_source_error)?;
        budget.charge(1, 0).map_err(budget_error)?;
        let wire_digest = ContentDigest::from_bytes(*blake3::hash(&wire).as_bytes());
        budget.check().map_err(budget_error)?;
        let wire_byte_length = wire.len() as u64;
        if wire_digest != loaded.actual_model_request.wire_digest
            || wire_digest != loaded.header.wire_digest
            || wire_digest != loaded.envelope.plan.wire_digest
            || wire_digest != loaded.envelope.manifest.assembly.wire_digest
            || request.receipt.payload_digest != Some(wire_digest)
            || wire_byte_length != loaded.actual_model_request.byte_length
            || wire_byte_length != loaded.header.wire_byte_length
        {
            return Err(integrity(
                "accepted source bytes differ from their wire commitments",
            ));
        }
        let envelope = &loaded.envelope;
        let missing = if envelope
            .materials
            .prepared_policy
            .as_ref()
            .and_then(|policy| policy.replay.as_ref())
            .is_none()
        {
            Some(CurrentSourceWireUnavailableReason::MissingReplayPreparation)
        } else if runtime.is_none() {
            Some(CurrentSourceWireUnavailableReason::MissingRuntime)
        } else {
            None
        };
        let (historical_selection, trusted_token_count, trusted_input_tokens) =
            if let Some(reason) = missing {
                (
                    CurrentSourceWireStatus::Unavailable(reason),
                    CurrentSourceWireStatus::Unavailable(reason),
                    None,
                )
            } else {
                let runtime =
                    runtime.ok_or_else(|| integrity("trusted source-wire runtime is absent"))?;
                let observation = envelope
                    .replay_observation
                    .as_ref()
                    .ok_or_else(|| integrity("accepted replay observation is absent"))?;
                let replay = ContextCompiler::replay_router_r0(
                    &envelope.request,
                    &envelope.plan,
                    &envelope.manifest,
                    &envelope.base,
                    &envelope.materials,
                    observation,
                    runtime.tokenizer,
                    runtime.encoder,
                    budget,
                )
                .map_err(|error| match error {
                    ContextError::BudgetExceeded(_) => trace_error(error),
                    _ => integrity("accepted source-wire historical replay is inconsistent"),
                })?;
                budget.check().map_err(budget_error)?;
                match replay {
                    RouterHistoricalReplayResult::Unavailable(reason) => {
                        let status = CurrentSourceWireStatus::Unavailable(
                            CurrentSourceWireUnavailableReason::Replay(reason),
                        );
                        (status, status, None)
                    }
                    RouterHistoricalReplayResult::Complete(replayed) => {
                        if replayed.assembly.outgoing.wire != wire
                            || replayed.score_selection != RouterMaterialStatus::Verified
                            || replayed.material_wire != RouterMaterialStatus::Verified
                        {
                            return Err(integrity(
                                "historical replay wire differs from current source bytes",
                            ));
                        }
                        let count = if replayed.token_count == RouterMaterialStatus::Verified
                            && replayed.assembly.outgoing.count_kind == RequestCountKind::Exact
                        {
                            (
                                CurrentSourceWireStatus::Verified,
                                Some(replayed.assembly.outgoing.input_tokens),
                            )
                        } else {
                            (
                                CurrentSourceWireStatus::Unavailable(
                                    CurrentSourceWireUnavailableReason::NonExactRequestCount,
                                ),
                                None,
                            )
                        };
                        (CurrentSourceWireStatus::Verified, count.0, count.1)
                    }
                }
            };
        let current_authority_binding = router_digest(
            &(
                "contextdb.current-source-wire.v1",
                &self.database_id,
                snapshot.sequence(),
                &request.context,
                &request.receipt,
                &loaded.controls,
                loaded.header.trace_digest,
                wire_digest,
            ),
            budget,
        )
        .map_err(trace_error)?;
        budget.check().map_err(budget_error)?;
        Ok(CurrentSourceWireVerificationResult::Complete(Box::new(
            CurrentSourceWireVerification {
                receipt: request.receipt,
                header: loaded.header,
                wire_digest,
                wire_byte_length,
                current_authority_binding,
                current_custody: CurrentSourceWireStatus::Verified,
                source_wire: CurrentSourceWireStatus::Verified,
                historical_selection,
                trusted_token_count,
                trusted_input_tokens,
            },
        )))
    }
}

fn accepted_source_error(error: ServiceError) -> ServiceError {
    match error.code {
        ErrorCode::InvalidArgument | ErrorCode::NotFound => {
            integrity("accepted request source or transform binding is invalid")
        }
        // Current denial, custody/removal barriers, shared allowance and actual
        // unavailable source evidence are never converted into Pruned absence.
        _ => error,
    }
}
