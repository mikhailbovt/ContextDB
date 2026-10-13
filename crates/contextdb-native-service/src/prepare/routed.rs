//! One native owner prepares a routed step under its original parent allowance.

use super::*;
use crate::encryption::NativeSnapshot;
use crate::raw_index::dense::graph::routing::query::VerifiedRoutedQueryView;
use crate::raw_index::dense::graph::routing::status::NativeRoutedMaintenanceTarget;
use contextdb_service::{OwnedHybridIntent, TextEmbeddingAdapter};
use std::time::Instant;

const RAW_BATCHES: u8 = 8;
const RAW_EVENTS: u32 = 64;
const DENSE_BATCHES: u8 = 8;
const DENSE_EVENTS: u64 = 4;

/// Process-local elapsed times; these grant no preparation or dispatch authority.
#[derive(Debug, Default)]
pub struct NativeRoutedPreparationTimings {
    /// Bounded raw/dense maintenance, including its initial owner admission.
    pub hook_micros: u64,
    /// Context preparation after maintenance, including all model callbacks.
    pub prepare_micros: u64,
}

/// A same-snapshot serving frame created only by the native owner.
pub(crate) struct RoutedPreparationAdmission {
    pub(crate) snapshot: NativeSnapshot,
    pub(crate) world: crate::WorkspaceState,
    pub(crate) view: VerifiedRoutedQueryView,
}

fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

fn capacity() -> ServiceError {
    ServiceError::new(
        contextdb_service::ErrorCode::ResourceExhausted,
        "routed fresh capacity requires maintenance before another model step",
        true,
    )
}

impl NativeService {
    /// Advance bounded original projection and prepare from its admitted snapshot.
    ///
    /// The owner authenticates the current checkpoint before source callbacks.
    /// Every operation, refresh and callback fence charges the supplied parent.
    #[expect(
        clippy::too_many_arguments,
        reason = "An owned step binds its exact request and three trusted adapters"
    )]
    pub fn prepare_context_with_routed_maintenance(
        &self,
        request: PrepareContextRequest,
        intent: OwnedHybridIntent,
        tokenizer: &dyn TokenCounter,
        outgoing: &dyn OutgoingEncoder,
        query_encoder: &dyn TextEmbeddingAdapter,
        parent: &mut QueryBudget,
        timings: &mut NativeRoutedPreparationTimings,
    ) -> ServiceResult<PreparedContext> {
        let started = Instant::now();
        let maintenance = (|| {
            // The existing uninterpreted hook and routed scalar admission retain
            // their charges. No per-batch child budget or deadline is created.
            parent.charge(2, 256).map_err(budget_error)?;
            self.admit_routed_maintenance_request(&request, &intent, parent)?;
            query_encoder.profile().validate()?;
            let mut caught_up = false;
            for _ in 0..RAW_BATCHES {
                let raw =
                    self.project_originals_bm25(&request.context, false, RAW_EVENTS, parent)?;
                if raw.caught_up {
                    caught_up = true;
                    break;
                }
            }
            if !caught_up {
                return Err(capacity());
            }
            let mut seed = self.routed_status_admission_seed(&request.context, parent)?;
            for _ in 0..DENSE_BATCHES {
                let target = seed.target();
                let (through, global, fresh_spans) =
                    admit_target(target, query_encoder, intent.limits, parent)?;
                if target.dense.as_ref().is_some_and(|dense| dense.caught_up)
                    && target.dense_matches_raw
                {
                    return Ok(seed);
                }
                // CaptureWork also includes omitted controls. Its worst case is
                // sixty-four real spans per event, before invoking the encoder.
                let batch = ((u64::from(intent.limits.tail_vectors) - fresh_spans) / 64)
                    .min(DENSE_EVENTS) as u32;
                if batch == 0 {
                    return Err(capacity());
                }
                self.project_original_spans(&request.context, query_encoder, batch, parent)?;
                seed = self.refresh_routed_status_admission_seed(seed, &request.context, parent)?;
                let (after_through, after_global, _) =
                    admit_target(seed.target(), query_encoder, intent.limits, parent)?;
                if after_through <= through || after_global <= global {
                    return Err(capacity());
                }
                if seed
                    .target()
                    .dense
                    .as_ref()
                    .is_some_and(|dense| dense.caught_up)
                    && seed.target().dense_matches_raw
                {
                    return Ok(seed);
                }
            }
            Err(capacity())
        })();
        timings.hook_micros = timings.hook_micros.saturating_add(elapsed(started));
        let seed = maintenance?;
        let started = Instant::now();
        let result = (|| {
            let frame = self.routed_query_view_from_status_seed(seed, &request.context, parent)?;
            self.prepare_context_inner(
                request,
                tokenizer,
                outgoing,
                Some((intent, query_encoder)),
                Some(frame),
                parent,
            )
        })();
        timings.prepare_micros = timings.prepare_micros.saturating_add(elapsed(started));
        result
    }

    fn admit_routed_maintenance_request(
        &self,
        request: &PrepareContextRequest,
        intent: &OwnedHybridIntent,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        intent.validate()?;
        if intent.limits.routed.is_none()
            || intent.limits.segments.is_some()
            || request.router_trace_profile != RouterTraceProfile::RequiredReplayV2
            || request.known_at.is_some()
            || request.valid_at.is_some()
            || request.after_receipt.is_none()
            || !request.raw_queries.is_empty()
            || request.bm25_query.is_some()
            || request.memory_query.is_some()
            || request.explicit_memory_request
            || request.required_facets.len() > 32
            || request.context.request.scopes.is_empty()
            || request.context.request.scopes.len() > 32
            || request.memory_budget.max_blocks > 512
            || request.memory_budget.max_evidence_blocks > 2048
            || request.memory_budget.max_selection_evaluations > 4096
            || contextdb_recall::purpose_key(&request.purpose.core_purpose())
                != request.context.request.purpose
        {
            return Err(invalid(
                "native routed maintenance requires the current bounded owned request",
            ));
        }
        let cost = crate::budgeted::auth::ContextCost::for_context(&request.context, parent)?;
        for capability in [
            Capability::Runtime,
            Capability::Admin,
            Capability::Recall,
            Capability::ReadMemory,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(&request.context, capability, parent)?;
        }
        for scope in &request.context.request.scopes {
            parent.charge(1, 0).map_err(budget_error)?;
            scope
                .parse::<ScopeId>()
                .map_err(|_| invalid("continuous scopes must be typed scope IDs"))?;
        }
        for message in &request.base.control {
            parent.charge(128, 0).map_err(budget_error)?;
            if matches!(
                message.id.as_str(),
                "contextdb.bm25-discovery-status.v1" | "contextdb.hybrid-discovery-status.v1"
            ) {
                return Err(invalid(
                    "owned query base uses a reserved native status identity",
                ));
            }
        }
        let checkpoint = request
            .after_receipt
            .as_ref()
            .ok_or_else(|| invalid("owned routed checkpoint absent"))?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let admission = self.admit_owned_query(
            &snapshot,
            &request.context,
            checkpoint,
            &request.model_profile,
            intent.call_id,
            intent.request_event,
            intent.interaction_sequence,
            parent,
        )?;
        self.validate_owned_query_base(&admission, &request.base, parent)
    }
}

fn admit_target(
    target: &NativeRoutedMaintenanceTarget,
    encoder: &dyn TextEmbeddingAdapter,
    limits: contextdb_service::OwnedHybridLimits,
    parent: &mut QueryBudget,
) -> ServiceResult<(u64, u64, u64)> {
    let dense = target
        .dense
        .as_ref()
        .ok_or_else(crate::raw_index::stale_index)?;
    let covered = target
        .covered
        .as_ref()
        .ok_or_else(crate::raw_index::stale_index)?;
    if target.base.is_none() || target.router.is_none() || !target.router_matches_directory {
        return Err(crate::raw_index::stale_index());
    }
    parent.charge(1, 32 * 1024).map_err(budget_error)?;
    encoder.profile().validate()?;
    if encoder.profile() != &dense.profile
        || dense.profile != covered.profile
        || dense.profile_digest != covered.profile_digest
        || dense.profile.digest()? != dense.profile_digest
        || dense.generation != target.generation
        || covered.generation != target.generation
        || dense.authorization_epoch != target.authorization_epoch
        || covered.authorization_epoch != target.authorization_epoch
        || target.directory.is_some() != target.directory_ref.is_some()
    {
        return Err(crate::integrity(
            "routed maintenance profile or native target changed",
        ));
    }
    let work = target
        .raw_through
        .checked_sub(covered.through)
        .ok_or_else(|| crate::integrity("routed raw coverage moved backwards"))?;
    let spans = dense
        .spans
        .checked_sub(covered.spans)
        .ok_or_else(|| crate::integrity("routed dense coverage moved backwards"))?;
    if work > u64::from(limits.tail_work) || spans > u64::from(limits.tail_vectors) {
        return Err(capacity());
    }
    Ok((dense.through, dense.global_commit, spans))
}
