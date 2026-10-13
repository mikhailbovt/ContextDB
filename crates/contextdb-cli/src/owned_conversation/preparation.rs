//! Advance bounded raw, then dense prefixes without interpreting originals.

use std::sync::Arc;

use contextdb_agent_runtime::{
    KeepUninterpreted, OwnedHybridPreparer, PreparationHook, PreparationPhaseTimings,
};
use contextdb_context::{OutgoingEncoder, TokenCounter};
use contextdb_native_service::{NativeRoutedPreparationTimings, NativeService};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, ErrorCode, OwnedHybridIntent, OwnedHybridLimits,
    PrepareContextRequest, PreparedContext, ServiceError, ServiceResult, TextEmbeddingAdapter,
};

pub(super) const PROFILE: &str = "keep-uninterpreted+native-raw-outbox-advance.v1";
pub(super) const MAX_BATCHES: u8 = 8;
pub(super) const BATCH_EVENTS: u32 = 256;
pub(super) const HYBRID_PROFILE: &str = "keep-uninterpreted+native-bm25-dense-tail-advance.v1";
pub(super) const HYBRID_MAX_BATCHES: u8 = 8;
pub(super) const HYBRID_BATCH_EVENTS: u32 = 64;
pub(super) const ROUTED_PROFILE: &str = "keep-uninterpreted+native-bm25-routed-tail-bounded.v2";
pub(super) const ROUTED_BATCH_EVENTS: u32 = 4;
pub(super) const ROUTED_MAX_BATCHES: u8 = 8;

mod routed;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(super) struct NativePreparation {
    owner: Arc<NativeService>,
    hybrid: Option<Arc<dyn TextEmbeddingAdapter>>,
    routed: Option<OwnedHybridLimits>,
}

impl NativePreparation {
    pub(super) fn new(owner: Arc<NativeService>) -> Self {
        Self {
            owner,
            hybrid: None,
            routed: None,
        }
    }

    pub(super) fn with_hybrid(
        owner: Arc<NativeService>,
        encoder: Arc<dyn TextEmbeddingAdapter>,
    ) -> Self {
        Self {
            owner,
            hybrid: Some(encoder),
            routed: None,
        }
    }

    pub(super) fn with_routed(
        owner: Arc<NativeService>,
        encoder: Arc<dyn TextEmbeddingAdapter>,
        limits: OwnedHybridLimits,
    ) -> Self {
        Self {
            owner,
            hybrid: Some(encoder),
            routed: Some(limits),
        }
    }

    fn admit_composite_configuration(
        &self,
        intent: &OwnedHybridIntent,
        query_encoder: &dyn TextEmbeddingAdapter,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let installed = self.routed.ok_or_else(|| {
            ServiceError::new(
                ErrorCode::InvalidArgument,
                "composite preparation requires the installed routed profile",
                false,
            )
        })?;
        let encoder = self.hybrid.as_ref().ok_or_else(|| {
            ServiceError::new(
                ErrorCode::InvalidArgument,
                "composite preparation requires its installed encoder",
                false,
            )
        })?;
        // Both profiles have bounded fields; pay validation and equality work.
        parent.charge(8192, 0).map_err(|_| {
            ServiceError::new(
                ErrorCode::BudgetExhausted,
                "composite preparation parent allowance exhausted",
                false,
            )
        })?;
        installed.validate()?;
        intent.validate()?;
        encoder.profile().validate()?;
        query_encoder.profile().validate()?;
        if installed.routed.is_none()
            || installed.segments.is_some()
            || intent.limits != installed
            || query_encoder.profile() != encoder.profile()
        {
            return Err(ServiceError::new(
                ErrorCode::IntegrityFailure,
                "composite preparation differs from the installed limits or encoder profile",
                false,
            ));
        }
        Ok(())
    }
}

impl PreparationHook for NativePreparation {
    fn owned_hybrid_preparer(&self) -> Option<&dyn OwnedHybridPreparer> {
        self.routed.map(|_| self as &dyn OwnedHybridPreparer)
    }

    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        KeepUninterpreted.before_prepare(context, budget)?;
        if let Some(limits) = self.routed {
            let encoder = self.hybrid.as_ref().ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::InvalidArgument,
                    "routed preparation requires its configured encoder",
                    false,
                )
            })?;
            return routed::advance(&self.owner, context, encoder.as_ref(), limits, budget);
        }
        if let Some(encoder) = &self.hybrid {
            // A fresh raw generation is not active until its complete bounded
            // catch-up finishes. Dense publication requires that accepted base.
            let mut raw_caught_up = false;
            for _ in 0..HYBRID_MAX_BATCHES {
                let raw = self.owner.project_originals_bm25(
                    context,
                    false,
                    HYBRID_BATCH_EVENTS,
                    budget,
                )?;
                if raw.caught_up {
                    raw_caught_up = true;
                    break;
                }
            }
            if !raw_caught_up {
                return Err(ServiceError::new(
                    ErrorCode::ResourceExhausted,
                    "hybrid raw catch-up exceeded the host allowance; retained work requires explicit continuation",
                    true,
                ));
            }
            for _ in 0..HYBRID_MAX_BATCHES {
                let dense = self.owner.project_original_spans(
                    context,
                    encoder.as_ref(),
                    HYBRID_BATCH_EVENTS,
                    budget,
                )?;
                if dense.caught_up {
                    return Ok(());
                }
            }
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "hybrid dense catch-up exceeded the host allowance; retained work requires explicit continuation",
                true,
            ));
        }
        // The native publication owner verifies authorization, generation and
        // source custody on every batch. Stale generations require an operator;
        // this host never rebuilds or relaxes the interactive query's guard.
        for _ in 0..MAX_BATCHES {
            let progress = self
                .owner
                .project_originals(context, false, BATCH_EVENTS, budget)?;
            if progress.caught_up {
                return Ok(());
            }
        }
        Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "raw index catch-up exceeded the host allowance; retained work requires explicit continuation",
            true,
        ))
    }
}

impl OwnedHybridPreparer for NativePreparation {
    fn prepare_owned_hybrid(
        &self,
        request: PrepareContextRequest,
        intent: OwnedHybridIntent,
        tokenizer: &dyn TokenCounter,
        outgoing: &dyn OutgoingEncoder,
        query_encoder: &dyn TextEmbeddingAdapter,
        parent: &mut QueryBudget,
        timings: &mut PreparationPhaseTimings,
    ) -> ServiceResult<PreparedContext> {
        let started = std::time::Instant::now();
        timings.prepare_micros = 0;
        let admitted = self.admit_composite_configuration(&intent, query_encoder, parent);
        timings.hook_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        admitted?;
        let mut native_timings = NativeRoutedPreparationTimings::default();
        let result = self.owner.prepare_context_with_routed_maintenance(
            request,
            intent,
            tokenizer,
            outgoing,
            query_encoder,
            parent,
            &mut native_timings,
        );
        timings.hook_micros = timings
            .hook_micros
            .saturating_add(native_timings.hook_micros);
        timings.prepare_micros = native_timings.prepare_micros;
        result
    }
}
