//! Advance bounded raw, then dense prefixes without interpreting originals.

use std::sync::Arc;

use contextdb_agent_runtime::{KeepUninterpreted, PreparationHook};
use contextdb_native_service::NativeService;
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, ErrorCode, OwnedHybridLimits, ServiceError, ServiceResult,
    TextEmbeddingAdapter,
};

pub(super) const PROFILE: &str = "keep-uninterpreted+native-raw-outbox-advance.v1";
pub(super) const MAX_BATCHES: u8 = 8;
pub(super) const BATCH_EVENTS: u32 = 256;
pub(super) const HYBRID_PROFILE: &str = "keep-uninterpreted+native-bm25-dense-tail-advance.v1";
pub(super) const HYBRID_MAX_BATCHES: u8 = 8;
pub(super) const HYBRID_BATCH_EVENTS: u32 = 64;
pub(super) const ROUTED_PROFILE: &str = "keep-uninterpreted+native-bm25-routed-tail-once.v1";
pub(super) const ROUTED_BATCH_EVENTS: u32 = 4;
pub(super) const ROUTED_MAX_BATCHES: u8 = 1;

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
}

impl PreparationHook for NativePreparation {
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
