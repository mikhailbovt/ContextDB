//! Advance the retained raw outbox without interpreting or promoting originals.

use std::sync::Arc;

use contextdb_agent_runtime::{KeepUninterpreted, PreparationHook};
use contextdb_native_service::NativeService;
use contextdb_recall::QueryBudget;
use contextdb_service::{AuthenticatedRequestContext, ErrorCode, ServiceError, ServiceResult};

pub(super) const PROFILE: &str = "keep-uninterpreted+native-raw-outbox-advance.v1";
pub(super) const MAX_BATCHES: u8 = 8;
pub(super) const BATCH_EVENTS: u32 = 256;

#[derive(Debug)]
pub(super) struct NativePreparation {
    owner: Arc<NativeService>,
}

impl NativePreparation {
    pub(super) fn new(owner: Arc<NativeService>) -> Self {
        Self { owner }
    }
}

impl PreparationHook for NativePreparation {
    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        KeepUninterpreted.before_prepare(context, budget)?;
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
