//! Historical computation over frozen inputs. No source resolver or dispatch.

use super::*;
use contextdb_context::router::{RouterHistoricalReplayResult, RouterReplayUnavailableReason};
use contextdb_context::{ContextCompiler, OutgoingEncoder, TokenCounter};
use contextdb_recall::QueryBudget;

/// Execute the actual pinned R0 over retained compiler preparation. Observations
/// are comparison inputs, never score proposals or model features. This checks
/// integrity only; callers still need rights to read and use the frozen artifact.
pub fn replay_router_behavior(
    input: &RouterQueryTimeRecord,
    behavior: &RouterBehaviorRecord,
    tokenizer: &dyn TokenCounter,
    encoder: &dyn OutgoingEncoder,
    budget: &mut QueryBudget,
) -> Result<RouterHistoricalReplayResult> {
    validate_router_query_time(input, budget)?;
    validate_router_behavior(input, behavior, budget)?;
    let Some(observation) = &behavior.replay_observation else {
        return Ok(RouterHistoricalReplayResult::Unavailable(
            RouterReplayUnavailableReason::MissingReplayObservation,
        ));
    };
    ContextCompiler::replay_router_r0(
        &input.request,
        &behavior.plan,
        &behavior.manifest,
        &input.base,
        &input.material,
        observation,
        tokenizer,
        encoder,
        budget,
    )
    .map_err(|error| match error {
        contextdb_context::ContextError::BudgetExceeded(_) => {
            BenchError::TelemetryBudget("router replay allowance exhausted".into())
        }
        _ => invalid(),
    })
}
