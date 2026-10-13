//! Reuse the existing recall request builder with the owned preparation's scope IDs.

use super::*;
use crate::{Capability, CompileContextPlan, CompileContextRequest, require_capability};
use contextdb_core::{NonEmptyVec, ScopeId, ScopeInheritance, ScopeKind, ScopeRef};
use contextdb_recall::DeterministicRecallRequest;
use std::str::FromStr;

/// Bind one generic query to the enclosing authenticated preparation, pinned
/// knowledge and applicability time. This performs no discovery or owner admission.
pub fn deterministic_prepare_recall(
    request: &PrepareContextRequest,
    query: &PrepareRecallQuery,
    known: u64,
    valid_at: TimestampMicros,
) -> ServiceResult<DeterministicRecallRequest> {
    require_capability(&request.context, Capability::Recall)?;
    if request.memory_query.as_ref() != Some(query)
        || request.known_at.is_some_and(|value| value != known)
        || request.valid_at.is_some_and(|value| value != valid_at)
        || request.context.request.scopes.is_empty()
        || request.context.request.scopes.len() > 32
        || request.context.request.purpose
            != contextdb_recall::purpose_key(&request.purpose.core_purpose())
        || query.query.trim().is_empty()
        || query.query.len() > 32 * 1024
        || query.query.contains('\0')
        || request.required_facets.len() > 32
    {
        return Err(invalid());
    }
    query.limits.validate().map_err(|_| invalid())?;
    if query.limits.max_nodes_examined > 100_000
        || query.limits.max_seed_candidates > 512
        || query.limits.max_graph_hops > 8
        || query.limits.max_frontier_per_hop > 512
        || query.limits.max_evidence_units > 2048
        || query.limits.max_context_tokens > request.memory_budget.hard_tokens
        || query.limits.deadline_micros > 30_000_000
    {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "prepared generic recall exceeds its bounded profile",
            false,
        ));
    }
    if let Some(vector) = &query.query_vector {
        vector.validate().map_err(|_| invalid())?;
        if vector.values.len() > 4096 {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "prepared query vector exceeds its dimension ceiling",
                false,
            ));
        }
    }
    let scopes = request
        .context
        .request
        .scopes
        .iter()
        .map(|scope| {
            ScopeId::from_str(scope)
                .map(|id| ScopeRef {
                    kind: ScopeKind::Other("service_scope".into()),
                    id,
                    inheritance: ScopeInheritance::Exact,
                })
                .map_err(|_| invalid())
        })
        .collect::<ServiceResult<Vec<_>>>()?;
    let enclosing = CompileContextRequest {
        context: request.context.clone(),
        plan: CompileContextPlan {
            pack_id: request.pack_id,
            query: query.query.clone(),
            mode: query.mode,
            intent: query.intent.clone(),
            purpose: request.purpose,
            at_commit: Some(known),
            now_micros: valid_at.0,
            required_facets: request.required_facets.clone(),
            recall_limits: query.limits,
            context_budgets: request.memory_budget,
            model_profile: request.model_profile.clone(),
            explicit_memory_request: request.explicit_memory_request,
            require_primary_evidence: false,
            include_evidence_quotes: false,
            permit_derived_only: true,
            max_projection_lag_commits: 0,
            allow_stale: false,
            query_vector: query.query_vector.clone(),
            continuation: None,
        },
    };
    let mut result = crate::context_pack::deterministic_request(&enclosing, None)?;
    result.request.scopes =
        NonEmptyVec::try_from_vec(scopes, "prepare_context.scopes").map_err(|_| invalid())?;
    result.principal.scopes = request.context.request.scopes.clone();
    result.validate().map_err(|_| invalid())?;
    Ok(result)
}

fn invalid() -> ServiceError {
    ServiceError::new(
        ErrorCode::InvalidArgument,
        "prepared generic recall binding is invalid",
        false,
    )
}
