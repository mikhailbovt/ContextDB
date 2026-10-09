//! Retained material checks reuse the live compiler's block construction. No
//! resolver, provider, policy reconstruction, tokenizer or scorer is involved.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_recall::QueryBudget;

use crate::assembly::charge;
use crate::compiler::to_block;
use crate::router::{
    self, AuthorizedRouterRequest, MAX_UNITS, MemoryUnit, ROUTER_PREPARED_POLICY_FORMAT,
    RouterMaterialStatus, RouterMaterialUnavailableReason, RouterMaterialVerification,
    RouterPreparedMaterial, canonical_bytes, canonical_digest, normalize_spans,
};
use crate::{ContextBlock, ContextCompiler, Result};

// The existing continuous preparation admits at most 2048 support records.
const MAX_PREPARED_EVIDENCE: usize = 2048;

impl ContextCompiler {
    /// Verify every retained sufficient support and its unit semantics under one
    /// shared allowance. The explicit policy extension also verifies the complete
    /// candidate commitment. Historical selection remains unavailable.
    ///
    /// Unused representation bytes and candidate-only flags are not authenticated
    /// by a support commitment. Acceptance and current rights remain owner checks.
    pub fn validate_router_material(
        request: &AuthorizedRouterRequest,
        material: &RouterPreparedMaterial,
        budget: &mut QueryBudget,
    ) -> Result<RouterMaterialVerification> {
        charge(budget, 1, 0)?;
        if request.units.len() > MAX_UNITS
            || material.candidates.len() > MAX_UNITS
            || material.evidence.len() > MAX_PREPARED_EVIDENCE
            || material.candidates.len() != request.units.len()
            || material
                .candidates
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || material
                .evidence
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
        {
            return Err(router::invalid(
                "duplicate, unordered or excessive prepared inventory",
            ));
        }
        if let Some(policy) = &material.prepared_policy {
            // Reject unsupported shape before any reconstruction or payload copy.
            if policy.format != ROUTER_PREPARED_POLICY_FORMAT
                || policy.units.len() != request.units.len()
                || policy.units.len() > MAX_UNITS
                || policy.units.windows(2).any(|pair| pair[0].id >= pair[1].id)
            {
                return Err(router::invalid(
                    "invalid prepared policy inventory or format",
                ));
            }
            for (policy, unit) in policy.units.iter().zip(&request.units) {
                charge(budget, policy.alternatives.len() as u64 + 1, 0)?;
                if policy.id != unit.id
                    || policy.id.as_str().len() > 16384
                    || policy.alternatives.is_empty()
                    || policy.alternatives.len() > 8
                    || policy.alternatives.len() != unit.support_alternatives.len()
                    || policy
                        .alternatives
                        .iter()
                        .enumerate()
                        .any(|(index, alternative)| alternative.index as usize != index)
                {
                    return Err(router::invalid(
                        "prepared policy support identities disagree",
                    ));
                }
            }
        }
        // Stream borrowed inputs through the existing ceiling before cloning any
        // block/representation or building temporary support inventories.
        canonical_bytes(&(request, material), budget)?;
        request.validate(budget)?;
        if material
            .candidates
            .iter()
            .map(|candidate| &candidate.id)
            .ne(request.units.iter().map(|unit| &unit.id))
        {
            return Err(router::invalid(
                "prepared candidates differ from authorized unit identities",
            ));
        }
        let mut handles = BTreeSet::new();
        for handle in request
            .units
            .iter()
            .flat_map(|unit| &unit.support_alternatives)
            .flat_map(|alternative| &alternative.evidence_handles)
        {
            charge(budget, 1, 0)?;
            handles.insert(handle);
            if handles.len() > MAX_PREPARED_EVIDENCE {
                return Err(router::invalid(
                    "excessive complete prepared support inventory",
                ));
            }
        }
        if material.evidence.iter().map(|item| &item.id).ne(handles) {
            return Err(router::invalid(
                "prepared evidence differs from the complete support inventory",
            ));
        }
        let mut evidence = BTreeMap::new();
        for item in &material.evidence {
            charge(
                budget,
                1,
                item.excerpt.as_ref().map_or(0, |text| text.len() as u64),
            )?;
            item.validate()
                .map_err(|_| router::invalid("invalid prepared evidence material"))?;
            if item.original_span.is_none() {
                return Err(router::invalid(
                    "continuous prepared evidence lacks its original span",
                ));
            }
            evidence.insert(&item.id, item);
        }
        for (unit_index, (unit, candidate)) in
            request.units.iter().zip(&material.candidates).enumerate()
        {
            charge(budget, 1, 0)?;
            candidate
                .validate()
                .map_err(|_| router::invalid("invalid prepared candidate material"))?;
            if candidate
                .evidence_handles
                .iter()
                .ne(unit.support_alternatives[0].evidence_handles.iter())
                || candidate.utility_micros != unit.descriptor.prior_utility_micros
                || candidate.confidence_micros != unit.descriptor.confidence_micros
            {
                return Err(router::invalid(
                    "first prepared support or descriptor differs from material",
                ));
            }
            let candidate_bytes = canonical_bytes(candidate, budget)?.len() as u64;
            let policy = material
                .prepared_policy
                .as_ref()
                .map(|policy| &policy.units[unit_index]);
            let mut committed_candidates = if policy.is_some() {
                charge(
                    budget,
                    1,
                    (unit.support_alternatives.len()
                        * size_of::<(
                            crate::PackCandidate,
                            crate::UseAction,
                            crate::DirectiveReason,
                        )>()) as u64,
                )?;
                Some(Vec::with_capacity(unit.support_alternatives.len()))
            } else {
                None
            };
            let mut representations = BTreeMap::new();
            for representation in &candidate.representations {
                charge(budget, 1, 0)?;
                representations.insert(canonical_digest(representation, budget)?, representation);
            }
            for alternative in &unit.support_alternatives {
                // Conservatively charge the candidate payload before to_block
                // copies its bounded fields; support evidence stays borrowed.
                charge(budget, 1, candidate_bytes)?;
                let representation = representations
                    .get(&alternative.representation_digest)
                    .ok_or_else(|| router::invalid("retained support representation is absent"))?;
                if representation.level != alternative.level
                    || representation
                        .omitted_facets
                        .iter()
                        .ne(alternative.omitted_facets.iter())
                {
                    return Err(router::invalid(
                        "support representation level or omitted facets differ",
                    ));
                }
                let mut block = to_block(candidate, (**representation).clone());
                block.evidence_handles = alternative.evidence_handles.iter().cloned().collect();
                if !unit_semantics_match(unit, &block) {
                    return Err(router::invalid(
                        "prepared unit semantics differ from material",
                    ));
                }
                let mut support = Vec::new();
                let mut originals = Vec::new();
                for handle in &alternative.evidence_handles {
                    charge(budget, 1, 0)?;
                    let item = evidence
                        .get(handle)
                        .ok_or_else(|| router::invalid("retained support evidence is absent"))?;
                    support.push(*item);
                    if let Some(span) = &item.original_span {
                        originals.push(span.clone());
                    }
                }
                normalize_spans(&mut originals);
                if originals != alternative.originals
                    || canonical_digest(&(&block, &support), budget)? != alternative.material_digest
                {
                    return Err(router::invalid(
                        "retained support material or original spans disagree",
                    ));
                }
                if let (Some(policy), Some(committed)) = (policy, &mut committed_candidates) {
                    // This is the original complete prepared candidate, with only
                    // its exact support handles replaced. Unused representations
                    // and candidate-only flags remain inside the commitment.
                    charge(budget, 1, candidate_bytes)?;
                    let mut variant = candidate.clone();
                    variant.evidence_handles =
                        alternative.evidence_handles.iter().cloned().collect();
                    let decision = policy.alternatives[alternative.index as usize];
                    committed.push((variant, decision.use_action, decision.directive_reason));
                }
            }
            if let Some(committed) = committed_candidates
                && canonical_digest(&committed, budget)? != unit.candidate_digest
            {
                return Err(router::invalid(
                    "complete prepared candidate commitment disagrees",
                ));
            }
        }
        let has_policy = material.prepared_policy.is_some();
        Ok(RouterMaterialVerification {
            support_material: RouterMaterialStatus::Verified,
            unit_semantics: RouterMaterialStatus::Verified,
            candidate_commitment: if has_policy {
                RouterMaterialStatus::Verified
            } else {
                RouterMaterialStatus::Unavailable(
                    RouterMaterialUnavailableReason::MissingPreparedPolicy,
                )
            },
            historical_selection: RouterMaterialStatus::Unavailable(if has_policy {
                RouterMaterialUnavailableReason::MissingReplayPreparation
            } else {
                RouterMaterialUnavailableReason::MissingPreparedPolicy
            }),
        })
    }
}

fn unit_semantics_match(unit: &MemoryUnit, block: &ContextBlock) -> bool {
    unit.id == block.id
        && unit.kind == block.kind
        && unit.epistemic == block.epistemic
        && unit.interpretation == block.interpretation
        && unit.render_role == super::render_role(block)
        && unit.instruction_capability == block.instruction_capability
        && unit.scopes.iter().eq(block.scopes.iter())
        && unit.facets.iter().eq(block.facets.iter())
        && unit.memory_refs == block.memory_refs
        && unit.claim_ids.iter().eq(block.claim_ids.iter())
        && unit.perspective == block.perspective
        && unit.valid_time == block.valid_time
        && unit.known_at_commit == block.known_at_commit
        && unit.source_class == block.source_class
        && unit.support == block.support
        && unit.conflict == block.conflict
        && unit.unknown == block.unknown
}
