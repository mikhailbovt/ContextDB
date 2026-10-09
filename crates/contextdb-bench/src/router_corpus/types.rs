use super::*;
use contextdb_context::OutgoingBase;
use contextdb_context::router::{
    AuthorizedRouterRequest, RouterManifest, RouterPreparedMaterial, RouterSelectionPlan,
};
use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use contextdb_service::CaptureReceipt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterQuerySpec {
    pub id: String,
    pub query: String,
    pub scope: String,
    pub logical_domain: String,
    pub known_at: u64,
}
impl RouterQuerySpec {
    /// Projection only; gold answers and evidence identities are not retained.
    pub fn from_target(
        target: &crate::ContinuousTarget,
        logical_domain: &str,
        budget: &mut QueryBudget,
    ) -> Result<Self> {
        for value in [&target.id, &target.scope, logical_domain] {
            identity(value)?;
        }
        if target.query.trim().is_empty() || target.query.len() > 32768 {
            return Err(invalid());
        }
        charge(
            budget,
            1,
            (target.id.len() + target.query.len() + target.scope.len() + logical_domain.len())
                as u64,
        )?;
        Ok(Self {
            id: target.id.clone(),
            query: target.query.clone(),
            scope: target.scope.clone(),
            logical_domain: logical_domain.into(),
            known_at: target.known_at,
        })
    }
    pub fn validate(&self) -> Result<()> {
        for value in [&self.id, &self.scope, &self.logical_domain] {
            identity(value)?;
        }
        if self.query.trim().is_empty() || self.query.len() > 32768 {
            return Err(invalid());
        }
        Ok(())
    }
}
impl std::fmt::Debug for RouterQuerySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterQuerySpec")
            .field("query_bytes", &self.query.len())
            .field("known_at", &self.known_at)
            .finish_non_exhaustive()
    }
}

/// Generator-declared logical mapping, not a native receipt or permission grant.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticObservationBinding {
    pub generator: String,
    pub fixture_id: String,
    pub source_domain: String,
    pub source_cutoff: u64,
    pub compiler_domain: String,
    pub compiler_cutoff: u64,
    pub source_nodes: Vec<RouterLineageRef>,
}
impl std::fmt::Debug for SyntheticObservationBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyntheticObservationBinding")
            .field("source_count", &self.source_nodes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterQueryTimeRecord {
    pub format: String,
    pub query: RouterQuerySpec,
    pub request: AuthorizedRouterRequest,
    pub base: OutgoingBase,
    pub material: RouterPreparedMaterial,
    pub observation: SyntheticObservationBinding,
}
impl RouterQueryTimeRecord {
    pub fn from_json(bytes: &[u8], budget: &mut QueryBudget) -> Result<Self> {
        let value: Self = decode(bytes, MAX_ROUTER_EXAMPLE_BYTES, budget)?;
        validate_router_query_time(&value, budget)?;
        Ok(value)
    }
}
impl std::fmt::Debug for RouterQueryTimeRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterQueryTimeRecord")
            .field("units", &self.request.units.len())
            .field("evidence", &self.material.evidence.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAttemptStatus {
    Prepared,
    Accepted,
    OutcomeUnknown,
    Aborted,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterBehaviorRecord {
    pub format: String,
    pub example_id: String,
    pub request_digest: ContentDigest,
    pub plan: RouterSelectionPlan,
    pub manifest: RouterManifest,
    pub attempt: RouterAttemptStatus,
    pub accepted_receipt: Option<CaptureReceipt>,
}
impl std::fmt::Debug for RouterBehaviorRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterBehaviorRecord")
            .field("attempt", &self.attempt)
            .field("evaluations", &self.plan.scores.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterLabelKind {
    SyntheticSourceSet,
    ExplicitFeedback,
    TeacherWeak,
    PairedFrozenReader,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterLabelProvenance {
    pub kind: RouterLabelKind,
    pub evaluator_version: String,
    pub available_at: u64,
    pub logical_domain: String,
    pub source_nodes: Vec<RouterLineageRef>,
}
impl std::fmt::Debug for RouterLabelProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterLabelProvenance")
            .field("kind", &self.kind)
            .field("available_at", &self.available_at)
            .field("sources", &self.source_nodes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateUtilityTarget {
    pub candidate_id: contextdb_context::BlockId,
    /// None is masked, never a negative. A label is not truth or propensity.
    pub useful: Option<bool>,
    pub provenance: Option<RouterLabelProvenance>,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleUtilityTarget {
    pub bundle_id: String,
    pub members: Vec<contextdb_context::BlockId>,
    pub useful: Option<bool>,
    pub provenance: Option<RouterLabelProvenance>,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterUtilityTargets {
    pub format: String,
    pub example_id: String,
    pub conditional_base_digest: ContentDigest,
    pub candidates: Vec<CandidateUtilityTarget>,
    pub bundles: Vec<BundleUtilityTarget>,
}
impl RouterUtilityTargets {
    pub fn from_json(bytes: &[u8], budget: &mut QueryBudget) -> Result<Self> {
        decode(bytes, MAX_ROUTER_TARGET_BYTES, budget)
    }
    /// Number of supervised independent labels; an all-unknown record has none.
    pub fn known_labels(&self) -> usize {
        self.candidates
            .iter()
            .filter(|item| item.useful.is_some())
            .count()
            + self
                .bundles
                .iter()
                .filter(|item| item.useful.is_some())
                .count()
    }
}
impl std::fmt::Debug for CandidateUtilityTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CandidateUtilityTarget")
            .field("known", &self.useful.is_some())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for BundleUtilityTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleUtilityTarget")
            .field("members", &self.members.len())
            .field("known", &self.useful.is_some())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for RouterUtilityTargets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterUtilityTargets")
            .field("candidates", &self.candidates.len())
            .field("bundles", &self.bundles.len())
            .field("known", &self.known_labels())
            .finish_non_exhaustive()
    }
}

pub fn validate_router_behavior(
    input: &RouterQueryTimeRecord,
    behavior: &RouterBehaviorRecord,
    budget: &mut QueryBudget,
) -> Result<()> {
    bounded_size(behavior, MAX_ROUTER_EXAMPLE_BYTES, budget)?;
    if behavior.format != ROUTER_BEHAVIOR_VERSION
        || behavior.example_id != input.query.id
        || behavior.request_digest != input.request.digest
        || behavior.plan.behavior_propensity.is_some()
        || behavior
            .plan
            .scores
            .iter()
            .any(|score| score.behavior_propensity.is_some())
        || behavior.manifest.trained_weights.is_some()
        || behavior.manifest.training_dataset.is_some()
        || matches!(behavior.attempt, RouterAttemptStatus::Prepared)
            && behavior.accepted_receipt.is_some()
        || matches!(
            behavior.attempt,
            RouterAttemptStatus::Accepted | RouterAttemptStatus::OutcomeUnknown
        ) && behavior.accepted_receipt.is_none()
    {
        return Err(invalid());
    }
    behavior
        .manifest
        .validate_observation(&input.request, &behavior.plan, budget)
        .map_err(|_| invalid())?;
    // A receipt here is provenance to be resolved by its owner, never proof from JSON.
    if behavior
        .accepted_receipt
        .as_ref()
        .is_some_and(|receipt| receipt.payload_digest != Some(behavior.plan.wire_digest))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Structural associations only; accepted receipt authority remains with the
/// native owner, and missing historical columns are never upgraded by this check.
pub fn validate_router_example(
    input: &RouterQueryTimeRecord,
    behavior: &RouterBehaviorRecord,
    targets: &RouterUtilityTargets,
    lineage: &RouterExampleLineage,
    budget: &mut QueryBudget,
) -> Result<contextdb_context::router::RouterMaterialVerification> {
    let verification = validate_router_query_time(input, budget)?;
    validate_router_behavior(input, behavior, budget)?;
    validate_router_targets(input, behavior, targets, budget)?;
    validate_router_example_lineage(input, lineage)?;
    Ok(verification)
}

pub fn validate_router_targets(
    input: &RouterQueryTimeRecord,
    behavior: &RouterBehaviorRecord,
    targets: &RouterUtilityTargets,
    budget: &mut QueryBudget,
) -> Result<()> {
    bounded_size(targets, MAX_ROUTER_TARGET_BYTES, budget)?;
    if targets.format != ROUTER_TARGET_VERSION
        || targets.example_id != input.query.id
        || targets.candidates.len() != input.request.units.len()
        || targets.candidates.len() > contextdb_context::router::MAX_UNITS
        || targets.bundles.len() > 64
        || !behavior
            .plan
            .scores
            .iter()
            .any(|score| score.selected_base_digest == targets.conditional_base_digest)
    {
        return Err(invalid());
    }
    let inventory: BTreeSet<_> = input.request.units.iter().map(|unit| &unit.id).collect();
    let mut candidates = BTreeSet::new();
    for target in &targets.candidates {
        charge(budget, 1, 0)?;
        if !inventory.contains(&target.candidate_id) || !candidates.insert(&target.candidate_id) {
            return Err(invalid());
        }
        validate_label(input, target.useful, &target.provenance)?;
    }
    let mut bundles = BTreeSet::new();
    for target in &targets.bundles {
        charge(budget, target.members.len() as u64 + 1, 0)?;
        identity(&target.bundle_id)?;
        if !bundles.insert(&target.bundle_id)
            || !(2..=16).contains(&target.members.len())
            || target.members.windows(2).any(|pair| pair[0] >= pair[1])
            || target.members.iter().any(|id| !inventory.contains(id))
        {
            return Err(invalid());
        }
        validate_label(input, target.useful, &target.provenance)?;
    }
    Ok(())
}
fn validate_label(
    input: &RouterQueryTimeRecord,
    useful: Option<bool>,
    provenance: &Option<RouterLabelProvenance>,
) -> Result<()> {
    if useful.is_some() != provenance.is_some() {
        return Err(invalid());
    }
    if let Some(provenance) = provenance {
        identity(&provenance.evaluator_version)?;
        if provenance.logical_domain != input.query.logical_domain
            || provenance.available_at < input.query.known_at
            || provenance.source_nodes.len() > MAX_ROUTER_LINEAGE_NODES
            || provenance
                .source_nodes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid());
        }
        for source in &provenance.source_nodes {
            source.validate()?;
            if source.domain != provenance.logical_domain {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
