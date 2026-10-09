use super::*;

pub(super) const EVALUATOR: &str = "synthetic-conditional-source-coverage.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Rule {
    Additive,
    SufficientUnionOnly,
    UnresolvedTask,
}

/// Each inner set is an independently sufficient proof, including valid
/// support alternatives. These are evaluator inputs, never collector inputs.
#[derive(Clone)]
pub(super) struct Oracle {
    pub(super) rule: Rule,
    pub(super) sufficient_sets: Vec<Vec<SourceInterval>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    RequiredCoverageGain,
    AlreadySufficient,
    NoRequiredCoverageGain,
    PartialRequiredCoverage,
    UnresolvedTask,
    NonDispatchableTrial,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub(super) row_id: String,
    pub(super) evaluation: u32,
    pub(super) feature_digest: ContentDigest,
    pub(super) selected_base_digest: ContentDigest,
    pub(super) trial_wire_digest: ContentDigest,
    pub(super) useful: Option<bool>,
    pub(super) reason: Reason,
    pub(super) provenance: Option<RouterLabelProvenance>,
}

fn covers(origins: &[SourceInterval], requirement: &SourceInterval) -> bool {
    origins.iter().any(|span| {
        span.event_id == requirement.event_id
            && span.payload_digest == requirement.payload_digest
            && span.start <= requirement.start
            && span.end >= requirement.end
    })
}

fn covered_bytes(origins: &[SourceInterval], requirement: &SourceInterval) -> u64 {
    origins
        .iter()
        .filter(|span| {
            span.event_id == requirement.event_id
                && span.payload_digest == requirement.payload_digest
        })
        .map(|span| {
            span.end
                .min(requirement.end)
                .saturating_sub(span.start.max(requirement.start))
        })
        .sum()
}

pub(super) fn label_row(
    row: &Observation,
    oracle: &Oracle,
    provenance: &RouterLabelProvenance,
    budget: &mut QueryBudget,
) -> Result<Target> {
    if oracle.sufficient_sets.len() > 16
        || oracle.sufficient_sets.iter().any(|set| set.len() > 16)
        || provenance.evaluator_version != EVALUATOR
        || provenance.logical_domain != row.logical_domain
        || provenance.available_at != row.known_at + 1
    {
        return Err(invalid());
    }
    charge(
        budget,
        1 + ((row.selected_origins.len() + row.trial_origins.len())
            * oracle.sufficient_sets.iter().map(Vec::len).sum::<usize>()) as u64,
        0,
    )?;
    let selected_complete = oracle
        .sufficient_sets
        .iter()
        .any(|set| set.iter().all(|span| covers(&row.selected_origins, span)));
    let trial_complete = oracle
        .sufficient_sets
        .iter()
        .any(|set| set.iter().all(|span| covers(&row.trial_origins, span)));
    let gain = oracle.sufficient_sets.iter().flatten().any(|span| {
        covered_bytes(&row.trial_origins, span) > covered_bytes(&row.selected_origins, span)
    });
    let (useful, reason) = if oracle.rule == Rule::UnresolvedTask {
        (None, Reason::UnresolvedTask)
    } else if !row.outgoing_fits {
        (None, Reason::NonDispatchableTrial)
    } else if selected_complete || oracle.sufficient_sets.is_empty() {
        (Some(false), Reason::AlreadySufficient)
    } else if !gain {
        (Some(false), Reason::NoRequiredCoverageGain)
    } else if oracle.rule == Rule::SufficientUnionOnly && !trial_complete {
        (None, Reason::PartialRequiredCoverage)
    } else {
        (Some(true), Reason::RequiredCoverageGain)
    };
    Ok(Target {
        row_id: row.row_id.clone(),
        evaluation: row.evaluation,
        feature_digest: row.feature_digest,
        selected_base_digest: row.selected_base_digest,
        trial_wire_digest: row.trial_wire_digest,
        useful,
        reason,
        provenance: useful.map(|_| provenance.clone()),
    })
}
