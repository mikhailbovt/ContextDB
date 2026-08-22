use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::SnapshotRef;

use crate::{
    GenerationNumber, HierarchyError, HierarchyItemId, HierarchyMembership, HierarchyNode,
    HierarchyProfile, HierarchyProposal, HierarchyProvenance, HierarchyValidity, MembershipRole,
    Result,
};

/// One possible parent produced by a manual, structural, deterministic, or
/// model-assisted builder. Assignment is deterministic and preserves multiple
/// qualifying parents unless the profile explicitly declares a cap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentCandidate {
    /// Possible parent.
    pub parent: HierarchyItemId,
    /// Child to assign.
    pub child: HierarchyItemId,
    /// Stable sibling ordering.
    pub order_key: u64,
    /// Assignment confidence.
    pub confidence: crate::Confidence,
    /// Inherited source validity.
    pub validity: HierarchyValidity,
    /// Explainable source, builder, and rationale.
    pub provenance: HierarchyProvenance,
}

/// Deterministic side-by-side proposal builder.
///
/// `finish` only creates a proposal. Call [`crate::validate_proposal`] and then
/// [`crate::HierarchyRepository::publish`] as separate steps.
#[derive(Clone, Debug)]
pub struct HierarchyProposalBuilder {
    profile: HierarchyProfile,
    generation: GenerationNumber,
    expected_active: Option<GenerationNumber>,
    built_from: SnapshotRef,
    build_provenance: HierarchyProvenance,
    nodes: BTreeMap<HierarchyItemId, HierarchyNode>,
    candidates: Vec<AssignmentCandidate>,
}

impl HierarchyProposalBuilder {
    /// Starts a side-by-side generation after observing an optional active
    /// generation. The proposed number is derived rather than caller-selected.
    pub fn new(
        profile: HierarchyProfile,
        expected_active: Option<GenerationNumber>,
        built_from: SnapshotRef,
        build_provenance: HierarchyProvenance,
    ) -> Result<Self> {
        let generation = match expected_active {
            Some(active) => active.checked_next()?,
            None => GenerationNumber::new(1)?,
        };
        Ok(Self {
            profile,
            generation,
            expected_active,
            built_from,
            build_provenance,
            nodes: BTreeMap::new(),
            candidates: Vec::new(),
        })
    }

    /// Adds one semantic or synthetic navigation item.
    pub fn add_node(&mut self, node: HierarchyNode) -> Result<&mut Self> {
        let id = node.id;
        if self.nodes.insert(id, node).is_some() {
            return Err(HierarchyError::DuplicateItem(id));
        }
        Ok(self)
    }

    /// Adds one possible parent. Candidate order never affects final output.
    pub fn add_candidate(&mut self, candidate: AssignmentCandidate) -> &mut Self {
        self.candidates.push(candidate);
        self
    }

    /// Builds a canonical deterministic proposal while preserving every
    /// qualifying parent up to an explicitly configured bound.
    #[must_use]
    pub fn finish(self) -> HierarchyProposal {
        let mut strongest_by_edge: BTreeMap<
            (HierarchyItemId, HierarchyItemId),
            AssignmentCandidate,
        > = BTreeMap::new();
        for candidate in self.candidates {
            if candidate.confidence < self.profile.assignment.minimum_confidence {
                continue;
            }
            let edge = (candidate.parent, candidate.child);
            match strongest_by_edge.get(&edge) {
                Some(current) if compare_candidate(current, &candidate).is_le() => {}
                _ => {
                    strongest_by_edge.insert(edge, candidate);
                }
            }
        }

        let mut by_child: BTreeMap<HierarchyItemId, Vec<AssignmentCandidate>> = BTreeMap::new();
        for candidate in strongest_by_edge.into_values() {
            by_child.entry(candidate.child).or_default().push(candidate);
        }
        let mut memberships = Vec::new();
        for candidates in by_child.values_mut() {
            candidates.sort_by(compare_candidate);
            if let Some(maximum) = self.profile.assignment.max_parents {
                candidates.truncate(usize::from(maximum));
            }
            for (index, candidate) in candidates.drain(..).enumerate() {
                memberships.push(HierarchyMembership {
                    parent: candidate.parent,
                    child: candidate.child,
                    role: if index == 0 && self.profile.assignment.select_primary {
                        MembershipRole::Primary
                    } else {
                        MembershipRole::Alternative
                    },
                    order_key: candidate.order_key,
                    confidence: candidate.confidence,
                    validity: candidate.validity,
                    provenance: candidate.provenance,
                });
            }
        }
        memberships.sort_by(|left, right| {
            left.child
                .cmp(&right.child)
                .then_with(|| role_rank(left.role).cmp(&role_rank(right.role)))
                .then_with(|| left.parent.cmp(&right.parent))
        });
        let children: BTreeSet<_> = memberships.iter().map(|edge| edge.child).collect();
        let roots = self
            .nodes
            .keys()
            .filter(|item| !children.contains(item))
            .copied()
            .collect();
        HierarchyProposal {
            profile: self.profile,
            generation: self.generation,
            expected_active: self.expected_active,
            built_from: self.built_from,
            roots,
            nodes: self.nodes,
            memberships,
            build_provenance: self.build_provenance,
        }
    }
}

fn compare_candidate(
    left: &AssignmentCandidate,
    right: &AssignmentCandidate,
) -> std::cmp::Ordering {
    right
        .provenance
        .source
        .precedence()
        .cmp(&left.provenance.source.precedence())
        .then_with(|| right.confidence.cmp(&left.confidence))
        .then_with(|| left.order_key.cmp(&right.order_key))
        .then_with(|| left.parent.cmp(&right.parent))
        .then_with(|| left.child.cmp(&right.child))
        .then_with(|| compare_validity(left.validity, right.validity))
        .then_with(|| left.provenance.rationale.cmp(&right.provenance.rationale))
        .then_with(|| {
            left.provenance
                .derivation
                .id
                .cmp(&right.provenance.derivation.id)
        })
        .then_with(|| {
            left.provenance
                .derivation
                .kind
                .cmp(&right.provenance.derivation.kind)
        })
        .then_with(|| {
            left.provenance
                .derivation
                .actor
                .cmp(&right.provenance.derivation.actor)
        })
        .then_with(|| {
            left.provenance
                .derivation
                .model_call
                .cmp(&right.provenance.derivation.model_call)
        })
        .then_with(|| {
            left.provenance
                .derivation
                .pipeline
                .cmp(&right.provenance.derivation.pipeline)
        })
        .then_with(|| {
            left.provenance
                .derivation
                .inputs
                .cmp(&right.provenance.derivation.inputs)
        })
}

fn compare_validity(left: HierarchyValidity, right: HierarchyValidity) -> std::cmp::Ordering {
    left.transaction_time
        .start
        .cmp(&right.transaction_time.start)
        .then_with(|| left.transaction_time.end.cmp(&right.transaction_time.end))
        .then_with(|| {
            left.valid_time
                .map(|range| range.start)
                .cmp(&right.valid_time.map(|range| range.start))
        })
        .then_with(|| {
            left.valid_time
                .and_then(|range| range.end)
                .cmp(&right.valid_time.and_then(|range| range.end))
        })
}

const fn role_rank(role: MembershipRole) -> u8 {
    match role {
        MembershipRole::Primary => 0,
        MembershipRole::Alternative => 1,
    }
}
