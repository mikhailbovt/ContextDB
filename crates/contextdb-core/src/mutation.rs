//! Atomic logical mutation contracts shared by storage implementations.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    Boundary, Claim, ClaimId, ClaimRevision, Commitment, ConflictSet, ConflictSetRevision,
    ContinuityProfile, Edge, EdgeRevision, EpisodeView, Goal, InteractionSignal, LineageEdge,
    LineageGraph, LineageNode, MemoryCandidate, MutationId, Node, NodeId, NodeRevision,
    NonEmptyVec, ObservationId, ObservationUnit, Preference, Procedure, PublicationId,
    RelationshipState, SelfModel, SharedReference, SnapshotRef, Validate, ValidationError,
    ValidationResult,
};

/// A higher-level typed memory revision included in an atomic semantic mutation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum TypedMemoryMutation {
    Preference(Preference),
    Boundary(Boundary),
    Goal(Goal),
    Commitment(Commitment),
    Procedure(Procedure),
    Relationship(RelationshipState),
    SharedReference(SharedReference),
    SelfModel(SelfModel),
    ContinuityProfile(ContinuityProfile),
    InteractionSignal(InteractionSignal),
}

impl Validate for TypedMemoryMutation {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::Preference(value) => value.validate(),
            Self::Boundary(value) => value.validate(),
            Self::Goal(value) => value.validate(),
            Self::Commitment(value) => value.validate(),
            Self::Procedure(value) => value.validate(),
            Self::Relationship(value) => value.validate(),
            Self::SharedReference(value) => value.validate(),
            Self::SelfModel(value) => value.validate(),
            Self::ContinuityProfile(value) => value.validate(),
            Self::InteractionSignal(value) => value.validate(),
        }
    }
}

impl TypedMemoryMutation {
    /// Returns the mandatory publication policy for this typed memory revision.
    #[must_use]
    pub fn envelope(&self) -> &crate::SemanticEnvelope {
        match self {
            Self::Preference(value) => &value.header.envelope,
            Self::Boundary(value) => &value.header.envelope,
            Self::Goal(value) => &value.header.envelope,
            Self::Commitment(value) => &value.header.envelope,
            Self::Procedure(value) => &value.header.envelope,
            Self::Relationship(value) => &value.header.envelope,
            Self::SharedReference(value) => &value.header.envelope,
            Self::SelfModel(value) => &value.header.envelope,
            Self::ContinuityProfile(value) => &value.envelope,
            Self::InteractionSignal(value) => &value.header.envelope,
        }
    }

    fn lineage_target(&self) -> LineageNode {
        match self {
            Self::Preference(value) => header_target(&value.header),
            Self::Boundary(value) => header_target(&value.header),
            Self::Goal(value) => header_target(&value.header),
            Self::Commitment(value) => header_target(&value.header),
            Self::Procedure(value) => header_target(&value.header),
            Self::Relationship(value) => header_target(&value.header),
            Self::SharedReference(value) => header_target(&value.header),
            Self::SelfModel(value) => header_target(&value.header),
            Self::ContinuityProfile(value) => LineageNode::ContinuityProfile {
                id: value.id,
                revision: value.revision,
            },
            Self::InteractionSignal(value) => header_target(&value.header),
        }
    }
}

/// Rebuildable work emitted by a semantic commit. These descriptors are not truth.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DerivedWorkItem {
    LexicalIndex {
        node_ids: Vec<NodeId>,
        claim_ids: Vec<ClaimId>,
    },
    Vectorize {
        nodes: Vec<NodeId>,
    },
    UpdateAliasMap {
        nodes: Vec<NodeId>,
    },
    UpdateFilterBitmaps {
        nodes: Vec<NodeId>,
    },
    DirtyHierarchyRegion {
        roots: Vec<NodeId>,
    },
    InvalidateSummaries {
        nodes: Vec<NodeId>,
    },
    Consolidate {
        roots: Vec<NodeId>,
    },
    UpdateSessionActiveSet {
        observations: Vec<ObservationId>,
    },
}

/// Atomic, pre-commit logical mutation. A storage engine assigns the next commit
/// sequence only after validating it against `base_snapshot`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticMutationSet {
    pub id: MutationId,
    pub base_snapshot: SnapshotRef,
    pub journal_refs: NonEmptyVec<ObservationId>,
    pub observation_appends: Vec<ObservationUnit>,
    pub episode_view_writes: Vec<EpisodeView>,
    pub node_creates: Vec<Node>,
    pub node_revisions: Vec<NodeRevision>,
    pub claim_creates: Vec<Claim>,
    pub claim_revisions: Vec<ClaimRevision>,
    pub edge_creates: Vec<Edge>,
    pub edge_revisions: Vec<EdgeRevision>,
    pub conflict_creates: Vec<ConflictSet>,
    pub conflict_revisions: Vec<ConflictSetRevision>,
    pub candidate_writes: Vec<MemoryCandidate>,
    pub typed_memory_writes: Vec<TypedMemoryMutation>,
    pub derived_work: Vec<DerivedWorkItem>,
}

impl SemanticMutationSet {
    /// Returns true when the mutation changes primary semantic state in addition
    /// to merely appending observations.
    #[must_use]
    pub fn has_semantic_writes(&self) -> bool {
        !self.episode_view_writes.is_empty()
            || !self.node_creates.is_empty()
            || !self.node_revisions.is_empty()
            || !self.claim_creates.is_empty()
            || !self.claim_revisions.is_empty()
            || !self.edge_creates.is_empty()
            || !self.edge_revisions.is_empty()
            || !self.conflict_creates.is_empty()
            || !self.conflict_revisions.is_empty()
            || !self.typed_memory_writes.is_empty()
    }

    /// Builds the lineage graph induced by all revision derivations in this set.
    #[must_use]
    pub fn lineage_graph(&self) -> LineageGraph {
        let mut edges = Vec::new();
        for (target, envelope) in self.enveloped_targets() {
            edges.extend(
                envelope
                    .derivation
                    .inputs
                    .iter()
                    .cloned()
                    .map(|source| LineageEdge {
                        derived: target.clone(),
                        source,
                    }),
            );
        }
        LineageGraph { edges }
    }

    fn enveloped_targets(&self) -> Vec<(LineageNode, &crate::SemanticEnvelope)> {
        let mut targets = Vec::new();
        targets.extend(self.node_revisions.iter().map(|revision| {
            (
                LineageNode::NodeRevision {
                    id: revision.node_id,
                    revision: revision.revision,
                },
                &revision.envelope,
            )
        }));
        targets.extend(self.claim_revisions.iter().map(|revision| {
            (
                LineageNode::ClaimRevision {
                    id: revision.claim_id,
                    revision: revision.revision,
                },
                &revision.envelope,
            )
        }));
        targets.extend(self.edge_revisions.iter().map(|revision| {
            (
                LineageNode::EdgeRevision {
                    id: revision.edge_id,
                    revision: revision.revision,
                },
                &revision.envelope,
            )
        }));
        targets.extend(self.conflict_revisions.iter().map(|revision| {
            (
                LineageNode::ConflictRevision {
                    id: revision.conflict_set_id,
                    revision: revision.revision,
                },
                &revision.envelope,
            )
        }));
        targets.extend(self.candidate_writes.iter().map(|candidate| {
            (
                LineageNode::Candidate { id: candidate.id },
                &candidate.envelope,
            )
        }));
        targets.extend(
            self.typed_memory_writes
                .iter()
                .map(|memory| (memory.lineage_target(), memory.envelope())),
        );
        targets
    }
}

fn header_target(header: &crate::MemoryRevisionHeader) -> LineageNode {
    LineageNode::NodeRevision {
        id: header.node_id,
        revision: header.revision,
    }
}

impl Validate for SemanticMutationSet {
    fn validate(&self) -> ValidationResult {
        validate_unique(self.journal_refs.iter().copied(), "mutation.journal_refs")?;
        validate_unique(
            self.observation_appends.iter().map(|value| value.id),
            "mutation.observation_appends",
        )?;
        validate_unique(
            self.node_creates.iter().map(|value| value.id),
            "mutation.node_creates",
        )?;
        validate_unique(
            self.claim_creates.iter().map(|value| value.id),
            "mutation.claim_creates",
        )?;
        validate_unique(
            self.edge_creates.iter().map(|value| value.id),
            "mutation.edge_creates",
        )?;
        validate_unique(
            self.conflict_creates.iter().map(|value| value.id),
            "mutation.conflict_creates",
        )?;
        validate_unique(
            self.candidate_writes.iter().map(|value| value.id),
            "mutation.candidate_writes",
        )?;

        for value in &self.observation_appends {
            value.validate()?;
        }
        for value in &self.episode_view_writes {
            value.validate()?;
        }
        for value in &self.node_creates {
            value.validate()?;
        }
        for value in &self.node_revisions {
            value.validate()?;
        }
        for value in &self.claim_creates {
            value.validate()?;
        }
        for value in &self.claim_revisions {
            value.validate()?;
        }
        for value in &self.edge_creates {
            value.validate()?;
        }
        for value in &self.edge_revisions {
            value.validate()?;
        }
        for value in &self.conflict_creates {
            value.validate()?;
        }
        for value in &self.conflict_revisions {
            value.validate()?;
        }
        for value in &self.candidate_writes {
            value.validate()?;
        }
        for value in &self.typed_memory_writes {
            value.validate()?;
        }

        validate_revision_batch(
            &self.node_revisions,
            |revision| revision.node_id,
            |revision| revision.revision,
            |revision| revision.temporal.transaction_time,
        )?;
        validate_revision_batch(
            &self.claim_revisions,
            |revision| revision.claim_id,
            |revision| revision.revision,
            |revision| revision.temporal.transaction_time,
        )?;
        validate_revision_batch(
            &self.edge_revisions,
            |revision| revision.edge_id,
            |revision| revision.revision,
            |revision| revision.temporal.transaction_time,
        )?;
        validate_revision_batch(
            &self.conflict_revisions,
            |revision| revision.conflict_set_id,
            |revision| revision.revision,
            |revision| revision.transaction_time,
        )?;

        require_first_revision_for_creates(
            self.node_creates.iter().map(|value| value.id),
            &self.node_revisions,
            |revision| revision.node_id,
            |revision| revision.revision,
        )?;
        require_first_revision_for_creates(
            self.claim_creates.iter().map(|value| value.id),
            &self.claim_revisions,
            |revision| revision.claim_id,
            |revision| revision.revision,
        )?;
        require_first_revision_for_creates(
            self.edge_creates.iter().map(|value| value.id),
            &self.edge_revisions,
            |revision| revision.edge_id,
            |revision| revision.revision,
        )?;
        require_first_revision_for_creates(
            self.conflict_creates.iter().map(|value| value.id),
            &self.conflict_revisions,
            |revision| revision.conflict_set_id,
            |revision| revision.revision,
        )?;

        self.lineage_graph().validate()?;
        validate_in_batch_policy_propagation(self)
    }
}

/// Immutable publication record appended after atomic commit. It does not mutate
/// the original journal observation records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPublicationRecord {
    pub id: PublicationId,
    pub mutation_id: MutationId,
    pub journal_refs: NonEmptyVec<ObservationId>,
    pub base_snapshot: SnapshotRef,
    pub committed_snapshot: SnapshotRef,
}

impl Validate for SemanticPublicationRecord {
    fn validate(&self) -> ValidationResult {
        if self.committed_snapshot.commit_seq <= self.base_snapshot.commit_seq {
            return Err(ValidationError::InvalidState {
                reason: "publication commit must follow its base snapshot",
            });
        }
        validate_unique(
            self.journal_refs.iter().copied(),
            "publication.journal_refs",
        )
    }
}

fn validate_in_batch_policy_propagation(mutation: &SemanticMutationSet) -> ValidationResult {
    let targets = mutation.enveloped_targets();
    let envelopes: BTreeMap<_, _> = targets
        .iter()
        .map(|(target, envelope)| (target.clone(), *envelope))
        .collect();
    for (_, derived) in targets {
        for input in &derived.derivation.inputs {
            if let Some(source) = envelopes.get(input) {
                derived.validate_derived_from(source)?;
            }
        }
    }
    Ok(())
}

fn validate_unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> ValidationResult {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ValidationError::DuplicateIdentifier { field });
        }
    }
    Ok(())
}

fn validate_revision_batch<T, K, KeyFn, RevisionFn, TimeFn>(
    revisions: &[T],
    key: KeyFn,
    revision: RevisionFn,
    transaction_time: TimeFn,
) -> ValidationResult
where
    K: Copy + Ord,
    KeyFn: Fn(&T) -> K,
    RevisionFn: Fn(&T) -> crate::RevisionNumber,
    TimeFn: Fn(&T) -> crate::CommitRange,
{
    let mut grouped: BTreeMap<K, Vec<&T>> = BTreeMap::new();
    for item in revisions {
        grouped.entry(key(item)).or_default().push(item);
    }
    for items in grouped.values_mut() {
        items.sort_by_key(|item| revision(item));
        for pair in items.windows(2) {
            if revision(pair[0]) == revision(pair[1]) {
                return Err(ValidationError::InvalidRevisionSequence);
            }
        }
        for (index, left) in items.iter().enumerate() {
            for right in &items[index + 1..] {
                if transaction_time(left).overlaps(transaction_time(right)) {
                    return Err(ValidationError::OverlappingTransactionIntervals);
                }
            }
        }
    }
    Ok(())
}

fn require_first_revision_for_creates<T, K, Creates, KeyFn, RevisionFn>(
    creates: Creates,
    revisions: &[T],
    key: KeyFn,
    revision: RevisionFn,
) -> ValidationResult
where
    K: Copy + Eq,
    Creates: IntoIterator<Item = K>,
    KeyFn: Fn(&T) -> K,
    RevisionFn: Fn(&T) -> crate::RevisionNumber,
{
    for created in creates {
        let first_count = revisions
            .iter()
            .filter(|item| key(item) == created && revision(item) == crate::RevisionNumber::FIRST)
            .count();
        if first_count != 1 {
            return Err(ValidationError::InvalidRevisionSequence);
        }
    }
    Ok(())
}
