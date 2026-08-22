use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{ContentDigest, SnapshotRef, Validate};
use serde::Serialize;

use crate::types::validate_text;
use crate::{
    BranchStatistics, HierarchyError, HierarchyItemId, HierarchyKind, HierarchyMembership,
    HierarchyProfile, HierarchyProposal, HierarchyProvenance, MembershipRole, Result,
    ValidatedHierarchyProposal,
};

/// Deterministically validates and canonicalizes a side-by-side build proposal.
///
/// Successful validation does not publish anything. The returned opaque type is
/// the only input accepted by hierarchy repositories.
pub fn validate_proposal(mut proposal: HierarchyProposal) -> Result<ValidatedHierarchyProposal> {
    validate_profile(&proposal.profile)?;
    if proposal
        .profile
        .partitions
        .values()
        .any(|partition| partition.policy_revision > proposal.built_from.commit_seq)
    {
        return Err(HierarchyError::InvalidPolicyPartition);
    }
    validate_provenance(&proposal.build_provenance)?;
    if proposal.nodes.is_empty() && (!proposal.roots.is_empty() || !proposal.memberships.is_empty())
    {
        return Err(HierarchyError::RootMismatch);
    }

    for (key, node) in &proposal.nodes {
        if *key != node.id {
            return Err(HierarchyError::ItemKeyMismatch);
        }
        validate_text(&node.label, "hierarchy_node.label")?;
        if !proposal.profile.partitions.contains_key(&node.partition) {
            return Err(HierarchyError::UnknownPolicyPartition {
                item: node.id,
                partition: node.partition,
            });
        }
        validate_validity(node.validity, proposal.built_from)?;
        validate_provenance(&node.provenance)?;
    }

    canonicalize_memberships(&mut proposal.memberships);
    let mut seen_edges = BTreeSet::new();
    let mut incoming: BTreeMap<HierarchyItemId, usize> = BTreeMap::new();
    let mut primary: BTreeSet<HierarchyItemId> = BTreeSet::new();
    let mut adjacency: BTreeMap<HierarchyItemId, Vec<HierarchyItemId>> = proposal
        .nodes
        .keys()
        .copied()
        .map(|item| (item, Vec::new()))
        .collect();

    for membership in &proposal.memberships {
        validate_membership(membership, &proposal)?;
        if membership.confidence < proposal.profile.assignment.minimum_confidence {
            return Err(HierarchyError::MembershipBelowMinimum {
                item: membership.child,
                actual: membership.confidence.basis_points(),
                minimum: proposal
                    .profile
                    .assignment
                    .minimum_confidence
                    .basis_points(),
            });
        }
        if !seen_edges.insert((membership.parent, membership.child)) {
            return Err(HierarchyError::DuplicateMembership {
                parent: membership.parent,
                child: membership.child,
            });
        }
        if membership.role == MembershipRole::Primary && !primary.insert(membership.child) {
            return Err(HierarchyError::MultiplePrimaryParents(membership.child));
        }
        *incoming.entry(membership.child).or_default() += 1;
        adjacency
            .get_mut(&membership.parent)
            .ok_or(HierarchyError::UnknownItem(membership.parent))?
            .push(membership.child);
    }

    if let Some(maximum) = proposal.profile.assignment.max_parents {
        if maximum == 0 {
            return Err(HierarchyError::InvalidBudget("assignment.max_parents"));
        }
        for (item, actual) in &incoming {
            if *actual > usize::from(maximum) {
                return Err(HierarchyError::ParentLimitExceeded {
                    item: *item,
                    actual: *actual,
                    maximum,
                });
            }
        }
    }
    for item in incoming.keys() {
        if primary.contains(item) != proposal.profile.assignment.select_primary {
            return Err(HierarchyError::PrimarySelectionMismatch(*item));
        }
    }

    for children in adjacency.values_mut() {
        children.sort_unstable();
    }
    let topological = topological_order(&adjacency, &incoming)?;
    let computed_roots: BTreeSet<_> = proposal
        .nodes
        .keys()
        .filter(|item| !incoming.contains_key(item))
        .copied()
        .collect();
    if computed_roots != proposal.roots {
        return Err(HierarchyError::RootMismatch);
    }
    if !proposal.nodes.is_empty() && computed_roots.is_empty() {
        return Err(HierarchyError::MissingRoot);
    }
    let statistics = compute_statistics(&adjacency, &proposal.roots, &topological);
    let canonical = canonical_proposal_bytes(&proposal)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-hierarchy-generation-manifest-v1\0");
    hasher.update(&canonical);
    let digest = ContentDigest::from_bytes(*hasher.finalize().as_bytes());
    if digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(HierarchyError::InvalidManifestDigest);
    }
    Ok(ValidatedHierarchyProposal {
        proposal,
        digest,
        statistics,
    })
}

#[derive(Serialize)]
struct CanonicalProfile<'a> {
    id: contextdb_core::HierarchyViewId,
    workspace_id: contextdb_core::WorkspaceId,
    kind: &'a HierarchyKind,
    name: &'a str,
    profile_revision: u64,
    partitions: Vec<&'a crate::PolicyPartition>,
    assignment: crate::AssignmentPolicy,
}

#[derive(Serialize)]
struct CanonicalProposal<'a> {
    profile: CanonicalProfile<'a>,
    generation: crate::GenerationNumber,
    built_from: SnapshotRef,
    roots: Vec<HierarchyItemId>,
    nodes: Vec<&'a crate::HierarchyNode>,
    memberships: &'a [HierarchyMembership],
    build_provenance: &'a HierarchyProvenance,
}

fn canonical_proposal_bytes(proposal: &HierarchyProposal) -> Result<Vec<u8>> {
    serde_json::to_vec(&CanonicalProposal {
        profile: CanonicalProfile {
            id: proposal.profile.id,
            workspace_id: proposal.profile.workspace_id,
            kind: &proposal.profile.kind,
            name: &proposal.profile.name,
            profile_revision: proposal.profile.profile_revision,
            partitions: proposal.profile.partitions.values().collect(),
            assignment: proposal.profile.assignment,
        },
        generation: proposal.generation,
        built_from: proposal.built_from,
        roots: proposal.roots.iter().copied().collect(),
        nodes: proposal.nodes.values().collect(),
        memberships: &proposal.memberships,
        build_provenance: &proposal.build_provenance,
    })
    .map_err(Into::into)
}

fn validate_profile(profile: &HierarchyProfile) -> Result<()> {
    validate_text(&profile.name, "hierarchy_profile.name")?;
    if profile.profile_revision == 0 {
        return Err(HierarchyError::InvalidText {
            field: "hierarchy_profile.profile_revision",
            reason: "must be greater than zero",
        });
    }
    if let HierarchyKind::Domain(label) = &profile.kind {
        validate_text(label, "hierarchy_profile.kind")?;
    }
    if profile.partitions.is_empty() {
        return Err(HierarchyError::EmptyPolicyPartitions);
    }
    if profile.assignment.max_parents == Some(0) {
        return Err(HierarchyError::InvalidBudget("assignment.max_parents"));
    }
    for (key, partition) in &profile.partitions {
        if *key != partition.id || partition.workspace_id != profile.workspace_id {
            return Err(HierarchyError::InvalidPolicyPartition);
        }
        partition.validate_digest()?;
        for scope in &partition.scopes {
            scope
                .validate()
                .map_err(|error| HierarchyError::InvalidProvenance(error.to_string()))?;
        }
    }
    Ok(())
}

fn validate_membership(
    membership: &HierarchyMembership,
    proposal: &HierarchyProposal,
) -> Result<()> {
    if membership.parent == membership.child {
        return Err(HierarchyError::SelfMembership(membership.parent));
    }
    let parent = proposal
        .nodes
        .get(&membership.parent)
        .ok_or(HierarchyError::UnknownItem(membership.parent))?;
    let child = proposal
        .nodes
        .get(&membership.child)
        .ok_or(HierarchyError::UnknownItem(membership.child))?;
    if parent.partition != child.partition {
        return Err(HierarchyError::CrossPartitionMembership);
    }
    validate_validity(membership.validity, proposal.built_from)?;
    validate_provenance(&membership.provenance)
}

fn validate_validity(validity: crate::HierarchyValidity, built_from: SnapshotRef) -> Result<()> {
    validity
        .transaction_time
        .validate()
        .map_err(|_| HierarchyError::InvalidValidity(built_from.commit_seq))?;
    if let Some(valid_time) = validity.valid_time {
        valid_time
            .validate()
            .map_err(|_| HierarchyError::InvalidValidity(built_from.commit_seq))?;
    }
    if !validity.transaction_time.contains(built_from.commit_seq) {
        return Err(HierarchyError::InvalidValidity(built_from.commit_seq));
    }
    Ok(())
}

fn validate_provenance(provenance: &HierarchyProvenance) -> Result<()> {
    validate_text(&provenance.rationale, "hierarchy_provenance.rationale")?;
    provenance
        .derivation
        .validate()
        .map_err(|error| HierarchyError::InvalidProvenance(error.to_string()))
}

fn canonicalize_memberships(memberships: &mut [HierarchyMembership]) {
    memberships.sort_by(|left, right| {
        left.child
            .cmp(&right.child)
            .then_with(|| role_rank(left.role).cmp(&role_rank(right.role)))
            .then_with(|| {
                right
                    .provenance
                    .source
                    .precedence()
                    .cmp(&left.provenance.source.precedence())
            })
            .then_with(|| right.confidence.cmp(&left.confidence))
            .then_with(|| left.order_key.cmp(&right.order_key))
            .then_with(|| left.parent.cmp(&right.parent))
    });
}

const fn role_rank(role: MembershipRole) -> u8 {
    match role {
        MembershipRole::Primary => 0,
        MembershipRole::Alternative => 1,
    }
}

pub(crate) fn topological_order(
    adjacency: &BTreeMap<HierarchyItemId, Vec<HierarchyItemId>>,
    incoming: &BTreeMap<HierarchyItemId, usize>,
) -> Result<Vec<HierarchyItemId>> {
    let mut remaining: BTreeMap<_, _> = adjacency
        .keys()
        .copied()
        .map(|item| (item, incoming.get(&item).copied().unwrap_or(0)))
        .collect();
    let mut ready: BTreeSet<_> = remaining
        .iter()
        .filter_map(|(item, count)| (*count == 0).then_some(*item))
        .collect();
    let mut ordered = Vec::with_capacity(adjacency.len());
    while let Some(item) = ready.pop_first() {
        ordered.push(item);
        if let Some(children) = adjacency.get(&item) {
            for child in children {
                let count = remaining
                    .get_mut(child)
                    .ok_or(HierarchyError::UnknownItem(*child))?;
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ready.insert(*child);
                }
            }
        }
    }
    if ordered.len() != adjacency.len() {
        return Err(HierarchyError::Cycle);
    }
    Ok(ordered)
}

pub(crate) fn compute_statistics(
    adjacency: &BTreeMap<HierarchyItemId, Vec<HierarchyItemId>>,
    roots: &BTreeSet<HierarchyItemId>,
    topological: &[HierarchyItemId],
) -> BTreeMap<HierarchyItemId, BranchStatistics> {
    let mut routes: BTreeMap<_, u64> = adjacency.keys().copied().map(|item| (item, 0)).collect();
    for root in roots {
        routes.insert(*root, 1);
    }
    for item in topological {
        let route_count = routes.get(item).copied().unwrap_or(0);
        if let Some(children) = adjacency.get(item) {
            for child in children {
                let entry = routes.entry(*child).or_default();
                *entry = entry.saturating_add(route_count);
            }
        }
    }

    let mut longest_downward_path: BTreeMap<HierarchyItemId, u32> = BTreeMap::new();
    for item in topological.iter().rev() {
        let depth = adjacency.get(item).map_or(0, |children| {
            children
                .iter()
                .map(|child| {
                    longest_downward_path
                        .get(child)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(1)
                })
                .max()
                .unwrap_or(0)
        });
        longest_downward_path.insert(*item, depth);
    }

    adjacency
        .keys()
        .copied()
        .map(|item| {
            let mut descendants = BTreeSet::new();
            let mut leaves = BTreeSet::new();
            let mut stack = Vec::new();
            if let Some(children) = adjacency.get(&item) {
                stack.extend(children.iter().copied());
            }
            while let Some(current) = stack.pop() {
                if !descendants.insert(current) {
                    continue;
                }
                match adjacency.get(&current) {
                    Some(children) if !children.is_empty() => {
                        stack.extend(children.iter().copied());
                    }
                    _ => {
                        leaves.insert(current);
                    }
                }
            }
            (
                item,
                BranchStatistics {
                    direct_children: u64::try_from(adjacency.get(&item).map_or(0, Vec::len))
                        .unwrap_or(u64::MAX),
                    unique_descendants: u64::try_from(descendants.len()).unwrap_or(u64::MAX),
                    leaf_descendants: u64::try_from(leaves.len()).unwrap_or(u64::MAX),
                    max_depth: longest_downward_path.get(&item).copied().unwrap_or(0),
                    routes_from_roots: routes.get(&item).copied().unwrap_or(0),
                },
            )
        })
        .collect()
}
