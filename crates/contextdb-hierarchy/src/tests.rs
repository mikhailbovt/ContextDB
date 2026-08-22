#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use immediate failure semantics"
)]

use std::collections::BTreeSet;

use contextdb_core::{
    ClaimId, CommitSeq, DerivationId, DerivationKind, DerivationRef, HierarchyViewId, LineageNode,
    MaintenanceOperation, MemorySpaceId, NodeId, PipelineIdentity, RevisionNumber, ScopeId,
    ScopeInheritance, ScopeKind, ScopeRef, SnapshotRef, TimeRange, TimestampMicros, Validate,
    WorkspaceId,
};
use proptest::prelude::*;

use crate::{
    AssignmentCandidate, AssignmentPolicy, AssignmentSource, AuthorizationSnapshot,
    BeamTraversalRequest, Confidence, DeletionRecord, FreshnessRequirement, GenerationNumber,
    HierarchyEpoch, HierarchyError, HierarchyGeneration, HierarchyInvalidation, HierarchyItemId,
    HierarchyKind, HierarchyNode, HierarchyProfile, HierarchyProposal, HierarchyProposalBuilder,
    HierarchyProvenance, HierarchyRead, HierarchySnapshotSelector, HierarchyValidity,
    InMemoryHierarchyEngine, InvalidationReason, MembershipRole, PolicyPartition, RouteRequest,
    validate_proposal,
};

fn confidence(value: u16) -> Confidence {
    Confidence::from_basis_points(value).expect("valid confidence")
}

fn provenance(
    source: AssignmentSource,
    rationale: &str,
    inputs: Vec<LineageNode>,
) -> HierarchyProvenance {
    HierarchyProvenance {
        source,
        derivation: DerivationRef {
            id: DerivationId::new(),
            kind: DerivationKind::DeterministicProjector,
            actor: None,
            model_call: None,
            pipeline: PipelineIdentity {
                name: "hierarchy-test-builder".to_owned(),
                version: "1".to_owned(),
                schema_version: "1".to_owned(),
            },
            inputs,
        },
        rationale: rationale.to_owned(),
    }
}

fn partition(workspace_id: WorkspaceId, revision: u64) -> PolicyPartition {
    PolicyPartition::new(
        workspace_id,
        BTreeSet::from([MemorySpaceId::new()]),
        BTreeSet::from([ScopeRef {
            kind: ScopeKind::Workspace,
            id: ScopeId::new(),
            inheritance: ScopeInheritance::Descendants,
        }]),
        CommitSeq::new(revision),
    )
    .expect("valid policy partition")
}

fn profile(
    view_id: HierarchyViewId,
    workspace_id: WorkspaceId,
    partitions: Vec<PolicyPartition>,
    profile_revision: u64,
) -> HierarchyProfile {
    HierarchyProfile {
        id: view_id,
        workspace_id,
        kind: HierarchyKind::TopicsKnowledge,
        name: "Topics and knowledge".to_owned(),
        profile_revision,
        partitions: partitions
            .into_iter()
            .map(|partition| (partition.id, partition))
            .collect(),
        assignment: AssignmentPolicy::default(),
    }
}

fn branch_node(
    view_id: HierarchyViewId,
    partition: crate::PolicyPartitionId,
    key: &str,
    build: CommitSeq,
    provenance: HierarchyProvenance,
) -> HierarchyNode {
    HierarchyNode {
        id: HierarchyItemId::Branch(
            crate::HierarchyBranchId::derive(view_id, partition, key).expect("branch id"),
        ),
        label: key.to_owned(),
        partition,
        confidence: confidence(9_000),
        validity: HierarchyValidity::current_from(build),
        provenance,
    }
}

fn semantic_node(
    id: NodeId,
    partition: crate::PolicyPartitionId,
    build: CommitSeq,
) -> HierarchyNode {
    HierarchyNode {
        id: HierarchyItemId::Semantic(id),
        label: "semantic item".to_owned(),
        partition,
        confidence: confidence(9_500),
        validity: HierarchyValidity::current_from(build),
        provenance: provenance(
            AssignmentSource::TypedRelation,
            "canonical semantic dependency",
            vec![LineageNode::NodeRevision {
                id,
                revision: RevisionNumber::FIRST,
            }],
        ),
    }
}

fn candidate(
    parent: HierarchyItemId,
    child: HierarchyItemId,
    source: AssignmentSource,
    score: u16,
    build: CommitSeq,
) -> AssignmentCandidate {
    AssignmentCandidate {
        parent,
        child,
        order_key: 0,
        confidence: confidence(score),
        validity: HierarchyValidity::current_from(build),
        provenance: provenance(source, "deterministic membership", Vec::new()),
    }
}

fn proposal_from(
    profile: HierarchyProfile,
    expected_active: Option<GenerationNumber>,
    built_from: CommitSeq,
    nodes: Vec<HierarchyNode>,
    candidates: Vec<AssignmentCandidate>,
) -> HierarchyProposal {
    let mut builder = HierarchyProposalBuilder::new(
        profile,
        expected_active,
        SnapshotRef {
            commit_seq: built_from,
        },
        provenance(
            AssignmentSource::DeterministicCommunity,
            "deterministic side-by-side build",
            Vec::new(),
        ),
    )
    .expect("proposal builder");
    for node in nodes {
        builder.add_node(node).expect("unique node");
    }
    for candidate in candidates {
        builder.add_candidate(candidate);
    }
    builder.finish()
}

fn authorization(
    workspace_id: WorkspaceId,
    partitions: impl IntoIterator<Item = crate::PolicyPartitionId>,
    at: CommitSeq,
) -> AuthorizationSnapshot {
    AuthorizationSnapshot::new(workspace_id, partitions.into_iter().collect(), at)
}

fn route_request(
    view_id: HierarchyViewId,
    target: HierarchyItemId,
    semantic: CommitSeq,
    freshness: FreshnessRequirement,
) -> RouteRequest {
    RouteRequest {
        view_id,
        target,
        semantic_snapshot: SnapshotRef {
            commit_seq: semantic,
        },
        domain_time: None,
        max_routes: 8,
        max_depth: 8,
        freshness,
    }
}

#[test]
fn deterministic_assignment_preserves_multiple_parents_and_materializes_both_routes() {
    let workspace = WorkspaceId::new();
    let view = HierarchyViewId::new();
    let partition = partition(workspace, 5);
    let first_profile = profile(view, workspace, vec![partition.clone()], 1);
    let build = CommitSeq::new(5);
    let parent_manual = branch_node(
        view,
        partition.id,
        "manual-parent",
        build,
        provenance(
            AssignmentSource::ManualOverride,
            "manual branch",
            Vec::new(),
        ),
    );
    let parent_adapter = branch_node(
        view,
        partition.id,
        "adapter-parent",
        build,
        provenance(
            AssignmentSource::AdapterStructure,
            "adapter branch",
            Vec::new(),
        ),
    );
    let child_id = NodeId::new();
    let child = semantic_node(child_id, partition.id, build);
    let manual = candidate(
        parent_manual.id,
        child.id,
        AssignmentSource::ManualOverride,
        7_000,
        build,
    );
    let adapter = candidate(
        parent_adapter.id,
        child.id,
        AssignmentSource::AdapterStructure,
        9_500,
        build,
    );

    let first = proposal_from(
        first_profile.clone(),
        None,
        build,
        vec![parent_manual.clone(), parent_adapter.clone(), child.clone()],
        vec![adapter.clone(), manual.clone()],
    );
    let mut second = proposal_from(
        first_profile,
        None,
        build,
        vec![child.clone(), parent_adapter.clone(), parent_manual.clone()],
        vec![manual, adapter],
    );
    second.build_provenance = first.build_provenance.clone();
    let first = validate_proposal(first).expect("valid first proposal");
    let second = validate_proposal(second).expect("valid reordered proposal");
    assert_eq!(first.digest(), second.digest());
    assert_eq!(
        first
            .statistics
            .get(&child.id)
            .expect("child statistics")
            .routes_from_roots,
        2
    );

    let engine = InMemoryHierarchyEngine::new();
    let published = engine.publish(&first).expect("publish generation");
    assert_eq!(published.generation.get(), 1);
    assert_eq!(published.manifest_digest, first.manifest_digest());
    assert!(
        published
            .manifest_digest
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0)
    );
    MaintenanceOperation::HierarchyPublication {
        view_id: published.view_id,
        generation: published.generation.get(),
        manifest_digest: published.manifest_digest,
    }
    .validate()
    .expect("core maintenance publication contract");
    let snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("snapshot");
    let authorization = authorization(workspace, [partition.id], build);
    let materialized = snapshot
        .materialize_routes(
            &route_request(view, child.id, build, FreshnessRequirement::RequireCurrent),
            &authorization,
        )
        .expect("materialize routes");
    assert_eq!(materialized.routes.len(), 2);
    assert_eq!(materialized.routes[0].items[0], parent_manual.id);
    assert_eq!(
        materialized.routes[0].memberships[0].role,
        MembershipRole::Primary
    );
    assert_eq!(materialized.routes[1].items[0], parent_adapter.id);
    assert_eq!(
        materialized.routes[1].memberships[0].role,
        MembershipRole::Alternative
    );
    assert_eq!(materialized.routes[0].nodes[1], child);

    let bundle = engine.export_persistent().expect("persistent bundle");
    let restored = InMemoryHierarchyEngine::from_persistent(&bundle).expect("restore hierarchy");
    let restored_routes = restored
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("restored snapshot")
        .materialize_routes(
            &route_request(view, child.id, build, FreshnessRequirement::RequireCurrent),
            &authorization,
        )
        .expect("restored routes");
    assert_eq!(restored_routes, materialized);
    let mut corrupted = bundle;
    corrupted.payload[0] ^= 1;
    assert!(InMemoryHierarchyEngine::from_persistent(&corrupted).is_err());
    let (statistics, freshness) = snapshot
        .branch_statistics(
            view,
            child.id,
            SnapshotRef { commit_seq: build },
            FreshnessRequirement::RequireCurrent,
            &authorization,
        )
        .expect("policy-safe statistics");
    assert_eq!(statistics.routes_from_roots, 2);
    assert!(freshness.current);

    let traversal = snapshot
        .beam_traverse(
            &BeamTraversalRequest {
                view_id: view,
                semantic_snapshot: SnapshotRef { commit_seq: build },
                domain_time: None,
                roots: BTreeSet::new(),
                beam_width: 8,
                max_depth: 2,
                max_expansions: 8,
                freshness: FreshnessRequirement::RequireCurrent,
            },
            &authorization,
        )
        .expect("beam traversal");
    assert_eq!(traversal.expansions, 2);
    assert_eq!(
        traversal
            .hits
            .iter()
            .filter(|hit| hit.item == child.id)
            .count(),
        2
    );
}

#[test]
fn branch_statistics_use_longest_path_in_a_converging_dag() {
    let workspace = WorkspaceId::new();
    let view = HierarchyViewId::new();
    let partition = partition(workspace, 1);
    let build = CommitSeq::new(1);
    let root = branch_node(
        view,
        partition.id,
        "root",
        build,
        provenance(AssignmentSource::ManualOverride, "root", Vec::new()),
    );
    let first = branch_node(
        view,
        partition.id,
        "first",
        build,
        provenance(AssignmentSource::ManualOverride, "first", Vec::new()),
    );
    let second = branch_node(
        view,
        partition.id,
        "second",
        build,
        provenance(AssignmentSource::ManualOverride, "second", Vec::new()),
    );
    let (long_parent, short_parent) = if first.id < second.id {
        (first.clone(), second.clone())
    } else {
        (second.clone(), first.clone())
    };
    let middle = branch_node(
        view,
        partition.id,
        "middle",
        build,
        provenance(AssignmentSource::ManualOverride, "middle", Vec::new()),
    );
    let shared = branch_node(
        view,
        partition.id,
        "shared",
        build,
        provenance(AssignmentSource::ManualOverride, "shared", Vec::new()),
    );
    let leaf = semantic_node(NodeId::new(), partition.id, build);
    let proposal = validate_proposal(proposal_from(
        profile(view, workspace, vec![partition], 1),
        None,
        build,
        vec![
            root.clone(),
            first,
            second,
            middle.clone(),
            shared.clone(),
            leaf.clone(),
        ],
        vec![
            candidate(
                root.id,
                short_parent.id,
                AssignmentSource::ManualOverride,
                9_000,
                build,
            ),
            candidate(
                root.id,
                long_parent.id,
                AssignmentSource::ManualOverride,
                9_000,
                build,
            ),
            candidate(
                short_parent.id,
                shared.id,
                AssignmentSource::ManualOverride,
                9_000,
                build,
            ),
            candidate(
                long_parent.id,
                middle.id,
                AssignmentSource::ManualOverride,
                9_000,
                build,
            ),
            candidate(
                middle.id,
                shared.id,
                AssignmentSource::ManualOverride,
                9_000,
                build,
            ),
            candidate(
                shared.id,
                leaf.id,
                AssignmentSource::ManualOverride,
                9_000,
                build,
            ),
        ],
    ))
    .expect("converging DAG validates");
    let root_statistics = proposal.statistics.get(&root.id).expect("root statistics");
    assert_eq!(root_statistics.max_depth, 4);
    assert_eq!(root_statistics.unique_descendants, 5);
    assert_eq!(root_statistics.leaf_descendants, 1);
    assert_eq!(
        proposal
            .statistics
            .get(&leaf.id)
            .expect("leaf statistics")
            .routes_from_roots,
        2
    );
}

proptest! {
    #[test]
    fn candidate_input_order_and_duplicates_do_not_change_generation_digest(
        order in prop::collection::vec(0_usize..3, 0..24)
    ) {
        let workspace = WorkspaceId::new();
        let view = HierarchyViewId::new();
        let partition = partition(workspace, 1);
        let profile = profile(view, workspace, vec![partition.clone()], 1);
        let build = CommitSeq::new(1);
        let child = semantic_node(NodeId::new(), partition.id, build);
        let parents = [
            branch_node(view, partition.id, "a", build, provenance(AssignmentSource::TypedRelation, "a", Vec::new())),
            branch_node(view, partition.id, "b", build, provenance(AssignmentSource::ScopeRelation, "b", Vec::new())),
            branch_node(view, partition.id, "c", build, provenance(AssignmentSource::AdapterStructure, "c", Vec::new())),
        ];
        let candidates = [
            candidate(parents[0].id, child.id, AssignmentSource::TypedRelation, 7_000, build),
            candidate(parents[1].id, child.id, AssignmentSource::ScopeRelation, 8_000, build),
            candidate(parents[2].id, child.id, AssignmentSource::AdapterStructure, 9_000, build),
        ];
        let nodes = vec![parents[0].clone(), parents[1].clone(), parents[2].clone(), child.clone()];
        let baseline_proposal = proposal_from(
            profile.clone(), None, build, nodes.clone(), candidates.to_vec()
        );
        let mut reordered = candidates.to_vec();
        reordered.extend(order.into_iter().map(|index| candidates[index].clone()));
        reordered.reverse();
        let mut candidate_proposal = proposal_from(
            profile, None, build, nodes, reordered
        );
        candidate_proposal.build_provenance = baseline_proposal.build_provenance.clone();
        let baseline = validate_proposal(baseline_proposal).expect("baseline validates");
        let candidate = validate_proposal(candidate_proposal).expect("reordered validates");
        prop_assert_eq!(candidate.digest(), baseline.digest());
        prop_assert_eq!(candidate.proposal.memberships.len(), 3);
    }
}

#[test]
fn equal_rank_duplicate_edges_are_canonicalized_without_input_order_dependence() {
    let workspace = WorkspaceId::new();
    let view = HierarchyViewId::new();
    let partition = partition(workspace, 1);
    let build = CommitSeq::new(1);
    let parent = branch_node(
        view,
        partition.id,
        "parent",
        build,
        provenance(AssignmentSource::TypedRelation, "parent", Vec::new()),
    );
    let child_id = NodeId::new();
    let child = semantic_node(child_id, partition.id, build);
    let mut first_candidate = candidate(
        parent.id,
        child.id,
        AssignmentSource::TypedRelation,
        8_000,
        build,
    );
    first_candidate.provenance.rationale = "first deterministic rationale".to_owned();
    let mut second_candidate = first_candidate.clone();
    second_candidate.provenance.rationale = "second deterministic rationale".to_owned();

    let baseline_proposal = proposal_from(
        profile(view, workspace, vec![partition.clone()], 1),
        None,
        build,
        vec![parent.clone(), child.clone()],
        vec![first_candidate.clone(), second_candidate.clone()],
    );
    let mut reordered_proposal = proposal_from(
        profile(view, workspace, vec![partition], 1),
        None,
        build,
        vec![parent, child],
        vec![second_candidate, first_candidate],
    );
    reordered_proposal.build_provenance = baseline_proposal.build_provenance.clone();
    let baseline = validate_proposal(baseline_proposal).expect("baseline validates");
    let reordered = validate_proposal(reordered_proposal).expect("reordered validates");
    assert_eq!(baseline.digest(), reordered.digest());
    assert_eq!(
        baseline.proposal.memberships,
        reordered.proposal.memberships
    );
}

#[test]
fn serialized_scalar_invariants_are_fail_closed() {
    assert!(serde_json::from_str::<Confidence>("10001").is_err());
    assert!(serde_json::from_str::<GenerationNumber>("0").is_err());
    assert_eq!(
        serde_json::from_str::<Confidence>("10000")
            .expect("maximum confidence")
            .basis_points(),
        10_000
    );
    assert_eq!(
        serde_json::from_str::<GenerationNumber>("1")
            .expect("first generation")
            .get(),
        1
    );
}

#[test]
fn persisted_generation_manifest_is_revalidatable_and_tamper_evident() {
    let workspace = WorkspaceId::new();
    let view = HierarchyViewId::new();
    let partition = partition(workspace, 1);
    let build = CommitSeq::new(1);
    let node = branch_node(
        view,
        partition.id,
        "root",
        build,
        provenance(AssignmentSource::ManualOverride, "root", Vec::new()),
    );
    let validated = validate_proposal(proposal_from(
        profile(view, workspace, vec![partition], 1),
        None,
        build,
        vec![node.clone()],
        Vec::new(),
    ))
    .expect("proposal");
    let mut loaded = HierarchyGeneration {
        profile: validated.proposal.profile.clone(),
        generation: validated.proposal.generation,
        built_from: validated.proposal.built_from,
        published_epoch: HierarchyEpoch::new(1),
        roots: validated.proposal.roots.clone(),
        nodes: validated.proposal.nodes.clone(),
        memberships: validated.proposal.memberships.clone(),
        statistics: validated.statistics.clone(),
        manifest_digest: validated.manifest_digest(),
        build_provenance: validated.proposal.build_provenance.clone(),
    };
    loaded.verify_manifest().expect("manifest verifies");
    loaded
        .statistics
        .get_mut(&node.id)
        .expect("root statistics")
        .direct_children = 1;
    assert!(matches!(
        loaded.verify_manifest(),
        Err(HierarchyError::ManifestMismatch)
    ));
}

#[test]
fn cycles_and_cross_partition_memberships_fail_before_publication() {
    let workspace = WorkspaceId::new();
    let view = HierarchyViewId::new();
    let first_partition = partition(workspace, 1);
    let second_partition = partition(workspace, 2);
    let build = CommitSeq::new(2);
    let profile = profile(
        view,
        workspace,
        vec![first_partition.clone(), second_partition.clone()],
        1,
    );
    let first = branch_node(
        view,
        first_partition.id,
        "first",
        build,
        provenance(AssignmentSource::ManualOverride, "first", Vec::new()),
    );
    let second = branch_node(
        view,
        first_partition.id,
        "second",
        build,
        provenance(AssignmentSource::ManualOverride, "second", Vec::new()),
    );
    let cycle = proposal_from(
        profile.clone(),
        None,
        build,
        vec![first.clone(), second.clone()],
        vec![
            candidate(
                first.id,
                second.id,
                AssignmentSource::ManualOverride,
                10_000,
                build,
            ),
            candidate(
                second.id,
                first.id,
                AssignmentSource::ManualOverride,
                10_000,
                build,
            ),
        ],
    );
    assert!(matches!(
        validate_proposal(cycle),
        Err(HierarchyError::Cycle)
    ));

    let other_partition_node = branch_node(
        view,
        second_partition.id,
        "other-partition",
        build,
        provenance(AssignmentSource::ManualOverride, "other", Vec::new()),
    );
    let crossing = proposal_from(
        profile,
        None,
        build,
        vec![first.clone(), other_partition_node.clone()],
        vec![candidate(
            first.id,
            other_partition_node.id,
            AssignmentSource::ManualOverride,
            10_000,
            build,
        )],
    );
    assert!(matches!(
        validate_proposal(crossing),
        Err(HierarchyError::CrossPartitionMembership)
    ));

    let engine = InMemoryHierarchyEngine::new();
    let snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("empty snapshot");
    assert_eq!(HierarchyRead::epoch(&snapshot), HierarchyEpoch::GENESIS);
    assert!(
        snapshot
            .available_views(
                SnapshotRef { commit_seq: build },
                &authorization(workspace, [first_partition.id], build)
            )
            .is_empty()
    );
}

#[test]
fn policy_filtering_prevents_tenant_and_partition_existence_leaks() {
    let workspace = WorkspaceId::new();
    let other_workspace = WorkspaceId::new();
    let view = HierarchyViewId::new();
    let visible_partition = partition(workspace, 1);
    let secret_partition = partition(workspace, 2);
    let build = CommitSeq::new(2);
    let profile = profile(
        view,
        workspace,
        vec![visible_partition.clone(), secret_partition.clone()],
        1,
    );
    let visible = branch_node(
        view,
        visible_partition.id,
        "visible",
        build,
        provenance(AssignmentSource::AdapterStructure, "visible", Vec::new()),
    );
    let secret = branch_node(
        view,
        secret_partition.id,
        "secret",
        build,
        provenance(AssignmentSource::AdapterStructure, "secret", Vec::new()),
    );
    let proposal = validate_proposal(proposal_from(
        profile,
        None,
        build,
        vec![visible.clone(), secret.clone()],
        Vec::new(),
    ))
    .expect("partitioned view validates");
    let engine = InMemoryHierarchyEngine::new();
    engine.publish(&proposal).expect("publish");
    let snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("snapshot");
    let visible_auth = authorization(workspace, [visible_partition.id], build);
    assert_eq!(
        snapshot.available_views(SnapshotRef { commit_seq: build }, &visible_auth),
        vec![view]
    );
    assert!(matches!(
        snapshot.resolve_node(
            view,
            secret.id,
            SnapshotRef { commit_seq: build },
            None,
            FreshnessRequirement::RequireCurrent,
            &visible_auth,
        ),
        Err(HierarchyError::RouteUnavailable)
    ));
    let cross_tenant = authorization(other_workspace, [visible_partition.id], build);
    assert!(matches!(
        snapshot.materialize_routes(
            &route_request(
                view,
                visible.id,
                build,
                FreshnessRequirement::RequireCurrent
            ),
            &cross_tenant,
        ),
        Err(HierarchyError::RouteUnavailable)
    ));
    assert!(
        snapshot
            .available_views(SnapshotRef { commit_seq: build }, &cross_tenant)
            .is_empty()
    );
    let stale_authorization = authorization(workspace, [visible_partition.id], CommitSeq::new(1));
    assert!(matches!(
        snapshot.resolve_node(
            view,
            visible.id,
            SnapshotRef { commit_seq: build },
            None,
            FreshnessRequirement::RequireCurrent,
            &stale_authorization,
        ),
        Err(HierarchyError::RouteUnavailable)
    ));
}

#[test]
fn overlapping_views_share_semantic_ids_without_becoming_one_taxonomy() {
    let workspace = WorkspaceId::new();
    let partition = partition(workspace, 3);
    let semantic_id = NodeId::new();
    let build = CommitSeq::new(3);
    let engine = InMemoryHierarchyEngine::new();
    let mut view_ids = Vec::new();
    for (kind, label) in [
        (HierarchyKind::TopicsKnowledge, "topic-root"),
        (HierarchyKind::Projects, "project-root"),
    ] {
        let view = HierarchyViewId::new();
        view_ids.push(view);
        let mut profile = profile(view, workspace, vec![partition.clone()], 1);
        profile.kind = kind;
        let root = branch_node(
            view,
            partition.id,
            label,
            build,
            provenance(AssignmentSource::AdapterStructure, label, Vec::new()),
        );
        let child = semantic_node(semantic_id, partition.id, build);
        let proposal = validate_proposal(proposal_from(
            profile,
            None,
            build,
            vec![root.clone(), child.clone()],
            vec![candidate(
                root.id,
                child.id,
                AssignmentSource::AdapterStructure,
                9_000,
                build,
            )],
        ))
        .expect("overlapping view validates");
        engine.publish(&proposal).expect("publish overlapping view");
    }
    let snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("snapshot");
    let authorization = authorization(workspace, [partition.id], build);
    assert_eq!(
        snapshot
            .available_views(SnapshotRef { commit_seq: build }, &authorization)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        view_ids.iter().copied().collect()
    );
    for view in view_ids {
        let result = snapshot
            .materialize_routes(
                &route_request(
                    view,
                    HierarchyItemId::Semantic(semantic_id),
                    build,
                    FreshnessRequirement::RequireCurrent,
                ),
                &authorization,
            )
            .expect("view-specific route");
        assert_eq!(result.routes.len(), 1);
    }
}

#[test]
fn side_by_side_rebuild_is_atomic_and_old_snapshot_remains_isolated() {
    let workspace = WorkspaceId::new();
    let partition = partition(workspace, 5);
    let view = HierarchyViewId::new();
    let child_id = NodeId::new();
    let first_build = CommitSeq::new(5);
    let first_profile = profile(view, workspace, vec![partition.clone()], 1);
    let first_root = branch_node(
        view,
        partition.id,
        "old-root",
        first_build,
        provenance(AssignmentSource::AdapterStructure, "old root", Vec::new()),
    );
    let first_child = semantic_node(child_id, partition.id, first_build);
    let first = validate_proposal(proposal_from(
        first_profile,
        None,
        first_build,
        vec![first_root.clone(), first_child.clone()],
        vec![candidate(
            first_root.id,
            first_child.id,
            AssignmentSource::AdapterStructure,
            9_000,
            first_build,
        )],
    ))
    .expect("first generation validates");
    let engine = InMemoryHierarchyEngine::new();
    let first_ref = engine.publish(&first).expect("publish first");
    let old_snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("old snapshot");
    let old_authorization = authorization(workspace, [partition.id], first_build);
    let old_route = old_snapshot
        .materialize_routes(
            &route_request(
                view,
                first_child.id,
                first_build,
                FreshnessRequirement::RequireCurrent,
            ),
            &old_authorization,
        )
        .expect("old route")
        .routes
        .remove(0);

    let second_build = CommitSeq::new(6);
    let second_profile = profile(view, workspace, vec![partition.clone()], 2);
    let second_root = branch_node(
        view,
        partition.id,
        "new-root",
        second_build,
        provenance(AssignmentSource::ManualOverride, "new root", Vec::new()),
    );
    let second_child = semantic_node(child_id, partition.id, second_build);
    let second_proposal = proposal_from(
        second_profile.clone(),
        Some(first_ref.generation),
        second_build,
        vec![second_root.clone(), second_child.clone()],
        vec![candidate(
            second_root.id,
            second_child.id,
            AssignmentSource::ManualOverride,
            10_000,
            second_build,
        )],
    );
    let mut reused_profile_revision = second_proposal.clone();
    reused_profile_revision.profile.profile_revision = 1;
    reused_profile_revision.profile.name = "changed without revision".to_owned();
    let reused_profile_revision =
        validate_proposal(reused_profile_revision).expect("structurally valid proposal");
    assert!(matches!(
        engine.publish(&reused_profile_revision),
        Err(HierarchyError::ProfileRevisionReuse(1))
    ));
    let stale_concurrent = validate_proposal(second_proposal.clone()).expect("stale build valid");
    let second = validate_proposal(second_proposal).expect("second generation validates");
    let second_ref = engine.publish(&second).expect("atomic generation switch");
    assert_eq!(second_ref.generation.get(), 2);
    assert!(matches!(
        engine.publish(&stale_concurrent),
        Err(HierarchyError::ActiveGenerationConflict)
    ));

    old_snapshot
        .validate_route(&old_route, &old_authorization)
        .expect("old snapshot retains old generation");
    let new_snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("new snapshot");
    assert!(matches!(
        new_snapshot.validate_route(&old_route, &old_authorization),
        Err(HierarchyError::StaleRoute)
    ));
    let new_authorization = authorization(workspace, [partition.id], second_build);
    let new_route = new_snapshot
        .materialize_routes(
            &route_request(
                view,
                second_child.id,
                second_build,
                FreshnessRequirement::RequireCurrent,
            ),
            &new_authorization,
        )
        .expect("new route");
    assert_eq!(new_route.routes[0].items[0], second_root.id);
    let historical = new_snapshot
        .materialize_routes(
            &route_request(
                view,
                first_child.id,
                first_build,
                FreshnessRequirement::RequireCurrent,
            ),
            &old_authorization,
        )
        .expect("new catalog retains historical semantic generation");
    assert_eq!(historical.routes[0].items[0], first_root.id);
}

#[test]
fn stale_and_future_routes_are_never_silently_presented_as_current() {
    let workspace = WorkspaceId::new();
    let partition = partition(workspace, 5);
    let view = HierarchyViewId::new();
    let build = CommitSeq::new(5);
    let first_profile = profile(view, workspace, vec![partition.clone()], 1);
    let node = branch_node(
        view,
        partition.id,
        "root",
        build,
        provenance(AssignmentSource::ManualOverride, "root", Vec::new()),
    );
    let proposal = validate_proposal(proposal_from(
        first_profile,
        None,
        build,
        vec![node.clone()],
        Vec::new(),
    ))
    .expect("proposal");
    let engine = InMemoryHierarchyEngine::new();
    engine.publish(&proposal).expect("publish");
    let snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("snapshot");
    let authorization = authorization(workspace, [partition.id], CommitSeq::new(7));
    assert!(matches!(
        snapshot.materialize_routes(
            &route_request(
                view,
                node.id,
                CommitSeq::new(7),
                FreshnessRequirement::RequireCurrent,
            ),
            &authorization,
        ),
        Err(HierarchyError::StaleGeneration { .. })
    ));
    let stale = snapshot
        .materialize_routes(
            &route_request(
                view,
                node.id,
                CommitSeq::new(7),
                FreshnessRequirement::AllowStale,
            ),
            &authorization,
        )
        .expect("explicit stale route");
    assert!(!stale.freshness.current);
    assert_eq!(stale.freshness.covered_through, build);
    assert!(matches!(
        snapshot.materialize_routes(
            &route_request(
                view,
                node.id,
                CommitSeq::new(4),
                FreshnessRequirement::AllowStale,
            ),
            &authorization,
        ),
        Err(HierarchyError::GenerationUnavailable(_))
    ));

    engine
        .invalidate(HierarchyInvalidation {
            view_id: view,
            workspace_id: workspace,
            dirty_through: CommitSeq::new(7),
            reason: InvalidationReason::SemanticRevision,
            affected_items: BTreeSet::from([node.id]),
        })
        .expect("mark dirty without mutation");
    let invalidated = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("invalidated snapshot");
    assert!(matches!(
        invalidated.materialize_routes(
            &route_request(
                view,
                node.id,
                CommitSeq::new(7),
                FreshnessRequirement::RequireCurrent,
            ),
            &authorization,
        ),
        Err(HierarchyError::StaleGeneration { .. })
    ));
}

#[test]
fn deletion_closure_applies_to_old_snapshots_and_blocks_stale_rebuild_resurrection() {
    let workspace = WorkspaceId::new();
    let partition = partition(workspace, 5);
    let view = HierarchyViewId::new();
    let semantic_id = NodeId::new();
    let build = CommitSeq::new(5);
    let first_profile = profile(view, workspace, vec![partition.clone()], 1);
    let root = branch_node(
        view,
        partition.id,
        "derived-root",
        build,
        provenance(
            AssignmentSource::DeterministicCommunity,
            "branch derived from semantic node",
            vec![LineageNode::NodeRevision {
                id: semantic_id,
                revision: RevisionNumber::FIRST,
            }],
        ),
    );
    let child = semantic_node(semantic_id, partition.id, build);
    let first = validate_proposal(proposal_from(
        first_profile,
        None,
        build,
        vec![root.clone(), child.clone()],
        vec![candidate(
            root.id,
            child.id,
            AssignmentSource::DeterministicCommunity,
            9_000,
            build,
        )],
    ))
    .expect("proposal");
    let engine = InMemoryHierarchyEngine::new();
    let first_ref = engine.publish(&first).expect("publish");
    let old_snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("old snapshot");
    let authorization = authorization(workspace, [partition.id], build);
    let cached = old_snapshot
        .materialize_routes(
            &route_request(view, child.id, build, FreshnessRequirement::RequireCurrent),
            &authorization,
        )
        .expect("route before deletion")
        .routes
        .remove(0);
    engine
        .record_deletions(DeletionRecord {
            workspace_id: workspace,
            node_ids: BTreeSet::from([semantic_id]),
            lineage_dependencies: BTreeSet::new(),
            effective_at: CommitSeq::new(6),
        })
        .expect("install deletion closure");
    assert!(matches!(
        old_snapshot.materialize_routes(
            &route_request(view, child.id, build, FreshnessRequirement::AllowStale,),
            &authorization,
        ),
        Err(HierarchyError::RouteUnavailable)
    ));
    assert!(matches!(
        old_snapshot.validate_route(&cached, &authorization),
        Err(HierarchyError::StaleRoute)
    ));
    let restored = InMemoryHierarchyEngine::from_persistent(
        &engine
            .export_persistent()
            .expect("persistent deletion state"),
    )
    .expect("restore deletion state");
    assert!(matches!(
        restored
            .snapshot(HierarchySnapshotSelector::At(first_ref.published_epoch))
            .expect("restored historical catalog")
            .materialize_routes(
                &route_request(view, child.id, build, FreshnessRequirement::AllowStale),
                &authorization,
            ),
        Err(HierarchyError::RouteUnavailable)
    ));

    let rebuild = validate_proposal(proposal_from(
        profile(view, workspace, vec![partition.clone()], 2),
        Some(first_ref.generation),
        CommitSeq::new(6),
        vec![
            branch_node(
                view,
                partition.id,
                "replacement-root",
                CommitSeq::new(6),
                provenance(AssignmentSource::ManualOverride, "replacement", Vec::new()),
            ),
            semantic_node(semantic_id, partition.id, CommitSeq::new(6)),
        ],
        Vec::new(),
    ))
    .expect("structurally valid rebuild");
    assert!(matches!(
        engine.publish(&rebuild),
        Err(HierarchyError::DeletedDependency(id)) if id == semantic_id
    ));
}

#[test]
fn policy_safe_statistics_recompute_after_deletion_closure() {
    let workspace = WorkspaceId::new();
    let partition = partition(workspace, 5);
    let view = HierarchyViewId::new();
    let deleted_id = NodeId::new();
    let retained_id = NodeId::new();
    let build = CommitSeq::new(5);
    let root = branch_node(
        view,
        partition.id,
        "root",
        build,
        provenance(AssignmentSource::ManualOverride, "root", Vec::new()),
    );
    let deleted = semantic_node(deleted_id, partition.id, build);
    let retained = semantic_node(retained_id, partition.id, build);
    let proposal = validate_proposal(proposal_from(
        profile(view, workspace, vec![partition.clone()], 1),
        None,
        build,
        vec![root.clone(), deleted.clone(), retained],
        vec![
            candidate(
                root.id,
                deleted.id,
                AssignmentSource::ManualOverride,
                9_000,
                build,
            ),
            candidate(
                root.id,
                HierarchyItemId::Semantic(retained_id),
                AssignmentSource::ManualOverride,
                9_000,
                build,
            ),
        ],
    ))
    .expect("proposal");
    let engine = InMemoryHierarchyEngine::new();
    engine.publish(&proposal).expect("publish");
    let snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("snapshot");
    let authorization = authorization(workspace, [partition.id], build);
    let (before, _) = snapshot
        .branch_statistics(
            view,
            root.id,
            SnapshotRef { commit_seq: build },
            FreshnessRequirement::RequireCurrent,
            &authorization,
        )
        .expect("statistics before deletion");
    assert_eq!(before.direct_children, 2);

    engine
        .record_deletions(DeletionRecord {
            workspace_id: workspace,
            node_ids: BTreeSet::from([deleted_id]),
            lineage_dependencies: BTreeSet::new(),
            effective_at: CommitSeq::new(6),
        })
        .expect("install deletion closure");
    let (after, freshness) = snapshot
        .branch_statistics(
            view,
            root.id,
            SnapshotRef { commit_seq: build },
            FreshnessRequirement::RequireCurrent,
            &authorization,
        )
        .expect("live deletion-safe statistics");
    assert_eq!(after.direct_children, 1);
    assert_eq!(after.unique_descendants, 1);
    assert!(freshness.current);
}

#[test]
fn exact_non_node_lineage_deletion_closes_routes_and_rebuilds() {
    let workspace = WorkspaceId::new();
    let partition = partition(workspace, 5);
    let view = HierarchyViewId::new();
    let build = CommitSeq::new(5);
    let dependency = LineageNode::ClaimRevision {
        id: ClaimId::new(),
        revision: RevisionNumber::FIRST,
    };
    let root = branch_node(
        view,
        partition.id,
        "claim-derived-root",
        build,
        provenance(
            AssignmentSource::DeterministicCommunity,
            "claim-derived root",
            vec![dependency.clone()],
        ),
    );
    let child_id = NodeId::new();
    let child = semantic_node(child_id, partition.id, build);
    let proposal = validate_proposal(proposal_from(
        profile(view, workspace, vec![partition.clone()], 1),
        None,
        build,
        vec![root.clone(), child.clone()],
        vec![candidate(
            root.id,
            child.id,
            AssignmentSource::DeterministicCommunity,
            9_000,
            build,
        )],
    ))
    .expect("proposal");
    let engine = InMemoryHierarchyEngine::new();
    let published = engine.publish(&proposal).expect("publish");
    let old_snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("snapshot");
    let authorization = authorization(workspace, [partition.id], build);
    engine
        .record_deletions(DeletionRecord {
            workspace_id: workspace,
            node_ids: BTreeSet::new(),
            lineage_dependencies: BTreeSet::from([dependency.clone()]),
            effective_at: CommitSeq::new(6),
        })
        .expect("install exact lineage closure");
    assert!(matches!(
        old_snapshot.materialize_routes(
            &route_request(view, child.id, build, FreshnessRequirement::AllowStale),
            &authorization,
        ),
        Err(HierarchyError::RouteUnavailable)
    ));

    let rebuild = validate_proposal(proposal_from(
        profile(view, workspace, vec![partition], 2),
        Some(published.generation),
        CommitSeq::new(6),
        vec![
            branch_node(
                view,
                root.partition,
                "replacement-claim-root",
                CommitSeq::new(6),
                provenance(
                    AssignmentSource::DeterministicCommunity,
                    "still depends on deleted claim",
                    vec![dependency.clone()],
                ),
            ),
            semantic_node(child_id, child.partition, CommitSeq::new(6)),
        ],
        Vec::new(),
    ))
    .expect("structurally valid rebuild");
    assert!(matches!(
        engine.publish(&rebuild),
        Err(HierarchyError::DeletedLineageDependency(found)) if found == dependency
    ));
}

#[test]
fn domain_validity_and_route_integrity_reject_stale_or_tampered_routes() {
    let workspace = WorkspaceId::new();
    let partition = partition(workspace, 1);
    let view = HierarchyViewId::new();
    let build = CommitSeq::new(1);
    let profile = profile(view, workspace, vec![partition.clone()], 1);
    let root = branch_node(
        view,
        partition.id,
        "root",
        build,
        provenance(AssignmentSource::ManualOverride, "root", Vec::new()),
    );
    let child = semantic_node(NodeId::new(), partition.id, build);
    let mut temporal = candidate(
        root.id,
        child.id,
        AssignmentSource::ManualOverride,
        10_000,
        build,
    );
    temporal.validity.valid_time = Some(
        TimeRange::new(TimestampMicros(10), Some(TimestampMicros(20)))
            .expect("valid domain interval"),
    );
    let proposal = validate_proposal(proposal_from(
        profile,
        None,
        build,
        vec![root, child.clone()],
        vec![temporal],
    ))
    .expect("temporal proposal");
    let engine = InMemoryHierarchyEngine::new();
    engine.publish(&proposal).expect("publish");
    let snapshot = engine
        .snapshot(HierarchySnapshotSelector::Latest)
        .expect("snapshot");
    let authorization = authorization(workspace, [partition.id], build);
    let mut request = route_request(view, child.id, build, FreshnessRequirement::RequireCurrent);
    request.domain_time = Some(TimestampMicros(15));
    let mut route = snapshot
        .materialize_routes(&request, &authorization)
        .expect("temporally visible")
        .routes
        .remove(0);
    snapshot
        .validate_route(&route, &authorization)
        .expect("fresh route validates");
    route.nodes[0].label.push_str(" tampered");
    assert!(matches!(
        snapshot.validate_route(&route, &authorization),
        Err(HierarchyError::StaleRoute)
    ));
    request.domain_time = Some(TimestampMicros(25));
    assert!(matches!(
        snapshot.materialize_routes(&request, &authorization),
        Err(HierarchyError::RouteUnavailable)
    ));
}
