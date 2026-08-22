//! Deterministic M6 flat-scan versus hierarchy-guided ablation.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    hint::black_box,
    time::Instant,
};

use contextdb_core::{
    CommitSeq, DerivationId, DerivationKind, DerivationRef, HierarchyViewId, MemorySpaceId, NodeId,
    PipelineIdentity, ScopeId, ScopeInheritance, ScopeKind, ScopeRef, SnapshotRef, WorkspaceId,
};
use contextdb_hierarchy::{
    AssignmentCandidate, AssignmentPolicy, AssignmentSource, AuthorizationSnapshot,
    BeamTraversalRequest, Confidence, FreshnessRequirement, HierarchyBranchId, HierarchyItemId,
    HierarchyKind, HierarchyNode, HierarchyProfile, HierarchyProposalBuilder, HierarchyProvenance,
    HierarchySnapshotSelector, HierarchyValidity, InMemoryHierarchyEngine, PolicyPartition,
    validate_proposal,
};
use serde_json::json;
use uuid::Uuid;

const BRANCHES: usize = 64;
const LEAVES_PER_BRANCH: usize = 64;
const ITERATIONS: usize = 201;
const TARGET_BRANCH: usize = 17;
const TARGET_LEAF: usize = 29;

fn fixed_uuid(namespace: u16, ordinal: usize) -> Uuid {
    Uuid::from_u128((u128::from(namespace) << 112) | (ordinal as u128 + 1))
}

fn provenance(rationale: &str) -> HierarchyProvenance {
    HierarchyProvenance {
        source: AssignmentSource::DeterministicCommunity,
        derivation: DerivationRef {
            id: DerivationId::from_uuid(fixed_uuid(5, 0)).expect("non-nil derivation ID"),
            kind: DerivationKind::DeterministicProjector,
            actor: None,
            model_call: None,
            pipeline: PipelineIdentity {
                name: "m6-hierarchy-ablation".to_owned(),
                version: "1".to_owned(),
                schema_version: "1".to_owned(),
            },
            inputs: Vec::new(),
        },
        rationale: rationale.to_owned(),
    }
}

fn confidence(value: u16) -> Confidence {
    Confidence::from_basis_points(value).expect("benchmark confidence is in range")
}

fn median(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn main() -> Result<(), Box<dyn Error>> {
    let workspace = WorkspaceId::from_uuid(fixed_uuid(1, 0))?;
    let memory_space = MemorySpaceId::from_uuid(fixed_uuid(2, 0))?;
    let view = HierarchyViewId::from_uuid(fixed_uuid(3, 0))?;
    let scope = ScopeRef {
        kind: ScopeKind::Workspace,
        id: ScopeId::from_uuid(fixed_uuid(4, 0))?,
        inheritance: ScopeInheritance::Descendants,
    };
    let build = CommitSeq::new(1);
    let partition = PolicyPartition::new(
        workspace,
        BTreeSet::from([memory_space]),
        BTreeSet::from([scope]),
        build,
    )?;
    let profile = HierarchyProfile {
        id: view,
        workspace_id: workspace,
        kind: HierarchyKind::TopicsKnowledge,
        name: "M6 predeclared balanced topic workload".to_owned(),
        profile_revision: 1,
        partitions: BTreeMap::from([(partition.id, partition.clone())]),
        assignment: AssignmentPolicy::default(),
    };
    let mut builder = HierarchyProposalBuilder::new(
        profile,
        None,
        SnapshotRef { commit_seq: build },
        provenance("predeclared deterministic balanced hierarchy"),
    )?;

    let root = HierarchyItemId::Branch(HierarchyBranchId::derive(
        view,
        partition.id,
        "benchmark-root",
    )?);
    builder.add_node(HierarchyNode {
        id: root,
        label: "all benchmark evidence".to_owned(),
        partition: partition.id,
        confidence: Confidence::ONE,
        validity: HierarchyValidity::current_from(build),
        provenance: provenance("workload root"),
    })?;

    let mut flat_candidates = Vec::with_capacity(BRANCHES * LEAVES_PER_BRANCH);
    let mut target = None;
    for branch_index in 0..BRANCHES {
        let branch = HierarchyItemId::Branch(HierarchyBranchId::derive(
            view,
            partition.id,
            &format!("topic-{branch_index:02}"),
        )?);
        let branch_score = if branch_index == TARGET_BRANCH {
            10_000
        } else {
            8_000
        };
        builder.add_node(HierarchyNode {
            id: branch,
            label: format!("topic branch {branch_index:02}"),
            partition: partition.id,
            confidence: confidence(branch_score),
            validity: HierarchyValidity::current_from(build),
            provenance: provenance("deterministic topic branch"),
        })?;
        builder.add_candidate(AssignmentCandidate {
            parent: root,
            child: branch,
            order_key: branch_index as u64,
            confidence: confidence(branch_score),
            validity: HierarchyValidity::current_from(build),
            provenance: provenance("root to topic membership"),
        });

        for leaf_index in 0..LEAVES_PER_BRANCH {
            let ordinal = branch_index * LEAVES_PER_BRANCH + leaf_index;
            let node_id = NodeId::from_uuid(fixed_uuid(6, ordinal))?;
            let leaf = HierarchyItemId::Semantic(node_id);
            let score = if branch_index == TARGET_BRANCH && leaf_index == TARGET_LEAF {
                target = Some(leaf);
                10_000
            } else {
                7_000
            };
            builder.add_node(HierarchyNode {
                id: leaf,
                label: format!("evidence item branch {branch_index:02} leaf {leaf_index:02}"),
                partition: partition.id,
                confidence: confidence(score),
                validity: HierarchyValidity::current_from(build),
                provenance: provenance("semantic evidence item"),
            })?;
            builder.add_candidate(AssignmentCandidate {
                parent: branch,
                child: leaf,
                order_key: leaf_index as u64,
                confidence: confidence(score),
                validity: HierarchyValidity::current_from(build),
                provenance: provenance("topic to evidence membership"),
            });
            flat_candidates.push((leaf, score));
        }
    }
    let target = target.expect("predeclared target exists");
    let validated = validate_proposal(builder.finish())?;
    let engine = InMemoryHierarchyEngine::new();
    engine.publish(&validated)?;
    let snapshot = engine.snapshot(HierarchySnapshotSelector::Latest)?;
    let authorization =
        AuthorizationSnapshot::new(workspace, BTreeSet::from([partition.id]), build);
    let request = BeamTraversalRequest {
        view_id: view,
        semantic_snapshot: SnapshotRef { commit_seq: build },
        domain_time: None,
        roots: BTreeSet::from([root]),
        beam_width: 1,
        max_depth: 2,
        max_expansions: BRANCHES * 2,
        freshness: FreshnessRequirement::RequireCurrent,
    };

    for _ in 0..20 {
        black_box(flat_candidates.iter().max_by_key(|(_, score)| score));
        black_box(snapshot.beam_traverse(&request, &authorization)?);
    }
    let mut flat_latencies = Vec::with_capacity(ITERATIONS);
    let mut hierarchy_latencies = Vec::with_capacity(ITERATIONS);
    let mut flat_hit = None;
    let mut hierarchy_hit = None;
    let mut hierarchy_expansions = 0;
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        flat_hit = flat_candidates
            .iter()
            .max_by_key(|(_, score)| score)
            .map(|(item, _)| *item);
        black_box(flat_hit);
        flat_latencies.push(started.elapsed().as_nanos());

        let started = Instant::now();
        let traversal = snapshot.beam_traverse(&request, &authorization)?;
        hierarchy_latencies.push(started.elapsed().as_nanos());
        hierarchy_expansions = traversal.expansions;
        hierarchy_hit = traversal.hits.last().map(|hit| hit.item);
        black_box(&traversal);
    }
    if flat_hit != Some(target) || hierarchy_hit != Some(target) {
        return Err("flat oracle or hierarchy missed the predeclared target".into());
    }

    let flat_nodes = flat_candidates.len();
    let hierarchy_nodes = hierarchy_expansions + 1;
    let flat_tokens = flat_nodes * 6;
    let hierarchy_tokens = 3 + BRANCHES * 3 + LEAVES_PER_BRANCH * 6;
    let output = json!({
        "schema_version": 1,
        "workload": "m6-balanced-topic-ablation-v1",
        "parameters": {
            "branches": BRANCHES,
            "leaves_per_branch": LEAVES_PER_BRANCH,
            "semantic_leaves": flat_nodes,
            "beam_width": 1,
            "max_depth": 2,
            "iterations": ITERATIONS,
            "target_branch": TARGET_BRANCH,
            "target_leaf": TARGET_LEAF
        },
        "flat": {
            "nodes_examined": flat_nodes,
            "median_latency_ns": median(flat_latencies),
            "precision_at_1": 1.0,
            "recall_at_1": 1.0,
            "navigation_label_whitespace_tokens_examined": flat_tokens
        },
        "hierarchy": {
            "nodes_examined": hierarchy_nodes,
            "edge_expansions": hierarchy_expansions,
            "median_latency_ns": median(hierarchy_latencies),
            "precision_at_1": 1.0,
            "recall_at_1": 1.0,
            "navigation_label_whitespace_tokens_examined": hierarchy_tokens
        },
        "reductions": {
            "nodes_examined_fraction": 1.0 - hierarchy_nodes as f64 / flat_nodes as f64,
            "navigation_token_fraction": 1.0 - hierarchy_tokens as f64 / flat_tokens as f64
        },
        "quality_collapse": false,
        "notes": [
            "The target and routing confidences are predeclared; this isolates hierarchy pruning from model quality.",
            "Token cost is an exact whitespace-token count over policy-safe navigation labels, not a production model tokenizer.",
            "Latency includes query execution only; generation validation and publication are excluded."
        ]
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
