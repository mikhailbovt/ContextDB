#![allow(
    clippy::unwrap_used,
    reason = "test fixtures use immediate failure semantics"
)]

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    AcceptanceState, AccessCapability, ActorId, Artifact, Audience, AudienceGrant, BitemporalRange,
    Claim, ClaimId, ClaimObject, ClaimRevision, CommitRange, CommitSeq, ConfidenceProfile,
    ConflictResolution, ConflictSet, ConflictSetId, ConflictSetRevision, ConflictState,
    ConsentPolicy, ContentBlockId, ContentDigest, DerivationId, DerivationKind, DerivationRef,
    Directionality, Edge, EdgeId, EdgeRevision, EdgeTypeId, EpistemicBasis, EpistemicRole,
    EpistemicState, IdentityState, LifecycleState, LineageNode, MaintenanceMutationSet,
    MaintenanceOperation, MemorySpaceId, MemorySpaceKind, MemorySubject, MemorySubjectId,
    MemoryUsePolicy, Modality, ModificationPolicy, MutationId, Node, NodeId, NodeRevision,
    NodeType, NonEmptyVec, ObservationId, OwnershipPolicy, PipelineIdentity, PolicyDecision,
    PolicyId, PredicateId, PublicationId, Purpose, RetentionPolicy, RevisionNumber, ScopeId,
    ScopeInheritance, ScopeKind, ScopeRef, SecurityClassification, SecurityPolicy,
    SemanticEnvelope, SemanticMutationSet, SnapshotRef, SourceId, SubjectKind, TimeRange,
    TimestampMicros, Workspace, WorkspaceId, WorkspaceState,
};
use contextdb_graph::{
    AdjacencyRange, AdjacencySegment, Direction, GraphError, GraphMutation, GraphSnapshot,
    GraphStore, PolicyIndexQuery, ReadPrincipal, SegmentEdge, SegmentManifest,
};
use contextdb_journal::{
    JournalEvent, PublicationReceipt, ValidatedMaintenanceBytes, ValidatedMutationBytes,
};
use contextdb_reference::{
    AccessLabel, Consent, ContextDb as ReferenceDb, Lifecycle, LogicalRecord, Mutation, Principal,
    RecordKind, SemanticLinks, SemanticTransaction, Sensitivity, ValidTime,
};
use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};
use contextdb_storage_memory::MemoryStorage;
use contextdb_storage_redb::RedbStorage;
use serde::Serialize;
use serde_json::json;

#[derive(Clone)]
struct Fixture {
    workspace: WorkspaceId,
    workspace_scope: ScopeId,
    space: MemorySpaceId,
    space_scope: ScopeId,
    owner: MemorySubjectId,
}

impl Fixture {
    fn new() -> Self {
        let workspace = WorkspaceId::new();
        let space = MemorySpaceId::new();
        Self {
            workspace,
            workspace_scope: ScopeId::from_uuid(workspace.as_uuid()).expect("workspace scope"),
            space,
            space_scope: ScopeId::from_uuid(space.as_uuid()).expect("space scope"),
            owner: MemorySubjectId::new(),
        }
    }

    fn envelope(&self) -> SemanticEnvelope {
        let mut scopes = NonEmptyVec::new(ScopeRef {
            kind: ScopeKind::Workspace,
            id: self.workspace_scope,
            inheritance: ScopeInheritance::Exact,
        });
        scopes.push(ScopeRef {
            kind: ScopeKind::MemorySpace,
            id: self.space_scope,
            inheritance: ScopeInheritance::Exact,
        });
        let purposes = BTreeSet::from([Purpose::KnowledgeRecall]);
        SemanticEnvelope {
            scopes,
            perspective: contextdb_core::Perspective {
                knower: self.owner,
                experiencer: Some(self.owner),
                narrator: ActorId::new(),
                role: EpistemicRole::Asserter,
            },
            ownership: OwnershipPolicy {
                owners: NonEmptyVec::new(self.owner),
                audience_grants: vec![AudienceGrant {
                    audience: Audience::Owner,
                    purposes: purposes.clone(),
                    capabilities: BTreeSet::from([AccessCapability::Retrieve]),
                }],
                allowed_purposes: purposes,
                modification: ModificationPolicy {
                    owners_may_modify: true,
                    delegates_may_modify: false,
                    system_may_derive: true,
                },
            },
            consent: ConsentPolicy {
                required: false,
                decisions: Vec::new(),
            },
            use_policy: MemoryUsePolicy {
                retrieve: PolicyDecision::Allow,
                influence_response: PolicyDecision::Allow,
                mention_explicitly: PolicyDecision::Allow,
                external_model_use: PolicyDecision::Deny,
                retention: RetentionPolicy::Indefinite,
            },
            security: SecurityPolicy {
                classification: SecurityClassification::Internal,
                labels: BTreeSet::new(),
                required_compartments: BTreeSet::new(),
                allow_external_processing: false,
            },
            derivation: DerivationRef {
                id: DerivationId::new(),
                kind: DerivationKind::DeterministicProjector,
                actor: None,
                model_call: None,
                pipeline: PipelineIdentity {
                    name: "graph-fixture".to_owned(),
                    version: "1".to_owned(),
                    schema_version: "1".to_owned(),
                },
                inputs: vec![LineageNode::External {
                    namespace: "fixture".to_owned(),
                    identifier: "source".to_owned(),
                }],
            },
        }
    }

    fn principal(&self) -> ReadPrincipal {
        ReadPrincipal {
            subject: self.owner,
            workspace_id: self.workspace,
            scopes: BTreeSet::from([self.workspace_scope, self.space_scope]),
            memory_spaces: BTreeSet::from([self.space]),
            audience_subjects: BTreeSet::new(),
            purpose: Purpose::KnowledgeRecall,
            clearance: SecurityClassification::Internal,
            compartments: BTreeSet::new(),
        }
    }

    fn workspace_record(&self) -> Workspace {
        Workspace {
            id: self.workspace,
            name: "fixture workspace".to_owned(),
            policy_profile: PolicyId::new(),
            ontology_profile: "fixture-v1".to_owned(),
            state: WorkspaceState::Active,
        }
    }

    fn space_record(&self) -> contextdb_core::MemorySpace {
        contextdb_core::MemorySpace {
            id: self.space,
            workspace_id: self.workspace,
            kind: MemorySpaceKind::UserPrivate,
            owners: NonEmptyVec::new(self.owner),
            default_policy: self.envelope().ownership,
            retention_policy: RetentionPolicy::Indefinite,
            parent: None,
        }
    }

    fn subject_record(&self, canonical_node: NodeId) -> MemorySubject {
        MemorySubject {
            id: self.owner,
            workspace_id: self.workspace,
            kind: SubjectKind::User,
            canonical_node,
            primary_spaces: NonEmptyVec::new(self.space),
            continuity_policy: PolicyId::new(),
        }
    }
}

fn epistemic(lifecycle: LifecycleState) -> EpistemicState {
    EpistemicState {
        basis: EpistemicBasis::Hypothesis,
        acceptance: AcceptanceState::Accepted,
        conflict: ConflictState::None,
        lifecycle,
    }
}

fn confidence() -> ConfidenceProfile {
    ConfidenceProfile {
        overall: 1.0,
        source_trust: 1.0,
        extraction_quality: 1.0,
        corroboration: 1.0,
    }
}

fn node(fixture: &Fixture, id: NodeId) -> Node {
    Node {
        id,
        workspace_id: fixture.workspace,
        node_type: NodeType::Entity,
        created_seq: CommitSeq::new(1),
        retired_seq: None,
        identity_state: IdentityState::Canonical,
        primary_scope: fixture.envelope().scopes.first().clone(),
    }
}

fn node_revision(
    fixture: &Fixture,
    id: NodeId,
    revision: u32,
    name: &str,
    valid_start: i64,
    valid_end: Option<i64>,
) -> NodeRevision {
    NodeRevision {
        node_id: id,
        revision: RevisionNumber::new(revision).expect("revision"),
        temporal: BitemporalRange {
            valid_time: TimeRange::new(
                TimestampMicros(valid_start),
                valid_end.map(TimestampMicros),
            )
            .expect("valid time"),
            transaction_time: CommitRange::current(CommitSeq::new(u64::from(revision))),
        },
        canonical_name: name.to_owned(),
        attributes: BTreeMap::new(),
        epistemic: epistemic(LifecycleState::Active),
        confidence: confidence(),
        evidence: Vec::new(),
        envelope: fixture.envelope(),
    }
}

fn edge(
    fixture: &Fixture,
    id: EdgeId,
    source: NodeId,
    target: NodeId,
    edge_type: EdgeTypeId,
    commit_seq: u64,
) -> (Edge, EdgeRevision) {
    (
        Edge {
            id,
            workspace_id: fixture.workspace,
            source,
            target,
            edge_type,
            directionality: Directionality::Directed,
            created_seq: CommitSeq::new(commit_seq),
            materialized_from_claim: None,
        },
        EdgeRevision {
            edge_id: id,
            revision: RevisionNumber::FIRST,
            temporal: BitemporalRange {
                valid_time: TimeRange::open_ended(TimestampMicros(0)),
                transaction_time: CommitRange::current(CommitSeq::new(commit_seq)),
            },
            weight: 1.0,
            epistemic: epistemic(LifecycleState::Active),
            confidence: confidence(),
            evidence: Vec::new(),
            attributes: BTreeMap::new(),
            envelope: fixture.envelope(),
        },
    )
}

fn initial_graph<E: StorageEngine>(
    store: &GraphStore<E>,
    fixture: &Fixture,
    nodes: &[NodeId],
) -> u64 {
    let canonical_node = *nodes.first().expect("at least one fixture node");
    store
        .commit(
            GraphMutation {
                base_storage_seq: 0,
                workspaces: vec![fixture.workspace_record()],
                memory_spaces: vec![fixture.space_record()],
                memory_subjects: vec![fixture.subject_record(canonical_node)],
                nodes: nodes.iter().map(|id| node(fixture, *id)).collect(),
                node_revisions: nodes
                    .iter()
                    .map(|id| node_revision(fixture, *id, 1, &format!("node-{id}"), 0, Some(100)))
                    .collect(),
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("initial graph")
}

fn three_paged_generations<E: StorageEngine>(
    store: &GraphStore<E>,
    fixture: &Fixture,
    durability: Durability,
) -> ([NodeId; 4], EdgeTypeId, [GraphSnapshot; 3]) {
    let nodes = [NodeId::new(), NodeId::new(), NodeId::new(), NodeId::new()];
    let edge_type = EdgeTypeId::new();
    initial_graph(store, fixture, &nodes);
    let mut snapshots = Vec::new();
    for (index, target) in nodes[1..].iter().enumerate() {
        let semantic_seq = u64::try_from(index).expect("index") + 2;
        let relation = edge(
            fixture,
            EdgeId::new(),
            nodes[0],
            *target,
            edge_type,
            semantic_seq,
        );
        let base_storage_seq = store
            .snapshot(SnapshotSelector::Latest)
            .expect("pre-edge snapshot")
            .storage_seq;
        store
            .commit(
                GraphMutation {
                    base_storage_seq,
                    edges: vec![relation.0],
                    edge_revisions: vec![relation.1],
                    ..GraphMutation::default()
                },
                durability,
            )
            .expect("generation edge");
        store.compact_graph(durability).expect("paged generation");
        snapshots.push(
            store
                .snapshot(SnapshotSelector::Latest)
                .expect("generation snapshot"),
        );
    }
    let snapshots: [GraphSnapshot; 3] = snapshots.try_into().expect("three snapshots");
    (nodes, edge_type, snapshots)
}

fn empty_v2_manifest(generation: u64) -> SegmentManifest {
    let row_root = blake3::hash(b"contextdb.graph.segment.v2.empty\0");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb.graph.segment.v2.manifest\0");
    hasher.update(&2_u16.to_be_bytes());
    hasher.update(&generation.to_be_bytes());
    hasher.update(&0_u64.to_be_bytes());
    hasher.update(&0_u64.to_be_bytes());
    hasher.update(&0_u64.to_be_bytes());
    hasher.update(&0_u64.to_be_bytes());
    hasher.update(row_root.as_bytes());
    SegmentManifest {
        format_version: 2,
        generation,
        built_through_seq: 0,
        segment_digest: hasher.finalize().to_hex().to_string(),
        row_count: 0,
        edge_count: 0,
        edge_bytes: 0,
    }
}

#[test]
fn stable_external_and_dense_ids_survive_revisions_and_graph_compaction() {
    let fixture = Fixture::new();
    let id = NodeId::new();
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    initial_graph(&store, &fixture, &[id]);
    let first_snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    assert_eq!(
        store
            .workspace(fixture.workspace, &first_snapshot, &fixture.principal())
            .expect("workspace")
            .id,
        fixture.workspace
    );
    assert_eq!(
        store
            .memory_space(fixture.space, &first_snapshot, &fixture.principal())
            .expect("memory space")
            .id,
        fixture.space
    );
    assert_eq!(
        store
            .memory_subject(fixture.owner, &first_snapshot, &fixture.principal())
            .expect("memory subject")
            .canonical_node,
        id
    );
    assert_eq!(
        store
            .subjects_in_space(fixture.space, &first_snapshot, &fixture.principal())
            .expect("space subjects"),
        BTreeSet::from([fixture.owner])
    );
    assert_eq!(
        store
            .spaces_owned_by(fixture.owner, &first_snapshot, &fixture.principal())
            .expect("owned spaces"),
        BTreeSet::from([fixture.space])
    );
    let mapping = store
        .id_mapping(&id.to_string(), &first_snapshot, &fixture.principal())
        .expect("mapping");
    for query in [
        PolicyIndexQuery::Workspace(fixture.workspace),
        PolicyIndexQuery::Subject(fixture.owner),
        PolicyIndexQuery::Scope(fixture.workspace_scope),
        PolicyIndexQuery::Owner(fixture.owner),
        PolicyIndexQuery::MemorySpace(fixture.space),
        PolicyIndexQuery::Audience(Audience::Owner),
        PolicyIndexQuery::Purpose(Purpose::KnowledgeRecall),
    ] {
        assert!(
            store
                .authorized_index(&query, &first_snapshot, &fixture.principal())
                .expect("policy index")
                .contains(&id.to_string())
        );
    }
    let first = store
        .node(id, &first_snapshot, &fixture.principal())
        .expect("first revision");
    assert_eq!(first.revision.revision, RevisionNumber::FIRST);

    store
        .commit(
            GraphMutation {
                base_storage_seq: first_snapshot.storage_seq,
                node_revisions: vec![node_revision(&fixture, id, 2, "current name", 100, None)],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("second revision");
    let second_snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    assert_eq!(
        store
            .id_mapping(&id.to_string(), &second_snapshot, &fixture.principal())
            .expect("mapping after revision"),
        mapping
    );
    assert_eq!(
        store
            .node(id, &first_snapshot, &fixture.principal())
            .expect("historical snapshot")
            .revision
            .canonical_name,
        first.revision.canonical_name
    );
    assert_eq!(
        store
            .node_at_valid_time(
                id,
                TimestampMicros(50),
                &second_snapshot,
                &fixture.principal(),
            )
            .expect("past valid time")
            .revision
            .revision,
        RevisionNumber::FIRST
    );
    assert_eq!(
        store
            .node_at_valid_time(
                id,
                TimestampMicros(150),
                &second_snapshot,
                &fixture.principal(),
            )
            .expect("current valid time")
            .revision
            .revision,
        RevisionNumber::new(2).expect("revision")
    );
    store
        .compact_graph(Durability::Ephemeral)
        .expect("graph compaction");
    let compacted = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    assert_eq!(
        store
            .id_mapping(&id.to_string(), &compacted, &fixture.principal())
            .expect("mapping after compaction"),
        mapping
    );
}

#[test]
fn authorization_indexes_precede_materialization_and_cross_space_data_has_no_influence() {
    let visible = Fixture::new();
    let secret = Fixture {
        workspace: visible.workspace,
        workspace_scope: visible.workspace_scope,
        ..Fixture::new()
    };
    let visible_a = NodeId::new();
    let visible_b = NodeId::new();
    let secret_node = NodeId::new();
    let secret_artifact_id = contextdb_core::ArtifactId::new();
    let visible_edge_id = EdgeId::new();
    let secret_edge_id = EdgeId::new();
    let edge_type = EdgeTypeId::new();
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    initial_graph(&store, &visible, &[visible_a, visible_b]);
    let (visible_edge, visible_edge_revision) = edge(
        &visible,
        visible_edge_id,
        visible_a,
        visible_b,
        edge_type,
        2,
    );
    store
        .commit(
            GraphMutation {
                base_storage_seq: 1,
                edges: vec![visible_edge],
                edge_revisions: vec![visible_edge_revision],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("visible edge");
    let before = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let before_result = store
        .traverse(
            &[visible_a],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            10,
            &before,
            &visible.principal(),
        )
        .expect("visible traversal");

    let (secret_edge, secret_edge_revision) = edge(
        &secret,
        secret_edge_id,
        visible_a,
        secret_node,
        edge_type,
        3,
    );
    let mut secret_stable_node = node(&secret, secret_node);
    secret_stable_node.created_seq = CommitSeq::new(3);
    let mut secret_node_revision = node_revision(
        &secret,
        secret_node,
        1,
        "SECRET-CONTENT-MUST-NOT-INFLUENCE",
        0,
        None,
    );
    secret_node_revision.temporal.transaction_time = CommitRange::current(CommitSeq::new(3));
    let secret_artifact = Artifact {
        id: secret_artifact_id,
        source_id: SourceId::new(),
        modality: Modality::Text,
        media_type: "text/plain".to_owned(),
        native_locator: Some("local://secret".to_owned()),
        content_blocks: NonEmptyVec::new(ContentBlockId::new()),
        content_hash: ContentDigest::from_bytes([4; 32]),
        created_at: None,
        ingested_at: TimestampMicros(1),
        envelope: secret.envelope(),
    };
    store
        .commit(
            GraphMutation {
                base_storage_seq: before.storage_seq,
                memory_spaces: vec![secret.space_record()],
                memory_subjects: vec![secret.subject_record(secret_node)],
                nodes: vec![secret_stable_node],
                node_revisions: vec![secret_node_revision],
                edges: vec![secret_edge],
                edge_revisions: vec![secret_edge_revision],
                artifacts: vec![secret_artifact],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("secret subgraph");
    let after = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let after_result = store
        .traverse(
            &[visible_a],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            10,
            &after,
            &visible.principal(),
        )
        .expect("traversal with secret data present");
    assert_eq!(before_result.nodes, after_result.nodes);
    assert_eq!(
        before_result.trace.authorized_edges,
        after_result.trace.authorized_edges
    );
    assert!(matches!(
        store.node(secret_node, &after, &visible.principal()),
        Err(GraphError::Unauthorized)
    ));
    assert!(matches!(
        store.id_mapping(&secret_node.to_string(), &after, &visible.principal()),
        Err(GraphError::Unauthorized)
    ));
    let universe = store
        .authorized_universe(&after, &visible.principal())
        .expect("authorized universe");
    assert!(universe.contains(&visible_a.to_string()));
    assert!(!universe.contains(&secret_node.to_string()));
    assert!(!universe.contains(&secret_edge_id.to_string()));

    // A corrupt protected identity must still produce Unauthorized: policy bytes are consulted
    // before any protected record bytes can be decoded or influence the result.
    let mut raw = engine.begin_write().expect("raw corruption transaction");
    raw.put(
        &Keyspace::new("graph_node_identity_v1").expect("keyspace"),
        secret_node.to_string().into_bytes(),
        b"not-json-and-definitely-secret".to_vec(),
    )
    .expect("stage corrupt protected bytes");
    raw.put(
        &Keyspace::new("graph_artifact_v1").expect("keyspace"),
        secret_artifact_id.to_string().into_bytes(),
        b"also-not-json-and-still-secret".to_vec(),
    )
    .expect("stage corrupt protected artifact bytes");
    raw.put(
        &Keyspace::new("graph_edge_revision_v1").expect("keyspace"),
        format!("{secret_edge_id}/0000000001").into_bytes(),
        b"corrupt-unauthorized-edge-revision".to_vec(),
    )
    .expect("stage corrupt protected edge revision");
    raw.commit(Durability::Ephemeral)
        .expect("publish protected corruption");
    let corrupt_snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    assert!(matches!(
        store.node(secret_node, &corrupt_snapshot, &visible.principal()),
        Err(GraphError::Unauthorized)
    ));
    assert!(matches!(
        store.artifact(secret_artifact_id, &corrupt_snapshot, &visible.principal()),
        Err(GraphError::Unauthorized)
    ));
    let corrupt_result = store
        .traverse(
            &[visible_a],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            10,
            &corrupt_snapshot,
            &visible.principal(),
        )
        .expect("unauthorized corrupt edge cannot influence traversal");
    assert_eq!(corrupt_result.nodes, before_result.nodes);
    assert_eq!(
        corrupt_result.trace.authorized_edges,
        before_result.trace.authorized_edges
    );
}

#[test]
fn exact_traversal_matches_the_in_memory_reference_oracle() {
    let fixture = Fixture::new();
    let a = NodeId::new();
    let b = NodeId::new();
    let c = NodeId::new();
    let edge_type = EdgeTypeId::new();
    let e1 = edge(&fixture, EdgeId::new(), a, b, edge_type, 2);
    let e2 = edge(&fixture, EdgeId::new(), a, c, edge_type, 2);
    let store = GraphStore::new(MemoryStorage::new()).expect("store");
    // Deliberately make dense allocation and edge insertion disagree with public-ID order.
    initial_graph(&store, &fixture, &[c, a, b]);
    store
        .commit(
            GraphMutation {
                base_storage_seq: 1,
                edges: vec![e2.0.clone(), e1.0.clone()],
                edge_revisions: vec![e2.1, e1.1],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("edges");
    let snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let persistent = store
        .traverse(
            &[a],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            2,
            10,
            &snapshot,
            &fixture.principal(),
        )
        .expect("persistent traversal")
        .nodes;

    let reference = ReferenceDb::new("differential").expect("reference");
    let access = AccessLabel {
        workspace: fixture.workspace.to_string(),
        scopes: BTreeSet::from([fixture.space_scope.to_string()]),
        owners: BTreeSet::from([fixture.owner.to_string()]),
        audience: BTreeSet::from([fixture.owner.to_string()]),
        audience_purpose_grants: BTreeMap::new(),
        purposes: BTreeSet::from(["knowledge_recall".to_owned()]),
        sensitivity: Sensitivity::Internal,
        consent: Consent::Granted,
        retrievable: true,
    };
    let reference_node = |id: NodeId| LogicalRecord {
        id: id.to_string(),
        kind: RecordKind::Node,
        access: access.clone(),
        valid_time: ValidTime::UNBOUNDED,
        lifecycle: Lifecycle::Active,
        links: SemanticLinks::default(),
        value: json!({}),
        search_text: None,
        vector: None,
        attributes: BTreeMap::new(),
    };
    let reference_edge = |edge: &Edge| LogicalRecord {
        id: edge.id.to_string(),
        kind: RecordKind::Edge,
        access: access.clone(),
        valid_time: ValidTime::UNBOUNDED,
        lifecycle: Lifecycle::Active,
        links: SemanticLinks {
            source: Some(edge.source.to_string()),
            target: Some(edge.target.to_string()),
            predicate: Some(edge.edge_type.to_string()),
            ..SemanticLinks::default()
        },
        value: json!({}),
        search_text: None,
        vector: None,
        attributes: BTreeMap::new(),
    };
    reference
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "graph".to_owned(),
            mutations: [
                reference_node(a),
                reference_node(b),
                reference_node(c),
                reference_edge(&e1.0),
                reference_edge(&e2.0),
            ]
            .into_iter()
            .map(|record| Mutation::Put {
                record,
                expected_revision: None,
            })
            .collect(),
        })
        .expect("reference graph");
    let reference_snapshot = reference.snapshot().expect("snapshot");
    let reference_principal = Principal {
        subject: fixture.owner.to_string(),
        audiences: BTreeSet::new(),
        workspace: fixture.workspace.to_string(),
        scopes: BTreeSet::from([fixture.space_scope.to_string()]),
        purpose: "knowledge_recall".to_owned(),
        clearance: Sensitivity::Internal,
    };
    let expected = reference
        .traverse(
            &[a.to_string()],
            contextdb_reference::Direction::Outgoing,
            &BTreeSet::from([edge_type.to_string()]),
            2,
            10,
            &reference_snapshot,
            &reference_principal,
        )
        .expect("reference traversal")
        .value;
    assert_eq!(persistent, expected);
    store
        .compact_graph(Durability::Ephemeral)
        .expect("compact differential graph");
    let compacted = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    assert_eq!(
        store
            .traverse(
                &[a],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                2,
                10,
                &compacted,
                &fixture.principal(),
            )
            .expect("compacted persistent traversal")
            .nodes,
        expected
    );
}

#[test]
fn revisioned_conflicts_and_artifact_metadata_are_snapshot_consistent() {
    let fixture = Fixture::new();
    let subject = NodeId::new();
    let claim_a = ClaimId::new();
    let claim_b = ClaimId::new();
    let predicate = PredicateId::new();
    let conflict_id = ConflictSetId::new();
    let store = GraphStore::new(MemoryStorage::new()).expect("store");
    initial_graph(&store, &fixture, &[subject]);
    let claim = |id| Claim {
        id,
        workspace_id: fixture.workspace,
        subject,
        predicate,
        created_seq: CommitSeq::new(2),
    };
    let claim_revision = |id, value: &str| ClaimRevision {
        claim_id: id,
        revision: RevisionNumber::FIRST,
        object: ClaimObject::String(value.to_owned()),
        temporal: BitemporalRange {
            valid_time: TimeRange::open_ended(TimestampMicros(0)),
            transaction_time: CommitRange::current(CommitSeq::new(2)),
        },
        epistemic: epistemic(LifecycleState::Active),
        confidence: confidence(),
        source_families: BTreeSet::new(),
        evidence: Vec::new(),
        supersedes: Vec::new(),
        envelope: fixture.envelope(),
    };
    let mut members = NonEmptyVec::new(claim_a);
    members.push(claim_b);
    let conflict = ConflictSet {
        id: conflict_id,
        workspace_id: fixture.workspace,
        subject,
        predicate,
        scopes: fixture.envelope().scopes,
        created_seq: CommitSeq::new(2),
    };
    let conflict_revision = ConflictSetRevision {
        conflict_set_id: conflict_id,
        revision: RevisionNumber::FIRST,
        transaction_time: CommitRange::current(CommitSeq::new(2)),
        members,
        resolution: ConflictResolution::Unresolved,
        evidence: Vec::new(),
        envelope: fixture.envelope(),
    };
    let artifact = Artifact {
        id: contextdb_core::ArtifactId::new(),
        source_id: SourceId::new(),
        modality: Modality::Image,
        media_type: "image/png".to_owned(),
        native_locator: Some("local://artifact.png".to_owned()),
        content_blocks: NonEmptyVec::new(ContentBlockId::new()),
        content_hash: ContentDigest::from_bytes([7; 32]),
        created_at: Some(TimestampMicros(5)),
        ingested_at: TimestampMicros(6),
        envelope: fixture.envelope(),
    };
    store
        .commit(
            GraphMutation {
                base_storage_seq: 1,
                claims: vec![claim(claim_a), claim(claim_b)],
                claim_revisions: vec![claim_revision(claim_a, "A"), claim_revision(claim_b, "B")],
                conflicts: vec![conflict],
                conflict_revisions: vec![conflict_revision],
                artifacts: vec![artifact.clone()],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("claims/conflict/artifact");
    let snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let conflict = store
        .conflict(conflict_id, &snapshot, &fixture.principal())
        .expect("conflict");
    assert_eq!(conflict.revision.members.len(), 2);
    assert_eq!(
        store
            .claim_at_valid_time(
                claim_a,
                TimestampMicros(10),
                &snapshot,
                &fixture.principal(),
            )
            .expect("claim")
            .revision
            .object,
        ClaimObject::String("A".to_owned())
    );
    assert_eq!(
        store
            .artifact(artifact.id, &snapshot, &fixture.principal())
            .expect("artifact")
            .artifact,
        artifact
    );

    let mismatched_claim_id = ClaimId::new();
    let mismatched_claim = Claim {
        id: mismatched_claim_id,
        workspace_id: fixture.workspace,
        subject,
        predicate: PredicateId::new(),
        created_seq: CommitSeq::new(3),
    };
    let mut mismatched_revision = claim_revision(mismatched_claim_id, "wrong predicate");
    mismatched_revision.temporal.transaction_time = CommitRange::current(CommitSeq::new(3));
    let mut invalid_members = NonEmptyVec::new(claim_a);
    invalid_members.push(mismatched_claim_id);
    let invalid_conflict_revision = ConflictSetRevision {
        conflict_set_id: conflict_id,
        revision: RevisionNumber::new(2).expect("revision"),
        transaction_time: CommitRange::current(CommitSeq::new(3)),
        members: invalid_members,
        resolution: ConflictResolution::Unresolved,
        evidence: Vec::new(),
        envelope: fixture.envelope(),
    };
    assert!(matches!(
        store.commit(
            GraphMutation {
                base_storage_seq: snapshot.storage_seq,
                claims: vec![mismatched_claim],
                claim_revisions: vec![mismatched_revision],
                conflict_revisions: vec![invalid_conflict_revision],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        ),
        Err(GraphError::Invariant(_))
    ));
    assert_eq!(
        store
            .snapshot(SnapshotSelector::Latest)
            .expect("unchanged snapshot")
            .storage_seq,
        snapshot.storage_seq
    );
}

#[test]
fn journal_projection_is_atomic_replay_safe_and_maintenance_is_fail_closed() {
    let fixture = Fixture::new();
    let administrative_node = NodeId::new();
    let published_node = NodeId::new();
    let store = GraphStore::new(MemoryStorage::new()).expect("store");
    initial_graph(&store, &fixture, &[administrative_node]);

    let mut stable_node = node(&fixture, published_node);
    stable_node.created_seq = CommitSeq::new(2);
    let mut revision = node_revision(&fixture, published_node, 1, "journal node", 0, None);
    revision.temporal.transaction_time = CommitRange::current(CommitSeq::new(2));
    let mutation = SemanticMutationSet {
        id: MutationId::new(),
        base_snapshot: SnapshotRef {
            commit_seq: CommitSeq::new(1),
        },
        journal_refs: NonEmptyVec::new(ObservationId::new()),
        observation_appends: Vec::new(),
        episode_view_writes: Vec::new(),
        node_creates: vec![stable_node],
        node_revisions: vec![revision],
        claim_creates: Vec::new(),
        claim_revisions: Vec::new(),
        edge_creates: Vec::new(),
        edge_revisions: Vec::new(),
        conflict_creates: Vec::new(),
        conflict_revisions: Vec::new(),
        candidate_writes: Vec::new(),
        typed_memory_writes: Vec::new(),
        derived_work: Vec::new(),
    };
    let validated = ValidatedMutationBytes::from_mutation(&mutation).expect("validated mutation");
    let receipt = PublicationReceipt {
        mutation_id: mutation.id,
        publication_id: PublicationId::new(),
        commit_seq: CommitSeq::new(2),
        durability: Durability::Ephemeral,
        outbox_count: 0,
        replayed: false,
        mutation_digest: validated.digest(),
    };
    let projected = store
        .project_publication(&validated, receipt)
        .expect("project publication");
    assert!(!projected.replayed);
    assert_eq!(projected.storage_seq, 2);

    // Simulate a crash after the graph commit but before the caller received its ACK.
    let replay = store
        .project_publication(&validated, receipt)
        .expect("replay lost acknowledgement");
    assert!(replay.replayed);
    assert_eq!(replay.storage_seq, projected.storage_seq);
    assert_eq!(
        store
            .snapshot(SnapshotSelector::Latest)
            .expect("head")
            .storage_seq,
        projected.storage_seq
    );
    let semantic_snapshot = store
        .snapshot_at_semantic(CommitSeq::new(2))
        .expect("semantic snapshot");
    assert_eq!(semantic_snapshot.semantic_seq, CommitSeq::new(2));
    assert_eq!(
        store
            .node(published_node, &semantic_snapshot, &fixture.principal())
            .expect("journal node")
            .revision
            .canonical_name,
        "journal node"
    );

    let event = JournalEvent::SemanticPublished {
        commit_seq: CommitSeq::new(2),
        mutation_id: mutation.id,
        publication_id: receipt.publication_id,
        exact_mutation_bytes: validated.exact_bytes().to_vec(),
        mutation_digest: validated.digest(),
        outbox: Vec::new(),
    };
    assert!(
        store
            .project_journal_event(&event, Durability::Ephemeral)
            .expect("journal replay")
            .expect("semantic projection")
            .replayed
    );
    assert!(
        store
            .project_journal_event(
                &JournalEvent::ObservationAccepted {
                    commit_seq: CommitSeq::new(3),
                    observation_id: ObservationId::new(),
                    exact_bytes: b"opaque-observation".to_vec(),
                    request_digest: [3; 32],
                },
                Durability::Ephemeral,
            )
            .expect("observation has no graph projection")
            .is_none()
    );

    let maintenance = MaintenanceMutationSet {
        id: MutationId::new(),
        base_snapshot: SnapshotRef {
            commit_seq: CommitSeq::new(2),
        },
        operation: MaintenanceOperation::CompactionMetadata {
            component: "graph".to_owned(),
            from_generation: 1,
            to_generation: 2,
            manifest_digest: ContentDigest::from_bytes([9; 32]),
        },
        derived_work: Vec::new(),
    };
    let validated_maintenance =
        ValidatedMaintenanceBytes::from_mutation(&maintenance).expect("maintenance");
    let maintenance_event = JournalEvent::MaintenancePublished {
        commit_seq: CommitSeq::new(3),
        mutation_id: maintenance.id,
        publication_id: PublicationId::new(),
        exact_mutation_bytes: validated_maintenance.exact_bytes().to_vec(),
        mutation_digest: validated_maintenance.digest(),
        outbox: Vec::new(),
    };
    assert!(matches!(
        store.project_journal_event(&maintenance_event, Durability::Ephemeral),
        Err(GraphError::UnsupportedMaintenance("compaction_metadata"))
    ));

    let mut conflicting = mutation.clone();
    let conflicting_node = NodeId::new();
    let mut conflicting_stable = node(&fixture, conflicting_node);
    conflicting_stable.created_seq = CommitSeq::new(2);
    let mut conflicting_revision =
        node_revision(&fixture, conflicting_node, 1, "different bytes", 0, None);
    conflicting_revision.temporal.transaction_time = CommitRange::current(CommitSeq::new(2));
    conflicting.node_creates = vec![conflicting_stable];
    conflicting.node_revisions = vec![conflicting_revision];
    let conflicting =
        ValidatedMutationBytes::from_mutation(&conflicting).expect("conflicting bytes");
    assert!(matches!(
        store.project_publication(
            &conflicting,
            PublicationReceipt {
                publication_id: PublicationId::new(),
                mutation_digest: conflicting.digest(),
                ..receipt
            }
        ),
        Err(GraphError::Invariant(_))
    ));
}

#[test]
fn compaction_merges_base_and_delta_tombstones_without_breaking_old_snapshots() {
    let fixture = Fixture::new();
    let a = NodeId::new();
    let b = NodeId::new();
    let c = NodeId::new();
    let edge_type = EdgeTypeId::new();
    let old_edge_id = EdgeId::new();
    let new_edge_id = EdgeId::new();
    let old_edge = edge(&fixture, old_edge_id, a, b, edge_type, 2);
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    initial_graph(&store, &fixture, &[a, b, c]);
    store
        .commit(
            GraphMutation {
                base_storage_seq: 1,
                edges: vec![old_edge.0],
                edge_revisions: vec![old_edge.1],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("base edge");
    let manifest = store
        .compact_graph(Durability::Ephemeral)
        .expect("first compaction");
    assert_eq!(manifest.format_version, 2);
    assert_eq!(manifest.row_count, 6);
    assert_eq!(manifest.edge_count, 2);
    assert!(manifest.edge_bytes > 0);
    let base_snapshot = store
        .snapshot(SnapshotSelector::Latest)
        .expect("base snapshot");
    assert_eq!(base_snapshot.segment_generation, 1);
    assert!(
        engine
            .begin_read(SnapshotSelector::Latest)
            .expect("physical snapshot")
            .get(
                &Keyspace::new("graph_segment_v1").expect("legacy segment keyspace"),
                &[b"base".as_slice(), &1_u64.to_be_bytes()].concat(),
            )
            .expect("legacy segment read")
            .is_none()
    );
    let physical = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let records = physical
        .scan_prefix(
            &Keyspace::new("graph_segment_v2").expect("paged segment keyspace"),
            &[b'g', 0, 0, 0, 0, 0, 0, 0, 1, b'e'],
        )
        .expect("paged edge records");
    assert_eq!(records.len(), 2);
    let segment_edges = records
        .iter()
        .map(|entry| serde_json::from_slice::<SegmentEdge>(&entry.value))
        .collect::<Result<Vec<_>, _>>()
        .expect("one canonical edge per record");
    let a_mapping = store
        .id_mapping(&a.to_string(), &base_snapshot, &fixture.principal())
        .expect("a mapping");
    let b_mapping = store
        .id_mapping(&b.to_string(), &base_snapshot, &fixture.principal())
        .expect("b mapping");
    assert!(
        segment_edges
            .iter()
            .all(|edge| { edge.source == a_mapping.dense_id && edge.target == b_mapping.dense_id })
    );

    let mut new_edge = edge(&fixture, new_edge_id, a, c, edge_type, 3);
    new_edge.0.directionality = Directionality::Undirected;
    let mut deleted_revision = EdgeRevision {
        edge_id: old_edge_id,
        revision: RevisionNumber::new(2).expect("revision"),
        temporal: BitemporalRange {
            valid_time: TimeRange::open_ended(TimestampMicros(0)),
            transaction_time: CommitRange::current(CommitSeq::new(3)),
        },
        weight: 1.0,
        epistemic: epistemic(LifecycleState::Deleted),
        confidence: confidence(),
        evidence: Vec::new(),
        attributes: BTreeMap::new(),
        envelope: fixture.envelope(),
    };
    deleted_revision.epistemic.acceptance = AcceptanceState::Rejected;
    store
        .commit(
            GraphMutation {
                base_storage_seq: base_snapshot.storage_seq,
                edges: vec![new_edge.0],
                edge_revisions: vec![deleted_revision, new_edge.1],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("delta add and tombstone");
    let delta_snapshot = store
        .snapshot(SnapshotSelector::Latest)
        .expect("delta snapshot");
    assert_eq!(delta_snapshot.segment_generation, 1);
    assert_eq!(
        store
            .traverse(
                &[a],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &delta_snapshot,
                &fixture.principal(),
            )
            .expect("base plus delta")
            .nodes,
        vec![c.to_string()]
    );
    assert_eq!(
        store
            .traverse(
                &[c],
                Direction::Incoming,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &delta_snapshot,
                &fixture.principal(),
            )
            .expect("incoming delta")
            .nodes,
        vec![a.to_string()]
    );
    assert_eq!(
        store
            .traverse(
                &[c],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &delta_snapshot,
                &fixture.principal(),
            )
            .expect("undirected outgoing traversal")
            .nodes,
        vec![a.to_string()]
    );
    assert_eq!(
        store
            .edge_at_valid_time(
                new_edge_id,
                TimestampMicros(1),
                &delta_snapshot,
                &fixture.principal(),
            )
            .expect("edge bitemporal lookup")
            .edge
            .directionality,
        Directionality::Undirected
    );
    assert_eq!(
        store
            .traverse(
                &[a],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &base_snapshot,
                &fixture.principal(),
            )
            .expect("retained pre-delta snapshot")
            .nodes,
        vec![b.to_string()]
    );

    store
        .compact_graph(Durability::Ephemeral)
        .expect("second compaction");
    let compacted = store.snapshot(SnapshotSelector::Latest).expect("compacted");
    assert_eq!(compacted.segment_generation, 2);
    let compacted_result = store
        .traverse(
            &[a],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            10,
            &compacted,
            &fixture.principal(),
        )
        .expect("compacted traversal")
        .nodes;
    assert_eq!(compacted_result, vec![c.to_string()]);
    let semantic_snapshot = store
        .snapshot_at_semantic(CommitSeq::new(3))
        .expect("pre-compaction logical snapshot");
    assert_eq!(
        store
            .traverse(
                &[a],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &semantic_snapshot,
                &fixture.principal(),
            )
            .expect("semantic snapshot")
            .nodes,
        compacted_result
    );
}

#[test]
fn paged_segment_v2_fails_closed_on_missing_rows_merkle_nodes_and_malformed_edges() {
    let fixture = Fixture::new();
    let a = NodeId::new();
    let b = NodeId::new();
    let edge_type = EdgeTypeId::new();
    let edge_id = EdgeId::new();
    let relation = edge(&fixture, edge_id, a, b, edge_type, 2);
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    initial_graph(&store, &fixture, &[a, b]);
    store
        .commit(
            GraphMutation {
                base_storage_seq: 1,
                edges: vec![relation.0],
                edge_revisions: vec![relation.1],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("edge");
    let manifest = store
        .compact_graph(Durability::Ephemeral)
        .expect("paged compaction");
    let snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let dense = store
        .id_mapping(&a.to_string(), &snapshot, &fixture.principal())
        .expect("dense mapping")
        .dense_id
        .get();
    let mut generation_prefix = vec![b'g'];
    generation_prefix.extend_from_slice(&manifest.generation.to_be_bytes());
    let mut row_key = generation_prefix.clone();
    row_key.extend_from_slice(&[b'r', 0]);
    row_key.extend_from_slice(&dense.to_be_bytes());
    let leaf_index = (dense - 1) * 2;
    let mut leaf_key = generation_prefix.clone();
    leaf_key.push(b't');
    leaf_key.extend_from_slice(&0_u16.to_be_bytes());
    leaf_key.extend_from_slice(&leaf_index.to_be_bytes());
    let physical = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let segment_space = Keyspace::new("graph_segment_v2").expect("segment keyspace");
    let row_bytes = physical
        .get(&segment_space, &row_key)
        .expect("row read")
        .expect("row manifest");
    let leaf_bytes = physical
        .get(&segment_space, &leaf_key)
        .expect("leaf read")
        .expect("Merkle leaf");
    drop(physical);

    let mut transaction = engine.begin_write().expect("missing-row writer");
    transaction
        .delete(&segment_space, row_key.clone())
        .expect("delete row");
    transaction
        .commit(Durability::Ephemeral)
        .expect("publish missing row");
    let corrupt = store
        .snapshot(SnapshotSelector::Latest)
        .expect("corrupt view");
    assert!(matches!(
        store.traverse(
            &[a],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            10,
            &corrupt,
            &fixture.principal(),
        ),
        Err(GraphError::Corrupt(message)) if message.contains("row manifest missing")
    ));

    let mut transaction = engine.begin_write().expect("missing-leaf writer");
    transaction
        .put(&segment_space, row_key, row_bytes)
        .expect("restore row");
    transaction
        .delete(&segment_space, leaf_key.clone())
        .expect("delete leaf");
    transaction
        .commit(Durability::Ephemeral)
        .expect("publish missing leaf");
    let corrupt = store
        .snapshot(SnapshotSelector::Latest)
        .expect("corrupt view");
    assert!(matches!(
        store.traverse(
            &[a],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            10,
            &corrupt,
            &fixture.principal(),
        ),
        Err(GraphError::Corrupt(message)) if message.contains("Merkle node missing")
    ));

    let mut outgoing_prefix = generation_prefix;
    outgoing_prefix.extend_from_slice(&[b'e', 0]);
    outgoing_prefix.extend_from_slice(&dense.to_be_bytes());
    let physical = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let edge_key = physical
        .scan_prefix(&segment_space, &outgoing_prefix)
        .expect("outgoing records")
        .into_iter()
        .next()
        .expect("outgoing edge")
        .key;
    drop(physical);
    let mut transaction = engine.begin_write().expect("malformed-edge writer");
    transaction
        .put(&segment_space, leaf_key, leaf_bytes)
        .expect("restore leaf");
    transaction
        .put(&segment_space, edge_key, b"{}".to_vec())
        .expect("corrupt edge");
    transaction
        .commit(Durability::Ephemeral)
        .expect("publish malformed edge");
    let corrupt = store
        .snapshot(SnapshotSelector::Latest)
        .expect("corrupt view");
    assert!(matches!(
        store.traverse(
            &[a],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            10,
            &corrupt,
            &fixture.principal(),
        ),
        Err(GraphError::Corrupt(_))
    ));
}

#[test]
fn legacy_v1_adjacency_remains_readable_after_v2_writer_upgrade() {
    #[derive(Serialize)]
    struct LegacyDigest<'a> {
        format_version: u16,
        generation: u64,
        built_through_seq: u64,
        outgoing_ranges: &'a [AdjacencyRange],
        outgoing_edges: &'a [SegmentEdge],
        incoming_ranges: &'a [AdjacencyRange],
        incoming_edges: &'a [SegmentEdge],
    }

    let fixture = Fixture::new();
    let a = NodeId::new();
    let b = NodeId::new();
    let edge_type = EdgeTypeId::new();
    let edge_id = EdgeId::new();
    let relation = edge(&fixture, edge_id, a, b, edge_type, 2);
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    initial_graph(&store, &fixture, &[a, b]);
    store
        .commit(
            GraphMutation {
                base_storage_seq: 1,
                edges: vec![relation.0],
                edge_revisions: vec![relation.1],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("edge");
    let pre_switch = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let a_dense = store
        .id_mapping(&a.to_string(), &pre_switch, &fixture.principal())
        .expect("a mapping")
        .dense_id;
    let b_dense = store
        .id_mapping(&b.to_string(), &pre_switch, &fixture.principal())
        .expect("b mapping")
        .dense_id;
    let row = SegmentEdge {
        edge_id: edge_id.to_string(),
        source: a_dense,
        target: b_dense,
        edge_type: edge_type.to_string(),
        directionality: Directionality::Directed,
    };
    let outgoing_ranges = vec![AdjacencyRange {
        node: a_dense,
        start: 0,
        end: 1,
    }];
    let incoming_ranges = vec![AdjacencyRange {
        node: b_dense,
        start: 0,
        end: 1,
    }];
    let outgoing_edges = vec![row.clone()];
    let incoming_edges = vec![row];
    let segment_digest = blake3::hash(
        &serde_json::to_vec(&LegacyDigest {
            format_version: 1,
            generation: 1,
            built_through_seq: 2,
            outgoing_ranges: &outgoing_ranges,
            outgoing_edges: &outgoing_edges,
            incoming_ranges: &incoming_ranges,
            incoming_edges: &incoming_edges,
        })
        .expect("legacy digest bytes"),
    )
    .to_hex()
    .to_string();
    let segment = AdjacencySegment {
        format_version: 1,
        generation: 1,
        built_through_seq: 2,
        outgoing_ranges,
        outgoing_edges,
        incoming_ranges,
        incoming_edges,
        digest: segment_digest.clone(),
    };
    let legacy_manifest = serde_json::to_vec(&json!({
        "generation": 1,
        "built_through_seq": 2,
        "segment_digest": segment_digest,
    }))
    .expect("legacy manifest bytes");
    let mut segment_key = b"base".to_vec();
    segment_key.extend_from_slice(&1_u64.to_be_bytes());
    let mut transaction = engine.begin_write().expect("legacy writer");
    transaction
        .put(
            &Keyspace::new("graph_segment_v1").expect("legacy segment keyspace"),
            segment_key,
            serde_json::to_vec(&segment).expect("legacy segment bytes"),
        )
        .expect("legacy segment");
    transaction
        .put(
            &Keyspace::new("graph_meta_v1").expect("meta keyspace"),
            b"active_manifest".to_vec(),
            legacy_manifest.clone(),
        )
        .expect("active legacy manifest");
    transaction
        .put(
            &Keyspace::new("graph_manifest_history_v1").expect("manifest history"),
            3_u64.to_be_bytes().to_vec(),
            legacy_manifest,
        )
        .expect("legacy history");
    transaction
        .commit(Durability::Ephemeral)
        .expect("legacy switch");

    let legacy_snapshot = store
        .snapshot(SnapshotSelector::Latest)
        .expect("legacy snapshot");
    assert_eq!(legacy_snapshot.segment_generation, 1);
    assert_eq!(
        store
            .traverse(
                &[a],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &legacy_snapshot,
                &fixture.principal(),
            )
            .expect("legacy traversal")
            .nodes,
        vec![b.to_string()]
    );
    let v2_manifest = store
        .compact_graph(Durability::Ephemeral)
        .expect("v1 to v2 generation switch");
    assert_eq!(v2_manifest.format_version, 2);
    assert_eq!(v2_manifest.generation, 2);
    let v2_snapshot = store
        .snapshot(SnapshotSelector::Latest)
        .expect("v2 snapshot");
    let report = store
        .prune_adjacency_generations(v2_snapshot.storage_seq, Durability::Sync)
        .expect("mixed-format prune");
    assert_eq!(report.baseline_generation, 2);
    assert_eq!(report.active_generation, 2);
    assert_eq!(report.v1_generations_deleted, 1);
    assert_eq!(report.v2_generations_deleted, 0);
    assert!(matches!(
        store.snapshot(SnapshotSelector::At(legacy_snapshot.storage_seq)),
        Err(GraphError::SnapshotPruned { .. })
    ));
    let mut old_segment_key = b"base".to_vec();
    old_segment_key.extend_from_slice(&1_u64.to_be_bytes());
    let physical = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    assert!(
        physical
            .get(
                &Keyspace::new("graph_segment_v1").expect("legacy segment keyspace"),
                &old_segment_key,
            )
            .expect("legacy generation read")
            .is_none()
    );
    assert_eq!(
        store
            .traverse(
                &[a],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &v2_snapshot,
                &fixture.principal(),
            )
            .expect("active v2 traversal")
            .nodes,
        vec![b.to_string()]
    );
}

#[test]
fn paged_manifest_rejects_global_resource_claims_over_the_hard_cap() {
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    let manifest = serde_json::to_vec(&json!({
        "format_version": 2,
        "generation": 1,
        "built_through_seq": 0,
        "segment_digest": "00".repeat(32),
        "row_count": 20_000_002_u64,
        "edge_count": 0,
        "edge_bytes": 0,
    }))
    .expect("oversized manifest");
    let mut transaction = engine.begin_write().expect("writer");
    transaction
        .put(
            &Keyspace::new("graph_meta_v1").expect("meta keyspace"),
            b"active_manifest".to_vec(),
            manifest.clone(),
        )
        .expect("active manifest");
    transaction
        .put(
            &Keyspace::new("graph_manifest_history_v1").expect("manifest history"),
            1_u64.to_be_bytes().to_vec(),
            manifest,
        )
        .expect("manifest history");
    transaction
        .commit(Durability::Ephemeral)
        .expect("publish manifest");
    assert!(matches!(
        store.snapshot(SnapshotSelector::Latest),
        Err(GraphError::ResourceExhausted {
            resource: "segment_v2_rows",
            limit: 20_000_000,
            required: 20_000_002,
        })
    ));
}

#[test]
fn paged_segment_root_authenticates_manifest_counters() {
    let fixture = Fixture::new();
    let a = NodeId::new();
    let b = NodeId::new();
    let edge_type = EdgeTypeId::new();
    let relation = edge(&fixture, EdgeId::new(), a, b, edge_type, 2);
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    initial_graph(&store, &fixture, &[a, b]);
    store
        .commit(
            GraphMutation {
                base_storage_seq: 1,
                edges: vec![relation.0],
                edge_revisions: vec![relation.1],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("edge");
    store
        .compact_graph(Durability::Ephemeral)
        .expect("paged generation");
    let physical = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &physical
            .get(
                &Keyspace::new("graph_meta_v1").expect("meta keyspace"),
                b"active_manifest",
            )
            .expect("manifest read")
            .expect("active manifest"),
    )
    .expect("manifest JSON");
    let next_edge_count = manifest["edge_count"]
        .as_u64()
        .expect("edge count")
        .checked_add(1)
        .expect("edge count increment");
    manifest["edge_count"] = json!(next_edge_count);
    let tampered = serde_json::to_vec(&manifest).expect("tampered manifest bytes");
    let manifest_history_key = physical
        .scan_prefix(
            &Keyspace::new("graph_manifest_history_v1").expect("manifest history"),
            b"",
        )
        .expect("history scan")
        .into_iter()
        .last()
        .expect("history entry")
        .key;
    drop(physical);
    let mut transaction = engine.begin_write().expect("writer");
    transaction
        .put(
            &Keyspace::new("graph_meta_v1").expect("meta keyspace"),
            b"active_manifest".to_vec(),
            tampered.clone(),
        )
        .expect("active manifest");
    transaction
        .put(
            &Keyspace::new("graph_manifest_history_v1").expect("manifest history"),
            manifest_history_key,
            tampered,
        )
        .expect("manifest history");
    transaction
        .commit(Durability::Ephemeral)
        .expect("tampered switch");
    assert!(matches!(
        store.snapshot(SnapshotSelector::Latest),
        Err(GraphError::Corrupt(message)) if message.contains("root disagrees")
    ));
}

#[test]
fn nodes_created_after_paged_compaction_use_deltas_until_the_next_generation() {
    let fixture = Fixture::new();
    let existing = NodeId::new();
    let later = NodeId::new();
    let edge_type = EdgeTypeId::new();
    let relation = edge(&fixture, EdgeId::new(), later, existing, edge_type, 2);
    let store = GraphStore::new(MemoryStorage::new()).expect("store");
    initial_graph(&store, &fixture, &[existing]);
    store
        .compact_graph(Durability::Ephemeral)
        .expect("initial paged generation");
    let compacted = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let mut later_node = node(&fixture, later);
    later_node.created_seq = CommitSeq::new(2);
    let mut later_revision = node_revision(&fixture, later, 1, "later", 0, None);
    later_revision.temporal.transaction_time = CommitRange::current(CommitSeq::new(2));
    store
        .commit(
            GraphMutation {
                base_storage_seq: compacted.storage_seq,
                nodes: vec![later_node],
                node_revisions: vec![later_revision],
                edges: vec![relation.0],
                edge_revisions: vec![relation.1],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("post-compaction node and edge");
    let snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    assert_eq!(snapshot.segment_generation, 1);
    assert_eq!(
        store
            .traverse(
                &[later],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &snapshot,
                &fixture.principal(),
            )
            .expect("delta-only row")
            .nodes,
        vec![existing.to_string()]
    );
}

#[test]
fn paged_compaction_crosses_source_and_dense_page_boundaries_without_skips() {
    let fixture = Fixture::new();
    let hub = NodeId::new();
    let targets = (0..130).map(|_| NodeId::new()).collect::<Vec<_>>();
    let mut nodes = vec![hub];
    nodes.extend(targets.iter().copied());
    let edge_type = EdgeTypeId::new();
    let relations = targets
        .iter()
        .map(|target| edge(&fixture, EdgeId::new(), hub, *target, edge_type, 2))
        .collect::<Vec<_>>();
    let store = GraphStore::new(MemoryStorage::new()).expect("store");
    initial_graph(&store, &fixture, &nodes);
    store
        .commit(
            GraphMutation {
                base_storage_seq: 1,
                edges: relations
                    .iter()
                    .map(|relation| relation.0.clone())
                    .collect(),
                edge_revisions: relations
                    .iter()
                    .map(|relation| relation.1.clone())
                    .collect(),
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        )
        .expect("edge page workload");
    let manifest = store
        .compact_graph(Durability::Ephemeral)
        .expect("multi-page compaction");
    assert_eq!(manifest.row_count, 262);
    assert_eq!(manifest.edge_count, 260);
    let snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let result = store
        .traverse(
            &[hub],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            200,
            &snapshot,
            &fixture.principal(),
        )
        .expect("multi-page traversal");
    assert_eq!(result.nodes.len(), targets.len());
    assert_eq!(
        result.nodes.into_iter().collect::<BTreeSet<_>>(),
        targets.iter().map(ToString::to_string).collect()
    );
}

#[test]
fn explicit_adjacency_prune_preserves_cutoff_and_active_snapshots_and_is_idempotent() {
    let fixture = Fixture::new();
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    let (nodes, edge_type, snapshots) =
        three_paged_generations(&store, &fixture, Durability::Ephemeral);
    assert_eq!(
        snapshots
            .iter()
            .map(|snapshot| snapshot.segment_generation)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let report = store
        .prune_adjacency_generations(snapshots[1].storage_seq, Durability::Sync)
        .expect("bounded adjacency prune");
    assert_eq!(report.previous_oldest_retained_storage_seq, 0);
    assert_eq!(report.oldest_retained_storage_seq, snapshots[1].storage_seq);
    assert_eq!(report.baseline_generation, 2);
    assert_eq!(report.active_generation, 3);
    assert_eq!(report.history_entries_deleted, 1);
    assert_eq!(report.v1_generations_deleted, 0);
    assert_eq!(report.v2_generations_deleted, 1);
    assert!(report.v2_records_deleted > 0);

    assert!(matches!(
        store.snapshot(SnapshotSelector::At(snapshots[0].storage_seq)),
        Err(GraphError::SnapshotPruned {
            requested,
            oldest_retained,
        }) if requested == snapshots[0].storage_seq
            && oldest_retained == snapshots[1].storage_seq
    ));
    assert!(matches!(
        store.snapshot_at_semantic(CommitSeq::new(2)),
        Err(GraphError::SnapshotPruned { .. })
    ));
    assert!(matches!(
        store.traverse(
            &[nodes[0]],
            Direction::Outgoing,
            &BTreeSet::from([edge_type]),
            1,
            10,
            &snapshots[0],
            &fixture.principal(),
        ),
        Err(GraphError::SnapshotPruned { .. })
    ));

    let retained = store
        .snapshot(SnapshotSelector::At(snapshots[1].storage_seq))
        .expect("cutoff snapshot remains readable");
    assert_eq!(retained.segment_generation, 2);
    assert_eq!(
        store
            .traverse(
                &[nodes[0]],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &retained,
                &fixture.principal(),
            )
            .expect("cutoff traversal")
            .nodes
            .into_iter()
            .collect::<BTreeSet<_>>(),
        nodes[1..3].iter().map(ToString::to_string).collect()
    );
    let active = store
        .snapshot(SnapshotSelector::Latest)
        .expect("active snapshot");
    assert_eq!(active.segment_generation, 3);
    assert_eq!(
        store
            .traverse(
                &[nodes[0]],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &active,
                &fixture.principal(),
            )
            .expect("active traversal")
            .nodes
            .len(),
        3
    );

    let physical = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let segment_space = Keyspace::new("graph_segment_v2").expect("segment keyspace");
    for (generation, expected_empty) in [(1_u64, true), (2, false), (3, false)] {
        let mut prefix = vec![b'g'];
        prefix.extend_from_slice(&generation.to_be_bytes());
        assert_eq!(
            physical
                .scan_prefix(&segment_space, &prefix)
                .expect("generation scan")
                .is_empty(),
            expected_empty
        );
    }
    drop(physical);

    let repeated = store
        .prune_adjacency_generations(snapshots[1].storage_seq, Durability::Sync)
        .expect("idempotent retry");
    assert_eq!(
        repeated.previous_oldest_retained_storage_seq,
        snapshots[1].storage_seq
    );
    assert_eq!(repeated.history_entries_deleted, 0);
    assert_eq!(repeated.v1_generations_deleted, 0);
    assert_eq!(repeated.v2_generations_deleted, 0);
    assert_eq!(repeated.v2_records_deleted, 0);
    assert_eq!(repeated.active_generation, 3);
}

#[test]
fn malformed_manifest_history_aborts_prune_before_floor_or_generation_deletion() {
    let fixture = Fixture::new();
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    let (_, _, snapshots) = three_paged_generations(&store, &fixture, Durability::Ephemeral);
    let mut transaction = engine.begin_write().expect("corruption writer");
    transaction
        .put(
            &Keyspace::new("graph_manifest_history_v1").expect("manifest history"),
            b"malformed".to_vec(),
            b"{}".to_vec(),
        )
        .expect("malformed history entry");
    transaction
        .commit(Durability::Ephemeral)
        .expect("publish malformed history");
    assert!(matches!(
        store.prune_adjacency_generations(snapshots[1].storage_seq, Durability::Sync),
        Err(GraphError::Corrupt(_))
    ));
    let physical = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    assert!(
        physical
            .get(
                &Keyspace::new("graph_meta_v1").expect("meta keyspace"),
                b"adjacency_retention_floor",
            )
            .expect("floor read")
            .is_none()
    );
    let mut generation_one = vec![b'g'];
    generation_one.extend_from_slice(&1_u64.to_be_bytes());
    assert!(
        !physical
            .scan_prefix(
                &Keyspace::new("graph_segment_v2").expect("segment keyspace"),
                &generation_one,
            )
            .expect("generation scan")
            .is_empty()
    );
}

#[test]
fn adjacency_prune_rejects_ephemeral_before_any_mutation() {
    let fixture = Fixture::new();
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    let (_, _, snapshots) = three_paged_generations(&store, &fixture, Durability::Ephemeral);
    let before = engine.head_sequence().expect("head before rejection");
    assert!(matches!(
        store.prune_adjacency_generations(snapshots[1].storage_seq, Durability::Ephemeral),
        Err(GraphError::SyncDurabilityRequired {
            operation: "prune_adjacency_generations"
        })
    ));
    assert_eq!(
        engine.head_sequence().expect("head after rejection"),
        before
    );
    let latest = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("latest after rejection");
    let meta = Keyspace::new("graph_meta_v1").expect("meta keyspace");
    assert!(
        latest
            .get(&meta, b"adjacency_retention_floor")
            .expect("floor read")
            .is_none()
    );
    assert!(
        latest
            .get(&meta, b"adjacency_maintenance_fence")
            .expect("fence read")
            .is_none()
    );
}

#[test]
fn post_prune_reads_fail_closed_when_exact_baseline_is_missing_or_tampered() {
    for tamper_manifest in [false, true] {
        let fixture = Fixture::new();
        let engine = MemoryStorage::new();
        let store = GraphStore::new(engine.clone()).expect("store");
        let (_, _, snapshots) = three_paged_generations(&store, &fixture, Durability::Ephemeral);
        let cutoff = snapshots[1].storage_seq;
        store
            .prune_adjacency_generations(cutoff, Durability::Sync)
            .expect("prune");
        let history = Keyspace::new("graph_manifest_history_v1").expect("history keyspace");
        let mut transaction = engine.begin_write().expect("corruption writer");
        if tamper_manifest {
            transaction
                .put(
                    &history,
                    cutoff.to_be_bytes().to_vec(),
                    serde_json::to_vec(&empty_v2_manifest(99)).expect("tampered manifest"),
                )
                .expect("tamper baseline history");
        } else {
            transaction
                .delete(&history, cutoff.to_be_bytes().to_vec())
                .expect("delete baseline history");
        }
        transaction
            .commit(Durability::Ephemeral)
            .expect("publish corruption");
        assert!(matches!(
            store.snapshot(SnapshotSelector::At(cutoff)),
            Err(GraphError::Corrupt(_))
        ));
        assert!(matches!(
            store.snapshot(SnapshotSelector::Latest),
            Err(GraphError::Corrupt(_))
        ));
    }
}

#[test]
fn persistent_maintenance_fence_blocks_cross_store_compaction_and_prune() {
    let fixture = Fixture::new();
    let engine = MemoryStorage::new();
    let first = GraphStore::new(engine.clone()).expect("first store");
    let second = GraphStore::new(engine.clone()).expect("second store");
    let (_, _, snapshots) = three_paged_generations(&first, &fixture, Durability::Ephemeral);
    let meta = Keyspace::new("graph_meta_v1").expect("meta keyspace");

    let head = engine.head_sequence().expect("head");
    let compact_fence = json!({
        "format_version": 1,
        "epoch": 1,
        "operation": {
            "compact": {
                "generation": 4,
                "source_storage_seq": head,
                "base_generation": 3,
            }
        },
    });
    let mut transaction = engine.begin_write().expect("compact fence writer");
    transaction
        .put(
            &meta,
            b"adjacency_maintenance_epoch".to_vec(),
            serde_json::to_vec(&1_u64).expect("epoch"),
        )
        .expect("epoch put");
    transaction
        .put(
            &meta,
            b"adjacency_maintenance_fence".to_vec(),
            serde_json::to_vec(&compact_fence).expect("compact fence"),
        )
        .expect("fence put");
    let segment = Keyspace::new("graph_segment_v2").expect("segment keyspace");
    let mut staged_generation_four = vec![b'g'];
    staged_generation_four.extend_from_slice(&4_u64.to_be_bytes());
    staged_generation_four.push(b't');
    staged_generation_four.extend_from_slice(&0_u16.to_be_bytes());
    staged_generation_four.extend_from_slice(&0_u64.to_be_bytes());
    transaction
        .put(&segment, staged_generation_four.clone(), vec![7; 32])
        .expect("staged generation record");
    transaction
        .commit(Durability::Ephemeral)
        .expect("publish compact fence");
    assert!(matches!(
        second.prune_adjacency_generations(snapshots[1].storage_seq, Durability::Sync),
        Err(GraphError::AdjacencyMaintenanceConflict {
            requested: "prune_adjacency_generations",
            active: "compact_graph",
        })
    ));

    let latest = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("latest after conflict");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &latest
                .get(&meta, b"adjacency_maintenance_fence")
                .expect("fence read")
                .expect("fence remains")
        )
        .expect("fence json"),
        compact_fence
    );
    assert_eq!(
        first
            .snapshot(SnapshotSelector::Latest)
            .expect("active snapshot survives")
            .segment_generation,
        3
    );
    assert_eq!(
        latest
            .get(&segment, &staged_generation_four)
            .expect("staged record read"),
        Some(vec![7; 32])
    );
}

#[test]
fn persistent_prune_fence_blocks_cross_store_compaction_without_touching_active_generation() {
    let fixture = Fixture::new();
    let engine = MemoryStorage::new();
    let first = GraphStore::new(engine.clone()).expect("first store");
    let second = GraphStore::new(engine.clone()).expect("second store");
    let (_, _, _) = three_paged_generations(&first, &fixture, Durability::Ephemeral);
    let meta = Keyspace::new("graph_meta_v1").expect("meta keyspace");
    let head = engine.head_sequence().expect("head");
    let prune_fence = json!({
        "format_version": 1,
        "epoch": 1,
        "operation": {
            "prune": {
                "oldest_retained_storage_seq": head,
            }
        },
    });
    let mut transaction = engine.begin_write().expect("prune fence writer");
    transaction
        .put(
            &meta,
            b"adjacency_maintenance_epoch".to_vec(),
            serde_json::to_vec(&1_u64).expect("epoch"),
        )
        .expect("epoch put");
    transaction
        .put(
            &meta,
            b"adjacency_maintenance_fence".to_vec(),
            serde_json::to_vec(&prune_fence).expect("prune fence"),
        )
        .expect("fence put");
    transaction
        .commit(Durability::Ephemeral)
        .expect("publish prune fence");
    assert!(matches!(
        second.compact_graph(Durability::Ephemeral),
        Err(GraphError::AdjacencyMaintenanceConflict {
            requested: "compact_graph",
            active: "prune_adjacency_generations",
        })
    ));
    assert_eq!(
        first
            .snapshot(SnapshotSelector::Latest)
            .expect("active snapshot survives")
            .segment_generation,
        3
    );
    let segment = Keyspace::new("graph_segment_v2").expect("segment keyspace");
    let mut generation_four = vec![b'g'];
    generation_four.extend_from_slice(&4_u64.to_be_bytes());
    assert!(
        engine
            .begin_read(SnapshotSelector::Latest)
            .expect("physical snapshot")
            .scan_prefix(&segment, &generation_four)
            .expect("generation four scan")
            .is_empty()
    );
}

#[test]
fn adjacency_prune_resumes_after_floor_publication_before_history_cleanup() {
    let fixture = Fixture::new();
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    let (_, _, snapshots) = three_paged_generations(&store, &fixture, Durability::Ephemeral);
    let cutoff = snapshots[1].storage_seq;
    let baseline_manifest: SegmentManifest = serde_json::from_slice(
        &engine
            .begin_read(SnapshotSelector::Latest)
            .expect("baseline reader")
            .get(
                &Keyspace::new("graph_manifest_history_v1").expect("history keyspace"),
                &cutoff.to_be_bytes(),
            )
            .expect("baseline read")
            .expect("baseline history entry"),
    )
    .expect("baseline manifest");
    let mut transaction = engine.begin_write().expect("interrupted prune writer");
    transaction
        .put(
            &Keyspace::new("graph_meta_v1").expect("meta keyspace"),
            b"adjacency_retention_floor".to_vec(),
            serde_json::to_vec(&cutoff).expect("floor bytes"),
        )
        .expect("retention floor");
    transaction
        .put(
            &Keyspace::new("graph_meta_v1").expect("meta keyspace"),
            b"adjacency_retention_baseline".to_vec(),
            serde_json::to_vec(&json!({
                "format_version": 2,
                "oldest_retained_storage_seq": cutoff,
                "baseline_switch_seq": cutoff,
                "baseline_generation": 2,
                "baseline_manifest": baseline_manifest,
            }))
            .expect("baseline bytes"),
        )
        .expect("retention baseline");
    transaction
        .commit(Durability::Ephemeral)
        .expect("interrupted floor publication");
    assert!(matches!(
        store.snapshot(SnapshotSelector::At(snapshots[0].storage_seq)),
        Err(GraphError::SnapshotPruned { .. })
    ));
    let resumed = store
        .prune_adjacency_generations(cutoff, Durability::Sync)
        .expect("resume prune");
    assert_eq!(resumed.previous_oldest_retained_storage_seq, cutoff);
    assert_eq!(resumed.baseline_generation, 2);
    assert_eq!(resumed.active_generation, 3);
    assert_eq!(resumed.history_entries_deleted, 1);
    assert_eq!(resumed.v2_generations_deleted, 1);
    assert!(resumed.v2_records_deleted > 0);
    assert_eq!(
        store
            .snapshot(SnapshotSelector::At(cutoff))
            .expect("retained cutoff")
            .segment_generation,
        2
    );
}

#[test]
fn adjacency_history_prune_deletes_more_than_one_page_without_losing_the_baseline() {
    const GENERATIONS: u64 = 1_026;
    let engine = MemoryStorage::new();
    let store = GraphStore::new(engine.clone()).expect("store");
    let meta = Keyspace::new("graph_meta_v1").expect("meta keyspace");
    let history = Keyspace::new("graph_manifest_history_v1").expect("history keyspace");
    for generation in 1..=GENERATIONS {
        let manifest = empty_v2_manifest(generation);
        let mut transaction = engine.begin_write().expect("history writer");
        assert_eq!(transaction.sequence(), generation - 1);
        transaction
            .put(
                &meta,
                b"active_manifest".to_vec(),
                serde_json::to_vec(&manifest).expect("manifest bytes"),
            )
            .expect("active manifest");
        transaction
            .put(
                &history,
                generation.to_be_bytes().to_vec(),
                serde_json::to_vec(&manifest).expect("history bytes"),
            )
            .expect("history entry");
        transaction
            .commit(Durability::Ephemeral)
            .expect("history commit");
    }
    let report = store
        .prune_adjacency_generations(GENERATIONS, Durability::Sync)
        .expect("multi-page history prune");
    assert_eq!(report.baseline_generation, GENERATIONS);
    assert_eq!(report.active_generation, GENERATIONS);
    assert_eq!(report.history_entries_deleted, GENERATIONS - 1);
    let physical = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let retained_history = physical
        .scan_prefix(&history, b"")
        .expect("retained history");
    assert_eq!(retained_history.len(), 1);
    assert_eq!(retained_history[0].key, GENERATIONS.to_be_bytes().to_vec());
    drop(physical);
    assert_eq!(
        store
            .snapshot(SnapshotSelector::At(GENERATIONS))
            .expect("baseline snapshot")
            .segment_generation,
        GENERATIONS
    );
    assert!(matches!(
        store.snapshot(SnapshotSelector::At(GENERATIONS - 1)),
        Err(GraphError::SnapshotPruned { .. })
    ));
    let retry = store
        .prune_adjacency_generations(GENERATIONS, Durability::Sync)
        .expect("multi-page retry");
    assert_eq!(retry.history_entries_deleted, 0);
}

#[test]
fn redb_adjacency_prune_survives_reopen_and_reconstructs_the_cutoff() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("adjacency-prune.redb");
    let nodes;
    let edge_type;
    let cutoff;
    {
        let store = GraphStore::new(RedbStorage::open(&path).expect("redb")).expect("store");
        let seeded = three_paged_generations(&store, &fixture, Durability::Sync);
        nodes = seeded.0;
        edge_type = seeded.1;
        cutoff = seeded.2[1].storage_seq;
        let report = store
            .prune_adjacency_generations(cutoff, Durability::Sync)
            .expect("redb prune");
        assert_eq!(report.baseline_generation, 2);
        assert_eq!(report.active_generation, 3);
        let retained = store
            .snapshot(SnapshotSelector::At(cutoff))
            .expect("latest-only retained snapshot");
        assert_eq!(retained.segment_generation, 2);
        assert_eq!(
            store
                .traverse(
                    &[nodes[0]],
                    Direction::Outgoing,
                    &BTreeSet::from([edge_type]),
                    1,
                    10,
                    &retained,
                    &fixture.principal(),
                )
                .expect("retained traversal")
                .nodes
                .len(),
            2
        );
    }
    let reopened =
        GraphStore::new(RedbStorage::open(&path).expect("redb reopen")).expect("store reopen");
    assert!(matches!(
        reopened.snapshot(SnapshotSelector::At(cutoff - 1)),
        Err(GraphError::SnapshotPruned {
            requested,
            oldest_retained,
        }) if requested == cutoff - 1 && oldest_retained == cutoff
    ));
    let retained = reopened
        .snapshot(SnapshotSelector::At(cutoff))
        .expect("reopened cutoff");
    assert_eq!(retained.segment_generation, 2);
    let active = reopened
        .snapshot(SnapshotSelector::Latest)
        .expect("reopened active");
    assert_eq!(active.segment_generation, 3);
    assert_eq!(
        reopened
            .traverse(
                &[nodes[0]],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &active,
                &fixture.principal(),
            )
            .expect("reopened active traversal")
            .nodes
            .len(),
        3
    );
    let repeated = reopened
        .prune_adjacency_generations(cutoff, Durability::Sync)
        .expect("reopened retry");
    assert_eq!(repeated.history_entries_deleted, 0);
    assert_eq!(repeated.v2_generations_deleted, 0);
}

#[test]
fn cross_type_external_id_collision_rolls_back_without_policy_aliasing() {
    let fixture = Fixture::new();
    let node_id = NodeId::new();
    let store = GraphStore::new(MemoryStorage::new()).expect("store");
    initial_graph(&store, &fixture, &[node_id]);
    let before = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    let colliding_artifact_id =
        contextdb_core::ArtifactId::from_uuid(node_id.as_uuid()).expect("typed collision");
    let colliding_artifact = Artifact {
        id: colliding_artifact_id,
        source_id: SourceId::new(),
        modality: Modality::Text,
        media_type: "text/plain".to_owned(),
        native_locator: None,
        content_blocks: NonEmptyVec::new(ContentBlockId::new()),
        content_hash: ContentDigest::from_bytes([8; 32]),
        created_at: None,
        ingested_at: TimestampMicros(1),
        envelope: fixture.envelope(),
    };
    assert!(matches!(
        store.commit(
            GraphMutation {
                base_storage_seq: before.storage_seq,
                artifacts: vec![colliding_artifact],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        ),
        Err(GraphError::Invariant(_))
    ));
    let after = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
    assert_eq!(before, after);
    let first_space = MemorySpaceId::new();
    let second_space = MemorySpaceId::new();
    let mut first = fixture.space_record();
    first.id = first_space;
    first.parent = Some(second_space);
    let mut second = fixture.space_record();
    second.id = second_space;
    second.parent = Some(first_space);
    assert!(matches!(
        store.commit(
            GraphMutation {
                base_storage_seq: before.storage_seq,
                memory_spaces: vec![first, second],
                ..GraphMutation::default()
            },
            Durability::Ephemeral,
        ),
        Err(GraphError::Invariant(_))
    ));
    assert_eq!(
        store.snapshot(SnapshotSelector::Latest).expect("snapshot"),
        before
    );
    assert!(matches!(
        store.artifact(colliding_artifact_id, &after, &fixture.principal()),
        Err(GraphError::NotFound {
            kind: "artifact",
            ..
        })
    ));
    assert_eq!(
        store
            .node(node_id, &after, &fixture.principal())
            .expect("original node survives")
            .node
            .id,
        node_id
    );
}

#[test]
fn redb_reopen_and_generation_switch_preserve_public_graph() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("graph.redb");
    let fixture = Fixture::new();
    let a = NodeId::new();
    let b = NodeId::new();
    let edge_type = EdgeTypeId::new();
    let edge = edge(&fixture, EdgeId::new(), a, b, edge_type, 1);
    let stable_mapping;
    {
        let store = GraphStore::new(RedbStorage::open(&path).expect("redb open")).expect("store");
        store
            .commit(
                GraphMutation {
                    base_storage_seq: 0,
                    workspaces: vec![fixture.workspace_record()],
                    memory_spaces: vec![fixture.space_record()],
                    memory_subjects: vec![fixture.subject_record(a)],
                    nodes: vec![node(&fixture, a), node(&fixture, b)],
                    node_revisions: vec![
                        node_revision(&fixture, a, 1, "a-v1", 0, None),
                        node_revision(&fixture, b, 1, "b", 0, None),
                    ],
                    edges: vec![edge.0],
                    edge_revisions: vec![edge.1],
                    ..GraphMutation::default()
                },
                Durability::Sync,
            )
            .expect("persistent graph");
        let snapshot = store.snapshot(SnapshotSelector::Latest).expect("snapshot");
        stable_mapping = store
            .id_mapping(&a.to_string(), &snapshot, &fixture.principal())
            .expect("mapping");
        let mut second_revision = node_revision(&fixture, a, 2, "a-v2", 0, None);
        second_revision.envelope.ownership.audience_grants[0].audience = Audience::Public;
        store
            .commit(
                GraphMutation {
                    base_storage_seq: snapshot.storage_seq,
                    node_revisions: vec![second_revision],
                    ..GraphMutation::default()
                },
                Durability::Sync,
            )
            .expect("persistent second revision");
        let manifest = store
            .compact_graph(Durability::Sync)
            .expect("compact graph");
        assert_eq!(manifest.generation, 1);
    }
    let reopened = GraphStore::new(RedbStorage::open(&path).expect("redb reopen")).expect("store");
    let snapshot = reopened
        .snapshot(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(snapshot.segment_generation, 1);
    assert_eq!(snapshot.semantic_seq, CommitSeq::new(2));
    assert_eq!(
        reopened
            .id_mapping(&a.to_string(), &snapshot, &fixture.principal())
            .expect("stable mapping"),
        stable_mapping
    );
    assert_eq!(
        reopened
            .traverse(
                &[a],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &snapshot,
                &fixture.principal(),
            )
            .expect("reopened traversal")
            .nodes,
        vec![b.to_string()]
    );
    assert_eq!(
        reopened
            .node(a, &snapshot, &fixture.principal())
            .expect("reopened current revision")
            .revision
            .canonical_name,
        "a-v2"
    );
    assert!(
        !reopened
            .authorized_index(
                &PolicyIndexQuery::Audience(Audience::Owner),
                &snapshot,
                &fixture.principal(),
            )
            .expect("current policy index")
            .contains(&a.to_string())
    );
    let historical = reopened
        .snapshot_at_semantic(CommitSeq::new(1))
        .expect("logical history over latest-only redb substrate");
    assert_eq!(historical.storage_seq, 1);
    assert_eq!(historical.segment_generation, 0);
    assert_eq!(
        reopened
            .node(a, &historical, &fixture.principal())
            .expect("reopened historical revision")
            .revision
            .canonical_name,
        "a-v1"
    );
    assert!(
        reopened
            .authorized_index(
                &PolicyIndexQuery::Audience(Audience::Owner),
                &historical,
                &fixture.principal(),
            )
            .expect("historical policy projection")
            .contains(&a.to_string())
    );
    assert_eq!(
        reopened
            .traverse(
                &[a],
                Direction::Outgoing,
                &BTreeSet::from([edge_type]),
                1,
                10,
                &historical,
                &fixture.principal(),
            )
            .expect("historical delta reconstruction")
            .nodes,
        vec![b.to_string()]
    );
}
