#![allow(
    clippy::unwrap_used,
    reason = "test fixtures use immediate failure semantics"
)]

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    AcceptanceState, AccessCapability, ActorId, Audience, AudienceGrant, BitemporalRange,
    CommitRange, CommitSeq, ConfidenceProfile, ConflictState, ConsentPolicy, DerivationKind,
    DerivationRef, EpistemicBasis, EpistemicRole, EpistemicState, IdentityState, LifecycleState,
    LineageNode, MemorySubjectId, MemoryUsePolicy, ModificationPolicy, MutationId, Node,
    NodeRevision, NodeType, NonEmptyVec, OwnershipPolicy, PipelineIdentity, PolicyDecision,
    Purpose, RetentionPolicy, RevisionNumber, ScopeId, ScopeInheritance, ScopeKind, ScopeRef,
    SecurityClassification, SecurityPolicy, SemanticEnvelope, SemanticMutationSet, SnapshotRef,
    TimeRange, TimestampMicros, WorkspaceId,
};
use contextdb_reference::{ContextDb, JournalEvent};

fn core_envelope(owner: MemorySubjectId, scope_id: ScopeId) -> SemanticEnvelope {
    let purposes = BTreeSet::from([Purpose::KnowledgeRecall]);
    SemanticEnvelope {
        scopes: NonEmptyVec::new(ScopeRef {
            kind: ScopeKind::Workspace,
            id: scope_id,
            inheritance: ScopeInheritance::Exact,
        }),
        perspective: contextdb_core::Perspective {
            knower: owner,
            experiencer: Some(owner),
            narrator: ActorId::new(),
            role: EpistemicRole::Asserter,
        },
        ownership: OwnershipPolicy {
            owners: NonEmptyVec::new(owner),
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
            id: contextdb_core::DerivationId::new(),
            kind: DerivationKind::DeterministicProjector,
            actor: None,
            model_call: None,
            pipeline: PipelineIdentity {
                name: "core-adapter-test".to_owned(),
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

#[test]
fn canonical_core_mutation_is_validated_published_and_preserved_for_replay() {
    let db = ContextDb::new("core-adapter-db").expect("database");
    let workspace_id = WorkspaceId::new();
    let node_id = contextdb_core::NodeId::new();
    let owner = MemorySubjectId::new();
    let scope_id = ScopeId::new();
    let envelope = core_envelope(owner, scope_id);
    let mutation = SemanticMutationSet {
        id: MutationId::new(),
        base_snapshot: SnapshotRef {
            commit_seq: CommitSeq::GENESIS,
        },
        journal_refs: NonEmptyVec::new(contextdb_core::ObservationId::new()),
        observation_appends: Vec::new(),
        episode_view_writes: Vec::new(),
        node_creates: vec![Node {
            id: node_id,
            workspace_id,
            node_type: NodeType::Entity,
            created_seq: CommitSeq::new(1),
            retired_seq: None,
            identity_state: IdentityState::Canonical,
            primary_scope: envelope.scopes.first().clone(),
        }],
        node_revisions: vec![NodeRevision {
            node_id,
            revision: RevisionNumber::FIRST,
            temporal: BitemporalRange {
                valid_time: TimeRange::open_ended(TimestampMicros(100)),
                transaction_time: CommitRange::current(CommitSeq::new(1)),
            },
            canonical_name: "Japan bar".to_owned(),
            attributes: BTreeMap::new(),
            epistemic: EpistemicState {
                basis: EpistemicBasis::Hypothesis,
                acceptance: AcceptanceState::Accepted,
                conflict: ConflictState::None,
                lifecycle: LifecycleState::Active,
            },
            confidence: ConfidenceProfile {
                overall: 1.0,
                source_trust: 1.0,
                extraction_quality: 1.0,
                corroboration: 1.0,
            },
            evidence: Vec::new(),
            envelope,
        }],
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

    let first = db.commit_core(&mutation, "core-key").expect("core commit");
    let replay = db.commit_core(&mutation, "core-key").expect("core replay");
    assert_eq!(first.commit_seq, 1);
    assert!(replay.replayed);
    let mut update = mutation.clone();
    update.id = MutationId::new();
    update.base_snapshot = SnapshotRef {
        commit_seq: CommitSeq::new(1),
    };
    update.journal_refs = NonEmptyVec::new(contextdb_core::ObservationId::new());
    update.node_creates.clear();
    update.node_revisions[0].revision = RevisionNumber::new(2).expect("second revision");
    update.node_revisions[0].temporal.transaction_time = CommitRange::current(CommitSeq::new(2));
    update.node_revisions[0].canonical_name = "Japan bar, current".to_owned();
    assert_eq!(
        db.commit_core(&update, "core-update")
            .expect("core update")
            .commit_seq,
        2
    );
    let journal = db.journal().expect("journal");
    let JournalEvent::SemanticPublished {
        affected_ids,
        request_content,
        ..
    } = &journal[0].event
    else {
        panic!("expected semantic publication");
    };
    assert_eq!(affected_ids, &BTreeSet::from([node_id.to_string()]));
    let export: contextdb_reference::LogicalExport =
        serde_json::from_slice(&db.export().expect("export")).expect("decode export");
    assert_eq!(
        export.contents.get(&request_content.id),
        Some(&serde_json::to_value(mutation).expect("canonical mutation value"))
    );
}
