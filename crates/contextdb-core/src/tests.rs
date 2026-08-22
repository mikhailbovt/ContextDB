use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use proptest::prelude::*;

use crate::*;

fn time(start: i64, end: Option<i64>) -> TimeRange {
    TimeRange::new(TimestampMicros(start), end.map(TimestampMicros))
        .expect("test interval must be valid")
}

fn commits(start: u64, end: Option<u64>) -> CommitRange {
    CommitRange::new(CommitSeq::new(start), end.map(CommitSeq::new))
        .expect("test commit interval must be valid")
}

fn pipeline() -> PipelineIdentity {
    PipelineIdentity {
        name: "test-projector".into(),
        version: "1.0.0".into(),
        schema_version: "1".into(),
    }
}

fn ownership(owner: MemorySubjectId, audience: Audience) -> OwnershipPolicy {
    let purposes = BTreeSet::from([Purpose::Conversation]);
    OwnershipPolicy {
        owners: NonEmptyVec::new(owner),
        audience_grants: vec![AudienceGrant {
            audience,
            purposes: purposes.clone(),
            capabilities: BTreeSet::from([
                AccessCapability::Retrieve,
                AccessCapability::InfluenceResponse,
                AccessCapability::Mention,
            ]),
        }],
        allowed_purposes: purposes,
        modification: ModificationPolicy {
            owners_may_modify: true,
            delegates_may_modify: false,
            system_may_derive: true,
        },
    }
}

fn envelope_with(
    owner: MemorySubjectId,
    actor: ActorId,
    audience: Audience,
    kind: DerivationKind,
    inputs: Vec<LineageNode>,
) -> SemanticEnvelope {
    SemanticEnvelope {
        scopes: NonEmptyVec::new(ScopeRef {
            kind: ScopeKind::Workspace,
            id: ScopeId::new(),
            inheritance: ScopeInheritance::Descendants,
        }),
        perspective: Perspective {
            knower: owner,
            experiencer: Some(owner),
            narrator: actor,
            role: EpistemicRole::Asserter,
        },
        ownership: ownership(owner, audience),
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
            classification: SecurityClassification::Confidential,
            labels: BTreeSet::from(["personal".into()]),
            required_compartments: BTreeSet::new(),
            allow_external_processing: false,
        },
        derivation: DerivationRef {
            id: DerivationId::new(),
            kind,
            actor: (kind == DerivationKind::ActorAssertion).then_some(actor),
            model_call: None,
            pipeline: pipeline(),
            inputs,
        },
    }
}

fn actor_assertion_envelope() -> SemanticEnvelope {
    let subject = MemorySubjectId::new();
    let actor = ActorId::new();
    envelope_with(
        subject,
        actor,
        Audience::Subject { id: subject },
        DerivationKind::ActorAssertion,
        Vec::new(),
    )
}

fn confidence() -> ConfidenceProfile {
    ConfidenceProfile {
        overall: 0.9,
        source_trust: 0.9,
        extraction_quality: 0.9,
        corroboration: 0.5,
    }
}

fn epistemic(basis: EpistemicBasis) -> EpistemicState {
    EpistemicState {
        basis,
        acceptance: AcceptanceState::Accepted,
        conflict: ConflictState::None,
        lifecycle: LifecycleState::Active,
    }
}

fn node() -> Node {
    Node {
        id: NodeId::new(),
        workspace_id: WorkspaceId::new(),
        node_type: NodeType::Entity,
        created_seq: CommitSeq::new(1),
        retired_seq: None,
        identity_state: IdentityState::Canonical,
        primary_scope: ScopeRef {
            kind: ScopeKind::Workspace,
            id: ScopeId::new(),
            inheritance: ScopeInheritance::Descendants,
        },
    }
}

fn node_revision(node_id: NodeId, number: u32, transaction: CommitRange) -> NodeRevision {
    NodeRevision {
        node_id,
        revision: RevisionNumber::new(number).expect("positive test revision"),
        temporal: BitemporalRange {
            valid_time: time(10, None),
            transaction_time: transaction,
        },
        canonical_name: format!("node-v{number}"),
        attributes: BTreeMap::new(),
        epistemic: epistemic(EpistemicBasis::ActorAssertion),
        confidence: confidence(),
        evidence: Vec::new(),
        envelope: actor_assertion_envelope(),
    }
}

fn claim_record(
    subject: NodeId,
    predicate: PredicateId,
    value: &str,
    conflict: ConflictState,
) -> ClaimRecord {
    let claim = Claim {
        id: ClaimId::new(),
        workspace_id: WorkspaceId::new(),
        subject,
        predicate,
        created_seq: CommitSeq::new(1),
    };
    let mut state = epistemic(EpistemicBasis::ActorAssertion);
    state.conflict = conflict;
    ClaimRecord {
        revisions: NonEmptyVec::new(ClaimRevision {
            claim_id: claim.id,
            revision: RevisionNumber::FIRST,
            object: ClaimObject::String(value.into()),
            temporal: BitemporalRange {
                valid_time: time(100, None),
                transaction_time: commits(1, None),
            },
            epistemic: state,
            confidence: confidence(),
            source_families: BTreeSet::new(),
            evidence: Vec::new(),
            supersedes: Vec::new(),
            envelope: actor_assertion_envelope(),
        }),
        claim,
    }
}

#[test]
fn stable_ids_are_canonical_strings_and_reject_nil() {
    let id = NodeId::new();
    let encoded = serde_json::to_string(&id).expect("serialize ID");
    assert_eq!(encoded, format!("\"{id}\""));
    assert_eq!(
        serde_json::from_str::<NodeId>(&encoded).expect("deserialize ID"),
        id
    );
    assert!(NodeId::from_str("00000000-0000-0000-0000-000000000000").is_err());
    assert!(serde_json::from_str::<NodeId>("\"00000000-0000-0000-0000-000000000000\"").is_err());
}

#[test]
fn non_empty_vec_rejects_empty_json() {
    assert!(serde_json::from_str::<NonEmptyVec<NodeId>>("[]").is_err());
    let values = NonEmptyVec::new(NodeId::new());
    let encoded = serde_json::to_string(&values).expect("serialize nonempty vector");
    assert_eq!(
        serde_json::from_str::<NonEmptyVec<NodeId>>(&encoded).expect("deserialize nonempty vector"),
        values
    );
}

#[test]
fn invalid_intervals_are_rejected_and_half_open_boundaries_do_not_overlap() {
    assert!(TimeRange::new(TimestampMicros(5), Some(TimestampMicros(5))).is_err());
    assert!(CommitRange::new(CommitSeq::new(3), Some(CommitSeq::new(2))).is_err());
    assert!(!time(0, Some(10)).overlaps(time(10, Some(20))));
    assert!(time(0, Some(11)).overlaps(time(10, Some(20))));
}

#[test]
fn derived_policy_may_narrow_but_not_broaden_access() {
    let owner = MemorySubjectId::new();
    let actor = ActorId::new();
    let source = envelope_with(
        owner,
        actor,
        Audience::Subject { id: owner },
        DerivationKind::DeterministicProjector,
        Vec::new(),
    );
    let mut narrower = source.clone();
    narrower.use_policy.mention_explicitly = PolicyDecision::Deny;
    narrower.security.classification = SecurityClassification::Restricted;
    assert_eq!(narrower.validate_derived_from(&source), Ok(()));

    let mut broader = source.clone();
    broader.ownership.audience_grants[0].audience = Audience::Public;
    assert!(matches!(
        broader.validate_derived_from(&source),
        Err(ValidationError::PolicyWeakening { .. })
    ));

    let mut external = source.clone();
    external.security.allow_external_processing = true;
    assert!(matches!(
        external.validate_derived_from(&source),
        Err(ValidationError::PolicyWeakening { .. })
    ));
}

#[test]
fn observation_requires_content_and_episode_is_a_separate_versioned_view() {
    let envelope = actor_assertion_envelope();
    let observation = ObservationUnit {
        id: ObservationId::new(),
        workspace_id: WorkspaceId::new(),
        memory_spaces: NonEmptyVec::new(MemorySpaceId::new()),
        source_id: SourceId::new(),
        stream_position: None,
        participants: NonEmptyVec::new(envelope.perspective.narrator),
        occurred_at: time(1, Some(2)),
        observed_at: TimestampMicros(2),
        recorded_at: TimestampMicros(3),
        artifact_refs: Vec::new(),
        content_block_refs: Vec::new(),
        content_hash: ContentDigest::from_bytes([7; 32]),
        envelope: envelope.clone(),
    };
    assert_eq!(
        observation.validate(),
        Err(ValidationError::MissingObservationContent)
    );

    let mut captured = observation;
    captured.content_block_refs.push(ContentBlockId::new());
    assert_eq!(captured.validate(), Ok(()));
    let episode = EpisodeView {
        id: EpisodeViewId::new(),
        revision: RevisionNumber::FIRST,
        workspace_id: captured.workspace_id,
        observation_ids: NonEmptyVec::new(captured.id),
        occurred_at: captured.occurred_at,
        transaction_time: commits(1, None),
        boundary: EpisodeBoundary::TurnPair,
        envelope,
    };
    assert_eq!(episode.validate(), Ok(()));
    assert_ne!(
        serde_json::to_value(&captured).expect("serialize observation"),
        serde_json::to_value(&episode).expect("serialize episode")
    );
}

#[test]
fn evidence_selectors_reject_empty_ranges() {
    assert!(
        EvidenceSelector::ByteRange { start: 4, end: 4 }
            .validate()
            .is_err()
    );
    assert!(
        EvidenceSelector::ImageRegion {
            x: 0,
            y: 0,
            width: 0,
            height: 10,
        }
        .validate()
        .is_err()
    );
    assert_eq!(
        EvidenceSelector::MediaTimeRange {
            start_millis: 5,
            end_millis: 6,
        }
        .validate(),
        Ok(())
    );
}

#[test]
fn revision_chain_rejects_overlap_and_non_contiguous_numbers() {
    let stable = node();
    let valid = NodeRecord {
        node: stable.clone(),
        revisions: NonEmptyVec::try_from_vec(
            vec![
                node_revision(stable.id, 1, commits(1, Some(2))),
                node_revision(stable.id, 2, commits(2, None)),
            ],
            "revisions",
        )
        .expect("nonempty revisions"),
    };
    assert_eq!(valid.validate(), Ok(()));

    let overlap = NodeRecord {
        node: stable.clone(),
        revisions: NonEmptyVec::try_from_vec(
            vec![
                node_revision(stable.id, 1, commits(1, Some(3))),
                node_revision(stable.id, 2, commits(2, None)),
            ],
            "revisions",
        )
        .expect("nonempty revisions"),
    };
    assert_eq!(
        overlap.validate(),
        Err(ValidationError::OverlappingTransactionIntervals)
    );

    let skipped = NodeRecord {
        node: stable.clone(),
        revisions: NonEmptyVec::try_from_vec(
            vec![
                node_revision(stable.id, 1, commits(1, Some(2))),
                node_revision(stable.id, 3, commits(2, None)),
            ],
            "revisions",
        )
        .expect("nonempty revisions"),
    };
    assert_eq!(
        skipped.validate(),
        Err(ValidationError::InvalidRevisionSequence)
    );
}

#[test]
fn evidence_is_required_except_actor_assertion_or_hypothesis() {
    let stable = node();
    let assertion = node_revision(stable.id, 1, commits(1, None));
    assert_eq!(assertion.validate(), Ok(()));

    let mut observed = assertion.clone();
    observed.epistemic.basis = EpistemicBasis::Observation;
    observed.envelope.derivation.kind = DerivationKind::DeterministicProjector;
    observed.envelope.derivation.actor = None;
    assert!(matches!(
        observed.validate(),
        Err(ValidationError::MissingEvidence { .. })
    ));
    observed.evidence.push(EvidenceId::new());
    assert_eq!(observed.validate(), Ok(()));
}

#[test]
fn single_cardinality_requires_an_explicit_shared_conflict_set() {
    let subject = NodeId::new();
    let predicate_id = PredicateId::new();
    let predicate = PredicateDefinition {
        id: predicate_id,
        name: "current_city".into(),
        domain: BTreeSet::from([NodeType::Entity]),
        range: ValueType::String,
        cardinality: Cardinality::OptionalSingle,
        temporal_mode: TemporalMode::Bitemporal,
        inverse: None,
        transitivity: Transitivity::None,
        conflict_policy: ConflictPolicy::RequireConflictSet,
        default_traversal_weight: 0.5,
        security_propagation: SecurityPropagation::InheritStrictest,
        version: RevisionNumber::FIRST,
    };
    let mut conflicting = vec![
        claim_record(subject, predicate_id, "Tokyo", ConflictState::None),
        claim_record(subject, predicate_id, "Singapore", ConflictState::None),
    ];
    conflicting[1].revisions[0].envelope.scopes =
        conflicting[0].revisions[0].envelope.scopes.clone();
    assert_eq!(
        validate_predicate_cardinality(&predicate, &conflicting),
        Err(ValidationError::CardinalityConflictWithoutConflictSet)
    );

    let set_id = ConflictSetId::new();
    let mut declared = vec![
        claim_record(
            subject,
            predicate_id,
            "Tokyo",
            ConflictState::InConflict { set_id },
        ),
        claim_record(
            subject,
            predicate_id,
            "Singapore",
            ConflictState::InConflict { set_id },
        ),
    ];
    declared[1].revisions[0].envelope.scopes = declared[0].revisions[0].envelope.scopes.clone();
    assert_eq!(
        validate_predicate_cardinality(&predicate, &declared),
        Ok(())
    );
}

#[test]
fn lineage_rejects_direct_and_indirect_self_support() {
    let claim = ClaimId::new();
    let claim_node = LineageNode::ClaimRevision {
        id: claim,
        revision: RevisionNumber::FIRST,
    };
    let summary = LineageNode::Summary {
        id: SummaryId::new(),
    };
    let direct = LineageGraph {
        edges: vec![LineageEdge {
            derived: claim_node.clone(),
            source: claim_node.clone(),
        }],
    };
    assert_eq!(
        direct.validate(),
        Err(ValidationError::SelfSupportingLineage)
    );

    let cycle = LineageGraph {
        edges: vec![
            LineageEdge {
                derived: claim_node.clone(),
                source: summary.clone(),
            },
            LineageEdge {
                derived: summary,
                source: claim_node,
            },
        ],
    };
    assert_eq!(cycle.validate(), Err(ValidationError::LineageCycle));
}

#[test]
fn candidate_quarantine_accepts_only_structured_payload() {
    let candidate = MemoryCandidate {
        id: CandidateId::new(),
        source_observations: NonEmptyVec::new(ObservationId::new()),
        candidate_type: CandidateType::Claim,
        payload: serde_json::json!(["not", "an", "object"]),
        evidence_spans: NonEmptyVec::new(EvidenceId::new()),
        pipeline: pipeline(),
        model_call: None,
        validation_state: CandidateValidationState::Quarantined,
        promotion: PromotionScore {
            overall: 0.5,
            explicitness: 0.5,
            future_utility: 0.5,
            source_trust: 0.5,
            corroboration: 0.5,
            sensitivity_penalty: 0.0,
            ambiguity_penalty: 0.0,
        },
        adjudication: CandidateAdjudication::Pending,
        envelope: actor_assertion_envelope(),
    };
    assert_eq!(
        candidate.validate(),
        Err(ValidationError::InvalidCandidatePayload)
    );
}

#[test]
fn mutation_requires_first_revision_for_each_created_identity() {
    let stable = node();
    let mutation = SemanticMutationSet {
        id: MutationId::new(),
        base_snapshot: SnapshotRef {
            commit_seq: CommitSeq::GENESIS,
        },
        journal_refs: NonEmptyVec::new(ObservationId::new()),
        observation_appends: Vec::new(),
        episode_view_writes: Vec::new(),
        node_creates: vec![stable.clone()],
        node_revisions: Vec::new(),
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
    assert_eq!(
        mutation.validate(),
        Err(ValidationError::InvalidRevisionSequence)
    );

    let mut complete = mutation;
    complete
        .node_revisions
        .push(node_revision(stable.id, 1, commits(1, None)));
    assert_eq!(complete.validate(), Ok(()));
}

#[test]
fn context_pack_rejects_future_watermarks_and_cross_snapshot_continuation() {
    let snapshot = SnapshotRef {
        commit_seq: CommitSeq::new(5),
    };
    let mut pack = ContextPack {
        id: ContextPackId::new(),
        snapshot,
        blocks: Vec::new(),
        evidence: Vec::new(),
        use_directives: Vec::new(),
        unknowns: vec!["no supported answer".into()],
        continuation: None,
        token_estimates: BTreeMap::new(),
        safety_labels: BTreeSet::new(),
        watermarks: IndexWatermarks {
            journal: CommitSeq::new(5),
            semantic: CommitSeq::new(5),
            lexical: CommitSeq::new(4),
            hierarchies: BTreeMap::new(),
            vectors: BTreeMap::new(),
            consolidation: CommitSeq::new(3),
        },
    };
    assert_eq!(pack.validate(), Ok(()));
    pack.watermarks.lexical = CommitSeq::new(6);
    assert!(pack.validate().is_err());
    pack.watermarks.lexical = CommitSeq::new(4);
    pack.continuation = Some(RecallContinuation {
        run_id: RecallRunId::new(),
        opaque: "next".into(),
        snapshot: SnapshotRef {
            commit_seq: CommitSeq::new(4),
        },
    });
    assert!(pack.validate().is_err());
}

#[test]
fn serde_rejects_unknown_fields_on_durable_contracts() {
    let json = r#"{"commit_seq":0,"future_field":true}"#;
    assert!(serde_json::from_str::<SnapshotRef>(json).is_err());
}

proptest! {
    #[test]
    fn digest_has_stable_hex_round_trip(bytes in any::<[u8; 32]>()) {
        let digest = ContentDigest::from_bytes(bytes);
        let text = digest.to_string();
        prop_assert_eq!(text.len(), 64);
        prop_assert_eq!(ContentDigest::from_str(&text), Ok(digest));
        let json = serde_json::to_string(&digest).expect("serialize digest");
        let decoded = serde_json::from_str::<ContentDigest>(&json).expect("deserialize digest");
        prop_assert_eq!(decoded, digest);
    }

    #[test]
    fn valid_time_ranges_are_half_open_and_overlap_is_symmetric(
        a_start in -1_000_000_i64..1_000_000,
        a_len in 1_i64..100_000,
        b_start in -1_000_000_i64..1_000_000,
        b_len in 1_i64..100_000,
    ) {
        let a = TimeRange::new(
            TimestampMicros(a_start),
            Some(TimestampMicros(a_start.saturating_add(a_len))),
        ).expect("positive interval");
        let b = TimeRange::new(
            TimestampMicros(b_start),
            Some(TimestampMicros(b_start.saturating_add(b_len))),
        ).expect("positive interval");
        prop_assert_eq!(a.overlaps(b), b.overlaps(a));
        prop_assert!(a.contains(a.start));
        prop_assert!(!a.contains(a.end.expect("bounded interval")));
    }

    #[test]
    fn generated_ids_remain_typed_and_serde_stable(_seed in any::<u64>()) {
        let node = NodeId::new();
        let claim = ClaimId::new();
        prop_assert_ne!(node.as_uuid(), claim.as_uuid());
        let encoded = serde_json::to_string(&node).expect("serialize node ID");
        let decoded = serde_json::from_str::<NodeId>(&encoded).expect("deserialize node ID");
        prop_assert_eq!(decoded, node);
    }
}
