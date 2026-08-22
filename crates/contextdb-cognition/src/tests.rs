use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::*;
use proptest::prelude::*;

use crate::*;

fn digest(text: &str) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes())
}

fn time(start: i64, end: Option<i64>) -> TimeRange {
    TimeRange::new(TimestampMicros(start), end.map(TimestampMicros))
        .expect("fixture time must be valid")
}

fn commits(start: u64, end: Option<u64>) -> CommitRange {
    CommitRange::new(CommitSeq::new(start), end.map(CommitSeq::new))
        .expect("fixture commit range must be valid")
}

fn pipeline_identity() -> PipelineIdentity {
    PipelineIdentity {
        name: "cognition-test".to_owned(),
        version: "1.0.0".to_owned(),
        schema_version: "1".to_owned(),
    }
}

fn envelope(
    owner: MemorySubjectId,
    actor: ActorId,
    scope: ScopeRef,
    kind: DerivationKind,
) -> SemanticEnvelope {
    let purposes = BTreeSet::from([Purpose::Conversation]);
    SemanticEnvelope {
        scopes: NonEmptyVec::new(scope),
        perspective: Perspective {
            knower: owner,
            experiencer: Some(owner),
            narrator: actor,
            role: EpistemicRole::Asserter,
        },
        ownership: OwnershipPolicy {
            owners: NonEmptyVec::new(owner),
            audience_grants: vec![AudienceGrant {
                audience: Audience::Subject { id: owner },
                purposes: purposes.clone(),
                capabilities: BTreeSet::from([
                    AccessCapability::Retrieve,
                    AccessCapability::InfluenceResponse,
                    AccessCapability::Mention,
                    AccessCapability::Derive,
                ]),
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
            classification: SecurityClassification::Confidential,
            labels: BTreeSet::from(["personal".to_owned()]),
            required_compartments: BTreeSet::new(),
            allow_external_processing: false,
        },
        derivation: DerivationRef {
            id: DerivationId::new(),
            kind,
            actor: (kind == DerivationKind::ActorAssertion).then_some(actor),
            model_call: None,
            pipeline: pipeline_identity(),
            inputs: Vec::new(),
        },
    }
}

fn confidence() -> ConfidenceProfile {
    ConfidenceProfile {
        overall: 0.9,
        source_trust: 0.9,
        extraction_quality: 0.9,
        corroboration: 0.5,
    }
}

fn accepted_actor_assertion() -> EpistemicState {
    EpistemicState {
        basis: EpistemicBasis::ActorAssertion,
        acceptance: AcceptanceState::Accepted,
        conflict: ConflictState::None,
        lifecycle: LifecycleState::Active,
    }
}

#[derive(Clone)]
struct Fixture {
    workspace: WorkspaceId,
    scope: ScopeRef,
    evidence_id: EvidenceId,
    quote_hash: ContentDigest,
    input: AdjudicationInput,
}

impl Fixture {
    fn new() -> Self {
        let workspace = WorkspaceId::new();
        let actor = ActorId::new();
        let owner = MemorySubjectId::new();
        let scope = ScopeRef {
            kind: ScopeKind::Workspace,
            id: ScopeId::new(),
            inheritance: ScopeInheritance::Descendants,
        };
        let source_envelope = envelope(owner, actor, scope.clone(), DerivationKind::ActorAssertion);
        let observation = ObservationId::new();
        let evidence_id = EvidenceId::new();
        let quote_hash = digest("primary quote");
        let evidence = EvidenceRecord {
            span: EvidenceSpan {
                id: evidence_id,
                observation_id: observation,
                artifact_id: None,
                content_block_id: ContentBlockId::new(),
                selector: EvidenceSelector::Whole,
                quote_hash,
                extracted_text: Some("primary quote".to_owned()),
                trust: TrustClass::Authenticated,
                derivation: None,
            },
            envelope: source_envelope.clone(),
            source_family: "conversation:user".to_owned(),
            observed_at: TimestampMicros(100),
            authority: EvidenceAuthority::ActorAssertion {
                actor,
                subject: owner,
            },
            taints: BTreeSet::new(),
            supports: Vec::new(),
        };
        let authorization = AuthorizationContext {
            actor,
            workspace_id: workspace,
            purpose: Purpose::Conversation,
            may_publish: true,
            permitted_evidence: BTreeSet::from([evidence_id]),
            permitted_nodes: BTreeSet::new(),
            permitted_claims: BTreeSet::new(),
        };
        let evidence = EvidenceCatalog(BTreeMap::from([(evidence_id, evidence)]));
        let journal_refs = NonEmptyVec::new(observation);
        let run = ProcessingRun {
            id: "run-v1".to_owned(),
            pipeline: pipeline_identity(),
            mode: ProcessingMode::Initial,
            model_call: None,
        };
        let input_hash = input_digest(&journal_refs, &evidence, &authorization);
        let policy_hash = policy_digest(&source_envelope).expect("fixture policy must serialize");
        let proposals = ProposalBatch {
            schema_id: PROPOSAL_SCHEMA_V1.to_owned(),
            processing_run: run.id.clone(),
            origin: ProposalOrigin::Deterministic,
            input_digest: input_hash,
            policy_digest: policy_hash,
            candidates: Vec::new(),
        };
        let input = AdjudicationInput {
            workspace_id: workspace,
            base_snapshot: SnapshotRef {
                commit_seq: CommitSeq::new(10),
            },
            reference_time: TimestampMicros(200),
            journal_refs,
            run,
            authorization,
            publication_envelope: source_envelope,
            evidence,
            entities: EntityIndex::default(),
            claims: ClaimIndex::default(),
            subject_anchors: BTreeMap::from([("user".to_owned(), owner)]),
            predicate_anchors: BTreeMap::new(),
            claim_anchors: BTreeMap::new(),
            proposals,
        };
        Self {
            workspace,
            scope,
            evidence_id,
            quote_hash,
            input,
        }
    }

    fn citation(&self) -> EvidenceCitation {
        EvidenceCitation {
            evidence_id: self.evidence_id,
            quote_hash: self.quote_hash,
        }
    }

    fn set_candidates(&mut self, candidates: Vec<CandidateProposal>) {
        self.input.proposals.processing_run = self.input.run.id.clone();
        self.input.proposals.origin = if let Some(call) = &self.input.run.model_call {
            ProposalOrigin::Model { call_id: call.id }
        } else {
            ProposalOrigin::Deterministic
        };
        self.input.proposals.input_digest = input_digest(
            &self.input.journal_refs,
            &self.input.evidence,
            &self.input.authorization,
        );
        self.input.proposals.policy_digest =
            policy_digest(&self.input.publication_envelope).expect("policy must serialize");
        self.input.proposals.candidates = candidates;
        if let Some(call) = &mut self.input.run.model_call {
            call.input_hash = self.input.proposals.input_digest;
            call.output_hash = self
                .input
                .proposals
                .canonical_digest()
                .expect("proposal must serialize");
        }
    }

    fn add_evidence(&mut self, family: &str, authority: EvidenceAuthority) -> EvidenceCitation {
        let observation = ObservationId::new();
        let evidence_id = EvidenceId::new();
        let quote_hash = digest(family);
        self.input.journal_refs.push(observation);
        self.input
            .authorization
            .permitted_evidence
            .insert(evidence_id);
        self.input.evidence.0.insert(
            evidence_id,
            EvidenceRecord {
                span: EvidenceSpan {
                    id: evidence_id,
                    observation_id: observation,
                    artifact_id: None,
                    content_block_id: ContentBlockId::new(),
                    selector: EvidenceSelector::Whole,
                    quote_hash,
                    extracted_text: Some(family.to_owned()),
                    trust: TrustClass::Authenticated,
                    derivation: None,
                },
                envelope: self.input.publication_envelope.clone(),
                source_family: family.to_owned(),
                observed_at: TimestampMicros(110 + self.input.evidence.0.len() as i64),
                authority,
                taints: BTreeSet::new(),
                supports: Vec::new(),
            },
        );
        EvidenceCitation {
            evidence_id,
            quote_hash,
        }
    }

    fn add_entity(&mut self, name: &str) -> NodeId {
        let node_id = NodeId::new();
        let node = Node {
            id: node_id,
            workspace_id: self.workspace,
            node_type: NodeType::Entity,
            created_seq: CommitSeq::new(1),
            retired_seq: None,
            identity_state: IdentityState::Canonical,
            primary_scope: self.scope.clone(),
        };
        let head = NodeRevision {
            node_id,
            revision: RevisionNumber::FIRST,
            temporal: BitemporalRange {
                valid_time: time(0, None),
                transaction_time: commits(1, None),
            },
            canonical_name: name.to_owned(),
            attributes: BTreeMap::new(),
            epistemic: accepted_actor_assertion(),
            confidence: confidence(),
            evidence: vec![self.evidence_id],
            envelope: self.input.publication_envelope.clone(),
        };
        self.input.entities.0.insert(
            node_id,
            EntityRecord {
                node,
                head,
                canonical_key: Some(name.to_lowercase()),
                aliases: BTreeSet::from([name.to_owned()]),
                external_keys: BTreeSet::new(),
                sensitive: false,
                active_context: true,
            },
        );
        self.input.authorization.permitted_nodes.insert(node_id);
        node_id
    }

    fn add_predicate(&mut self, key: &str) -> PredicateDefinition {
        let predicate = PredicateDefinition {
            id: PredicateId::new(),
            name: key.to_owned(),
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
        self.input
            .predicate_anchors
            .insert(key.to_owned(), predicate.clone());
        predicate
    }

    fn add_existing_claim(
        &mut self,
        anchor: &str,
        subject: NodeId,
        predicate: &PredicateDefinition,
        value: &str,
        valid_time: TimeRange,
    ) -> ClaimId {
        let claim_id = ClaimId::new();
        let claim = Claim {
            id: claim_id,
            workspace_id: self.workspace,
            subject,
            predicate: predicate.id,
            created_seq: CommitSeq::new(2),
        };
        let head = ClaimRevision {
            claim_id,
            revision: RevisionNumber::FIRST,
            object: ClaimObject::String(value.to_owned()),
            temporal: BitemporalRange {
                valid_time,
                transaction_time: commits(2, None),
            },
            epistemic: accepted_actor_assertion(),
            confidence: confidence(),
            source_families: BTreeSet::from(["conversation:user".to_owned()]),
            evidence: vec![self.evidence_id],
            supersedes: Vec::new(),
            envelope: self.input.publication_envelope.clone(),
        };
        self.input.claims.0.insert(
            claim_id,
            ExistingClaim {
                claim,
                head,
                subject_type: NodeType::Entity,
            },
        );
        self.input.authorization.permitted_claims.insert(claim_id);
        self.input.claim_anchors.insert(anchor.to_owned(), claim_id);
        claim_id
    }
}

fn preference(fixture: &Fixture, local_id: &str) -> CandidateProposal {
    CandidateProposal {
        local_id: local_id.to_owned(),
        mentions: Vec::new(),
        body: ProposalBody::Preference {
            subject_ref: "user".to_owned(),
            domain: "editor".to_owned(),
            value: serde_json::json!("vim"),
            strength: PreferenceStrength::Strong,
        },
        evidence: vec![fixture.citation()],
        temporal: None,
        extraction_confidence: 0.95,
    }
}

fn entity_mention(name: &str) -> EntityMention {
    EntityMention {
        local_ref: "subject".to_owned(),
        surface: name.to_owned(),
        expected_type: NodeType::Entity,
        canonical_key: Some(name.to_lowercase()),
        external_key: None,
        sensitive: false,
    }
}

fn claim_candidate(
    fixture: &Fixture,
    local_id: &str,
    name: &str,
    predicate: &str,
    value: &str,
) -> CandidateProposal {
    CandidateProposal {
        local_id: local_id.to_owned(),
        mentions: vec![entity_mention(name)],
        body: ProposalBody::Claim {
            subject_ref: "subject".to_owned(),
            predicate_ref: predicate.to_owned(),
            object: ProposedValue::String(value.to_owned()),
        },
        evidence: vec![fixture.citation()],
        temporal: None,
        extraction_confidence: 0.95,
    }
}

#[test]
fn strict_json_is_request_bound_and_rejects_unknown_fields() {
    let fixture = Fixture::new();
    let config = CognitionConfig::default();
    let mut value = serde_json::to_value(&fixture.input.proposals).expect("batch serializes");
    value
        .as_object_mut()
        .expect("batch is an object")
        .insert("provider_secret".to_owned(), serde_json::json!(true));
    let bytes = serde_json::to_vec(&value).expect("value serializes");
    assert!(matches!(
        ProposalBatch::from_json(
            &bytes,
            &config,
            &fixture.input.run.id,
            fixture.input.proposals.input_digest,
            fixture.input.proposals.policy_digest,
            None,
        ),
        Err(CognitionError::InvalidJson(_))
    ));

    let mut mismatched = fixture.input.proposals.clone();
    mismatched.input_digest = digest("fabricated input");
    assert_eq!(
        mismatched.validate_contract(
            &config,
            &fixture.input.run.id,
            fixture.input.proposals.input_digest,
            fixture.input.proposals.policy_digest,
            None,
        ),
        Err(CognitionError::InputDigestMismatch)
    );
}

#[test]
fn explicit_preference_promotes_with_typed_memory_and_strict_policy() {
    let mut fixture = Fixture::new();
    fixture.set_candidates(vec![preference(&fixture, "pref-1")]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("adjudication succeeds");
    assert_eq!(output.status, PipelineStatus::SemanticPlan);
    assert_eq!(
        output.decisions[0].disposition,
        CandidateDisposition::Promoted
    );
    let transaction = output.transaction.expect("promotion has a transaction");
    assert!(matches!(
        transaction.candidate_writes.as_slice(),
        [MemoryCandidate {
            validation_state: CandidateValidationState::Promoted { .. },
            ..
        }]
    ));
    assert!(matches!(
        transaction.typed_memory_writes.as_slice(),
        [TypedMemoryMutation::Preference(_)]
    ));
    assert!(transaction.validate().is_ok());
    assert_eq!(
        transaction.typed_memory_writes[0].envelope().ownership,
        fixture.input.publication_envelope.ownership
    );
}

#[test]
fn one_incidental_observation_does_not_fossilise_a_preference() {
    let mut fixture = Fixture::new();
    let record = fixture
        .input
        .evidence
        .0
        .get_mut(&fixture.evidence_id)
        .expect("fixture evidence exists");
    record.authority = EvidenceAuthority::PrimaryObservation;
    record.span.trust = TrustClass::Unknown;
    fixture.set_candidates(vec![preference(&fixture, "pref-weak")]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("adjudication succeeds");
    assert_eq!(
        output.decisions[0].disposition,
        CandidateDisposition::Quarantined
    );
    assert!(
        output.decisions[0]
            .issues
            .contains(&ValidationIssue::PreferenceNeedsExplicitOrIndependentSupport)
    );
    let transaction = output.transaction.expect("safe quarantine is auditable");
    assert!(matches!(
        transaction.candidate_writes.as_slice(),
        [MemoryCandidate {
            validation_state: CandidateValidationState::Quarantined,
            ..
        }]
    ));
    assert!(transaction.typed_memory_writes.is_empty());
    assert!(!transaction.has_semantic_writes());
}

#[test]
fn hallucinated_and_wrong_hash_evidence_are_rejected_before_resolution() {
    let mut fixture = Fixture::new();
    let mut candidate = preference(&fixture, "fake-evidence");
    candidate.evidence[0].quote_hash = digest("model invented this quote");
    fixture.set_candidates(vec![candidate]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("adjudication succeeds");
    let decision = &output.decisions[0];
    assert_eq!(decision.disposition, CandidateDisposition::Rejected);
    assert_eq!(decision.entity_resolution, Vec::new());
    assert!(
        decision
            .issues
            .contains(&ValidationIssue::QuoteHashMismatch)
    );
    assert_eq!(output.metrics.hallucinated_evidence_rejected, 1);
    assert!(output.transaction.is_none());
}

#[test]
fn unauthorized_catalog_entries_have_zero_influence() {
    let mut baseline = Fixture::new();
    baseline.add_predicate("lives_in");
    baseline.set_candidates(vec![claim_candidate(
        &baseline,
        "claim-1",
        "Mikhail",
        "lives_in",
        "Singapore",
    )]);
    let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
    let expected = engine
        .adjudicate(&baseline.input)
        .expect("baseline succeeds");

    let mut poisoned = baseline.clone();
    let forbidden = NodeId::new();
    poisoned.input.entities.0.insert(
        forbidden,
        EntityRecord {
            node: Node {
                id: forbidden,
                workspace_id: poisoned.workspace,
                node_type: NodeType::Entity,
                created_seq: CommitSeq::new(1),
                retired_seq: None,
                identity_state: IdentityState::Canonical,
                primary_scope: poisoned.scope.clone(),
            },
            head: NodeRevision {
                node_id: forbidden,
                revision: RevisionNumber::FIRST,
                temporal: BitemporalRange {
                    valid_time: time(0, None),
                    transaction_time: commits(1, None),
                },
                canonical_name: "Mikhail".to_owned(),
                attributes: BTreeMap::new(),
                epistemic: accepted_actor_assertion(),
                confidence: confidence(),
                evidence: vec![poisoned.evidence_id],
                envelope: poisoned.input.publication_envelope.clone(),
            },
            canonical_key: Some("mikhail".to_owned()),
            aliases: BTreeSet::from(["Mikhail".to_owned()]),
            external_keys: BTreeSet::new(),
            sensitive: true,
            active_context: true,
        },
    );
    let actual = engine
        .adjudicate(&poisoned.input)
        .expect("poisoned snapshot still succeeds");
    assert_eq!(actual, expected);
    assert_eq!(actual.metrics.authorized_entities_examined, 0);
}

#[test]
fn prompt_injection_cannot_create_boundary_authority() {
    let mut fixture = Fixture::new();
    let record = fixture
        .input
        .evidence
        .0
        .get_mut(&fixture.evidence_id)
        .expect("fixture evidence exists");
    record.authority = EvidenceAuthority::ExternalReport;
    record.taints.insert(ContentTaint::PolicyOverrideAttempt);
    let candidate = CandidateProposal {
        local_id: "injected-boundary".to_owned(),
        mentions: Vec::new(),
        body: ProposalBody::Boundary {
            subject_ref: "user".to_owned(),
            rule: BoundaryRule::DoNotRetrieve,
            applies_to: Vec::new(),
        },
        evidence: vec![fixture.citation()],
        temporal: None,
        extraction_confidence: 1.0,
    };
    fixture.set_candidates(vec![candidate]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("adjudication succeeds");
    assert_eq!(
        output.decisions[0].disposition,
        CandidateDisposition::Rejected
    );
    assert!(
        output.decisions[0]
            .issues
            .contains(&ValidationIssue::TaintedInstructionAttempt)
    );
    assert!(output.transaction.is_none());
}

#[test]
fn relationship_emotion_is_rejected_but_explicit_role_is_publishable() {
    let mut fixture = Fixture::new();
    let agent = MemorySubjectId::new();
    fixture
        .input
        .subject_anchors
        .insert("agent".to_owned(), agent);
    let proposal = |local_id: &str, signal| CandidateProposal {
        local_id: local_id.to_owned(),
        mentions: Vec::new(),
        body: ProposalBody::Relationship {
            participant_refs: vec!["user".to_owned(), "agent".to_owned()],
            relationship_kind: RelationshipKind::UserAgent,
            signal,
            roles: BTreeMap::from([
                ("user".to_owned(), "user".to_owned()),
                ("agent".to_owned(), "assistant".to_owned()),
            ]),
            interaction_norms: Vec::new(),
        },
        evidence: vec![fixture.citation()],
        temporal: None,
        extraction_confidence: 0.95,
    };
    fixture.set_candidates(vec![
        proposal("emotion", RelationshipSignal::InferredEmotion),
        proposal("role", RelationshipSignal::ExplicitRole),
    ]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("adjudication succeeds");
    assert_eq!(output.decisions[0].local_id, "emotion");
    assert_eq!(
        output.decisions[0].disposition,
        CandidateDisposition::Rejected
    );
    assert_eq!(
        output.decisions[1].disposition,
        CandidateDisposition::Promoted
    );
    assert!(
        output
            .transaction
            .as_ref()
            .expect("role is promoted")
            .typed_memory_writes
            .iter()
            .any(|item| matches!(item, TypedMemoryMutation::Relationship(_)))
    );
}

#[test]
fn duplicate_transition_contradiction_and_correction_remain_distinct() {
    let mut fixture = Fixture::new();
    let subject = fixture.add_entity("Sessions");
    let predicate = fixture.add_predicate("stored_in");
    let old_claim =
        fixture.add_existing_claim("old-storage", subject, &predicate, "Redis", time(0, None));

    let duplicate = claim_candidate(&fixture, "duplicate", "Sessions", "stored_in", "Redis");
    fixture.set_candidates(vec![duplicate]);
    let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
    let duplicate_output = engine
        .adjudicate(&fixture.input)
        .expect("duplicate succeeds");
    assert_eq!(
        duplicate_output.decisions[0]
            .change
            .as_ref()
            .map(|value| value.classification),
        Some(ChangeClassification::Duplicate)
    );
    assert_eq!(
        duplicate_output.decisions[0].disposition,
        CandidateDisposition::NoOp
    );

    let second = fixture.add_evidence("repository:adapter", EvidenceAuthority::DeterministicSource);
    let mut transition = claim_candidate(
        &fixture,
        "transition",
        "Sessions",
        "stored_in",
        "PostgreSQL",
    );
    transition.evidence.push(second);
    transition.temporal = Some(TemporalProposal {
        valid_from: Some(TimestampMicros(300)),
        valid_to: None,
        change_hint: Some(ChangeHint::TemporalTransition),
    });
    fixture.set_candidates(vec![transition]);
    let transition_output = engine
        .adjudicate(&fixture.input)
        .expect("transition succeeds");
    assert_eq!(
        transition_output.decisions[0]
            .change
            .as_ref()
            .map(|value| value.classification),
        Some(ChangeClassification::TemporalTransition)
    );
    let transaction = transition_output.transaction.expect("transition publishes");
    assert!(transaction.claim_revisions.iter().any(|revision| {
        revision.claim_id == old_claim && revision.epistemic.lifecycle == LifecycleState::Historical
    }));
    assert_eq!(transaction.claim_creates.len(), 1);

    let contradiction = claim_candidate(
        &fixture,
        "contradiction",
        "Sessions",
        "stored_in",
        "PostgreSQL",
    );
    fixture.set_candidates(vec![contradiction]);
    let conflict_output = engine
        .adjudicate(&fixture.input)
        .expect("conflict succeeds");
    assert_eq!(
        conflict_output.decisions[0]
            .change
            .as_ref()
            .map(|value| value.classification),
        Some(ChangeClassification::Contradiction)
    );
    assert_eq!(
        conflict_output
            .transaction
            .as_ref()
            .expect("conflict publishes")
            .conflict_creates
            .len(),
        1
    );

    let correction = CandidateProposal {
        local_id: "correction".to_owned(),
        mentions: vec![entity_mention("Sessions")],
        body: ProposalBody::Correction {
            target_claim_ref: "old-storage".to_owned(),
            replacement_subject_ref: "subject".to_owned(),
            predicate_ref: "stored_in".to_owned(),
            replacement: ProposedValue::String("SQLite".to_owned()),
            reason: "I meant the local test environment".to_owned(),
            was_never_true: true,
        },
        evidence: vec![fixture.citation()],
        temporal: None,
        extraction_confidence: 1.0,
    };
    fixture.set_candidates(vec![correction]);
    let corrected = engine
        .adjudicate(&fixture.input)
        .expect("correction succeeds");
    assert_eq!(
        corrected.decisions[0].disposition,
        CandidateDisposition::Promoted
    );
    let transaction = corrected.transaction.expect("correction publishes");
    assert!(transaction.claim_revisions.iter().any(|revision| {
        revision.claim_id == old_claim && revision.epistemic.lifecycle == LifecycleState::Retracted
    }));
    assert!(matches!(
        transaction.conflict_revisions[0].resolution,
        ConflictResolution::Corrected { .. }
    ));
    assert!(
        transaction
            .node_creates
            .iter()
            .any(|node| node.node_type == NodeType::Correction)
    );
    assert!(
        transaction
            .derived_work
            .iter()
            .any(|work| { matches!(work, DerivedWorkItem::InvalidateSummaries { .. }) })
    );
}

#[test]
fn reflection_is_only_a_supported_hypothesis_and_summary_is_derived() {
    let mut fixture = Fixture::new();
    let owner_node = fixture.add_entity("Project Rift");
    let support_2 = fixture.add_evidence("incident:2", EvidenceAuthority::PrimaryObservation);
    let support_3 = fixture.add_evidence("incident:3", EvidenceAuthority::PrimaryObservation);
    let negative = fixture.add_evidence("counterexample:1", EvidenceAuthority::PrimaryObservation);
    let reflection = CandidateProposal {
        local_id: "reflection".to_owned(),
        mentions: vec![entity_mention("Project Rift")],
        body: ProposalBody::Reflection {
            owner_ref: "subject".to_owned(),
            pattern_kind: PatternKind::RecurringFailure,
            label: "Session invalidation race".to_owned(),
            hypothesis: "Non-atomic invalidation may be a common cause".to_owned(),
            negative_evidence: vec![negative],
            required_verification: vec!["Inspect the transaction boundary".to_owned()],
            proposes_causality: true,
            sensitive_trait: false,
        },
        evidence: vec![fixture.citation(), support_2, support_3],
        temporal: None,
        extraction_confidence: 0.9,
    };
    fixture.set_candidates(vec![reflection]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("reflection succeeds");
    assert_eq!(
        output.decisions[0].disposition,
        CandidateDisposition::Hypothesis
    );
    assert_eq!(output.hypotheses.len(), 1);
    let transaction = output.transaction.expect("hypothesis publishes");
    let reflection_revision = transaction
        .node_revisions
        .iter()
        .find(|revision| revision.node_id == output.hypotheses[0].node_id)
        .expect("reflection revision exists");
    assert_eq!(
        reflection_revision.epistemic.basis,
        EpistemicBasis::Hypothesis
    );
    assert_eq!(
        output.hypotheses[0].negative_evidence,
        vec![negative.evidence_id]
    );
    assert!(output.dirty_regions[0].roots.contains(&owner_node));

    let summary = CandidateProposal {
        local_id: "summary".to_owned(),
        mentions: vec![entity_mention("Project Rift")],
        body: ProposalBody::Summary {
            owner_ref: "subject".to_owned(),
            level: 1,
            content: serde_json::json!({"summary": "Three incidents"}),
            known_omissions: vec!["Root cause is unverified".to_owned()],
        },
        evidence: vec![fixture.citation(), support_2, support_3],
        temporal: None,
        extraction_confidence: 0.9,
    };
    fixture.set_candidates(vec![summary]);
    let summary_output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("summary succeeds");
    assert_eq!(
        summary_output.decisions[0].disposition,
        CandidateDisposition::SummaryReady
    );
    assert_eq!(summary_output.summaries.len(), 1);
    let summary_plan = &summary_output.summaries[0];
    assert!(summary_plan.publication.validate().is_ok());
    assert!(matches!(
        summary_plan.publication.operation,
        MaintenanceOperation::SummaryRevision {
            summary_id,
            revision: 1,
            ..
        } if summary_id == summary_plan.id
    ));
    assert!(
        !summary_output
            .transaction
            .expect("candidate audit is committed")
            .has_semantic_writes()
    );
}

#[test]
fn self_reference_and_derived_only_evidence_are_rejected() {
    let mut fixture = Fixture::new();
    fixture.set_candidates(vec![preference(&fixture, "self")]);
    let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
    let first = engine
        .adjudicate(&fixture.input)
        .expect("first run succeeds");
    let candidate_id = first.decisions[0].candidate_id;
    let record = fixture
        .input
        .evidence
        .0
        .get_mut(&fixture.evidence_id)
        .expect("evidence exists");
    record.authority = EvidenceAuthority::SummaryDerived {
        summary_id: SummaryId::new(),
    };
    record.span.derivation = Some(DerivationRef {
        id: DerivationId::new(),
        kind: DerivationKind::Consolidation,
        actor: None,
        model_call: None,
        pipeline: pipeline_identity(),
        inputs: vec![LineageNode::Candidate { id: candidate_id }],
    });
    fixture.set_candidates(vec![preference(&fixture, "self")]);
    let output = engine
        .adjudicate(&fixture.input)
        .expect("run is safely rejected");
    assert_eq!(
        output.decisions[0].disposition,
        CandidateDisposition::Rejected
    );
    assert!(
        output.decisions[0]
            .issues
            .contains(&ValidationIssue::SelfSupportingLineage)
    );
    assert!(output.transaction.is_none());
}

#[test]
fn shadow_reprocessing_never_publishes_and_replay_is_byte_deterministic() {
    let mut fixture = Fixture::new();
    fixture.set_candidates(vec![preference(&fixture, "pref")]);
    let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
    let first = engine
        .adjudicate(&fixture.input)
        .expect("initial run succeeds");
    let replay = engine.adjudicate(&fixture.input).expect("replay succeeds");
    assert_eq!(
        serde_json::to_vec(&first).expect("output serializes"),
        serde_json::to_vec(&replay).expect("output serializes")
    );
    assert_eq!(
        first.logical_digest().expect("digest"),
        replay.logical_digest().expect("digest")
    );

    fixture.input.run.id = "run-v2-shadow".to_owned();
    fixture.input.run.mode = ProcessingMode::Shadow {
        previous_run: "run-v1".to_owned(),
    };
    fixture.set_candidates(vec![preference(&fixture, "pref")]);
    let shadow = engine.adjudicate(&fixture.input).expect("shadow succeeds");
    assert_eq!(shadow.status, PipelineStatus::Shadow);
    assert!(shadow.transaction.is_none());
    assert_eq!(
        shadow.decisions[0].disposition,
        CandidateDisposition::ShadowValidated
    );
    let diff = ReprocessingDiff::between(&first, &shadow);
    assert_eq!(diff.previous_run, "run-v1");
    assert_eq!(diff.new_run, "run-v2-shadow");
}

#[test]
fn deterministic_post_turn_baseline_prefers_noop_and_extracts_explicit_signals() {
    let fixture = Fixture::new();
    let extractor =
        DeterministicPostTurnExtractor::new(CognitionConfig::default()).expect("config valid");
    let input = |text: &str| PostTurnInput {
        processing_run: fixture.input.run.id.clone(),
        input_digest: fixture.input.proposals.input_digest,
        policy_digest: fixture.input.proposals.policy_digest,
        speaker: TurnSpeaker::User,
        speaker_subject_ref: "user".to_owned(),
        text: text.to_owned(),
        evidence_id: fixture.evidence_id,
        quote_hash: fixture.quote_hash,
        structured: Vec::new(),
    };
    assert!(
        extractor
            .extract(&input("Привет!"))
            .expect("greeting parses")
            .candidates
            .is_empty()
    );
    let preference = extractor
        .extract(&input("Я предпочитаю тёмную тему"))
        .expect("preference parses");
    assert!(matches!(
        preference.candidates[0].body,
        ProposalBody::Preference { .. }
    ));
    let boundary = extractor
        .extract(&input("Не упоминай этот разговор"))
        .expect("boundary parses");
    assert!(matches!(
        boundary.candidates[0].body,
        ProposalBody::Boundary {
            rule: BoundaryRule::DoNotMention,
            ..
        }
    ));
    let goal = extractor
        .extract(&input("Моя цель — выпустить v1"))
        .expect("goal parses");
    assert!(matches!(
        &goal.candidates[0].body,
        ProposalBody::Goal { statement, .. } if statement == "выпустить v1"
    ));
}

#[test]
fn reference_evaluator_measures_noop_correction_and_fake_evidence() {
    let mut fixture = Fixture::new();
    let mut fake = preference(&fixture, "fake");
    fake.evidence[0].quote_hash = digest("wrong");
    fixture.set_candidates(vec![fake]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("adjudication succeeds");
    let labels = vec![DecisionLabel {
        local_id: "fake".to_owned(),
        kind: ProposalKind::Preference,
        expected: ExpectedDisposition::Reject,
        hallucinated_evidence: true,
        entity_resolution: BTreeMap::new(),
    }];
    let report = ReferenceEvaluator::evaluate(&[EvaluationCase {
        case_id: "fake-evidence",
        output: &output,
        labels: &labels,
        expected_pipeline_noop: true,
    }]);
    assert_eq!(report.hallucinated_evidence_rejection, 1.0);
    assert_eq!(report.no_op_precision, 1.0);
    assert_eq!(report.false_preference_rate, 0.0);
    assert!(
        !report.meets(QualityThresholds::default()),
        "a tiny fixture must not vacuously satisfy release thresholds"
    );
}

#[test]
fn recorded_model_replay_recreates_the_exact_canonical_plan() {
    let mut fixture = Fixture::new();
    fixture.input.run.model_call = Some(ModelCall {
        id: ModelCallId::new(),
        purpose: "extraction".to_owned(),
        provider: "provider-neutral-test".to_owned(),
        model: "recorded-model".to_owned(),
        model_revision: Some("fixture-v1".to_owned()),
        prompt_version: "extract/v1".to_owned(),
        schema_version: "1".to_owned(),
        input_hash: digest("placeholder"),
        output_hash: digest("placeholder"),
        input_tokens: Some(20),
        output_tokens: Some(10),
        latency_micros: 100,
        external_processing_allowed: false,
    });
    fixture.set_candidates(vec![preference(&fixture, "recorded-preference")]);
    let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
    let live = engine
        .adjudicate(&fixture.input)
        .expect("validated live output adjudicates");

    fixture.input.run.mode = ProcessingMode::Replay {
        original_run: fixture.input.run.id.clone(),
    };
    let call_id = fixture
        .input
        .run
        .model_call_id()
        .expect("fixture has a model call");
    fixture.input.proposals.origin = ProposalOrigin::RecordedModel { call_id };
    let output_hash = fixture
        .input
        .proposals
        .canonical_digest()
        .expect("recorded proposal serializes");
    fixture
        .input
        .run
        .model_call
        .as_mut()
        .expect("fixture has a model call")
        .output_hash = output_hash;
    let replay = engine
        .adjudicate(&fixture.input)
        .expect("recorded replay adjudicates");

    assert_eq!(replay, live);
    assert_eq!(
        replay.logical_digest().expect("replay digest"),
        live.logical_digest().expect("live digest")
    );
}

#[test]
fn validated_model_output_is_digest_bound_and_has_no_commit_capability() {
    let mut fixture = Fixture::new();
    fixture.input.run.model_call = Some(ModelCall {
        id: ModelCallId::new(),
        purpose: "extraction".to_owned(),
        provider: "provider-neutral-test".to_owned(),
        model: "recorded-model".to_owned(),
        model_revision: Some("2026-08-12".to_owned()),
        prompt_version: "extract/v1".to_owned(),
        schema_version: "1".to_owned(),
        input_hash: digest("placeholder"),
        output_hash: digest("placeholder"),
        input_tokens: Some(20),
        output_tokens: Some(10),
        latency_micros: 100,
        external_processing_allowed: false,
    });
    fixture.set_candidates(vec![preference(&fixture, "model-preference")]);
    let bytes = serde_json::to_vec(&fixture.input.proposals).expect("batch serializes");
    let parsed = ProposalBatch::from_json(
        &bytes,
        &CognitionConfig::default(),
        &fixture.input.run.id,
        fixture.input.proposals.input_digest,
        fixture.input.proposals.policy_digest,
        fixture.input.run.model_call_id(),
    )
    .expect("strict output validates");
    assert_eq!(parsed, fixture.input.proposals);

    let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
    let output = engine
        .adjudicate(&fixture.input)
        .expect("model proposal adjudicates");
    let transaction = output
        .transaction
        .expect("deterministic layer planned a transaction");
    assert!(transaction.validate().is_ok());
    assert_eq!(
        transaction.candidate_writes[0].model_call,
        fixture.input.run.model_call_id()
    );

    let call = fixture
        .input
        .run
        .model_call
        .as_mut()
        .expect("model call exists");
    call.output_hash = digest("tampered validated output");
    assert_eq!(
        engine.adjudicate(&fixture.input),
        Err(CognitionError::ModelCallMismatch)
    );
}

#[test]
fn external_model_route_and_policy_broadening_fail_closed() {
    let mut fixture = Fixture::new();
    fixture.input.run.model_call = Some(ModelCall {
        id: ModelCallId::new(),
        purpose: "extraction".to_owned(),
        provider: "external".to_owned(),
        model: "model".to_owned(),
        model_revision: None,
        prompt_version: "extract/v1".to_owned(),
        schema_version: "1".to_owned(),
        input_hash: digest("placeholder"),
        output_hash: digest("placeholder"),
        input_tokens: None,
        output_tokens: None,
        latency_micros: 1,
        external_processing_allowed: true,
    });
    fixture.set_candidates(vec![preference(&fixture, "external")]);
    let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
    assert_eq!(
        engine.adjudicate(&fixture.input),
        Err(CognitionError::ModelCallMismatch)
    );

    fixture.input.run.model_call = None;
    fixture.input.publication_envelope.ownership.audience_grants[0].audience = Audience::Public;
    fixture.set_candidates(vec![preference(&fixture, "broader")]);
    let rejected = engine
        .adjudicate(&fixture.input)
        .expect("policy violation becomes a candidate rejection");
    assert_eq!(
        rejected.decisions[0].disposition,
        CandidateDisposition::Rejected
    );
    assert!(
        rejected.decisions[0]
            .issues
            .contains(&ValidationIssue::PolicyWouldBroaden)
    );
    assert!(rejected.transaction.is_none());
}

#[test]
fn exact_entity_resolution_and_candidate_order_are_deterministic() {
    let mut fixture = Fixture::new();
    let entity = fixture.add_entity("ContextDB");
    fixture.add_predicate("language");
    let first = claim_candidate(&fixture, "b", "ContextDB", "language", "Rust");
    let mut second = preference(&fixture, "a");
    second.body = ProposalBody::Goal {
        owner_ref: "user".to_owned(),
        statement: "Ship v1".to_owned(),
        status: GoalStatus::Active,
        horizon: GoalHorizon::LongTerm,
    };
    fixture.set_candidates(vec![first.clone(), second.clone()]);
    let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
    let left = engine.adjudicate(&fixture.input).expect("left succeeds");
    fixture.set_candidates(vec![second, first]);
    let right = engine.adjudicate(&fixture.input).expect("right succeeds");
    assert_eq!(left, right);
    let claim = left
        .decisions
        .iter()
        .find(|decision| decision.local_id == "b")
        .expect("claim decision exists");
    assert!(matches!(
        claim.entity_resolution[0].result,
        EntityResolution::Existing { node_id, .. } if node_id == entity
    ));
    assert!(
        !left
            .transaction
            .expect("semantic transaction exists")
            .node_creates
            .iter()
            .any(|node| node.id == entity)
    );
}

#[test]
fn refinement_revises_the_claim_without_inventing_a_conflict() {
    let mut fixture = Fixture::new();
    let subject = fixture.add_entity("Backend");
    let predicate = fixture.add_predicate("language");
    let existing =
        fixture.add_existing_claim("backend-language", subject, &predicate, "Go", time(0, None));
    fixture.set_candidates(vec![claim_candidate(
        &fixture, "refine", "Backend", "language", "Go 1.26",
    )]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("refinement succeeds");
    assert_eq!(
        output.decisions[0]
            .change
            .as_ref()
            .map(|value| value.classification),
        Some(ChangeClassification::Refinement)
    );
    let transaction = output.transaction.expect("refinement publishes");
    assert_eq!(transaction.claim_creates.len(), 0);
    assert_eq!(transaction.conflict_creates.len(), 0);
    assert!(transaction.claim_revisions.iter().any(|revision| {
        revision.claim_id == existing
            && revision.object == ClaimObject::String("Go 1.26".to_owned())
    }));
}

#[test]
fn repeated_mirror_sources_do_not_fake_corroboration() {
    let mut fixture = Fixture::new();
    fixture
        .input
        .evidence
        .0
        .get_mut(&fixture.evidence_id)
        .expect("evidence exists")
        .authority = EvidenceAuthority::PrimaryObservation;
    let mirror = fixture.add_evidence("conversation:user", EvidenceAuthority::PrimaryObservation);
    let mut proposal = preference(&fixture, "mirrored");
    proposal.evidence.push(mirror);
    fixture.set_candidates(vec![proposal]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("adjudication succeeds");
    assert_eq!(output.decisions[0].promotion.corroboration, 0.35);
    assert_eq!(
        output.decisions[0].disposition,
        CandidateDisposition::Quarantined
    );
}

#[test]
fn hallucinated_negative_example_cannot_enter_reflection_lineage() {
    let mut fixture = Fixture::new();
    fixture.add_entity("System");
    let support_2 = fixture.add_evidence("support:2", EvidenceAuthority::PrimaryObservation);
    let support_3 = fixture.add_evidence("support:3", EvidenceAuthority::PrimaryObservation);
    let reflection = CandidateProposal {
        local_id: "bad-negative".to_owned(),
        mentions: vec![entity_mention("System")],
        body: ProposalBody::Reflection {
            owner_ref: "subject".to_owned(),
            pattern_kind: PatternKind::RecurringFailure,
            label: "Pattern".to_owned(),
            hypothesis: "A bounded hypothesis".to_owned(),
            negative_evidence: vec![EvidenceCitation {
                evidence_id: EvidenceId::new(),
                quote_hash: digest("fake"),
            }],
            required_verification: vec!["Verify".to_owned()],
            proposes_causality: false,
            sensitive_trait: false,
        },
        evidence: vec![fixture.citation(), support_2, support_3],
        temporal: None,
        extraction_confidence: 0.9,
    };
    fixture.set_candidates(vec![reflection]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("candidate is rejected safely");
    assert_eq!(
        output.decisions[0].disposition,
        CandidateDisposition::Rejected
    );
    assert!(
        output.decisions[0]
            .issues
            .contains(&ValidationIssue::UnauthorizedEvidence)
    );
    assert!(output.hypotheses.is_empty());
}

#[test]
fn dirty_region_invalidates_current_summary_without_deleting_history() {
    let mut fixture = Fixture::new();
    let owner = fixture.add_entity("Project");
    let support_2 = fixture.add_evidence("summary:2", EvidenceAuthority::PrimaryObservation);
    let support_3 = fixture.add_evidence("summary:3", EvidenceAuthority::PrimaryObservation);
    let summary = CandidateProposal {
        local_id: "summary-stale".to_owned(),
        mentions: vec![entity_mention("Project")],
        body: ProposalBody::Summary {
            owner_ref: "subject".to_owned(),
            level: 1,
            content: serde_json::json!({"summary": "Current state"}),
            known_omissions: Vec::new(),
        },
        evidence: vec![fixture.citation(), support_2, support_3],
        temporal: None,
        extraction_confidence: 0.9,
    };
    fixture.set_candidates(vec![summary]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("summary validates");
    let summary = output.summaries[0].clone();
    let mut catalog = SummaryCatalog(BTreeMap::from([(summary.id, summary)]));
    let region = DirtyRegion {
        based_on: fixture.input.base_snapshot,
        roots: BTreeSet::from([owner]),
        claims: BTreeSet::new(),
        reasons: BTreeSet::from([DirtyReason::NodeChanged]),
    };
    let invalidated = catalog.invalidate(
        &region,
        SnapshotRef {
            commit_seq: CommitSeq::new(11),
        },
    );
    assert_eq!(invalidated.len(), 1);
    assert_eq!(catalog.0.len(), 1);
    assert_eq!(catalog.current().count(), 0);
}

#[test]
fn empty_post_turn_is_a_measured_noop_without_a_transaction() {
    let fixture = Fixture::new();
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("empty batch succeeds");
    assert_eq!(output.status, PipelineStatus::NoOp);
    assert_eq!(output.metrics.no_op, 1);
    assert!(output.transaction.is_none());
}

#[test]
fn scoped_coexistence_and_independent_evidence_do_not_become_conflicts() {
    let mut fixture = Fixture::new();
    let subject = fixture.add_entity("Runtime");
    let predicate = fixture.add_predicate("backend");
    let existing = fixture.add_existing_claim(
        "runtime-backend",
        subject,
        &predicate,
        "SQLite",
        time(0, None),
    );

    let mut other_scope_envelope = fixture.input.publication_envelope.clone();
    other_scope_envelope.scopes = NonEmptyVec::new(ScopeRef {
        kind: ScopeKind::Project,
        id: ScopeId::new(),
        inheritance: ScopeInheritance::Exact,
    });
    let scoped = classify_change(
        subject,
        &predicate,
        &ClaimObject::String("PostgreSQL".to_owned()),
        time(0, None),
        false,
        &other_scope_envelope,
        &fixture.input.claims,
        &fixture.input.authorization,
    );
    assert_eq!(scoped.compared_claim, Some(existing));
    assert_eq!(
        scoped.classification,
        ChangeClassification::ScopedCoexistence
    );

    let mut multi_valued = predicate;
    multi_valued.cardinality = Cardinality::Set;
    let independent = classify_change(
        subject,
        &multi_valued,
        &ClaimObject::String("PostgreSQL".to_owned()),
        time(0, None),
        false,
        &fixture.input.publication_envelope,
        &fixture.input.claims,
        &fixture.input.authorization,
    );
    assert_eq!(
        independent.classification,
        ChangeClassification::IndependentEvidence
    );
}

#[test]
fn explicit_goals_and_commitments_publish_typed_memory_only_after_adjudication() {
    let mut fixture = Fixture::new();
    let goal = CandidateProposal {
        local_id: "goal".to_owned(),
        mentions: Vec::new(),
        body: ProposalBody::Goal {
            owner_ref: "user".to_owned(),
            statement: "Ship ContextDB v1".to_owned(),
            status: GoalStatus::Active,
            horizon: GoalHorizon::LongTerm,
        },
        evidence: vec![fixture.citation()],
        temporal: None,
        extraction_confidence: 1.0,
    };
    let commitment = CandidateProposal {
        local_id: "commitment".to_owned(),
        mentions: Vec::new(),
        body: ProposalBody::Commitment {
            owner_ref: "user".to_owned(),
            beneficiary_ref: None,
            statement: "Review the release evidence".to_owned(),
            due: None,
            trigger: None,
            status: CommitmentStatus::Active,
        },
        evidence: vec![fixture.citation()],
        temporal: None,
        extraction_confidence: 1.0,
    };
    fixture.set_candidates(vec![goal, commitment]);
    let output = CognitionEngine::new(CognitionConfig::default())
        .expect("config valid")
        .adjudicate(&fixture.input)
        .expect("explicit memories adjudicate");
    let transaction = output.transaction.expect("typed memories publish");
    assert!(transaction.validate().is_ok());
    assert!(
        transaction
            .typed_memory_writes
            .iter()
            .any(|write| matches!(write, TypedMemoryMutation::Goal(_)))
    );
    assert!(
        transaction
            .typed_memory_writes
            .iter()
            .any(|write| matches!(write, TypedMemoryMutation::Commitment(_)))
    );
}

#[test]
fn invalid_threshold_configuration_fails_before_processing() {
    let config = CognitionConfig {
        auto_link_threshold: f32::NAN,
        ..CognitionConfig::default()
    };
    assert!(matches!(
        CognitionEngine::new(config),
        Err(CognitionError::InvalidProposal {
            field: "config.entity_thresholds",
            ..
        })
    ));

    let config = CognitionConfig {
        min_reflection_support: 0,
        ..CognitionConfig::default()
    };
    assert!(matches!(
        CognitionEngine::new(config),
        Err(CognitionError::InvalidProposal {
            field: "config.limit",
            ..
        })
    ));
}

proptest! {
    #[test]
    fn unauthorized_entities_never_change_output(extra in 0_usize..32) {
        let mut fixture = Fixture::new();
        fixture.add_predicate("uses");
        fixture.set_candidates(vec![claim_candidate(
            &fixture,
            "claim",
            "ContextDB",
            "uses",
            "Rust",
        )]);
        let engine = CognitionEngine::new(CognitionConfig::default()).expect("config valid");
        let baseline = engine.adjudicate(&fixture.input).expect("baseline succeeds");
        for ordinal in 0..extra {
            let node_id = NodeId::new();
            fixture.input.entities.0.insert(node_id, EntityRecord {
                node: Node {
                    id: node_id,
                    workspace_id: fixture.workspace,
                    node_type: NodeType::Entity,
                    created_seq: CommitSeq::new(1),
                    retired_seq: None,
                    identity_state: IdentityState::Canonical,
                    primary_scope: fixture.scope.clone(),
                },
                head: NodeRevision {
                    node_id,
                    revision: RevisionNumber::FIRST,
                    temporal: BitemporalRange {
                        valid_time: time(0, None),
                        transaction_time: commits(1, None),
                    },
                    canonical_name: format!("ContextDB-{ordinal}"),
                    attributes: BTreeMap::new(),
                    epistemic: accepted_actor_assertion(),
                    confidence: confidence(),
                    evidence: vec![fixture.evidence_id],
                    envelope: fixture.input.publication_envelope.clone(),
                },
                canonical_key: Some("contextdb".to_owned()),
                aliases: BTreeSet::from(["ContextDB".to_owned()]),
                external_keys: BTreeSet::new(),
                sensitive: false,
                active_context: true,
            });
        }
        let with_forbidden = engine.adjudicate(&fixture.input).expect("forbidden data is ignored");
        prop_assert_eq!(with_forbidden, baseline);
    }
}
