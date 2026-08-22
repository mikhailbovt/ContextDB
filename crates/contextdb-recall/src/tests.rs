use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    ActivatedNode, ActiveReferent, ActorId, AgentId, CommitRange, CommitSeq, ConversationMode,
    CueBundle, EvidencePolicy, FacetRequirement, MemorySubjectId, NodeId, NonEmptyVec,
    PolicyDecision, PolicyId, Purpose, QueryContent, RecallBudgets, RecallIntent, RecallRequest,
    ScopeId, ScopeInheritance, ScopeKind, ScopeRef, TemporalConstraint, TemporalContext, TimeRange,
    TimestampMicros,
};
use proptest::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

use contextdb_reference::{
    AccessLabel as ReferenceAccessLabel, Consent as ReferenceConsent, ContextDb, Lifecycle,
    LogicalRecord, Mutation, RecordKind, SemanticLinks, SemanticTransaction,
    Sensitivity as ReferenceSensitivity, ValidTime,
};

use crate::{
    AccessConsent, AccessRule, AuthorizedCorpus, DeterministicRecallRequest, DocumentId,
    DocumentPerspective, DocumentTemporalState, DocumentUseProfile, GateReason, MemoryUseDecision,
    ProviderDocument, ProviderEvidence, ProviderRelation, ProviderRequest, ProviderSnapshot,
    RecallConflictState, RecallDocument, RecallDocumentKind, RecallEngine, RecallError,
    RecallLimits, RecallMode, RecallProvider, RecallRelation, RecallRelationKind, RecallRoute,
    RecallSensitivity, RecallStatus, RecallWatermarks, ReferenceProvider, Result, StopReason,
    SuppliedVector,
};

const AGENT: &str = "00000000-0000-0000-0000-000000000001";
const ACTOR: &str = "00000000-0000-0000-0000-000000000002";
const ALICE: &str = "00000000-0000-0000-0000-000000000003";
const BOB: &str = "00000000-0000-0000-0000-000000000004";
const SCOPE: &str = "00000000-0000-0000-0000-000000000005";
const POLICY: &str = "00000000-0000-0000-0000-000000000006";
const BAR_NODE: &str = "00000000-0000-0000-0000-000000000007";
const WORKSPACE: &str = "workspace-japan";

#[derive(Clone)]
struct FixtureProvider {
    snapshot: ProviderSnapshot,
    documents: Vec<ProviderDocument>,
    relations: Vec<ProviderRelation>,
}

struct FailingProvider;

impl RecallProvider for FailingProvider {
    fn snapshot(&self, _at_commit: Option<u64>) -> Result<ProviderSnapshot> {
        Err(RecallError::Provider(
            "memory gate must prevent this snapshot call".to_owned(),
        ))
    }

    fn authorized_corpus(&self, _request: &ProviderRequest) -> Result<AuthorizedCorpus> {
        Err(RecallError::Provider(
            "memory gate must prevent this authorization call".to_owned(),
        ))
    }
}

impl FixtureProvider {
    fn new(documents: Vec<ProviderDocument>) -> Self {
        Self {
            snapshot: snapshot(10),
            documents,
            relations: Vec::new(),
        }
    }

    fn with_relations(mut self, relations: Vec<ProviderRelation>) -> Self {
        self.relations = relations;
        self
    }
}

impl RecallProvider for FixtureProvider {
    fn snapshot(&self, at_commit: Option<u64>) -> Result<ProviderSnapshot> {
        let mut snapshot = self.snapshot.clone();
        if let Some(commit) = at_commit {
            if commit > snapshot.commit_seq {
                return Err(RecallError::Provider(
                    "fixture snapshot is not retained".to_owned(),
                ));
            }
            snapshot.commit_seq = commit;
            snapshot.watermarks.journal = snapshot.watermarks.journal.min(commit);
            snapshot.watermarks.semantic = snapshot.watermarks.semantic.min(commit);
            snapshot.watermarks.lexical = snapshot.watermarks.lexical.min(commit);
            snapshot.watermarks.graph = snapshot.watermarks.graph.min(commit);
            for value in snapshot.watermarks.vector.values_mut() {
                *value = (*value).min(commit);
            }
        }
        Ok(snapshot)
    }

    fn authorized_corpus(&self, request: &ProviderRequest) -> Result<AuthorizedCorpus> {
        AuthorizedCorpus::authorize(request, self.documents.clone(), self.relations.clone())
    }
}

#[derive(Debug, Deserialize)]
struct JapanFixture {
    query: String,
    active_surface: String,
    recommendation_text: String,
    expected_document: String,
}

fn japan_fixture() -> JapanFixture {
    serde_json::from_str(include_str!("../tests/fixtures/japan_bar.json"))
        .expect("test fixture must be valid")
}

fn snapshot(commit_seq: u64) -> ProviderSnapshot {
    ProviderSnapshot {
        database_id: "fixture-db".to_owned(),
        commit_seq,
        watermarks: RecallWatermarks {
            journal: commit_seq,
            semantic: commit_seq,
            lexical: commit_seq,
            vector: BTreeMap::from([("fixture-vector".to_owned(), commit_seq)]),
            graph: commit_seq,
            hierarchy: BTreeMap::new(),
        },
    }
}

fn scope() -> ScopeRef {
    ScopeRef {
        kind: ScopeKind::Project,
        id: SCOPE
            .parse::<ScopeId>()
            .expect("test fixture must be valid"),
        inheritance: ScopeInheritance::Exact,
    }
}

fn principal(subject: &str) -> crate::RecallPrincipal {
    crate::RecallPrincipal {
        subject: subject.to_owned(),
        audiences: BTreeSet::new(),
        workspace: WORKSPACE.to_owned(),
        scopes: BTreeSet::from([SCOPE.to_owned()]),
        purpose: "conversation".to_owned(),
        clearance: RecallSensitivity::Restricted,
    }
}

fn access(owner: &str) -> AccessRule {
    AccessRule {
        workspace: WORKSPACE.to_owned(),
        scopes: BTreeSet::from([SCOPE.to_owned()]),
        owners: BTreeSet::from([owner.to_owned()]),
        audience_purpose_grants: BTreeMap::from([(
            "@owner".to_owned(),
            BTreeSet::from(["conversation".to_owned()]),
        )]),
        sensitivity: RecallSensitivity::Confidential,
        required_compartments: BTreeSet::new(),
        consent: AccessConsent::Granted,
        retrievable: true,
    }
}

fn request(
    query: &str,
    subject: &str,
    mode: RecallMode,
    intent: RecallIntent,
    required_facet: Option<&str>,
) -> DeterministicRecallRequest {
    let node = BAR_NODE
        .parse::<NodeId>()
        .expect("test fixture must be valid");
    let subject_id = subject
        .parse::<MemorySubjectId>()
        .expect("test fixture must be valid");
    DeterministicRecallRequest {
        request: RecallRequest {
            agent_id: AGENT
                .parse::<AgentId>()
                .expect("test fixture must be valid"),
            actor_id: ACTOR
                .parse::<ActorId>()
                .expect("test fixture must be valid"),
            session_id: None,
            cues: CueBundle {
                current_input: QueryContent::Text(query.to_owned()),
                recent_observations: Vec::new(),
                participants: NonEmptyVec::new(subject_id),
                active_referents: vec![ActiveReferent {
                    surface: "бар в Японии".to_owned(),
                    candidates: NonEmptyVec::new(ActivatedNode {
                        node_id: node,
                        activation: 1.0,
                    }),
                    resolved: Some(node),
                }],
                active_topics: vec![node],
                temporal_context: TemporalContext {
                    now: TimestampMicros(500),
                    referenced_valid_time: None,
                    known_at: None,
                },
                location_context: None,
                conversation_mode: ConversationMode::Planning,
                goal: None,
                interaction_signals: Vec::new(),
            },
            intent,
            scopes: NonEmptyVec::new(scope()),
            temporal: TemporalConstraint::Current,
            required_facets: required_facet
                .map(|name| FacetRequirement {
                    name: name.to_owned(),
                    required: true,
                    minimum_confidence: 0.5,
                })
                .into_iter()
                .collect(),
            budgets: RecallBudgets {
                max_tokens: 256,
                max_latency_micros: 5_000_000,
                max_candidates: 128,
                max_graph_visits: 64,
                max_evidence_items: 16,
            },
            evidence_policy: EvidencePolicy {
                require_primary_evidence: true,
                include_quotes: true,
                permit_derived_only: false,
            },
            memory_use_policy: POLICY
                .parse::<PolicyId>()
                .expect("test fixture must be valid"),
            purpose: Purpose::Conversation,
            target_model: None,
        },
        principal: principal(subject),
        mode,
        limits: RecallLimits {
            max_nodes_examined: 128,
            max_seed_candidates: 32,
            max_graph_hops: 3,
            max_frontier_per_hop: 16,
            max_evidence_units: 16,
            max_context_tokens: 256,
            deadline_micros: 5_000_000,
        },
        query_vector: None,
        continuation: None,
    }
}

fn document(
    id: &str,
    kind: RecallDocumentKind,
    text: &str,
    facet: &str,
    subject: &str,
) -> RecallDocument {
    RecallDocument {
        id: DocumentId::new(id).expect("test fixture must be valid"),
        kind,
        canonical_name: None,
        aliases: Vec::new(),
        text: text.to_owned(),
        facets: BTreeSet::from([facet.to_owned()]),
        subjects: BTreeSet::from([subject.to_owned()]),
        participants: BTreeSet::from([subject.to_owned()]),
        active_keys: BTreeSet::from([BAR_NODE.to_owned()]),
        temporal: DocumentTemporalState {
            valid_time: None,
            transaction_time: CommitRange::current(CommitSeq::GENESIS),
        },
        perspective: DocumentPerspective {
            knower: Some(subject.to_owned()),
            narrator: Some(ACTOR.to_owned()),
            role: "experiencer".to_owned(),
        },
        conflict: RecallConflictState::None,
        evidence: vec![crate::RecallEvidence {
            id: format!("evidence:{id}"),
            source_observation: Some(format!("observation:{id}")),
            excerpt: Some(text.to_owned()),
            primary: true,
            trust: 1.0,
            estimated_tokens: 3,
        }],
        vector: None,
        source_trust: 1.0,
        importance: 1.0,
        estimated_tokens: 12,
        use_profile: DocumentUseProfile {
            influence: PolicyDecision::Allow,
            mention: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Allow,
            shared_with_principal: true,
            personal_detail: false,
            constraint_only: false,
            style_only: false,
        },
    }
}

fn labelled(mut document: RecallDocument) -> ProviderDocument {
    let record_access = access(ALICE);
    let evidence = std::mem::take(&mut document.evidence)
        .into_iter()
        .map(|evidence| ProviderEvidence {
            access: record_access.clone(),
            evidence,
        })
        .collect();
    ProviderDocument {
        access: record_access,
        document,
        evidence,
    }
}

fn relation(id: &str, source: &str, target: &str) -> ProviderRelation {
    ProviderRelation {
        access: access(ALICE),
        relation: RecallRelation {
            id: id.to_owned(),
            source: DocumentId::new(source).expect("test fixture must be valid"),
            target: DocumentId::new(target).expect("test fixture must be valid"),
            kind: RecallRelationKind::Supports,
            weight: 1.0,
            valid_time: None,
            trust: 1.0,
        },
    }
}

#[test]
fn implicit_japan_bar_recall_matches_deterministic_golden() {
    let fixture = japan_fixture();
    let mut recommendation = document(
        &fixture.expected_document,
        RecallDocumentKind::Claim,
        &fixture.recommendation_text,
        "recommendation",
        ALICE,
    );
    recommendation.canonical_name = Some("решение по бару".to_owned());
    let mut background = document(
        "entity:japan-bar",
        RecallDocumentKind::Entity,
        "План бара в Японии",
        "venture",
        ALICE,
    );
    background.canonical_name = Some(fixture.active_surface);
    background.source_trust = 0.1;
    background.importance = 0.1;
    let provider = FixtureProvider::new(vec![labelled(background), labelled(recommendation)]);
    let request = request(
        &fixture.query,
        ALICE,
        RecallMode::ImplicitContinuity,
        RecallIntent::Continuity,
        Some("recommendation"),
    );

    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    assert_eq!(result.status, RecallStatus::Complete);
    assert_eq!(result.stop_reason, StopReason::Sufficient);
    assert!(result.gate.reasons.contains(&GateReason::VagueReference));
    assert!(result.gate.reasons.contains(&GateReason::ActiveReferent));
    assert_eq!(
        result.items[0].document_id.as_str(),
        fixture.expected_document
    );
    let encoded = serde_json::to_string(&result).expect("recall result must serialize");
    let decoded: crate::DeterministicRecallResult =
        serde_json::from_str(&encoded).expect("recall result must deserialize");
    assert_eq!(decoded, result);

    let projection = json!({
        "status": result.status,
        "stop_reason": result.stop_reason,
        "items": result.items.iter().map(|item| json!({
            "id": item.document_id,
            "use": item.use_decision,
            "score": item.score.final_micros,
            "routes": item.score.routes.iter().map(|route| route.route).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "covered_facets": result.sufficiency.covered_facets,
        "missing_facets": result.sufficiency.missing_facets,
        "evidence_ids": result.evidence.iter().map(|item| item.evidence.id.clone()).collect::<Vec<_>>(),
        "usage": result.usage,
    });
    let golden: Value =
        serde_json::from_str(include_str!("../tests/fixtures/japan_bar_golden.json"))
            .expect("test fixture must be valid");
    assert_eq!(projection, golden);
}

#[test]
fn memory_gate_runs_before_snapshot_or_authorization() {
    let request = request(
        "self contained question",
        ALICE,
        RecallMode::Never,
        RecallIntent::CurrentTruth,
        None,
    );
    let result = RecallEngine::new([7; 32])
        .recall(&FailingProvider, &request)
        .expect("mode never must skip all provider access");
    assert_eq!(result.status, RecallStatus::Skipped);
    assert_eq!(result.stop_reason, StopReason::GateSkipped);
    assert!(result.snapshot.is_none());
}

#[test]
fn wrong_person_memory_is_not_a_candidate() {
    let wrong = labelled(document(
        "claim:bob-japan-bar",
        RecallDocumentKind::Claim,
        "Бобу стоит открывать бар",
        "recommendation",
        BOB,
    ));
    let provider = FixtureProvider::new(vec![wrong]);
    let request = request(
        "стоит открывать?",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("recommendation"),
    );
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    assert_eq!(result.status, RecallStatus::Unknown);
    assert!(result.items.is_empty());
}

#[test]
fn current_and_historical_truth_use_both_time_axes() {
    let mut old = document(
        "claim:old-answer",
        RecallDocumentKind::Claim,
        "Старое решение: не открывать",
        "status",
        ALICE,
    );
    old.temporal.valid_time = Some(
        TimeRange::new(TimestampMicros(0), Some(TimestampMicros(400)))
            .expect("test fixture must be valid"),
    );
    old.temporal.transaction_time = CommitRange::new(CommitSeq::GENESIS, Some(CommitSeq::new(5)))
        .expect("test fixture must be valid");
    old.conflict = RecallConflictState::ResolvedLoser {
        set_id: "conflict:bar".to_owned(),
        winner: DocumentId::new("claim:current-answer").expect("test fixture must be valid"),
    };
    let mut current = document(
        "claim:current-answer",
        RecallDocumentKind::Claim,
        "Текущее решение: открыть пилот",
        "status",
        ALICE,
    );
    current.temporal.valid_time = Some(TimeRange::open_ended(TimestampMicros(400)));
    current.temporal.transaction_time = CommitRange::current(CommitSeq::new(5));
    current.conflict = RecallConflictState::ResolvedWinner {
        set_id: "conflict:bar".to_owned(),
    };
    let provider = FixtureProvider::new(vec![labelled(old), labelled(current)]);

    let current_request = request(
        "какой статус?",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("status"),
    );
    let current_result = RecallEngine::new([7; 32])
        .recall(&provider, &current_request)
        .expect("test fixture must be valid");
    assert_eq!(
        current_result.items[0].document_id.as_str(),
        "claim:current-answer"
    );

    let mut historical_request = request(
        "какой статус был?",
        ALICE,
        RecallMode::Historical,
        RecallIntent::HistoricalTruth,
        Some("status"),
    );
    historical_request.request.temporal = TemporalConstraint::KnownAt {
        commit_seq: CommitSeq::new(4),
    };
    historical_request.request.cues.temporal_context.now = TimestampMicros(300);
    let historical_result = RecallEngine::new([7; 32])
        .recall(&provider, &historical_request)
        .expect("test fixture must be valid");
    assert_eq!(
        historical_result
            .snapshot
            .expect("test fixture must be valid")
            .commit_seq,
        4
    );
    assert_eq!(
        historical_result.items[0].document_id.as_str(),
        "claim:old-answer"
    );
}

#[test]
fn competing_hypotheses_produce_unknown_instead_of_arbitrary_winner() {
    let mut open = document(
        "hypothesis:open",
        RecallDocumentKind::Claim,
        "Открывать стоит",
        "recommendation",
        ALICE,
    );
    open.conflict = RecallConflictState::Unresolved {
        set_id: "conflict:decision".to_owned(),
    };
    let mut do_not_open = document(
        "hypothesis:do-not-open",
        RecallDocumentKind::Claim,
        "Открывать не стоит",
        "recommendation",
        ALICE,
    );
    do_not_open.conflict = open.conflict.clone();
    let provider = FixtureProvider::new(vec![labelled(open), labelled(do_not_open)]);
    let request = request(
        "стоит открывать?",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("recommendation"),
    );
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    assert_eq!(result.status, RecallStatus::Unknown);
    assert_eq!(result.stop_reason, StopReason::UnknownOrConflicted);
    assert_eq!(
        result.sufficiency.unresolved_conflicts,
        BTreeSet::from(["conflict:decision".to_owned()])
    );
    assert!(
        result
            .items
            .iter()
            .all(|item| item.use_decision == MemoryUseDecision::WithholdDueToUncertainty)
    );
}

#[test]
fn facet_confidence_threshold_is_part_of_rule_based_sufficiency() {
    let mut weak = document(
        "claim:weak",
        RecallDocumentKind::Claim,
        "weak recommendation",
        "recommendation",
        ALICE,
    );
    weak.source_trust = 0.4;
    let provider = FixtureProvider::new(vec![labelled(weak)]);
    let mut request = request(
        "weak recommendation",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("recommendation"),
    );
    request.request.required_facets[0].minimum_confidence = 0.8;
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("recall must return structured insufficiency");
    assert_eq!(result.status, RecallStatus::Partial);
    assert_eq!(
        result.sufficiency.missing_facets,
        BTreeSet::from(["recommendation".to_owned()])
    );
    assert!(!result.sufficiency.sufficient);
}

#[test]
fn omitted_policy_grant_fails_closed() {
    let mut record = labelled(document(
        "claim:no-grant",
        RecallDocumentKind::Claim,
        "Скрытая рекомендация",
        "recommendation",
        ALICE,
    ));
    record.access.audience_purpose_grants.clear();
    let provider = FixtureProvider::new(vec![record]);
    let request = request(
        "стоит открывать?",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("recommendation"),
    );
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    assert_eq!(result.status, RecallStatus::Unknown);
    assert!(
        serde_json::to_string(&result)
            .expect("test fixture must be valid")
            .find("no-grant")
            .is_none()
    );
}

#[test]
fn evidence_with_an_omitted_grant_cannot_support_or_leak_through_a_claim() {
    let mut record = labelled(document(
        "claim:visible-with-hidden-evidence",
        RecallDocumentKind::Claim,
        "Visible semantic claim",
        "answer",
        ALICE,
    ));
    record.evidence[0].access.audience_purpose_grants.clear();
    record.evidence[0].evidence.excerpt = Some("HIDDEN-EVIDENCE-921".to_owned());
    let provider = FixtureProvider::new(vec![record]);
    let request = request(
        "visible semantic claim",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("answer"),
    );
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("missing evidence grants must produce structured unknown");
    assert_eq!(result.status, RecallStatus::Unknown);
    assert_eq!(result.stop_reason, StopReason::UnknownOrConflicted);
    assert!(result.evidence.is_empty());
    let serialized = serde_json::to_string(&result).expect("result must serialize");
    assert!(!serialized.contains("HIDDEN-EVIDENCE-921"));
    assert!(!serialized.contains("Visible semantic claim"));
}

#[test]
fn stable_document_ids_reject_blank_deserialization() {
    assert!(serde_json::from_str::<DocumentId>(r#"""#).is_err());
    assert_eq!(
        serde_json::from_str::<DocumentId>(r#""claim:stable""#)
            .expect("non-empty stable ID must deserialize")
            .as_str(),
        "claim:stable"
    );
}

#[test]
fn forbidden_candidate_cannot_change_ranking_trace_or_work_buckets() {
    let allowed = labelled(document(
        "claim:allowed",
        RecallDocumentKind::Claim,
        "Стоит открыть осторожный пилот",
        "recommendation",
        ALICE,
    ));
    let baseline = FixtureProvider::new(vec![allowed.clone()]);
    let mut forbidden = labelled(document(
        "claim:forbidden-super-score",
        RecallDocumentKind::Claim,
        "Стоит открыть немедленно SECRET",
        "recommendation",
        ALICE,
    ));
    forbidden.access.consent = AccessConsent::Denied;
    forbidden.access.owners.clear();
    // Invalid content demonstrates that rejected payload is not even validated.
    forbidden.document.estimated_tokens = 0;
    let adversarial = FixtureProvider::new(vec![forbidden, allowed]);
    let request = request(
        "стоит открывать?",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("recommendation"),
    );
    let baseline_result = RecallEngine::new([7; 32])
        .recall(&baseline, &request)
        .expect("test fixture must be valid");
    let adversarial_result = RecallEngine::new([7; 32])
        .recall(&adversarial, &request)
        .expect("test fixture must be valid");
    assert_eq!(baseline_result, adversarial_result);
    let serialized =
        serde_json::to_string(&adversarial_result).expect("test fixture must be valid");
    assert!(!serialized.contains("forbidden"));
    assert!(!serialized.contains("SECRET"));
}

#[test]
fn equal_scores_have_stable_identifier_tie_break() {
    let first = labelled(document(
        "a",
        RecallDocumentKind::Claim,
        "одинаковый ответ",
        "answer",
        ALICE,
    ));
    let second = labelled(document(
        "b",
        RecallDocumentKind::Claim,
        "одинаковый ответ",
        "answer",
        ALICE,
    ));
    let request = request(
        "одинаковый ответ",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("answer"),
    );
    let forward = RecallEngine::new([7; 32])
        .recall(
            &FixtureProvider::new(vec![first.clone(), second.clone()]),
            &request,
        )
        .expect("test fixture must be valid");
    let reverse = RecallEngine::new([7; 32])
        .recall(&FixtureProvider::new(vec![second, first]), &request)
        .expect("test fixture must be valid");
    assert_eq!(forward, reverse);
    assert_eq!(forward.items[0].document_id.as_str(), "a");
}

#[test]
fn supplied_vector_route_is_exact_and_explainable() {
    let mut vector_document = document(
        "vector:match",
        RecallDocumentKind::Knowledge,
        "семантическое совпадение",
        "vector_answer",
        ALICE,
    );
    vector_document.active_keys.clear();
    vector_document.vector = Some(SuppliedVector {
        space: "fixture-vector".to_owned(),
        values: vec![1.0, 0.0],
    });
    let provider = FixtureProvider::new(vec![labelled(vector_document)]);
    let mut request = request(
        "совсем другие слова",
        ALICE,
        RecallMode::Required,
        RecallIntent::Associative,
        Some("vector_answer"),
    );
    request.request.cues.active_referents.clear();
    request.request.cues.active_topics.clear();
    request.query_vector = Some(SuppliedVector {
        space: "fixture-vector".to_owned(),
        values: vec![1.0, 0.0],
    });
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    assert!(
        result.items[0]
            .score
            .routes
            .iter()
            .any(|contribution| contribution.route == RecallRoute::SuppliedVector)
    );
}

#[test]
fn every_universal_seed_route_is_observable_in_the_authorized_trace() {
    let mut active = document(
        "route:active",
        RecallDocumentKind::Knowledge,
        "active memory",
        "misc",
        ALICE,
    );
    active.canonical_name = Some("active memory".to_owned());
    let mut exact = document(
        "route:exact",
        RecallDocumentKind::Entity,
        "Project Sakura",
        "misc",
        ALICE,
    );
    exact.canonical_name = Some("Project Sakura".to_owned());
    exact.active_keys.clear();
    let mut relationship = document(
        "route:relationship",
        RecallDocumentKind::Relationship,
        "shared plan",
        "misc",
        ALICE,
    );
    relationship.active_keys.clear();
    let mut episode = document(
        "route:episode",
        RecallDocumentKind::Episode,
        "visited Tokyo",
        "misc",
        ALICE,
    );
    episode.active_keys.clear();
    let mut temporal = document(
        "route:temporal",
        RecallDocumentKind::Claim,
        "current permit",
        "misc",
        ALICE,
    );
    temporal.active_keys.clear();
    temporal.temporal.valid_time = Some(TimeRange::open_ended(TimestampMicros(100)));
    let mut structural = document(
        "route:structural",
        RecallDocumentKind::Claim,
        "required structure",
        "answer",
        ALICE,
    );
    structural.active_keys.clear();
    let mut vector = document(
        "route:vector",
        RecallDocumentKind::Knowledge,
        "vector only",
        "misc",
        ALICE,
    );
    vector.active_keys.clear();
    vector.vector = Some(SuppliedVector {
        space: "fixture-vector".to_owned(),
        values: vec![0.25, 0.75],
    });
    let provider = FixtureProvider::new(
        [
            active,
            exact,
            relationship,
            episode,
            temporal,
            structural,
            vector,
        ]
        .into_iter()
        .map(labelled)
        .collect(),
    );
    let mut request = request(
        "Project Sakura",
        ALICE,
        RecallMode::Required,
        RecallIntent::Relational,
        Some("answer"),
    );
    request.query_vector = Some(SuppliedVector {
        space: "fixture-vector".to_owned(),
        values: vec![0.25, 0.75],
    });
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    let route_outputs = result
        .trace
        .steps
        .iter()
        .filter_map(|step| step.route.map(|route| (route, step.selected_ids.clone())))
        .collect::<BTreeMap<_, _>>();
    for route in [
        RecallRoute::ActiveContext,
        RecallRoute::ExactAlias,
        RecallRoute::Relationship,
        RecallRoute::Episodic,
        RecallRoute::Temporal,
        RecallRoute::Structural,
        RecallRoute::Lexical,
        RecallRoute::SuppliedVector,
    ] {
        assert!(
            route_outputs.get(&route).is_some_and(|ids| !ids.is_empty()),
            "route {route:?} produced no authorized candidates"
        );
    }
}

#[test]
fn reference_oracle_adapter_executes_policy_first_recall() {
    let database = ContextDb::new("recall-adapter-db").expect("reference database must initialize");
    let reference_access = ReferenceAccessLabel {
        workspace: WORKSPACE.to_owned(),
        scopes: BTreeSet::from([SCOPE.to_owned()]),
        owners: BTreeSet::from([ALICE.to_owned()]),
        audience: BTreeSet::from([ALICE.to_owned()]),
        audience_purpose_grants: BTreeMap::from([(
            "@owner".to_owned(),
            BTreeSet::from(["conversation".to_owned()]),
        )]),
        purposes: BTreeSet::from(["conversation".to_owned()]),
        sensitivity: ReferenceSensitivity::Internal,
        consent: ReferenceConsent::Granted,
        retrievable: true,
    };
    database
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "reference-recall-record".to_owned(),
            mutations: vec![Mutation::Put {
                record: LogicalRecord {
                    id: "reference:answer".to_owned(),
                    kind: RecordKind::Node,
                    access: reference_access,
                    valid_time: ValidTime::UNBOUNDED,
                    lifecycle: Lifecycle::Active,
                    links: SemanticLinks::default(),
                    value: json!({"answer": "reference oracle"}),
                    search_text: Some("adapter answer".to_owned()),
                    vector: None,
                    attributes: BTreeMap::from([
                        ("facets".to_owned(), json!(["answer"])),
                        ("canonical_name".to_owned(), json!("adapter answer")),
                    ]),
                },
                expected_revision: None,
            }],
        })
        .expect("reference record must commit");
    let provider = ReferenceProvider {
        database: &database,
    };
    let mut request = request(
        "adapter answer",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("answer"),
    );
    request.request.evidence_policy = EvidencePolicy {
        require_primary_evidence: false,
        include_quotes: false,
        permit_derived_only: true,
    };
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("reference adapter recall must succeed");
    assert_eq!(result.status, RecallStatus::Complete);
    assert_eq!(result.items[0].document_id.as_str(), "reference:answer");
    assert_eq!(result.items[0].content.as_deref(), Some("adapter answer"));
}

#[test]
fn reference_candidate_records_never_influence_before_typed_promotion() {
    let database =
        ContextDb::new("recall-candidate-gate-db").expect("reference database must initialize");
    let reference_access = ReferenceAccessLabel {
        workspace: WORKSPACE.to_owned(),
        scopes: BTreeSet::from([SCOPE.to_owned()]),
        owners: BTreeSet::from([ALICE.to_owned()]),
        audience: BTreeSet::from([ALICE.to_owned()]),
        audience_purpose_grants: BTreeMap::from([(
            "@owner".to_owned(),
            BTreeSet::from(["conversation".to_owned()]),
        )]),
        purposes: BTreeSet::from(["conversation".to_owned()]),
        sensitivity: ReferenceSensitivity::Internal,
        consent: ReferenceConsent::Granted,
        retrievable: true,
    };
    database
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "reference-candidate-gate".to_owned(),
            mutations: vec![
                Mutation::Put {
                    record: LogicalRecord {
                        id: "candidate:forged-promotion".to_owned(),
                        kind: RecordKind::Candidate,
                        access: reference_access.clone(),
                        valid_time: ValidTime::UNBOUNDED,
                        lifecycle: Lifecycle::Active,
                        links: SemanticLinks::default(),
                        value: json!({
                            "validation_state": {
                                "state": "promoted",
                                "commit_seq": 1
                            },
                            "payload": "MALICIOUS-CANDIDATE-CONTENT"
                        }),
                        search_text: Some("MALICIOUS-CANDIDATE-CONTENT".to_owned()),
                        vector: Some(vec![1.0, 0.0]),
                        attributes: BTreeMap::from([
                            ("candidate_state".to_owned(), json!("promoted")),
                            ("promotion_authorized".to_owned(), json!(true)),
                            ("facets".to_owned(), json!(["answer"])),
                        ]),
                    },
                    expected_revision: None,
                },
                Mutation::Put {
                    record: LogicalRecord {
                        id: "node:typed-promotion".to_owned(),
                        kind: RecordKind::Node,
                        access: reference_access,
                        valid_time: ValidTime::UNBOUNDED,
                        lifecycle: Lifecycle::Active,
                        links: SemanticLinks::default(),
                        value: json!({"answer": "authorized typed promotion"}),
                        search_text: Some("authorized typed promotion".to_owned()),
                        vector: None,
                        attributes: BTreeMap::from([("facets".to_owned(), json!(["answer"]))]),
                    },
                    expected_revision: None,
                },
            ],
        })
        .expect("candidate and typed promotion must commit");
    let provider = ReferenceProvider {
        database: &database,
    };

    let recall = |query: &str| {
        let mut request = request(
            query,
            ALICE,
            RecallMode::Required,
            RecallIntent::CurrentTruth,
            Some("answer"),
        );
        request.request.evidence_policy = EvidencePolicy {
            require_primary_evidence: false,
            include_quotes: false,
            permit_derived_only: true,
        };
        RecallEngine::new([7; 32])
            .recall(&provider, &request)
            .expect("candidate gate recall must remain valid")
    };

    let candidate_result = recall("MALICIOUS-CANDIDATE-CONTENT");
    assert!(
        candidate_result
            .items
            .iter()
            .all(|item| item.document_id.as_str() != "candidate:forged-promotion")
    );
    assert!(
        !serde_json::to_string(&candidate_result)
            .expect("result serializes")
            .contains("MALICIOUS-CANDIDATE-CONTENT")
    );

    let promoted_result = recall("authorized typed promotion");
    assert!(promoted_result.items.iter().any(|item| {
        item.document_id.as_str() == "node:typed-promotion"
            && item.content.as_deref() == Some("authorized typed promotion")
    }));
}

#[test]
fn evidence_and_creepy_use_guards_withhold_without_leaking_content() {
    let mut unsupported = document(
        "claim:unsupported",
        RecallDocumentKind::Claim,
        "unsupported assertion",
        "answer",
        ALICE,
    );
    unsupported.evidence.clear();
    let mut private = document(
        "claim:private",
        RecallDocumentKind::Claim,
        "unexpected private detail",
        "answer",
        ALICE,
    );
    private.use_profile.personal_detail = true;
    private.use_profile.shared_with_principal = false;
    let provider = FixtureProvider::new(vec![labelled(unsupported), labelled(private)]);
    let request = request(
        "что учитывать?",
        ALICE,
        RecallMode::ImplicitContinuity,
        RecallIntent::Continuity,
        Some("answer"),
    );
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    assert_eq!(result.status, RecallStatus::Unknown);
    assert!(
        result
            .sufficiency
            .unsupported_documents
            .contains(&DocumentId::new("claim:unsupported").expect("test fixture must be valid"))
    );
    assert!(result.items.iter().any(|item| {
        item.document_id.as_str() == "claim:private"
            && item.use_decision == MemoryUseDecision::WithholdDueToPrivacy
            && item.content.is_none()
    }));
    assert_eq!(result.usage.context_tokens, 0);
    let serialized = serde_json::to_string(&result).expect("recall result must serialize");
    assert!(!serialized.contains("unexpected private detail"));
    assert!(!serialized.contains("unsupported assertion"));
}

#[test]
fn typed_graph_activation_respects_edge_and_hop_budgets() {
    let mut seed = document(
        "node:seed",
        RecallDocumentKind::Entity,
        "точный seed",
        "seed",
        ALICE,
    );
    seed.canonical_name = Some("точный seed".to_owned());
    seed.active_keys.clear();
    let mut answer = document(
        "claim:via-graph",
        RecallDocumentKind::Claim,
        "графовый ответ",
        "answer",
        ALICE,
    );
    answer.active_keys.clear();
    let provider =
        FixtureProvider::new(vec![labelled(seed), labelled(answer)]).with_relations(vec![
            relation("edge:support", "node:seed", "claim:via-graph"),
        ]);
    let mut request = request(
        "точный seed",
        ALICE,
        RecallMode::Required,
        RecallIntent::Associative,
        Some("answer"),
    );
    request.request.cues.active_referents.clear();
    request.request.cues.active_topics.clear();
    request.request.budgets.max_graph_visits = 1;
    request.limits.max_graph_hops = 1;
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    assert!(
        result
            .items
            .iter()
            .any(|item| item.document_id.as_str() == "claim:via-graph")
    );
    assert!(result.usage.graph_edges_examined <= 1);
    assert!(result.usage.max_hop_reached <= 1);
}

#[test]
fn node_and_token_limits_are_strict_and_continuation_is_authenticated() {
    let mut expensive = document(
        "claim:expensive",
        RecallDocumentKind::Claim,
        "дорогой ответ",
        "answer",
        ALICE,
    );
    expensive.estimated_tokens = 40;
    let provider = FixtureProvider::new(vec![labelled(expensive)]);
    let engine = RecallEngine::new([7; 32]);
    let mut first = request(
        "дорогой ответ",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("answer"),
    );
    first.request.budgets.max_tokens = 20;
    first.limits.max_context_tokens = 20;
    first.request.budgets.max_candidates = 2;
    first.limits.max_nodes_examined = 2;
    let first_result = engine
        .recall(&provider, &first)
        .expect("test fixture must be valid");
    assert_eq!(first_result.stop_reason, StopReason::TokenBudget);
    assert!(first_result.usage.context_tokens <= 20);
    assert!(first_result.usage.nodes_examined <= 2);
    let token = first_result
        .continuation
        .expect("test fixture must be valid");
    let token_json = serde_json::to_string(&token).expect("test fixture must be valid");
    assert!(!token_json.contains("дорогой ответ"));

    let mut tampered_request = first.clone();
    let mut tampered = token.clone();
    tampered.consumed.context_tokens = 999;
    tampered_request.continuation = Some(tampered);
    assert_eq!(
        engine.recall(&provider, &tampered_request),
        Err(RecallError::InvalidContinuation)
    );

    let mut continued = first;
    continued.request.budgets.max_tokens = 80;
    continued.limits.max_context_tokens = 80;
    continued.request.budgets.max_candidates = 8;
    continued.limits.max_nodes_examined = 8;
    continued.continuation = Some(token);
    let continued_result = engine
        .recall(&provider, &continued)
        .expect("test fixture must be valid");
    assert_eq!(continued_result.status, RecallStatus::Complete);
    assert_eq!(
        continued_result.items[0].document_id.as_str(),
        "claim:expensive"
    );
    assert!(continued_result.usage.context_tokens <= 80);
    assert!(continued_result.usage.nodes_examined <= 8);
}

#[test]
fn node_and_evidence_limits_fail_closed_at_the_exact_boundary() {
    let misc = document(
        "a:misc",
        RecallDocumentKind::Claim,
        "first authorized candidate",
        "misc",
        ALICE,
    );
    let answer = document(
        "z:answer",
        RecallDocumentKind::Claim,
        "second authorized answer",
        "answer",
        ALICE,
    );
    let provider = FixtureProvider::new(vec![labelled(misc), labelled(answer)]);
    let mut node_limited = request(
        "authorized",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("answer"),
    );
    node_limited.request.budgets.max_candidates = 1;
    node_limited.limits.max_nodes_examined = 1;
    let node_result = RecallEngine::new([7; 32])
        .recall(&provider, &node_limited)
        .expect("bounded recall must return a partial result");
    assert_eq!(node_result.usage.nodes_examined, 1);
    assert_eq!(node_result.stop_reason, StopReason::NodeBudget);
    assert!(node_result.sufficiency.missing_facets.contains("answer"));

    let first = document(
        "claim:a",
        RecallDocumentKind::Claim,
        "first facet",
        "first",
        ALICE,
    );
    let second = document(
        "claim:b",
        RecallDocumentKind::Claim,
        "second facet",
        "second",
        ALICE,
    );
    let provider = FixtureProvider::new(vec![labelled(first), labelled(second)]);
    let mut evidence_limited = request(
        "facet",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("first"),
    );
    evidence_limited
        .request
        .required_facets
        .push(FacetRequirement {
            name: "second".to_owned(),
            required: true,
            minimum_confidence: 0.5,
        });
    evidence_limited.request.budgets.max_evidence_items = 1;
    evidence_limited.limits.max_evidence_units = 1;
    let evidence_result = RecallEngine::new([7; 32])
        .recall(&provider, &evidence_limited)
        .expect("evidence exhaustion must be structured");
    assert_eq!(evidence_result.usage.evidence_units, 1);
    assert_eq!(evidence_result.status, RecallStatus::Partial);
    assert_eq!(evidence_result.stop_reason, StopReason::UnknownOrConflicted);
    assert_eq!(evidence_result.sufficiency.unsupported_documents.len(), 1);
}

#[test]
fn continuation_is_bound_to_snapshot_and_filters() {
    let mut expensive = document(
        "claim:bound",
        RecallDocumentKind::Claim,
        "bound answer",
        "answer",
        ALICE,
    );
    expensive.estimated_tokens = 40;
    let provider = FixtureProvider::new(vec![labelled(expensive)]);
    let engine = RecallEngine::new([7; 32]);
    let mut original = request(
        "bound answer",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("answer"),
    );
    original.request.budgets.max_tokens = 20;
    original.limits.max_context_tokens = 20;
    let token = engine
        .recall(&provider, &original)
        .expect("test fixture must be valid")
        .continuation
        .expect("test fixture must be valid");

    let mut changed_query = original.clone();
    changed_query.request.cues.current_input = QueryContent::Text("other query".to_owned());
    changed_query.continuation = Some(token.clone());
    assert_eq!(
        engine.recall(&provider, &changed_query),
        Err(RecallError::InvalidContinuation)
    );

    let mut changed_snapshot = original;
    let mut forged = token;
    forged.snapshot.commit_seq = 9;
    changed_snapshot.continuation = Some(forged);
    assert_eq!(
        engine.recall(&provider, &changed_snapshot),
        Err(RecallError::InvalidContinuation)
    );
}

#[test]
fn continuation_carries_opaque_coverage_and_cumulative_budgets() {
    let first_document = document(
        "claim:a-first",
        RecallDocumentKind::Claim,
        "first continuation fact",
        "part_a",
        ALICE,
    );
    let second_document = document(
        "claim:b-second",
        RecallDocumentKind::Claim,
        "second continuation fact",
        "part_b",
        ALICE,
    );
    let provider = FixtureProvider::new(vec![labelled(first_document), labelled(second_document)]);
    let engine = RecallEngine::new([7; 32]);
    let mut first = request(
        "continuation fact",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("part_a"),
    );
    first.request.required_facets.push(FacetRequirement {
        name: "part_b".to_owned(),
        required: true,
        minimum_confidence: 0.5,
    });
    first.request.budgets.max_tokens = 20;
    first.limits.max_context_tokens = 20;

    let first_result = engine
        .recall(&provider, &first)
        .expect("first continuation page must succeed");
    assert_eq!(first_result.stop_reason, StopReason::TokenBudget);
    assert_eq!(
        first_result.sufficiency.covered_facets,
        BTreeSet::from(["part a".to_owned()])
    );
    let token = first_result
        .continuation
        .expect("budget boundary must return a continuation");
    let serialized = serde_json::to_string(&token).expect("continuation must serialize");
    assert!(!serialized.contains("part a"));
    assert!(!serialized.contains("evidence:claim:a-first"));

    let mut next = first;
    next.request.budgets.max_tokens = 64;
    next.limits.max_context_tokens = 64;
    next.continuation = Some(token);
    let completed = engine
        .recall(&provider, &next)
        .expect("continued recall must succeed");
    assert_eq!(completed.status, RecallStatus::Complete);
    assert_eq!(
        completed.sufficiency.covered_facets,
        BTreeSet::from(["part a".to_owned(), "part b".to_owned()])
    );
    assert_eq!(completed.items[0].document_id.as_str(), "claim:b-second");
    assert!(completed.usage.context_tokens <= 64);
    assert_eq!(completed.usage.evidence_units, 2);
}

#[test]
fn one_microsecond_deadline_returns_bounded_partial_result() {
    let records = (0..256)
        .map(|index| {
            labelled(document(
                &format!("claim:{index:04}"),
                RecallDocumentKind::Claim,
                "deadline candidate",
                "answer",
                ALICE,
            ))
        })
        .collect();
    let provider = FixtureProvider::new(records);
    let mut request = request(
        "deadline candidate",
        ALICE,
        RecallMode::Required,
        RecallIntent::CurrentTruth,
        Some("answer"),
    );
    request.request.budgets.max_latency_micros = 1;
    request.limits.deadline_micros = 1;
    let result = RecallEngine::new([7; 32])
        .recall(&provider, &request)
        .expect("test fixture must be valid");
    assert_eq!(result.stop_reason, StopReason::Deadline);
    assert!(result.usage.nodes_examined <= request.max_nodes_examined());
}

proptest! {
    #[test]
    fn arbitrary_denied_payloads_never_change_results(secret in ".{0,128}") {
        let allowed = labelled(document(
            "claim:stable",
            RecallDocumentKind::Claim,
            "stable answer",
            "answer",
            ALICE,
        ));
        let mut denied = labelled(document(
            "claim:denied",
            RecallDocumentKind::Claim,
            &secret,
            "answer",
            ALICE,
        ));
        denied.access.retrievable = false;
        denied.document.estimated_tokens = 0;
        let request = request(
            "stable answer",
            ALICE,
            RecallMode::Required,
            RecallIntent::CurrentTruth,
            Some("answer"),
        );
        let baseline = RecallEngine::new([7; 32])
            .recall(&FixtureProvider::new(vec![allowed.clone()]), &request)
            .expect("test fixture must be valid");
        let with_denied = RecallEngine::new([7; 32])
            .recall(&FixtureProvider::new(vec![denied, allowed]), &request)
            .expect("test fixture must be valid");
        prop_assert_eq!(baseline, with_denied);
    }
}
