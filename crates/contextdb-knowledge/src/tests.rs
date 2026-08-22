use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::{
    CompileRequest, ContextBudgets, ContextCompiler, ContextProvider, InstructionHierarchy,
    ModelProfile, PackFacetRequirement, PackPurpose, PositionProfile, ReferenceTokenizer,
    RendererKind, StructuredFormat,
};
use contextdb_core::{
    Audience, ClaimObject, MemorySubjectId, NonEmptyVec, SnapshotRef, TemporalConstraint,
    TimestampMicros, Validate,
};
use contextdb_recall::{RecallPrincipal, RecallSensitivity};
use proptest::prelude::*;

use crate::*;

fn adapter() -> GenericDocumentAdapter {
    GenericDocumentAdapter::new(DocumentAdapterConfig::default()).expect("config is valid")
}

fn principal(fixture: &BenchCFixture) -> RecallPrincipal {
    RecallPrincipal {
        subject: fixture.subject_id.to_string(),
        audiences: BTreeSet::new(),
        workspace: fixture.workspace_id.to_string(),
        scopes: BTreeSet::from([fixture.scope.id.to_string()]),
        purpose: contextdb_recall::purpose_key(&contextdb_core::Purpose::KnowledgeRecall),
        clearance: RecallSensitivity::Internal,
    }
}

fn query(
    fixture: &BenchCFixture,
    snapshot: SnapshotRef,
    predicate: &str,
    valid_at: i64,
) -> KnowledgeQuery {
    KnowledgeQuery {
        subject_key: "sessions".to_owned(),
        predicate_key: predicate.to_owned(),
        valid_at: TimestampMicros(valid_at),
        known_at: snapshot,
        source: SourceConstraint::AnyAuthorized,
        include_history: true,
        disclose_conflicts: true,
        include_excerpts: true,
        principal: principal(fixture),
    }
}

fn publish(ledger: &mut KnowledgeLedger, input: DocumentRevisionInput) -> KnowledgePublication {
    ledger
        .publish(adapter().adapt(&input).expect("document adapts"))
        .expect("document publishes")
}

fn supported_object(result: &KnowledgeQueryResult) -> &ClaimObject {
    match &result.state {
        KnowledgeAnswerState::Supported { answer } => &answer.object,
        other => panic!("expected supported answer, got {other:?}"),
    }
}

#[test]
fn generic_adapter_is_deterministic_and_citations_are_exact() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let input = fixture.redis_document();
    let left = adapter().adapt(&input).expect("left adapts");
    let right = adapter().adapt(&input).expect("right adapts");
    assert_eq!(left, right);
    assert_eq!(left.source_revision.sections.len(), 1);
    assert_eq!(left.source_revision.hierarchy.len(), 4);
    assert_eq!(left.source_revision.evidence.len(), 1);
    let evidence = &left.source_revision.evidence[0];
    assert_eq!(
        evidence.extracted_text.as_deref(),
        Some("Product uses Redis for sessions")
    );
    assert!(matches!(
        evidence.selector,
        contextdb_core::EvidenceSelector::ByteRange { start, end } if end > start
    ));
    assert!(matches!(
        left.proposals[0].action,
        KnowledgeProposalAction::Assert { .. }
    ));
}

#[test]
fn hallucinated_or_ambiguous_quote_is_rejected_before_publication() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut absent = fixture.redis_document();
    absent.sections[0].statements[0].quote = "text that is not present".to_owned();
    assert!(matches!(
        adapter().adapt(&absent),
        Err(KnowledgeError::HallucinatedCitation { .. })
    ));

    let mut repeated = fixture.redis_document();
    repeated.sections[0].content =
        "Product uses Redis for sessions. Product uses Redis for sessions.".to_owned();
    assert!(matches!(
        adapter().adapt(&repeated),
        Err(KnowledgeError::HallucinatedCitation { .. })
    ));
}

#[test]
fn redis_to_postgres_is_current_and_historical_without_invented_rationale() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    let redis = publish(&mut ledger, fixture.redis_document());
    assert!(
        redis
            .semantic_transaction
            .as_ref()
            .is_some_and(|transaction| transaction.validate().is_ok())
    );
    let postgres = publish(&mut ledger, fixture.postgres_document());

    let historical = ledger
        .query(&query(&fixture, postgres.snapshot, "backend", 100))
        .expect("historical query succeeds");
    assert_eq!(
        supported_object(&historical),
        &ClaimObject::String("Redis".to_owned())
    );
    assert_eq!(historical.history.len(), 2);

    let current = ledger
        .query(&query(&fixture, postgres.snapshot, "backend", 250))
        .expect("current query succeeds");
    assert_eq!(
        supported_object(&current),
        &ClaimObject::String("PostgreSQL".to_owned())
    );
    let rationale = ledger
        .query(&query(
            &fixture,
            postgres.snapshot,
            "migration_rationale",
            250,
        ))
        .expect("unknown rationale query succeeds");
    assert!(matches!(
        rationale.state,
        KnowledgeAnswerState::Unknown {
            reason: UnknownReason::OpenQuestion,
            ..
        }
    ));
}

#[test]
fn historical_system_cutoff_does_not_see_future_source_revision() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    let first = publish(&mut ledger, fixture.redis_document());
    publish(&mut ledger, fixture.postgres_document());
    let past = ledger
        .query(&query(&fixture, first.snapshot, "backend", 250))
        .expect("past query succeeds");
    assert!(matches!(
        past.state,
        KnowledgeAnswerState::Unknown {
            reason: UnknownReason::NoMatchingClaim,
            ..
        }
    ));
}

#[test]
fn same_source_update_preserves_old_valid_time_and_explains_transition() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.redis_document());
    let mut update = fixture.redis_document();
    update.native_revision = "rev-2".to_owned();
    update.supersedes_native_revision = Some("rev-1".to_owned());
    update.native_locator = "bench-c://architecture-v1/rev-2".to_owned();
    update.sections[0].content =
        "Product uses PostgreSQL for sessions after version 2.0.".to_owned();
    update.sections[0].statements[0].quote = "Product uses PostgreSQL for sessions".to_owned();
    update.sections[0].statements[0].action = DocumentStatementAction::Assert {
        object: ClaimObject::String("PostgreSQL".to_owned()),
        valid_time: contextdb_core::TimeRange::open_ended(TimestampMicros(200)),
        epistemic: StatementEpistemic::SourceAssertion,
    };
    let second = publish(&mut ledger, update);

    let old_time = ledger
        .query(&query(&fixture, second.snapshot, "backend", 100))
        .expect("old valid-time query succeeds");
    assert_eq!(
        supported_object(&old_time),
        &ClaimObject::String("Redis".to_owned())
    );
    let new_time = ledger
        .query(&query(&fixture, second.snapshot, "backend", 250))
        .expect("new valid-time query succeeds");
    assert_eq!(
        supported_object(&new_time),
        &ClaimObject::String("PostgreSQL".to_owned())
    );
    let KnowledgeAnswerState::Supported { answer } = &new_time.state else {
        panic!("new valid time must be supported")
    };
    assert!(
        answer
            .citations
            .iter()
            .any(|citation| citation.revision_lineage.len() == 2)
    );
    assert!(new_time.history.iter().any(|entry| {
        entry.reason == KnowledgeChangeReason::ExplicitTemporalTransition
            && entry.object == ClaimObject::String("PostgreSQL".to_owned())
    }));
}

#[test]
fn disagreement_is_visible_and_retraction_restores_supported_current_state() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.redis_document());
    publish(&mut ledger, fixture.postgres_document());
    let disputed_at = publish(&mut ledger, fixture.mysql_disagreement()).snapshot;
    let disputed = ledger
        .query(&query(&fixture, disputed_at, "backend", 250))
        .expect("disputed query succeeds");
    let conflict_id = match &disputed.state {
        KnowledgeAnswerState::Disputed {
            conflict_set_id,
            canonical_conflict,
            alternatives,
        } => {
            assert_eq!(alternatives.len(), 2);
            assert!(*canonical_conflict);
            *conflict_set_id
        }
        other => panic!("expected disagreement, got {other:?}"),
    };
    let retracted_at = publish(&mut ledger, fixture.mysql_retraction()).snapshot;
    let current = ledger
        .query(&query(&fixture, retracted_at, "backend", 250))
        .expect("current query succeeds");
    assert_eq!(
        supported_object(&current),
        &ClaimObject::String("PostgreSQL".to_owned())
    );
    assert!(current.history.iter().any(|entry| {
        entry.lifecycle == contextdb_core::LifecycleState::Retracted
            && entry.reason == KnowledgeChangeReason::SourceRetracted
    }));
    assert!(
        ledger
            .export()
            .conflicts
            .values()
            .any(|record| record.conflict.id == conflict_id
                && record.revisions.iter().any(|revision| {
                    matches!(
                        revision.resolution,
                        contextdb_core::ConflictResolution::WinnerWithDissent { .. }
                    )
                }))
    );
}

#[test]
fn whole_document_retraction_preserves_history_and_removes_current_support() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.postgres_document());
    let mut retraction = fixture.postgres_document();
    retraction.native_revision = "rev-2".to_owned();
    retraction.supersedes_native_revision = Some("rev-1".to_owned());
    retraction.native_locator = "bench-c://migration-v2/rev-2".to_owned();
    retraction.revision_kind = DocumentRevisionKind::RetractDocument;
    retraction.sections[0].content = "The PostgreSQL migration document is withdrawn.".to_owned();
    retraction.sections[0].statements = vec![DocumentStatementInput {
        statement_key: "withdraw-backend-claim".to_owned(),
        subject_key: "sessions".to_owned(),
        subject_label: "Sessions".to_owned(),
        predicate_key: "backend".to_owned(),
        quote: "migration document is withdrawn".to_owned(),
        action: DocumentStatementAction::Retract {
            target: SourceStatementRef {
                source_key: "migration-v2".to_owned(),
                statement_key: "sessions-backend".to_owned(),
            },
            reason: "the complete source document was withdrawn".to_owned(),
        },
    }];
    let published = publish(&mut ledger, retraction);
    assert_eq!(published.retracted_claims.len(), 1);
    let result = ledger
        .query(&query(&fixture, published.snapshot, "backend", 250))
        .expect("post-retraction query succeeds");
    assert!(matches!(
        result.state,
        KnowledgeAnswerState::Unknown {
            reason: UnknownReason::AllSupportRetracted,
            ..
        }
    ));
    assert!(result.history.iter().any(|entry| {
        entry.reason == KnowledgeChangeReason::SourceRetracted
            && entry.lifecycle == contextdb_core::LifecycleState::Retracted
    }));
}

#[test]
fn source_specific_query_does_not_flatten_a_global_disagreement() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    let postgres = publish(&mut ledger, fixture.postgres_document());
    let mysql = publish(&mut ledger, fixture.mysql_disagreement());
    let global = ledger
        .query(&query(&fixture, mysql.snapshot, "backend", 250))
        .expect("global query succeeds");
    assert!(matches!(
        global.state,
        KnowledgeAnswerState::Disputed { .. }
    ));

    let mut postgres_query = query(&fixture, mysql.snapshot, "backend", 250);
    postgres_query.source = SourceConstraint::Source {
        id: postgres.source_id,
    };
    assert_eq!(
        supported_object(
            &ledger
                .query(&postgres_query)
                .expect("source-specific query succeeds")
        ),
        &ClaimObject::String("PostgreSQL".to_owned())
    );
}

#[test]
fn cross_policy_disagreement_is_visible_without_a_dangling_canonical_reference() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.postgres_document());
    let mut differently_labelled = fixture.mysql_disagreement();
    differently_labelled
        .envelope
        .security
        .labels
        .insert("separate-policy-cohort".to_owned());
    publish(&mut ledger, differently_labelled);
    let knowledge_query = query(&fixture, ledger.snapshot(), "backend", 250);
    let result = ledger
        .query(&knowledge_query)
        .expect("cross-policy query succeeds");
    let KnowledgeAnswerState::Disputed {
        canonical_conflict, ..
    } = result.state
    else {
        panic!("cross-policy disagreement must remain visible")
    };
    assert!(!canonical_conflict);
    assert!(ledger.export().conflicts.is_empty());

    let material = KnowledgeContextAdapter::prepare(&ledger, &knowledge_query)
        .expect("cross-policy provider prepares");
    let conflict_id = material
        .provider
        .candidate_labels()
        .expect("labels load")
        .into_iter()
        .find(|label| label.id.to_string().contains("knowledge:conflict:"))
        .expect("query-local conflict candidate exists")
        .id;
    let conflict = material
        .provider
        .materialize_candidate(&conflict_id)
        .expect("authorized conflict materializes");
    assert!(
        conflict
            .memory_refs
            .iter()
            .all(|reference| !matches!(reference, contextdb_core::MemoryRef::ConflictSet { .. }))
    );
}

#[test]
fn dependent_mirror_does_not_fake_source_independence() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.postgres_document());
    let before = ledger
        .query(&query(&fixture, ledger.snapshot(), "backend", 250))
        .expect("before query succeeds");
    let before_answer = match before.state {
        KnowledgeAnswerState::Supported { answer } => answer,
        other => panic!("expected support, got {other:?}"),
    };
    publish(&mut ledger, fixture.postgres_mirror());
    let after = ledger
        .query(&query(&fixture, ledger.snapshot(), "backend", 250))
        .expect("after query succeeds");
    let after_answer = match after.state {
        KnowledgeAnswerState::Supported { answer } => answer,
        other => panic!("expected support, got {other:?}"),
    };
    assert_eq!(after_answer.independent_source_families.len(), 1);
    assert_eq!(
        after_answer.confidence_micros,
        before_answer.confidence_micros
    );
    assert_eq!(after_answer.citations.len(), 2);
}

#[test]
fn source_trust_not_security_classification_drives_claim_confidence() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut verified_ledger = KnowledgeLedger::default();
    publish(&mut verified_ledger, fixture.postgres_document());
    let verified = verified_ledger
        .query(&query(&fixture, verified_ledger.snapshot(), "backend", 250))
        .expect("verified query succeeds");
    let verified_confidence = match verified.state {
        KnowledgeAnswerState::Supported { answer } => answer.confidence_micros,
        other => panic!("expected verified support, got {other:?}"),
    };

    let mut untrusted_document = fixture.postgres_document();
    untrusted_document.trust = contextdb_core::TrustClass::Untrusted;
    let mut untrusted_ledger = KnowledgeLedger::default();
    publish(&mut untrusted_ledger, untrusted_document);
    let untrusted = untrusted_ledger
        .query(&query(
            &fixture,
            untrusted_ledger.snapshot(),
            "backend",
            250,
        ))
        .expect("untrusted query succeeds");
    let untrusted_confidence = match untrusted.state {
        KnowledgeAnswerState::Supported { answer } => answer.confidence_micros,
        other => panic!("expected untrusted support, got {other:?}"),
    };
    assert!(verified_confidence > untrusted_confidence);
}

#[test]
fn hypothesis_remains_visible_but_cannot_become_supported_truth() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    let postgres = adapter()
        .adapt(&fixture.postgres_document())
        .expect("document adapts");
    let supporting_evidence = postgres.source_revision.evidence[0].id;
    ledger.publish(postgres).expect("source publishes");
    publish(
        &mut ledger,
        fixture.hypothesis_document(supporting_evidence),
    );
    let result = ledger
        .query(&query(&fixture, ledger.snapshot(), "migration_driver", 250))
        .expect("query succeeds");
    assert!(matches!(
        result.state,
        KnowledgeAnswerState::Unknown {
            reason: UnknownReason::OnlyDerivedHypotheses,
            ..
        }
    ));
    assert_eq!(result.hypotheses.len(), 1);
}

#[test]
fn source_revision_idempotency_conflict_and_fork_are_atomic() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    let adapted = adapter()
        .adapt(&fixture.redis_document())
        .expect("document adapts");
    let first = ledger.publish(adapted.clone()).expect("first publishes");
    let replay = ledger.publish(adapted).expect("replay succeeds");
    assert_eq!(replay.status, PublicationStatus::AlreadyPublished);
    assert_eq!(replay.snapshot, first.snapshot);

    let before = ledger.export();
    let mut changed = fixture.redis_document();
    changed.title = "Changed under the same native revision".to_owned();
    let changed = adapter().adapt(&changed).expect("changed source adapts");
    assert!(matches!(
        ledger.publish(changed),
        Err(KnowledgeError::RevisionDigestConflict { .. })
    ));
    assert_eq!(ledger.export(), before);

    let mut fork = fixture.redis_document();
    fork.native_revision = "rev-2".to_owned();
    fork.supersedes_native_revision = Some("not-the-head".to_owned());
    let fork = adapter().adapt(&fork).expect("fork adapts");
    assert_eq!(
        ledger.publish(fork),
        Err(KnowledgeError::SourceRevisionFork)
    );
    assert_eq!(ledger.export(), before);

    let mut family_change = fixture.redis_document();
    family_change.native_revision = "rev-2".to_owned();
    family_change.supersedes_native_revision = Some("rev-1".to_owned());
    family_change.source_family = "invented-independent-family".to_owned();
    let family_change = adapter()
        .adapt(&family_change)
        .expect("family-change source adapts");
    assert!(matches!(
        ledger.publish(family_change),
        Err(KnowledgeError::InvalidInput {
            field: "document.source_identity",
            ..
        })
    ));
    assert_eq!(ledger.export(), before);
}

#[test]
fn unauthorized_source_cannot_change_answer_history_or_authorized_watermark() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.postgres_document());
    let before = ledger
        .query(&query(&fixture, ledger.snapshot(), "backend", 250))
        .expect("baseline query succeeds");

    let secret_subject: MemorySubjectId = "00000000-0000-4000-8999-000000000013"
        .parse()
        .expect("fixed secret subject is valid");
    let mut secret = fixture.mysql_disagreement();
    secret.source_key = "secret-status".to_owned();
    secret.source_family = "private-observation".to_owned();
    secret.native_locator = "bench-c://secret-status/rev-1".to_owned();
    secret.envelope.perspective.knower = secret_subject;
    secret.envelope.ownership.owners = NonEmptyVec::new(secret_subject);
    secret.envelope.ownership.audience_grants[0].audience =
        Audience::Subject { id: secret_subject };
    publish(&mut ledger, secret);

    let after = ledger
        .query(&query(&fixture, ledger.snapshot(), "backend", 250))
        .expect("authorized query succeeds");
    assert_eq!(after.state, before.state);
    assert_eq!(after.history, before.history);
    assert_eq!(after.hypotheses, before.hypotheses);
    assert_eq!(
        after.source_revision_watermark,
        before.source_revision_watermark
    );
}

#[test]
fn policy_is_evaluated_at_the_requested_snapshot_before_source_materialization() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    let first = publish(&mut ledger, fixture.redis_document());

    let secret_subject: MemorySubjectId = "00000000-0000-4000-8998-000000000013"
        .parse()
        .expect("fixed secret subject is valid");
    let mut restricted = fixture.redis_document();
    restricted.native_revision = "rev-2".to_owned();
    restricted.supersedes_native_revision = Some("rev-1".to_owned());
    restricted.native_locator = "bench-c://architecture-v1/rev-2".to_owned();
    restricted.envelope.perspective.knower = secret_subject;
    restricted.envelope.ownership.owners = NonEmptyVec::new(secret_subject);
    restricted.envelope.ownership.audience_grants[0].audience =
        Audience::Subject { id: secret_subject };
    let second = publish(&mut ledger, restricted);

    let historical = ledger
        .query(&query(&fixture, first.snapshot, "backend", 100))
        .expect("historical policy query succeeds");
    assert_eq!(
        supported_object(&historical),
        &ClaimObject::String("Redis".to_owned())
    );
    let current = ledger
        .query(&query(&fixture, second.snapshot, "backend", 100))
        .expect("current policy query succeeds");
    assert!(matches!(
        current.state,
        KnowledgeAnswerState::Unknown {
            reason: UnknownReason::NoAuthorizedSource,
            ..
        }
    ));
}

#[test]
fn later_policy_relaxation_does_not_expose_an_older_restricted_claim() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let secret_subject: MemorySubjectId = "00000000-0000-4000-8997-000000000013"
        .parse()
        .expect("fixed secret subject is valid");
    let mut restricted = fixture.postgres_document();
    restricted.envelope.perspective.knower = secret_subject;
    restricted.envelope.ownership.owners = NonEmptyVec::new(secret_subject);
    restricted.envelope.ownership.audience_grants[0].audience =
        Audience::Subject { id: secret_subject };
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, restricted);

    let mut public_metadata_only = fixture.postgres_document();
    public_metadata_only.native_revision = "rev-2".to_owned();
    public_metadata_only.supersedes_native_revision = Some("rev-1".to_owned());
    public_metadata_only.native_locator = "bench-c://migration-v2/rev-2".to_owned();
    public_metadata_only.sections[0].content =
        "This public revision contains no backend statement.".to_owned();
    public_metadata_only.sections[0].statements.clear();
    let public = publish(&mut ledger, public_metadata_only);

    let result = ledger
        .query(&query(&fixture, public.snapshot, "backend", 250))
        .expect("relaxed policy query succeeds");
    assert!(matches!(
        result.state,
        KnowledgeAnswerState::Unknown {
            reason: UnknownReason::NoMatchingClaim,
            ..
        }
    ));
    assert!(result.history.is_empty());
    assert_eq!(
        result.source_revision_watermark,
        contextdb_core::CommitSeq::GENESIS
    );
}

#[test]
fn independent_source_cannot_retract_even_a_same_family_claim() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.postgres_document());
    let before = ledger.export();
    let mut attacker = fixture.postgres_mirror();
    attacker.sections[0].content =
        "The mirror requests retracting the official sessions backend claim.".to_owned();
    attacker.sections[0].statements = vec![DocumentStatementInput {
        statement_key: "retract-official-backend".to_owned(),
        subject_key: "sessions".to_owned(),
        subject_label: "Sessions".to_owned(),
        predicate_key: "backend".to_owned(),
        quote: "retracting the official sessions backend claim".to_owned(),
        action: DocumentStatementAction::Retract {
            target: SourceStatementRef {
                source_key: "migration-v2".to_owned(),
                statement_key: "sessions-backend".to_owned(),
            },
            reason: "mirror requested deletion".to_owned(),
        },
    }];
    let adapted = adapter()
        .adapt(&attacker)
        .expect("attacker document adapts");
    assert_eq!(
        ledger.publish(adapted),
        Err(KnowledgeError::CrossFamilyRetraction)
    );
    assert_eq!(ledger.export(), before);
}

#[test]
fn circular_hypothesis_support_is_rejected_atomically() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    let postgres = adapter()
        .adapt(&fixture.postgres_document())
        .expect("source adapts");
    let independent_support = postgres.source_revision.evidence[0].id;
    ledger.publish(postgres).expect("source publishes");
    let before = ledger.export();
    let mut circular = adapter()
        .adapt(&fixture.hypothesis_document(independent_support))
        .expect("hypothesis adapts");
    let own_evidence = circular.source_revision.evidence[0].id;
    let KnowledgeProposalAction::Assert { epistemic, .. } = &mut circular.proposals[0].action
    else {
        panic!("fixture must contain one assertion")
    };
    *epistemic = StatementEpistemic::DerivedHypothesis {
        supporting_evidence: vec![own_evidence],
    };
    assert!(matches!(
        ledger.publish(circular),
        Err(KnowledgeError::InvalidInput {
            field: "knowledge.hypothesis.supporting_evidence",
            ..
        })
    ));
    assert_eq!(ledger.export(), before);
}

#[test]
fn export_import_is_canonical_and_preserves_queries() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.redis_document());
    publish(&mut ledger, fixture.postgres_document());
    publish(&mut ledger, fixture.mysql_disagreement());
    let before = ledger
        .query(&query(&fixture, ledger.snapshot(), "backend", 250))
        .expect("query succeeds");
    let export = ledger.export();
    let encoded = serde_json::to_vec(&export).expect("export serializes");
    let decoded: KnowledgeExport = serde_json::from_slice(&encoded).expect("export parses");
    let restored = KnowledgeLedger::import(decoded).expect("export imports");
    assert_eq!(restored.export(), export);
    assert_eq!(
        restored
            .query(&query(&fixture, restored.snapshot(), "backend", 250))
            .expect("restored query succeeds"),
        before
    );
}

#[test]
fn import_rejects_tampered_citation_and_non_contiguous_source_history() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.redis_document());
    let mut second = fixture.redis_document();
    second.native_revision = "rev-2".to_owned();
    second.supersedes_native_revision = Some("rev-1".to_owned());
    second.native_locator = "bench-c://architecture-v1/rev-2".to_owned();
    publish(&mut ledger, second);

    let mut bad_quote = ledger.export();
    bad_quote
        .sources
        .values_mut()
        .next()
        .expect("source exists")[0]
        .evidence[0]
        .quote_hash = contextdb_core::ContentDigest::from_bytes([0xA5; 32]);
    assert!(matches!(
        KnowledgeLedger::import(bad_quote),
        Err(KnowledgeError::InvalidInput {
            field: "source_revision.evidence",
            ..
        })
    ));

    let mut bad_chain = ledger.export();
    bad_chain
        .sources
        .values_mut()
        .next()
        .expect("source exists")[1]
        .supersedes = None;
    assert!(matches!(
        KnowledgeLedger::import(bad_chain),
        Err(KnowledgeError::InvalidInput {
            field: "knowledge_export.sources",
            ..
        })
    ));
}

#[test]
fn knowledge_context_provider_compiles_fact_history_conflict_and_unknown_sections() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, fixture.redis_document());
    publish(&mut ledger, fixture.postgres_document());
    publish(&mut ledger, fixture.mysql_disagreement());
    let backend_query = query(&fixture, ledger.snapshot(), "backend", 250);
    let material =
        KnowledgeContextAdapter::prepare(&ledger, &backend_query).expect("provider prepares");
    assert_eq!(
        material.provider.snapshot().expect("snapshot"),
        provider_snapshot(&material.result)
    );

    let backend_compile_request =
        compile_request(&backend_query, provider_snapshot(&material.result));
    let compiled = ContextCompiler::new([13_u8; 32])
        .expect("compiler key valid")
        .compile(
            &backend_compile_request,
            &material.provider,
            &ReferenceTokenizer,
        )
        .expect("knowledge pack compiles");
    assert_eq!(compiled.pack.purpose, PackPurpose::Knowledge);
    assert_eq!(compiled.pack.sections.conflicts.len(), 1);
    assert_eq!(compiled.pack.sections.facts.len(), 2);
    assert!(!compiled.pack.sections.timeline.is_empty());

    let unknown_query = query(&fixture, ledger.snapshot(), "migration_rationale", 250);
    let unknown = KnowledgeContextAdapter::prepare(&ledger, &unknown_query)
        .expect("unknown provider prepares");
    let compiled_unknown = ContextCompiler::new([14_u8; 32])
        .expect("compiler key valid")
        .compile(
            &compile_request(&unknown_query, provider_snapshot(&unknown.result)),
            &unknown.provider,
            &ReferenceTokenizer,
        )
        .expect("unknown pack compiles");
    // The compiler may add a second, deterministic missing-facet marker beside
    // the source-level unknown. Both preserve uncertainty instead of inventing
    // an answer.
    assert!(!compiled_unknown.pack.sections.unknowns.is_empty());
}

#[test]
fn knowledge_context_propagates_source_use_policy_before_materialization() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut document = fixture.postgres_document();
    document.envelope.use_policy.influence_response = contextdb_core::PolicyDecision::Deny;
    document.envelope.use_policy.mention_explicitly = contextdb_core::PolicyDecision::Deny;
    let mut ledger = KnowledgeLedger::default();
    publish(&mut ledger, document);
    let knowledge_query = query(&fixture, ledger.snapshot(), "backend", 250);
    let material = KnowledgeContextAdapter::prepare(&ledger, &knowledge_query)
        .expect("policy-bound provider prepares");
    let labels = material
        .provider
        .candidate_labels()
        .expect("labels are available without payload materialization");
    let fact = labels
        .iter()
        .find(|label| label.id.to_string().contains("knowledge:fact:"))
        .expect("fact policy label exists");
    assert_eq!(
        fact.use_policy.influence,
        contextdb_core::PolicyDecision::Deny
    );
    assert_eq!(
        fact.use_policy.mention,
        contextdb_core::PolicyDecision::Deny
    );
    assert_eq!(
        fact.use_policy.disclosure,
        contextdb_context::DisclosureRule::DoNotDisclose
    );

    let compiled = ContextCompiler::new([15_u8; 32])
        .expect("compiler key valid")
        .compile(
            &compile_request(&knowledge_query, provider_snapshot(&material.result)),
            &material.provider,
            &ReferenceTokenizer,
        )
        .expect("policy-filtered pack compiles");
    assert!(compiled.pack.sections.facts.is_empty());
    assert!(!compiled.pack.sections.unknowns.is_empty());
}

#[test]
fn bench_c_reference_report_covers_support_conflict_unknown_and_citations() {
    let fixture = BenchCFixture::canonical().expect("fixture is valid");
    let mut ledger = KnowledgeLedger::default();
    let redis = publish(&mut ledger, fixture.redis_document());
    let postgres = publish(&mut ledger, fixture.postgres_document());
    let current = ledger
        .query(&query(&fixture, postgres.snapshot, "backend", 250))
        .expect("current query");
    let historical = ledger
        .query(&query(&fixture, postgres.snapshot, "backend", 100))
        .expect("historical query");
    let rationale = ledger
        .query(&query(
            &fixture,
            postgres.snapshot,
            "migration_rationale",
            250,
        ))
        .expect("unknown query");
    let past_unknown = ledger
        .query(&query(&fixture, redis.snapshot, "backend", 250))
        .expect("past unknown query");
    let disputed_snapshot = publish(&mut ledger, fixture.mysql_disagreement()).snapshot;
    let disputed = ledger
        .query(&query(&fixture, disputed_snapshot, "backend", 250))
        .expect("conflict query");
    let restored_snapshot = publish(&mut ledger, fixture.mysql_retraction()).snapshot;
    let restored = ledger
        .query(&query(&fixture, restored_snapshot, "backend", 250))
        .expect("restored query");
    let evidence: BTreeSet<_> = ledger
        .export()
        .sources
        .values()
        .flatten()
        .flat_map(|revision| revision.evidence.iter().map(|evidence| evidence.id))
        .collect();
    let cases = [
        BenchCCase {
            id: "current",
            result: &current,
            expected: BenchCExpectedState::Supported {
                object: ClaimObject::String("PostgreSQL".to_owned()),
            },
            permitted_evidence: &evidence,
            stale_summary_selected: false,
            rendered_tokens: 60,
        },
        BenchCCase {
            id: "historical",
            result: &historical,
            expected: BenchCExpectedState::Supported {
                object: ClaimObject::String("Redis".to_owned()),
            },
            permitted_evidence: &evidence,
            stale_summary_selected: false,
            rendered_tokens: 65,
        },
        BenchCCase {
            id: "rationale-unknown",
            result: &rationale,
            expected: BenchCExpectedState::Unknown,
            permitted_evidence: &evidence,
            stale_summary_selected: false,
            rendered_tokens: 20,
        },
        BenchCCase {
            id: "system-time-unknown",
            result: &past_unknown,
            expected: BenchCExpectedState::Unknown,
            permitted_evidence: &evidence,
            stale_summary_selected: false,
            rendered_tokens: 20,
        },
        BenchCCase {
            id: "disagreement",
            result: &disputed,
            expected: BenchCExpectedState::Disputed {
                objects: vec![
                    ClaimObject::String("MySQL".to_owned()),
                    ClaimObject::String("PostgreSQL".to_owned()),
                ],
            },
            permitted_evidence: &evidence,
            stale_summary_selected: false,
            rendered_tokens: 90,
        },
        BenchCCase {
            id: "retracted",
            result: &restored,
            expected: BenchCExpectedState::Supported {
                object: ClaimObject::String("PostgreSQL".to_owned()),
            },
            permitted_evidence: &evidence,
            stale_summary_selected: false,
            rendered_tokens: 55,
        },
    ];
    let report = BenchCEvaluator::evaluate(&cases);
    assert!(report.meets(BenchCThresholds::default()));
    assert_eq!(report.hallucinated_evidence_rate, 0.0);
    assert_eq!(report.stale_summary_rate, 0.0);
}

#[test]
fn bench_c_demo_is_deterministic_and_meets_declared_thresholds() {
    let left = run_bench_c_demo().expect("first demo succeeds");
    let right = run_bench_c_demo().expect("second demo succeeds");
    assert_eq!(left, right);
    assert!(
        left.report.meets(BenchCThresholds::default()),
        "report: {:?}",
        left.report
    );
    assert_eq!(left.report.correct_supported_cases, 3);
    assert_eq!(left.report.hallucinated_citations, 0);
}

#[test]
fn bench_c_evaluator_detects_stale_summary_and_hallucinated_evidence() {
    let demo = run_bench_c_demo().expect("demo succeeds");
    let permitted_evidence = BTreeSet::new();
    let adversarial = [BenchCCase {
        id: "adversarial-output",
        result: &demo.current,
        expected: BenchCExpectedState::Supported {
            object: ClaimObject::String("PostgreSQL".to_owned()),
        },
        permitted_evidence: &permitted_evidence,
        stale_summary_selected: true,
        rendered_tokens: 60,
    }];
    let report = BenchCEvaluator::evaluate(&adversarial);
    assert_eq!(report.stale_summary_rate, 1.0);
    assert_eq!(report.hallucinated_evidence_rate, 1.0);
}

fn provider_snapshot(result: &KnowledgeQueryResult) -> contextdb_recall::ProviderSnapshot {
    let commit = result.snapshot.commit_seq.get();
    contextdb_recall::ProviderSnapshot {
        database_id: "contextdb:knowledge".to_owned(),
        commit_seq: commit,
        watermarks: contextdb_recall::RecallWatermarks {
            journal: commit,
            semantic: commit,
            lexical: 0,
            vector: BTreeMap::new(),
            graph: 0,
            hierarchy: BTreeMap::from([("knowledge-source".to_owned(), commit)]),
        },
    }
}

fn compile_request(
    query: &KnowledgeQuery,
    snapshot: contextdb_recall::ProviderSnapshot,
) -> CompileRequest {
    CompileRequest {
        pack_id: contextdb_core::ContextPackId::new(),
        snapshot,
        principal: query.principal.clone(),
        filter_digest: "bench-c-policy-filter-v1".to_owned(),
        purpose: PackPurpose::Knowledge,
        scopes: query.principal.scopes.clone(),
        temporal_view: TemporalConstraint::Bitemporal {
            valid_during: contextdb_core::TimeRange::open_ended(query.valid_at),
            known_at: query.known_at.commit_seq,
        },
        required_facets: vec![PackFacetRequirement {
            name: query.predicate_key.clone(),
            minimum_confidence_micros: 0,
            require_evidence: false,
        }],
        budgets: ContextBudgets {
            hard_tokens: 20_000,
            soft_tokens: 16_000,
            max_blocks: 64,
            max_evidence_blocks: 64,
            max_raw_evidence_tokens: 8_000,
            max_history_tokens: 8_000,
            max_conflict_tokens: 4_000,
            max_serialized_bytes: 1_000_000,
            max_selection_evaluations: 128,
        },
        model_profile: ModelProfile {
            id: "bench-c-model".to_owned(),
            family: "deterministic-fixture".to_owned(),
            tokenizer_id: ReferenceTokenizer::ID.to_owned(),
            renderer: RendererKind::CanonicalJson,
            max_context_tokens: 32_000,
            reserved_output_tokens: 2_000,
            preferred_structured_format: StructuredFormat::Json,
            supports_tool_results: false,
            supports_native_citations: true,
            supports_prompt_caching: false,
            position_profile: PositionProfile::EvidenceAdjacent,
            instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
            max_schema_complexity: 64,
            external_processing: false,
        },
        explicit_memory_request: true,
        require_primary_evidence: true,
        continuation: None,
    }
}

proptest! {
    #[test]
    fn independent_source_ingestion_order_does_not_change_current_answer(reverse in any::<bool>()) {
        let fixture = BenchCFixture::canonical().expect("fixture is valid");
        let mut documents = vec![fixture.postgres_document(), fixture.mysql_disagreement()];
        if reverse {
            documents.reverse();
        }
        let mut ledger = KnowledgeLedger::default();
        for document in documents {
            publish(&mut ledger, document);
        }
        let result = ledger
            .query(&query(&fixture, ledger.snapshot(), "backend", 250))
            .expect("query succeeds");
        let KnowledgeAnswerState::Disputed { alternatives, .. } = result.state else {
            prop_assert!(false, "expected disagreement");
            return Ok(());
        };
        let objects: Vec<_> = alternatives.into_iter().map(|alternative| alternative.object).collect();
        prop_assert_eq!(objects, vec![
            ClaimObject::String("MySQL".to_owned()),
            ClaimObject::String("PostgreSQL".to_owned()),
        ]);
    }
}
