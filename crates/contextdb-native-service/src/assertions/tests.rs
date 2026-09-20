use std::{
    sync::{Arc, Barrier},
    time::Duration,
};

use contextdb_core::*;
use contextdb_service::{CaptureRequest, EventInterpretation, StateCoverageGap};

use super::*;

mod preparation;

fn budget() -> QueryBudget {
    QueryBudget::new(
        20_000,
        32 * 1024 * 1024,
        Duration::from_secs(20),
        Default::default(),
    )
}
fn capture(sequence: u64, text: &str) -> CaptureRequest {
    let mut request = crate::capture::tests::request(sequence, text);
    request.context.request.subject_id = MemorySubjectId::from_uuid(uuid::Uuid::from_u128(10))
        .expect("native assertion fixture")
        .to_string();
    request.context.request.audiences =
        BTreeSet::from([request.context.request.subject_id.clone()]);
    request
}
fn key(input: &CaptureRequest) -> StateKey {
    StateKey {
        subject: NodeId::from_uuid(uuid::Uuid::from_u128(20)).expect("native assertion fixture"),
        predicate: PredicateId::from_uuid(uuid::Uuid::from_u128(21))
            .expect("native assertion fixture"),
        scope: *input
            .event
            .scope_ids
            .first()
            .expect("native assertion fixture"),
    }
}
fn authority(input: &CaptureRequest) -> SourceAuthority {
    SourceAuthority {
        adapter_id: input.event.adapter_id.clone(),
        actor_id: input.context.actor_id.clone(),
        role: input.event.role,
    }
}
fn policy(input: &CaptureRequest) -> AuthorityPolicy {
    AuthorityPolicy {
        key: key(input),
        version: RevisionNumber::FIRST,
        grants: vec![AssertionGrant {
            source: authority(input),
            stance: AssertionStance::Decision,
        }],
    }
}
fn pipeline() -> PipelineIdentity {
    PipelineIdentity {
        name: "verified-fixture-interpreter".into(),
        version: "1".into(),
        schema_version: "1".into(),
    }
}
fn assertion(
    input: &CaptureRequest,
    value: &str,
    start: i64,
    end: Option<i64>,
    supersedes: Vec<ClaimId>,
) -> SourceAssertion {
    let key = key(input);
    let id = ClaimId::new();
    let evidence_id = EvidenceId::new();
    let owner: MemorySubjectId = input
        .context
        .request
        .subject_id
        .parse()
        .expect("native assertion fixture");
    let actor = ActorId::new();
    let digest = input
        .event
        .payload
        .digest()
        .expect("native assertion fixture");
    let span = OriginalSourceSpan {
        event_id: input.event.event_id,
        payload_digest: digest,
        start: 0,
        end: RawSource::from(&input.event)
            .byte_length
            .expect("native assertion fixture"),
        span_digest: digest,
    };
    let envelope = SemanticEnvelope {
        scopes: NonEmptyVec::new(ScopeRef {
            kind: ScopeKind::Repository,
            id: key.scope,
            inheritance: ScopeInheritance::Exact,
        }),
        perspective: Perspective {
            knower: owner,
            experiencer: None,
            narrator: actor,
            role: EpistemicRole::Asserter,
        },
        ownership: OwnershipPolicy {
            owners: NonEmptyVec::new(owner),
            audience_grants: vec![],
            allowed_purposes: BTreeSet::from([Purpose::UserSpecified("assist".into())]),
            modification: ModificationPolicy {
                owners_may_modify: true,
                delegates_may_modify: false,
                system_may_derive: true,
            },
        },
        consent: ConsentPolicy {
            required: false,
            decisions: vec![],
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
            labels: BTreeSet::new(),
            required_compartments: BTreeSet::new(),
            allow_external_processing: false,
        },
        derivation: DerivationRef {
            id: DerivationId::new(),
            kind: DerivationKind::ActorAssertion,
            actor: Some(actor),
            model_call: None,
            pipeline: pipeline(),
            inputs: vec![LineageNode::Evidence { id: evidence_id }],
        },
    };
    SourceAssertion {
        claim: Claim {
            id,
            workspace_id: input.event.workspace_id,
            subject: key.subject,
            predicate: key.predicate,
            created_seq: CommitSeq::GENESIS,
        },
        revision: ClaimRevision {
            claim_id: id,
            revision: RevisionNumber::FIRST,
            object: ClaimObject::String(value.into()),
            temporal: BitemporalRange {
                valid_time: TimeRange::new(TimestampMicros(start), end.map(TimestampMicros))
                    .expect("native assertion fixture"),
                transaction_time: CommitRange::current(CommitSeq::GENESIS),
            },
            epistemic: EpistemicState {
                basis: EpistemicBasis::ActorAssertion,
                acceptance: AcceptanceState::Accepted,
                conflict: ConflictState::None,
                lifecycle: LifecycleState::Active,
            },
            confidence: ConfidenceProfile {
                overall: 1.0,
                source_trust: 1.0,
                extraction_quality: 1.0,
                corroboration: 0.0,
            },
            source_families: BTreeSet::from([input.event.source_id.to_string()]),
            evidence: vec![evidence_id],
            supersedes,
            envelope,
        },
        key,
        stance: AssertionStance::Decision,
        source: authority(input),
        originating_event: input.event.event_id,
        original_evidence: vec![span],
    }
}
fn change(assertion: SourceAssertion) -> AssertionMutation {
    AssertionMutation::Assert {
        assertion: Box::new(assertion),
    }
}
fn publication(
    service: &NativeService,
    input: &CaptureRequest,
    retry: &str,
    mutations: Vec<AssertionMutation>,
) -> PublishAssertionsRequest {
    let window = service
        .interpretation_inputs(&input.context, key(input).scope, &mut budget())
        .expect("native assertion fixture");
    let origins: BTreeSet<_> = mutations
        .iter()
        .filter_map(|mutation| match mutation {
            AssertionMutation::Assert { assertion } => Some(assertion.originating_event),
            AssertionMutation::Retract { retraction } => Some(retraction.originating_event),
            _ => None,
        })
        .collect();
    PublishAssertionsRequest {
        context: input.context.clone(),
        idempotency_key: retry.into(),
        scope: key(input).scope,
        expected_scope_epoch: window.scope_epoch,
        covered_through: window.through,
        pipeline: pipeline(),
        interpretations: window
            .events
            .into_iter()
            .map(|event_id| EventInterpretation {
                event_id,
                disposition: if origins.contains(&event_id) {
                    InterpretationDisposition::Interpreted
                } else {
                    InterpretationDisposition::NoStateChange
                },
            })
            .collect(),
        mutations,
        after_receipt: None,
    }
}
fn publish(
    service: &NativeService,
    input: &CaptureRequest,
    retry: &str,
    changes: Vec<AssertionMutation>,
) -> AssertionReceipt {
    service
        .publish_assertions(publication(service, input, retry, changes), &mut budget())
        .expect("native assertion fixture")
}
fn query(
    service: &NativeService,
    input: &CaptureRequest,
    valid: i64,
    known: Option<u64>,
) -> StateView {
    service
        .resolve_state(
            ResolveStateRequest {
                context: input.context.clone(),
                key: key(input),
                known_at: known,
                valid_at: TimestampMicros(valid),
                after_receipt: None,
            },
            &mut budget(),
        )
        .expect("native assertion fixture")
}
fn value(view: &StateView) -> Option<&str> {
    match &view.resolution.state {
        ResolvedState::Known {
            answer:
                StateAlternative {
                    value: ClaimObject::String(value),
                    ..
                },
        } => Some(value),
        _ => None,
    }
}
fn initial(service: &NativeService) -> (CaptureRequest, SourceAssertion, AssertionReceipt) {
    let input = capture(1, "Нельзя загружать данные в облако. Только локально.");
    service
        .append_event(input.clone())
        .expect("native assertion fixture");
    let assertion = assertion(&input, "local-only", 0, None, vec![]);
    let receipt = publish(
        service,
        &input,
        "initial-state",
        vec![
            AssertionMutation::Policy {
                policy: policy(&input),
            },
            change(assertion.clone()),
        ],
    );
    (input, assertion, receipt)
}

#[test]
fn assistant_cannot_promote_or_cancel_user_decision_and_journal_survives_reopen() {
    let dir = tempfile::tempdir().expect("native assertion fixture");
    let service = NativeService::open(dir.path(), "assertions-db", [7; 32])
        .expect("native assertion fixture");
    let (input, original, _) = initial(&service);
    assert_eq!(value(&query(&service, &input, 1, None)), Some("local-only"));
    let mut proposal = capture(2, "Давайте всё загрузим в облако.");
    proposal.event.role = EventRole::Assistant;
    service
        .append_event(proposal.clone())
        .expect("native assertion fixture");
    let unresolved = query(&service, &input, 1, None);
    assert_eq!(unresolved.resolution.state, ResolvedState::Incomplete);
    assert_eq!(unresolved.pending_events, vec![proposal.event.event_id]);
    let mut proposed = assertion(&proposal, "upload", 0, None, vec![original.claim.id]);
    let rejected = publication(
        &service,
        &proposal,
        "forged-decision",
        vec![change(proposed.clone())],
    );
    assert_eq!(
        service
            .publish_assertions(rejected, &mut budget())
            .expect_err("invalid state must be rejected")
            .code,
        ErrorCode::PermissionDenied
    );
    proposed.stance = AssertionStance::Proposed;
    proposed.revision.epistemic.acceptance = AcceptanceState::Proposed;
    proposed.revision.supersedes.clear();
    let request = publication(&service, &proposal, "proposal", vec![change(proposed)]);
    let receipt = service
        .publish_assertions(request.clone(), &mut budget())
        .expect("native assertion fixture");
    assert_eq!(
        service
            .publish_assertions(request.clone(), &mut budget())
            .expect("native assertion fixture"),
        receipt
    );
    let mut changed = request.clone();
    changed.pipeline.version = "2".into();
    assert_eq!(
        service
            .publish_assertions(changed, &mut budget())
            .expect_err("invalid state must be rejected")
            .code,
        ErrorCode::IdempotencyConflict
    );
    let view = query(&service, &input, 1, None);
    assert_eq!(value(&view), Some("local-only"));
    assert_eq!(view.assertions.len(), 2);
    assert!(view.resolution.retired_claims.is_empty());
    service
        .verify_native(true)
        .expect("native assertion fixture");
    drop(service);
    let reopened = NativeService::open(dir.path(), "assertions-db", [7; 32])
        .expect("native assertion fixture");
    assert_eq!(
        value(&query(&reopened, &input, 1, None)),
        Some("local-only")
    );
    assert_eq!(
        reopened
            .publish_assertions(request, &mut budget())
            .expect("native assertion fixture"),
        receipt
    );
    reopened
        .verify_native(true)
        .expect("native assertion fixture");
}

#[test]
fn separate_knowledge_and_valid_times_preserve_future_retroactive_and_rollback_changes() {
    let dir = tempfile::tempdir().expect("native assertion fixture");
    let service =
        NativeService::open(dir.path(), "temporal-db", [8; 32]).expect("native assertion fixture");
    let (input, original, first) = initial(&service);
    let next = capture(2, "Со 100 разрешаю облако.");
    service
        .append_event(next.clone())
        .expect("native assertion fixture");
    let future = assertion(&next, "cloud", 100, None, vec![original.claim.id]);
    let second = publish(&service, &next, "future", vec![change(future.clone())]);
    let before = query(&service, &input, 99, None);
    assert_eq!(value(&before), Some("local-only"));
    assert_eq!(before.resolution.valid_until, Some(TimestampMicros(100)));
    assert_eq!(value(&query(&service, &input, 100, None)), Some("cloud"));
    assert_eq!(
        value(&query(&service, &input, 100, Some(first.workspace_commit))),
        Some("local-only")
    );
    let correction = capture(3, "Уточняю: с 50 до 75 была разрешена песочница.");
    service
        .append_event(correction.clone())
        .expect("native assertion fixture");
    publish(
        &service,
        &correction,
        "retroactive",
        vec![change(assertion(
            &correction,
            "sandbox",
            50,
            Some(75),
            vec![original.claim.id],
        ))],
    );
    assert_eq!(value(&query(&service, &input, 60, None)), Some("sandbox"));
    assert_eq!(
        value(&query(&service, &input, 60, Some(second.workspace_commit))),
        Some("local-only")
    );
    assert_eq!(
        value(&query(&service, &input, 90, None)),
        Some("local-only")
    );
    let rollback = capture(4, "С 200 возвращаю только локальную обработку.");
    service
        .append_event(rollback.clone())
        .expect("native assertion fixture");
    let rollback_assertion = assertion(&rollback, "local-only", 200, None, vec![future.claim.id]);
    publish(
        &service,
        &rollback,
        "rollback",
        vec![change(rollback_assertion.clone())],
    );
    assert_eq!(
        value(&query(&service, &input, 200, None)),
        Some("local-only")
    );
    let retract = capture(5, "С 250 отзываю решение, новое пока не принято.");
    service
        .append_event(retract.clone())
        .expect("native assertion fixture");
    let support = assertion(&retract, "unused", 250, None, vec![]);
    publish(
        &service,
        &retract,
        "retract",
        vec![AssertionMutation::Retract {
            retraction: AssertionRetraction {
                key: key(&retract),
                target: rollback_assertion.claim.id,
                temporal: support.revision.temporal,
                source: support.source,
                originating_event: retract.event.event_id,
                original_evidence: support.original_evidence,
            },
        }],
    );
    assert_eq!(
        query(&service, &input, 250, None).resolution.state,
        ResolvedState::Unknown
    );
    service
        .verify_native(true)
        .expect("native assertion fixture");
}

#[test]
fn branches_conflicts_and_scoped_freshness_do_not_choose_a_similarity_winner() {
    let dir = tempfile::tempdir().expect("native assertion fixture");
    let service =
        NativeService::open(dir.path(), "branches-db", [9; 32]).expect("native assertion fixture");
    let (input, original, _) = initial(&service);
    let mut branch = capture(1, "Для этой ветки разрешено облако.");
    let branch_scope = ScopeId::new();
    branch.event.event_id = ObservationId::new();
    branch.event.producer_id = StreamId::new();
    branch.event.scope_ids = BTreeSet::from([branch_scope]);
    branch.context.request.scopes = BTreeSet::from([branch_scope.to_string()]);
    service
        .append_event(branch.clone())
        .expect("native assertion fixture");
    let other = assertion(&branch, "cloud", 0, None, vec![]);
    publish(
        &service,
        &branch,
        "branch",
        vec![
            AssertionMutation::Policy {
                policy: policy(&branch),
            },
            change(other),
        ],
    );
    assert_eq!(value(&query(&service, &input, 0, None)), Some("local-only"));
    assert_eq!(value(&query(&service, &branch, 0, None)), Some("cloud"));
    for sequence in 2..=145 {
        let mut noise = branch.clone();
        noise.event.event_id = ObservationId::new();
        noise.event.producer_sequence = sequence;
        noise.idempotency_key = format!("noise-{sequence}");
        service
            .append_event(noise)
            .expect("native assertion fixture");
    }
    let mut bounded = QueryBudget::new(12, 128 * 1024, Duration::from_secs(5), Default::default());
    let view = service
        .resolve_state(
            ResolveStateRequest {
                context: input.context.clone(),
                key: key(&input),
                known_at: None,
                valid_at: TimestampMicros(0),
                after_receipt: None,
            },
            &mut bounded,
        )
        .expect("native assertion fixture");
    assert_eq!(value(&view), Some("local-only"));
    let contradictory = capture(2, "Можно облако.");
    service
        .append_event(contradictory.clone())
        .expect("native assertion fixture");
    // Advance bounded raw windows; unrelated branch work is not claimed as understood.
    while service
        .interpretation_inputs(&input.context, key(&input).scope, &mut budget())
        .expect("native assertion fixture")
        .more
    {
        publish(
            &service,
            &input,
            &format!(
                "advance-{}",
                service
                    .workspace_state(
                        &service
                            .engine
                            .begin_read(SnapshotSelector::Latest)
                            .expect("native assertion fixture"),
                        &input.context.request.workspace_id
                    )
                    .expect("native assertion fixture")
                    .watermarks
                    .journal
            ),
            vec![],
        );
        assert_eq!(
            query(&service, &input, 0, None).resolution.state,
            ResolvedState::Incomplete
        );
    }
    let conflict = assertion(&contradictory, "cloud", 0, None, vec![]);
    publish(
        &service,
        &contradictory,
        "conflict",
        vec![change(conflict.clone())],
    );
    assert!(
        matches!(query(&service, &input, 0, None).resolution.state, ResolvedState::Conflict { ref alternatives } if alternatives.len() == 2)
    );
    let authorized = query(&service, &input, 0, None);
    let mut reversed = authorized.assertions.clone();
    reversed.reverse();
    let resolved = resolve_assertions(
        &authorized.authority,
        &reversed,
        &[],
        CommitSeq::new(u64::MAX),
        TimestampMicros(0),
        true,
    )
    .expect("native assertion fixture");
    assert_eq!(resolved.state, authorized.resolution.state);
    assert!(!resolved.retired_claims.contains(&original.claim.id));
    service
        .verify_native(true)
        .expect("native assertion fixture");
}

#[test]
fn producer_gaps_partial_sources_and_uninterpreted_text_block_current_state() {
    let dir = tempfile::tempdir().expect("native assertion fixture");
    let service =
        NativeService::open(dir.path(), "gaps-db", [10; 32]).expect("native assertion fixture");
    let (input, _, _) = initial(&service);
    let later = capture(3, "Третий пакет, второй потерян.");
    service
        .append_event(later.clone())
        .expect("native assertion fixture");
    publish(&service, &later, "gap-seen", vec![]);
    let view = query(&service, &input, 0, None);
    assert_eq!(view.resolution.state, ResolvedState::Incomplete);
    assert!(view.coverage_gaps.contains(&StateCoverageGap::CaptureGap));
    let missing = capture(2, "Второй пакет найден, изменений нет.");
    service
        .append_event(missing.clone())
        .expect("native assertion fixture");
    publish(&service, &missing, "gap-filled", vec![]);
    assert_eq!(value(&query(&service, &input, 0, None)), Some("local-only"));
    let mut partial = capture(4, "Нельзя...");
    partial.event.coverage = EventCoverage::PartialObservation;
    partial.event.upstream_truncated = true;
    service
        .append_event(partial.clone())
        .expect("native assertion fixture");
    publish(&service, &partial, "partial-cannot-clear", vec![]);
    let view = query(&service, &input, 0, None);
    assert_eq!(view.resolution.state, ResolvedState::Incomplete);
    assert!(view.pending_events.contains(&partial.event.event_id));
    service
        .verify_native(true)
        .expect("native assertion fixture");
}

#[test]
fn negative_overlay_checks_current_evidence_acl_before_reading_denied_content() {
    let dir = tempfile::tempdir().expect("native assertion fixture");
    let service = NativeService::open(dir.path(), "revocation-db", [11; 32])
        .expect("native assertion fixture");
    let (input, first, old) = initial(&service);
    let update = capture(2, "Разрешаю облако вместо локального режима.");
    service
        .append_event(update.clone())
        .expect("native assertion fixture");
    let replacement = assertion(&update, "cloud", 0, None, vec![first.claim.id]);
    publish(
        &service,
        &update,
        "replace",
        vec![change(replacement.clone())],
    );
    service
        .revoke_original(
            &input.context,
            update.event.event_id,
            "revoke-new",
            &mut budget(),
        )
        .expect("native assertion fixture");
    assert!(
        service
            .maintain_custody(&input.context, 64, &mut budget())
            .expect("complete current custody before state resolution")
            .caught_up
    );
    assert_eq!(
        query(&service, &input, 0, None).resolution.state,
        ResolvedState::Incomplete
    );
    assert_eq!(
        value(&query(&service, &input, 0, Some(old.workspace_commit))),
        Some("local-only")
    );
    service
        .verify_native(true)
        .expect("native assertion fixture");
    let mut tx = service
        .engine
        .begin_write()
        .expect("native assertion fixture");
    tx.put(
        &service.keyspaces.continuous,
        claim_key(replacement.claim.id),
        b"forbidden corrupt body".to_vec(),
    )
    .expect("native assertion fixture");
    tx.commit(Durability::Sync)
        .expect("native assertion fixture");
    assert_eq!(
        query(&service, &input, 0, None).resolution.state,
        ResolvedState::Incomplete
    );
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("invalid state must be rejected")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn compare_publish_and_receipt_fences_reject_races_without_losing_originals() {
    let dir = tempfile::tempdir().expect("native assertion fixture");
    let service = Arc::new(
        NativeService::open(dir.path(), "race-db", [12; 32]).expect("native assertion fixture"),
    );
    let (input, _, first) = initial(&service);
    let stale_request = publication(&service, &input, "stale-analysis", vec![]);
    let next = capture(2, "Новое ограничение ещё не разобрано.");
    let capture_receipt = service
        .append_event(next.clone())
        .expect("native assertion fixture");
    assert_eq!(
        service
            .publish_assertions(stale_request, &mut budget())
            .expect_err("invalid state must be rejected")
            .code,
        ErrorCode::IndexTooStale
    );
    let fenced = ResolveStateRequest {
        context: input.context.clone(),
        key: key(&input),
        known_at: Some(first.workspace_commit),
        valid_at: TimestampMicros(0),
        after_receipt: Some(capture_receipt),
    };
    assert_eq!(
        service
            .resolve_state(fenced, &mut budget())
            .expect_err("invalid state must be rejected")
            .code,
        ErrorCode::InvalidArgument
    );
    let request = publication(&service, &input, "concurrent-exact-retry", vec![]);
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let service = Arc::clone(&service);
            let barrier = Arc::clone(&barrier);
            let request = request.clone();
            std::thread::spawn(move || {
                barrier.wait();
                service
                    .publish_assertions(request, &mut budget())
                    .expect("native assertion fixture")
            })
        })
        .collect();
    let receipts: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("native assertion fixture"))
        .collect();
    assert!(receipts.iter().all(|receipt| receipt == &receipts[0]));
    service
        .verify_native(true)
        .expect("native assertion fixture");
}

#[test]
fn semantic_journal_reconstructs_all_derived_rows_and_detects_whole_family_loss() {
    let dir = tempfile::tempdir().expect("native assertion fixture");
    let service = NativeService::open(dir.path(), "integrity-db", [13; 32])
        .expect("native assertion fixture");
    initial(&service);
    service
        .verify_native(true)
        .expect("native assertion fixture");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("native assertion fixture");
    let mut tx = service
        .engine
        .begin_write()
        .expect("native assertion fixture");
    for entry in snapshot
        .scan_prefix(&service.keyspaces.continuous, b"state/")
        .expect("native assertion fixture")
    {
        tx.delete(&service.keyspaces.continuous, entry.key)
            .expect("native assertion fixture");
    }
    tx.commit(Durability::Sync)
        .expect("native assertion fixture");
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("invalid state must be rejected")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn source_authority_and_lineage_cannot_be_forged_and_backup_preserves_resolution() {
    let (_authority_directory, ledger) = crate::suppression::tests::authority("authority-db");
    use contextdb_service::{CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest};
    let dir = tempfile::tempdir().expect("source directory");
    let restored_dir = tempfile::tempdir().expect("restore directory");
    let service =
        NativeService::open_with_suppression(dir.path(), "authority-db", [14; 32], ledger.clone())
            .expect("open");
    let (input, original, _) = initial(&service);
    let mut forbidden_policy = policy(&input);
    forbidden_policy.grants[0].source.role = EventRole::Assistant;
    assert!(forbidden_policy.validate().is_err());
    let mut reader = input.clone();
    reader.context.request.subject_id = "another-reader".into();
    reader.context.request.audiences.clear();
    let denied = ResolveStateRequest {
        context: reader.context,
        key: key(&input),
        known_at: None,
        valid_at: TimestampMicros(0),
        after_receipt: None,
    };
    assert_eq!(
        service
            .resolve_state(denied, &mut budget())
            .expect_err("authority ACL")
            .code,
        ErrorCode::PermissionDenied
    );
    let mut source = capture(2, "Предлагаю облако.");
    source.event.role = EventRole::Assistant;
    service
        .append_event(source.clone())
        .expect("proposal capture");
    let mut forged = assertion(&source, "cloud", 0, None, vec![original.claim.id]);
    forged.source.role = EventRole::User;
    assert_eq!(
        service
            .publish_assertions(
                publication(&service, &source, "forged-role", vec![change(forged)]),
                &mut budget()
            )
            .expect_err("captured role must match")
            .code,
        ErrorCode::PermissionDenied
    );
    let mut invented = assertion(&source, "cloud", 0, None, vec![]);
    invented.stance = AssertionStance::Proposed;
    invented.revision.epistemic.acceptance = AcceptanceState::Proposed;
    invented
        .revision
        .source_families
        .insert("invented-second-source".into());
    assert_eq!(
        service
            .publish_assertions(
                publication(&service, &source, "forged-family", vec![change(invented)]),
                &mut budget()
            )
            .expect_err("source families must match")
            .code,
        ErrorCode::InvalidArgument
    );
    publish(&service, &source, "covered-proposal", vec![]);
    let expected = query(&service, &input, 0, None);
    let backup = service
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("backup");
    let restored = NativeService::open_with_suppression(
        restored_dir.path(),
        "authority-db",
        [15; 32],
        ledger.clone(),
    )
    .expect("fresh restore target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: input.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore with rotated key");
    assert_eq!(
        query(&restored, &input, 0, None).resolution,
        expected.resolution
    );
    restored
        .verify_native(true)
        .expect("restored semantic closure");
}
