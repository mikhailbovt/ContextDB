use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use proptest::prelude::*;

use crate::test_support::{
    InMemoryHeadMacAuthorityV2, NonProductionCompositeHeadRepositoryV2,
    NonProductionKeyAuthorityAdapterV2, NonProductionManagedCopyDeletionAdapterV2,
};
use crate::*;

fn root(label: &str) -> StateRootV2 {
    StateRootV2::commit("p3-test", label.as_bytes()).expect("state root")
}

fn namespace(database: &str, workspace: &str, partition: &str) -> StateNamespaceV2 {
    StateNamespaceV2::new("p3-test-authority", database, workspace, partition).expect("namespace")
}

fn scope(database: &str, workspace: &str, owner: &str) -> DekScopeV2 {
    DekScopeV2::new(
        ContentHandleV2::generate().expect("content handle"),
        ErasureDomainV2::generate().expect("erasure domain"),
        ContentSecurityContextV2::new(
            database,
            workspace,
            "checkpoint.payload",
            owner,
            root("policy"),
            1,
        )
        .expect("context"),
    )
    .expect("scope")
}

fn head_payload(label: &str) -> CompositeHeadPayloadV2 {
    CompositeHeadPayloadV2 {
        projection_root: root(&format!("projection-{label}")),
        policy_root: root(&format!("policy-{label}")),
        key_catalog_root: root(&format!("keys-{label}")),
        deletion_workflow_root: root(&format!("deletion-{label}")),
        suppression: SuppressionBindingV2::Clear,
    }
}

fn applied<T>(outcome: AuthorityOperationOutcomeV2<T>) -> T {
    match outcome {
        AuthorityOperationOutcomeV2::Applied(value) => value,
        other => panic!("expected applied outcome, got {other:?}"),
    }
}

fn cas_applied(outcome: CompositeHeadCasOutcomeV2) -> AnchoredCompositeHeadV2 {
    match outcome {
        CompositeHeadCasOutcomeV2::Applied(value) => value,
        other => panic!("expected applied CAS, got {other:?}"),
    }
}

#[test]
fn production_key_create_or_get_is_idempotent_and_conflict_safe() {
    let adapter =
        NonProductionKeyAuthorityAdapterV2::random("key-boundary", "process-a").expect("adapter");
    let ns = namespace("db", "ws", "primary");
    let object_scope = scope("db", "ws", "owner-a");
    let request_id = OperationRequestIdV2::generate().expect("request ID");
    let request =
        ProductionKeyCreateRequestV2::new(request_id.clone(), ns.clone(), object_scope.clone())
            .expect("request");
    let first = applied(adapter.create_or_get(&request).expect("create"));
    match adapter.create_or_get(&request).expect("retry") {
        AuthorityOperationOutcomeV2::AlreadyApplied(value) => assert_eq!(value, first),
        other => panic!("expected idempotent replay, got {other:?}"),
    }

    let conflicting =
        ProductionKeyCreateRequestV2::new(request_id, ns.clone(), scope("db", "ws", "owner-b"))
            .expect("conflicting request");
    assert!(matches!(
        adapter
            .create_or_get(&conflicting)
            .expect("conflict outcome"),
        AuthorityOperationOutcomeV2::Conflict { .. }
    ));

    let same_scope_new_request = ProductionKeyCreateRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        ns,
        object_scope,
    )
    .expect("same scope request");
    match adapter
        .create_or_get(&same_scope_new_request)
        .expect("same-scope lookup")
    {
        AuthorityOperationOutcomeV2::AlreadyApplied(value) => assert_eq!(value, first),
        other => panic!("expected same-scope get, got {other:?}"),
    }
}

#[test]
fn key_destroy_ticket_rejects_stale_generation_and_forged_evidence() {
    let adapter =
        NonProductionKeyAuthorityAdapterV2::random("key-boundary", "process-a").expect("adapter");
    let ns = namespace("db", "ws", "primary");
    let create = ProductionKeyCreateRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        ns.clone(),
        scope("db", "ws", "owner"),
    )
    .expect("create request");
    let active = applied(adapter.create_or_get(&create).expect("create"));
    let destroy = ProductionKeyDestroyRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        ns.clone(),
        active.clone(),
    )
    .expect("destroy request");
    let ticket = applied(adapter.request_destroy(&destroy).expect("destroy request"));
    let ticket_json = serde_json::to_vec(&ticket).expect("ticket JSON");
    assert_eq!(
        KeyDestroyTicketV2::from_json_bounded(&ticket_json, adapter.provenance())
            .expect("recover ticket"),
        ticket
    );
    assert!(
        KeyDestroyTicketV2::from_json_bounded(
            &vec![b' '; MAX_PRODUCTION_KEY_OPERATION_JSON_BYTES_V2 + 1],
            adapter.provenance(),
        )
        .is_err()
    );

    let stale_destroy = ProductionKeyDestroyRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        ns.clone(),
        active.clone(),
    )
    .expect("stale destroy request shape");
    assert!(matches!(
        adapter
            .request_destroy(&stale_destroy)
            .expect("stale conflict"),
        AuthorityOperationOutcomeV2::Conflict { .. }
    ));

    let stale_describe = ProductionKeyDescribeRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        ns.clone(),
        active.key_handle().clone(),
        active.scope().clone(),
        3,
    )
    .expect("describe request");
    assert!(
        adapter
            .describe_strongly_consistent(&stale_describe)
            .is_err()
    );

    let pending_poll = ProductionKeyDestroyPollRequestV2::new(
        OperationRequestIdV2::generate().expect("poll ID"),
        ticket.clone(),
    );
    assert!(matches!(
        applied(adapter.poll_destroy(&pending_poll).expect("pending poll")),
        KeyDestroyPollV2::Pending { .. }
    ));

    let destroyed = adapter
        .complete_destroy_for_test(ticket.ticket_handle(), 50)
        .expect("destroy key");
    assert_eq!(
        destroyed.destroyed_descriptor().lifecycle(),
        KeyLifecycleV2::Destroyed
    );
    destroyed
        .verify_current(60, &adapter)
        .expect("current destruction evidence");
    let evidence = destroyed.authority_evidence();
    let encoded = serde_json::to_vec(evidence).expect("serialize evidence");
    let subject = key_destruction_subject(destroyed.ticket(), destroyed.destroyed_descriptor())
        .expect("subject");
    VerifiedAuthorityEvidenceV2::from_json_bounded(
        &encoded,
        AuthorityEvidenceKindV2::KeyDestroyed,
        adapter.provenance(),
        &ns,
        destroy.request_id(),
        &subject,
        60,
        &adapter,
    )
    .expect("verify evidence");

    let mut forged = serde_json::to_value(evidence).expect("evidence JSON");
    let signature = forged["signature"].as_array_mut().expect("signature array");
    signature[0] = serde_json::Value::from(signature[0].as_u64().expect("byte") ^ 1);
    let forged = serde_json::to_vec(&forged).expect("forged JSON");
    assert!(
        VerifiedAuthorityEvidenceV2::from_json_bounded(
            &forged,
            AuthorityEvidenceKindV2::KeyDestroyed,
            adapter.provenance(),
            &ns,
            destroy.request_id(),
            &subject,
            60,
            &adapter,
        )
        .is_err()
    );
    let other_ns = namespace("db-other", "ws", "primary");
    assert!(
        VerifiedAuthorityEvidenceV2::from_json_bounded(
            &encoded,
            AuthorityEvidenceKindV2::KeyDestroyed,
            adapter.provenance(),
            &other_ns,
            destroy.request_id(),
            &subject,
            60,
            &adapter,
        )
        .is_err()
    );
}

fn setup_repository_chain(
    labels: &[&str],
) -> (
    Arc<InMemoryHeadMacAuthorityV2>,
    NonProductionCompositeHeadRepositoryV2,
    Vec<AnchoredCompositeHeadV2>,
) {
    let ns = namespace("db", "ws", "primary");
    let mac = Arc::new(InMemoryHeadMacAuthorityV2::random("head-key").expect("MAC authority"));
    let repository =
        NonProductionCompositeHeadRepositoryV2::random("head-repository", "process-a", mac.clone())
            .expect("repository");
    let mut anchored: Vec<AnchoredCompositeHeadV2> = Vec::new();
    for (index, label) in labels.iter().enumerate() {
        let head = if let Some(previous) = anchored.last() {
            previous
                .head()
                .successor(&ns, head_payload(label), mac.as_ref())
                .expect("successor")
        } else {
            CompositeStateHeadV2::initial(ns.clone(), head_payload(label), mac.as_ref())
                .expect("initial head")
        };
        let request = CompositeHeadCasRequestV2::new(
            OperationRequestIdV2::generate().expect("request ID"),
            anchored.last().map(|value| value.anchor().clone()),
            head,
        )
        .expect("CAS request");
        let result = cas_applied(repository.compare_and_swap(&request).expect("CAS"));
        assert_eq!(result.head().sequence(), (index + 1) as u64);
        anchored.push(result);
    }
    (mac, repository, anchored)
}

#[test]
fn repository_initialization_idempotency_and_exact_conflict_are_explicit() {
    let ns = namespace("db", "ws", "primary");
    let mac = Arc::new(InMemoryHeadMacAuthorityV2::random("head-key").expect("MAC authority"));
    let repository =
        NonProductionCompositeHeadRepositoryV2::random("head-repository", "process-a", mac.clone())
            .expect("repository");
    let request_id = OperationRequestIdV2::generate().expect("request ID");
    let initial = CompositeStateHeadV2::initial(ns.clone(), head_payload("one"), mac.as_ref())
        .expect("initial head");
    let initialize =
        CompositeHeadCasRequestV2::new(request_id.clone(), None, initial).expect("initialize");
    let anchored = cas_applied(
        repository
            .compare_and_swap(&initialize)
            .expect("initialize CAS"),
    );
    assert_eq!(anchored.head().sequence(), 1);
    assert!(anchored.receipt().previous_anchor().is_none());
    assert!(matches!(
        repository
            .compare_and_swap(&initialize)
            .expect("idempotent CAS"),
        CompositeHeadCasOutcomeV2::AlreadyAnchored(_)
    ));

    let alternate = CompositeStateHeadV2::initial(ns, head_payload("alternate"), mac.as_ref())
        .expect("alternate initial");
    let conflicting =
        CompositeHeadCasRequestV2::new(request_id, None, alternate).expect("conflicting intent");
    assert!(matches!(
        repository.compare_and_swap(&conflicting).expect("conflict"),
        CompositeHeadCasOutcomeV2::Conflict { .. }
    ));

    let illegal_second = anchored
        .head()
        .successor(
            anchored.head().namespace(),
            head_payload("second"),
            mac.as_ref(),
        )
        .expect("second head");
    assert!(
        CompositeHeadCasRequestV2::new(
            OperationRequestIdV2::generate().expect("request ID"),
            None,
            illegal_second,
        )
        .is_err()
    );
}

#[test]
fn repository_ahead_requires_complete_signed_lineage() {
    let (_mac, repository, chain) = setup_repository_chain(&["one", "two", "three"]);
    let expected = chain[0].anchor().clone();
    assert!(
        CompositeHeadLoadRequestV2::new(
            OperationRequestIdV2::generate().expect("request ID"),
            namespace("other-db", "ws", "primary"),
            Some(expected.clone()),
        )
        .is_err()
    );
    let load = CompositeHeadLoadRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        expected.namespace().clone(),
        Some(expected.clone()),
    )
    .expect("load request");
    match repository.load(&load).expect("load") {
        CompositeHeadLoadOutcomeV2::Ahead { current, lineage } => {
            assert_eq!(current.anchor(), chain[2].anchor());
            assert_eq!(lineage.receipts().len(), 2);
            lineage
                .verify_current(4, &repository)
                .expect("current lineage receipts");
        }
        other => panic!("expected proven ahead, got {other:?}"),
    }

    assert!(matches!(
        classify_composite_head_load_v2(Some(&expected), Some(chain[2].clone()), None)
            .expect("classification"),
        CompositeHeadLoadOutcomeV2::MissingLineage {
            expected_sequence: 1,
            observed_sequence: 3
        }
    ));
    assert!(matches!(
        classify_composite_head_load_v2(Some(chain[2].anchor()), Some(chain[0].clone()), None,)
            .expect("rollback classification"),
        CompositeHeadLoadOutcomeV2::Rollback {
            expected_sequence: 3,
            observed_sequence: 1
        }
    ));
}

#[test]
fn lineage_rejects_missing_reordered_forked_and_oversized_receipts() {
    let (mac, main_repository, main) = setup_repository_chain(&["one", "two", "three"]);
    let receipts = main_repository
        .lineage_receipts_after_for_test(1)
        .expect("main receipts");
    assert_eq!(receipts.len(), 2);
    assert!(CompositeHeadLineageProofV2::try_new(
        main[0].anchor(),
        &main[2],
        vec![receipts[1].clone()],
    )
    .is_err());
    assert!(
        CompositeHeadLineageProofV2::try_new(
            main[0].anchor(),
            &main[2],
            vec![receipts[1].clone(), receipts[0].clone()],
        )
        .is_err()
    );

    let ns = main[0].head().namespace().clone();
    let fork_repository =
        NonProductionCompositeHeadRepositoryV2::random("head-repository", "process-a", mac.clone())
            .expect("fork repository");
    let fork_initial = CompositeHeadCasRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        None,
        main[0].head().clone(),
    )
    .expect("fork initial request");
    let fork_one = cas_applied(
        fork_repository
            .compare_and_swap(&fork_initial)
            .expect("fork initial"),
    );
    let fork_head = fork_one
        .head()
        .successor(&ns, head_payload("fork-two"), mac.as_ref())
        .expect("fork head");
    let fork_request = CompositeHeadCasRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        Some(fork_one.anchor().clone()),
        fork_head,
    )
    .expect("fork request");
    let fork_two = cas_applied(
        fork_repository
            .compare_and_swap(&fork_request)
            .expect("fork CAS"),
    );
    assert!(
        CompositeHeadLineageProofV2::try_new(
            main[0].anchor(),
            &main[2],
            vec![fork_two.receipt().clone(), receipts[1].clone()],
        )
        .is_err()
    );

    assert!(
        CompositeHeadLineageProofV2::try_new(
            main[0].anchor(),
            &main[1],
            vec![receipts[0].clone(); MAX_COMPOSITE_HEAD_LINEAGE_RECEIPTS_V2 + 1],
        )
        .is_err()
    );
}

#[test]
fn repository_receipt_rejects_signature_tamper_namespace_replay_and_divergence() {
    let (_mac, repository, main) = setup_repository_chain(&["one"]);
    let receipt = main[0].receipt();
    let evidence = receipt.authority_evidence();
    let subject =
        head_anchor_subject(receipt.previous_anchor(), receipt.anchor()).expect("subject");
    let bytes = serde_json::to_vec(evidence).expect("evidence JSON");
    let other_ns = namespace("other-db", "ws", "primary");
    assert!(
        VerifiedAuthorityEvidenceV2::from_json_bounded(
            &bytes,
            AuthorityEvidenceKindV2::CompositeHeadAnchored,
            repository.provenance(),
            &other_ns,
            evidence.request_id(),
            &subject,
            2,
            &repository,
        )
        .is_err()
    );

    let mut tampered = serde_json::to_value(evidence).expect("evidence JSON");
    tampered["signature"][0] =
        serde_json::Value::from(tampered["signature"][0].as_u64().expect("byte") ^ 1);
    assert!(
        VerifiedAuthorityEvidenceV2::from_json_bounded(
            &serde_json::to_vec(&tampered).expect("tampered JSON"),
            AuthorityEvidenceKindV2::CompositeHeadAnchored,
            repository.provenance(),
            main[0].head().namespace(),
            evidence.request_id(),
            &subject,
            2,
            &repository,
        )
        .is_err()
    );

    let (_, fork_repository, fork) = setup_repository_chain(&["different-one"]);
    assert!(matches!(
        classify_composite_head_load_v2(Some(main[0].anchor()), Some(fork[0].clone()), None,)
            .expect("divergence classification"),
        CompositeHeadLoadOutcomeV2::Divergence { sequence: 1, .. }
    ));
    assert_eq!(
        fork_repository.provenance().role(),
        AuthorityRoleV2::CompositeHeadRepository
    );
}

#[test]
fn managed_copy_intent_is_bounded_recoverable_and_idempotent() {
    let adapter = NonProductionManagedCopyDeletionAdapterV2::random("provider", "process-a")
        .expect("adapter");
    let request_id = OperationRequestIdV2::generate().expect("request ID");
    let request = ManagedCopyDeleteRequestV2::new(
        request_id.clone(),
        namespace("db", "ws", "primary"),
        DeletionHandleV2::generate().expect("deletion"),
        DeletionTargetHandleV2::generate().expect("target"),
        DeletionClosureClassV2::ProviderCopy,
        7,
        root("inventory"),
    )
    .expect("request");
    let bytes = serde_json::to_vec(&request).expect("request JSON");
    let recovered = ManagedCopyDeleteRequestV2::from_json_bounded(&bytes).expect("recover request");
    assert_eq!(recovered, request);
    assert!(
        ManagedCopyDeleteRequestV2::from_json_bounded(&vec![
            b' ';
            MAX_MANAGED_COPY_DELETE_REQUEST_JSON_BYTES_V2
                + 1
        ])
        .is_err()
    );

    let ticket = applied(adapter.request_delete(&request).expect("submit"));
    match adapter.request_delete(&request).expect("retry") {
        AuthorityOperationOutcomeV2::AlreadyApplied(replayed) => assert_eq!(replayed, ticket),
        other => panic!("expected replay, got {other:?}"),
    }
    let ticket_bytes = serde_json::to_vec(&ticket).expect("ticket JSON");
    let recovered_ticket =
        ManagedCopyDeleteTicketV2::from_json_bounded(&ticket_bytes, adapter.provenance())
            .expect("recover ticket");
    assert_eq!(recovered_ticket, ticket);

    let conflicting = ManagedCopyDeleteRequestV2::new(
        request_id,
        request.namespace().clone(),
        request.deletion().clone(),
        DeletionTargetHandleV2::generate().expect("other target"),
        request.class(),
        request.copy_generation(),
        request.inventory_commitment().clone(),
    )
    .expect("conflicting request");
    assert!(matches!(
        adapter.request_delete(&conflicting).expect("conflict"),
        AuthorityOperationOutcomeV2::Conflict { .. }
    ));
}

#[test]
fn managed_copy_outside_control_is_terminal_but_never_complete() {
    let adapter = NonProductionManagedCopyDeletionAdapterV2::random("provider", "process-a")
        .expect("adapter");
    let request = ManagedCopyDeleteRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        namespace("db", "ws", "primary"),
        DeletionHandleV2::generate().expect("deletion"),
        DeletionTargetHandleV2::generate().expect("target"),
        DeletionClosureClassV2::Backup,
        1,
        root("inventory"),
    )
    .expect("request");
    let ticket = applied(adapter.request_delete(&request).expect("request delete"));
    let outside = adapter
        .mark_terminal_for_test(
            ticket.ticket_handle(),
            ManagedCopyTerminalDispositionV2::OutsideControl,
            10,
        )
        .expect("outside-control evidence");
    assert!(outside.disposition().is_terminal());
    assert!(!outside.disposition().is_complete());
    outside
        .verify_current(11, &adapter)
        .expect("current managed-copy evidence");
    assert!(matches!(
        outside.workflow_disposition(),
        ManagedCopyDispositionV2::OutsideControl { .. }
    ));
    let subject = managed_copy_terminal_subject(outside.ticket(), outside.disposition())
        .expect("managed-copy subject");
    let evidence_bytes = serde_json::to_vec(outside.authority_evidence()).expect("evidence JSON");
    VerifiedAuthorityEvidenceV2::from_json_bounded(
        &evidence_bytes,
        AuthorityEvidenceKindV2::ManagedCopyOutsideControl,
        adapter.provenance(),
        request.namespace(),
        request.request_id(),
        &subject,
        11,
        &adapter,
    )
    .expect("verify managed evidence");
    let mut forged = serde_json::to_value(outside.authority_evidence()).expect("evidence value");
    forged["signature"][0] =
        serde_json::Value::from(forged["signature"][0].as_u64().expect("signature byte") ^ 1);
    assert!(
        VerifiedAuthorityEvidenceV2::from_json_bounded(
            &serde_json::to_vec(&forged).expect("forged evidence"),
            AuthorityEvidenceKindV2::ManagedCopyOutsideControl,
            adapter.provenance(),
            request.namespace(),
            request.request_id(),
            &subject,
            11,
            &adapter,
        )
        .is_err()
    );
    let poll = ManagedCopyDeletePollRequestV2::new(
        OperationRequestIdV2::generate().expect("poll ID"),
        ticket,
    );
    assert!(matches!(
        applied(adapter.poll_delete(&poll).expect("poll")),
        ManagedCopyDeletePollV2::Terminal(_)
    ));
}

struct TestTrustRoot {
    revoked: AtomicBool,
    reject_signature: bool,
}

impl AuthorityProvenanceVerifierV2 for TestTrustRoot {
    fn verify_attestation(
        &self,
        _signing_key: &ReceiptSigningKeyRefV2,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<()> {
        if self.reject_signature {
            Err(SecureStoreError::CryptographicFailure)
        } else {
            Ok(())
        }
    }

    fn verify_current(
        &self,
        _provenance: &AuthorityProvenanceV2,
        _evaluated_at_micros: u64,
    ) -> Result<()> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(SecureStoreError::Integrity(
                "test trust root revoked provenance".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

impl AuthorityEvidenceVerifierV2 for TestTrustRoot {
    fn verify_current_provenance(
        &self,
        _provenance: &AuthorityProvenanceV2,
        _evaluated_at_micros: u64,
    ) -> Result<()> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(SecureStoreError::Integrity(
                "test trust root revoked evidence provenance".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    fn verify_evidence(
        &self,
        _provenance: &AuthorityProvenanceV2,
        _signing_key: &ReceiptSigningKeyRefV2,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<()> {
        if self.reject_signature {
            Err(SecureStoreError::CryptographicFailure)
        } else {
            Ok(())
        }
    }
}

fn attested_provenance_json(role: AuthorityRoleV2, expires_at_micros: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "unsigned": {
            "format_version": SECURE_STORE_FORMAT_VERSION,
            "role": role,
            "trust_level": "production",
            "authority_id": format!("authority-{role:?}"),
            "deployment_id": "deployment-a",
            "attestation_generation": 3,
            "attested_at_micros": 10,
            "expires_at_micros": expires_at_micros
        },
        "signing_key": { "key_id": "trust-root", "generation": 4 },
        "signature": [1, 2, 3]
    }))
    .expect("attestation JSON")
}

fn production_provenance(
    role: AuthorityRoleV2,
    verifier: &dyn AuthorityProvenanceVerifierV2,
) -> AuthorityProvenanceV2 {
    AuthorityProvenanceV2::from_attested_json_bounded(
        &attested_provenance_json(role, 100),
        role,
        50,
        verifier,
    )
    .expect("production provenance")
}

fn production_evidence_json(
    kind: AuthorityEvidenceKindV2,
    provenance: &AuthorityProvenanceV2,
    namespace: &StateNamespaceV2,
    request_id: &OperationRequestIdV2,
    subject_commitment: &StateRootV2,
    issued_at_micros: u64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "format_version": SECURE_STORE_FORMAT_VERSION,
        "kind": kind,
        "provenance": provenance,
        "namespace": namespace,
        "request_id": request_id,
        "subject_commitment": subject_commitment,
        "issued_at_micros": issued_at_micros,
        "evidence_handle": EvidenceHandleV2::generate().expect("evidence handle"),
        "signing_key": { "key_id": "authority-key", "generation": 7 },
        "signature": [1, 2, 3]
    }))
    .expect("production evidence JSON")
}

#[test]
fn production_evidence_time_is_bound_to_attestation_and_evaluation() {
    let trust_root = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: false,
    };
    let provenance = production_provenance(AuthorityRoleV2::KeyAuthority, &trust_root);
    let ns = namespace("db", "ws", "primary");
    let request_id = OperationRequestIdV2::generate().expect("request ID");
    let subject = root("destroyed-key-subject");
    let verify = |issued_at_micros, evaluated_at_micros| {
        VerifiedAuthorityEvidenceV2::from_json_bounded(
            &production_evidence_json(
                AuthorityEvidenceKindV2::KeyDestroyed,
                &provenance,
                &ns,
                &request_id,
                &subject,
                issued_at_micros,
            ),
            AuthorityEvidenceKindV2::KeyDestroyed,
            &provenance,
            &ns,
            &request_id,
            &subject,
            evaluated_at_micros,
            &trust_root,
        )
    };

    verify(10, 10).expect("attestation boundary is inclusive");
    verify(50, 50).expect("current evidence");
    assert!(verify(9, 50).is_err(), "pre-attestation evidence accepted");
    assert!(verify(51, 50).is_err(), "future evidence accepted");
    assert!(verify(99, 100).is_err(), "expired evidence accepted");
    assert!(
        verify(100, 100).is_err(),
        "evidence issued at expiry accepted"
    );
}

#[test]
fn p3_public_recovery_rejects_oversized_authority_inputs_before_parse() {
    let trust_root = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: false,
    };
    assert!(
        AuthorityProvenanceV2::from_attested_json_bounded(
            &vec![b' '; MAX_AUTHORITY_PROVENANCE_JSON_BYTES_V2 + 1],
            AuthorityRoleV2::KeyAuthority,
            50,
            &trust_root,
        )
        .is_err()
    );

    let provenance = production_provenance(AuthorityRoleV2::KeyAuthority, &trust_root);
    let ns = namespace("db", "ws", "primary");
    let request_id = OperationRequestIdV2::generate().expect("request ID");
    let subject = root("subject");
    assert!(
        VerifiedAuthorityEvidenceV2::from_json_bounded(
            &vec![b' '; MAX_AUTHORITY_EVIDENCE_JSON_BYTES_V2 + 1],
            AuthorityEvidenceKindV2::KeyDestroyed,
            &provenance,
            &ns,
            &request_id,
            &subject,
            50,
            &trust_root,
        )
        .is_err()
    );
    assert!(
        ProductionKeyCreateRequestV2::from_json_bounded(&vec![
            b' ';
            MAX_PRODUCTION_KEY_OPERATION_JSON_BYTES_V2
                + 1
        ])
        .is_err()
    );
}

struct UnavailableProductionKeyAuthorityV2 {
    provenance: AuthorityProvenanceV2,
    calls: AtomicUsize,
}

impl ProductionKeyAuthorityV2 for UnavailableProductionKeyAuthorityV2 {
    fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }

    fn create_or_get(
        &self,
        _request: &ProductionKeyCreateRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDescriptorV2>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorityOperationOutcomeV2::Unavailable)
    }

    fn describe_strongly_consistent(
        &self,
        _request: &ProductionKeyDescribeRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDescriptorV2>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorityOperationOutcomeV2::Unavailable)
    }

    fn request_destroy(
        &self,
        _request: &ProductionKeyDestroyRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDestroyTicketV2>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorityOperationOutcomeV2::Unavailable)
    }

    fn poll_destroy(
        &self,
        _request: &ProductionKeyDestroyPollRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<KeyDestroyPollV2>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorityOperationOutcomeV2::Unavailable)
    }
}

struct UnavailableProductionHeadRepositoryV2 {
    provenance: AuthorityProvenanceV2,
    calls: AtomicUsize,
}

struct StaticProductionHeadRepositoryV2 {
    provenance: AuthorityProvenanceV2,
    cas_outcome: CompositeHeadCasOutcomeV2,
}

impl CompositeHeadRepositoryV2 for StaticProductionHeadRepositoryV2 {
    fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }

    fn load(&self, _request: &CompositeHeadLoadRequestV2) -> Result<CompositeHeadLoadOutcomeV2> {
        Ok(CompositeHeadLoadOutcomeV2::Unavailable)
    }

    fn compare_and_swap(
        &self,
        _request: &CompositeHeadCasRequestV2,
    ) -> Result<CompositeHeadCasOutcomeV2> {
        Ok(self.cas_outcome.clone())
    }
}

impl CompositeHeadRepositoryV2 for UnavailableProductionHeadRepositoryV2 {
    fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }

    fn load(&self, _request: &CompositeHeadLoadRequestV2) -> Result<CompositeHeadLoadOutcomeV2> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CompositeHeadLoadOutcomeV2::Unavailable)
    }

    fn compare_and_swap(
        &self,
        _request: &CompositeHeadCasRequestV2,
    ) -> Result<CompositeHeadCasOutcomeV2> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CompositeHeadCasOutcomeV2::Unavailable)
    }
}

struct UnavailableProductionManagedCopyV2 {
    provenance: AuthorityProvenanceV2,
    calls: AtomicUsize,
}

impl ManagedCopyDeletionAdapterV2 for UnavailableProductionManagedCopyV2 {
    fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }

    fn request_delete(
        &self,
        _request: &ManagedCopyDeleteRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<ManagedCopyDeleteTicketV2>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorityOperationOutcomeV2::Unavailable)
    }

    fn poll_delete(
        &self,
        _request: &ManagedCopyDeletePollRequestV2,
    ) -> Result<AuthorityOperationOutcomeV2<ManagedCopyDeletePollV2>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorityOperationOutcomeV2::Unavailable)
    }
}

#[test]
fn integration_views_require_host_freshness_before_every_backend_use() {
    let trust_root = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: false,
    };
    let key_backend = UnavailableProductionKeyAuthorityV2 {
        provenance: production_provenance(AuthorityRoleV2::KeyAuthority, &trust_root),
        calls: AtomicUsize::new(0),
    };
    let repository_backend = UnavailableProductionHeadRepositoryV2 {
        provenance: production_provenance(AuthorityRoleV2::CompositeHeadRepository, &trust_root),
        calls: AtomicUsize::new(0),
    };
    let managed_backend = UnavailableProductionManagedCopyV2 {
        provenance: production_provenance(AuthorityRoleV2::ManagedCopyProvider, &trust_root),
        calls: AtomicUsize::new(0),
    };
    let mac = InMemoryHeadMacAuthorityV2::random("head-key").expect("MAC authority");
    let key = CurrentProductionKeyAuthorityV2::bind(&key_backend, 50, &trust_root, &trust_root)
        .expect("current key view");
    let repository = CurrentCompositeHeadRepositoryV2::bind(
        &repository_backend,
        50,
        &trust_root,
        &trust_root,
        &mac,
    )
    .expect("current repository view");
    let managed =
        CurrentManagedCopyDeletionAdapterV2::bind(&managed_backend, 50, &trust_root, &trust_root)
            .expect("current managed-copy view");

    let ns = namespace("db", "ws", "primary");
    let create = ProductionKeyCreateRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        ns.clone(),
        scope("db", "ws", "owner"),
    )
    .expect("create request");
    let load = CompositeHeadLoadRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        ns.clone(),
        None,
    )
    .expect("load request");
    let delete = ManagedCopyDeleteRequestV2::new(
        OperationRequestIdV2::generate().expect("request ID"),
        ns,
        DeletionHandleV2::generate().expect("deletion"),
        DeletionTargetHandleV2::generate().expect("target"),
        DeletionClosureClassV2::ProviderCopy,
        1,
        root("inventory"),
    )
    .expect("managed-copy request");

    assert!(matches!(
        key.create_or_get(50, &create).expect("key call"),
        AuthorityOperationOutcomeV2::Unavailable
    ));
    assert!(matches!(
        repository.load(50, &load).expect("repository call"),
        CompositeHeadLoadOutcomeV2::Unavailable
    ));
    assert!(matches!(
        managed
            .request_delete(50, &delete)
            .expect("managed-copy call"),
        AuthorityOperationOutcomeV2::Unavailable
    ));

    trust_root.revoked.store(true, Ordering::SeqCst);
    assert!(key.create_or_get(51, &create).is_err());
    assert!(repository.load(51, &load).is_err());
    assert!(managed.request_delete(51, &delete).is_err());
    assert_eq!(key_backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(repository_backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(managed_backend.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn current_repository_rejects_a_valid_receipt_for_another_request_id() {
    let trust_root = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: false,
    };
    let provenance = production_provenance(AuthorityRoleV2::CompositeHeadRepository, &trust_root);
    let mac = InMemoryHeadMacAuthorityV2::random("head-key").expect("MAC authority");
    let ns = namespace("db", "ws", "primary");
    let head =
        CompositeStateHeadV2::initial(ns.clone(), head_payload("one"), &mac).expect("initial head");
    let anchor = HeadAnchorV2::from_head(&head).expect("head anchor");
    let first_request_id = OperationRequestIdV2::generate().expect("request ID");
    let subject = head_anchor_subject(None, &anchor).expect("anchor subject");
    let evidence = VerifiedAuthorityEvidenceV2::from_json_bounded(
        &production_evidence_json(
            AuthorityEvidenceKindV2::CompositeHeadAnchored,
            &provenance,
            &ns,
            &first_request_id,
            &subject,
            50,
        ),
        AuthorityEvidenceKindV2::CompositeHeadAnchored,
        &provenance,
        &ns,
        &first_request_id,
        &subject,
        50,
        &trust_root,
    )
    .expect("valid repository evidence");
    let receipt = HeadAnchorReceiptV2::from_verified(anchor, None, provenance.clone(), evidence)
        .expect("anchor receipt");
    let anchored = AnchoredCompositeHeadV2::try_new(head.clone(), receipt).expect("anchored head");
    let backend = StaticProductionHeadRepositoryV2 {
        provenance,
        cas_outcome: CompositeHeadCasOutcomeV2::Applied(anchored),
    };
    let repository =
        CurrentCompositeHeadRepositoryV2::bind(&backend, 50, &trust_root, &trust_root, &mac)
            .expect("current repository");
    let exact = CompositeHeadCasRequestV2::new(first_request_id, None, head.clone())
        .expect("exact CAS request");
    repository
        .compare_and_swap(50, &exact)
        .expect("exact receipt accepted");

    let substituted = CompositeHeadCasRequestV2::new(
        OperationRequestIdV2::generate().expect("other request ID"),
        None,
        head,
    )
    .expect("substituted CAS request");
    assert!(repository.compare_and_swap(50, &substituted).is_err());
}

#[test]
fn integration_views_reject_every_nonproduction_backend() {
    let verifier = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: false,
    };
    let key = NonProductionKeyAuthorityAdapterV2::random("key", "process-a").expect("key");
    let mac = InMemoryHeadMacAuthorityV2::random("head-key").expect("MAC authority");
    let repository = NonProductionCompositeHeadRepositoryV2::random(
        "repository",
        "process-a",
        Arc::new(InMemoryHeadMacAuthorityV2::random("repository-mac").expect("MAC authority")),
    )
    .expect("repository");
    let managed = NonProductionManagedCopyDeletionAdapterV2::random("provider", "process-a")
        .expect("managed-copy provider");

    assert!(CurrentProductionKeyAuthorityV2::bind(&key, 50, &verifier, &verifier).is_err());
    assert!(
        CurrentCompositeHeadRepositoryV2::bind(&repository, 50, &verifier, &verifier, &mac,)
            .is_err()
    );
    assert!(CurrentManagedCopyDeletionAdapterV2::bind(&managed, 50, &verifier, &verifier).is_err());
}

#[test]
fn p3_debug_output_redacts_authority_and_opaque_operation_payloads() {
    let verifier = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: false,
    };
    let provenance = production_provenance(AuthorityRoleV2::KeyAuthority, &verifier);
    let request_id = OperationRequestIdV2::generate().expect("request ID");
    let object_scope = scope("sensitive-db", "sensitive-workspace", "sensitive-owner");
    let content_handle = object_scope.content_handle().as_str().to_owned();
    let request = ProductionKeyCreateRequestV2::new(
        request_id.clone(),
        namespace("sensitive-db", "sensitive-workspace", "primary"),
        object_scope,
    )
    .expect("request");

    let provenance_debug = format!("{provenance:?}");
    assert!(!provenance_debug.contains(provenance.authority_id()));
    assert!(!provenance_debug.contains(provenance.deployment_id()));
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains(request_id.as_str()));
    assert!(!request_debug.contains(&content_handle));
    assert!(!request_debug.contains("sensitive-db"));
    assert!(!request_debug.contains("sensitive-workspace"));
    assert!(!request_debug.contains("sensitive-owner"));
}

#[test]
fn provenance_is_freshness_bounded_revocable_and_nonproduction_is_denied() {
    let accepting = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: false,
    };
    let key = AuthorityProvenanceV2::from_attested_json_bounded(
        &attested_provenance_json(AuthorityRoleV2::KeyAuthority, 100),
        AuthorityRoleV2::KeyAuthority,
        50,
        &accepting,
    )
    .expect("key provenance");
    let repository = AuthorityProvenanceV2::from_attested_json_bounded(
        &attested_provenance_json(AuthorityRoleV2::CompositeHeadRepository, 100),
        AuthorityRoleV2::CompositeHeadRepository,
        50,
        &accepting,
    )
    .expect("repository provenance");
    assert_eq!(key.attestation_generation(), 3);
    assert_eq!(
        evaluate_production_trust_v2(
            ProductionCapabilityV2::HardDelete,
            ProductionTrustRequirementsV2::new(0).expect("requirements"),
            &[key.clone(), repository.clone()],
            50,
            &accepting,
        )
        .expect("trust gate"),
        ProductionTrustGateV2::EligibleForIntegrationOnly
    );

    accepting.revoked.store(true, Ordering::SeqCst);
    assert!(
        evaluate_production_trust_v2(
            ProductionCapabilityV2::Complete,
            ProductionTrustRequirementsV2::new(0).expect("requirements"),
            &[key, repository],
            50,
            &accepting,
        )
        .is_err()
    );

    let stale_verifier = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: false,
    };
    assert!(
        AuthorityProvenanceV2::from_attested_json_bounded(
            &attested_provenance_json(AuthorityRoleV2::KeyAuthority, 50),
            AuthorityRoleV2::KeyAuthority,
            50,
            &stale_verifier,
        )
        .is_err()
    );
    let rejecting = TestTrustRoot {
        revoked: AtomicBool::new(false),
        reject_signature: true,
    };
    assert!(
        AuthorityProvenanceV2::from_attested_json_bounded(
            &attested_provenance_json(AuthorityRoleV2::KeyAuthority, 100),
            AuthorityRoleV2::KeyAuthority,
            50,
            &rejecting,
        )
        .is_err()
    );

    let nonproduction = vec![
        AuthorityProvenanceV2::non_production(
            AuthorityRoleV2::KeyAuthority,
            "test-key",
            "process-a",
        )
        .expect("non-production key"),
        AuthorityProvenanceV2::non_production(
            AuthorityRoleV2::CompositeHeadRepository,
            "test-repository",
            "process-a",
        )
        .expect("non-production repository"),
        AuthorityProvenanceV2::non_production(
            AuthorityRoleV2::ManagedCopyProvider,
            "test-provider",
            "process-a",
        )
        .expect("non-production provider"),
    ];
    assert!(matches!(
        evaluate_production_trust_v2(
            ProductionCapabilityV2::HardDelete,
            ProductionTrustRequirementsV2::new(1).expect("requirements"),
            &nonproduction,
            50,
            &stale_verifier,
        )
        .expect("non-production decision"),
        ProductionTrustGateV2::DeniedNonProduction { .. }
    ));
    assert!(matches!(
        evaluate_production_trust_v2(
            ProductionCapabilityV2::Complete,
            ProductionTrustRequirementsV2::new(1).expect("requirements"),
            &nonproduction,
            50,
            &stale_verifier,
        )
        .expect("non-production complete decision"),
        ProductionTrustGateV2::DeniedNonProduction { .. }
    ));
    let oversized = vec![nonproduction[0].clone(); MAX_PRODUCTION_TRUST_COMPONENTS_V2 + 1];
    assert!(
        evaluate_production_trust_v2(
            ProductionCapabilityV2::HardDelete,
            ProductionTrustRequirementsV2::new(0).expect("requirements"),
            &oversized,
            50,
            &stale_verifier,
        )
        .is_err()
    );
}

proptest! {
    #[test]
    fn arbitrary_operation_request_ids_are_never_accepted_unvalidated(value in ".{0,140}") {
        if let Ok(parsed) = OperationRequestIdV2::parse(value.clone()) {
            prop_assert_eq!(parsed.as_str(), value.as_str());
            prop_assert!(value.starts_with("req2_"));
            prop_assert_eq!(value.len(), 69);
        }
    }
}
