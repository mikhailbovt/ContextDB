use std::collections::BTreeSet;

use proptest::prelude::*;

use super::*;
use crate::test_support::{
    AcceptAllDeletionEvidenceV2, InMemoryHeadMacAuthorityV2, InMemoryKeyAuthorityV2,
    InMemoryReceiptAuthorityV2,
};

fn root(label: &str) -> StateRootV2 {
    StateRootV2::commit(label, label.as_bytes()).expect("test root")
}

fn namespace(database: &str, workspace: &str) -> StateNamespaceV2 {
    StateNamespaceV2::new("test-authority", database, workspace, "primary").expect("test namespace")
}

fn context(
    database: &str,
    workspace: &str,
    record_kind: &str,
    owner: &str,
    policy: &str,
    key_revision: u64,
) -> ContentSecurityContextV2 {
    ContentSecurityContextV2::new(
        database,
        workspace,
        record_kind,
        owner,
        root(policy),
        key_revision,
    )
    .expect("test content context")
}

fn head_payload(suppression: SuppressionBindingV2) -> CompositeHeadPayloadV2 {
    CompositeHeadPayloadV2 {
        projection_root: root("projection"),
        policy_root: root("policy"),
        key_catalog_root: root("key-catalog"),
        deletion_workflow_root: root("deletion"),
        suppression,
    }
}

fn full_inventory() -> (
    DeletionClosureInventoryV2,
    Vec<(DeletionClosureClassV2, DeletionTargetHandleV2)>,
) {
    let mut targets = Vec::new();
    let classes = ALL_DELETION_CLOSURE_CLASSES_V2
        .into_iter()
        .map(|class| {
            let target = DeletionTargetHandleV2::generate().expect("target handle");
            targets.push((class, target.clone()));
            ClassInventoryV2::new(class, BTreeSet::from([target]), None).expect("class inventory")
        })
        .collect::<Vec<_>>();
    (
        DeletionClosureInventoryV2::try_new(classes).expect("full inventory"),
        targets,
    )
}

fn empty_inventory() -> DeletionClosureInventoryV2 {
    DeletionClosureInventoryV2::try_new(
        ALL_DELETION_CLOSURE_CLASSES_V2
            .into_iter()
            .map(|class| {
                ClassInventoryV2::new(
                    class,
                    BTreeSet::new(),
                    Some(EvidenceHandleV2::generate().expect("absence evidence")),
                )
                .expect("empty class inventory")
            })
            .collect(),
    )
    .expect("empty exact inventory")
}

fn advance_to_awaiting(
    workflow: &mut DeletionWorkflowV2,
    targets: &[(DeletionClosureClassV2, DeletionTargetHandleV2)],
) {
    let verifier = AcceptAllDeletionEvidenceV2;
    let mut at = workflow.updated_at_micros() + 1;
    workflow
        .begin_suppression(workflow.revision(), at)
        .expect("begin suppression");
    at += 1;
    workflow
        .confirm_suppressed(workflow.revision(), at, root("suppressed-head"), &verifier)
        .expect("confirm suppression");
    at += 1;
    workflow
        .begin_purging(workflow.revision(), at)
        .expect("begin purge");
    for (class, target) in targets {
        at += 1;
        let disposition = if class.is_managed_copy() {
            DeletionTargetDispositionV2::Managed(ManagedCopyDispositionV2::DeletionRequested {
                request: EvidenceHandleV2::generate().expect("request evidence"),
            })
        } else {
            DeletionTargetDispositionV2::Local(LocalDeletionDispositionV2::Purged {
                evidence: EvidenceHandleV2::generate().expect("purge evidence"),
            })
        };
        workflow
            .record_disposition(workflow.revision(), at, target.clone(), disposition)
            .expect("record target disposition");
    }
    at += 1;
    workflow
        .await_external(workflow.revision(), at)
        .expect("await external");
}

fn complete_workflow() -> (DeletionWorkflowV2, InMemoryReceiptAuthorityV2) {
    let (inventory, targets) = full_inventory();
    let mut workflow =
        DeletionWorkflowV2::prepare(namespace("db-a", "ws-a"), inventory.clone(), 100)
            .expect("prepare");
    advance_to_awaiting(&mut workflow, &targets);
    let mut at = workflow.updated_at_micros();
    for (class, target) in &targets {
        if class.is_managed_copy() {
            at += 1;
            workflow
                .record_disposition(
                    workflow.revision(),
                    at,
                    target.clone(),
                    DeletionTargetDispositionV2::Managed(ManagedCopyDispositionV2::Deleted {
                        receipt: EvidenceHandleV2::generate().expect("managed receipt"),
                    }),
                )
                .expect("complete managed copy");
        }
    }
    at += 1;
    workflow
        .verify_closure(
            workflow.revision(),
            at,
            &inventory,
            &AcceptAllDeletionEvidenceV2,
        )
        .expect("verify closure");
    at += 1;
    workflow
        .begin_receipt(workflow.revision(), at)
        .expect("begin receipt");
    let receipt_authority =
        InMemoryReceiptAuthorityV2::random("receipt-key", 7).expect("receipt authority");
    at += 1;
    let unsigned =
        UnsignedDeletionReceiptV2::from_workflow(&workflow, at).expect("unsigned receipt");
    let signed = SignedDeletionReceiptV2::sign(unsigned, &receipt_authority).expect("sign receipt");
    let expected_revision = workflow.revision();
    signed
        .complete_workflow(&mut workflow, expected_revision, at, &receipt_authority)
        .expect("complete workflow");
    (workflow, receipt_authority)
}

#[test]
fn opaque_handles_are_validated_and_redacted() {
    let handle = ContentHandleV2::generate().expect("handle");
    assert!(handle.as_str().starts_with("cth2_"));
    assert!(!format!("{handle:?}").contains(handle.as_str()));
    assert!(ContentHandleV2::parse("cth2_not-hex").is_err());
    assert!(ContentHandleV2::parse(format!("cth2_{}", "0".repeat(63))).is_err());
}

#[test]
fn state_namespace_deserialization_validates_every_field() {
    for field in [
        "authority_namespace",
        "database_id",
        "workspace_id",
        "partition_id",
    ] {
        let mut value = serde_json::json!({
            "authority_namespace": "authority",
            "database_id": "database",
            "workspace_id": "workspace",
            "partition_id": "partition",
        });
        value[field] = serde_json::Value::String(String::new());
        assert!(serde_json::from_value::<StateNamespaceV2>(value).is_err());
    }
}

#[test]
fn encryption_is_random_context_bound_and_has_no_plaintext_digest() {
    let mut authority = InMemoryKeyAuthorityV2::default();
    let security_context = context("db-a", "ws-a", "observation.raw", "owner-a", "policy-a", 4);
    let secret = b"v2-plaintext-never-public-4ee2b488ae534bf6";
    let first = EncryptedContentV2::encrypt_new(
        &mut authority,
        ErasureDomainV2::generate().expect("domain"),
        security_context.clone(),
        secret,
    )
    .expect("first encryption");
    let second = EncryptedContentV2::encrypt_new(
        &mut authority,
        ErasureDomainV2::generate().expect("domain"),
        security_context.clone(),
        secret,
    )
    .expect("second encryption");
    assert_ne!(
        first.header().key().key_handle(),
        second.header().key().key_handle()
    );
    assert_ne!(
        first.sealed_payload().nonce(),
        second.sealed_payload().nonce()
    );
    assert_ne!(
        first.sealed_payload().ciphertext(),
        second.sealed_payload().ciphertext()
    );
    assert_eq!(
        first
            .decrypt(&authority, &security_context)
            .expect("decrypt")
            .as_slice(),
        secret
    );
    let json = serde_json::to_string(&first).expect("serialize envelope");
    assert!(!json.contains(std::str::from_utf8(secret).expect("ASCII secret")));
    assert!(!json.contains("plaintext_digest"));
    let debug = format!("{first:?}");
    assert!(!debug.contains(std::str::from_utf8(secret).expect("ASCII secret")));
}

#[test]
fn every_anti_relocation_context_dimension_is_enforced() {
    let mut authority = InMemoryKeyAuthorityV2::default();
    let expected = context("db-a", "ws-a", "episode", "owner-a", "policy-a", 5);
    let envelope = EncryptedContentV2::encrypt_new(
        &mut authority,
        ErasureDomainV2::generate().expect("domain"),
        expected.clone(),
        b"relocation test",
    )
    .expect("encrypt");
    let wrong = [
        context("db-b", "ws-a", "episode", "owner-a", "policy-a", 5),
        context("db-a", "ws-b", "episode", "owner-a", "policy-a", 5),
        context("db-a", "ws-a", "evidence", "owner-a", "policy-a", 5),
        context("db-a", "ws-a", "episode", "owner-b", "policy-a", 5),
        context("db-a", "ws-a", "episode", "owner-a", "policy-b", 5),
        context("db-a", "ws-a", "episode", "owner-a", "policy-a", 6),
    ];
    for destination in wrong {
        assert!(envelope.decrypt(&authority, &destination).is_err());
    }
    assert!(envelope.decrypt(&authority, &expected).is_ok());
}

#[test]
fn destroying_one_random_dek_never_affects_another() {
    let mut authority = InMemoryKeyAuthorityV2::default();
    let security_context = context("db", "ws", "raw", "owner", "policy", 1);
    let first = EncryptedContentV2::encrypt_new(
        &mut authority,
        ErasureDomainV2::generate().expect("domain"),
        security_context.clone(),
        b"object A",
    )
    .expect("encrypt A");
    let second = EncryptedContentV2::encrypt_new(
        &mut authority,
        ErasureDomainV2::generate().expect("domain"),
        security_context.clone(),
        b"object B",
    )
    .expect("encrypt B");
    let key_a = first.header().key().key_handle().clone();
    assert!(authority.request_destroy(&key_a, 0).is_err());
    let pending = authority
        .request_destroy(&key_a, 1)
        .expect("request destroy");
    assert_eq!(pending.lifecycle(), KeyLifecycleV2::DestroyPending);
    assert!(first.decrypt(&authority, &security_context).is_err());
    assert_eq!(
        second
            .decrypt(&authority, &security_context)
            .expect("B remains decryptable")
            .as_slice(),
        b"object B"
    );
    let destroyed = authority
        .confirm_destroy(
            &key_a,
            2,
            EvidenceHandleV2::generate().expect("destruction evidence"),
        )
        .expect("confirm destroy");
    assert_eq!(destroyed.lifecycle(), KeyLifecycleV2::Destroyed);
    assert!(authority.request_destroy(&key_a, 3).is_err());
    assert!(first.decrypt(&authority, &security_context).is_err());
}

#[test]
fn key_catalog_rejects_two_deks_for_the_same_exact_object_scope() {
    let scope = DekScopeV2::new(
        ContentHandleV2::generate().expect("content handle"),
        ErasureDomainV2::generate().expect("erasure domain"),
        context("db", "ws", "raw", "owner", "policy", 1),
    )
    .expect("scope");
    let first = KeyDescriptorV2::authority_active(
        KeyHandleV2::generate().expect("key handle"),
        scope.clone(),
    )
    .expect("first descriptor");
    let second =
        KeyDescriptorV2::authority_active(KeyHandleV2::generate().expect("key handle"), scope)
            .expect("second descriptor");
    assert!(KeyCatalogSnapshotV2::try_new(vec![first, second]).is_err());
}

#[test]
fn composite_head_rejects_database_workspace_partition_replay_and_is_monotonic() {
    let mut authority = InMemoryHeadMacAuthorityV2::random("head-key").expect("head authority");
    let ns = namespace("db-a", "ws-a");
    let overlay = root("deletion");
    let pending = CompositeStateHeadV2::initial(
        ns.clone(),
        head_payload(SuppressionBindingV2::Pending {
            overlay_root: overlay.clone(),
            pending_workflow_count: 1,
        }),
        &authority,
    )
    .expect("initial head");
    assert_eq!(
        pending.payload().read_gate(),
        SuppressionReadGateV2::DenyWhilePending
    );
    pending.verify(&ns, &authority).expect("verify head");
    assert!(
        pending
            .verify(&namespace("db-b", "ws-a"), &authority)
            .is_err()
    );
    assert!(
        pending
            .verify(&namespace("db-a", "ws-b"), &authority)
            .is_err()
    );
    let other_partition = StateNamespaceV2::new("test-authority", "db-a", "ws-a", "replica")
        .expect("other partition");
    assert!(pending.verify(&other_partition, &authority).is_err());
    authority.rotate().expect("rotate head key");
    let token = pending.cas_token();
    let enforced = pending
        .successor(
            &ns,
            head_payload(SuppressionBindingV2::Enforced {
                overlay_root: overlay,
            }),
            &authority,
        )
        .expect("successor");
    validate_composite_head_cas(&token, &ns, &pending, &enforced, &authority).expect("valid CAS");
    assert_eq!(
        enforced.payload().read_gate(),
        SuppressionReadGateV2::RequireLiveOverlay
    );
    let third = enforced
        .successor(&ns, head_payload(SuppressionBindingV2::Clear), &authority)
        .expect("third head");
    assert!(validate_composite_head_cas(&token, &ns, &enforced, &third, &authority).is_err());
}

#[test]
fn composite_head_rejects_malformed_and_one_bit_mac_tags() {
    let authority = InMemoryHeadMacAuthorityV2::random("head-key").expect("head authority");
    let ns = namespace("db", "ws");
    let head = CompositeStateHeadV2::initial(
        ns.clone(),
        head_payload(SuppressionBindingV2::Clear),
        &authority,
    )
    .expect("head");
    let mut one_bit = serde_json::to_value(&head).expect("head JSON");
    let tag = one_bit
        .pointer_mut("/authentication/tag")
        .and_then(|value| value.as_str())
        .expect("tag")
        .to_owned();
    let replacement = if tag.starts_with('0') { '1' } else { '0' };
    let changed = format!("{replacement}{}", &tag[1..]);
    *one_bit
        .pointer_mut("/authentication/tag")
        .expect("mutable tag") = serde_json::Value::String(changed);
    let tampered = serde_json::to_vec(&one_bit).expect("tampered head JSON");
    assert!(CompositeStateHeadV2::from_json_bounded(&tampered, &ns, &authority).is_err());

    let mut malformed = serde_json::to_value(&head).expect("head JSON");
    *malformed
        .pointer_mut("/authentication/tag")
        .expect("mutable tag") = serde_json::Value::String("not-a-tag".to_owned());
    let malformed = serde_json::to_vec(&malformed).expect("malformed head JSON");
    assert!(CompositeStateHeadV2::from_json_bounded(&malformed, &ns, &authority).is_err());
    let authentic = serde_json::to_vec(&head).expect("authentic head JSON");
    assert!(CompositeStateHeadV2::from_json_bounded(&authentic, &ns, &authority).is_ok());
    assert!(
        CompositeStateHeadV2::from_json_bounded(
            &vec![b' '; MAX_COMPOSITE_HEAD_JSON_BYTES_V2 + 1],
            &ns,
            &authority,
        )
        .is_err()
    );
}

struct HistoricalHeadAuthority<'a> {
    delegate: &'a InMemoryHeadMacAuthorityV2,
    historical_generation: u64,
}

impl HeadMacAuthorityV2 for HistoricalHeadAuthority<'_> {
    fn active_key(&self) -> Result<HeadMacKeyRefV2> {
        HeadMacKeyRefV2::new("head-key", self.historical_generation)
    }

    fn compute_mac(&self, key: &HeadMacKeyRefV2, message: &[u8]) -> Result<HeadMacTagV2> {
        self.delegate.compute_mac(key, message)
    }
}

#[test]
fn composite_head_cas_rejects_a_valid_but_stale_mac_key_generation() {
    let mut authority = InMemoryHeadMacAuthorityV2::random("head-key").expect("head authority");
    let ns = namespace("db", "ws");
    let current = CompositeStateHeadV2::initial(
        ns.clone(),
        head_payload(SuppressionBindingV2::Clear),
        &authority,
    )
    .expect("head");
    authority.rotate().expect("rotate");
    let historical = HistoricalHeadAuthority {
        delegate: &authority,
        historical_generation: 1,
    };
    let stale_successor = current
        .successor(&ns, head_payload(SuppressionBindingV2::Clear), &historical)
        .expect("historically valid successor");
    assert!(
        validate_composite_head_cas(
            &current.cas_token(),
            &ns,
            &current,
            &stale_successor,
            &authority,
        )
        .is_err()
    );
}

#[test]
fn inventory_requires_exactly_thirteen_classes_and_exact_equality() {
    let exact = empty_inventory();
    assert_eq!(exact.classes().len(), 13);
    let mut missing = exact.classes().to_vec();
    missing.pop();
    assert!(DeletionClosureInventoryV2::try_new(missing).is_err());

    let (with_targets, targets) = full_inventory();
    let mut changed_classes = with_targets.classes().to_vec();
    let first = changed_classes.remove(0);
    changed_classes.push(
        ClassInventoryV2::new(
            first.class(),
            BTreeSet::from([DeletionTargetHandleV2::generate().expect("changed target")]),
            None,
        )
        .expect("changed class"),
    );
    let changed = DeletionClosureInventoryV2::try_new(changed_classes).expect("changed closure");
    assert!(with_targets.require_exact(&changed).is_err());
    assert!(with_targets.require_exact(&with_targets).is_ok());
    assert_eq!(targets.len(), 13);
}

#[test]
fn workflow_survives_failpoint_roundtrips_and_cannot_resurrect() {
    let (workflow, receipt_authority) = complete_workflow();
    assert_eq!(workflow.state(), DeletionWorkflowStateV2::Complete);
    assert_eq!(
        workflow
            .signed_receipt()
            .expect("embedded receipt")
            .signing_key()
            .generation(),
        7
    );
    let receipt_bytes = serde_json::to_vec(workflow.signed_receipt().expect("signed receipt"))
        .expect("serialize signed receipt");
    assert!(
        SignedDeletionReceiptV2::from_json_bounded(
            &receipt_bytes,
            workflow.namespace(),
            &receipt_authority,
        )
        .is_ok()
    );
    assert!(
        SignedDeletionReceiptV2::from_json_bounded(
            &receipt_bytes,
            &namespace("other-db", "ws-a"),
            &receipt_authority,
        )
        .is_err()
    );
    assert!(
        SignedDeletionReceiptV2::from_json_bounded(
            &vec![b' '; MAX_SIGNED_DELETION_RECEIPT_JSON_BYTES_V2 + 1],
            workflow.namespace(),
            &receipt_authority,
        )
        .is_err()
    );
    let bytes = serde_json::to_vec(&workflow).expect("serialize complete workflow");
    let recovered = DeletionWorkflowV2::from_json_bounded(
        &bytes,
        &AcceptAllDeletionEvidenceV2,
        &AcceptAllDeletionEvidenceV2,
        &receipt_authority,
    )
    .expect("recover complete workflow");
    assert_eq!(recovered.state(), DeletionWorkflowStateV2::Complete);
    let mut resurrect = recovered.clone();
    assert!(
        resurrect
            .begin_suppression(resurrect.revision(), resurrect.updated_at_micros() + 1)
            .is_err()
    );
    assert!(
        resurrect
            .begin_purging(resurrect.revision(), resurrect.updated_at_micros() + 1)
            .is_err()
    );
}

#[test]
fn every_workflow_transition_survives_a_failpoint_roundtrip() {
    let verifier = AcceptAllDeletionEvidenceV2;
    let receipt_authority =
        InMemoryReceiptAuthorityV2::random("receipt-failpoints", 3).expect("receipt authority");
    let inventory = empty_inventory();
    let mut workflow =
        DeletionWorkflowV2::prepare(namespace("db", "ws"), inventory.clone(), 10).expect("prepare");

    let recover = |workflow: &DeletionWorkflowV2| {
        let bytes = serde_json::to_vec(workflow).expect("serialize failpoint");
        DeletionWorkflowV2::from_json_bounded(&bytes, &verifier, &verifier, &receipt_authority)
            .expect("recover failpoint")
    };

    workflow = recover(&workflow);
    assert_eq!(workflow.state(), DeletionWorkflowStateV2::Prepared);
    workflow
        .begin_suppression(workflow.revision(), 11)
        .expect("begin suppression");
    workflow = recover(&workflow);
    assert_eq!(
        workflow.state(),
        DeletionWorkflowStateV2::SuppressionPending
    );
    workflow
        .confirm_suppressed(workflow.revision(), 12, root("suppression"), &verifier)
        .expect("confirm suppression");
    workflow = recover(&workflow);
    assert_eq!(workflow.state(), DeletionWorkflowStateV2::Suppressed);
    workflow
        .begin_purging(workflow.revision(), 13)
        .expect("begin purge");
    workflow = recover(&workflow);
    assert_eq!(workflow.state(), DeletionWorkflowStateV2::Purging);
    workflow
        .await_external(workflow.revision(), 14)
        .expect("await external");
    workflow = recover(&workflow);
    assert_eq!(workflow.state(), DeletionWorkflowStateV2::AwaitingExternal);
    workflow
        .verify_closure(workflow.revision(), 15, &inventory, &verifier)
        .expect("verify closure");
    workflow = recover(&workflow);
    assert_eq!(workflow.state(), DeletionWorkflowStateV2::Verified);
    workflow
        .begin_receipt(workflow.revision(), 16)
        .expect("begin receipt");
    workflow = recover(&workflow);
    assert_eq!(workflow.state(), DeletionWorkflowStateV2::ReceiptPending);
    let unsigned =
        UnsignedDeletionReceiptV2::from_workflow(&workflow, 17).expect("unsigned receipt");
    let signed =
        SignedDeletionReceiptV2::sign(unsigned, &receipt_authority).expect("signed receipt");
    let revision = workflow.revision();
    signed
        .complete_workflow(&mut workflow, revision, 17, &receipt_authority)
        .expect("complete");
    workflow = recover(&workflow);
    assert_eq!(workflow.state(), DeletionWorkflowStateV2::Complete);
}

#[derive(Debug)]
struct RejectSuppression;

impl SuppressionCommitmentVerifierV2 for RejectSuppression {
    fn verify_suppression(
        &self,
        _namespace: &StateNamespaceV2,
        _deletion: &DeletionHandleV2,
        _suppression_pending_workflow_root: &StateRootV2,
        _closure_root: &StateRootV2,
        _suppression_commitment: &StateRootV2,
    ) -> Result<()> {
        Err(SecureStoreError::Integrity(
            "test suppression proof rejected".to_owned(),
        ))
    }
}

#[derive(Debug)]
struct RejectEvidence;

impl DeletionEvidenceVerifierV2 for RejectEvidence {
    fn verify_absent_class(
        &self,
        _namespace: &StateNamespaceV2,
        _class: DeletionClosureClassV2,
        _evidence: &EvidenceHandleV2,
    ) -> Result<()> {
        Err(SecureStoreError::Integrity(
            "test evidence rejected".to_owned(),
        ))
    }

    fn verify_target(
        &self,
        _namespace: &StateNamespaceV2,
        _deletion: &DeletionHandleV2,
        _target: &DeletionTargetHandleV2,
        _class: DeletionClosureClassV2,
        _disposition: &DeletionTargetDispositionV2,
    ) -> Result<()> {
        Err(SecureStoreError::Integrity(
            "test evidence rejected".to_owned(),
        ))
    }
}

#[test]
fn workflow_recovery_requires_external_suppression_evidence() {
    let (inventory, targets) = full_inventory();
    let mut workflow =
        DeletionWorkflowV2::prepare(namespace("db", "ws"), inventory, 1).expect("prepare");
    advance_to_awaiting(&mut workflow, &targets);
    let bytes = serde_json::to_vec(&workflow).expect("serialize awaiting workflow");
    let receipt_authority =
        InMemoryReceiptAuthorityV2::random("receipt", 1).expect("receipt authority");
    assert!(
        DeletionWorkflowV2::from_json_bounded(
            &bytes,
            &RejectSuppression,
            &AcceptAllDeletionEvidenceV2,
            &receipt_authority,
        )
        .is_err()
    );
}

#[test]
fn verified_workflow_recovery_rechecks_external_target_evidence() {
    let verifier = AcceptAllDeletionEvidenceV2;
    let inventory = empty_inventory();
    let mut workflow =
        DeletionWorkflowV2::prepare(namespace("db", "ws"), inventory.clone(), 1).expect("prepare");
    workflow
        .begin_suppression(workflow.revision(), 2)
        .expect("begin suppression");
    workflow
        .confirm_suppressed(workflow.revision(), 3, root("suppression"), &verifier)
        .expect("confirm suppression");
    workflow
        .begin_purging(workflow.revision(), 4)
        .expect("begin purge");
    workflow
        .await_external(workflow.revision(), 5)
        .expect("await external");
    workflow
        .verify_closure(workflow.revision(), 6, &inventory, &verifier)
        .expect("verify");
    let bytes = serde_json::to_vec(&workflow).expect("verified JSON");
    let receipt_authority =
        InMemoryReceiptAuthorityV2::random("receipt", 1).expect("receipt authority");
    assert!(
        DeletionWorkflowV2::from_json_bounded(
            &bytes,
            &verifier,
            &RejectEvidence,
            &receipt_authority,
        )
        .is_err()
    );
}

#[test]
fn adversarial_workflow_json_cannot_jump_or_forge_late_states() {
    let (inventory, targets) = full_inventory();
    let prepared =
        DeletionWorkflowV2::prepare(namespace("db", "ws"), inventory.clone(), 1).expect("prepare");
    let receipt_authority =
        InMemoryReceiptAuthorityV2::random("receipt", 1).expect("receipt authority");
    let mut jumped = serde_json::to_value(&prepared).expect("prepared JSON");
    jumped["state"] = serde_json::Value::String("awaiting_external".to_owned());
    jumped["revision"] = serde_json::Value::from(99_u64);
    jumped["suppression_commitment"] =
        serde_json::to_value(root("fake suppression")).expect("root JSON");
    let jumped_bytes = serde_json::to_vec(&jumped).expect("jumped JSON");
    assert!(
        DeletionWorkflowV2::from_json_bounded(
            &jumped_bytes,
            &AcceptAllDeletionEvidenceV2,
            &AcceptAllDeletionEvidenceV2,
            &receipt_authority,
        )
        .is_err()
    );

    let mut awaiting = prepared;
    advance_to_awaiting(&mut awaiting, &targets);
    let mut omitted_receipts = serde_json::to_value(&awaiting).expect("awaiting JSON");
    omitted_receipts["state"] = serde_json::Value::String("verified".to_owned());
    omitted_receipts["revision"] = serde_json::Value::from(awaiting.revision() + 1);
    omitted_receipts["verification_commitment"] =
        serde_json::to_value(root("forged verification")).expect("root JSON");
    let omitted_bytes = serde_json::to_vec(&omitted_receipts).expect("omitted receipt JSON");
    assert!(
        DeletionWorkflowV2::from_json_bounded(
            &omitted_bytes,
            &AcceptAllDeletionEvidenceV2,
            &AcceptAllDeletionEvidenceV2,
            &receipt_authority,
        )
        .is_err()
    );

    let (complete, complete_authority) = complete_workflow();
    let mut forged = serde_json::to_value(&complete).expect("complete JSON");
    let signature = forged
        .pointer_mut("/signed_receipt/signature")
        .and_then(serde_json::Value::as_array_mut)
        .expect("signature array");
    let first = signature
        .first_mut()
        .and_then(|value| value.as_u64())
        .expect("signature byte");
    signature[0] = serde_json::Value::from(first ^ 1);
    let forged_bytes = serde_json::to_vec(&forged).expect("forged complete JSON");
    assert!(
        DeletionWorkflowV2::from_json_bounded(
            &forged_bytes,
            &AcceptAllDeletionEvidenceV2,
            &AcceptAllDeletionEvidenceV2,
            &complete_authority,
        )
        .is_err()
    );

    let mut wrong_workflow = serde_json::to_value(&complete).expect("complete JSON");
    wrong_workflow["handle"] =
        serde_json::to_value(DeletionHandleV2::generate().expect("different deletion handle"))
            .expect("handle JSON");
    let wrong_binding = serde_json::to_vec(&wrong_workflow).expect("wrong binding JSON");
    assert!(
        DeletionWorkflowV2::from_json_bounded(
            &wrong_binding,
            &AcceptAllDeletionEvidenceV2,
            &AcceptAllDeletionEvidenceV2,
            &complete_authority,
        )
        .is_err()
    );
}

#[test]
fn canonical_export_streaming_manifest_enforces_object_count_and_is_plaintext_free() {
    let mut authority = InMemoryKeyAuthorityV2::default();
    let security_context = context("db", "ws", "raw", "owner", "policy", 1);
    let secret = b"export-secret-never-in-manifest";
    let encrypted = EncryptedContentV2::encrypt_new(
        &mut authority,
        ErasureDomainV2::generate().expect("domain"),
        security_context,
        secret,
    )
    .expect("encrypt");
    let ciphertext_len = encrypted.sealed_payload().ciphertext().len() as u64;
    let export = CanonicalExportV2::from_encrypted(
        namespace("db", "ws"),
        root("head"),
        5,
        std::slice::from_ref(&encrypted),
    )
    .expect("export manifest");
    let json = serde_json::to_vec(&export).expect("serialize export");
    assert!(!String::from_utf8_lossy(&json).contains("export-secret-never-in-manifest"));
    assert!(!String::from_utf8_lossy(&json).contains("plaintext_digest"));
    let decoded = CanonicalExportV2::from_json_bounded(&json).expect("bounded decode");
    assert_eq!(decoded.encrypted_objects().len(), 1);
    assert_eq!(
        decoded.encrypted_objects()[0].ciphertext_bytes(),
        ciphertext_len
    );
    assert!(
        CanonicalExportV2::from_encrypted(
            namespace("other-db", "ws"),
            root("head"),
            5,
            &[encrypted],
        )
        .is_err()
    );
    assert!(
        CanonicalExportV2::from_json_bounded(&vec![b' '; MAX_CANONICAL_EXPORT_JSON_BYTES_V2 + 1])
            .is_err()
    );
    assert!(
        CanonicalExportV2::new(
            namespace("db", "ws"),
            root("head"),
            5,
            vec![decoded.encrypted_objects()[0].clone(); MAX_CANONICAL_EXPORT_OBJECTS_V2 + 1],
        )
        .is_err()
    );
}

#[test]
fn oversized_ciphertext_chunk_is_rejected_during_decode() {
    let chunk = serde_json::json!({
        "export_handle": ExportHandleV2::generate().expect("export handle"),
        "content_handle": ContentHandleV2::generate().expect("content handle"),
        "chunk_index": 0,
        "final_chunk": true,
        "ciphertext": vec![0_u8; MAX_EXPORT_CIPHERTEXT_CHUNK_BYTES_V2 + 1],
    });
    let bytes = serde_json::to_vec(&chunk).expect("chunk JSON");
    assert!(serde_json::from_slice::<ExportCiphertextChunkV2>(&bytes).is_err());
}

#[test]
fn deletion_workflow_decode_rejects_oversized_buffer_before_parse() {
    let receipt_authority =
        InMemoryReceiptAuthorityV2::random("receipt", 1).expect("receipt authority");
    assert!(
        DeletionWorkflowV2::from_json_bounded(
            &vec![b' '; MAX_DELETION_WORKFLOW_JSON_BYTES_V2 + 1],
            &AcceptAllDeletionEvidenceV2,
            &AcceptAllDeletionEvidenceV2,
            &receipt_authority,
        )
        .is_err()
    );
}

proptest! {
    #[test]
    fn arbitrary_unvalidated_content_handles_are_rejected(value in ".{0,140}") {
        let canonical = value.starts_with("cth2_")
            && value.len() == 69
            && value[5..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        prop_assert_eq!(ContentHandleV2::parse(value).is_ok(), canonical);
    }

    #[test]
    fn stale_workflow_revisions_never_advance(stale in any::<u64>().prop_filter("not current", |v| *v != 1)) {
        let mut workflow = DeletionWorkflowV2::prepare(
            namespace("db", "ws"),
            empty_inventory(),
            1,
        ).expect("prepare");
        prop_assert!(workflow.begin_suppression(stale, 2).is_err());
        prop_assert_eq!(workflow.state(), DeletionWorkflowStateV2::Prepared);
    }
}
