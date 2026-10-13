use super::*;
use crate::capture::tests::request;
use contextdb_service::{CapturePort, CaptureRequest, PayloadPort, StagePayloadRequest};
use std::sync::Arc;

pub(crate) use crate::retention::keys::witness::tests::budget;

pub(crate) struct Fixture {
    pub root: tempfile::TempDir,
    pub native: Arc<NativeService>,
    pub keys: Arc<NativeCustodyKeys>,
    pub ledger: Arc<NativeSuppressionLedger>,
    pub input: CaptureRequest,
    pub payload: OriginalPayloadRef,
    pub removal: NativeRemovalRequestReceipt,
    pub witness: NativeOwnedKeyRemovalWitness,
}

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([89; 32])).expect("master")
}

pub(crate) fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "owned-decisions", master())
        .expect("keys");
    let ledger = NativeSuppressionLedger::create(root.path().join("ledger"), "owned-decisions")
        .expect("ledger");
    let native = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            "owned-decisions",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native"),
    );
    let mut input = request(1, "placeholder");
    let payload = native
        .stage_payload(StagePayloadRequest {
            context: input.context.clone(),
            idempotency_key: "payload".into(),
            block_id: ContentBlockId::new(),
            bytes: b"private-owned-payload-sentinel"
                .iter()
                .copied()
                .cycle()
                .take(256 * 1024 + 17)
                .collect(),
        })
        .expect("stage")
        .reference;
    input.event.payload = contextdb_core::EventPayload::Staged {
        reference: payload.clone(),
        media_type: "text/plain".into(),
    };
    native.append_event(input.clone()).expect("capture");
    let removal = native
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("remove request");
    let witness = native
        .retain_payload_key_removal(&input.context, &removal, payload.block_id, &mut budget())
        .expect("retain decisions");
    Fixture {
        root,
        native,
        keys,
        ledger,
        input,
        payload,
        removal,
        witness,
    }
}

#[test]
fn owned_decisions_reopen_both_authorities_and_retry_without_native_publication() {
    let f = fixture();
    let before = f.native.verify_native(true).expect("before");
    assert_eq!(f.witness.dispositions.len(), 2);
    for keys in f.witness.dispositions.values() {
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].action,
            NativeOwnedKeyAction::RemoveAcknowledgedCopies
        );
        assert_eq!(keys[0].versions.len(), 1);
        assert_eq!(keys[0].acknowledged_instances.len(), 1);
    }
    assert_eq!(
        f.native
            .retain_payload_key_removal(
                &f.input.context,
                &f.removal,
                f.payload.block_id,
                &mut budget()
            )
            .expect("exact retry"),
        f.witness
    );
    assert_eq!(
        f.native.verify_native(true).expect("after").archive_digest,
        before.archive_digest
    );
    assert!(
        !String::from_utf8(encode(&f.witness).expect("json"))
            .expect("text")
            .contains("private-owned-payload-sentinel")
    );
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "owned-decisions",
        key_id,
        master(),
    )
    .expect("keys reopen");
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "owned-decisions", ledger_id)
            .expect("ledger reopen");
    let native = NativeService::open_encrypted(
        f.root.path().join("native"),
        "owned-decisions",
        [8; 32],
        ledger,
        keys,
    )
    .expect("native reopen");
    assert_eq!(
        native
            .read_payload_key_removal(
                &f.input.context,
                &f.removal,
                f.payload.block_id,
                &f.witness.receipt,
                &mut budget()
            )
            .expect("historical witness"),
        f.witness
    );
}

#[test]
fn owned_decisions_require_admin_and_request_and_fence_both_custody_frontiers() {
    let f = fixture();
    for fault in ["admin", "workspace"] {
        let mut denied = f.input.context.clone();
        match fault {
            "admin" => {
                denied.capability_grants.remove(&Capability::Admin);
            }
            "workspace" => denied.request.workspace_id = "another-workspace".into(),
            _ => unreachable!(),
        }
        assert!(
            f.native
                .retain_payload_key_removal(&denied, &f.removal, f.payload.block_id, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.native
                .read_payload_key_removal(
                    &denied,
                    &f.removal,
                    f.payload.block_id,
                    &f.witness.receipt,
                    &mut budget()
                )
                .is_err(),
            "{fault}"
        );
    }
    let mut forged = f.witness.receipt.clone();
    forged.removal_sequence += 1;
    assert!(
        f.native
            .read_payload_key_removal(
                &f.input.context,
                &f.removal,
                f.payload.block_id,
                &forged,
                &mut budget()
            )
            .is_err()
    );
    let mut exhausted =
        QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert_eq!(
        f.native
            .retain_payload_key_removal(
                &f.input.context,
                &f.removal,
                f.payload.block_id,
                &mut exhausted
            )
            .expect_err("budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    for allocate in [false, true] {
        let native = f.native.clone();
        BEFORE_WITNESS_FENCE.with(|hook| {
            hook.replace(Some(Box::new(move || {
                let mut tx = native.engine.begin_write().expect("concurrent tx");
                let space = keyspace("owned-witness-race").expect("space");
                if allocate {
                    tx.put(&space, b"other".to_vec(), b"independent".to_vec())
                        .expect("allocate");
                } else {
                    tx.delete(&space, b"absent".to_vec())
                        .expect("use-only growth");
                }
                tx.commit(Durability::Sync).expect("concurrent publication");
            })))
        });
        assert_eq!(
            f.native
                .retain_payload_key_removal(
                    &f.input.context,
                    &f.removal,
                    f.payload.block_id,
                    &mut budget()
                )
                .expect_err("frontier race")
                .code,
            ErrorCode::IndexTooStale
        );
    }
    assert_eq!(
        f.native
            .read_payload_key_removal(
                &f.input.context,
                &f.removal,
                f.payload.block_id,
                &f.witness.receipt,
                &mut budget()
            )
            .expect("old history"),
        f.witness
    );
    let later = f
        .native
        .retain_payload_key_removal(
            &f.input.context,
            &f.removal,
            f.payload.block_id,
            &mut budget(),
        )
        .expect("fresh frontier");
    assert_ne!(later.receipt, f.witness.receipt);
    assert_eq!(later.dispositions, f.witness.dispositions);
}
