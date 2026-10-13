use super::*;
use crate::capture::tests::request;
use contextdb_service::{CapturePort, CaptureRequest};
use std::{sync::Arc, time::Duration};

pub(crate) fn budget() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        256 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

pub(crate) struct Fixture {
    pub root: tempfile::TempDir,
    pub native: Arc<NativeService>,
    pub keys: Arc<NativeCustodyKeys>,
    pub ledger: Arc<NativeSuppressionLedger>,
    pub input: CaptureRequest,
    pub removal: NativeRemovalRequestReceipt,
    pub witness: NativePrimaryKeyRemovalWitness,
}

pub(crate) fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "primary-decisions", master())
        .expect("keys");
    let ledger = NativeSuppressionLedger::create(root.path().join("ledger"), "primary-decisions")
        .expect("ledger");
    let native = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            "primary-decisions",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native"),
    );
    let input = request(1, "private-original-witness-sentinel");
    native.append_event(input.clone()).expect("capture");
    native
        .append_event(request(2, "independent-original-witness-sentinel"))
        .expect("independent");
    let removal = native
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("request");
    let witness = native
        .retain_original_key_removal(&input.context, &removal, &mut budget())
        .expect("retain");
    Fixture {
        root,
        native,
        keys,
        ledger,
        input,
        removal,
        witness,
    }
}

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master")
}

#[test]
fn primary_decisions_survive_both_authority_reopens_without_native_publication() {
    let f = fixture();
    let state = f.native.verify_native(true).expect("native state");
    assert_eq!(f.witness.dispositions.len(), 1);
    let selected = &f.witness.dispositions[&f.input.event.event_id];
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0].action,
        NativePrimaryKeyAction::RemoveAcknowledgedCopies
    );
    assert_eq!(selected[0].versions.len(), 1);
    assert_eq!(selected[0].acknowledged_instances.len(), 1);
    assert_eq!(
        f.native
            .retain_original_key_removal(&f.input.context, &f.removal, &mut budget())
            .expect("same frontier"),
        f.witness
    );
    assert_eq!(
        f.native
            .verify_native(true)
            .expect("unchanged")
            .archive_digest,
        state.archive_digest
    );
    let text = String::from_utf8(encode(&f.witness).expect("json")).expect("text");
    assert!(!text.contains("original-witness-sentinel"));
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_id,
        master(),
    )
    .expect("actual keys reopen");
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "primary-decisions", ledger_id)
            .expect("actual ledger reopen");
    let native = NativeService::open_encrypted(
        f.root.path().join("native"),
        "primary-decisions",
        [8; 32],
        ledger,
        keys,
    )
    .expect("native reopen");
    assert_eq!(
        native
            .read_original_key_removal(
                &f.input.context,
                &f.removal,
                &f.witness.receipt,
                &mut budget()
            )
            .expect("read retained"),
        f.witness
    );
}

#[test]
fn primary_decisions_require_admin_exact_request_and_unchanged_publication_frontiers() {
    let f = fixture();
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    for read in [false, true] {
        let result = if read {
            f.native.read_original_key_removal(
                &denied,
                &f.removal,
                &f.witness.receipt,
                &mut budget(),
            )
        } else {
            f.native
                .retain_original_key_removal(&denied, &f.removal, &mut budget())
        };
        assert_eq!(result.expect_err("admin").code, ErrorCode::Unauthorized);
    }
    let mut other_scope = f.input.context.clone();
    other_scope.request.workspace_id = "another-workspace".into();
    assert!(
        f.native
            .read_original_key_removal(&other_scope, &f.removal, &f.witness.receipt, &mut budget())
            .is_err()
    );
    let mut forged = f.witness.receipt.clone();
    forged.removal_sequence += 1;
    assert!(
        f.native
            .read_original_key_removal(&f.input.context, &f.removal, &forged, &mut budget())
            .is_err()
    );
    let mut empty = QueryBudget::new(0, 0, Duration::from_secs(30), Default::default());
    assert_eq!(
        f.native
            .retain_original_key_removal(&f.input.context, &f.removal, &mut empty)
            .expect_err("budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    for allocate in [false, true] {
        let native = f.native.clone();
        BEFORE_WITNESS_FENCE.with(|hook| {
            hook.replace(Some(Box::new(move || {
                let mut tx = native.engine.begin_write().expect("concurrent tx");
                let space = keyspace("witness-race-fixture").expect("space");
                if allocate {
                    tx.put(&space, b"other".to_vec(), b"independent".to_vec())
                        .expect("allocate");
                } else {
                    tx.delete(&space, b"absent".to_vec())
                        .expect("native-use-only growth");
                }
                tx.commit(Durability::Sync).expect("concurrent publication");
            })))
        });
        assert_eq!(
            f.native
                .retain_original_key_removal(&f.input.context, &f.removal, &mut budget())
                .expect_err("frontier race")
                .code,
            ErrorCode::IndexTooStale
        );
    }
    assert_eq!(
        f.native
            .read_original_key_removal(
                &f.input.context,
                &f.removal,
                &f.witness.receipt,
                &mut budget()
            )
            .expect("old checkpoint remains exact"),
        f.witness
    );
    let later = f
        .native
        .retain_original_key_removal(&f.input.context, &f.removal, &mut budget())
        .expect("fresh frontier");
    assert_ne!(later.receipt, f.witness.receipt);
    assert_eq!(later.dispositions, f.witness.dispositions);
}
