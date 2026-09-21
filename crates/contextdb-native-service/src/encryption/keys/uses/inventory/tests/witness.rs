use super::*;
use crate::NativePrimaryKeyAction;
use contextdb_service::CapturePort;

#[test]
fn primary_witness_requires_real_v4_history_not_legacy_allocations() {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create_version(
        &root.path().join("keys"),
        "legacy-decisions",
        master(),
        3,
    )
    .expect("legacy keys");
    let ledger =
        crate::NativeSuppressionLedger::create(root.path().join("ledger"), "legacy-decisions")
            .expect("ledger");
    let native = crate::NativeService::open_encrypted(
        root.path().join("native"),
        "legacy-decisions",
        [7; 32],
        ledger,
        keys,
    )
    .expect("legacy native");
    let input = crate::capture::tests::request(1, "legacy original");
    native.append_event(input.clone()).expect("capture");
    let removal = native
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("request");
    assert_eq!(
        native
            .retain_original_key_removal(&input.context, &removal, &mut budget())
            .expect_err("explicit migration required")
            .code,
        ErrorCode::FormatIncompatible
    );
}
use crate::retention::keys::witness::tests::fixture;

#[test]
fn primary_witness_preserves_prepared_outcomes_after_real_commit_or_abort() {
    for publish in [false, true] {
        let f = fixture();
        let space = &f.native.keyspaces.observations_content;
        let row = crate::digest_bytes(f.input.event.event_id.to_string().as_bytes()).into_bytes();
        let address = address(space, &row);
        let logical = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("read")
            .get(space, &row)
            .expect("value")
            .expect("present");
        let mut unused = PendingKeys::new();
        f.keys
            .seal_value(space, &row, &logical, &mut unused)
            .expect("unused key");
        let unused_id = unused[&address].record.id;
        f.keys
            .publish(&unused)
            .expect("allocation without preparation");
        let publication = f.keys.use_publication().expect("publisher");
        let previous = publication
            .reconcile(f.native.engine.physical())
            .expect("base");
        let before_bytes = f
            .native
            .engine
            .physical()
            .begin_read(SnapshotSelector::Latest)
            .expect("physical")
            .get(space, &row)
            .expect("cipher")
            .expect("present");
        let before = f
            .keys
            .observe_use_version(space, &row, &before_bytes, None)
            .expect("before");
        let mut pending = PendingKeys::new();
        let cipher = f
            .keys
            .seal_value(space, &row, &logical, &mut pending)
            .expect("pending cipher");
        let after = f
            .keys
            .observe_use_version(space, &row, &cipher, Some(&pending))
            .expect("after");
        let after_id = after.key_id;
        let marker = publication
            .prepare(
                &previous,
                &BTreeMap::from([(
                    address.clone(),
                    NativeKeyUseChange {
                        address_digest: address,
                        before: Some(before),
                        after: Some(after),
                    },
                )]),
                &pending,
            )
            .expect("prepare");
        if publish {
            let mut tx = f.native.engine.physical().begin_write().expect("tx");
            tx.put(space, row, cipher).expect("cipher");
            tx.put(
                &Keyspace::new(LOCAL_SPACE).expect("marker space"),
                LOCAL_HEAD.to_vec(),
                f.keys.seal_local_marker(&marker).expect("marker"),
            )
            .expect("marker row");
            tx.commit(Durability::Ephemeral)
                .expect("visible without acknowledgement");
        }
        drop(publication);
        let witness = f
            .native
            .retain_original_key_removal(&f.input.context, &f.removal, &mut budget())
            .expect("retain unresolved decision without recovery");
        for key in &witness.dispositions[&f.input.event.event_id] {
            if key.allocation.key_id == unused_id {
                assert_eq!(key.action, NativePrimaryKeyAction::AssessRetainedCopies);
                assert!(key.versions.is_empty());
            } else {
                assert_eq!(key.action, NativePrimaryKeyAction::ResolvePreparedUse);
                assert_eq!(key.unresolved_preparations.len(), 1);
            }
        }
        f.native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("idle recovery");
        assert_eq!(
            f.native
                .read_original_key_removal(
                    &f.input.context,
                    &f.removal,
                    &witness.receipt,
                    &mut budget()
                )
                .expect("later outcome cannot rewrite prior witness"),
            witness
        );
        let resolved = f
            .native
            .retain_original_key_removal(&f.input.context, &f.removal, &mut budget())
            .expect("resolved frontier");
        let after = resolved.dispositions[&f.input.event.event_id]
            .iter()
            .find(|key| key.allocation.key_id == after_id)
            .expect("after key");
        assert!(after.unresolved_preparations.is_empty());
        assert_eq!(
            after.action,
            if publish {
                NativePrimaryKeyAction::RemoveAcknowledgedCopies
            } else {
                NativePrimaryKeyAction::AssessRetainedCopies
            }
        );
        assert_eq!(after.versions.len(), 1, "aborted versions remain evidence");
    }
}
