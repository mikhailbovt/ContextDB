use super::*;
use crate::raw_index::copies::tests::{budget, fixture, reclaim};

#[test]
fn raw_copy_lost_ack_keeps_observation_without_deleting_native_rows() {
    let f = fixture();
    let before = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("native");
    let head = f.native.global_head(&before).expect("head");
    let rows = before
        .scan_prefix(&f.native.keyspaces.continuous, b"raw/")
        .expect("rows");
    drop(before);
    let cancel = contextdb_recall::QueryCancellation::default();
    let signal = cancel.clone();
    AFTER_RETAIN.with(|hook| hook.replace(Some(Box::new(move || signal.cancel()))));
    let mut cancelled = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        cancel,
    );
    assert_eq!(
        f.native
            .reclaim_raw_generations(&f.first.context, 1, &mut cancelled)
            .expect_err("lost observation acknowledgement")
            .code,
        ErrorCode::BudgetExhausted
    );
    let after = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("native");
    assert_eq!(f.native.global_head(&after).expect("head"), head);
    assert_eq!(
        after
            .scan_prefix(&f.native.keyspaces.continuous, b"raw/")
            .expect("rows"),
        rows
    );
    let retained = f
        .ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("retained");
    let lost = f.ledger.removal_global_head(&retained).expect("head");
    let receipt = NativeRawCopyReceipt {
        authority_id: f.ledger.authority_id(),
        sequence: lost.sequence,
        digest: lost.digest,
    };
    let witness = f
        .native
        .read_raw_copy_witness(&f.first.context, &receipt, &mut budget())
        .expect("accepted observation survives cancellation");
    assert_eq!(witness.native_commit, head);
    assert_eq!(witness.removed_before, 0);
    let retry = reclaim(&f, 1).copies.expect("retry receipt");
    assert!(retry.sequence > receipt.sequence);
    assert_eq!(
        f.native
            .read_raw_copy_witness(&f.first.context, &retry, &mut budget())
            .expect("retry"),
        witness
    );
    f.ledger.verify().expect("both observations retained");
    f.native
        .verify_native(true)
        .expect("only committed native GC is published");
}

#[test]
fn raw_copy_missing_blobs_or_rehashed_false_page_links_fail_closed() {
    for mutation in ["missing", "digest", "previous", "orphan", "state"] {
        let f = fixture();
        let first = reclaim(&f, 1).copies.expect("first");
        let second = reclaim(&f, 1).copies.expect("second");
        if mutation == "state" {
            let mut tx = f.native.engine.begin_write().expect("native fault");
            let key = raw_index::state_key(&digest_bytes(
                f.first.context.request.workspace_id.as_bytes(),
            ));
            let mut state: raw_index::IndexState = decode(
                &tx.get(&f.native.keyspaces.continuous, &key)
                    .expect("read")
                    .expect("state"),
                "state",
            )
            .expect("decode");
            state.reclaiming.as_mut().expect("job").copies = Some(first);
            tx.put(
                &f.native.keyspaces.continuous,
                key,
                encode(&state).expect("state"),
            )
            .expect("put");
            tx.commit(Durability::Sync).expect("fault");
            assert!(f.native.verify_native(true).is_err());
            continue;
        }
        let mut tx = f.ledger.engine.begin_write().expect("retained fault");
        match mutation {
            "missing" => tx
                .delete(&f.ledger.rows, blob_key(first.sequence))
                .expect("remove predecessor"),
            "digest" => tx
                .put(&f.ledger.rows, blob_key(second.sequence), b"{}".to_vec())
                .expect("damage blob"),
            "orphan" => tx
                .put(
                    &f.ledger.rows,
                    blob_key(second.sequence + 1),
                    b"{}".to_vec(),
                )
                .expect("orphan"),
            "previous" => {
                let mut event = f
                    .ledger
                    .read_removal_event(&tx, second.sequence)
                    .expect("event");
                let Operation::RawCopies { observation } = &mut event.operation else {
                    panic!("observation");
                };
                let mut witness = f
                    .ledger
                    .load_raw_copy_witness(&tx, second.sequence, observation, &mut budget())
                    .expect("witness");
                witness.removed_before += 1;
                let bytes = encode(&witness).expect("changed witness");
                observation.witness_digest = digest_bytes(&bytes);
                event.digest.clear();
                event.digest =
                    canonical_digest(&(DOMAIN, &f.ledger.identity, &event)).expect("rehash");
                tx.put(&f.ledger.rows, blob_key(second.sequence), bytes)
                    .expect("blob");
                tx.put(
                    &f.ledger.rows,
                    event_key(second.sequence),
                    encode(&event).expect("event"),
                )
                .expect("event");
                tx.put(
                    &f.ledger.rows,
                    HEAD.to_vec(),
                    encode(&event.checkpoint()).expect("head"),
                )
                .expect("head");
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("fault commit");
        assert!(
            f.ledger.verify().is_err(),
            "{mutation} cannot pass independent reverse closure"
        );
        if mutation != "orphan" {
            assert!(
                f.native.verify_native(true).is_err(),
                "{mutation} cannot pass native verification"
            );
        }
    }
}
