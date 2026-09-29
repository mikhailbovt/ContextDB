use super::*;
use crate::raw_index::copies::tests::{budget, fixture, reclaim};

#[test]
fn raw_copy_discovery_rejects_missing_history_and_rehashed_false_source_or_key_claims() {
    for mutation in ["blob", "event", "head", "source", "key"] {
        let f = fixture();
        let request = f
            .native
            .request_original_removal(
                &f.first.context,
                &BTreeSet::from([f.first.event.event_id]),
                "remove",
                &mut budget(),
            )
            .expect("request");
        let before = f
            .ledger
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("before");
        let previous = f.ledger.removal_global_head(&before).expect("head");
        drop(before);
        let receipt = reclaim(&f, 1024).copies.expect("witness");
        let mut tx = f.ledger.engine.begin_write().expect("fault");
        match mutation {
            "blob" => tx
                .delete(&f.ledger.rows, blob_key(receipt.sequence))
                .expect("remove blob"),
            "event" => tx
                .delete(&f.ledger.rows, event_key(receipt.sequence))
                .expect("remove event"),
            "head" => tx
                .put(
                    &f.ledger.rows,
                    HEAD.to_vec(),
                    encode(&previous).expect("old head"),
                )
                .expect("roll head back"),
            "source" | "key" => {
                let mut event = f
                    .ledger
                    .read_removal_event(&tx, receipt.sequence)
                    .expect("event");
                let Operation::RawCopies { observation } = &mut event.operation else {
                    panic!("raw observation");
                };
                let mut witness = f
                    .ledger
                    .load_raw_copy_witness(&tx, receipt.sequence, observation, &mut budget())
                    .expect("witness");
                if mutation == "source" {
                    witness
                        .sources
                        .get_mut(&f.first.event.event_id)
                        .expect("source")
                        .capture_commit += 1;
                } else {
                    witness
                        .rows
                        .iter_mut()
                        .find(|row| row.source == Some(f.first.event.event_id))
                        .expect("owned row")
                        .version
                        .as_mut()
                        .expect("encrypted version")
                        .key_id = Uuid::from_u128(31);
                }
                let bytes = encode(&witness).expect("changed witness");
                observation.witness_digest = digest_bytes(&bytes);
                event.digest.clear();
                event.digest =
                    canonical_digest(&(DOMAIN, &f.ledger.identity, &event)).expect("rehash");
                tx.put(&f.ledger.rows, blob_key(receipt.sequence), bytes)
                    .expect("blob");
                tx.put(
                    &f.ledger.rows,
                    event_key(receipt.sequence),
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
        if mutation != "key" {
            assert!(
                f.native
                    .read_raw_removal_copies(&f.first.context, &request, None, 64, &mut budget())
                    .is_err(),
                "{mutation}"
            );
        }
        assert!(
            f.native
                .read_reclaimed_raw_key_inventory(&f.first.context, &request, &mut budget())
                .is_err(),
            "{mutation} cannot produce a complete key report"
        );
    }
}
