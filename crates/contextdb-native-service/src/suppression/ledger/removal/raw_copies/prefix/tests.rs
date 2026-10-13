use super::*;
use crate::raw_index::copies::tests::{budget, fixture, reclaim};
use crate::raw_index::inventory::tests::request;

#[test]
fn raw_decision_prefix_rejects_lost_observations_and_damaged_later_history() {
    for fault in ["observation_blob", "later_event", "unrecorded_tail"] {
        let f = fixture();
        while !reclaim(&f, 64).finished {}
        let context = &f.first.context;
        let removal = request(&f);
        let report = f
            .native
            .read_reclaimed_raw_key_inventory(context, &removal, &mut budget())
            .expect("coverage");
        let frontier = report.observation_frontier();
        let decision = f
            .native
            .retain_reclaimed_raw_key_removal(context, &removal, &frontier, &mut budget())
            .expect("decisions");
        let first = &report.witnesses[0];
        let page = f
            .native
            .read_raw_copy_witness(context, first, &mut budget())
            .expect("page");
        f.ledger
            .retain_raw_copy_witness(&page, &mut budget())
            .expect("later event");
        let mut tx = f.ledger.engine.begin_write().expect("tx");
        match fault {
            "observation_blob" => tx
                .delete(&f.ledger.rows, blob_key(first.sequence))
                .expect("blob"),
            "later_event" => tx
                .delete(&f.ledger.rows, event_key(decision.receipt.witness_sequence))
                .expect("event after frozen prefix"),
            "unrecorded_tail" => {
                let head = f
                    .ledger
                    .read_removal_event(&tx, decision.receipt.witness_sequence)
                    .expect("older head");
                tx.put(
                    &f.ledger.rows,
                    HEAD.to_vec(),
                    encode(&head.checkpoint()).expect("head"),
                )
                .expect("false head");
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("damage");
        assert_eq!(
            f.native
                .retain_reclaimed_raw_key_removal(context, &removal, &frontier, &mut budget())
                .expect_err(fault)
                .code,
            ErrorCode::IntegrityFailure
        );
        assert_eq!(
            f.native
                .read_reclaimed_raw_key_inventory(context, &removal, &mut budget())
                .expect_err(fault)
                .code,
            ErrorCode::IntegrityFailure
        );
    }
}
