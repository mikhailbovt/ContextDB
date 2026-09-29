use super::*;
use crate::record_journal::controls::witness::tests::{fixture, prepare};
use crate::record_sources::tests::budget;

#[test]
fn retained_record_validation_loss_is_not_absence_or_permission_to_republish() {
    for mutation in ["locator", "event", "orphan"] {
        let f = fixture();
        let witness = prepare(&f, "private-record", 1).expect("witness");
        f.service
            .prune_record_revision(&f.context, &witness, &mut budget())
            .expect("prune");
        let mut tx = f.ledger.engine.begin_write().expect("transaction");
        let head = f.ledger.removal_global_head(&tx).expect("head");
        let rows = tx
            .scan_prefix(&f.ledger.rows, b"removal/record-validation/")
            .expect("validations");
        assert_eq!(rows.len(), 2);
        let row = &rows[0];
        let checkpoint: RemovalCheckpoint = decode(&row.value, "checkpoint").expect("checkpoint");
        match mutation {
            "locator" => tx
                .delete(&f.ledger.rows, row.key.clone())
                .expect("delete locator"),
            "event" => tx
                .delete(&f.ledger.rows, event_key(checkpoint.sequence))
                .expect("delete event"),
            "orphan" => tx
                .put(
                    &f.ledger.rows,
                    b"removal/record-validation/orphan".to_vec(),
                    row.value.clone(),
                )
                .expect("orphan"),
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("fixture");
        assert_eq!(
            f.ledger.verify().expect_err(mutation).code,
            ErrorCode::IntegrityFailure
        );
        if mutation != "orphan" {
            assert!(
                f.service
                    .prune_record_revision(&f.context, &witness, &mut budget())
                    .is_err()
            );
        }
        let after = f
            .ledger
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        assert_eq!(f.ledger.removal_global_head(&after).expect("head"), head);
    }
}
