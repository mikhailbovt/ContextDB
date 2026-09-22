use super::*;
use crate::record_journal::controls::witness::tests::{fixture, prepare};
use crate::record_sources::tests::budget;

#[test]
fn record_witness_metadata_cannot_be_replaced_by_rehashed_local_controls() {
    let f = fixture();
    let receipt = prepare(&f, "private-record", 1).expect("witness");
    let snapshot = f
        .ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let event = f
        .ledger
        .read_removal_event(&snapshot, receipt.witness_sequence)
        .expect("event");
    let Operation::RecordWitness {
        witness: declaration,
    } = &event.operation
    else {
        panic!("witness operation");
    };
    let retained = f
        .ledger
        .load_record_witness(&snapshot, &event.checkpoint(), declaration, &mut budget())
        .expect("retained witness");
    let origin = f
        .ledger
        .retained_record_sources(
            &declaration.workspace,
            &declaration.record_digest,
            declaration.revision,
        )
        .expect("origin")
        .expect("classified");
    // A document digest alone cannot validate derived links once its body is
    // erased. A locally recomputed witness must not replace accepted metadata.
    let mut value = serde_json::to_value(&retained).expect("witness JSON");
    for mutation in ["birth", "closure"] {
        value[mutation]["links"]["evidence"] = serde_json::json!(["ab".repeat(32)]);
    }
    let forged: RecordRemovalWitness = serde_json::from_value(value).expect("typed control");
    forged
        .validate(origin.record_control().expect("origin"))
        .expect("well-shaped metadata");
    assert_eq!(
        f.ledger
            .retain_record_removal_witness(
                &declaration.request,
                declaration.removed_source,
                &origin,
                &forged,
                &mut budget()
            )
            .expect_err("independent commitment rejects replacement")
            .code,
        ErrorCode::IdempotencyConflict
    );
    assert_eq!(
        prepare(&f, "private-record", 1).expect("original retry"),
        receipt
    );
    f.ledger.verify().expect("independent witness unchanged");
}

#[test]
fn record_witness_blobs_are_private_control_metadata_and_reopen_with_current_authority() {
    let f = fixture();
    let accepted = prepare(&f, "PRIVATE-CHILD", 1).expect("witness");
    let snapshot = f
        .ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let bytes = snapshot
        .get(&f.ledger.rows, &blob_key(accepted.witness_sequence))
        .expect("read")
        .expect("blob");
    let text = std::str::from_utf8(&bytes).expect("JSON");
    for raw in [
        "PRIVATE-CHILD",
        "PRIVATE-PARENT",
        "PRIVATE-PROPOSAL-BODY",
        "PRIVATE-PROPOSAL-TEXT",
        f.context.actor_id.as_str(),
        f.context.request.request_id.as_str(),
    ] {
        assert!(!text.contains(raw), "arbitrary string retained: {raw}");
    }
    f.ledger.verify().expect("complete ledger closure");
    let authority = f.ledger.authority_id();
    let path = f.ledger.path.clone();
    drop(snapshot);
    drop(f.service);
    drop(f.ledger);
    let reopened = NativeSuppressionLedger::open(&path, "record-witness", authority)
        .expect("reopen current authority");
    reopened.verify().expect("witness survives reopen");
    drop((reopened, f.root, f.ledger_directory));
}

#[test]
fn missing_or_forged_retained_witness_rows_fail_without_a_second_publication() {
    for mutation in [
        "locator",
        "blob",
        "digest",
        "orphan",
        "origin",
        "request-source",
    ] {
        let f = fixture();
        let receipt = prepare(&f, "private-record", 1).expect("witness");
        let mut tx = f.ledger.engine.begin_write().expect("transaction");
        let mut event = f
            .ledger
            .read_removal_event(&tx, receipt.witness_sequence)
            .expect("event");
        let Operation::RecordWitness { witness } = &mut event.operation else {
            panic!("witness operation");
        };
        let locator = witness.key();
        match mutation {
            "locator" => tx.delete(&f.ledger.rows, locator).expect("delete"),
            "blob" => tx
                .delete(&f.ledger.rows, blob_key(receipt.witness_sequence))
                .expect("delete"),
            "digest" => tx
                .put(
                    &f.ledger.rows,
                    blob_key(receipt.witness_sequence),
                    b"{}".to_vec(),
                )
                .expect("replace"),
            "orphan" => tx
                .put(
                    &f.ledger.rows,
                    b"removal/record-witness-blob/orphan".to_vec(),
                    b"{}".to_vec(),
                )
                .expect("orphan"),
            "origin" | "request-source" => {
                if mutation == "origin" {
                    witness.origin.digest = "ab".repeat(32);
                } else {
                    witness.removed_source = f.independent;
                }
                event.digest.clear();
                event.digest =
                    canonical_digest(&(DOMAIN, &f.ledger.identity, &event)).expect("hash");
                tx.put(
                    &f.ledger.rows,
                    event_key(event.sequence),
                    encode(&event).expect("event"),
                )
                .expect("event");
                tx.put(
                    &f.ledger.rows,
                    HEAD.to_vec(),
                    encode(&event.checkpoint()).expect("head"),
                )
                .expect("head");
                tx.put(
                    &f.ledger.rows,
                    locator,
                    encode(&event.checkpoint()).expect("locator"),
                )
                .expect("locator");
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("fixture");
        assert_eq!(
            f.ledger.verify().expect_err(mutation).code,
            ErrorCode::IntegrityFailure
        );
        if mutation != "orphan" {
            assert!(prepare(&f, "private-record", 1).is_err(), "{mutation}");
        }
        let snapshot = f
            .ledger
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        assert_eq!(
            f.ledger
                .removal_global_head(&snapshot)
                .expect("head")
                .sequence,
            receipt.witness_sequence
        );
    }
}
