use super::*;
use crate::assertions::retention::witness::tests::{budget, fixture, retry};

#[test]
fn assertion_witness_omits_values_rejects_replacement_and_reopens() {
    let f = fixture();
    let snapshot = f
        .ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let event = f
        .ledger
        .read_removal_event(&snapshot, f.witness.witness_sequence)
        .expect("event");
    let Operation::AssertionWitness {
        witness: declaration,
    } = &event.operation
    else {
        panic!("assertion witness operation");
    };
    let bytes = snapshot
        .get(&f.ledger.rows, &blob_key(event.sequence))
        .expect("read")
        .expect("blob");
    let text = std::str::from_utf8(&bytes).expect("JSON");
    for raw in [
        "raw-private-assertion-source",
        "semanticremovalsentinel",
        "removed-envelope-sentinel",
        "independent-semantic-value",
        "verified-fixture-interpreter",
        f.first.context.actor_id.as_str(),
    ] {
        assert!(
            !text.contains(raw),
            "arbitrary source content retained: {raw}"
        );
    }
    let witness: AssertionRemovalWitness = decode(&bytes, "witness").expect("typed witness");
    let mut value = serde_json::to_value(&witness).expect("JSON");
    value["mutations"][1]["source_digest"] = serde_json::json!("ab".repeat(32));
    let forged: AssertionRemovalWitness =
        serde_json::from_value(value).expect("typed changed metadata");
    forged
        .validate(&f.ledger.identity.database, &declaration.workspace)
        .expect("well shaped");
    assert_eq!(
        f.ledger
            .retain_assertion_removal_witness(&declaration.request, &forged, &mut budget())
            .expect_err("existing witness is immutable")
            .code,
        ErrorCode::IdempotencyConflict
    );
    assert_eq!(retry(&f).expect("exact retry"), f.witness);
    f.ledger.verify().expect("exact independent closure");
    let authority = f.ledger.authority_id();
    let path = f.ledger.path.clone();
    drop(snapshot);
    drop(f.native);
    drop(f.ledger);
    let reopened = NativeSuppressionLedger::open(path, "assertion-witness", authority)
        .expect("actual authority reopen");
    reopened.verify().expect("reopened witness closure");
    let (restored, selected) = reopened
        .read_assertion_removal_witness(&f.witness, &mut budget())
        .expect("readback");
    assert_eq!(restored, witness);
    assert_eq!(selected, BTreeSet::from([1]));
    drop((reopened, f.root, f.ledger_directory));
}

#[test]
fn assertion_witness_loss_or_rehashed_false_selection_cannot_mint_new_acceptance() {
    for mutation in [
        "locator",
        "blob",
        "digest",
        "selection",
        "request",
        "orphan",
    ] {
        let f = fixture();
        let mut tx = f.ledger.engine.begin_write().expect("tx");
        let mut event = f
            .ledger
            .read_removal_event(&tx, f.witness.witness_sequence)
            .expect("event");
        let Operation::AssertionWitness {
            witness: declaration,
        } = &mut event.operation
        else {
            panic!("assertion witness operation");
        };
        let locator = declaration.key();
        match mutation {
            "locator" => tx.delete(&f.ledger.rows, locator).expect("delete"),
            "blob" => tx
                .delete(&f.ledger.rows, blob_key(event.sequence))
                .expect("delete"),
            "digest" => tx
                .put(&f.ledger.rows, blob_key(event.sequence), b"{}".to_vec())
                .expect("replace"),
            "request" => tx
                .delete(&f.ledger.rows, event_key(declaration.request.sequence))
                .expect("delete request"),
            "orphan" => tx
                .put(
                    &f.ledger.rows,
                    b"removal/assertion-witness-blob/orphan".to_vec(),
                    b"{}".to_vec(),
                )
                .expect("orphan"),
            "selection" => {
                declaration.selected = BTreeSet::from([1, 3]);
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
        tx.commit(Durability::Sync)
            .expect("persist fixture mutation");
        assert_eq!(
            f.ledger.verify().expect_err(mutation).code,
            ErrorCode::IntegrityFailure
        );
        if mutation != "orphan" {
            assert!(
                f.native
                    .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
                    .is_err(),
                "{mutation}"
            );
            assert!(retry(&f).is_err(), "{mutation}");
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
            f.witness.witness_sequence
        );
    }
}
