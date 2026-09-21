use super::*;
use crate::assertions::retention::witness::tests::budget;
use crate::assertions::retention::witness::values::tests::pruned_fixture;

#[test]
fn assertion_value_ownership_rejects_missing_rows_and_rehashed_false_composition() {
    for fault in ["locator", "blob", "source_witness", "orphan", "composition"] {
        let (f, receipt) = pruned_fixture();
        let mut tx = f.ledger.engine.begin_write().expect("damage tx");
        let mut event = f
            .ledger
            .read_removal_event(&tx, receipt.witness_sequence)
            .expect("event");
        let Operation::AssertionValues {
            witness: declaration,
        } = &mut event.operation
        else {
            panic!("value declaration");
        };
        match fault {
            "locator" => tx
                .delete(&f.ledger.rows, declaration.key())
                .expect("locator"),
            "blob" => tx
                .delete(&f.ledger.rows, blob_key(event.sequence))
                .expect("blob"),
            "source_witness" => tx
                .delete(&f.ledger.rows, event_key(f.witness.witness_sequence))
                .expect("owner event"),
            "orphan" => tx
                .put(
                    &f.ledger.rows,
                    b"removal/assertion-values-blob/orphan".to_vec(),
                    b"{}".to_vec(),
                )
                .expect("orphan"),
            "composition" => {
                let bytes = tx
                    .get(&f.ledger.rows, &blob_key(event.sequence))
                    .expect("read")
                    .expect("blob");
                let mut json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
                let values = json["body"]["values"].as_array_mut().expect("values");
                for value in values {
                    if value["owner"]["kind"] == "batch" && value["owner"]["value"] == "retained" {
                        value["live_mutations"] = serde_json::json!([]);
                    }
                }
                let forged: AttestedAssertionValues =
                    serde_json::from_value(json).expect("typed false composition");
                let bytes = encode(&forged).expect("bytes");
                let old_key = declaration.key();
                declaration.classification_digest =
                    canonical_digest(&forged.body).expect("body digest");
                declaration.witness_digest = digest_bytes(&bytes);
                let new_key = declaration.key();
                event.digest.clear();
                event.digest =
                    canonical_digest(&(DOMAIN, &f.ledger.identity, &event)).expect("event digest");
                tx.delete(&f.ledger.rows, old_key).expect("old locator");
                tx.put(
                    &f.ledger.rows,
                    new_key,
                    encode(&event.checkpoint()).expect("locator"),
                )
                .expect("new locator");
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
                tx.put(&f.ledger.rows, blob_key(event.sequence), bytes)
                    .expect("blob");
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("persist fault");
        if fault == "composition" {
            f.ledger
                .verify()
                .expect("structural ledger commitments can be rehashed");
        } else {
            assert_eq!(
                f.ledger.verify().expect_err(fault).code,
                ErrorCode::IntegrityFailure
            );
        }
        if fault != "orphan" {
            assert_eq!(
                f.native
                    .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
                    .expect_err(fault)
                    .code,
                ErrorCode::IntegrityFailure
            );
            assert!(f.native.verify_native(true).is_err(), "{fault}");
        }
    }
}
