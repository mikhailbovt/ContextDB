use super::*;
use crate::raw_index::copies::tests::{budget, fixture};
use crate::raw_index::inventory::tests::{gather, request};
use uuid::Uuid;

#[test]
fn raw_index_inventory_damage_and_rehashed_claims_cannot_create_key_coverage() {
    for mutation in [
        "blob",
        "locator",
        "event",
        "head",
        "source",
        "key",
        "manifest",
        "chain",
        "repeated_address",
        "deep_blob",
    ] {
        let f = fixture();
        let request = request(&f);
        let first = f
            .native
            .inventory_raw_removal_copies(&f.first.context, &request, None, 1024, &mut budget())
            .expect("first generation");
        let final_page = f
            .native
            .inventory_raw_removal_copies(
                &f.first.context,
                &request,
                first.continuation.as_deref(),
                1024,
                &mut budget(),
            )
            .expect("final generation");
        let mut receipt = final_page.receipt.clone();
        let mut deep_first = None;
        if mutation == "deep_blob" {
            let pages = gather(&f.native, &f.first.context, &request);
            deep_first = Some(pages[0].receipt.sequence);
            receipt = pages.last().expect("terminal").receipt.clone();
        }
        let mut tx = f.ledger.engine.begin_write().expect("fault");
        let first_event = f
            .ledger
            .read_removal_event(&tx, first.receipt.sequence)
            .expect("first event");
        let Operation::RawIndexInventory {
            witness: first_declaration,
        } = &first_event.operation
        else {
            panic!("inspection");
        };
        match mutation {
            "blob" => tx
                .delete(&f.ledger.rows, blob_key(first.receipt.sequence))
                .expect("missing ancestor blob"),
            "deep_blob" => tx
                .delete(&f.ledger.rows, blob_key(deep_first.expect("deep ancestor")))
                .expect("missing deep blob"),
            "locator" => tx
                .delete(&f.ledger.rows, first_declaration.key())
                .expect("missing ancestor locator"),
            "event" => tx
                .delete(&f.ledger.rows, event_key(first.receipt.sequence))
                .expect("missing event"),
            "head" => tx
                .put(
                    &f.ledger.rows,
                    HEAD.to_vec(),
                    encode(&RemovalCheckpoint {
                        sequence: request.sequence,
                        digest: request.digest.clone(),
                    })
                    .expect("old head"),
                )
                .expect("rollback"),
            _ => {
                let mut event = f
                    .ledger
                    .read_removal_event(&tx, receipt.sequence)
                    .expect("event");
                let checkpoint = event.checkpoint();
                let Operation::RawIndexInventory {
                    witness: declaration,
                } = &mut event.operation
                else {
                    panic!("inspection");
                };
                let old_key = declaration.key();
                let mut witness = f
                    .ledger
                    .load_raw_index_inventory(&tx, &checkpoint, declaration, &mut budget())
                    .expect("witness");
                match mutation {
                    "source" => {
                        witness
                            .sources
                            .get_mut(&f.first.event.event_id)
                            .expect("selected source")
                            .capture_commit += 1
                    }
                    "key" => {
                        witness
                            .rows
                            .iter_mut()
                            .find(|row| row.source == Some(f.first.event.event_id))
                            .expect("selected row")
                            .version
                            .as_mut()
                            .expect("ciphertext")
                            .key_id = Uuid::from_u128(31)
                    }
                    "manifest" => {
                        witness
                            .rows
                            .iter_mut()
                            .find(|row| row.kind == NativeRawCopyKind::Manifest)
                            .expect("manifest")
                            .value_digest = digest_bytes(b"not-the-manifest")
                    }
                    "chain" => {
                        witness.rows_before = 1;
                        witness.after_digest = first.witness.last_digest.clone();
                    }
                    "repeated_address" => {
                        let row = first
                            .witness
                            .rows
                            .iter()
                            .find(|row| row.source == Some(f.first.event.event_id))
                            .expect("source row")
                            .clone();
                        witness.last_digest = Some(row.address_digest.clone());
                        witness.rows.insert(witness.rows.len() - 1, row);
                    }
                    _ => unreachable!(),
                }
                let bytes = encode(&witness).expect("changed body");
                declaration.witness_digest = digest_bytes(&bytes);
                declaration.identity = witness.identity_digest().expect("changed identity");
                let key = declaration.key();
                event.digest.clear();
                event.digest =
                    canonical_digest(&(DOMAIN, &f.ledger.identity, &event)).expect("rehash");
                tx.delete(&f.ledger.rows, old_key).expect("old locator");
                tx.put(
                    &f.ledger.rows,
                    key,
                    encode(&event.checkpoint()).expect("new locator"),
                )
                .expect("locator");
                tx.put(&f.ledger.rows, blob_key(event.sequence), bytes)
                    .expect("blob");
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
                receipt.digest = event.digest;
            }
        }
        tx.commit(Durability::Sync).expect("fault commit");
        assert!(
            f.native
                .read_raw_index_key_inventory(&f.first.context, &request, &receipt, &mut budget())
                .is_err(),
            "{mutation} cannot establish full source key coverage"
        );
        if !matches!(
            mutation,
            "key" | "repeated_address" | "deep_blob" | "locator"
        ) {
            assert!(
                f.native
                    .read_raw_index_inventory_witness(&f.first.context, &receipt, &mut budget())
                    .is_err(),
                "{mutation}"
            );
        }
        if matches!(mutation, "locator" | "head") {
            assert!(
                f.native
                    .inventory_raw_removal_copies(
                        &f.first.context,
                        &request,
                        None,
                        1024,
                        &mut budget()
                    )
                    .is_err(),
                "lost accepted history cannot mint replacement acceptance"
            );
        }
    }
}

#[test]
fn raw_index_inventory_retains_lost_ack_without_native_mutation_and_retries_once() {
    let f = fixture();
    let request = request(&f);
    let head = f.native.engine.head_sequence().expect("head");
    let cancellation = contextdb_recall::QueryCancellation::default();
    let stop = cancellation.clone();
    AFTER_RETAIN.with(|hook| *hook.borrow_mut() = Some(Box::new(move || stop.cancel())));
    let mut allowance = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        cancellation,
    );
    assert_eq!(
        f.native
            .inventory_raw_removal_copies(&f.first.context, &request, None, 3, &mut allowance)
            .expect_err("lost ack")
            .code,
        ErrorCode::BudgetExhausted
    );
    let retained = f.ledger.engine.head_sequence().expect("retained head");
    let page = f
        .native
        .inventory_raw_removal_copies(&f.first.context, &request, None, 3, &mut budget())
        .expect("retry");
    assert_eq!(
        f.ledger
            .engine
            .head_sequence()
            .expect("no second acceptance"),
        retained
    );
    assert_eq!(
        f.native.engine.head_sequence().expect("no native writes"),
        head
    );
    assert_eq!(
        f.native
            .read_raw_index_inventory_witness(&f.first.context, &page.receipt, &mut budget())
            .expect("retained witness"),
        page.witness
    );
}
