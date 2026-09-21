use super::*;
use crate::retention::keys::owned::tests::{budget, fixture};

#[test]
fn owned_witness_loss_cannot_be_retried_as_a_new_acceptance() {
    for fault in ["locator", "blob", "request", "orphan"] {
        let f = fixture();
        let mut tx = f.ledger.engine.begin_write().expect("tx");
        let event = f
            .ledger
            .read_removal_event(&tx, f.witness.receipt.witness_sequence)
            .expect("event");
        let Operation::OwnedKeys {
            witness: declaration,
        } = &event.operation
        else {
            panic!("owned witness");
        };
        match fault {
            "locator" => tx
                .delete(&f.ledger.rows, declaration.key())
                .expect("locator"),
            "blob" => tx
                .delete(&f.ledger.rows, blob_key(event.sequence))
                .expect("blob"),
            "request" => tx
                .delete(&f.ledger.rows, event_key(declaration.request.sequence))
                .expect("request"),
            "orphan" => tx
                .put(
                    &f.ledger.rows,
                    b"removal/owned-keys-blob/orphan".to_vec(),
                    b"{}".to_vec(),
                )
                .expect("orphan"),
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("damage");
        assert_eq!(
            f.ledger.verify().expect_err(fault).code,
            ErrorCode::IntegrityFailure,
            "{fault}"
        );
        if fault != "orphan" {
            assert!(
                f.native
                    .retain_payload_key_removal(
                        &f.input.context,
                        &f.removal,
                        f.payload.block_id,
                        &mut budget()
                    )
                    .is_err()
            );
            assert!(
                f.native
                    .read_payload_key_removal(
                        &f.input.context,
                        &f.removal,
                        f.payload.block_id,
                        &f.witness.receipt,
                        &mut budget()
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn rehashed_owned_version_cannot_override_independent_custody_history() {
    for fault in [
        "value",
        "acknowledged",
        "allocation",
        "use_frontier",
        "allocation_frontier",
        "owner",
    ] {
        let f = fixture();
        let mut inventory = f.witness.inventory.clone();
        let usage = &mut inventory.native_use;
        let address = usage.addresses.values_mut().next().expect("source");
        match fault {
            "value" => {
                address.transitions[0]
                    .after
                    .as_mut()
                    .expect("version")
                    .value_digest = "ab".repeat(32)
            }
            "acknowledged" => address.acknowledged.clear(),
            "allocation" => {
                (match &mut inventory.owner {
                    NativeOwnedKeyOwner::Payload { chunks, .. } => {
                        &mut chunks.values_mut().next().expect("keys")[0]
                    }
                    _ => unreachable!(),
                })
                .descriptor_digest = "ab".repeat(32)
            }
            "use_frontier" => usage.revision_digest = Some("ab".repeat(32)),
            "allocation_frontier" => inventory.allocation_digest = Some("ab".repeat(32)),
            "owner" => {
                (match &mut inventory.owner {
                    NativeOwnedKeyOwner::Payload { chunks, .. } => {
                        &mut chunks.values_mut().next().expect("keys")[0]
                    }
                    _ => unreachable!(),
                })
                .address_digest = "ab".repeat(32)
            }
            _ => unreachable!(),
        }
        let bytes = encode(&inventory).expect("inventory");
        let mut tx = f.ledger.engine.begin_write().expect("tx");
        let mut event = f
            .ledger
            .read_removal_event(&tx, f.witness.receipt.witness_sequence)
            .expect("event");
        let Operation::OwnedKeys {
            witness: declaration,
        } = &mut event.operation
        else {
            panic!("owned witness");
        };
        let old_key = declaration.key();
        *declaration =
            OwnedKeyDeclaration::from_inventory(&inventory, &bytes).expect("declaration");
        let new_key = declaration.key();
        event.digest.clear();
        event.digest = canonical_digest(&(DOMAIN, &f.ledger.identity, &event)).expect("rehash");
        let receipt = owned_receipt(&f.ledger, &event.checkpoint(), f.removal.sequence);
        tx.delete(&f.ledger.rows, old_key).expect("old locator");
        tx.put(
            &f.ledger.rows,
            new_key,
            encode(&event.checkpoint()).expect("locator"),
        )
        .expect("locator");
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
        tx.commit(Durability::Sync).expect("coherent false ledger");
        if fault == "owner" {
            assert!(f.ledger.verify().is_err());
        } else {
            f.ledger
                .verify()
                .expect("custody semantics are independently checked by service");
        }
        assert_eq!(
            f.native
                .read_payload_key_removal(
                    &f.input.context,
                    &f.removal,
                    f.payload.block_id,
                    &receipt,
                    &mut budget()
                )
                .expect_err(fault)
                .code,
            ErrorCode::IntegrityFailure
        );
    }
}
