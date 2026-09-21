use super::*;
use crate::assertions::retention::tests::{prepare, remove};
use crate::assertions::retention::witness::archives::tests::{Fixture, fixture, master, prune};
use crate::assertions::retention::witness::tests::budget;
use crate::{NativeCustodyKeys, NativeSuppressionLedger};
use contextdb_service::{BackupResponse, CognitiveMemoryService, RestoreBackupRequest};

fn selection(f: &Fixture) -> NativeRemovalKeySelection {
    NativeRemovalKeySelection::Assertions {
        witness: f.witness.clone(),
    }
}

fn selected_keys(f: &Fixture) -> BTreeSet<Uuid> {
    keys_for(&f.native, &f.first.context, &f.removal, &f.witness)
}

fn keys_for(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    request: &NativeRemovalRequestReceipt,
    witness: &NativeAssertionRemovalWitnessReceipt,
) -> BTreeSet<Uuid> {
    native
        .read_assertion_backup_inventory(context, request, witness, &mut budget())
        .expect("classified archive report")
        .key_inventory
        .value_ownership
        .expect("classified")
        .addresses
        .into_values()
        .flatten()
        .filter(|value| {
            matches!(
                value.disposition,
                NativeAssertionValueDisposition::RequiresRemoval { .. }
            )
        })
        .map(|value| value.version.key_id)
        .collect()
}

fn preserve(f: &Fixture) -> BackupResponse {
    let clean = f
        .native
        .create_removal_backup(&f.first.context, &f.removal, &f.old, &mut budget())
        .expect("verified replacement");
    assert!(
        f.native
            .retain_removal_backup(&f.first.context, &f.removal, &clean, 0, 16, &mut budget())
            .expect("available bytes")
            .complete
    );
    clean.backup
}

fn retire(f: &Fixture, keys: &BTreeSet<Uuid>) -> ServiceResult<NativeKeyRetirement> {
    f.native.retire_removal_keys(
        &f.first.context,
        &f.removal,
        &selection(f),
        keys,
        &mut budget(),
    )
}

fn clean_batch(
    native: &NativeService,
    f: &Fixture,
    input: &contextdb_service::CaptureRequest,
    request: &NativeRemovalRequestReceipt,
) {
    prepare(native, input, request);
    native
        .prune_source_assertions(
            &input.context,
            request,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("prune source-supported mutations");
}

#[test]
fn shared_retirement_requires_preservation_and_reconciled_use_in_every_native_instance() {
    let f = fixture();
    let replica = NativeService::open_encrypted(
        f.root.path().join("replica"),
        "assertion-archives",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("replica");
    replica
        .restore_backup(RestoreBackupRequest {
            context: f.first.context.clone(),
            bytes: f.old.bytes.clone(),
            format: f.old.format.clone(),
            digest: f.old.digest.clone(),
        })
        .expect("actual old archive import");
    prune(&f);
    preserve(&f);
    let selected = selected_keys(&f);
    assert!(
        retire(&f, &selected).is_err(),
        "replica still acknowledges retiring keys"
    );
    clean_batch(&replica, &f, &f.first, &f.removal);
    let row = retained_key(
        &digest_bytes(f.first.context.request.workspace_id.as_bytes()),
        f.accepted.workspace_commit,
    );
    let space = replica.keyspaces.continuous.clone();
    let ciphertext = replica
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view")
        .inner
        .get(&space, &row)
        .expect("retained batch ciphertext")
        .expect("present");
    let mut tx = replica
        .engine
        .begin_write()
        .expect("simulate lost replacement");
    tx.delete(&space, row.clone())
        .expect("remove replica batch");
    tx.commit(Durability::Sync).expect("tracked loss");
    assert!(
        retire(&f, &selected).is_err(),
        "one good instance cannot replace another's independent history"
    );
    let mut tx = replica
        .engine
        .begin_write()
        .expect("restore exact preserved version");
    tx.put_ciphertext(&space, row.clone(), ciphertext.clone())
        .expect("same key and content");
    tx.commit(Durability::Sync).expect("repair");

    let mut tx = replica
        .engine
        .begin_write()
        .expect("interrupted replacement publication");
    tx.put_ciphertext(&space, row, ciphertext)
        .expect("stage current version");
    crate::encryption::tests::fail_next_native_commit();
    tx.commit(Durability::Sync)
        .expect_err("interruption after retained preparation");
    assert!(
        retire(&f, &selected)
            .expect_err("last acknowledgement cannot hide an unresolved batch transaction")
            .message
            .contains("unresolved batch")
    );
    replica
        .verify_native(true)
        .expect("reconcile the actual abandoned preparation");
    assert_eq!(
        retire(&f, &selected)
            .expect("independent/control bytes retained in both instances")
            .receipt
            .sequence,
        1
    );
    f.native.verify_native(true).expect("primary replay");
    replica.verify_native(true).expect("replica replay");
}

#[test]
fn shared_retirement_handles_separately_authorized_removals_in_both_orders() {
    for reverse in [false, true] {
        let f = fixture();
        let second_request = remove(&f.native, &f.second, "other source");
        let second_witness = f
            .native
            .prepare_assertion_removal(
                &f.second.context,
                &second_request,
                f.witness.scope,
                f.accepted.workspace_commit,
                &mut budget(),
            )
            .expect("second ownership");
        let (first_input, first_request, first_witness, later_input, later_request, later_witness) =
            if reverse {
                (
                    &f.second,
                    &second_request,
                    &second_witness,
                    &f.first,
                    &f.removal,
                    &f.witness,
                )
            } else {
                (
                    &f.first,
                    &f.removal,
                    &f.witness,
                    &f.second,
                    &second_request,
                    &second_witness,
                )
            };
        clean_batch(&f.native, &f, first_input, first_request);
        let first_keys = keys_for(
            &f.native,
            &first_input.context,
            first_request,
            first_witness,
        );
        let middle = f
            .native
            .create_removal_backup(&first_input.context, first_request, &f.old, &mut budget())
            .expect("first authorized replacement");
        assert!(
            f.native
                .retain_removal_backup(
                    &first_input.context,
                    first_request,
                    &middle,
                    0,
                    16,
                    &mut budget()
                )
                .expect("middle bytes")
                .complete
        );
        clean_batch(&f.native, &f, later_input, later_request);
        let last = f
            .native
            .create_removal_backup(
                &later_input.context,
                later_request,
                &middle.backup,
                &mut budget(),
            )
            .expect("second authorized replacement");
        assert!(
            f.native
                .retain_removal_backup(
                    &later_input.context,
                    later_request,
                    &last,
                    0,
                    16,
                    &mut budget()
                )
                .expect("last bytes")
                .complete
        );
        let first_selection = NativeRemovalKeySelection::Assertions {
            witness: first_witness.clone(),
        };
        let first = f
            .native
            .retire_removal_keys(
                &first_input.context,
                first_request,
                &first_selection,
                &first_keys,
                &mut budget(),
            )
            .expect("missing independent source is covered by its separate retained authority");
        let later_keys = keys_for(
            &f.native,
            &later_input.context,
            later_request,
            later_witness,
        )
        .difference(&first_keys)
        .copied()
        .collect::<BTreeSet<_>>();
        assert!(!later_keys.is_empty());
        let later = f
            .native
            .retire_removal_keys(
                &later_input.context,
                later_request,
                &NativeRemovalKeySelection::Assertions {
                    witness: later_witness.clone(),
                },
                &later_keys,
                &mut budget(),
            )
            .expect("remaining shared/source keys");
        assert_eq!(later.receipt.sequence, first.receipt.sequence + 1);
        f.native
            .verify_native(true)
            .expect("both host policies and replay controls remain");
        assert_eq!(
            f.keys
                .key_retirement(&first.receipt, &mut budget())
                .expect("first immutable acceptance"),
            first
        );
    }
}

#[test]
fn shared_retirement_rejects_unclassified_values_and_fences_policy_native_and_classification() {
    for race in ["native", "classification"] {
        let f = fixture();
        let unknown = f
            .native
            .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
            .expect("allocations");
        let original: BTreeSet<_> = unknown.batches[&NativeAssertionBatchKind::Original]
            .iter()
            .map(|key| key.key_id)
            .collect();
        assert!(!original.is_empty());
        assert!(
            retire(&f, &original).is_err(),
            "allocation alone cannot classify a shared value"
        );
        prune(&f);
        preserve(&f);
        let selected = selected_keys(&f);
        let mut denied = f.first.context.clone();
        denied.capability_grants.remove(&Capability::Admin);
        assert_eq!(
            f.native
                .retire_removal_keys(
                    &denied,
                    &f.removal,
                    &selection(&f),
                    &selected,
                    &mut budget()
                )
                .expect_err("admin")
                .code,
            ErrorCode::Unauthorized
        );
        let mut wrong = f.witness.clone();
        wrong.digest = "ab".repeat(32);
        assert!(
            f.native
                .retire_removal_keys(
                    &f.first.context,
                    &f.removal,
                    &NativeRemovalKeySelection::Assertions { witness: wrong },
                    &selected,
                    &mut budget()
                )
                .is_err()
        );
        let native = f.native.clone();
        let second = f.second.clone();
        let before = f
            .keys
            .key_catalog_page(None, 256, &mut budget())
            .expect("allocation frontier");
        BEFORE_SHARED_RETIREMENT_FENCE.with(|hook| {
            hook.replace(Some(Box::new(move || {
                if race == "classification" {
                    remove(&native, &second, "concurrent retained request");
                } else {
                    let tx = native
                        .engine
                        .begin_write()
                        .expect("concurrent native publication");
                    tx.commit(Durability::Sync)
                        .expect("native-use frontier changed");
                }
            })))
        });
        assert_eq!(
            retire(&f, &selected)
                .expect_err("fresh acceptance frontiers")
                .code,
            ErrorCode::IndexTooStale
        );
        assert_eq!(
            f.keys
                .key_catalog_page(None, 256, &mut budget())
                .expect("no new allocations"),
            before
        );
        retire(&f, &selected).expect("retry after current evidence is rebuilt");
    }
}

#[test]
fn shared_retirement_preserves_independent_data_and_controls_through_cold_restore() {
    let f = fixture();
    let view = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("old view");
    let row = journal_key(
        &digest_bytes(f.first.context.request.workspace_id.as_bytes()),
        f.accepted.workspace_commit,
    );
    let space = f.native.keyspaces.continuous.clone();
    assert!(view.get(&space, &row).expect("old mixed bytes").is_some());
    prune(&f);
    let selected = selected_keys(&f);
    assert_eq!(selected.len(), 4);
    assert!(
        retire(&f, &selected).is_err(),
        "archive preservation is required"
    );
    let clean = preserve(&f);
    let report = f
        .native
        .read_assertion_backup_inventory(&f.first.context, &f.removal, &f.witness, &mut budget())
        .expect("before refusal");
    let values = report
        .key_inventory
        .value_ownership
        .as_ref()
        .expect("values");
    for role in ["independent", "control"] {
        let key = values
            .addresses
            .values()
            .flatten()
            .find(|value| match &value.disposition {
                NativeAssertionValueDisposition::PreserveIndependent { .. } => {
                    role == "independent"
                }
                NativeAssertionValueDisposition::PreserveControl => role == "control",
                _ => false,
            })
            .expect("preserved value")
            .version
            .key_id;
        assert!(
            retire(&f, &BTreeSet::from([key])).is_err(),
            "{role} key remains needed"
        );
    }
    let accepted = retire(&f, &selected).expect("shared refusal");
    assert_eq!(
        accepted
            .evidence
            .classification
            .as_ref()
            .expect("independent fence")
            .sequence,
        values.revision
    );
    assert_eq!(
        retire(&f, &selected).expect("accepted exact retry"),
        accepted
    );
    assert!(
        view.get(&space, &row)
            .expect_err("old mixed snapshot denied")
            .to_string()
            .contains("retired")
    );
    drop(view);
    f.native
        .verify_native(true)
        .expect("independent assertions and host policies replay");
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "assertion-archives",
        key_id,
        master(),
    )
    .expect("cold key authority");
    let ledger = NativeSuppressionLedger::open(
        f.root.path().join("ledger"),
        "assertion-archives",
        ledger_id,
    )
    .expect("cold removal authority");
    assert_eq!(
        keys.key_retirement(&accepted.receipt, &mut budget())
            .expect("durable receipt"),
        accepted
    );
    for (name, backup, allowed) in [("old", f.old, false), ("clean", clean, true)] {
        let restored = NativeService::open_encrypted(
            f.root.path().join(name),
            "assertion-archives",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("fresh restore instance");
        let before = restored.engine.head_sequence().expect("head");
        let result = restored.restore_backup(RestoreBackupRequest {
            context: f.first.context.clone(),
            bytes: backup.bytes,
            format: backup.format,
            digest: backup.digest,
        });
        if allowed {
            result.expect("clean restore");
            restored
                .verify_native(true)
                .expect("complete independent/control replay");
        } else {
            assert!(result.is_err());
            assert_eq!(
                restored.engine.head_sequence().expect("no mutation"),
                before
            );
        }
    }
}
