use super::*;
use crate::assertions::retention::tests::{prepare, remove};
use crate::assertions::retention::witness::tests::{Fixture, budget, fixture};
use crate::assertions::tests::capture;
use contextdb_recall::QueryCancellation;

pub(crate) fn pruned_fixture() -> (Fixture, NativeAssertionValueWitnessReceipt) {
    let f = fixture();
    prepare(&f.native, &f.first, &f.removal);
    f.native
        .prune_source_assertions(
            &f.first.context,
            &f.removal,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("prune");
    let report = f
        .native
        .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
        .expect("inventory");
    let receipt = report.value_ownership.expect("classified").witnesses[0].clone();
    (f, receipt)
}

#[test]
fn assertion_value_ownership_retains_independent_policies_across_sequential_removals() {
    let (f, first_receipt) = pruned_fixture();
    let second = capture(2, "independent source");
    let second_removal = remove(&f.native, &second, "second value ownership");
    let second_owner = f
        .native
        .prepare_assertion_removal(
            &second.context,
            &second_removal,
            f.witness.scope,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("second owner");
    let before = f
        .native
        .read_assertion_key_inventory(&second.context, &second_owner, &mut budget())
        .expect("classify previous cleaned batch for new request");
    let old_cleaned = &before.batches[&NativeAssertionBatchKind::Retained][0];
    assert_eq!(
        before.value_ownership.as_ref().expect("values").addresses[&old_cleaned.address_digest][0]
            .disposition,
        NativeAssertionValueDisposition::RequiresRemoval {
            selected_mutations: BTreeSet::from([3]),
            independent_mutations: BTreeSet::from([0, 2])
        }
    );
    prepare(&f.native, &second, &second_removal);
    f.native
        .prune_source_assertions(
            &second.context,
            &second_removal,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("second prune");
    let after = f
        .native
        .read_assertion_key_inventory(&second.context, &second_owner, &mut budget())
        .expect("two distinct shared versions");
    let allocations = &after.batches[&NativeAssertionBatchKind::Retained];
    assert_eq!(allocations.len(), 2);
    let values = after.value_ownership.expect("values");
    assert_eq!(values.witnesses.len(), 2);
    assert!(values.witnesses.contains(&first_receipt));
    let cleaned = values.addresses[&allocations[1].address_digest]
        .iter()
        .find(|v| v.version.key_id == allocations[1].key_id)
        .expect("final cleaned version");
    assert_eq!(
        cleaned.disposition,
        NativeAssertionValueDisposition::PreserveIndependent {
            mutations: BTreeSet::from([0, 2])
        }
    );
    let retained = f
        .ledger
        .read_assertion_value_witness(&values.witnesses[1], &mut budget())
        .expect("read durable ownership");
    let json = String::from_utf8(encode(&retained).expect("witness json")).expect("text");
    for raw in [
        "raw-private-assertion-source",
        "semanticremovalsentinel",
        "removed-envelope-sentinel",
        "independent-semantic-value",
    ] {
        assert!(!json.contains(raw), "raw content retained: {raw}");
    }
    f.native
        .verify_native(true)
        .expect("policies and controls remain verifiable");
}

#[test]
fn assertion_value_ownership_recovers_lost_ack_without_inventing_native_versions() {
    for intervening_capture in [false, true] {
        let f = fixture();
        prepare(&f.native, &f.first, &f.removal);
        let before = f.native.verify_native(true).expect("before").archive_digest;
        let cancel = QueryCancellation::default();
        let trigger = cancel.clone();
        AFTER_VALUES_SYNC.with(|hook| hook.replace(Some(Box::new(move || trigger.cancel()))));
        let mut budget_cancel = QueryBudget::new(
            1_000_000,
            512 * 1024 * 1024,
            std::time::Duration::from_secs(30),
            cancel,
        );
        f.native
            .prune_source_assertions(
                &f.first.context,
                &f.removal,
                f.accepted.workspace_commit,
                &mut budget_cancel,
            )
            .expect_err("interrupted after independent Sync");
        assert_eq!(
            f.native
                .verify_native(true)
                .expect("no native publication")
                .archive_digest,
            before
        );
        let pending = f
            .native
            .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
            .expect("classification without native use");
        assert!(pending.batches[&NativeAssertionBatchKind::Retained].is_empty());
        let retained = pending.value_ownership.expect("durable observation");
        assert_eq!(retained.witnesses.len(), 1);
        if intervening_capture {
            f.native
                .append_event(capture(4, "independent interleaving"))
                .expect("advance native prefix");
        }
        let pruning = f
            .native
            .prune_source_assertions(
                &f.first.context,
                &f.removal,
                f.accepted.workspace_commit,
                &mut budget(),
            )
            .expect("retry");
        let current = f
            .native
            .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
            .expect("published versions only");
        assert_eq!(
            current.batches[&NativeAssertionBatchKind::Retained].len(),
            1
        );
        let current_values = current.value_ownership.expect("classified");
        assert_eq!(
            current_values.witnesses.len(),
            if intervening_capture { 2 } else { 1 }
        );
        assert!(current_values.witnesses.contains(&retained.witnesses[0]));
        assert_eq!(
            f.native
                .prune_source_assertions(
                    &f.first.context,
                    &f.removal,
                    f.accepted.workspace_commit,
                    &mut budget()
                )
                .expect("native exact retry"),
            pruning
        );
    }
}
