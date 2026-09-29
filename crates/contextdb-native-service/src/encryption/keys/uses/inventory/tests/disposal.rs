use super::*;
use crate::backup::executor::tests::{finish, issued, worker_path};
use crate::encryption::keys::uses::disposal::receipt as disposal_receipt;
use crate::{NativeArchiveCleanup, NativeArchiveWorkerDisposalProgress, NativeService};

#[test]
fn managed_disposal_inventory_rejects_missing_and_rehashed_preservation_evidence() {
    let f = crate::retention::keys::witness::tests::fixture();
    let original = issued(&f, true);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    drop(executor);
    let job = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("catalog")
        .jobs
        .pop()
        .expect("terminal");
    let worker = NativeService::open_encrypted(
        worker_path(&root, &original),
        "primary-decisions",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("exact worker");
    let seal = worker
        .seal_removal_backup_worker(&f.input.context, &f.removal, &job.receipt, &mut budget())
        .expect("seal");
    drop(worker);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    let mut absent = false;
    for _ in 0..32 {
        if matches!(
            executor
                .dispose_worker(
                    &f.input.context,
                    &f.removal,
                    &job.receipt,
                    16,
                    &mut budget()
                )
                .expect("controlled disposal"),
            NativeArchiveWorkerDisposalProgress::DirectoryAbsent { .. }
        ) {
            absent = true;
            break;
        }
    }
    assert!(absent);
    let current = f
        .native
        .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
        .expect("current")
        .native_use
        .expect("v4");
    let completed = current.disposed_workers[&seal.worker_instance].clone();
    assert!(completed.directory_absent);
    let inventory = || {
        f.native
            .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
    };
    let snapshot = f
        .keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("custody snapshot");
    let state_key = state_key(seal.worker_instance);
    let state_bytes = snapshot
        .get(&f.keys.rows, &state_key)
        .expect("state")
        .expect("present");
    let mut state = f
        .keys
        .use_state(&snapshot, seal.worker_instance)
        .expect("state");
    let mut event = f
        .keys
        .use_event(&snapshot, completed.sequence)
        .expect("completed event");
    let complete_key = event_key(completed.sequence);
    let complete_bytes = snapshot
        .get(&f.keys.rows, &complete_key)
        .expect("event")
        .expect("present");
    let mut tx = f
        .keys
        .engine
        .begin_write()
        .expect("owned fixture missing event");
    tx.delete(&f.keys.rows, complete_key.clone())
        .expect("delete");
    tx.commit(Durability::Sync).expect("fixture Sync");
    assert!(
        inventory().is_err(),
        "a completed state without its exact acceptance cannot discharge copies"
    );
    let mut tx = f.keys.engine.begin_write().expect("restore event");
    tx.put(&f.keys.rows, complete_key.clone(), complete_bytes)
        .expect("restore");
    tx.commit(Durability::Sync).expect("restore Sync");
    state.disposal = None;
    let mut tx = f
        .keys
        .engine
        .begin_write()
        .expect("owned fixture missing disposition");
    tx.put(
        &f.keys.rows,
        state_key.clone(),
        f.keys
            .seal_use(&state_key, &encode(&state).expect("state"), "journal")
            .expect("envelope"),
    )
    .expect("put");
    tx.commit(Durability::Sync).expect("fixture Sync");
    assert!(
        inventory().is_err(),
        "accepted completed disposition cannot be omitted"
    );
    let mut tx = f.keys.engine.begin_write().expect("restore state");
    tx.put(&f.keys.rows, state_key.clone(), state_bytes)
        .expect("restore");
    tx.commit(Durability::Sync).expect("restore Sync");
    state.disposal = Some(completed.clone());
    let UseOperation::Disposal {
        binding,
        prepared: Some(_),
    } = &mut event.change
    else {
        panic!("actual completed disposal");
    };
    // Authenticated, complete dirty bytes are not preservation of this sealed
    // job's exact clean result. Every digest/envelope/index below is rehashed.
    binding.preservation_artifact = job.binding.source_artifact.clone();
    let binding = *binding.clone();
    event.checkpoint.digest = Some(event.digest().expect("new commitment"));
    state.accepted = event.checkpoint.clone();
    state.disposal = Some(
        disposal_receipt(
            f.keys.authority_id(),
            &event.checkpoint,
            binding.clone(),
            true,
        )
        .expect("rehashed completed receipt"),
    );
    // The final acceptance must also point to an intent with the same binding.
    let UseOperation::Disposal {
        prepared: Some(prepared),
        ..
    } = &event.change
    else {
        panic!("complete");
    };
    let mut intent = f
        .keys
        .use_event(&snapshot, prepared.sequence)
        .expect("intent");
    assert_eq!(intent.checkpoint.sequence + 1, event.checkpoint.sequence);
    let UseOperation::Disposal {
        binding: intent_binding,
        prepared: None,
    } = &mut intent.change
    else {
        panic!("intent");
    };
    **intent_binding = binding;
    intent.checkpoint.digest = Some(intent.digest().expect("intent commitment"));
    event.previous_digest = intent.checkpoint.digest.clone();
    let UseOperation::Disposal {
        prepared: Some(prepared),
        ..
    } = &mut event.change
    else {
        panic!("complete");
    };
    *prepared = intent.checkpoint.clone();
    event.checkpoint.digest = Some(event.digest().expect("final commitment"));
    state.accepted = event.checkpoint.clone();
    state.disposal.as_mut().expect("value").digest =
        event.checkpoint.digest.clone().expect("digest");
    let mutated = [
        (
            event_key(intent.checkpoint.sequence),
            encode(&intent).expect("intent"),
        ),
        (
            instance_key(seal.worker_instance, state.revision - 1),
            encode(&intent.checkpoint).expect("intent locator"),
        ),
        (complete_key, encode(&event).expect("event")),
        (HEAD.to_vec(), encode(&event.checkpoint).expect("head")),
        (
            instance_key(seal.worker_instance, state.revision),
            encode(&event.checkpoint).expect("locator"),
        ),
        (state_key, encode(&state).expect("state")),
    ];
    let originals: Vec<_> = mutated
        .iter()
        .map(|(key, _)| {
            (
                key.clone(),
                snapshot
                    .get(&f.keys.rows, key)
                    .expect("row")
                    .expect("present"),
            )
        })
        .collect();
    drop(snapshot);
    let mut tx = f
        .keys
        .engine
        .begin_write()
        .expect("rehashed fixture mutation");
    for (key, bytes) in mutated {
        tx.put(
            &f.keys.rows,
            key.clone(),
            f.keys.seal_use(&key, &bytes, "journal").expect("envelope"),
        )
        .expect("put");
    }
    tx.commit(Durability::Sync).expect("fixture Sync");
    f.keys
        .verify_native_use(
            &f.keys
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("rehashed complete use snapshot"),
        )
        .expect("the rehashed native-use chain remains structurally valid");
    assert!(
        inventory().is_err(),
        "validly rehashed absence cannot bypass semantic preservation"
    );
    assert!(f.keys.verify().is_err());
    let mut tx = f.keys.engine.begin_write().expect("restore exact rows");
    for (key, bytes) in originals {
        tx.put(&f.keys.rows, key, bytes).expect("restore");
    }
    tx.commit(Durability::Sync).expect("restore Sync");
    assert_eq!(
        inventory().expect("restored inventory").native_use,
        Some(current)
    );
    f.native
        .verify_native(true)
        .expect("all accepted historical evidence remains");
}
