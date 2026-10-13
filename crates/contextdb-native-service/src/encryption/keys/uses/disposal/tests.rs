use super::*;
use crate::backup::executor::tests::{finish, issued, worker_path};
use crate::retention::keys::witness::tests::{budget, fixture};
use crate::{NativeArchiveCleanup, NativeArchiveWorkerDisposalProgress, NativeService};

#[test]
fn worker_disposal_holds_preservation_keys_and_rejects_rehashed_wrong_preservation() {
    let f = fixture();
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
    .expect("actual worker");
    let seal = worker
        .seal_removal_backup_worker(&f.input.context, &f.removal, &job.receipt, &mut budget())
        .expect("seal");
    drop(worker);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    let NativeArchiveWorkerDisposalProgress::Prepared { disposal } = executor
        .dispose_worker(
            &f.input.context,
            &f.removal,
            &job.receipt,
            16,
            &mut budget(),
        )
        .expect("intent")
    else {
        panic!("intent");
    };
    let (contents, _, _) = job.next_source().expect("clean result");
    let page = f
        .keys
        .backup_contents_page(&contents.receipt, 0, &mut budget())
        .expect("preserved copies");
    let held = BTreeSet::from([page.copies[0].version.key_id]);
    let snapshot = f
        .keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("custody");
    assert_eq!(
        f.keys
            .require_active_job_keys(&snapshot, &held, &mut budget())
            .expect_err("pending disposal holds readable preservation")
            .code,
        ErrorCode::EvidenceRequired
    );
    let key = state_key(seal.worker_instance);
    let state_bytes = snapshot
        .get(&f.keys.rows, &key)
        .expect("state")
        .expect("retained");
    let mut state = f
        .keys
        .use_state(&snapshot, seal.worker_instance)
        .expect("state");
    let mut event = f
        .keys
        .use_event(&snapshot, disposal.sequence)
        .expect("intent");
    state.disposal = None;
    let mut tx = f.keys.engine.begin_write().expect("owned test mutation");
    tx.put(
        &f.keys.rows,
        key.clone(),
        f.keys
            .seal_use(&key, &encode(&state).expect("state"), "journal")
            .expect("envelope"),
    )
    .expect("put");
    tx.commit(Durability::Sync).expect("tamper sync");
    assert!(
        f.keys
            .backup_worker_disposal(seal.worker_instance, &mut budget())
            .is_err()
    );
    let mut tx = f.keys.engine.begin_write().expect("restore state");
    tx.put(&f.keys.rows, key.clone(), state_bytes).expect("put");
    tx.commit(Durability::Sync).expect("restore Sync");
    state.disposal = Some(*disposal.clone());
    // All envelopes, digests and locators remain valid. Point preservation at
    // the original dirty artifact; only semantic ancestry validation rejects it.
    let UseOperation::Disposal {
        binding,
        prepared: None,
    } = &mut event.change
    else {
        panic!("intent");
    };
    binding.preservation_artifact = job.binding.source_artifact.clone();
    let binding = *binding.clone();
    event.checkpoint.digest = Some(event.digest().expect("forged digest"));
    state.accepted = event.checkpoint.clone();
    state.disposal =
        Some(receipt(f.keys.authority_id(), &event.checkpoint, binding, false).expect("receipt"));
    let mutated = [
        (
            event_key(event.checkpoint.sequence),
            encode(&event).expect("event"),
        ),
        (HEAD.to_vec(), encode(&event.checkpoint).expect("head")),
        (
            instance_key(seal.worker_instance, state.revision),
            encode(&event.checkpoint).expect("locator"),
        ),
        (key, encode(&state).expect("state")),
    ];
    let originals: Vec<_> = mutated
        .iter()
        .map(|(key, _)| {
            (
                key.clone(),
                snapshot
                    .get(&f.keys.rows, key)
                    .expect("old row")
                    .expect("present"),
            )
        })
        .collect();
    drop(snapshot);
    let mut tx = f.keys.engine.begin_write().expect("rehashed mutation");
    for (key, value) in mutated {
        let sealed = f.keys.seal_use(&key, &value, "journal").expect("envelope");
        tx.put(&f.keys.rows, key, sealed).expect("put");
    }
    tx.commit(Durability::Sync).expect("tamper Sync");
    assert!(
        f.keys
            .backup_worker_disposal(seal.worker_instance, &mut budget())
            .is_err()
    );
    assert!(f.keys.verify().is_err());
    let mut tx = f
        .keys
        .engine
        .begin_write()
        .expect("restore exact fixture rows");
    for (key, value) in originals {
        tx.put(&f.keys.rows, key, value).expect("restore");
    }
    tx.commit(Durability::Sync).expect("restore Sync");
    let mut absent = false;
    for _ in 0..16 {
        if matches!(
            executor
                .dispose_worker(
                    &f.input.context,
                    &f.removal,
                    &job.receipt,
                    16,
                    &mut budget()
                )
                .expect("actual directory disposal"),
            NativeArchiveWorkerDisposalProgress::DirectoryAbsent { .. }
        ) {
            absent = true;
            break;
        }
    }
    assert!(absent);
    let snapshot = f
        .keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("custody");
    f.keys
        .require_active_job_keys(&snapshot, &held, &mut budget())
        .expect("this intent no longer holds keys; other retirement requirements still apply");
    f.keys
        .verify_backup_catalog(&snapshot)
        .expect("complete retained history");
    drop(snapshot);
    f.keys
        .verify()
        .expect("all native-use evidence remains valid");
}
