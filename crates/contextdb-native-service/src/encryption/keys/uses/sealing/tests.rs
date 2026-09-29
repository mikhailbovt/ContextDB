use super::*;
use crate::backup::jobs::tests::{finish, prepared};
use crate::retention::keys::witness::tests::budget;

#[test]
fn archive_worker_seal_rejects_missing_state_and_resealed_unfinished_job_claims() {
    let (f, worker, _, original) = prepared();
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("start");
    finish(&f, &worker, &f.removal, &start.receipt);
    let seal = worker
        .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("actual worker sealed");
    let snapshot = f
        .keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("custody");
    let key = state_key(seal.worker_instance);
    let original_state = snapshot
        .get(&f.keys.rows, &key)
        .expect("state")
        .expect("present");
    let mut state = f
        .keys
        .use_state(&snapshot, seal.worker_instance)
        .expect("accepted state");
    let mut event = f
        .keys
        .use_event(&snapshot, seal.sequence)
        .expect("seal event");
    drop(snapshot);
    state.sealed = None;
    let mut tx = f.keys.engine.begin_write().expect("tamper");
    tx.put(
        &f.keys.rows,
        key.clone(),
        f.keys
            .seal_use(&key, &encode(&state).expect("state bytes"), "journal")
            .expect("valid envelope"),
    )
    .expect("erase seal flag");
    tx.commit(Durability::Sync).expect("tamper Sync");
    assert!(
        f.keys
            .backup_worker_seal(seal.worker_instance, &mut budget())
            .is_err()
    );
    let mut tx = f
        .keys
        .engine
        .begin_write()
        .expect("restore exact fixture row");
    tx.put(&f.keys.rows, key.clone(), original_state)
        .expect("original state");
    tx.commit(Durability::Sync).expect("restore");
    assert_eq!(
        f.keys
            .backup_worker_seal(seal.worker_instance, &mut budget())
            .expect("restored fixture"),
        Some(seal)
    );
    // Keep every envelope, digest, index and terminal consistent, but replace the
    // terminal job with its real unfinished start. The semantic verifier must fail.
    let UseOperation::Seal { previous, job } = &mut event.change else {
        panic!("seal")
    };
    *job = start.receipt.clone();
    let previous = previous.clone();
    event.checkpoint.digest = Some(event.digest().expect("forged commitment"));
    state.accepted = event.checkpoint.clone();
    state.sealed = Some(
        receipt(
            f.keys.authority_id(),
            &event.checkpoint,
            &previous,
            &start.receipt,
        )
        .expect("forged receipt"),
    );
    let mut tx = f
        .keys
        .engine
        .begin_write()
        .expect("rehashed fixture mutation");
    for (key, value) in [
        (
            event_key(event.checkpoint.sequence),
            encode(&event).expect("event"),
        ),
        (HEAD.to_vec(), encode(&event.checkpoint).expect("head")),
        (
            instance_key(previous.instance, state.revision),
            encode(&event.checkpoint).expect("reference"),
        ),
        (key, encode(&state).expect("state")),
    ] {
        let sealed = f
            .keys
            .seal_use(&key, &value, "journal")
            .expect("valid envelope");
        tx.put(&f.keys.rows, key, sealed).expect("mutation");
    }
    tx.commit(Durability::Sync).expect("tamper Sync");
    assert!(
        f.keys
            .backup_worker_seal(previous.instance, &mut budget())
            .is_err()
    );
    assert!(f.keys.verify().is_err());
}
