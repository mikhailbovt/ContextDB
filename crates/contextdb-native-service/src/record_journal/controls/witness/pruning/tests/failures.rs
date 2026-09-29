use super::*;
use crate::record_sources::tests::input;
use contextdb_recall::QueryCancellation;
use contextdb_service::CapturePort;

#[test]
fn record_pruning_checks_policy_budget_cas_and_recovers_lost_sync_acknowledgement() {
    let f = fixture();
    let witness = prepare(&f, "private-record", 1).expect("witness");
    let mut context = f.context.clone();
    context.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.service
            .prune_record_revision(&context, &witness, &mut budget())
            .expect_err("admin")
            .code,
        ErrorCode::Unauthorized
    );
    context = f.context.clone();
    context.request.scopes = BTreeSet::from(["outside".into()]);
    assert_eq!(
        f.service
            .prune_record_revision(&context, &witness, &mut budget())
            .expect_err("policy")
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(
        f.service
            .prune_record_revision(
                &f.context,
                &witness,
                &mut QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default())
            )
            .is_err()
    );
    let service = f.service.clone();
    BEFORE_PRUNING.with(|hook| {
        hook.replace(Some(Box::new(move || {
            service
                .append_event(input(3, "concurrent capture"))
                .expect("capture");
        })))
    });
    assert_eq!(
        f.service
            .prune_record_revision(&f.context, &witness, &mut budget())
            .expect_err("CAS")
            .code,
        ErrorCode::IndexTooStale
    );
    let snapshot = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        snapshot
            .get(
                &f.service.keyspaces.content_history,
                &history_key(&witness.record_digest, 1)
            )
            .expect("body")
            .is_some()
    );
    let cancellation = QueryCancellation::default();
    let cancel = cancellation.clone();
    AFTER_PRUNING.with(|hook| hook.replace(Some(Box::new(move || cancel.cancel()))));
    let mut interrupted = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        cancellation,
    );
    assert!(
        f.service
            .prune_record_revision(&f.context, &witness, &mut interrupted)
            .is_err()
    );
    let after_sync = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let head = f.service.global_head(&after_sync).expect("head");
    let receipt = f
        .service
        .prune_record_revision(&f.context, &witness, &mut budget())
        .expect("recover lost acknowledgement");
    assert_eq!(
        f.service
            .prune_record_revision(&f.context, &witness, &mut budget())
            .expect("repeat"),
        receipt
    );
    let after_retry = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(f.service.global_head(&after_retry).expect("head"), head);
    f.service.verify_native(true).expect("accepted cleanup");
}

#[test]
fn record_pruning_rejects_missing_markers_resurrection_or_rehashed_false_validation() {
    for mutation in [
        "marker",
        "resurrection",
        "marker-and-resurrection",
        "declaration",
        "validation",
        "orphan",
    ] {
        let f = fixture();
        let witness = prepare(&f, "private-record", 1).expect("witness");
        let before = f
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        let retained = f
            .ledger
            .read_record_removal_witness(&witness, &mut budget())
            .expect("control");
        let key = history_key(&witness.record_digest, 1);
        let body = before
            .get(&f.service.keyspaces.content_history, &key)
            .expect("content")
            .expect("body");
        f.service
            .prune_record_revision(&f.context, &witness, &mut budget())
            .expect("prune");
        let mut tx = f.service.engine.begin_write().expect("transaction");
        let global = f.service.global_head(&tx).expect("head");
        match mutation {
            "marker" | "marker-and-resurrection" => {
                tx.delete(
                    &f.service.keyspaces.continuous,
                    pruned_key(&witness.record_digest, 1),
                )
                .expect("delete marker");
            }
            "orphan" => {
                tx.put(
                    &f.service.keyspaces.continuous,
                    b"record-pruned/orphan".to_vec(),
                    b"{}".to_vec(),
                )
                .expect("orphan");
            }
            "declaration" | "validation" => {
                let mut event = f
                    .service
                    .recovery_global_event(&tx, global, &mut budget())
                    .expect("event");
                if mutation == "declaration" {
                    event.accepted_record_pruning = None;
                } else {
                    let publication = event.accepted_record_pruning.as_mut().expect("declaration");
                    for value in publication.write_validations.values_mut() {
                        *value = RemovalCheckpoint {
                            sequence: witness.witness_sequence,
                            digest: witness.digest.clone(),
                        };
                    }
                    let bytes = encode(publication).expect("publication");
                    event.response_digest = digest_bytes(&bytes);
                    tx.put(
                        &f.service.keyspaces.continuous,
                        pruned_key(&witness.record_digest, 1),
                        bytes.clone(),
                    )
                    .expect("marker");
                    let retry = StoredIdempotency {
                        schema_version: SCHEMA_VERSION,
                        operation: OPERATION.into(),
                        request_digest: event.request_digest.clone(),
                        response_digest: event.response_digest.clone(),
                        response_bytes: bytes,
                    };
                    tx.put(
                        &f.service.keyspaces.idempotency,
                        event.request_digest.as_bytes().to_vec(),
                        encode(&retry).expect("retry"),
                    )
                    .expect("retry");
                }
                tx.put(
                    &f.service.keyspaces.events,
                    global.to_be_bytes().to_vec(),
                    encode(&event).expect("event"),
                )
                .expect("event");
                preparation::tests::rehash(&f.service, &mut tx);
            }
            _ => {}
        }
        if mutation == "resurrection" || mutation == "marker-and-resurrection" {
            tx.put(&f.service.keyspaces.content_history, key, body)
                .expect("resurrect content");
            for control in retained.controls() {
                let commit = control
                    .policy
                    .transaction_to
                    .unwrap_or(control.policy.transaction_from);
                let address = mutation_address(commit, &witness.record_digest, 1);
                tx.put(
                    &f.service.keyspaces.continuous,
                    address.clone(),
                    before
                        .get(&f.service.keyspaces.continuous, &address)
                        .expect("read original")
                        .expect("mutation"),
                )
                .expect("resurrect mutation");
            }
        }
        tx.commit(Durability::Sync).expect("corruption fixture");
        assert_eq!(
            f.service.verify_native(true).expect_err(mutation).code,
            ErrorCode::IntegrityFailure
        );
        if mutation != "orphan" {
            assert!(
                f.service
                    .prune_record_revision(&f.context, &witness, &mut budget())
                    .is_err(),
                "{mutation}"
            );
        }
        let after = f
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        assert_eq!(f.service.global_head(&after).expect("head"), global);
    }
}
