use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{budget, fixture};
use contextdb_service::{
    CapturePort, CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest,
};

#[test]
fn removal_request_discovery_preserves_scope_order_and_requests_after_an_older_restore() {
    let f = fixture();
    let backup = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("old archive");
    let second = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "next",
            &mut budget(),
        )
        .expect("later request");
    let mut foreign = request(1, "separate workspace");
    foreign.event.workspace_id = contextdb_core::WorkspaceId::new();
    foreign.event.event_id = ObservationId::new();
    foreign.context.request.workspace_id = foreign.event.workspace_id.to_string();
    f.native
        .append_event(foreign.clone())
        .expect("foreign capture");
    let other = f
        .native
        .request_original_removal(
            &foreign.context,
            &BTreeSet::from([foreign.event.event_id]),
            "other",
            &mut budget(),
        )
        .expect("foreign request");
    let report = f
        .native
        .read_original_removal_requests(&f.input.context, &mut budget())
        .expect("requests");
    assert_eq!(report.requests, vec![f.removal, second]);
    assert_eq!(
        f.native
            .read_original_removal_requests(&foreign.context, &mut budget())
            .expect("foreign")
            .requests,
        vec![other]
    );
    let restored = NativeService::open_encrypted(
        f.root.path().join("old-restore"),
        "primary-decisions",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: f.input.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    assert_eq!(
        restored
            .read_original_removal_requests(&f.input.context, &mut budget())
            .expect("current independent requests"),
        report
    );
}

#[test]
fn removal_request_discovery_rejects_lost_or_extra_locators_and_unbudgeted_access() {
    let f = fixture();
    let workspace = digest_bytes(f.input.context.request.workspace_id.as_bytes());
    let snapshot = f
        .ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    let event = f
        .ledger
        .read_removal_event(&snapshot, f.removal.sequence)
        .expect("event");
    let Operation::Request { intent, .. } = &event.operation else {
        panic!("request")
    };
    for key in [
        current_key(&workspace),
        request_key(&workspace, f.removal.sequence),
        retry_key(&workspace, &intent.retry_key),
        event_key(f.removal.sequence),
    ] {
        let value = snapshot
            .get(&f.ledger.rows, &key)
            .expect("row")
            .expect("accepted");
        let mut tx = f.ledger.engine.begin_write().expect("remove locator");
        tx.delete(&f.ledger.rows, key.clone()).expect("delete");
        tx.commit(Durability::Sync).expect("sync");
        assert_eq!(
            f.native
                .read_original_removal_requests(&f.input.context, &mut budget())
                .expect_err("missing is not idle")
                .code,
            ErrorCode::IntegrityFailure
        );
        let mut tx = f.ledger.engine.begin_write().expect("recover locator");
        tx.put(&f.ledger.rows, key, value).expect("put");
        tx.commit(Durability::Sync).expect("sync");
    }
    let extra = request_key(&workspace, f.removal.sequence + 100);
    let mut tx = f.ledger.engine.begin_write().expect("extra locator");
    tx.put(
        &f.ledger.rows,
        extra.clone(),
        encode(&event.checkpoint()).expect("bytes"),
    )
    .expect("put");
    tx.commit(Durability::Sync).expect("sync");
    assert!(
        f.native
            .read_original_removal_requests(&f.input.context, &mut budget())
            .is_err()
    );
    let mut tx = f.ledger.engine.begin_write().expect("remove extra");
    tx.delete(&f.ledger.rows, extra).expect("delete");
    tx.commit(Durability::Sync).expect("sync");
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .read_original_removal_requests(&denied, &mut budget())
            .expect_err("no admin")
            .code,
        ErrorCode::Unauthorized
    );
    let mut empty = QueryBudget::new(0, 0, std::time::Duration::from_secs(10), Default::default());
    assert_eq!(
        f.native
            .read_original_removal_requests(&f.input.context, &mut empty)
            .expect_err("bounded")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        f.native
            .read_original_removal_requests(&f.input.context, &mut budget())
            .expect("recovered")
            .requests
            .len(),
        1
    );
}

#[test]
fn removal_request_discovery_rechecks_concurrent_requests_before_returning() {
    let f = fixture();
    let native = f.native.clone();
    let context = f.input.context.clone();
    BEFORE_DISCOVERY_FENCE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            native.request_original_removal(
                &context,
                &BTreeSet::from([request(2, "").event.event_id]),
                "concurrent",
                &mut budget(),
            )?;
            Ok(())
        }))
    });
    assert_eq!(
        f.native
            .read_original_removal_requests(&f.input.context, &mut budget())
            .expect_err("changed frontier")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        f.native
            .read_original_removal_requests(&f.input.context, &mut budget())
            .expect("fresh")
            .requests
            .len(),
        2
    );
}
