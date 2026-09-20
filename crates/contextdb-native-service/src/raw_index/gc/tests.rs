use super::*;
use contextdb_core::{RawFilter, RawTextQuery};
use contextdb_recall::{IndexedQuery, IndexedRecallProvider, IndexedSelection};
use contextdb_service::{
    CapturePort, CaptureRequest, CognitiveMemoryService, CreateBackupRequest, ReadOriginalRequest,
    RestoreBackupRequest,
};
use std::time::Duration;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

fn fixture(service: &NativeService) -> CaptureRequest {
    let first = crate::capture::tests::request(1, "shared secret 7319 original one");
    service.append_event(first.clone()).expect("capture");
    service
        .append_event(crate::capture::tests::request(2, "shared original two"))
        .expect("capture");
    first
}

fn query() -> IndexedQuery {
    IndexedQuery {
        filter: RawFilter::default(),
        text: Some(RawTextQuery::AllTerms("shared".into())),
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 10 },
    }
}

fn finish(service: &NativeService, context: &AuthenticatedRequestContext) -> RawReclaimProgress {
    for _ in 0..100 {
        let progress = service
            .reclaim_raw_generations(context, 7, &mut budget())
            .expect("reclaim batch");
        assert!(progress.removed_rows <= 7);
        if progress.finished {
            return progress;
        }
    }
    panic!("fixture generation was not reclaimed");
}

#[test]
fn interrupted_reclamation_survives_restore_and_frees_more_than_three_lifetime_generations() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "raw-gc", [7; 32]).expect("open");
    let input = fixture(&service);
    assert!(
        service
            .project_originals(&input.context, false, 64, &mut budget())
            .expect("index1")
            .caught_up
    );
    let backup = {
        let provider = service.indexed_recall_provider(&input.context);
        let old_view = provider
            .open_view(None, &mut budget())
            .expect("short-lived view1");
        for expected in [2, 3] {
            assert_eq!(
                service
                    .project_originals(&input.context, true, 64, &mut budget())
                    .expect("rebuild")
                    .generation,
                expected
            );
        }
        assert_eq!(
            service
                .project_originals(&input.context, true, 64, &mut budget())
                .expect_err("retention cap before reclamation")
                .code,
            ErrorCode::ResourceExhausted
        );
        let first = service
            .reclaim_raw_generations(&input.context, 1, &mut budget())
            .expect("first row");
        assert_eq!(first.generation, Some(1));
        assert_eq!(first.removed_rows, 1);
        assert!(!first.finished);
        assert_eq!(
            provider
                .candidates(&old_view, &query(), &mut budget())
                .expect("pinned snapshot")
                .hits
                .len(),
            2,
            "logical GC cannot corrupt an already admitted short-lived physical view"
        );
        service
            .verify_native(true)
            .expect("unfinished unreachable generation");
        service
            .create_backup(CreateBackupRequest {
                context: input.context.clone(),
            })
            .expect("pending GC backup")
    };
    drop(service);
    let reopened = NativeService::open(directory.path(), "raw-gc", [7; 32]).expect("reopen job");
    let next = reopened
        .reclaim_raw_generations(&input.context, 1, &mut budget())
        .expect("resume");
    assert_eq!(next.generation, Some(1));
    assert_eq!(next.total_removed_rows, 2);
    reopened.verify_native(true).expect("resumed job");
    drop(reopened);
    let restore_directory = tempfile::tempdir().expect("restore directory");
    let service =
        NativeService::open(restore_directory.path(), "raw-gc", [8; 32]).expect("restore owner");
    service
        .restore_backup(RestoreBackupRequest {
            context: input.context.clone(),
            bytes: backup.bytes,
            format: backup.format,
            digest: backup.digest,
        })
        .expect("restore partial generation reclamation");
    let done = finish(&service, &input.context);
    assert_eq!(done.generation, Some(1));
    assert_eq!(done.retained_generations, 2);
    assert!(done.total_removed_rows > 1);
    let workspace = digest_bytes(input.context.request.workspace_id.as_bytes());
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    assert!(
        snapshot
            .scan_prefix(
                &service.keyspaces.continuous,
                generation_prefix(&workspace, 1).as_bytes()
            )
            .expect("reclaimed rows")
            .is_empty()
    );
    assert!(
        snapshot
            .get(
                &service.keyspaces.continuous,
                &generation_key(&workspace, 1)
            )
            .expect("manifest")
            .is_none()
    );
    drop(snapshot);
    for expected in 4..=10 {
        assert_eq!(
            service
                .project_originals(&input.context, true, 64, &mut budget())
                .expect("identity is monotonic, not a lifetime cap")
                .generation,
            expected
        );
        assert_eq!(finish(&service, &input.context).retained_generations, 2);
    }
    assert_eq!(
        service
            .read_original(ReadOriginalRequest {
                context: input.context.clone(),
                event_id: input.event.event_id,
                after_receipt: None,
            })
            .expect("original survives index GC")
            .event,
        input.event
    );
    let provider = service.indexed_recall_provider(&input.context);
    let view = provider
        .open_view(None, &mut budget())
        .expect("current view");
    assert_eq!(
        provider
            .candidates(&view, &query(), &mut budget())
            .expect("current index")
            .hits
            .len(),
        2
    );
    service
        .verify_native(true)
        .expect("retained generations and source archive");
}

#[test]
fn current_active_and_building_generations_are_protected_but_stale_builds_can_be_abandoned() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "raw-gc", [7; 32]).expect("open");
    let input = fixture(&service);
    let building = service
        .project_originals(&input.context, false, 1, &mut budget())
        .expect("partial first build");
    assert!(!building.caught_up);
    assert!(
        service
            .reclaim_raw_generations(&input.context, 64, &mut budget())
            .expect("protect building")
            .generation
            .is_none()
    );
    service
        .revoke_original(
            &input.context,
            input.event.event_id,
            "revoke",
            &mut budget(),
        )
        .expect("revoke during build");
    let reclaimed = finish(&service, &input.context);
    assert_eq!(reclaimed.generation, Some(building.generation));
    assert_eq!(reclaimed.retained_generations, 0);
    assert!(
        service
            .maintain_custody(&input.context, 64, &mut budget())
            .expect("custody")
            .caught_up
    );
    assert!(
        service
            .project_originals(&input.context, false, 64, &mut budget())
            .expect("fresh build after abandonment")
            .caught_up
    );
    service
        .project_originals(&input.context, true, 1, &mut budget())
        .expect("second partial build");
    let before = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before");
    let head = service.global_head(&before).expect("head");
    let idle = service
        .reclaim_raw_generations(&input.context, 64, &mut budget())
        .expect("protect both generations");
    assert_eq!(idle.retained_generations, 2);
    assert!(idle.generation.is_none());
    let after = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after");
    assert_eq!(
        service.global_head(&after).expect("head"),
        head,
        "idle maintenance has no publication"
    );
    service
        .verify_native(true)
        .expect("active plus current build");
}

#[test]
fn reclamation_budget_and_forged_active_job_fail_before_deleting_rows() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "raw-gc", [7; 32]).expect("open");
    let input = fixture(&service);
    service
        .project_originals(&input.context, false, 64, &mut budget())
        .expect("index");
    service
        .project_originals(&input.context, true, 64, &mut budget())
        .expect("rebuild");
    let workspace = digest_bytes(input.context.request.workspace_id.as_bytes());
    let before = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before");
    let rows = before
        .scan_prefix(&service.keyspaces.continuous, b"raw/")
        .expect("rows");
    let mut tiny = QueryBudget::new(100, 1, Duration::from_secs(5), Default::default());
    assert_eq!(
        service
            .reclaim_raw_generations(&input.context, 64, &mut tiny)
            .expect_err("bounded read")
            .code,
        ErrorCode::BudgetExhausted
    );
    let after = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after");
    assert_eq!(
        after
            .scan_prefix(&service.keyspaces.continuous, b"raw/")
            .expect("rows"),
        rows
    );
    let mut tx = service.engine.begin_write().expect("corruption fixture");
    let mut state: IndexState = service
        .raw_value(&tx, &state_key(&workspace))
        .expect("state")
        .expect("present");
    state.reclaiming = Some(Reclaiming {
        generation: state.active.expect("active"),
        removed_rows: 0,
    });
    tx.put(
        &service.keyspaces.continuous,
        state_key(&workspace),
        encode(&state).expect("state"),
    )
    .expect("fault");
    tx.commit(Durability::Sync).expect("fault commit");
    assert_eq!(
        service
            .reclaim_raw_generations(&input.context, 64, &mut budget())
            .expect_err("active job forbidden")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("invalid retention state")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert!(
        service
            .indexed_recall_provider(&input.context)
            .open_view(None, &mut budget())
            .is_err()
    );
}
