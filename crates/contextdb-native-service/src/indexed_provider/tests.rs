use std::collections::BTreeSet;

use contextdb_core::{
    ContentBlockId, RawFilter, ScopeId, SessionId, SourceId, TimeRange, TimestampMicros,
};
use contextdb_service::{
    CaptureRequest, CognitiveMemoryService, CreateBackupRequest, PayloadPort, RawRecallBudget,
    RawRecallPort, RestoreBackupRequest, StagePayloadRequest,
};
use contextdb_storage::{Durability, WriteTransaction};

use super::*;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}

fn request(input: &CaptureRequest, text: Option<RawTextQuery>) -> RawRecallRequest {
    RawRecallRequest {
        context: input.context.clone(),
        filter: RawFilter::default(),
        text,
        known_at: None,
        after_receipt: None,
        page_size: 256,
        budget: RawRecallBudget::default(),
        continuation: None,
    }
}

fn project(service: &NativeService, input: &CaptureRequest, mut rebuild: bool) {
    loop {
        let progress = service
            .project_originals(&input.context, rebuild, 64, &mut budget())
            .expect("project");
        rebuild = false;
        if progress.caught_up {
            return;
        }
    }
}

fn selective_work(service: &NativeService, input: &CaptureRequest) -> u64 {
    let provider = service.indexed_recall_provider(&input.context);
    let mut allowance = budget();
    let before = allowance.remaining_work();
    let view = provider.open_view(None, &mut allowance).expect("view");
    let page = provider
        .candidates(
            &view,
            &IndexedQuery {
                filter: RawFilter::default(),
                text: Some(RawTextQuery::AllTerms("rare_sentinel".into())),
                neighbor_of: None,
                selection: IndexedSelection::TopK { limit: 3 },
            },
            &mut allowance,
        )
        .expect("selective query");
    assert_eq!(page.hits.len(), 1);
    before - allowance.remaining_work()
}

fn collect(service: &NativeService, mut query: RawRecallRequest, oracle: bool) -> Vec<RawSource> {
    let mut hits = Vec::new();
    for _ in 0..10_000 {
        let page = if oracle {
            service.recall_originals_oracle(query.clone())
        } else {
            service.recall_originals(query.clone())
        }
        .expect("recall");
        hits.extend(page.hits.into_iter().map(|hit| hit.source));
        let Some(cursor) = page.continuation else {
            hits.sort_by_key(|source| source.event_id);
            return hits;
        };
        query.continuation = Some(cursor);
    }
    panic!("enumeration failed to terminate");
}

#[test]
fn persistent_routes_match_oracle_and_selective_work_is_independent_of_archive_size() {
    let directory = tempfile::tempdir().expect("directory");
    let input = crate::capture::tests::request(1, "rare_sentinel exact evidence 7319");
    let session = SessionId::new();
    let source = SourceId::new();
    {
        let service = NativeService::open(directory.path(), "indexed-db", [7; 32]).expect("open");
        service.append_event(input.clone()).expect("first");
        project(&service, &input, false);
        let small_work = selective_work(&service, &input);
        for number in 2..202 {
            let mut next =
                crate::capture::tests::request(number, "ordinary discussion e\u{301} / é");
            next.event.recorded_at = TimestampMicros(number as i64);
            if number % 3 == 0 {
                next.event.session_id = Some(session);
                next.event.source_id = source;
            }
            service.append_event(next).expect("capture");
        }
        project(&service, &input, false);
        assert_eq!(selective_work(&service, &input), small_work);
        let provider = service.indexed_recall_provider(&input.context);
        let mut allowance = budget();
        let before = allowance.remaining_work();
        let view = provider.open_view(None, &mut allowance).expect("view");
        let page = provider
            .candidates(
                &view,
                &IndexedQuery {
                    filter: RawFilter::default(),
                    text: Some(RawTextQuery::AllTerms("rare_sentinel".into())),
                    neighbor_of: None,
                    selection: IndexedSelection::TopK { limit: 3 },
                },
                &mut allowance,
            )
            .expect("selective query");
        assert_eq!(page.hits.len(), 1);
        assert!(
            before - allowance.remaining_work() <= 4,
            "keyed posting route, not a corpus scan"
        );
        service
            .verify_native(true)
            .expect("deep generation reconstruction");
    }
    let service = NativeService::open(directory.path(), "indexed-db", [7; 32])
        .expect("reopen persistent index");
    let mut queries = vec![
        request(&input, Some(RawTextQuery::AllTerms("7319".into()))),
        request(
            &input,
            Some(RawTextQuery::ExactPhrase("e\u{301} / é".into())),
        ),
        request(&input, None),
    ];
    let mut query = request(&input, None);
    query.filter.session_id = Some(session);
    queries.push(query);
    let mut query = request(&input, None);
    query.filter.source_id = Some(source);
    queries.push(query);
    let mut query = request(&input, None);
    query.filter.recorded_range =
        Some(TimeRange::new(TimestampMicros(20), Some(TimestampMicros(30))).expect("range"));
    queries.push(query);
    let mut query = request(&input, None);
    query.filter.event_ids.insert(input.event.event_id);
    queries.push(query);
    for mut query in queries {
        query.page_size = 11;
        assert_eq!(
            collect(&service, query.clone(), false),
            collect(&service, query, true)
        );
    }
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot")
        .sequence();
    project(&service, &input, false);
    assert_eq!(
        service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("same snapshot")
            .sequence(),
        snapshot,
        "idle projection does not write maintenance loops"
    );
}

#[test]
fn forbidden_domain_insertions_and_corrupted_content_do_not_change_ranked_hits() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "indexed-db", [7; 32]).expect("open");
    let input = crate::capture::tests::request(1, "7319");
    service.append_event(input.clone()).expect("first");
    service
        .append_event(crate::capture::tests::request(2, "7319 additional context"))
        .expect("second");
    project(&service, &input, false);
    let query = IndexedQuery {
        filter: RawFilter::default(),
        text: Some(RawTextQuery::AllTerms("7319".into())),
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 20 },
    };
    let provider = service.indexed_recall_provider(&input.context);
    let view = provider.open_view(None, &mut budget()).expect("view");
    let before = provider
        .candidates(&view, &query, &mut budget())
        .expect("before");
    let forbidden_scope = ScopeId::new();
    let mut forbidden = crate::capture::tests::request(3, "7319 7319 7319");
    forbidden.event.scope_ids = BTreeSet::from([forbidden_scope]);
    forbidden.context.request.scopes = BTreeSet::from([forbidden_scope.to_string()]);
    service
        .append_event(forbidden.clone())
        .expect("private capture");
    project(&service, &input, false);
    let workspace = digest_bytes(input.context.request.workspace_id.as_bytes());
    let mut tx = service
        .engine
        .begin_write()
        .expect("corrupt forbidden projection");
    tx.put(
        &service.keyspaces.continuous,
        doc_key(&workspace, 1, forbidden.event.event_id),
        b"corrupted private lexical document".to_vec(),
    )
    .expect("injected corruption");
    tx.commit(Durability::Sync).expect("commit");
    let view = provider
        .open_view(None, &mut budget())
        .expect("authorized labels only");
    let after = provider
        .candidates(&view, &query, &mut budget())
        .expect("forbidden body must remain unread");
    assert_eq!(before.hits, after.hits);
    assert_eq!(before.completion, after.completion);
    assert_eq!(before.continuation, after.continuation);
    assert_eq!(before.snapshot.len(), after.snapshot.len());
}

#[test]
fn revocation_invalidates_old_views_until_a_separate_generation_catches_up() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "indexed-db", [7; 32]).expect("open");
    let input = crate::capture::tests::request(1, "private 7319");
    service.append_event(input.clone()).expect("first");
    service
        .append_event(crate::capture::tests::request(2, "allowed 7319"))
        .expect("second");
    project(&service, &input, false);
    let provider = service.indexed_recall_provider(&input.context);
    let view = provider.open_view(None, &mut budget()).expect("old view");
    let query = IndexedQuery {
        filter: RawFilter::default(),
        text: Some(RawTextQuery::AllTerms("7319".into())),
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 20 },
    };
    let receipt = service
        .revoke_original(
            &input.context,
            input.event.event_id,
            "revoke-first",
            &mut budget(),
        )
        .expect("revoke");
    assert_eq!(
        service
            .revoke_original(
                &input.context,
                input.event.event_id,
                "revoke-first",
                &mut budget()
            )
            .expect("retry"),
        receipt
    );
    assert_eq!(
        provider
            .candidates(&view, &query, &mut budget())
            .expect_err("old view invalidated")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        provider
            .open_view(None, &mut budget())
            .expect_err("route disabled before content search")
            .code,
        ErrorCode::IndexTooStale
    );
    let partial = service
        .project_originals(&input.context, true, 1, &mut budget())
        .expect("new staging generation");
    assert!(!partial.caught_up);
    assert_eq!(
        provider
            .open_view(None, &mut budget())
            .expect_err("old generation not silently reused")
            .code,
        ErrorCode::IndexTooStale
    );
    project(&service, &input, false);
    let fresh = provider
        .open_view(None, &mut budget())
        .expect("new active generation");
    let page = provider
        .candidates(&fresh, &query, &mut budget())
        .expect("current policy domains");
    assert_eq!(page.hits.len(), 1);
    assert_ne!(page.hits[0].source.event_id, input.event.event_id);
    service
        .verify_native(true)
        .expect("revocation and generation closure");
    let backup = service
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("backup");
    let target = tempfile::tempdir().expect("target");
    let restored =
        NativeService::open(target.path(), "indexed-db", [9; 32]).expect("restored owner");
    restored
        .restore_backup(RestoreBackupRequest {
            context: input.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    assert_eq!(
        collect(&restored, request(&input, None), false).len(),
        1,
        "restore must not revive revoked source"
    );
}

#[test]
fn pending_raw_tail_is_visible_without_query_time_indexing_and_overflow_is_explicit() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "indexed-db", [7; 32]).expect("open");
    let input = crate::capture::tests::request(1, "old");
    service.append_event(input.clone()).expect("capture");
    project(&service, &input, false);
    let fresh = crate::capture::tests::request(2, "fresh raw needle");
    let receipt = service.append_event(fresh.clone()).expect("fresh");
    let sequence = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot")
        .sequence();
    let mut query = request(&input, Some(RawTextQuery::AllTerms("needle".into())));
    query.after_receipt = Some(receipt);
    assert_eq!(
        collect(&service, query, false)[0].event_id,
        fresh.event.event_id
    );
    assert_eq!(
        service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("no query index writes")
            .sequence(),
        sequence
    );
    for number in 3..132 {
        service
            .append_event(crate::capture::tests::request(number, "pending"))
            .expect("pending");
    }
    assert_eq!(
        service
            .recall_originals(request(&input, None))
            .expect_err("bounded tail")
            .code,
        ErrorCode::IndexTooStale
    );
    let mut exact = request(&input, None);
    exact.filter.event_ids.insert(fresh.event.event_id);
    assert_eq!(
        collect(&service, exact, false).len(),
        1,
        "explicit originals remain addressable"
    );
}

#[test]
fn exhaustive_cursor_freezes_tail_and_routes_across_incremental_publication() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "indexed-db", [7; 32]).expect("open");
    let input = crate::capture::tests::request(1, "same");
    service.append_event(input.clone()).expect("capture");
    project(&service, &input, false);
    for number in 2..8 {
        service
            .append_event(crate::capture::tests::request(number, "same"))
            .expect("tail");
    }
    let mut query = request(&input, None);
    query.page_size = 2;
    let first = service.recall_originals(query.clone()).expect("first");
    let mut ids = first
        .hits
        .into_iter()
        .map(|hit| hit.source.event_id)
        .collect::<Vec<_>>();
    query.continuation = first.continuation;
    project(&service, &input, false);
    service
        .append_event(crate::capture::tests::request(8, "after selection"))
        .expect("later");
    while query.continuation.is_some() {
        let page = service
            .recall_originals(query.clone())
            .expect("stable enumeration");
        assert_eq!(page.snapshot, first.snapshot);
        ids.extend(page.hits.into_iter().map(|hit| hit.source.event_id));
        query.continuation = page.continuation;
    }
    assert_eq!(ids.len(), 7);
    assert_eq!(ids.into_iter().collect::<BTreeSet<_>>().len(), 7);
}

#[test]
fn large_unindexed_source_and_direct_causal_neighbors_remain_recallable() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "indexed-db", [7; 32]).expect("open");
    let input = crate::capture::tests::request(1, "parent");
    let first_receipt = service.append_event(input.clone()).expect("parent");
    let mut bytes = vec![b' '; 1024 * 1024 + 1];
    bytes.extend_from_slice(b"oversized_needle");
    let payload = service
        .stage_payload(StagePayloadRequest {
            context: input.context.clone(),
            idempotency_key: "large".into(),
            block_id: ContentBlockId::new(),
            bytes,
        })
        .expect("payload");
    let mut child = crate::capture::tests::request(2, "");
    child.event.parent_event_ids.insert(input.event.event_id);
    child.event.payload = contextdb_core::EventPayload::Staged {
        reference: payload.reference,
        media_type: "text/plain".into(),
    };
    service.append_event(child.clone()).expect("child");
    project(&service, &input, false);
    assert_eq!(
        collect(
            &service,
            request(
                &input,
                Some(RawTextQuery::AllTerms("oversized_needle".into()))
            ),
            false
        )[0]
        .event_id,
        child.event.event_id
    );
    let provider = service.indexed_recall_provider(&input.context);
    let historical = provider
        .open_view(Some(first_receipt.workspace_commit), &mut budget())
        .expect("historical view");
    let future_query = IndexedQuery {
        filter: RawFilter::default(),
        text: None,
        neighbor_of: Some(child.event.event_id),
        selection: IndexedSelection::TopK { limit: 10 },
    };
    assert_eq!(
        provider
            .candidates(&historical, &future_query, &mut budget())
            .expect_err("future adjacency is unavailable")
            .code,
        ErrorCode::NotFound
    );
    let view = provider.open_view(None, &mut budget()).expect("view");
    for (target, expected) in [
        (input.event.event_id, child.event.event_id),
        (child.event.event_id, input.event.event_id),
    ] {
        let page = provider
            .candidates(
                &view,
                &IndexedQuery {
                    filter: RawFilter::default(),
                    text: None,
                    neighbor_of: Some(target),
                    selection: IndexedSelection::TopK { limit: 10 },
                },
                &mut budget(),
            )
            .expect("addressed adjacency");
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].source.event_id, expected);
    }
}

#[test]
fn cancellation_deadline_and_lost_generation_rows_fail_closed() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "indexed-db", [7; 32]).expect("open");
    let input = crate::capture::tests::request(1, "cancel me");
    service.append_event(input.clone()).expect("capture");
    project(&service, &input, false);
    let provider = service.indexed_recall_provider(&input.context);
    let cancellation = QueryCancellation::default();
    let held = (0..64)
        .map(|_| {
            provider
                .open_view(None, &mut budget())
                .expect("bounded read view")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        provider
            .open_view(None, &mut budget())
            .expect_err("view pressure")
            .code,
        ErrorCode::ResourceExhausted
    );
    drop(held);
    drop(
        provider
            .open_view(None, &mut budget())
            .expect("released view permits"),
    );
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(100, 1000, Duration::from_secs(1), cancellation);
    assert_eq!(
        provider
            .open_view(None, &mut cancelled)
            .expect_err("cancelled before any materialization")
            .code,
        ErrorCode::BudgetExhausted
    );
    let mut expired = QueryBudget::new(100, 1000, Duration::ZERO, QueryCancellation::default());
    assert_eq!(
        provider
            .open_view(None, &mut expired)
            .expect_err("deadline before authorization traversal")
            .code,
        ErrorCode::BudgetExhausted
    );
    {
        let _guard = service.lock_writes().expect("contended writer");
        let mut allowance = QueryBudget::new(
            100,
            1000,
            Duration::from_millis(10),
            QueryCancellation::default(),
        );
        assert_eq!(
            service
                .revoke_original(
                    &input.context,
                    input.event.event_id,
                    "deadline-revoke",
                    &mut allowance
                )
                .expect_err("shared deadline bounds writer acquisition")
                .code,
            ErrorCode::BudgetExhausted
        );
    }
    let workspace = digest_bytes(input.context.request.workspace_id.as_bytes());
    let mut tx = service.engine.begin_write().expect("corruption injection");
    tx.delete(
        &service.keyspaces.continuous,
        doc_key(&workspace, 1, input.event.event_id),
    )
    .expect("delete projection");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("lost document family")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = service
        .engine
        .begin_write()
        .expect("entire projection loss");
    for entry in tx
        .scan_prefix(&service.keyspaces.continuous, b"raw/")
        .expect("derived keys")
    {
        tx.delete(&service.keyspaces.continuous, entry.key)
            .expect("delete derived row");
    }
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("journal detects entire index loss")
            .code,
        ErrorCode::IntegrityFailure
    );
}
