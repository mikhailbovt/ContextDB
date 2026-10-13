//! Native population, source authority and shared-budget contracts.

use super::*;
use contextdb_core::ScopeId;
use contextdb_service::CapturePort;
use contextdb_storage::{Durability, WriteTransaction};

mod automatic;

fn budget() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}
fn query(text: &str) -> RawBm25Query {
    RawBm25Query {
        text: text.into(),
        filter: RawFilter::default(),
        limit: 64,
    }
}
fn project(service: &NativeService, context: &AuthenticatedRequestContext, mut rebuild: bool) {
    loop {
        if service
            .maintain_custody(context, 64, &mut budget())
            .expect("current custody")
            .caught_up
        {
            break;
        }
    }
    loop {
        let progress = service
            .project_originals_bm25(context, rebuild, 64, &mut budget())
            .expect("BM25 projection");
        rebuild = false;
        if progress.caught_up {
            break;
        }
    }
}

#[test]
fn cold_bm25_or_unites_complementary_sources_and_refuses_revoked_views() {
    let directory = tempfile::tempdir().expect("directory");
    let (_keys_dir, keys) = crate::encryption::tests::authority("bm25-or");
    let (_ledger_dir, ledger) = crate::suppression::tests::authority("bm25-or");
    let path = directory.path().join("native");
    let service =
        NativeService::open_encrypted(&path, "bm25-or", [7; 32], ledger.clone(), keys.clone())
            .expect("owner");
    let first = crate::capture::tests::request(1, "ASTROLABE4312 launch_code red");
    let second = crate::capture::tests::request(2, "HYDROFOIL9821 recovery_code blue");
    let mut hidden =
        crate::capture::tests::request(3, "ASTROLABE4312 HYDROFOIL9821 forbidden_population");
    let hidden_scope = ScopeId::new();
    hidden.event.scope_ids = BTreeSet::from([hidden_scope]);
    hidden.context.request.scopes = BTreeSet::from([hidden_scope.to_string()]);
    for input in [&first, &second, &hidden] {
        service.append_event(input.clone()).expect("capture");
    }
    project(&service, &first.context, false);
    drop(service);
    let service =
        NativeService::open_encrypted(&path, "bm25-or", [7; 32], ledger, keys).expect("cold owner");
    let provider = service.indexed_recall_provider(&first.context);
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("current budgeted view");
    let page = provider
        .bm25_candidates(&view, &query("ASTROLABE4312 HYDROFOIL9821"), &mut budget())
        .expect("OR query");
    assert_eq!(page.profile_status, RawBm25ProfileStatus::Supported);
    assert_eq!(page.completion, RawBm25Completion::Complete);
    assert_eq!(
        page.hits
            .iter()
            .map(|hit| hit.source.event_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([first.event.event_id, second.event.event_id])
    );
    assert!(
        page.hits
            .iter()
            .all(|hit| hit.score.is_finite() && hit.matches.len() == 1)
    );
    assert!(
        (page.hits[0].score - 2_f64.ln()).abs() < 1e-12,
        "denied domain cannot influence N/DF"
    );
    let mut bounded = query("ASTROLABE4312 HYDROFOIL9821");
    bounded.limit = 1;
    assert_eq!(
        provider
            .bm25_candidates(&view, &bounded, &mut budget())
            .expect("rank cap")
            .completion,
        RawBm25Completion::RankedLimit
    );
    service
        .revoke_original(
            &first.context,
            first.event.event_id,
            "bm25-revoke",
            &mut budget(),
        )
        .expect("revoke");
    assert_eq!(
        provider
            .bm25_candidates(&view, &query("ASTROLABE4312"), &mut budget())
            .expect_err("stale policy epoch")
            .code,
        ErrorCode::IndexTooStale
    );
    drop(view);
    project(&service, &first.context, true);
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("fresh epoch");
    let page = provider
        .bm25_candidates(&view, &query("ASTROLABE4312 HYDROFOIL9821"), &mut budget())
        .expect("current permitted only");
    assert_eq!(page.hits.len(), 1);
    assert_eq!(page.hits[0].source.event_id, second.event.event_id);
}

#[test]
fn fresh_tail_population_is_joined_once_and_unsupported_profiles_stay_explicit() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "bm25-tail", [7; 32]).expect("owner");
    let first = crate::capture::tests::request(1, "ASTROLABE4312 HYDROFOIL9821");
    service.append_event(first.clone()).expect("capture");
    let provider = service.indexed_recall_provider(&first.context);
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("unprojected view");
    assert_eq!(
        provider
            .bm25_candidates(&view, &query("ASTROLABE4312"), &mut budget())
            .expect("explicit missing")
            .profile_status,
        RawBm25ProfileStatus::MissingProjection
    );
    drop(view);
    project(&service, &first.context, false);
    let tail = crate::capture::tests::request(2, "ASTROLABE4312 HYDROFOIL9821");
    service
        .append_event(tail.clone())
        .expect("fresh unprojected capture");
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("with tail");
    let page = provider
        .bm25_candidates(&view, &query("ASTROLABE4312 HYDROFOIL9821"), &mut budget())
        .expect("tail OR");
    assert_eq!(page.hits.len(), 2);
    let expected = 2.0 * (1.0_f64 + 0.5 / 2.5).ln();
    assert!(
        page.hits
            .iter()
            .all(|hit| (hit.score - expected).abs() < 1e-12),
        "tail document is counted once across both OR terms"
    );
    let mut narrowed = query("ASTROLABE4312");
    narrowed.filter.event_ids.insert(first.event.event_id);
    assert_eq!(
        provider
            .bm25_candidates(&view, &narrowed, &mut budget())
            .expect("narrowed refusal")
            .profile_status,
        RawBm25ProfileStatus::UnsupportedFilter
    );
    let old = provider
        .open_bm25_view(Some(1), &mut budget())
        .expect("historical view");
    assert_eq!(
        provider
            .bm25_candidates(&old, &query("ASTROLABE4312"), &mut budget())
            .expect("historical refusal")
            .profile_status,
        RawBm25ProfileStatus::UnsupportedHistorical
    );
    assert_eq!(
        provider
            .bm25_candidates(
                &provider
                    .open_view(None, &mut budget())
                    .expect("legacy view"),
                &query("ASTROLABE4312"),
                &mut budget()
            )
            .expect_err("no legacy budget laundering")
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn metadata_budget_refusals_remain_typed_and_feature_fence_is_mandatory() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "bm25-budget", [7; 32]).expect("owner");
    let first = crate::capture::tests::request(1, "ASTROLABE4312");
    service.append_event(first.clone()).expect("capture");
    project(&service, &first.context, false);
    let provider = service.indexed_recall_provider(&first.context);
    for mut allowance in [
        QueryBudget::new(0, u64::MAX, Duration::from_secs(30), Default::default()),
        QueryBudget::new(1_000_000, 0, Duration::from_secs(30), Default::default()),
        QueryBudget::new(1_000_000, u64::MAX, Duration::ZERO, Default::default()),
    ] {
        assert_eq!(
            provider
                .open_bm25_view(None, &mut allowance)
                .expect_err("same parent limits")
                .code,
            ErrorCode::BudgetExhausted
        );
    }
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut canceled = QueryBudget::new(1_000_000, u64::MAX, Duration::from_secs(30), cancellation);
    assert_eq!(
        provider
            .open_bm25_view(None, &mut canceled)
            .expect_err("cancellation")
            .code,
        ErrorCode::BudgetExhausted
    );
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let mut bytes = QueryBudget::new(100_000, 1, Duration::from_secs(30), Default::default());
    assert_eq!(
        budget::metadata(&snapshot, &mut bytes, |reader| reader
            .get(&service.keyspaces.meta, crate::META_MANIFEST_KEY)
            .map_err(storage_error))
        .expect_err("bounded point read")
        .code,
        ErrorCode::BudgetExhausted
    );
    let mut work = QueryBudget::new(1, 1_000_000, Duration::from_secs(30), Default::default());
    assert_eq!(
        budget::metadata(&snapshot, &mut work, |reader| reader
            .scan_prefix_page(
                &service.keyspaces.continuous,
                ScanPageRequest {
                    prefix: b"outbox/",
                    start_after: None,
                    max_entries: 129,
                    max_bytes: 1_000_000
                }
            )
            .map_err(storage_error))
        .expect_err("bounded scan")
        .code,
        ErrorCode::BudgetExhausted
    );
    let mut manifest = service.raw_manifest(&snapshot).expect("manifest");
    drop(snapshot);
    assert!(manifest.features.remove(statistics::FEATURE));
    manifest.checksum = crate::manifest_checksum(&manifest).expect("valid manifest checksum");
    let mut tx = service.engine.begin_write().expect("writer");
    tx.put(
        &service.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest bytes"),
    )
    .expect("strip marker");
    tx.commit(Durability::Sync).expect("commit");
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("metadata view");
    assert_eq!(
        provider
            .bm25_candidates(&view, &query("ASTROLABE4312"), &mut budget())
            .expect_err("feature profile cannot disappear")
            .code,
        ErrorCode::IntegrityFailure
    );
}
