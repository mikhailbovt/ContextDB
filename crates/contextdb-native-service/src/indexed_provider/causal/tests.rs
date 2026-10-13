//! Structural routing/authority fixtures. No learned retrieval-quality claim.

use super::*;
use contextdb_core::{ContentDigest, EventKind, ScopeId};
use contextdb_service::CaptureRequest;
use contextdb_storage::{Durability, WriteTransaction};
use std::sync::Arc;

struct Fixture {
    service: NativeService,
    inputs: Vec<CaptureRequest>,
    root: tempfile::TempDir,
    keys: Arc<crate::NativeCustodyKeys>,
    ledger: Arc<crate::NativeSuppressionLedger>,
    _keys: tempfile::TempDir,
    _ledger: tempfile::TempDir,
}
fn budget() -> QueryBudget {
    QueryBudget::new(
        5_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}
fn project(service: &NativeService, context: &AuthenticatedRequestContext) {
    while !service
        .maintain_custody(context, 64, &mut budget())
        .expect("custody")
        .caught_up
    {}
    while !service
        .project_originals_bm25(context, false, 64, &mut budget())
        .expect("raw projection")
        .caught_up
    {}
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("native root");
    let (_keys, keys) = crate::encryption::tests::authority("causal-fixture");
    let (_ledger, ledger) = crate::suppression::tests::authority("causal-fixture");
    let service = NativeService::open_encrypted(
        root.path().join("native"),
        "causal-fixture",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted owner");
    let parent = crate::capture::tests::request(1, "original parent");
    let mut seed = crate::capture::tests::request(2, "current seed");
    seed.event.parent_event_ids.insert(parent.event.event_id);
    seed.event.source_version = Some("version one".into());
    let mut correction = crate::capture::tests::request(3, "corrected source");
    correction.event.kind = EventKind::MessageEdited;
    correction.event.supersedes_event_id = Some(seed.event.event_id);
    let mut child = crate::capture::tests::request(4, "direct child");
    child.event.parent_event_ids.insert(seed.event.event_id);
    let mut grandchild = crate::capture::tests::request(5, "second hop excluded");
    grandchild
        .event
        .parent_event_ids
        .insert(child.event.event_id);
    let mut denied = crate::capture::tests::request(6, "denied child");
    denied.event.parent_event_ids.insert(seed.event.event_id);
    let hidden = ScopeId::new();
    denied.context.request.scopes.insert(hidden.to_string());
    denied.event.scope_ids.clear();
    denied.event.scope_ids.insert(hidden);
    let inputs = vec![parent, seed, correction, child, grandchild, denied];
    for input in &inputs {
        service.append_event(input.clone()).expect("capture");
    }
    project(&service, &inputs[0].context);
    Fixture {
        service,
        inputs,
        root,
        keys,
        ledger,
        _keys,
        _ledger,
    }
}
fn seed(f: &Fixture) -> RawSource {
    RawSource::from(&f.inputs[1].event)
}
fn ids(page: &CausalPage) -> Vec<ObservationId> {
    page.hits.iter().map(|hit| hit.source.event_id).collect()
}

#[test]
fn encrypted_cold_one_hop_preserves_parent_correction_and_child_without_body_reads() {
    let f = fixture();
    let source = seed(&f);
    let context = f.inputs[0].context.clone();
    let expected = vec![
        f.inputs[0].event.event_id,
        f.inputs[2].event.event_id,
        f.inputs[3].event.event_id,
    ];
    drop(f.service);
    let service = NativeService::open_encrypted(
        f.root.path().join("native"),
        "causal-fixture",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold owner");
    let provider = service.indexed_recall_provider(&context);
    let mut shared = budget();
    let view = provider
        .open_bm25_view(None, &mut shared)
        .expect("budgeted view");
    let first = provider
        .causal_candidates(&view, std::slice::from_ref(&source), &mut shared)
        .expect("one hop");
    assert_eq!(first.completion, CausalCompletion::Complete);
    assert_eq!(ids(&first), expected);
    assert!(!first.raw_lag);
    assert!(!first.source_coverage_incomplete);
    assert_eq!(first.admitted_sources.len(), 4);
    assert!(first.admitted_sources.contains_key(&source.event_id));
    assert!(
        !first
            .admitted_sources
            .contains_key(&f.inputs[4].event.event_id)
    );
    assert!(
        !first
            .admitted_sources
            .contains_key(&f.inputs[5].event.event_id)
    );
    assert!(first.hits.iter().all(|hit| hit.matches.is_empty()));
    let current = provider
        .causal_owned_query_seeds(&view, &[source.event_id, source.event_id], &mut shared)
        .expect("current source seed");
    assert_eq!(current.seeds, vec![source.clone()]);
    assert!(!current.unprojected);

    // Corrupt original bodies only after reopening the valid store. This route
    // must use accepted metadata; actual materialization still owns body checks.
    let mut tx = service.engine.begin_write().expect("fault writer");
    for input in &f.inputs {
        tx.put(
            &service.keyspaces.observations_content,
            digest_bytes(input.event.event_id.to_string().as_bytes()).into_bytes(),
            b"body must not be loaded by causal discovery".to_vec(),
        )
        .expect("fault body");
    }
    tx.put(
        &service.keyspaces.continuous,
        doc_key(
            &view.workspace,
            view.generation.number,
            f.inputs[5].event.event_id,
        ),
        b"denied derived document must not be read".to_vec(),
    )
    .expect("fault denied document");
    tx.commit(Durability::Sync).expect("fault commit");
    let view = provider
        .open_bm25_view(None, &mut shared)
        .expect("fresh fault view");
    let current = provider
        .causal_owned_query_seeds(&view, &[source.event_id], &mut shared)
        .expect("current seed attribution without loading its body");
    assert_eq!(current.seeds, vec![source.clone()]);
    assert_eq!(
        provider
            .causal_owned_query_seeds(&view, &[f.inputs[5].event.event_id], &mut shared)
            .expect_err("inaccessible current input cannot be suppressed as empty success")
            .code,
        ErrorCode::PermissionDenied
    );
    let repeated = provider
        .causal_candidates(&view, &[source], &mut shared)
        .expect("no body census");
    assert_eq!(repeated.hits, first.hits);
    assert_eq!(repeated.admitted_sources, first.admitted_sources);
    assert_eq!(repeated.completion, CausalCompletion::Complete);
}

#[test]
fn raw_tail_is_explicit_and_is_not_manufactured_from_recovery_version_digest() {
    let f = fixture();
    let mut tail = crate::capture::tests::request(7, "fresh unprojected child");
    tail.event
        .parent_event_ids
        .insert(f.inputs[1].event.event_id);
    tail.event.source_version = Some("must not be invented from a digest".into());
    f.service.append_event(tail.clone()).expect("tail");
    let provider = f.service.indexed_recall_provider(&f.inputs[0].context);
    let mut shared = budget();
    let view = provider
        .open_bm25_view(None, &mut shared)
        .expect("current lag view");
    let page = provider
        .causal_candidates(&view, &[seed(&f)], &mut shared)
        .expect("projected only");
    assert_eq!(page.completion, CausalCompletion::RawLag);
    assert!(page.raw_lag);
    assert_eq!(
        ids(&page),
        vec![
            f.inputs[0].event.event_id,
            f.inputs[2].event.event_id,
            f.inputs[3].event.event_id
        ]
    );
    assert!(!page.admitted_sources.contains_key(&tail.event.event_id));
    let current_seed = provider
        .causal_candidates(&view, &[RawSource::from(&tail.event)], &mut shared)
        .expect("unprojected seed status");
    assert_eq!(current_seed.completion, CausalCompletion::UnprojectedSource);
    assert!(current_seed.raw_lag);
    assert!(current_seed.hits.is_empty());
    let current = provider
        .causal_owned_query_seeds(
            &view,
            &[tail.event.event_id, f.inputs[1].event.event_id],
            &mut shared,
        )
        .expect("projected current sources only");
    assert!(current.unprojected);
    assert_eq!(current.seeds, vec![seed(&f)]);
}

#[test]
fn forged_versions_edges_and_wrong_child_postings_do_not_become_candidates() {
    let f = fixture();
    let provider = f.service.indexed_recall_provider(&f.inputs[0].context);
    let view = provider.open_bm25_view(None, &mut budget()).expect("view");
    let source = seed(&f);
    let mut forged_seed = source.clone();
    forged_seed.source_version = Some("forged seed version".into());
    assert_eq!(
        provider
            .causal_candidates(&view, &[forged_seed], &mut budget())
            .expect_err("owner input version mismatch")
            .code,
        ErrorCode::IntegrityFailure
    );
    let key = doc_key(&view.workspace, view.generation.number, source.event_id);
    let snapshot = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("read");
    let bytes = snapshot
        .get(&f.service.keyspaces.continuous, &key)
        .expect("row")
        .expect("document");
    let original: IndexedOriginal = decode(&bytes, "raw source").expect("raw source");
    let mut changed = original.clone();
    changed.parents.insert(f.inputs[4].event.event_id);
    let mut tx = f.service.engine.begin_write().expect("fault writer");
    tx.put(
        &f.service.keyspaces.continuous,
        key.clone(),
        encode(&changed).expect("encode"),
    )
    .expect("wrong parents");
    tx.commit(Durability::Sync).expect("commit");
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("wrong-parent fault view");
    assert_eq!(
        provider
            .causal_candidates(&view, std::slice::from_ref(&source), &mut budget())
            .expect_err("recovery authenticates exact edge set")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut changed = original.clone();
    changed.source.payload_digest = Some(ContentDigest::from_bytes([9; 32]));
    let mut tx = f.service.engine.begin_write().expect("fault writer");
    tx.put(
        &f.service.keyspaces.continuous,
        key.clone(),
        encode(&changed).expect("encode"),
    )
    .expect("wrong payload");
    tx.commit(Durability::Sync).expect("commit");
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("wrong-payload fault view");
    assert_eq!(
        provider
            .causal_candidates(&view, std::slice::from_ref(&source), &mut budget())
            .expect_err("accepted payload metadata")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = f.service.engine.begin_write().expect("fault writer");
    tx.put(&f.service.keyspaces.continuous, key, bytes)
        .expect("restore source");
    let prefix = format!(
        "{}route/{}/child/{}/",
        generation_prefix(&view.workspace, view.generation.number),
        original.policy_domain,
        source.event_id
    );
    let false_key = format!("{prefix}{:020}/{}", 1, f.inputs[4].event.event_id).into_bytes();
    tx.put(
        &f.service.keyspaces.continuous,
        false_key,
        encode(&f.inputs[4].event.event_id).expect("encode"),
    )
    .expect("invented adjacency");
    tx.commit(Durability::Sync).expect("commit");
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("invented-edge fault view");
    assert_eq!(
        provider
            .causal_candidates(&view, &[source], &mut budget())
            .expect_err("posting cannot grant adjacency")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn current_revocation_historical_legacy_and_budget_refusals_are_explicit() {
    let f = fixture();
    let source = seed(&f);
    let provider = f.service.indexed_recall_provider(&f.inputs[0].context);
    let mut shared = budget();
    let view = provider
        .open_bm25_view(None, &mut shared)
        .expect("current view");
    let legacy = provider
        .open_view(None, &mut budget())
        .expect("legacy view");
    assert_eq!(
        provider
            .causal_candidates(&legacy, std::slice::from_ref(&source), &mut budget())
            .expect("explicit legacy")
            .completion,
        CausalCompletion::UnsupportedProfile
    );
    let past = provider
        .open_bm25_view(Some(1), &mut budget())
        .expect("historical view");
    assert_eq!(
        provider
            .causal_candidates(&past, std::slice::from_ref(&source), &mut budget())
            .expect("explicit historical")
            .completion,
        CausalCompletion::UnsupportedProfile
    );
    let mut no_work = QueryBudget::new(0, 16 * 1024, Duration::from_secs(5), Default::default());
    let work_page = provider
        .causal_candidates(&view, std::slice::from_ref(&source), &mut no_work)
        .expect("typed work limit");
    assert_eq!(work_page.completion, CausalCompletion::WorkLimit);
    assert!(work_page.hits.is_empty());
    let mut no_bytes = QueryBudget::new(100_000, 0, Duration::from_secs(5), Default::default());
    let bytes_page = provider
        .causal_candidates(&view, std::slice::from_ref(&source), &mut no_bytes)
        .expect("typed byte limit");
    assert_eq!(bytes_page.completion, CausalCompletion::ByteLimit);
    assert!(bytes_page.hits.is_empty());
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(1000, 1024, Duration::from_secs(5), cancellation);
    assert_eq!(
        provider
            .causal_candidates(&view, std::slice::from_ref(&source), &mut cancelled)
            .expect_err("same cancellation")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        provider
            .causal_candidates(&view, &vec![source.clone(); 9], &mut budget())
            .expect_err("seed cap")
            .code,
        ErrorCode::InvalidArgument
    );
    f.service
        .revoke_original(
            &f.inputs[0].context,
            f.inputs[0].event.event_id,
            "causal-revoke-parent",
            &mut budget(),
        )
        .expect("revoke");
    assert_eq!(
        provider
            .causal_owned_query_seeds(&view, &[source.event_id], &mut shared)
            .expect_err("current seed revocation before metadata")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        provider
            .causal_candidates(&view, &[source], &mut shared)
            .expect_err("current epoch changed before derived metadata read")
            .code,
        ErrorCode::IndexTooStale
    );
}

#[test]
fn full_admitted_frontier_cap_is_checked_before_another_source_clone() {
    let mut page = CausalPage::empty(CausalCompletion::Complete);
    for sequence in 1..=256 {
        admit(
            &RawSource::from(&crate::capture::tests::request(sequence, "source").event),
            &mut page,
            &mut budget(),
        )
        .expect("bounded source");
    }
    assert_eq!(
        admit(
            &RawSource::from(&crate::capture::tests::request(257, "source").event),
            &mut page,
            &mut budget()
        )
        .expect_err("source cap")
        .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(page.admitted_sources.len(), 256);
}
