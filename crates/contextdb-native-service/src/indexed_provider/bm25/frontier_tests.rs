//! Full inspected-source retention for owned hybrid provenance only.

use super::*;
use contextdb_core::{EventPayload, ScopeId};
use contextdb_storage::{Durability, WriteTransaction};

fn budget() -> QueryBudget {
    QueryBudget::new(
        20_000_000,
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
fn query() -> RawBm25Query {
    RawBm25Query {
        text: "RETAIN4312".into(),
        filter: RawFilter::default(),
        limit: 1,
    }
}

#[test]
fn cold_frontier_retains_ranked_out_and_permitted_tail_omissions_but_excludes_denied_sources() {
    let root = tempfile::tempdir().expect("native");
    let (_keys, keys) = crate::encryption::tests::authority("bm25-frontier");
    let (_ledger, ledger) = crate::suppression::tests::authority("bm25-frontier");
    let path = root.path().join("native");
    let service = NativeService::open_encrypted(
        &path,
        "bm25-frontier",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("owner");
    let indexed: Vec<_> = (1..=3)
        .map(|sequence| crate::capture::tests::request(sequence, "RETAIN4312 indexed source"))
        .collect();
    for input in &indexed {
        service
            .append_event(input.clone())
            .expect("indexed capture");
    }
    project(&service, &indexed[0].context);
    let mut nontext = crate::capture::tests::request(4, "placeholder");
    nontext.event.payload = EventPayload::InlineBytes {
        bytes: vec![0xff, 0xfa],
        media_type: "application/octet-stream".into(),
        digest: contextdb_core::ContentDigest::from_bytes(*blake3::hash(&[0xff, 0xfa]).as_bytes()),
    };
    let unrelated = crate::capture::tests::request(5, "permitted tail without query terms");
    let hidden_scope = ScopeId::new();
    let mut denied = crate::capture::tests::request(6, "RETAIN4312 denied tail");
    denied.event.scope_ids = BTreeSet::from([hidden_scope]);
    denied.context.request.scopes = BTreeSet::from([hidden_scope.to_string()]);
    for input in [&nontext, &unrelated, &denied] {
        service.append_event(input.clone()).expect("tail capture");
    }
    drop(service);
    let service = NativeService::open_encrypted(&path, "bm25-frontier", [7; 32], ledger, keys)
        .expect("cold owner");
    let provider = service.indexed_recall_provider(&indexed[0].context);
    let mut shared = budget();
    // An inaccessible body must not be opened just to populate the frontier.
    let mut tx = service.engine.begin_write().expect("fault writer");
    tx.put(
        &service.keyspaces.observations_content,
        digest_bytes(denied.event.event_id.to_string().as_bytes()).into_bytes(),
        b"denied body must stay unread".to_vec(),
    )
    .expect("body fault");
    tx.commit(Durability::Sync).expect("fault commit");
    let view = provider
        .open_bm25_view(None, &mut shared)
        .expect("fault view");
    let result = provider
        .bm25_candidates_with_frontier(&view, &query(), &mut shared)
        .expect("owned frontier");
    assert_eq!(result.page.hits.len(), 1);
    assert_eq!(result.page.completion, RawBm25Completion::RankedLimit);
    assert_eq!(
        result.page.profile_status,
        RawBm25ProfileStatus::IncompleteLexicalCoverage
    );
    assert_eq!(
        result
            .admitted_sources
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        indexed
            .iter()
            .map(|input| input.event.event_id)
            .chain([nontext.event.event_id, unrelated.event.event_id])
            .collect()
    );
    assert_eq!(
        result.admitted_sources.get(&nontext.event.event_id),
        Some(&RawSource::from(&nontext.event))
    );
    assert!(!result.admitted_sources.contains_key(&denied.event.event_id));
}

#[test]
fn public_bm25_wrapper_preserves_none_collector_results_and_exact_parent_fees() {
    let root = tempfile::tempdir().expect("native");
    let service = NativeService::open(root.path(), "bm25-frontier-legacy", [7; 32]).expect("owner");
    let input = crate::capture::tests::request(1, "RETAIN4312 unchanged");
    service.append_event(input.clone()).expect("capture");
    project(&service, &input.context);
    let provider = service.indexed_recall_provider(&input.context);
    let view = provider.open_bm25_view(None, &mut budget()).expect("view");
    let mut public_budget = budget();
    let public = provider
        .bm25_candidates(&view, &query(), &mut public_budget)
        .expect("public");
    let mut none_budget = budget();
    let none = provider
        .bm25_candidates_inner(&view, &query(), &mut none_budget, None)
        .expect("none collector");
    assert_eq!(public.terms, none.terms);
    assert_eq!(public.hits, none.hits);
    assert_eq!(public.profile_status, none.profile_status);
    assert_eq!(public.completion, none.completion);
    assert_eq!(
        (
            public_budget.remaining_work(),
            public_budget.remaining_bytes()
        ),
        (none_budget.remaining_work(), none_budget.remaining_bytes())
    );
}

#[test]
fn frontier_cap_refuses_before_another_source_document_or_body_is_materialized() {
    let root = tempfile::tempdir().expect("native");
    let service = NativeService::open(root.path(), "bm25-frontier-cap", [7; 32]).expect("owner");
    let inputs: Vec<_> = (1..=257)
        .map(|sequence| crate::capture::tests::request(sequence, "RETAIN4312 source"))
        .collect();
    for input in &inputs {
        service.append_event(input.clone()).expect("capture");
    }
    project(&service, &inputs[0].context);
    let provider = service.indexed_recall_provider(&inputs[0].context);
    let view = provider.open_bm25_view(None, &mut budget()).expect("view");
    let mut tx = service.engine.begin_write().expect("fault writer");
    tx.put(
        &service.keyspaces.continuous,
        statistics::document_key(
            &view.workspace,
            view.generation.number,
            inputs[256].event.event_id,
        ),
        b"257th derived document must remain unread".to_vec(),
    )
    .expect("doc fault");
    tx.put(
        &service.keyspaces.observations_content,
        digest_bytes(inputs[256].event.event_id.to_string().as_bytes()).into_bytes(),
        b"257th original body must remain unread".to_vec(),
    )
    .expect("body fault");
    tx.commit(Durability::Sync).expect("commit");
    // Reopen the immutable read view after fault injection so this assertion
    // observes the actual corrupted rows if the frontier guard were too late.
    let view = provider
        .open_bm25_view(None, &mut budget())
        .expect("fault view");
    assert_eq!(
        provider
            .bm25_candidates_with_frontier(&view, &query(), &mut budget())
            .expect_err("full frontier cap")
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        provider
            .bm25_candidates(&view, &query(), &mut budget())
            .expect_err("legacy still reaches the injected document corruption")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn repeat_metadata_and_insufficient_shared_scratch_allowance_are_checked() {
    let source = RawSource::from(&crate::capture::tests::request(1, "source").event);
    let mut frontier = Bm25Frontier::default();
    frontier
        .admit(&source, &mut budget())
        .expect("admitted source");
    frontier
        .admit(&source, &mut budget())
        .expect("same exact source");
    assert_eq!(frontier.sources.len(), 1);
    let mut changed = source.clone();
    changed.source_version = Some("different immutable version".into());
    assert_eq!(
        frontier
            .admit(&changed, &mut budget())
            .expect_err("version collision")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut frontier = Bm25Frontier::default();
    let mut too_small =
        QueryBudget::new(100_000, 1024, Duration::from_secs(30), Default::default());
    assert_eq!(
        frontier
            .guard(source.event_id, &mut too_small)
            .expect_err("whole tree scratch")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert!(frontier.sources.is_empty());
    assert!(!frontier.scratch_admitted);
}
