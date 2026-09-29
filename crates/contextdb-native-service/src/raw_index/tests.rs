use super::*;
use contextdb_core::{RawFilter, RawTextQuery};
use contextdb_service::{
    CapturePort, PayloadPort, RawRecallBudget, RawRecallPort, RawRecallRequest, ReadOriginalRequest,
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

#[test]
fn encrypted_projection_accepts_a_full_lexical_document() {
    let root = tempfile::tempdir().expect("native directory");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("large-raw");
    let (_keys_directory, keys) = crate::encryption::tests::authority("large-raw");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "large-raw",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let text = (0..MAX_INDEX_TERMS)
        .map(|n| format!("term{n:05}"))
        .collect::<Vec<_>>()
        .join(" ");
    let input = crate::capture::tests::request(1, &text);
    let later = crate::capture::tests::request(2, &text.replace("term", "later"));
    let first = native.append_event(input.clone()).expect("capture");
    native.append_event(later.clone()).expect("later capture");
    let progress = native
        .project_originals(&input.context, false, 256, &mut budget())
        .expect("a legal maximum-term original must be projectable");
    assert!(
        !progress.caught_up,
        "two full documents exceed one key batch"
    );
    assert_eq!(progress.through, first.workspace_commit);
    assert_eq!(progress.projected_sources, 1);
    let workspace = digest_bytes(input.context.request.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let document: IndexedOriginal = native
        .raw_value(
            &snapshot,
            &doc_key(&workspace, progress.generation, input.event.event_id),
        )
        .expect("document")
        .expect("indexed original");
    assert!(document.lexical_complete);
    assert_eq!(document.first_terms.len(), MAX_INDEX_TERMS);
    assert!(
        native
            .raw_value::<IndexedOriginal, _>(
                &snapshot,
                &doc_key(&workspace, progress.generation, later.event.event_id),
            )
            .expect("deferred document")
            .is_none()
    );
    let state: IndexState = native
        .raw_value(&snapshot, &state_key(&workspace))
        .expect("state")
        .expect("building generation");
    assert_eq!(state.building, Some(progress.generation));
    assert_eq!(state.active, None);
    drop(snapshot);
    native
        .verify_native(true)
        .expect("valid whole-source prefix");
    drop(native);

    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "large-raw",
        [7; 32],
        ledger,
        keys,
    )
    .expect("reopen after partial projection");
    let completed = native
        .project_originals(&input.context, false, 256, &mut budget())
        .expect("resume deferred original");
    assert!(completed.caught_up);
    assert_eq!(completed.generation, progress.generation);
    assert_eq!(completed.projected_sources, 2);
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let domain: PolicyDomain = native
        .raw_value(
            &snapshot,
            &domain_key(&workspace, progress.generation, &document.policy_domain),
        )
        .expect("domain")
        .expect("shared policy");
    assert_eq!(domain.first_commit, first.workspace_commit);
    for (input, term) in [(&input, "term16383"), (&later, "later16383")] {
        let document: IndexedOriginal = native
            .raw_value(
                &snapshot,
                &doc_key(&workspace, progress.generation, input.event.event_id),
            )
            .expect("document")
            .expect("complete original");
        assert!(document.lexical_complete);
        assert_eq!(document.first_terms.len(), MAX_INDEX_TERMS);
        assert_eq!(
            native
                .read_original(ReadOriginalRequest {
                    context: input.context.clone(),
                    event_id: input.event.event_id,
                    after_receipt: None,
                })
                .expect("unchanged original")
                .event,
            input.event
        );
        let page = native
            .recall_originals(RawRecallRequest {
                context: input.context.clone(),
                filter: RawFilter::default(),
                text: Some(RawTextQuery::AllTerms(term.into())),
                known_at: None,
                after_receipt: None,
                page_size: 1,
                budget: RawRecallBudget::default(),
                continuation: None,
            })
            .expect("last term remains routable");
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].source.event_id, input.event.event_id);
        assert_eq!(
            native
                .read_original_span(&input.context, &page.hits[0].matches[0])
                .expect("exact last term"),
            term.as_bytes()
        );
    }
    native
        .verify_native(true)
        .expect("complete encrypted generation");
    let head = native.engine.head_sequence().expect("head");
    assert!(
        native
            .project_originals(&input.context, false, 256, &mut budget())
            .expect("empty maintenance")
            .caught_up
    );
    assert_eq!(native.engine.head_sequence().expect("head"), head);
}
