//! Incremental publication, explicit migration and shared-budget atomicity.

use super::*;
use contextdb_service::CapturePort;
use std::time::Duration;

mod routing;

fn allowance(bytes: u64) -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        bytes,
        Duration::from_secs(30),
        Default::default(),
    )
}

#[test]
fn bm25_resumes_the_exact_profile_and_updates_statistics_without_double_counting() {
    let directory = tempfile::tempdir().expect("native directory");
    let path = directory.path().join("native");
    let native = NativeService::open(&path, "bm25-progress", [7; 32]).expect("native");
    let first = crate::capture::tests::request(1, "alpha alpha shared");
    let second = crate::capture::tests::request(2, "beta shared shared");
    let third = crate::capture::tests::request(3, "gamma shared");
    let accepted = native.append_event(first.clone()).expect("first source");
    native.append_event(second).expect("second source");
    let before = native.engine.head_sequence().expect("head");
    assert_eq!(
        native
            .project_originals_bm25(&first.context, false, 1, &mut allowance(0))
            .expect_err("metadata cannot bypass zero bytes")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(native.engine.head_sequence().expect("head"), before);
    let partial = native
        .project_originals_bm25(&first.context, false, 1, &mut allowance(128 * 1024 * 1024))
        .expect("whole first source");
    assert!(!partial.caught_up);
    assert_eq!(
        (partial.projected_sources, partial.through),
        (1, accepted.workspace_commit)
    );
    native
        .verify_native(true)
        .expect("partial accepted projection");
    drop(native);
    let native = NativeService::open(&path, "bm25-progress", [8; 32]).expect("cold native");
    // Ordinary resume preserves the declaration instead of silently returning
    // to the legacy scoring method.
    let complete = native
        .project_originals(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("ordinary resume retains BM25");
    assert!(complete.caught_up);
    assert_eq!(
        (complete.generation, complete.projected_sources),
        (partial.generation, 2)
    );
    native.append_event(third).expect("new accepted source");
    let complete = native
        .project_originals_bm25(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("incremental frequencies");
    assert_eq!(complete.projected_sources, 3);
    let workspace = digest_bytes(first.context.request.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let document: Bm25Document = native
        .raw_value(
            &snapshot,
            &document_key(&workspace, complete.generation, first.event.event_id),
        )
        .expect("document")
        .expect("first statistical document");
    let corpus: DomainStatistics = native
        .raw_value(
            &snapshot,
            &corpus_key(&workspace, complete.generation, &document.policy_domain),
        )
        .expect("corpus")
        .expect("corpus row");
    assert_eq!(
        (
            corpus.documents,
            corpus.total_tokens,
            corpus.omitted_documents
        ),
        (3, 8, 0)
    );
    let df: TermStatistics = native
        .raw_value(
            &snapshot,
            &df_key(
                &workspace,
                complete.generation,
                &document.policy_domain,
                "shared",
            ),
        )
        .expect("DF")
        .expect("shared term");
    assert_eq!(df.document_frequency, 3);
    drop(snapshot);
    // The maintenance publication itself advances the world journal; one more
    // prefix receipt may be needed, then an empty resume must become a no-op.
    native
        .project_originals_bm25(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("empty resume");
    let head = native.engine.head_sequence().expect("head");
    native
        .project_originals_bm25(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("stable empty resume");
    assert_eq!(native.engine.head_sequence().expect("head"), head);
    native
        .verify_native(true)
        .expect("accepted exact incremental statistics");
}

#[test]
fn legacy_generation_requires_an_explicit_bm25_rebuild() {
    let directory = tempfile::tempdir().expect("native directory");
    let native = NativeService::open(directory.path(), "bm25-migration", [7; 32]).expect("native");
    let input = crate::capture::tests::request(1, "explicit migration");
    native.append_event(input.clone()).expect("source");
    native
        .project_originals(&input.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("legacy generation");
    let before = native.engine.head_sequence().expect("head");
    assert_eq!(
        native
            .project_originals_bm25(&input.context, false, 64, &mut allowance(128 * 1024 * 1024))
            .expect_err("legacy generations cannot be reinterpreted")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(native.engine.head_sequence().expect("head"), before);
    let rebuilt = native
        .project_originals_bm25(&input.context, true, 64, &mut allowance(128 * 1024 * 1024))
        .expect("new declared generation");
    assert_eq!(rebuilt.generation, 2);
    native
        .verify_native(true)
        .expect("both generation methods retain their identity");
}

#[test]
fn bm25_row_omission_preserves_the_complete_legacy_lexical_document() {
    let directory = tempfile::tempdir().expect("native directory");
    let native = NativeService::open(directory.path(), "bm25-row-cap", [7; 32]).expect("native");
    let text = (0..MAX_INDEX_TERMS)
        .map(|n| format!("term{n:05}"))
        .collect::<Vec<_>>()
        .join(" ");
    let input = crate::capture::tests::request(1, &text);
    native
        .append_event(input.clone())
        .expect("full accepted original");
    let progress = native
        .project_originals_bm25(&input.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("one intrinsic row omission fits the atomic publication");
    assert!(progress.caught_up);
    let workspace = digest_bytes(input.context.request.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let raw: IndexedOriginal = native
        .raw_value(
            &snapshot,
            &doc_key(&workspace, progress.generation, input.event.event_id),
        )
        .expect("raw document")
        .expect("complete lexical projection");
    assert!(raw.lexical_complete);
    assert_eq!(raw.first_terms.len(), MAX_INDEX_TERMS);
    assert!(raw.first_terms.contains_key("term16383"));
    let document: Bm25Document = native
        .raw_value(
            &snapshot,
            &document_key(&workspace, progress.generation, input.event.event_id),
        )
        .expect("BM25 document")
        .expect("explicit omission");
    assert_eq!(document.omission, Some(Bm25Omission::RowLimit));
    assert_eq!(document.token_count, 0);
    assert!(document.term_frequencies.is_empty());
    let corpus: DomainStatistics = native
        .raw_value(
            &snapshot,
            &corpus_key(&workspace, progress.generation, &document.policy_domain),
        )
        .expect("corpus")
        .expect("zero corpus with explicit coverage gap");
    assert_eq!(
        (
            corpus.documents,
            corpus.total_tokens,
            corpus.omitted_documents
        ),
        (0, 0, 1)
    );
    drop(snapshot);
    native
        .verify_native(true)
        .expect("both projections reconstruct the same omission");
}

#[test]
fn a_missing_required_df_cannot_be_reinitialized_by_an_incremental_publication() {
    let directory = tempfile::tempdir().expect("native directory");
    let native =
        NativeService::open(directory.path(), "bm25-sparse-integrity", [7; 32]).expect("native");
    let first = crate::capture::tests::request(1, "shared shared");
    native.append_event(first.clone()).expect("first source");
    let progress = native
        .project_originals_bm25(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("first statistics");
    let workspace = digest_bytes(first.context.request.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let document: Bm25Document = native
        .raw_value(
            &snapshot,
            &document_key(&workspace, progress.generation, first.event.event_id),
        )
        .expect("document")
        .expect("statistics");
    let key = df_key(
        &workspace,
        progress.generation,
        &document.policy_domain,
        "shared",
    );
    let bytes = snapshot
        .get(&native.keyspaces.continuous, &key)
        .expect("DF read")
        .expect("required DF");
    drop(snapshot);
    native
        .append_event(crate::capture::tests::request(2, "shared"))
        .expect("new source");
    let mut tx = native.engine.begin_write().expect("fault transaction");
    tx.delete(&native.keyspaces.continuous, key.clone())
        .expect("remove required DF");
    tx.commit(Durability::Sync).expect("fault commit");
    let before = native.engine.head_sequence().expect("head");
    let error = native
        .project_originals_bm25(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect_err("missing prior DF cannot reset to one");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert!(
        error
            .message
            .contains("required previous document frequency is absent")
    );
    assert_eq!(native.engine.head_sequence().expect("head"), before);
    let mut tx = native.engine.begin_write().expect("repair transaction");
    tx.put(&native.keyspaces.continuous, key.clone(), bytes)
        .expect("restore exact DF");
    tx.commit(Durability::Sync).expect("repair commit");
    native
        .project_originals_bm25(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("resume original publication");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let df: TermStatistics = native
        .raw_value(&snapshot, &key)
        .expect("DF read")
        .expect("exact DF");
    assert_eq!(df.document_frequency, 2);
    native
        .verify_raw_index_records(&snapshot)
        .expect("accepted exact aggregate after repair");
}

#[test]
fn sparse_df_can_start_after_a_legitimate_nontext_lexical_route() {
    let directory = tempfile::tempdir().expect("native directory");
    let native =
        NativeService::open(directory.path(), "bm25-sparse-omission", [7; 32]).expect("native");
    let mut first = crate::capture::tests::request(1, "SparseBoundary7755");
    first.event.payload = EventPayload::InlineBytes {
        bytes: b"SparseBoundary7755".to_vec(),
        digest: ContentDigest::from_bytes(*blake3::hash(b"SparseBoundary7755").as_bytes()),
        media_type: "application/octet-stream".into(),
    };
    native
        .append_event(first.clone())
        .expect("accepted nontext original");
    native
        .project_originals_bm25(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("explicit omission");
    native
        .append_event(crate::capture::tests::request(2, "SparseBoundary7755"))
        .expect("eligible source");
    let progress = native
        .project_originals_bm25(&first.context, false, 64, &mut allowance(128 * 1024 * 1024))
        .expect("first eligible occurrence");
    let workspace = digest_bytes(first.context.request.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let document: Bm25Document = native
        .raw_value(
            &snapshot,
            &document_key(&workspace, progress.generation, first.event.event_id),
        )
        .expect("document")
        .expect("omission");
    assert_eq!(document.omission, Some(Bm25Omission::NonText));
    let df: TermStatistics = native
        .raw_value(
            &snapshot,
            &df_key(
                &workspace,
                progress.generation,
                &document.policy_domain,
                "sparseboundary7755",
            ),
        )
        .expect("DF read")
        .expect("first eligible frequency");
    assert_eq!(df.document_frequency, 1);
    drop(snapshot);
    native
        .verify_native(true)
        .expect("valid sparse statistics and preserved original");
}
