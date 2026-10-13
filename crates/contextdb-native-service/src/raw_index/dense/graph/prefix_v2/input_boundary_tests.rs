//! Real removal and historical-cutoff contracts; no fabricated prefix or work.

use super::*;
use crate::raw_index::dense::graph::prefix_v2::types;
use contextdb_core::EventPayload;
use std::collections::BTreeSet;

#[test]
fn prepared_removal_blocks_new_dense_prefix_until_completion_is_available() {
    let f = fixture();
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let removed = f.sources[1];
    let mut parent = budget();
    let roots = BTreeSet::from([removed]);
    let request = f
        .native
        .request_original_removal(
            &f.context,
            &roots,
            "prefix-v2-real-prepared-removal",
            &mut parent,
        )
        .expect("retained real original removal request");
    let prepared = f
        .native
        .prepare_original_removal_sources(&f.context, &request, &roots, &mut parent)
        .expect("accepted real source preparation");
    f.native
        .maintain_custody(&f.context, 64, &mut parent)
        .expect("current custody after actual source revocation");
    let raw = f
        .native
        .project_originals_bm25(&f.context, true, 64, &mut parent)
        .expect("genuine new raw generation excludes prepared original");
    assert!(raw.caught_up);
    assert_eq!(raw.projected_sources, 2);
    let generation = {
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("actual prepared target snapshot");
        let generation = generation_at(&f.native, &snapshot, &workspace, &mut parent)
            .expect("genuine raw admission after preparation");
        assert!(
            generation
                .removal_through
                .is_some_and(|n| n >= prepared.workspace_commit)
        );
        assert!(
            f.native
                .source_prepared_at(
                    &snapshot,
                    &workspace,
                    removed,
                    generation.removal_through,
                    &mut parent
                )
                .expect("accepted prepared-source outcome")
        );
        assert_eq!(generation.number, raw.generation);
        assert_eq!(generation.projected_sources, 2);
        assert!(generation.dense.is_none());
        assert!(generation.dense_prefix_base.is_none());
        let removed_document: Option<IndexedOriginal> = f
            .native
            .graph_read(
                &snapshot,
                &f.native.keyspaces.continuous,
                &doc_key(&workspace, generation.number, removed),
                &mut parent,
            )
            .expect("actual rebuilt raw source metadata");
        assert!(
            removed_document.is_none(),
            "prepared original is absent from the real raw generation"
        );
        generation
    };
    // The current retention protocol has no completion publication that can
    // reopen disclosure. Raw cleanup is legal, but it cannot authorize neural
    // processing or supply a genuine dense target containing a removal outcome.
    // A missing prepared-work input E2E remains pending that actual protocol.
    let head = f
        .native
        .engine
        .head_sequence()
        .expect("native head before refused projection");
    let error = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect_err("prepared removal still closes ModelProcessing for this workspace");
    assert_eq!(error.code, ErrorCode::IndexTooStale);
    assert!(
        error
            .message
            .contains("current retention removal must finish before disclosure")
    );
    assert_eq!(
        f.native
            .engine
            .head_sequence()
            .expect("native head after refused projection"),
        head
    );
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current snapshot after the real completion-gate refusal");
    let unchanged = generation_at(&f.native, &snapshot, &workspace, &mut parent)
        .expect("genuine raw admission after refused neural processing");
    assert_eq!(unchanged, generation);
    let prefix =
        types::prefix_key(&workspace, generation.number).expect("canonical prefix-v2 namespace");
    let page = snapshot
        .scan_prefix_page(
            &f.native.keyspaces.continuous,
            ScanPageRequest {
                prefix: &prefix,
                start_after: None,
                max_entries: 1,
                max_bytes: ROW_BYTES + 2048,
            },
        )
        .expect("bounded actual prefix-row absence check");
    assert!(
        page.entries.is_empty() && page.continuation.is_none(),
        "refusal creates neither a dense target nor accepted prefix-base rows"
    );
}

fn binary_original(f: &Fixture, sequence: u64) -> contextdb_service::CaptureRequest {
    let mut request = crate::capture::tests::request(sequence, "binary placeholder");
    request.context = f.context.clone();
    let bytes = vec![0xff, 0, 0xfe];
    request.event.payload = EventPayload::InlineBytes {
        digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
        bytes,
        media_type: "application/octet-stream".into(),
    };
    request.event.source_version = Some(format!("prefix-boundary-binary-{sequence}"));
    request
}

#[test]
fn exact_128_work_prefix_with_noncapture_gap_replays_after_future_dense_progress() {
    let f = fixture();
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let mut last_capture_commit = 0;
    for sequence in 4..=128 {
        last_capture_commit = f
            .native
            .append_event(binary_original(&f, sequence))
            .expect("real independent binary capture with explicit dense omission")
            .workspace_commit;
    }
    let mut parent = budget();
    let first_raw = f
        .native
        .project_originals_bm25(&f.context, false, 64, &mut parent)
        .expect("first actual bounded raw advance");
    assert!(!first_raw.caught_up);
    let full_raw = f
        .native
        .project_originals_bm25(&f.context, false, 64, &mut parent)
        .expect("second bounded raw advance includes the non-capture journal gap");
    assert!(full_raw.caught_up);
    assert_eq!(full_raw.projected_sources, 128);
    assert!(
        full_raw.through > last_capture_commit,
        "the first raw projection itself is a genuine non-capture gap after work128"
    );
    let first_dense = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("bounded dense advance from the existing two-source prefix");
    assert!(!first_dense.caught_up);
    let receipt = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("real caught-up 128-work dense target");
    assert!(receipt.caught_up);
    assert_eq!(receipt.sources, 128);
    assert_eq!(receipt.raw_sources, 128);
    assert_eq!(receipt.through, full_raw.through);
    assert_eq!(receipt.spans, 2);
    let (admission, reference, before) = {
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("exact 128-work target snapshot");
        let admission = generation_at(&f.native, &snapshot, &workspace, &mut parent)
            .expect("saved authentic full raw admission");
        let target = f
            .native
            .verify_current_prefix_dense_target(
                &snapshot,
                &workspace,
                &admission,
                &receipt,
                &mut parent,
            )
            .expect("real signed 128-work census");
        assert_eq!(target.work().len(), 128);
        assert!(
            target.work().last().expect("work128").workspace_commit < target.manifest().through,
            "historical cutoff ends after real non-capture work"
        );
        let before = f
            .native
            .prefix_build_input(
                &snapshot,
                None,
                &workspace,
                &admission,
                &target,
                &mut parent,
            )
            .expect("complete genuine 128-work input");
        assert_eq!(before.interval.work_items, 128);
        assert_eq!(before.documents.len(), 128);
        (admission, target.reference().clone(), before)
    };
    let future_request = binary_original(&f, 129);
    let future_id = future_request.event.event_id;
    let future = f
        .native
        .append_event(future_request)
        .expect("actual future accepted work129");
    assert!(future.workspace_commit > receipt.through);
    let raw = f
        .native
        .project_originals_bm25(&f.context, false, 64, &mut parent)
        .expect("genuine raw metadata advances beyond the saved admission");
    assert!(raw.caught_up);
    assert_eq!(raw.projected_sources, 129);
    let advanced = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("real future dense progress does not alter the historical target");
    assert!(advanced.caught_up);
    assert_eq!(advanced.sources, 129);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("advanced real history snapshot");
    let target = f
        .native
        .verify_accepted_prefix_dense_target(&snapshot, &workspace, &reference, &mut parent)
        .expect("remint historical target only from retained native acceptance");
    assert_eq!(target.receipt(), &receipt);
    assert_eq!(target.work().len(), 128);
    assert!(target.work().iter().all(|work| work.event_id != future_id));
    let after = f
        .native
        .prefix_build_input(
            &snapshot,
            None,
            &workspace,
            &admission,
            &target,
            &mut parent,
        )
        .expect("historical 128 prefix with future outbox continuation");
    assert_eq!(after.interval, before.interval);
    assert_eq!(after.documents, before.documents);
    assert_eq!(after.inputs.len(), before.inputs.len());
    assert!(
        after
            .documents
            .iter()
            .all(|document| document.source.event_id != future_id)
    );
    assert!(
        after
            .inputs
            .iter()
            .all(|input| input.vector.source.event_id != future_id)
    );
    let current = generation_at(&f.native, &snapshot, &workspace, &mut parent)
        .expect("actual advancing generation remains untouched");
    assert_eq!(current.projected_sources, 129);
    assert_eq!(
        current.dense.expect("current actual dense prefix").sources,
        129
    );
    assert_eq!(
        admission.projected_sources, 128,
        "historical reconstruction used saved genuine metadata, never fabricated counters"
    );
}
