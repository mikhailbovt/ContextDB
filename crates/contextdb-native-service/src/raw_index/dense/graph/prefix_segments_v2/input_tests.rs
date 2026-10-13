//! Accepted capture ranges over real encrypted prefixes; no retrieval-quality claim.

use super::super::super::prefix_v2::inputs::tests::{Fixture, budget, fixture, read_generation};
use super::super::super::prefix_v2::types::DensePrefixBaseRequestV2;
use super::super::proof::VerifiedPrefixSegmentInterval;
use super::super::types::CaptureBoundaryRefV2;
use super::*;
use contextdb_core::EventPayload;
use contextdb_recall::QueryCancellation;
use contextdb_service::{CapturePort, ErrorCode};
use contextdb_storage::{
    Durability, Entry, Keyspace, ScanPage, ScanPageRequest, SnapshotSelector, StorageEngine,
    StorageSequence, WriteTransaction,
};
use std::{cell::Cell, time::Duration};

fn base(
    f: &Fixture,
    target: &crate::raw_index::dense::DenseProjectionReceipt,
    parent: &mut QueryBudget,
) -> PrefixSegmentBaseRefV2 {
    let receipt = f
        .native
        .publish_original_span_prefix_base(
            &f.context,
            &DensePrefixBaseRequestV2 {
                generation: target.generation,
                target: target.clone(),
            },
            parent,
        )
        .expect("actual accepted prefix base");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual base snapshot");
    PrefixSegmentBaseRefV2 {
        publication: f
            .native
            .prefix_publication_ref(&snapshot, receipt.global_commit, parent)
            .expect("actual accepted base event reference"),
        receipt_digest: ContentDigest::from_bytes(
            *blake3::hash(&crate::encode(&receipt).expect("actual base receipt bytes")).as_bytes(),
        ),
        content_digest: receipt.manifest.content_digest,
    }
}

fn first_start(
    f: &Fixture,
    before: &crate::raw_index::dense::DenseProjectionReceipt,
    parent: &mut QueryBudget,
) -> CaptureBoundaryRefV2 {
    let workspace = crate::digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before snapshot");
    let reference = f
        .native
        .prefix_publication_ref(&snapshot, before.global_commit, parent)
        .expect("actual before dense acceptance");
    let target = f
        .native
        .verify_accepted_prefix_dense_target(&snapshot, &workspace, &reference, parent)
        .expect("actual bounded base census");
    f.native
        .first_prefix_segment_capture_boundary(&snapshot, &workspace, &target, parent)
        .expect("native accepted capture start")
        .reference()
        .clone()
}

fn interval(
    f: &Fixture,
    before: &crate::raw_index::dense::DenseProjectionReceipt,
    after: &crate::raw_index::dense::DenseProjectionReceipt,
    start: &CaptureBoundaryRefV2,
    parent: &mut QueryBudget,
) -> ServiceResult<VerifiedPrefixSegmentInterval> {
    let workspace = crate::digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(crate::storage_error)?;
    let before_ref = f
        .native
        .prefix_publication_ref(&snapshot, before.global_commit, parent)?;
    let after_ref = f
        .native
        .prefix_publication_ref(&snapshot, after.global_commit, parent)?;
    let before =
        f.native
            .verify_prefix_segment_dense_state(&snapshot, &workspace, &before_ref, parent)?;
    let after = f
        .native
        .verify_prefix_segment_dense_state(&snapshot, &workspace, &after_ref, parent)?;
    let start = f
        .native
        .verify_prefix_segment_capture_boundary(&snapshot, &workspace, start, parent)?;
    f.native
        .verify_prefix_segment_interval(&snapshot, &workspace, before, after, start, parent)
}

fn input(
    f: &Fixture,
    admission: &Generation,
    base: &PrefixSegmentBaseRefV2,
    proof: &VerifiedPrefixSegmentInterval,
    parent: &mut QueryBudget,
) -> ServiceResult<PrefixSegmentBuildInput> {
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(crate::storage_error)?;
    f.native.prefix_segment_build_input(
        &snapshot,
        Some(&f.context),
        &crate::digest_bytes(f.context.request.workspace_id.as_bytes()),
        admission,
        base,
        proof,
        parent,
    )
}

fn append_binary(f: &Fixture, sequence: u64) {
    let mut request = crate::capture::tests::request(sequence, "binary placeholder");
    request.context = f.context.clone();
    let bytes = vec![0xff, 0, 0xfe];
    request.event.payload = EventPayload::InlineBytes {
        digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
        bytes,
        media_type: "application/octet-stream".into(),
    };
    request.event.source_version = Some(format!("prefix-segment-binary-{sequence}"));
    f.native
        .append_event(request)
        .expect("real accepted independent binary source");
}

fn catch_up_raw(f: &Fixture, parent: &mut QueryBudget) {
    for _ in 0..4 {
        if f.native
            .project_originals_bm25(&f.context, false, 64, parent)
            .expect("bounded actual raw batch")
            .caught_up
        {
            return;
        }
    }
    panic!("fixture raw catch-up bound");
}

#[test]
fn pre_recorded_capture_before_both_publications_enters_actual_interval() {
    let f = fixture();
    let mut parent = budget();
    let base = base(&f, &f.target, &mut parent);
    let start = first_start(&f, &f.target, &mut parent);
    let after = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("advance the real pre-recorded source3");
    let proof = interval(&f, &f.target, &after, &start, &mut parent)
        .expect("complete actual capture range");
    assert_eq!(proof.work().len(), 1);
    assert_eq!(proof.work()[0].event_id, f.sources[2]);
    assert!(proof.end().reference().global_commit < f.target.global_commit);
    assert!(
        proof.end().reference().global_commit < base.publication.global_commit,
        "starting at either publication would lose the actual backlog capture"
    );
    let admission = read_generation(&f.native, &f.context, &mut parent);
    let actual =
        input(&f, &admission, &base, &proof, &mut parent).expect("complete whole source replay");
    assert_eq!(actual.interval.work_items, 1);
    assert_eq!(actual.documents.len(), 1);
    assert_eq!(actual.inputs.len(), 1);
    assert_eq!(actual.inputs[0].vector.source.event_id, f.sources[2]);
    assert_eq!(
        actual.inputs[0].vector.source.source_version.as_deref(),
        Some("prefix-v2-actual-source-3")
    );
    assert_eq!(
        read_generation(&f.native, &f.context, &mut parent),
        admission
    );
}

#[test]
fn two_real_omission_intervals_accept_total_history_greater_than_128() {
    let f = fixture();
    for sequence in 4..=132 {
        append_binary(&f, sequence);
    }
    let mut parent = budget();
    catch_up_raw(&f, &mut parent);
    let before = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("actual bounded base target within full132 raw history");
    assert_eq!(before.sources, 66);
    assert_eq!(before.raw_sources, 132);
    let base = base(&f, &before, &mut parent);
    let start = first_start(&f, &before, &mut parent);
    let after = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("actual first64-work interval");
    assert_eq!(after.sources, 130);
    let first = interval(&f, &before, &after, &start, &mut parent)
        .expect("state point proof has no total-history128 restriction");
    assert_eq!(first.work().len(), 64);
    let admission = read_generation(&f.native, &f.context, &mut parent);
    let actual =
        input(&f, &admission, &base, &first, &mut parent).expect("actual omission-only interval");
    assert_eq!(actual.interval.work_items, 64);
    assert_eq!(actual.documents.len(), 64);
    assert!(actual.inputs.is_empty());
    assert!(
        actual
            .documents
            .iter()
            .all(|d| d.omission == Some(crate::raw_index::dense::DenseOmission::NonText))
    );
    let ending = first.end().reference().clone();
    let final_target = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("actual final two pre-recorded sources");
    assert!(final_target.caught_up);
    assert_eq!(final_target.sources, 132);
    let second = interval(&f, &after, &final_target, &ending, &mut parent)
        .expect("second complete capture interval");
    assert_eq!(second.work().len(), 2);
    let actual = input(
        &f,
        &read_generation(&f.native, &f.context, &mut parent),
        &base,
        &second,
        &mut parent,
    )
    .expect("whole second zero-node interval");
    assert_eq!(actual.interval.work_items, 2);
    assert_eq!(actual.documents.len(), 2);
    assert!(actual.inputs.is_empty());
}

#[test]
fn exact128_interval_with_gap_survives_future_work_and129_interval_refuses() {
    let f = fixture();
    let mut parent = budget();
    let base = base(&f, &f.target, &mut parent);
    let start = first_start(&f, &f.target, &mut parent);
    for sequence in 4..=130 {
        append_binary(&f, sequence);
    }
    catch_up_raw(&f, &mut parent);
    let partial = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("first dense batch");
    assert!(!partial.caught_up);
    let after = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("genuine after130 target");
    assert!(after.caught_up);
    assert_eq!(after.sources, 130);
    let first =
        interval(&f, &f.target, &after, &start, &mut parent).expect("exact128 complete interval");
    assert_eq!(first.work().len(), 128);
    assert!(
        first.end().reference().work.workspace_commit < after.through,
        "real raw-maintenance frames form the terminal non-capture gap"
    );
    let admission = read_generation(&f.native, &f.context, &mut parent);
    let before = input(&f, &admission, &base, &first, &mut parent).expect("real128 input");
    assert_eq!(before.interval.work_items, 128);
    assert_eq!(before.inputs.len(), 1);
    append_binary(&f, 131);
    catch_up_raw(&f, &mut parent);
    let future = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("real future dense progress");
    assert_eq!(future.sources, 131);
    let historical = interval(&f, &f.target, &after, &start, &mut parent)
        .expect("historical range ends at actual old dense event");
    let workspace = crate::digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("advanced snapshot");
    let actual = f
        .native
        .prefix_segment_build_input(
            &snapshot,
            None,
            &workspace,
            &admission,
            &base,
            &historical,
            &mut parent,
        )
        .expect("historical128 with future outbox work");
    assert_eq!(actual.interval, before.interval);
    assert_eq!(actual.documents, before.documents);
    assert_eq!(actual.inputs.len(), before.inputs.len());
    let error = interval(&f, &f.target, &future, &start, &mut parent)
        .err()
        .expect("129 accepted interval cannot be shortened");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(error.message.contains("exceeds 128"));
}

#[test]
fn accepted_work_missing_after_census_refuses_before_any_removal_outcome() {
    let f = fixture();
    let mut parent = budget();
    let base = base(&f, &f.target, &mut parent);
    let start = first_start(&f, &f.target, &mut parent);
    let after = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("after3");
    let proof = interval(&f, &f.target, &after, &start, &mut parent)
        .expect("complete accepted work census");
    let admission = read_generation(&f.native, &f.context, &mut parent);
    let workspace = crate::digest_bytes(f.context.request.workspace_id.as_bytes());
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("actual controlled row fault");
    tx.delete(
        &f.native.keyspaces.continuous,
        crate::capture::work_key(&workspace, proof.work()[0].workspace_commit),
    )
    .expect("delete exact work");
    tx.commit(Durability::Sync).expect("fault publication");
    let error = input(&f, &admission, &base, &proof, &mut parent)
        .err()
        .expect("no shorter result");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert!(error.message.contains("accepted outbox work"));
}

struct Watched<'a, S> {
    inner: &'a S,
    body_space: Keyspace,
    source_prefixes: Vec<Vec<u8>>,
    body_reads: Cell<usize>,
    source_reads: Cell<usize>,
}
impl<S: ReadSnapshot> Watched<'_, S> {
    fn observe(&self, space: &Keyspace, key: &[u8]) {
        if space == &self.body_space {
            self.body_reads.set(self.body_reads.get() + 1);
        }
        if self.source_prefixes.iter().any(|p| key.starts_with(p)) {
            self.source_reads.set(self.source_reads.get() + 1);
        }
    }
}
impl<S: ReadSnapshot> ReadSnapshot for Watched<'_, S> {
    fn sequence(&self) -> StorageSequence {
        self.inner.sequence()
    }
    fn get(&self, space: &Keyspace, key: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
        self.observe(space, key);
        self.inner.get(space, key)
    }
    fn scan_prefix(&self, _: &Keyspace, _: &[u8]) -> contextdb_storage::Result<Vec<Entry>> {
        panic!("input proof must not perform an unbounded corpus scan")
    }
    fn scan_prefix_page(
        &self,
        space: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> contextdb_storage::Result<ScanPage> {
        self.observe(space, request.prefix);
        self.inner.scan_prefix_page(space, request)
    }
}

#[test]
fn current_denial_and_parent_limits_precede_source_materialization_and_body_reads() {
    let f = fixture();
    let mut parent = budget();
    let base = base(&f, &f.target, &mut parent);
    let start = first_start(&f, &f.target, &mut parent);
    let after = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
        .expect("after3");
    let proof =
        interval(&f, &f.target, &after, &start, &mut parent).expect("accepted actual interval");
    let admission = read_generation(&f.native, &f.context, &mut parent);
    let workspace = crate::digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual snapshot");
    let prefix = crate::raw_index::generation_prefix(&workspace, admission.number);
    let watched = Watched {
        inner: &snapshot,
        body_space: f.native.keyspaces.observations_content.clone(),
        source_prefixes: ["doc/", "dense/document/", "dense/vector/"]
            .into_iter()
            .map(|suffix| format!("{prefix}{suffix}").into_bytes())
            .collect(),
        body_reads: Cell::new(0),
        source_reads: Cell::new(0),
    };
    f.native
        .verify_prefix_segment_capture_boundary(&watched, &workspace, &start, &mut parent)
        .expect("capture boundary is actually body-free");
    assert_eq!(watched.body_reads.get(), 0);
    let mut denied = f.context.clone();
    denied.request.scopes.clear();
    let error = f
        .native
        .prefix_segment_build_input(
            &watched,
            Some(&denied),
            &workspace,
            &admission,
            &base,
            &proof,
            &mut parent,
        )
        .err()
        .expect("current admission refusal");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(watched.source_reads.get(), 0);
    assert_eq!(watched.body_reads.get(), 0);
    for (work, bytes, duration, cancelled, message) in [
        (0, 1024, Duration::from_secs(1), false, "work budget"),
        (100, 0, Duration::from_secs(1), false, "byte budget"),
        (100, 1024, Duration::ZERO, false, "deadline"),
        (100, 1024, Duration::from_secs(1), true, "cancel"),
    ] {
        let cancellation = QueryCancellation::default();
        let mut tiny = QueryBudget::new(work, bytes, duration, cancellation.clone());
        if cancelled {
            cancellation.cancel();
        }
        let error = f
            .native
            .prefix_segment_build_input(
                &watched,
                Some(&f.context),
                &workspace,
                &admission,
                &base,
                &proof,
                &mut tiny,
            )
            .err()
            .expect("same-parent refusal");
        assert_eq!(error.code, ErrorCode::BudgetExhausted);
        assert!(
            error.message.contains(message),
            "typed refusal: {}",
            error.message
        );
        assert_eq!(watched.source_reads.get(), 0);
    }
}

#[test]
fn capture_boundary_needs_actual_capture_primary_key_not_journal_request_digest() {
    let f = fixture();
    let mut parent = budget();
    let start = first_start(&f, &f.target, &mut parent);
    let (actual_key, guessed_key, actual_retry) = {
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("control snapshot");
        // Exact existing capture-control namespace, used only for this fault.
        let record_key = format!("receipt/{}", start.work.event_id).into_bytes();
        let bytes = snapshot
            .get(&f.native.keyspaces.continuous, &record_key)
            .expect("actual record read")
            .expect("actual record");
        let record: serde_json::Value =
            serde_json::from_slice(&bytes).expect("actual bounded control fields");
        let actual_key = record["idempotency_digest"]
            .as_str()
            .expect("actual capture retry identity")
            .as_bytes()
            .to_vec();
        let event: crate::StoredEvent = decode(
            &snapshot
                .get(
                    &f.native.keyspaces.events,
                    &start.global_commit.to_be_bytes(),
                )
                .expect("actual event read")
                .expect("actual event"),
            "capture event",
        )
        .expect("actual capture event");
        let guessed_key = event.request_digest.into_bytes();
        assert_ne!(actual_key, guessed_key);
        let actual_retry = snapshot
            .get(&f.native.keyspaces.idempotency, &actual_key)
            .expect("actual primary read")
            .expect("actual primary receipt");
        (actual_key, guessed_key, actual_retry)
    };
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("controlled primary identity fault");
    tx.put(&f.native.keyspaces.idempotency, guessed_key, actual_retry)
        .expect("leave a valid receipt at the guessed key");
    tx.delete(&f.native.keyspaces.idempotency, actual_key)
        .expect("remove only real capture primary");
    tx.commit(Durability::Sync).expect("publish primary fault");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("faulted snapshot");
    let error = f
        .native
        .verify_prefix_segment_capture_boundary(
            &snapshot,
            &crate::digest_bytes(f.context.request.workspace_id.as_bytes()),
            &start,
            &mut parent,
        )
        .err()
        .expect("guessed journal key cannot replace actual capture acceptance");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert!(error.message.contains("primary receipt is absent"));
}
