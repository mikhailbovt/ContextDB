//! Actual encrypted owner publications. Constant vectors prove no retrieval quality.

use super::*;
mod gc;
mod lag;
use contextdb_core::EventPayload;
use contextdb_service::{CapturePort, TextEmbeddingAdapter};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Debug)]
struct Encoder {
    profile: TextEmbeddingProfile,
    forwards: AtomicUsize,
}
impl TextEmbeddingAdapter for Encoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.profile
    }

    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        parent
            .charge(
                1,
                self.profile.dimensions as u64 * 4 + text.len() as u64 * 4 + 8192,
            )
            .map_err(budget_error)?;
        let mut values = vec![0_f32; self.profile.dimensions as usize];
        values[0] = 1.;
        let mut hash = blake3::Hasher::new();
        for value in &values {
            hash.update(&value.to_le_bytes());
        }
        self.forwards.fetch_add(1, Ordering::SeqCst);
        Ok(EmbeddedText {
            profile_digest: self.profile.digest()?,
            kind,
            text_digest: digest(text.as_bytes()),
            input_digest: digest(self.profile.input_text(kind, text)?.as_bytes()),
            tokens_digest: digest(b"explicit segment fixture tokens"),
            token_count: 7,
            values,
            vector_digest: ContentDigest::from_bytes(*hash.finalize().as_bytes()),
        })
    }
}

struct Fixture {
    native: NativeService,
    context: AuthenticatedRequestContext,
    source: ObservationId,
    root: tempfile::TempDir,
    ledger: Arc<crate::NativeSuppressionLedger>,
    keys: Arc<crate::NativeCustodyKeys>,
    _ledger: tempfile::TempDir,
    _keys: tempfile::TempDir,
    encoder: Encoder,
    base: DenseGraphReceipt,
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        5_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}

fn project(f: &Fixture) -> DenseProjectionReceipt {
    let mut parent = budget();
    let mut raw_complete = false;
    for _ in 0..4 {
        if f.native
            .project_originals_bm25(&f.context, false, 64, &mut parent)
            .expect("bounded raw source batch")
            .caught_up
        {
            raw_complete = true;
            break;
        }
    }
    assert!(raw_complete, "explicit fixture maintenance batch bound");
    for _ in 0..4 {
        let receipt = f
            .native
            .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
            .expect("bounded complete dense source batch");
        if receipt.caught_up {
            return receipt;
        }
    }
    panic!("explicit fixture dense batch bound");
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("segment encrypted directory");
    let (ld, ledger) = crate::suppression::tests::authority("span-ann-segment-fixture");
    let (kd, keys) = crate::encryption::tests::authority("span-ann-segment-fixture");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "span-ann-segment-fixture",
        [31; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted native owner");
    let mut first = crate::capture::tests::request(1, "first independently captured base original");
    first
        .context
        .capability_grants
        .insert(Capability::ModelProcessing);
    first.event.source_version = Some("original-version-one".into());
    let source = first.event.event_id;
    native
        .append_event(first.clone())
        .expect("first base original");
    let mut second =
        crate::capture::tests::request(2, "second independently captured base original");
    second.event.source_version = Some("original-version-two".into());
    native.append_event(second).expect("second base original");
    let context = first.context;
    let encoder = Encoder {
        profile: TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(
            b"segment controlled backend",
        )),
        forwards: AtomicUsize::new(0),
    };
    native
        .project_originals_bm25(&context, false, 64, &mut budget())
        .expect("base raw projection");
    native
        .project_original_spans(&context, &encoder, 64, &mut budget())
        .expect("base exact vectors");
    let base = native
        .publish_original_span_graph(&context, &mut budget())
        .expect("accepted immutable base");
    assert_eq!(base.manifest.dense.sources, 2);
    Fixture {
        native,
        context,
        source,
        root,
        ledger,
        keys,
        _ledger: ld,
        _keys: kd,
        encoder,
        base,
    }
}

fn generation(native: &NativeService, context: &AuthenticatedRequestContext) -> Generation {
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current source snapshot");
    native
        .graph_read(
            &snapshot,
            &native.keyspaces.continuous,
            &generation_key(&digest_bytes(context.request.workspace_id.as_bytes()), 1),
            &mut budget(),
        )
        .expect("bounded current generation")
        .expect("actual generation")
}

fn seal_request(f: &Fixture, target: DenseProjectionReceipt) -> SealRequest {
    let previous = f
        .native
        .original_span_segment_head(&f.context, 1, &mut budget())
        .expect("actual accepted operator resume point");
    assert_eq!(previous, generation(&f.native, &f.context).dense_segments);
    SealRequest {
        generation: 1,
        previous,
        target,
    }
}

fn small_binary(sequence: u64) -> contextdb_service::CaptureRequest {
    let mut request = crate::capture::tests::request(sequence, "binary placeholder");
    let bytes = vec![0xff, 0, 0xfe];
    request.event.payload = EventPayload::InlineBytes {
        digest: digest(&bytes),
        bytes,
        media_type: "application/octet-stream".into(),
    };
    request.event.source_version = Some(format!("binary-original-{sequence}"));
    request
}

fn latest_global(native: &NativeService) -> u64 {
    native
        .global_head(
            &native
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("head snapshot"),
        )
        .expect("actual global head")
}

fn assert_base_unchanged(native: &NativeService, base: &DenseGraphReceipt) {
    let workspace = digest_bytes(base.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("base snapshot");
    let retained: DenseGraphReceipt = native
        .graph_read(
            &snapshot,
            &native.keyspaces.continuous,
            &receipt_key(&workspace, 1),
            &mut budget(),
        )
        .expect("bounded base receipt")
        .expect("retained original base");
    assert_eq!(
        &retained, base,
        "delta publication never replaces the accepted base"
    );
}

#[test]
fn encrypted_repeated_segments_retry_never_rewinds_and_cold_omissions_verify() {
    let f = fixture();
    let mut third = crate::capture::tests::request(
        3,
        &"whole multispan original 原文 🙂 boundary ".repeat(150),
    );
    third.event.source_version = Some("actual-multispan-version".into());
    f.native
        .append_event(third)
        .expect("complete multispan source");
    f.native
        .append_event(crate::capture::tests::request(
            4,
            "another independently captured delta source",
        ))
        .expect("second whole delta source");
    let first_request = seal_request(&f, project(&f));
    let first = f
        .native
        .seal_original_span_segment(&f.context, &first_request, &mut budget())
        .expect("first accepted immutable delta");
    assert_eq!(first.delta.manifest.ordinal, 1);
    assert_eq!(first.delta.manifest.work_items, 2);
    assert!(
        first.delta.manifest.nodes > 2,
        "whole multispan source is retained"
    );
    assert_eq!(
        first.delta.manifest.after.sources - first.delta.manifest.before.sources,
        2
    );
    assert_eq!(first.delta.manifest.before, f.base.manifest.dense);
    assert_eq!(first.directory.head.covered, first.delta.manifest.after);
    assert_base_unchanged(&f.native, &f.base);

    f.native
        .append_event(crate::capture::tests::request(
            5,
            "new actual source after the first sealed interval",
        ))
        .expect("second interval source");
    let second_request = seal_request(&f, project(&f));
    let second = f
        .native
        .seal_original_span_segment(&f.context, &second_request, &mut budget())
        .expect("second accepted immutable delta");
    assert_eq!(second.delta.manifest.ordinal, 2);
    assert_eq!(second.delta.manifest.before, first.directory.head.covered);
    assert_eq!(second.directory.head.previous, second_request.previous);
    let head_two = generation(&f.native, &f.context).dense_segments;
    let position_two = latest_global(&f.native);
    let forwards_two = f.encoder.forwards.load(Ordering::SeqCst);
    assert_eq!(
        f.native
            .seal_original_span_segment(&f.context, &first_request, &mut budget())
            .expect("exact historical accepted retry"),
        first
    );
    assert_eq!(generation(&f.native, &f.context).dense_segments, head_two);
    assert_eq!(
        latest_global(&f.native),
        position_two,
        "retry appends no journal frame"
    );
    assert_eq!(
        f.encoder.forwards.load(Ordering::SeqCst),
        forwards_two,
        "sealing performs no encoder forward"
    );

    f.native
        .append_event(small_binary(6))
        .expect("actual nontext original");
    let omitted_request = seal_request(&f, project(&f));
    let omitted = f
        .native
        .seal_original_span_segment(&f.context, &omitted_request, &mut budget())
        .expect("complete coverage-only delta over nonempty base");
    assert_eq!(omitted.delta.manifest.ordinal, 3);
    assert_eq!(omitted.delta.manifest.work_items, 1);
    assert_eq!(omitted.delta.manifest.nodes, 0);
    assert!(omitted.delta.manifest.cohorts.is_empty());
    assert_eq!(
        omitted.delta.manifest.after.spans,
        omitted.delta.manifest.before.spans
    );
    assert_eq!(
        omitted.delta.manifest.after.omitted_sources,
        omitted.delta.manifest.before.omitted_sources + 1
    );
    assert_eq!(
        f.encoder.forwards.load(Ordering::SeqCst),
        forwards_two,
        "omission has no invented embedding"
    );
    let head_three = generation(&f.native, &f.context).dense_segments;
    f.native
        .verify_native(true)
        .expect("actual accepted append/head/row closure");
    assert_base_unchanged(&f.native, &f.base);
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        "span-ann-segment-fixture",
        [31; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold same-key encrypted owner");
    assert_eq!(
        cold.seal_original_span_segment(&f.context, &first_request, &mut budget())
            .expect("cold exact retained retry"),
        first
    );
    assert_eq!(generation(&cold, &f.context).dense_segments, head_three);
    cold.verify_native(true)
        .expect("cold deep accepted segment closure");
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cold raw verifier snapshot");
    cold.verify_raw_index_records(&snapshot)
        .expect("cold raw base/delta topology and prefix reconstruction");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    assert_eq!(
        cold.accepted_segment_for_ordinal(&snapshot, &workspace, 1, 2, &mut budget())
            .expect("retained second ordinal"),
        second
    );
    assert_eq!(
        cold.accepted_segment_for_ordinal(&snapshot, &workspace, 1, 3, &mut budget())
            .expect("retained coverage-only ordinal"),
        omitted
    );
}

#[test]
fn changed_current_authorization_refuses_a_new_seal_before_any_publication() {
    let f = fixture();
    f.native
        .append_event(crate::capture::tests::request(
            3,
            "current candidate before revocation",
        ))
        .expect("new source");
    let request = seal_request(&f, project(&f));
    f.native
        .revoke_original(
            &f.context,
            f.source,
            "segment-current-epoch-revoke",
            &mut budget(),
        )
        .expect("real current authorization epoch advance");
    let generation_before = generation(&f.native, &f.context);
    let position = latest_global(&f.native);
    let forwards = f.encoder.forwards.load(Ordering::SeqCst);
    assert_eq!(
        f.native
            .seal_original_span_segment(&f.context, &request, &mut budget())
            .expect_err("stale current membership cannot append")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(generation(&f.native, &f.context), generation_before);
    assert_eq!(latest_global(&f.native), position);
    assert_eq!(f.encoder.forwards.load(Ordering::SeqCst), forwards);
    assert_base_unchanged(&f.native, &f.base);
}

#[test]
fn complete_interval_over_128_actual_work_items_never_publishes_a_partial_head() {
    let f = fixture();
    // Tiny genuine nontext captures isolate the work bound from the vector cap.
    for sequence in 3..=131 {
        f.native
            .append_event(small_binary(sequence))
            .expect("actual omitted source");
    }
    let request = seal_request(&f, project(&f));
    assert_eq!(request.target.omitted_sources, 129);
    let generation_before = generation(&f.native, &f.context);
    let position = latest_global(&f.native);
    let forwards = f.encoder.forwards.load(Ordering::SeqCst);
    assert_eq!(
        f.native
            .seal_original_span_segment(&f.context, &request, &mut budget())
            .expect_err("partial accepted interval is refused")
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(generation(&f.native, &f.context), generation_before);
    assert!(generation_before.dense_segments.is_none());
    assert_eq!(latest_global(&f.native), position);
    assert_eq!(f.encoder.forwards.load(Ordering::SeqCst), forwards);
    assert_base_unchanged(&f.native, &f.base);
}
