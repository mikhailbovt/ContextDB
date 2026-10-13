//! Structural accepted-prefix contracts; constant vectors establish no quality.

use super::*;
use contextdb_recall::QueryCancellation;
use contextdb_service::{CapturePort, TextEmbeddingAdapter};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct Encoder(TextEmbeddingProfile);
impl TextEmbeddingAdapter for Encoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.0
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
                self.0.dimensions as u64 * 4 + text.len() as u64 * 4 + 8192,
            )
            .map_err(budget_error)?;
        let mut values = vec![0_f32; self.0.dimensions as usize];
        values[0] = 1.;
        let mut hasher = blake3::Hasher::new();
        for value in &values {
            hasher.update(&value.to_le_bytes());
        }
        Ok(EmbeddedText {
            profile_digest: self.0.digest()?,
            kind,
            text_digest: digest(text.as_bytes()),
            input_digest: digest(self.0.input_text(kind, text)?.as_bytes()),
            tokens_digest: digest(b"prefix fixture exact tokens"),
            token_count: 7,
            values,
            vector_digest: ContentDigest::from_bytes(*hasher.finalize().as_bytes()),
        })
    }
}

struct Fixture {
    native: NativeService,
    context: AuthenticatedRequestContext,
    root: tempfile::TempDir,
    ledger: Arc<crate::NativeSuppressionLedger>,
    keys: Arc<crate::NativeCustodyKeys>,
    _ledger: tempfile::TempDir,
    _keys: tempfile::TempDir,
    encoder: Encoder,
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        5_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        QueryCancellation::default(),
    )
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("prefix native directory");
    let (ld, ledger) = crate::suppression::tests::authority("span-ann-prefix-fixture");
    let (kd, keys) = crate::encryption::tests::authority("span-ann-prefix-fixture");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "span-ann-prefix-fixture",
        [23; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted native");
    let mut first = crate::capture::tests::request(1, "immutable prefix original");
    first
        .context
        .capability_grants
        .insert(Capability::ModelProcessing);
    native.append_event(first.clone()).expect("base capture");
    let context = first.context;
    native
        .project_originals_bm25(&context, false, 64, &mut budget())
        .expect("base raw prefix");
    let encoder = Encoder(TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(
        b"prefix fixture backend",
    )));
    native
        .project_original_spans(&context, &encoder, 64, &mut budget())
        .expect("base dense prefix");
    native
        .publish_original_span_graph(&context, &mut budget())
        .expect("accepted immutable base");
    Fixture {
        native,
        context,
        root,
        ledger,
        keys,
        _ledger: ld,
        _keys: kd,
        encoder,
    }
}

fn witnessed(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    max_work: usize,
    tracked: bool,
    parent: &mut QueryBudget,
) -> ServiceResult<Witness> {
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(storage_error)?;
    let state: IndexState = native
        .graph_read(
            &snapshot,
            &native.keyspaces.continuous,
            &state_key(&workspace),
            parent,
        )?
        .ok_or_else(stale_index)?;
    let generation: Generation = native
        .graph_read(
            &snapshot,
            &native.keyspaces.continuous,
            &generation_key(&workspace, state.active.ok_or_else(stale_index)?),
            parent,
        )?
        .ok_or_else(stale_index)?;
    let receipt = native.accepted_graph_receipt(&snapshot, &workspace, &generation, parent)?;
    native.admit_tail_generation(&generation, &receipt.manifest, parent)?;
    native.tail_dense_receipt(&snapshot, &workspace, &generation, parent)?;
    native.graph_tail_fence(context, &workspace, &generation, &receipt, parent)?;
    if tracked {
        native.tracked_base_dense_prefix_witness(
            &snapshot,
            &workspace,
            &generation,
            &receipt,
            max_work,
            parent,
        )
    } else {
        native.dense_tail_witness(
            &snapshot,
            &workspace,
            &generation,
            &receipt,
            max_work,
            parent,
        )
    }
}

#[test]
fn encrypted_complete_interval_counts_omissions_and_survives_cold_reopen() {
    let f = fixture();
    let empty = witnessed(&f.native, &f.context, 128, true, &mut budget())
        .expect("authenticated empty interval");
    assert!(empty.complete && empty.documents.is_empty());
    assert_eq!(
        empty
            .interval
            .as_ref()
            .expect("complete tracking")
            .work_items,
        0
    );
    f.native
        .append_event(crate::capture::tests::request(
            2,
            "new independently captured original",
        ))
        .expect("tail capture");
    f.native
        .append_event(crate::capture::tests::request(3, &"excluded ".repeat(8193)))
        .expect("tail exceeding dense source bound");
    f.native
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("advanced raw prefix");
    f.native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("advanced dense prefix with explicit omission");

    let legacy = witnessed(&f.native, &f.context, 128, false, &mut budget())
        .expect("unchanged legacy witness");
    assert!(legacy.complete && legacy.interval.is_none());
    let tracked =
        witnessed(&f.native, &f.context, 128, true, &mut budget()).expect("complete seal witness");
    assert!(tracked.complete);
    assert_eq!(tracked.documents, legacy.documents);
    assert_eq!(tracked.documents.len(), 2);
    assert_eq!(
        tracked
            .documents
            .iter()
            .filter(|doc| doc.omission == Some(DenseOmission::TooLarge))
            .count(),
        1,
    );
    let interval = tracked.interval.expect("complete interval commitment");
    assert_eq!(
        interval.work_items, 2,
        "omitted document remains accepted work"
    );
    let repeat =
        witnessed(&f.native, &f.context, 128, true, &mut budget()).expect("repeat exact witness");
    assert_eq!(
        repeat.interval.expect("repeat complete").digest,
        interval.digest
    );
    let partial = witnessed(&f.native, &f.context, 1, true, &mut budget())
        .expect("bounded incomplete witness");
    assert!(!partial.complete && partial.documents.is_empty() && partial.interval.is_none());

    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        "span-ann-prefix-fixture",
        [23; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold encrypted native");
    let actual = witnessed(&cold, &f.context, 128, true, &mut budget())
        .expect("cold owner authenticates interval");
    assert_eq!(actual.documents, tracked.documents);
    let actual = actual.interval.expect("cold complete interval");
    assert_eq!(
        (actual.work_items, actual.digest),
        (interval.work_items, interval.digest)
    );
}

#[test]
fn streaming_digest_refuses_shared_bytes_and_cancellation_before_hashing() {
    let mut hasher = blake3::Hasher::new();
    let before = *hasher.finalize().as_bytes();
    let mut parent = QueryBudget::new(100, 1, Duration::from_secs(1), QueryCancellation::default());
    let mut writer = BudgetHashWriter {
        hasher: &mut hasher,
        budget: &mut parent,
        limit: None,
    };
    writer
        .write_all(b"admitted only before hash")
        .expect_err("byte refusal");
    assert_eq!(writer.limit, Some(QueryLimit::Bytes));
    assert_eq!(*hasher.finalize().as_bytes(), before);

    let cancellation = QueryCancellation::default();
    let mut parent = QueryBudget::new(100, 100, Duration::from_secs(1), cancellation.clone());
    cancellation.cancel();
    let mut writer = BudgetHashWriter {
        hasher: &mut hasher,
        budget: &mut parent,
        limit: None,
    };
    writer
        .write_all(b"still not hashed")
        .expect_err("same parent cancellation");
    assert_eq!(writer.limit, Some(QueryLimit::Cancelled));
    assert_eq!(*hasher.finalize().as_bytes(), before);
}

#[test]
fn streamed_canonical_parts_are_delimited_and_do_not_promote_failed_tracking() {
    let mut tracked = IntervalHash {
        hasher: blake3::Hasher::new(),
        work_items: 0,
    };
    let parts = [("prepared_removal", Some(9_u64)), ("document", None)];
    let mut expected = blake3::Hasher::new();
    for part in parts {
        tracked
            .part(&part, &mut budget())
            .expect("stream canonical part");
        expected.update(&serde_json::to_vec(&part).expect("fixture canonical encoding"));
        expected.update(&[0]);
    }
    assert_eq!(
        tracked
            .finish(&mut budget())
            .expect("complete stream")
            .digest,
        ContentDigest::from_bytes(*expected.finalize().as_bytes())
    );

    let mut tracked = IntervalHash {
        hasher: blake3::Hasher::new(),
        work_items: 0,
    };
    let mut parent = QueryBudget::new(100, 0, Duration::from_secs(1), QueryCancellation::default());
    let error = tracked
        .part(&"unfinished", &mut parent)
        .expect_err("typed parent bytes");
    assert_eq!(error.code, ErrorCode::BudgetExhausted);
    assert!(error.message.contains("byte budget"));
}
