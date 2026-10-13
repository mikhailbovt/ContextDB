//! Encrypted source-prefix contracts; artificial vectors imply no model quality.
use super::*;
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
            .charge(1, self.0.dimensions as u64 * 4 + text.len() as u64)
            .map_err(budget_error)?;
        let mut values = vec![0_f32; self.0.dimensions as usize];
        values[blake3::hash(text.as_bytes()).as_bytes()[0] as usize] = 1.;
        let mut hash = blake3::Hasher::new();
        for value in &values {
            hash.update(&value.to_le_bytes());
        }
        Ok(EmbeddedText {
            profile_digest: self.0.digest()?,
            kind,
            text_digest: digest(text.as_bytes()),
            input_digest: digest(self.0.input_text(kind, text)?.as_bytes()),
            tokens_digest: digest(b"explicit tail fixture tokens"),
            token_count: 7,
            values,
            vector_digest: ContentDigest::from_bytes(*hash.finalize().as_bytes()),
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
    graph: DenseGraphReceipt,
}
fn budget() -> QueryBudget {
    QueryBudget::new(
        5_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}
fn limits() -> DenseGraphTailQueryLimits {
    DenseGraphTailQueryLimits {
        graph: DenseGraphQueryLimits {
            limit: 4,
            max_node_reads: 64,
            max_vector_reads: 32,
            max_discovered: 32,
            ef_search: 16,
        },
        max_tail_work: 128,
        max_tail_vectors: 256,
    }
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("tail native directory");
    let (ld, ledger) = crate::suppression::tests::authority("span-ann-tail-fixture");
    let (kd, keys) = crate::encryption::tests::authority("span-ann-tail-fixture");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "span-ann-tail-fixture",
        [21; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted native");
    let mut first = crate::capture::tests::request(1, "immutable first original");
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
        b"tail fixture backend",
    )));
    native
        .project_original_spans(&context, &encoder, 64, &mut budget())
        .expect("base dense prefix");
    let graph = native
        .publish_original_span_graph(&context, &mut budget())
        .expect("immutable ANN graph");
    Fixture {
        native,
        context,
        root,
        ledger,
        keys,
        _ledger: ld,
        _keys: kd,
        encoder,
        graph,
    }
}
fn graph_rows(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
) -> Vec<contextdb_storage::Entry> {
    native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot")
        .scan_prefix(
            &native.keyspaces.continuous,
            &graph_prefix(&digest_bytes(context.request.workspace_id.as_bytes()), 1),
        )
        .expect("graph inventory")
}
fn replace(
    native: &NativeService,
    space: &contextdb_storage::Keyspace,
    key: &[u8],
    value: Option<&[u8]>,
) {
    let mut tx = native.engine.begin_write().expect("fault transaction");
    if let Some(value) = value {
        tx.put(space, key.to_vec(), value.to_vec())
            .expect("fault put");
    } else {
        tx.delete(space, key.to_vec()).expect("fault delete");
    }
    tx.commit(Durability::Sync).expect("fault sync");
}

#[test]
fn cold_tail_proves_complete_extension_without_graph_rebuild_and_retains_caps() {
    let f = fixture();
    let before = graph_rows(&f.native, &f.context);
    let cue = "independent tail original";
    let query = f
        .encoder
        .embed(EmbeddingTextKind::Query, cue, &mut budget())
        .expect("fixture query");
    let base = f
        .native
        .search_original_spans(&f.context, cue, &query, limits().graph, &mut budget())
        .expect("strict original base");
    let added = crate::capture::tests::request(2, cue);
    let added_id = added.event.event_id;
    let long = crate::capture::tests::request(3, &"tail 原文 🙂 repeated boundary ".repeat(180));
    f.native.append_event(added).expect("first tail capture");
    f.native.append_event(long).expect("multispan tail capture");
    let raw_lag = f
        .native
        .search_original_spans_with_tail(&f.context, cue, &query, limits(), &mut budget())
        .expect("unprojected accepted capture is explicit");
    assert_eq!(raw_lag.completion, DenseGraphTailCompletion::RawLag);
    assert!(raw_lag.raw_lag && !raw_lag.dense_lag);
    assert_eq!(raw_lag.hits, base.hits);
    assert_eq!(graph_rows(&f.native, &f.context), before);
    f.native
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("advanced raw prefix");
    let lag = f
        .native
        .search_original_spans_with_tail(&f.context, cue, &query, limits(), &mut budget())
        .expect("explicit dense lag");
    assert_eq!(lag.completion, DenseGraphTailCompletion::DenseLag);
    assert!(lag.dense_lag && lag.tail_witness_complete);
    assert_eq!(lag.tail_vector_reads, 0);
    assert_eq!(lag.hits, base.hits);
    assert_eq!(lag.proven_through, lag.base_through);
    assert!(lag.raw_through > lag.observed_dense_through);
    let dense = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("complete new dense prefix");
    assert_eq!(
        f.native
            .search_original_spans(&f.context, cue, &query, limits().graph, &mut budget())
            .expect_err("strict API still refuses advancement")
            .code,
        ErrorCode::IndexTooStale
    );
    let actual = f
        .native
        .search_original_spans_with_tail(&f.context, cue, &query, limits(), &mut budget())
        .expect("authenticated exact tail");
    assert_eq!(actual.completion, DenseGraphTailCompletion::Complete);
    assert!(actual.tail_witness_complete && actual.tail_scoring_complete && !actual.dense_lag);
    assert_eq!(actual.proven_through, dense.through);
    assert_eq!(actual.proven_dense_commitment, dense.commitment);
    assert_eq!(
        actual.vector_reads,
        base.vector_reads + actual.tail_vector_reads
    );
    assert_eq!(
        actual.tail_vector_reads,
        dense.spans - f.graph.manifest.dense.spans
    );
    assert!(
        actual
            .hits
            .iter()
            .any(|hit| hit.source.event_id == added_id)
    );
    assert_eq!(graph_rows(&f.native, &f.context), before);
    assert_eq!(
        actual.admitted_sources.len(),
        3,
        "whole source frontier survives top-k"
    );
    let mut work_cap = limits();
    work_cap.max_tail_work = 1;
    let capped = f
        .native
        .search_original_spans_with_tail(&f.context, cue, &query, work_cap, &mut budget())
        .expect("base-only incomplete witness");
    assert_eq!(capped.completion, DenseGraphTailCompletion::TailWorkLimit);
    assert!(!capped.tail_witness_complete && !capped.tail_scoring_complete);
    assert_eq!(capped.hits, base.hits);
    assert_eq!(capped.tail_vector_reads, 0);
    assert_eq!(capped.proven_through, capped.base_through);
    assert_eq!(
        capped.proven_dense_commitment,
        f.graph.manifest.dense.commitment
    );
    assert_ne!(
        capped.observed_dense_commitment,
        capped.proven_dense_commitment
    );
    let mut vector_cap = limits();
    vector_cap.max_tail_vectors = 1;
    let capped = f
        .native
        .search_original_spans_with_tail(&f.context, cue, &query, vector_cap, &mut budget())
        .expect("permitted vector cap");
    assert_eq!(capped.completion, DenseGraphTailCompletion::TailVectorLimit);
    assert!(capped.tail_witness_complete && !capped.tail_scoring_complete);
    assert_eq!(capped.tail_vector_reads, 1);
    assert_eq!(
        capped.admitted_sources.len(),
        3,
        "unscored permitted tail sources retain controls"
    );
    let mut shared_cap = limits();
    shared_cap.graph.max_vector_reads = base.vector_reads as usize;
    let capped = f
        .native
        .search_original_spans_with_tail(&f.context, cue, &query, shared_cap, &mut budget())
        .expect("one operation vector budget");
    assert_eq!(capped.completion, DenseGraphTailCompletion::VectorLimit);
    assert_eq!(capped.vector_reads, base.vector_reads);
    assert_eq!(capped.tail_vector_reads, 0);
    let mut denied = f.context.clone();
    denied.request.purpose = "not-permitted".into();
    let denied = f
        .native
        .search_original_spans_with_tail(&denied, cue, &query, limits(), &mut budget())
        .expect("forbidden domains remain metadata only");
    assert!(denied.hits.is_empty());
    assert_eq!(
        (
            denied.node_reads,
            denied.vector_reads,
            denied.discovered,
            denied.tail_vector_reads
        ),
        (0, 0, 0, 0)
    );
    assert!(denied.admitted_sources.is_empty());
    let serialized = serde_json::to_value(&actual).expect("public observation");
    assert!(serialized.get("admitted_sources").is_none());
    let debug = format!("{actual:?}");
    for field in [
        "base_through",
        "observed_dense_through",
        "proven_through",
        "raw_through",
    ] {
        assert!(serialized.get(field).is_none(), "private cutoff {field}");
        assert!(!debug.contains(field), "private debug cutoff {field}");
    }
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        "span-ann-tail-fixture",
        [21; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold native");
    assert_eq!(
        cold.search_original_spans_with_tail(&f.context, cue, &query, limits(), &mut budget())
            .expect("cold accepted-tail points"),
        actual
    );
    assert_eq!(graph_rows(&cold, &f.context), before);
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cold verify");
    cold.verify_raw_index_records(&snapshot)
        .expect("frozen base plus advanced dense verifies");
}

#[test]
fn missing_tail_work_tag_receipt_and_revocation_never_become_complete() {
    let f = fixture();
    let cue = "new authentic tail";
    let added = crate::capture::tests::request(2, cue);
    let id = added.event.event_id;
    f.native.append_event(added).expect("tail capture");
    f.native
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("raw tail");
    f.native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("dense tail");
    let query = f
        .encoder
        .embed(EmbeddingTextKind::Query, cue, &mut budget())
        .expect("fixture query");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault snapshot");
    let doc_bytes = snapshot
        .get(
            &f.native.keyspaces.continuous,
            &document_key(&workspace, 1, id),
        )
        .expect("doc read")
        .expect("doc");
    let doc: DenseDocument = decode(&doc_bytes, "tail doc").expect("doc decode");
    let work_key = crate::capture::work_key(&workspace, doc.commit);
    let work = snapshot
        .get(&f.native.keyspaces.continuous, &work_key)
        .expect("work read")
        .expect("work");
    let receipt: DenseProjectionReceipt = decode(
        &snapshot
            .get(
                &f.native.keyspaces.continuous,
                &super::super::receipt_key(&workspace, 1),
            )
            .expect("dense receipt read")
            .expect("dense receipt"),
        "dense receipt",
    )
    .expect("decode");
    let event: crate::StoredEvent = decode(
        &snapshot
            .get(
                &f.native.keyspaces.events,
                &receipt.global_commit.to_be_bytes(),
            )
            .expect("event read")
            .expect("event"),
        "event",
    )
    .expect("decode");
    let retained = snapshot
        .get(
            &f.native.keyspaces.idempotency,
            event.request_digest.as_bytes(),
        )
        .expect("retained read")
        .expect("retained");
    drop(snapshot);
    replace(&f.native, &f.native.keyspaces.continuous, &work_key, None);
    assert!(
        f.native
            .search_original_spans_with_tail(&f.context, cue, &query, limits(), &mut budget())
            .expect_err("missing accepted work cannot cover complete prefix")
            .message
            .contains("prefix witness")
    );
    replace(
        &f.native,
        &f.native.keyspaces.continuous,
        &work_key,
        Some(&work),
    );
    let mut forged = doc.clone();
    forged.spans[0].span.span_digest = digest(b"forged chunk");
    replace(
        &f.native,
        &f.native.keyspaces.continuous,
        &document_key(&workspace, 1, id),
        Some(&encode(&forged).expect("forged doc")),
    );
    assert_eq!(
        f.native
            .search_original_spans_with_tail(&f.context, cue, &query, limits(), &mut budget())
            .expect_err("tagged original span refused")
            .code,
        ErrorCode::IntegrityFailure
    );
    replace(
        &f.native,
        &f.native.keyspaces.continuous,
        &document_key(&workspace, 1, id),
        Some(&doc_bytes),
    );
    replace(
        &f.native,
        &f.native.keyspaces.idempotency,
        event.request_digest.as_bytes(),
        None,
    );
    assert!(
        f.native
            .search_original_spans_with_tail(&f.context, cue, &query, limits(), &mut budget())
            .expect_err("latest dense receipt is retained")
            .message
            .contains("retained receipt")
    );
    replace(
        &f.native,
        &f.native.keyspaces.idempotency,
        event.request_digest.as_bytes(),
        Some(&retained),
    );
    assert!(
        f.native
            .search_original_spans_with_tail(
                &f.context,
                cue,
                &query,
                limits(),
                &mut QueryBudget::new(100, 1024, Duration::from_secs(5), Default::default())
            )
            .is_err()
    );
    let mut invalid = limits();
    invalid.max_tail_work = 129;
    assert_eq!(
        f.native
            .search_original_spans_with_tail(&f.context, cue, &query, invalid, &mut budget())
            .expect_err("finite work cap")
            .code,
        ErrorCode::InvalidArgument
    );
    invalid = limits();
    invalid.max_tail_vectors = 257;
    assert_eq!(
        f.native
            .search_original_spans_with_tail(&f.context, cue, &query, invalid, &mut budget())
            .expect_err("finite vector cap")
            .code,
        ErrorCode::InvalidArgument
    );
    f.native
        .revoke_original(&f.context, id, "revoke-tail-original", &mut budget())
        .expect("actual revocation");
    assert!(
        f.native
            .search_original_spans_with_tail(&f.context, cue, &query, limits(), &mut budget())
            .is_err()
    );
}
