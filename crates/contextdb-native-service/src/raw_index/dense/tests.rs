//! Contract fixture vectors only. Real encoder execution belongs to host proof.

use super::*;
use contextdb_service::{CapturePort, CaptureRequest, TextEmbeddingAdapter};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct FixtureEncoder {
    profile: TextEmbeddingProfile,
    calls: AtomicUsize,
}
impl FixtureEncoder {
    fn new() -> Self {
        Self {
            profile: TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(
                b"fixture-backend-artifacts",
            )),
            calls: AtomicUsize::new(0),
        }
    }
}
impl TextEmbeddingAdapter for FixtureEncoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.profile
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        budget
            .charge(1, self.profile.dimensions as u64 * 4 + text.len() as u64)
            .map_err(budget_error)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut values = vec![0.0_f32; self.profile.dimensions as usize];
        values[usize::from(blake3::hash(text.as_bytes()).as_bytes()[0])] = 1.0;
        let mut hash = blake3::Hasher::new();
        for value in &values {
            hash.update(&value.to_le_bytes());
        }
        Ok(EmbeddedText {
            profile_digest: self.profile.digest()?,
            kind,
            text_digest: digest(text.as_bytes()),
            input_digest: digest(self.profile.input_text(kind, text)?.as_bytes()),
            tokens_digest: digest(b"explicit-fixture-token-observation"),
            token_count: 7,
            values,
            vector_digest: ContentDigest::from_bytes(*hash.finalize().as_bytes()),
        })
    }
}

struct Fixture {
    native: NativeService,
    context: AuthenticatedRequestContext,
    first: CaptureRequest,
    second: CaptureRequest,
    root: tempfile::TempDir,
    ledger: Arc<crate::NativeSuppressionLedger>,
    keys: Arc<crate::NativeCustodyKeys>,
    _ledger_directory: tempfile::TempDir,
    _keys_directory: tempfile::TempDir,
}
fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        Default::default(),
    )
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("dense native directory");
    let (ledger_directory, ledger) = crate::suppression::tests::authority("source-dense-fixture");
    let (keys_directory, keys) = crate::encryption::tests::authority("source-dense-fixture");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "source-dense-fixture",
        [17; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted native");
    let mut first = crate::capture::tests::request(1, &"alpha 原文 🙂 boundary ".repeat(240));
    first
        .context
        .capability_grants
        .insert(Capability::ModelProcessing);
    let second = crate::capture::tests::request(2, "independent original");
    let large = crate::capture::tests::request(3, &"large ".repeat(12_000));
    for request in [&first, &second, &large] {
        native
            .append_event(request.clone())
            .expect("accepted original");
    }
    let context = first.context.clone();
    native
        .project_originals_bm25(&context, false, 64, &mut budget())
        .expect("BM25 prefix");
    Fixture {
        native,
        context,
        first,
        second,
        root,
        ledger,
        keys,
        _ledger_directory: ledger_directory,
        _keys_directory: keys_directory,
    }
}
fn verify(native: &NativeService) -> ServiceResult<()> {
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("verify snapshot");
    native.verify_raw_index_records(&snapshot)
}
fn replace(native: &NativeService, key: &[u8], bytes: Option<&[u8]>) {
    let mut tx = native.engine.begin_write().expect("fault transaction");
    if let Some(bytes) = bytes {
        tx.put(&native.keyspaces.continuous, key.to_vec(), bytes.to_vec())
            .expect("replace");
    } else {
        tx.delete(&native.keyspaces.continuous, key.to_vec())
            .expect("remove");
    }
    tx.commit(Durability::Sync).expect("fault sync");
}

#[test]
fn encrypted_dense_prefix_binds_originals_and_owner_vectors_after_cold_reopen() {
    let f = fixture();
    let encoder = FixtureEncoder::new();
    let mut denied = f.context.clone();
    denied
        .capability_grants
        .remove(&Capability::ModelProcessing);
    assert!(
        f.native
            .project_original_spans(&denied, &encoder, 64, &mut budget())
            .is_err()
    );
    assert_eq!(encoder.calls.load(Ordering::SeqCst), 0);
    let receipt = f
        .native
        .project_original_spans(&f.context, &encoder, 64, &mut budget())
        .expect("dense publication");
    assert_eq!(
        (
            receipt.sources,
            receipt.embedded_sources,
            receipt.omitted_sources
        ),
        (3, 2, 1)
    );
    assert!(receipt.spans > 2 && receipt.caught_up);
    assert_eq!(encoder.calls.load(Ordering::SeqCst) as u64, receipt.spans);
    assert_eq!(
        f.native
            .project_original_spans(&f.context, &encoder, 64, &mut budget())
            .expect("exact no-work retry"),
        receipt
    );
    assert_eq!(encoder.calls.load(Ordering::SeqCst) as u64, receipt.spans);
    verify(&f.native).expect("exact source and vector commitments");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let key = vector_key(&workspace, receipt.generation, f.first.event.event_id, 0);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("vector snapshot");
    let bytes = snapshot
        .get(&f.native.keyspaces.continuous, &key)
        .expect("vector read")
        .expect("vector");
    let mut vector: DenseVector = decode(&bytes, "fixture vector").expect("decode");
    drop(snapshot);
    vector.values_bits.swap(0, 1);
    // A shape-valid rewrite cannot manufacture an owner observation.
    vector.values_bits[0] = 0.5_f32.to_bits();
    replace(
        &f.native,
        &key,
        Some(&encode(&vector).expect("fault vector")),
    );
    assert!(verify(&f.native).is_err());
    replace(&f.native, &key, Some(&bytes));
    let mut wrong = encoder.profile.clone();
    wrong.backend_artifacts_digest = digest(b"different backend");
    let different = FixtureEncoder {
        profile: wrong,
        calls: AtomicUsize::new(0),
    };
    assert!(
        f.native
            .project_original_spans(&f.context, &different, 64, &mut budget())
            .is_err()
    );
    assert_eq!(different.calls.load(Ordering::SeqCst), 0);
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        "source-dense-fixture",
        [17; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold native");
    verify(&cold).expect("cold owner commitments without neural forward");
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cold rows");
    let generation_bytes = snapshot
        .get(
            &cold.keyspaces.continuous,
            &generation_key(&workspace, receipt.generation),
        )
        .expect("generation read")
        .expect("generation");
    let rows = snapshot
        .scan_prefix(
            &cold.keyspaces.continuous,
            format!(
                "{}dense/",
                generation_prefix(&workspace, receipt.generation)
            )
            .as_bytes(),
        )
        .expect("dense rows");
    let mut generation: Generation = decode(&generation_bytes, "generation").expect("decode");
    drop(snapshot);
    generation.dense = None;
    replace(
        &cold,
        &generation_key(&workspace, receipt.generation),
        Some(&encode(&generation).expect("stripped profile")),
    );
    for row in rows {
        replace(&cold, &row.key, None);
    }
    assert!(
        verify(&cold)
            .expect_err("profile plus rows cannot jointly become legacy")
            .message
            .contains("retained accepted declaration")
    );
}

#[test]
#[ignore = "requires explicitly provisioned pinned local GPU assets"]
fn real_encoder_projects_encrypted_originals_and_verifies_after_cold_reopen() {
    use contextdb_agent_runtime::{LocalEmbeddingConfig, OwnedLocalEmbedding};
    use contextdb_recall::QueryCancellation;
    use std::time::{Duration, Instant};

    let path = std::env::var_os("CONTEXTDB_EMBEDDING_CONFIG").expect("explicit pinned host config");
    let config_bytes = std::fs::read(path).expect("provisioned embedding config");
    assert!(config_bytes.len() < 64 * 1024);
    let config: LocalEmbeddingConfig =
        serde_json::from_slice(&config_bytes).expect("trusted fixed config");
    let mut provisioning = QueryBudget::new(
        1_000_000,
        4 * 1024 * 1024 * 1024,
        Duration::from_secs(120),
        QueryCancellation::default(),
    );
    let mut encoder = OwnedLocalEmbedding::launch(&config, &mut provisioning)
        .expect("verified real owned encoder");
    let f = fixture();
    let start = Instant::now();
    let mut projection = QueryBudget::new(
        2_000_000,
        256 * 1024 * 1024,
        Duration::from_secs(60),
        QueryCancellation::default(),
    );
    let receipt = f
        .native
        .project_original_spans(&f.context, &encoder, 64, &mut projection)
        .expect("actual native owner projection");
    assert_eq!(
        (
            receipt.sources,
            receipt.embedded_sources,
            receipt.omitted_sources
        ),
        (3, 2, 1)
    );
    assert!(receipt.spans > 2 && receipt.caught_up);
    assert_eq!(receipt.profile, *encoder.profile());
    let first_snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("published exact vectors");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let prefix = format!(
        "{}dense/vector/",
        generation_prefix(&workspace, receipt.generation)
    );
    let vector_rows = first_snapshot
        .scan_prefix(&f.native.keyspaces.continuous, prefix.as_bytes())
        .expect("fixture proof vector rows");
    assert_eq!(vector_rows.len() as u64, receipt.spans);
    for row in &vector_rows {
        let vector: DenseVector = decode(&row.value, "actual owner vector").expect("source vector");
        assert_eq!(vector.values_bits.len(), 1024);
        assert!(
            vector
                .values_bits
                .iter()
                .filter(|bits| f32::from_bits(**bits) != 0.0)
                .count()
                > 100,
            "real distributed vector rather than fixture one-hot"
        );
    }
    drop(first_snapshot);
    verify(&f.native).expect("exact originals and accepted real-vector commitments");
    let projection_millis = start.elapsed().as_millis();
    let graph = f
        .native
        .publish_original_span_graph(&f.context, &mut budget())
        .expect("owner publication of the actual source-vector graph");
    verify(&f.native).expect("final graph rows and accepted source bindings");
    let query_text = "Find the independent original.";
    let mut query_budget = budget();
    let query = encoder
        .embed(EmbeddingTextKind::Query, query_text, &mut query_budget)
        .expect("actual instructed query embedding under the same parent");
    let query_limits = graph::DenseGraphQueryLimits {
        limit: 3,
        max_node_reads: 64,
        max_vector_reads: 32,
        max_discovered: 32,
        ef_search: 16,
    };
    let discovered = f
        .native
        .search_original_spans(
            &f.context,
            query_text,
            &query,
            query_limits,
            &mut query_budget,
        )
        .expect("point-only native query of actual accepted vectors");
    assert!(
        discovered
            .hits
            .iter()
            .any(|hit| hit.source.event_id == f.second.event.event_id),
        "small composed wiring fixture must rediscover its independent source"
    );
    assert!(discovered.node_reads <= 64 && discovered.vector_reads <= 32);
    encoder
        .shutdown(&mut QueryBudget::new(
            10_000,
            1024 * 1024,
            Duration::from_secs(5),
            QueryCancellation::default(),
        ))
        .expect("bounded encoder cleanup");
    drop(encoder);
    let path = f.root.path().join("native");
    drop(f.native);
    let reopened = NativeService::open_encrypted(
        path,
        "source-dense-fixture",
        [17; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold encrypted native reopen");
    verify(&reopened).expect("cold exact source plans, MACs and retained commitments");
    let mut cold_budget = budget();
    let cold = reopened
        .search_original_spans(
            &f.context,
            query_text,
            &query,
            query_limits,
            &mut cold_budget,
        )
        .expect("cold point query without a neural rerun or rebuild");
    assert_eq!(cold.hits, discovered.hits);
    let independent = cold
        .hits
        .iter()
        .find(|hit| hit.source.event_id == f.second.event.event_id)
        .expect("retained exact original identity");
    let snapshot = reopened
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cold original materialization snapshot");
    let bytes = reopened
        .source_span_inner(
            &snapshot,
            Some(&f.context),
            &independent.span,
            true,
            Some(&mut cold_budget),
        )
        .expect("authenticated original bytes with the query's parent allowance");
    assert_eq!(bytes, b"independent original");
    drop(snapshot);
    // A separate maintenance/query attempt extends the cold source prefix;
    // neither serving path rebuilds the already accepted immutable graph.
    let snapshot = reopened
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("frozen graph snapshot");
    let graph_prefix = graph::graph_prefix(&workspace, receipt.generation);
    let graph_rows_before = snapshot
        .scan_prefix(&reopened.keyspaces.continuous, &graph_prefix)
        .expect("fixture graph row proof");
    drop(snapshot);
    let mut tail_encoder = OwnedLocalEmbedding::launch(
        &config,
        &mut QueryBudget::new(
            1_000_000,
            4 * 1024 * 1024 * 1024,
            Duration::from_secs(120),
            QueryCancellation::default(),
        ),
    )
    .expect("pinned encoder for fresh source maintenance");
    let tool_text = "Correction from the latest tool observation: the spare batteries are now beside the front entrance.";
    let mut fresh = crate::capture::tests::request(4, tool_text);
    fresh.event.role = contextdb_core::EventRole::Tool;
    fresh.event.kind = EventKind::ToolCompleted;
    reopened
        .append_event(fresh.clone())
        .expect("fresh tool original capture");
    reopened
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("advance raw prefix without rebuilding graph");
    let tail_receipt = reopened
        .project_original_spans(&f.context, &tail_encoder, 64, &mut budget())
        .expect("complete fresh dense source projection");
    assert_eq!(tail_receipt.sources, 4);
    let tail_text = "Where did the latest observation place the extra batteries?";
    let mut tail_budget = budget();
    let oversized = "x|".repeat(2200);
    let oversize_measurement = tail_encoder
        .measure_tokens(EmbeddingTextKind::Query, &oversized, &mut tail_budget)
        .expect("exact oversized token observation without inference");
    assert!(
        !oversize_measurement
            .fits_inference_limit(tail_encoder.profile(), &mut tail_budget)
            .expect("exact pinned token capacity")
    );
    let measurement = tail_encoder
        .measure_tokens(EmbeddingTextKind::Query, tail_text, &mut tail_budget)
        .expect("fresh exact token preflight with same live backend");
    let tail_query = tail_encoder
        .embed(EmbeddingTextKind::Query, tail_text, &mut tail_budget)
        .expect("one valid fresh query forward");
    assert_eq!(
        (
            measurement.token_count,
            measurement.tokens_digest,
            measurement.input_digest
        ),
        (
            tail_query.token_count,
            tail_query.tokens_digest,
            tail_query.input_digest
        )
    );
    let tail_limits = graph::DenseGraphTailQueryLimits {
        graph: graph::DenseGraphQueryLimits {
            limit: 7,
            ..query_limits
        },
        max_tail_work: 128,
        max_tail_vectors: 256,
    };
    let tail_result = reopened
        .search_original_spans_with_tail(
            &f.context,
            tail_text,
            &tail_query,
            tail_limits,
            &mut tail_budget,
        )
        .expect("actual point base plus fresh-vector tail");
    assert_eq!(tail_result.graph_digest, graph.manifest.content_digest);
    assert!(
        tail_result.tail_witness_complete
            && tail_result.tail_scoring_complete
            && !tail_result.dense_lag
    );
    assert_eq!(tail_result.tail_vector_reads, 1);
    let fresh_hit = tail_result
        .hits
        .iter()
        .find(|hit| hit.source.event_id == fresh.event.event_id)
        .expect("fresh exact tool original candidate");
    let snapshot = reopened
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("served fresh original snapshot");
    assert_eq!(
        reopened
            .source_span_inner(
                &snapshot,
                Some(&f.context),
                &fresh_hit.span,
                true,
                Some(&mut tail_budget)
            )
            .expect("fresh authorized source bytes"),
        tool_text.as_bytes()
    );
    assert_eq!(
        snapshot
            .scan_prefix(&reopened.keyspaces.continuous, &graph_prefix)
            .expect("unchanged graph row proof"),
        graph_rows_before
    );
    drop(snapshot);
    tail_encoder
        .shutdown(&mut QueryBudget::new(
            10_000,
            1024 * 1024,
            Duration::from_secs(5),
            QueryCancellation::default(),
        ))
        .expect("bounded fresh encoder cleanup");
    drop(tail_encoder);
    verify(&reopened).expect("complete cold advanced dense graph custody");
    drop(reopened);
    let reopened = NativeService::open_encrypted(
        f.root.path().join("native"),
        "source-dense-fixture",
        [17; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("second cold encrypted owner");
    let cold_tail = reopened
        .search_original_spans_with_tail(
            &f.context,
            tail_text,
            &tail_query,
            tail_limits,
            &mut budget(),
        )
        .expect("cold base-tail without encoder");
    assert_eq!(cold_tail.hits, tail_result.hits);
    verify(&reopened).expect("cold advanced graph reconstruction");
    println!(
        "{}",
        serde_json::json!({"profile_digest":receipt.profile_digest,"sources":receipt.sources,"embedded_sources":receipt.embedded_sources,"spans":receipt.spans,"omitted_sources":receipt.omitted_sources,"caught_up":receipt.caught_up,"commitment":receipt.commitment,"projection_millis_observation":projection_millis,"graph_digest":graph.manifest.content_digest,"native_graph_query_wiring_verified":true,"query_node_reads":discovered.node_reads,"query_vector_reads":discovered.vector_reads,"cold_encrypted_native_verification":true,"cold_query_and_exact_original_materialization":true,"base_tail_cold_wiring_verified":true,"immutable_graph_rows_unchanged":true,"tail_vector_reads":tail_result.tail_vector_reads,"tail_sources":tail_receipt.sources,"oversize_preflight_tokens":oversize_measurement.token_count,"valid_query_preflight_tokens":measurement.token_count,"automatic_owned_query_embedding_enabled":false,"query_retrieval_quality_evaluated":false,"main_reader_benefit_evaluated":false,"final_benchmarks_accessed":false})
    );
}

#[test]
fn dense_retirement_observes_owned_vectors_and_shared_receipt_before_removal() {
    let f = fixture();
    let encoder = FixtureEncoder::new();
    let receipt = f
        .native
        .project_original_spans(&f.context, &encoder, 64, &mut budget())
        .expect("dense publication");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let address = crate::encryption::address(
        &f.native.keyspaces.continuous,
        &vector_key(&workspace, 1, f.first.event.event_id, 0),
    );
    let second_address = crate::encryption::address(
        &f.native.keyspaces.continuous,
        &vector_key(&workspace, 1, f.second.event.event_id, 0),
    );
    let shared =
        crate::encryption::address(&f.native.keyspaces.continuous, &receipt_key(&workspace, 1));
    f.native
        .project_originals(&f.context, true, 64, &mut budget())
        .expect("separate legacy generation");
    let mut observations = BTreeMap::new();
    loop {
        let progress = f
            .native
            .reclaim_raw_generations(&f.context, 3, &mut budget())
            .expect("bounded encrypted GC");
        let witness = f
            .native
            .read_raw_copy_witness(
                &f.context,
                &progress.copies.expect("retained copy witness"),
                &mut budget(),
            )
            .expect("witness");
        for row in witness.rows {
            observations.insert(row.address_digest.clone(), row);
        }
        if progress.finished {
            break;
        }
    }
    for (address, source) in [
        (address, f.first.event.event_id),
        (second_address, f.second.event.event_id),
    ] {
        let row = &observations[&address];
        assert_eq!(
            (row.kind, row.source),
            (NativeRawCopyKind::Document, Some(source))
        );
        assert!(row.version.is_some());
    }
    assert_eq!(
        (observations[&shared].kind, observations[&shared].source),
        (NativeRawCopyKind::SharedMetadata, None)
    );
    verify(&f.native).expect("retained declarations after full generation GC");
    assert_eq!(encoder.calls.load(Ordering::SeqCst) as u64, receipt.spans);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("manifest snapshot");
    let bytes = snapshot
        .get(&f.native.keyspaces.meta, crate::META_MANIFEST_KEY)
        .expect("manifest read")
        .expect("manifest");
    let mut manifest: crate::Manifest = decode(&bytes, "manifest").expect("decode");
    drop(snapshot);
    manifest.features.remove(FEATURE);
    manifest.checksum = crate::manifest_checksum(&manifest).expect("checksum");
    let mut tx = f.native.engine.begin_write().expect("feature fault");
    tx.put(
        &f.native.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest bytes"),
    )
    .expect("replace feature");
    tx.commit(Durability::Sync).expect("feature fault sync");
    assert!(
        verify(&f.native).is_err(),
        "dense feature remains required after complete GC"
    );
}

struct RevokingEncoder<'a> {
    native: &'a NativeService,
    context: AuthenticatedRequestContext,
    source: ObservationId,
    inner: FixtureEncoder,
}
impl std::fmt::Debug for RevokingEncoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevokingEncoder").finish_non_exhaustive()
    }
}
impl TextEmbeddingAdapter for RevokingEncoder<'_> {
    fn profile(&self) -> &TextEmbeddingProfile {
        self.inner.profile()
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        let result = self.inner.embed(kind, text, parent)?;
        if self.inner.calls.load(Ordering::SeqCst) == 1 {
            // Same-thread native mutation while inference is in flight proves
            // no publication lock is held around the model callback.
            self.native.revoke_original(
                &self.context,
                self.source,
                "revoke-during-dense-forward",
                parent,
            )?;
        }
        Ok(result)
    }
}

fn assert_no_dense_publication(native: &NativeService, context: &AuthenticatedRequestContext) {
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("refusal snapshot");
    let generation: Generation = native
        .raw_value(&snapshot, &generation_key(&workspace, 1))
        .expect("generation read")
        .expect("generation");
    assert!(generation.dense.is_none());
    assert!(
        snapshot
            .scan_prefix(
                &native.keyspaces.continuous,
                format!("{}dense/", generation_prefix(&workspace, 1)).as_bytes()
            )
            .expect("dense rows")
            .is_empty()
    );
    assert!(
        native
            .accepted_dense_generations(&snapshot)
            .expect("retained declarations")
            .is_empty()
    );
}

#[test]
fn revocation_inside_first_embed_stops_remaining_spans_and_publishes_nothing() {
    let f = fixture();
    let encoder = RevokingEncoder {
        native: &f.native,
        context: f.context.clone(),
        source: f.first.event.event_id,
        inner: FixtureEncoder::new(),
    };
    let error = f
        .native
        .project_original_spans(&f.context, &encoder, 64, &mut budget())
        .expect_err("fresh admission rejects revoked remaining chunks");
    assert!(matches!(
        error.code,
        ErrorCode::IndexTooStale | ErrorCode::PermissionDenied
    ));
    assert_eq!(
        encoder.inner.calls.load(Ordering::SeqCst),
        1,
        "multispan source stops before forwarding a second span"
    );
    assert_no_dense_publication(&f.native, &f.context);
}

#[derive(Debug)]
struct ChangingEncoder {
    inner: FixtureEncoder,
    alternate: TextEmbeddingProfile,
    switched: std::sync::atomic::AtomicBool,
}
impl TextEmbeddingAdapter for ChangingEncoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        if self.switched.load(Ordering::SeqCst) {
            &self.alternate
        } else {
            self.inner.profile()
        }
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        let result = self.inner.embed(kind, text, parent)?;
        self.switched.store(true, Ordering::SeqCst);
        Ok(result)
    }
}

#[test]
fn encoder_profile_change_during_callback_cannot_publish_under_frozen_profile() {
    let f = fixture();
    let alternate =
        TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(b"alternate-fixture-runtime"));
    let encoder = ChangingEncoder {
        inner: FixtureEncoder::new(),
        alternate,
        switched: std::sync::atomic::AtomicBool::new(false),
    };
    let error = f
        .native
        .project_original_spans(&f.context, &encoder, 64, &mut budget())
        .expect_err("mutable host profile refused");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert_eq!(encoder.inner.calls.load(Ordering::SeqCst), 1);
    assert_no_dense_publication(&f.native, &f.context);
}
