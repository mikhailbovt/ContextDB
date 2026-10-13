//! Native owner/cold/custody contracts using explicitly artificial vectors.
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
        budget: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        budget
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
            tokens_digest: digest(b"explicit graph fixture tokens"),
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
}
fn budget() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        256 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}
fn limits() -> DenseGraphQueryLimits {
    DenseGraphQueryLimits {
        limit: 4,
        max_node_reads: 64,
        max_vector_reads: 32,
        max_discovered: 32,
        ef_search: 16,
    }
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("graph directory");
    let (ld, ledger) = crate::suppression::tests::authority("span-ann-fixture");
    let (kd, keys) = crate::encryption::tests::authority("span-ann-fixture");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "span-ann-fixture",
        [19; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted owner");
    let mut first = crate::capture::tests::request(1, &"original 原文 🙂 boundary ".repeat(150));
    first
        .context
        .capability_grants
        .insert(Capability::ModelProcessing);
    let second = crate::capture::tests::request(2, "independent original");
    native.append_event(first.clone()).expect("first capture");
    native.append_event(second).expect("second capture");
    let context = first.context;
    let source = first.event.event_id;
    native
        .project_originals_bm25(&context, false, 64, &mut budget())
        .expect("BM25 base");
    let encoder = Encoder(TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(
        b"graph fixture backend",
    )));
    native
        .project_original_spans(&context, &encoder, 64, &mut budget())
        .expect("dense source vectors");
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
    }
}
fn verify(native: &NativeService) -> ServiceResult<()> {
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(storage_error)?;
    native.verify_raw_index_records(&snapshot)
}
fn replace(native: &NativeService, key: &[u8], value: Option<&[u8]>) {
    let mut tx = native.engine.begin_write().expect("fault tx");
    if let Some(value) = value {
        tx.put(&native.keyspaces.continuous, key.to_vec(), value.to_vec())
            .expect("fault put");
    } else {
        tx.delete(&native.keyspaces.continuous, key.to_vec())
            .expect("fault delete");
    }
    tx.commit(Durability::Sync).expect("fault sync");
}

#[test]
fn encrypted_graph_cold_points_stale_base_and_full_retirement() {
    let f = fixture();
    let receipt = f
        .native
        .publish_original_span_graph(&f.context, &mut budget())
        .expect("owner graph");
    assert_eq!(receipt.manifest.authorization_epoch, 0);
    assert_eq!(
        f.native
            .publish_original_span_graph(&f.context, &mut budget())
            .expect("point retry"),
        receipt
    );
    verify(&f.native).expect("owner canonical graph reconstruction");
    let cue = "independent original";
    let query = f
        .encoder
        .embed(EmbeddingTextKind::Query, cue, &mut budget())
        .expect("fixture query");
    let actual = f
        .native
        .search_original_spans(&f.context, cue, &query, limits(), &mut budget())
        .expect("native point traversal");
    assert!(!actual.hits.is_empty());
    assert!(actual.vector_reads > 0);
    let mut forbidden = f.context.clone();
    forbidden.request.purpose = "not-granted".into();
    let denied = f
        .native
        .search_original_spans(&forbidden, cue, &query, limits(), &mut budget())
        .expect("denied cohorts excluded");
    assert!(denied.hits.is_empty());
    assert_eq!(
        (denied.node_reads, denied.vector_reads, denied.discovered),
        (0, 0, 0)
    );
    let mut no_model = f.context.clone();
    no_model
        .capability_grants
        .remove(&Capability::ModelProcessing);
    assert_eq!(
        f.native
            .search_original_spans(&no_model, cue, &query, limits(), &mut budget())
            .expect_err("processing grant required")
            .code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        f.native
            .search_original_spans(
                &f.context,
                cue,
                &query,
                limits(),
                &mut QueryBudget::new(100, 1024, Duration::from_secs(5), Default::default())
            )
            .expect_err("same parent allowance")
            .code,
        ErrorCode::BudgetExhausted
    );
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("graph rows");
    let rows = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            &graph_prefix(&workspace, receipt.manifest.generation),
        )
        .expect("finite test inventory");
    let member_row = rows
        .iter()
        .find(|r| {
            r.key.starts_with(
                format!(
                    "{}dense/graph/member/",
                    generation_prefix(&workspace, receipt.manifest.generation)
                )
                .as_bytes(),
            )
        })
        .expect("member row")
        .clone();
    let mut member: GraphMember = decode(&member_row.value, "member").expect("member decode");
    member.vector_digest = digest(b"forged source vector");
    drop(snapshot);
    replace(
        &f.native,
        &member_row.key,
        Some(&encode(&member).expect("forged row")),
    );
    assert!(
        f.native
            .search_original_spans(&f.context, cue, &query, limits(), &mut budget())
            .is_err()
    );
    assert!(verify(&f.native).is_err());
    replace(&f.native, &member_row.key, Some(&member_row.value));
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        "span-ann-fixture",
        [19; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold owner");
    verify(&cold).expect("cold canonical commitment");
    assert_eq!(
        cold.search_original_spans(&f.context, cue, &query, limits(), &mut budget())
            .expect("cold point-only query")
            .hits,
        actual.hits
    );
    let request = crate::capture::tests::request(3, "later original");
    cold.append_event(request).expect("new accepted source");
    cold.project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("raw advance");
    assert_eq!(
        cold.search_original_spans(&f.context, cue, &query, limits(), &mut budget())
            .expect_err("raw prefix changed")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        cold.publish_original_span_graph(&f.context, &mut budget())
            .expect_err("immutable same generation")
            .code,
        ErrorCode::IndexTooStale
    );
    verify(&cold).expect("legitimate stale graph remains reconstructible");
    cold.project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("dense advance");
    verify(&cold).expect("frozen graph census ignores later dense vectors");
    cold.project_originals(&f.context, true, 64, &mut budget())
        .expect("new legacy generation");
    let member_address = crate::encryption::address(&cold.keyspaces.continuous, &member_row.key);
    let node_address = crate::encryption::address(
        &cold.keyspaces.continuous,
        &node_key(
            &workspace,
            receipt.manifest.generation,
            decode::<GraphMember>(&member_row.value, "old member")
                .expect("member")
                .representation_id,
        ),
    );
    let mut observed = BTreeMap::new();
    loop {
        let progress = cold
            .reclaim_raw_generations(&f.context, 3, &mut budget())
            .expect("bounded graph GC");
        let witness = cold
            .read_raw_copy_witness(
                &f.context,
                &progress.copies.expect("copy receipt"),
                &mut budget(),
            )
            .expect("witness");
        for row in witness.rows {
            observed.insert(row.address_digest.clone(), row);
        }
        if progress.finished {
            break;
        }
    }
    assert_eq!(observed[&member_address].kind, NativeRawCopyKind::Document);
    assert!(observed[&member_address].source.is_some());
    assert_eq!(
        (observed[&node_address].kind, observed[&node_address].source),
        (NativeRawCopyKind::SharedMetadata, None)
    );
    verify(&cold).expect("retained declaration survives full graph GC");
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("retained receipt");
    assert!(
        cold.accepted_dense_graph_generations(&snapshot)
            .expect("retained declaration")
            .contains_key(&(workspace, receipt.manifest.generation))
    );
}

#[test]
fn graph_joint_strip_revocation_and_malformed_counts_refuse() {
    let f = fixture();
    let receipt = f
        .native
        .publish_original_span_graph(&f.context, &mut budget())
        .expect("owner graph");
    let mut malformed = receipt.clone();
    malformed.manifest.cohorts[0].nodes = u64::MAX;
    assert_eq!(
        f.native
            .check_graph_receipt(&malformed)
            .expect_err("bounded counts before MAC")
            .code,
        ErrorCode::IntegrityFailure
    );
    f.native
        .revoke_original(&f.context, f.source, "graph-source-revoke", &mut budget())
        .expect("current native revocation");
    let cue = "independent original";
    let query = f
        .encoder
        .embed(EmbeddingTextKind::Query, cue, &mut budget())
        .expect("fixture query");
    assert!(
        f.native
            .search_original_spans(&f.context, cue, &query, limits(), &mut budget())
            .is_err()
    );
    verify(&f.native).expect("revoked historical graph verifies without restoring authority");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault snapshot");
    let key = generation_key(&workspace, receipt.manifest.generation);
    let mut generation: Generation = decode(
        &snapshot
            .get(&f.native.keyspaces.continuous, &key)
            .expect("generation read")
            .expect("generation"),
        "generation",
    )
    .expect("decode");
    let rows = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            &graph_prefix(&workspace, receipt.manifest.generation),
        )
        .expect("graph rows");
    drop(snapshot);
    generation.dense_graph = None;
    replace(
        &f.native,
        &key,
        Some(&encode(&generation).expect("stripped manifest")),
    );
    for row in rows {
        replace(&f.native, &row.key, None);
    }
    assert!(
        verify(&f.native)
            .expect_err("retained declaration defeats joint strip")
            .message
            .contains("retained accepted declaration")
    );
}
