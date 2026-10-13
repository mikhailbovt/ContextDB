//! Encrypted native query wiring. Controlled coordinates are not learned recall.

use super::super::types::{SealRequest, SegCohort, SegMember, SegNode};
use super::*;
use crate::raw_index::dense::DenseVector;
use contextdb_core::RawSource;
use contextdb_recall::QueryCancellation;
use contextdb_service::{CapturePort, TextEmbeddingAdapter};
use contextdb_storage::{
    Durability, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const QUERY: &str = "structural query over independently captured original bytes";
const DATABASE: &str = "span-ann-segment-query-fixture";
const TOKEN_KEY: [u8; 32] = [33; 32];

#[derive(Debug)]
struct Encoder {
    profile: TextEmbeddingProfile,
    source_forwards: AtomicUsize,
    query_forwards: AtomicUsize,
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
                self.profile.dimensions as u64 * 8 + text.len() as u64 * 4 + 8192,
            )
            .map_err(budget_error)?;
        let mut values = vec![0_f32; self.profile.dimensions as usize];
        if kind == EmbeddingTextKind::Source {
            let basis = text
                .strip_prefix("basis-")
                .and_then(|rest| rest.split_once(' '))
                .and_then(|(number, _)| number.parse::<usize>().ok())
                .filter(|basis| *basis < 6)
                .expect("explicit structural source coordinate");
            values[basis] = 1.;
            self.source_forwards.fetch_add(1, Ordering::SeqCst);
        } else {
            assert_eq!(text, QUERY, "one exact structural query");
            let norm = 91_f32.sqrt();
            for (index, value) in values.iter_mut().take(6).enumerate() {
                *value = (index + 1) as f32 / norm;
            }
            self.query_forwards.fetch_add(1, Ordering::SeqCst);
        }
        let mut hash = blake3::Hasher::new();
        for value in &values {
            hash.update(&value.to_le_bytes());
        }
        Ok(EmbeddedText {
            profile_digest: self.profile.digest()?,
            kind,
            text_digest: digest(text.as_bytes()),
            input_digest: digest(self.profile.input_text(kind, text)?.as_bytes()),
            tokens_digest: digest(b"explicit controlled segment-query token receipt"),
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
    base: DenseGraphReceipt,
    first: DenseSegmentPublication,
    second: DenseSegmentPublication,
    sources: Vec<RawSource>,
    query: EmbeddedText,
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        5_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}
fn limits() -> DenseSegmentQueryLimits {
    DenseSegmentQueryLimits {
        graph: DenseGraphQueryLimits {
            limit: 6,
            max_node_reads: 128,
            max_vector_reads: 64,
            max_discovered: 64,
            ef_search: 64,
        },
        max_segments: 2,
        max_tail_work: 128,
        max_tail_vectors: 64,
    }
}
fn generation(native: &NativeService, context: &AuthenticatedRequestContext) -> Generation {
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current native snapshot");
    native
        .graph_read(
            &snapshot,
            &native.keyspaces.continuous,
            &generation_key(&digest_bytes(context.request.workspace_id.as_bytes()), 1),
            &mut budget(),
        )
        .expect("bounded current generation")
        .expect("accepted generation")
}
fn project(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    encoder: &Encoder,
) -> DenseProjectionReceipt {
    let mut parent = budget();
    let mut raw_complete = false;
    for _ in 0..4 {
        if native
            .project_originals_bm25(context, false, 64, &mut parent)
            .expect("bounded raw maintenance batch")
            .caught_up
        {
            raw_complete = true;
            break;
        }
    }
    assert!(raw_complete, "explicit fixture raw maintenance bound");
    for _ in 0..4 {
        let receipt = native
            .project_original_spans(context, encoder, 64, &mut parent)
            .expect("bounded exact source maintenance batch");
        if receipt.caught_up {
            return receipt;
        }
    }
    panic!("explicit fixture dense maintenance bound");
}
fn seal(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    target: DenseProjectionReceipt,
) -> DenseSegmentPublication {
    let request = SealRequest {
        generation: 1,
        previous: generation(native, context).dense_segments,
        target,
    };
    native
        .seal_original_span_segment(context, &request, &mut budget())
        .expect("actual accepted whole-source segment")
}
fn capture(native: &NativeService, basis: usize) -> (AuthenticatedRequestContext, RawSource) {
    let text = format!(
        "basis-{basis} actual independently captured original sentinel for structural path {basis}"
    );
    let mut request = crate::capture::tests::request(basis as u64 + 1, &text);
    request
        .context
        .capability_grants
        .insert(Capability::ModelProcessing);
    request.event.source_version = Some(if basis == 2 {
        format!("actual-complete-version-{basis}-{}", "v".repeat(1870))
    } else {
        format!("actual-source-version-{basis}")
    });
    let source = RawSource::from(&request.event);
    native
        .append_event(request.clone())
        .expect("actual encrypted source capture");
    (request.context, source)
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("encrypted segment-query directory");
    let (ld, ledger) = crate::suppression::tests::authority(DATABASE);
    let (kd, keys) = crate::encryption::tests::authority(DATABASE);
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        DATABASE,
        TOKEN_KEY,
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted native owner");
    let encoder = Encoder {
        profile: TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(
            b"controlled segment-query backend",
        )),
        source_forwards: AtomicUsize::new(0),
        query_forwards: AtomicUsize::new(0),
    };
    let (context, first_source) = capture(&native, 0);
    let mut sources = vec![first_source, capture(&native, 1).1];
    project(&native, &context, &encoder);
    let base = native
        .publish_original_span_graph(&context, &mut budget())
        .expect("actual immutable two-source base");
    sources.push(capture(&native, 2).1);
    let first = seal(&native, &context, project(&native, &context, &encoder));
    sources.push(capture(&native, 3).1);
    let second = seal(&native, &context, project(&native, &context, &encoder));
    sources.push(capture(&native, 4).1);
    sources.push(capture(&native, 5).1);
    project(&native, &context, &encoder);
    let query = encoder
        .embed(EmbeddingTextKind::Query, QUERY, &mut budget())
        .expect("one controlled query observation");
    assert_eq!(encoder.source_forwards.load(Ordering::SeqCst), 6);
    assert_eq!(encoder.query_forwards.load(Ordering::SeqCst), 1);
    Fixture {
        native,
        context,
        root,
        ledger,
        keys,
        _ledger: ld,
        _keys: kd,
        encoder,
        base,
        first,
        second,
        sources,
        query,
    }
}
fn latest_global(native: &NativeService) -> u64 {
    native
        .global_head(
            &native
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("native head snapshot"),
        )
        .expect("actual accepted global head")
}
fn search(f: &Fixture, limits: DenseSegmentQueryLimits) -> ServiceResult<DenseSegmentQueryResult> {
    f.native
        .search_original_spans_segmented(&f.context, QUERY, &f.query, limits, &mut budget())
}
fn assert_totals(result: &DenseSegmentQueryResult, limits: DenseSegmentQueryLimits) {
    assert_eq!(
        result.node_reads,
        result
            .witness
            .paths
            .iter()
            .map(|path| path.node_reads)
            .sum::<u64>()
    );
    assert_eq!(
        result.vector_reads,
        result
            .witness
            .paths
            .iter()
            .map(|path| path.vector_reads)
            .sum::<u64>()
    );
    assert_eq!(
        result.discovered,
        result
            .witness
            .paths
            .iter()
            .map(|path| path.discovered)
            .sum::<u64>()
    );
    let fresh = result
        .witness
        .paths
        .last()
        .expect("protected fresh-tail observation");
    assert_eq!(fresh.kind, HybridDensePathKind::FreshTail);
    assert_eq!(result.tail_vector_reads, fresh.vector_reads);
    assert!(result.node_reads <= limits.graph.max_node_reads as u64);
    assert!(result.vector_reads <= limits.graph.max_vector_reads as u64);
    assert!(result.discovered <= limits.graph.max_discovered as u64);
    for path in &result.witness.paths {
        assert!(path.node_reads <= u64::from(path.max_node_reads));
        assert!(path.vector_reads <= u64::from(path.max_vector_reads));
        assert!(path.discovered <= u64::from(path.max_discovered));
    }
}
fn replace(native: &NativeService, key: &[u8], value: Option<&[u8]>) {
    let mut tx = native
        .engine
        .begin_write()
        .expect("explicit fixture fault transaction");
    if let Some(value) = value {
        tx.put(&native.keyspaces.continuous, key.to_vec(), value.to_vec())
            .expect("fault row");
    } else {
        tx.delete(&native.keyspaces.continuous, key.to_vec())
            .expect("fault delete");
    }
    tx.commit(Durability::Sync).expect("fixture fault sync");
}
fn original_row(native: &NativeService, key: &[u8]) -> Vec<u8> {
    native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault source snapshot")
        .get(&native.keyspaces.continuous, key)
        .expect("actual original row")
        .expect("present row")
}

#[test]
fn encrypted_all_paths_have_one_global_rank_full_frontier_and_cold_exact_attribution() {
    let f = fixture();
    let position = latest_global(&f.native);
    let result = search(&f, limits()).expect("actual base plus two sealed deltas plus fresh tail");
    assert_eq!(result.completion, DenseSegmentQueryCompletion::Complete);
    assert!(
        result.tail_witness_complete
            && result.tail_scoring_complete
            && !result.raw_lag
            && !result.dense_lag
    );
    assert_eq!(result.vector_reads, 6);
    assert_eq!(result.discovered, 6);
    assert_eq!(result.tail_vector_reads, 2);
    assert_eq!(
        result
            .hits
            .iter()
            .map(|hit| hit.source.event_id)
            .collect::<Vec<_>>(),
        f.sources
            .iter()
            .rev()
            .map(|source| source.event_id)
            .collect::<Vec<_>>(),
        "one strict score rank across every path"
    );
    assert!(
        result
            .hits
            .windows(2)
            .all(|pair| pair[0].score > pair[1].score)
    );
    for hit in &result.hits {
        let source = f
            .sources
            .iter()
            .find(|source| source.event_id == hit.source.event_id)
            .expect("actual captured supplier");
        assert_eq!(
            &hit.source, source,
            "complete RawSource metadata, including original version"
        );
        assert_eq!(hit.span.event_id, source.event_id);
        assert_eq!(Some(hit.span.payload_digest), source.payload_digest);
        assert_eq!(
            (hit.span.start, Some(hit.span.end)),
            (0, source.byte_length)
        );
    }
    assert!(
        f.sources[2]
            .source_version
            .as_ref()
            .expect("full source version")
            .len()
            > 1800
    );
    assert_eq!(
        result.admitted_sources,
        f.sources
            .iter()
            .map(|source| (source.event_id, source.clone()))
            .collect()
    );
    assert_eq!(result.witness.selected_ordinals, vec![1, 2]);
    assert!(result.witness.selection_complete);
    assert_eq!(result.witness.head.count, 2);
    assert_eq!(
        result.witness.base.graph_digest,
        f.base.manifest.content_digest
    );
    assert_eq!(
        result.witness.latest.manifest_digest,
        f.second.delta.manifest.content_digest
    );
    assert_eq!(
        result.witness.covered_dense_commitment,
        f.second.directory.head.covered.commitment
    );
    assert_eq!(
        result.witness.proven_dense_commitment,
        result.witness.observed_dense_commitment
    );
    assert_eq!(
        result
            .witness
            .paths
            .iter()
            .map(|path| path.kind)
            .collect::<Vec<_>>(),
        vec![
            HybridDensePathKind::Base,
            HybridDensePathKind::Segment,
            HybridDensePathKind::Segment,
            HybridDensePathKind::FreshTail
        ]
    );
    assert_totals(&result, limits());

    let mut top_two = limits();
    top_two.graph.limit = 2;
    let ranked =
        search(&f, top_two).expect("bounded returned sources retain complete admitted suppliers");
    assert_eq!(ranked.hits.len(), 2);
    assert_eq!(ranked.hits[0].source, f.sources[5]);
    assert_eq!(ranked.hits[1].source, f.sources[4]);
    assert_eq!(
        ranked.admitted_sources, result.admitted_sources,
        "discarded immutable ranks remain protected suppliers"
    );
    assert_totals(&ranked, top_two);
    let serialized = serde_json::to_value(&result).expect("public query observation");
    assert!(serialized.get("witness").is_none() && serialized.get("admitted_sources").is_none());
    assert!(!format!("{result:?}").contains("covered_through"));
    assert_eq!(
        latest_global(&f.native),
        position,
        "query appends no owner publication"
    );
    assert_eq!(f.encoder.source_forwards.load(Ordering::SeqCst), 6);
    assert_eq!(
        f.encoder.query_forwards.load(Ordering::SeqCst),
        1,
        "query traversal never invokes an encoder"
    );
    f.native
        .verify_native(true)
        .expect("actual source/base/segment closure after read-only queries");
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        DATABASE,
        TOKEN_KEY,
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold same-key encrypted owner");
    assert_eq!(
        cold.search_original_spans_segmented(&f.context, QUERY, &f.query, limits(), &mut budget())
            .expect("cold accepted segmented query"),
        result
    );
    cold.verify_native(true)
        .expect("cold actual segmented query substrate closure");
}

#[test]
fn partial_tail_and_bounded_directory_report_coverage_without_resetting_parent() {
    let f = fixture();
    let position = latest_global(&f.native);
    let mut partial_limits = limits();
    partial_limits.max_tail_work = 1;
    let partial =
        search(&f, partial_limits).expect("only completely proved immutable paths are returned");
    assert_eq!(
        partial.completion,
        DenseSegmentQueryCompletion::TailWorkLimit
    );
    assert!(!partial.tail_witness_complete && !partial.tail_scoring_complete);
    assert_eq!(partial.tail_vector_reads, 0);
    assert_eq!(
        partial.witness.proven_through,
        partial.witness.covered_through
    );
    assert_eq!(
        partial.witness.proven_dense_commitment,
        partial.witness.covered_dense_commitment
    );
    assert_eq!(partial.admitted_sources.len(), 4);
    assert!(
        f.sources[4..]
            .iter()
            .all(|source| !partial.admitted_sources.contains_key(&source.event_id))
    );
    assert!(
        partial
            .hits
            .iter()
            .all(|hit| f.sources[..4].contains(&hit.source))
    );
    assert_totals(&partial, partial_limits);

    let mut selected_limits = limits();
    selected_limits.max_segments = 1;
    let selected = search(&f, selected_limits).expect("honest first-ordinal selection observation");
    assert_eq!(
        selected.completion,
        DenseSegmentQueryCompletion::SegmentSelectionLimit
    );
    assert!(!selected.witness.selection_complete);
    assert_eq!(selected.witness.selected_ordinals, vec![1]);
    assert_eq!(
        selected.witness.head.count, 2,
        "bounded selection never rewrites the actual head"
    );
    assert!(selected.tail_witness_complete && selected.tail_scoring_complete);
    assert!(
        !selected
            .admitted_sources
            .contains_key(&f.sources[3].event_id)
    );
    assert_totals(&selected, selected_limits);

    let cancellation = QueryCancellation::default();
    let mut parent = QueryBudget::new(
        5_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        cancellation.clone(),
    );
    cancellation.cancel();
    assert_eq!(
        f.native
            .search_original_spans_segmented(&f.context, QUERY, &f.query, limits(), &mut parent)
            .expect_err("same parent cancellation")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(parent.check(), Err(QueryLimit::Cancelled));
    let mut expired = QueryBudget::new(
        5_000_000,
        512 * 1024 * 1024,
        Duration::ZERO,
        Default::default(),
    );
    assert_eq!(
        f.native
            .search_original_spans_segmented(&f.context, QUERY, &f.query, limits(), &mut expired)
            .expect_err("original parent deadline")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(expired.check(), Err(QueryLimit::Deadline));
    assert_eq!(latest_global(&f.native), position);
    assert_eq!(f.encoder.source_forwards.load(Ordering::SeqCst), 6);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 1);
}

#[test]
fn selected_immutable_rows_and_current_head_refuse_tampering_and_real_revocation() {
    let f = fixture();
    search(&f, limits()).expect("untampered actual segmented query");
    let position = latest_global(&f.native);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let prefix = types::segment_prefix(&workspace, 1, 1).expect("actual first segment prefix");
    let rows = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault inventory snapshot")
        .scan_prefix(&f.native.keyspaces.continuous, &prefix)
        .expect("small actual selected segment rows");
    let cohort_key = types::segment_cohort_key(
        &workspace,
        1,
        1,
        &f.first.delta.manifest.cohorts[0].policy_domain,
    )
    .expect("actual selected cohort");
    let node_key = rows
        .iter()
        .find(|row| {
            row.key
                .strip_prefix(prefix.as_slice())
                .is_some_and(|suffix| suffix.starts_with(b"node/"))
        })
        .expect("actual selected node")
        .key
        .clone();
    let member_key = rows
        .iter()
        .find(|row| {
            row.key
                .strip_prefix(prefix.as_slice())
                .is_some_and(|suffix| suffix.starts_with(b"member/"))
        })
        .expect("actual selected member")
        .key
        .clone();
    let vector_key = vector_key(&workspace, 1, f.sources[2].event_id, 0);
    let mut cohort: SegCohort = decode(
        &original_row(&f.native, &cohort_key),
        "actual cohort fixture",
    )
    .expect("cohort");
    cohort.partition[0] ^= 1;
    let mut node: SegNode =
        decode(&original_row(&f.native, &node_key), "actual node fixture").expect("node");
    node.canonical_node[0] ^= 1;
    let mut member: SegMember = decode(
        &original_row(&f.native, &member_key),
        "actual member fixture",
    )
    .expect("member");
    member.source.source_version = Some("foreign version never captured for this member".into());
    let mut vector: DenseVector = decode(
        &original_row(&f.native, &vector_key),
        "actual vector fixture",
    )
    .expect("vector");
    vector.values_bits[0] = 1_f32.to_bits();
    for (key, altered) in [
        (cohort_key, encode(&cohort).expect("cohort fault")),
        (node_key, encode(&node).expect("node fault")),
        (member_key, encode(&member).expect("foreign source fault")),
        (vector_key, encode(&vector).expect("vector fault")),
    ] {
        let original = original_row(&f.native, &key);
        replace(&f.native, &key, Some(&altered));
        assert_eq!(
            search(&f, limits())
                .expect_err("selected immutable row has no legacy fallback")
                .code,
            ErrorCode::IntegrityFailure
        );
        replace(&f.native, &key, Some(&original));
    }
    let head_key = types::directory_head_key(&workspace, 1).expect("actual directory row");
    let head = original_row(&f.native, &head_key);
    replace(&f.native, &head_key, None);
    assert_eq!(
        search(&f, limits())
            .expect_err("missing accepted head cannot become base-only discovery")
            .code,
        ErrorCode::IntegrityFailure
    );
    replace(&f.native, &head_key, Some(&head));
    search(&f, limits()).expect("exact original rows restore accepted query binding");
    assert_eq!(
        latest_global(&f.native),
        position,
        "fault observations create no owner journal frame"
    );
    f.native
        .revoke_original(
            &f.context,
            f.sources[0].event_id,
            "segment-query-current-revocation",
            &mut budget(),
        )
        .expect("real current source revocation");
    let revoked_position = latest_global(&f.native);
    assert_eq!(
        search(&f, limits())
            .expect_err("old profile cannot restore current revoked membership")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(latest_global(&f.native), revoked_position);
    assert_eq!(f.encoder.source_forwards.load(Ordering::SeqCst), 6);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 1);
}
