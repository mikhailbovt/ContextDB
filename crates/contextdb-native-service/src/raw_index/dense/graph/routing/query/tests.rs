//! Encrypted routed serving contracts with controlled vectors, not recall quality.
use super::*;
use crate::raw_index::dense::graph::prefix_segments_v2::types::PrefixSegmentSealRequestV2;
use crate::raw_index::dense::graph::prefix_v2::inputs::tests::{
    Encoder, Fixture, budget, fixture, read_generation,
};
use crate::raw_index::dense::graph::prefix_v2::types::DensePrefixBaseRequestV2;
use contextdb_service::{CapturePort, ErrorCode, TextEmbeddingAdapter, TextEmbeddingProfile};
use contextdb_storage::{Durability, WriteTransaction};
use std::time::Duration;

mod fresh;

const QUERY: &str = "Find the archived sapphire orbital observation";
#[derive(Debug)]
struct Directions<'a>(&'a Encoder);
impl TextEmbeddingAdapter for Directions<'_> {
    fn profile(&self) -> &TextEmbeddingProfile {
        self.0.profile()
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        let mut observation = self.0.embed(kind, text, parent)?;
        if text.contains("sapphire orbital") {
            parent
                .charge(observation.values.len() as u64 + 1, 256)
                .map_err(budget_error)?;
            observation.values[0] = 0.;
            observation.values[1] = 1.;
            let mut hash = blake3::Hasher::new();
            for v in &observation.values {
                hash.update(&v.to_le_bytes());
            }
            observation.vector_digest = ContentDigest::from_bytes(*hash.finalize().as_bytes());
        }
        Ok(observation)
    }
}
fn query_budget() -> QueryBudget {
    QueryBudget::new(
        // Structural integration uses the existing owned-runtime allowance;
        // these checks do not establish latency quality.
        50_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}
fn limits() -> DenseRoutedQueryLimits {
    DenseRoutedQueryLimits {
        graph: DenseGraphQueryLimits {
            limit: 2,
            max_node_reads: 256,
            max_vector_reads: 6,
            max_discovered: 6,
            ef_search: 4,
        },
        max_fine_paths: 1,
        coarse_node_reads: 128,
        coarse_vector_reads: 3,
        coarse_discovered: 3,
        coarse_ef_search: 3,
        max_tail_work: 128,
        max_tail_vectors: 2,
    }
}
fn base(f: &Fixture) {
    f.native
        .publish_original_span_prefix_base(
            &f.context,
            &DensePrefixBaseRequestV2 {
                generation: 1,
                target: f.target.clone(),
            },
            &mut budget(),
        )
        .expect("actual prefix acceptance");
}
fn capture(f: &Fixture, sequence: u64, text: &str) -> ObservationId {
    let mut request = crate::capture::tests::request(sequence, text);
    request.context = f.context.clone();
    request.event.source_version = Some(format!("routed-serving-original-{sequence}"));
    let id = request.event.event_id;
    f.native
        .append_event(request)
        .expect("actual original capture");
    id
}
fn project(f: &Fixture, encoder: &dyn TextEmbeddingAdapter) -> DenseProjectionReceipt {
    f.native
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("actual raw progress");
    f.native
        .project_original_spans(&f.context, encoder, 64, &mut budget())
        .expect("actual dense whole plans")
}
fn seal(f: &Fixture, encoder: &dyn TextEmbeddingAdapter) {
    let target = project(f, encoder);
    let previous = f
        .native
        .original_span_prefix_segment_head(&f.context, 1, &mut budget())
        .expect("current fine predecessor");
    f.native
        .seal_original_span_prefix_segment(
            &f.context,
            &PrefixSegmentSealRequestV2 {
                generation: 1,
                previous,
                target,
            },
            &mut budget(),
        )
        .expect("actual immutable interval acceptance");
}
fn router(f: &Fixture) {
    let request = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("complete actual directory");
    // Explicit offline construction allowance, unchanged from the maintenance
    // all-ordinal fixture. Serving still has its own fixed 512 MiB parent.
    let mut parent = QueryBudget::new(
        250_000_000,
        8 * 1024 * 1024 * 1024,
        Duration::from_secs(180),
        Default::default(),
    );
    f.native
        .publish_original_span_directory_router(&f.context, &request, &mut parent)
        .expect("ALL paths covered before serving");
}
fn search(
    f: &Fixture,
    query: &EmbeddedText,
    limits: DenseRoutedQueryLimits,
) -> ServiceResult<DenseRoutedQueryResult> {
    f.native
        .search_original_spans_routed(&f.context, QUERY, query, limits, &mut query_budget())
}
fn assert_counts(result: &DenseRoutedQueryResult) {
    let w = &result.witness;
    assert_eq!(
        result.node_reads,
        w.coarse.node_reads + w.paths.iter().map(|p| p.node_reads).sum::<u64>()
    );
    assert_eq!(
        result.vector_reads,
        w.coarse.vector_reads + w.paths.iter().map(|p| p.vector_reads).sum::<u64>()
    );
    assert_eq!(
        result.discovered,
        w.coarse.discovered + w.paths.iter().map(|p| p.discovered).sum::<u64>()
    );
    assert_eq!(result.coarse_vector_reads, w.coarse.scores.len() as u64);
    assert_eq!(result.vector_reads, result.discovered);
}

#[test]
fn genuine_directory_routes_ordinal_sixty_five_then_fresh_work_under_one_global_cap() {
    let f = fixture();
    base(&f);
    let encoder = Directions(&f.encoder);
    seal(&f, &encoder);
    let omitted = "x".repeat(64 * 1024 + 1);
    let mut late = None;
    for ordinal in 2..=65_u64 {
        let text = if ordinal == 65 {
            "Actual sapphire orbital observation in the late interval"
        } else {
            &omitted
        };
        let id = capture(&f, 200 + ordinal, text);
        if ordinal == 65 {
            late = Some(id);
        }
        seal(&f, &encoder);
    }
    router(&f);
    let query = encoder
        .embed(EmbeddingTextKind::Query, QUERY, &mut query_budget())
        .expect("controlled exact query observation");
    let mut tight = limits();
    tight.graph.max_vector_reads = 4;
    tight.graph.max_discovered = 4;
    let result = search(&f, &query, tight).expect("point-only routed serving");
    assert_eq!(result.witness.coverage_count, 66);
    assert_eq!(result.witness.selected_paths.len(), 1);
    assert_eq!(result.witness.selected_paths[0].ordinal(), 65);
    assert!(result.witness.unvisited_paths && !result.witness.selection_complete);
    assert!(result.hits.iter().any(|h| Some(h.source.event_id) == late));
    assert_eq!(result.completion, DenseRoutedQueryCompletion::Complete);
    assert_counts(&result);
    assert!(result.vector_reads <= 4 && result.discovered <= 4 && result.node_reads <= 256);
    let coarse = &result.witness.coarse.scores[0];
    let actual = &result.hits[0];
    let mut parent = query_budget();
    let mut typed = QueryLedger::new(
        Caps {
            nodes: 4,
            vectors: 2,
            discovered: 2,
        },
        &mut parent,
    )
    .expect("typed shared identity ledger");
    typed
        .admit_route(
            coarse.representation_id,
            coarse.identity_digest,
            &coarse.path,
            &coarse.policy_domain,
            &mut parent,
        )
        .expect("actual coarse identity");
    assert!(
        typed
            .admit_span(
                coarse.representation_id,
                coarse.identity_digest,
                &actual.source,
                &actual.span,
                &mut parent
            )
            .is_err(),
        "a shared routing ID cannot become an original source ID"
    );
    assert!(
        typed.finish().is_err(),
        "metadata admission alone is not an actual scored discovery"
    );
    // Current source IDs enter only through real capture/owner receipts. The
    // request supplies query text and its own encoder observation, never paths.
    let fresh = capture(&f, 400, "Fresh sapphire orbital follow-up");
    project(&f, &encoder);
    let result =
        search(&f, &query, limits()).expect("immutable router plus genuine fresh interval");
    assert_counts(&result);
    assert_eq!(result.tail_vector_reads, 1);
    assert!(result.admitted_sources.contains_key(&fresh));
    assert!(
        result
            .admitted_sources
            .contains_key(&late.expect("late actual source"))
    );
    assert!(result.vector_reads <= 6 && result.discovered <= 6);
    capture(&f, 401, "Second fresh sapphire orbital update");
    project(&f, &encoder);
    let mut limited = limits();
    limited.max_tail_work = 1;
    let partial = search(&f, &query, limited).expect("honest bounded fresh-work status");
    assert!(!partial.tail_witness_complete);
    assert_eq!(partial.tail_vector_reads, 0);
    assert_eq!(
        partial.witness.proven_through,
        partial.witness.covered_through
    );
    assert_eq!(
        partial.completion,
        DenseRoutedQueryCompletion::TailWorkLimit
    );
    assert_counts(&partial);
}

#[test]
fn selected_router_node_loss_and_revocation_refuse_without_a_query_write() {
    let f = fixture();
    base(&f);
    router(&f);
    let query = f
        .encoder
        .embed(EmbeddingTextKind::Query, QUERY, &mut query_budget())
        .expect("query observation");
    let result = search(&f, &query, limits()).expect("genuine base query");
    assert_counts(&result);
    let source = result
        .hits
        .first()
        .expect("actual fine source")
        .source
        .event_id;
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let generation = read_generation(&f.native, &f.context, &mut budget());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("node point");
    let before = f.native.global_head(&snapshot).expect("owner head");
    let id = result
        .witness
        .coarse
        .scores
        .first()
        .expect("actual coarse observation")
        .representation_id;
    let key = types::node_key(
        &workspace,
        1,
        generation
            .dense_directory_router
            .as_ref()
            .expect("root")
            .serial,
        id,
    )
    .expect("exact router node key");
    let value = snapshot
        .get(&f.native.keyspaces.continuous, &key)
        .expect("actual row")
        .expect("node exists");
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("fault writer");
    tx.delete(&f.native.keyspaces.continuous, key.clone())
        .expect("remove node");
    tx.commit(Durability::Sync).expect("fault Sync");
    assert_eq!(
        search(&f, &query, limits())
            .expect_err("missing node never falls back to ordinal prefix")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = f.native.engine.begin_write().expect("restore");
    tx.put(&f.native.keyspaces.continuous, key, value)
        .expect("exact restore");
    tx.commit(Durability::Sync).expect("restore Sync");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("no query write");
    assert_eq!(f.native.global_head(&snapshot).expect("head"), before);
    drop(snapshot);
    f.native
        .revoke_original(
            &f.context,
            source,
            "routed-current-source-revocation",
            &mut budget(),
        )
        .expect("actual current revocation");
    assert_eq!(
        search(&f, &query, limits())
            .expect_err("old router cannot authorize a revoked current source")
            .code,
        ErrorCode::IndexTooStale
    );
}

#[test]
fn denied_cohort_control_skips_missing_routing_nodes_before_ann_reads() {
    let f = fixture();
    base(&f);
    router(&f);
    let query = f
        .encoder
        .embed(EmbeddingTextKind::Query, QUERY, &mut query_budget())
        .expect("actual query observation");
    let admitted = search(&f, &query, limits()).expect("permitted real routing");
    let score = admitted
        .witness
        .coarse
        .scores
        .first()
        .expect("actual coarse identity");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let root = read_generation(&f.native, &f.context, &mut budget())
        .dense_directory_router
        .expect("actual accepted router root");
    let key = types::node_key(&workspace, 1, root.serial, score.representation_id)
        .expect("exact routing node key");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("node inventory");
    let saved = snapshot
        .get(&f.native.keyspaces.continuous, &key)
        .expect("node point")
        .expect("real admitted node");
    drop(snapshot);
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("routing-node-only fault");
    tx.delete(&f.native.keyspaces.continuous, key.clone())
        .expect("delete node");
    tx.commit(Durability::Sync).expect("fault Sync");
    let mut denied = f.context.clone();
    denied.request.clearance = contextdb_service::Sensitivity::Public;
    let result = f.native.search_original_spans_routed(
        &denied,
        QUERY,
        &query,
        limits(),
        &mut query_budget(),
    );
    let mut tx = f.native.engine.begin_write().expect("exact node restore");
    tx.put(&f.native.keyspaces.continuous, key, saved)
        .expect("restore bytes");
    tx.commit(Durability::Sync).expect("restore Sync");
    let result = result.expect("denied coarse control never reaches the missing ANN node");
    assert!(result.hits.is_empty() && result.admitted_sources.is_empty());
    assert!(result.witness.coarse.scores.is_empty());
    assert_eq!(
        (result.node_reads, result.vector_reads, result.discovered),
        (0, 0, 0)
    );
}

#[test]
fn shared_caps_and_cancelled_parent_do_not_admit_unrecorded_identities() {
    let mut parent = query_budget();
    let mut ledger = QueryLedger::new(
        Caps {
            nodes: 4,
            vectors: 2,
            discovered: 2,
        },
        &mut parent,
    )
    .expect("ledger");
    let source = RawSource::from(&crate::capture::tests::request(1, "actual original bytes").event);
    let span = OriginalSourceSpan {
        event_id: source.event_id,
        payload_digest: source.payload_digest.expect("original"),
        start: 0,
        end: 2,
        span_digest: ContentDigest::from_bytes([7; 32]),
    };
    let full = ContentDigest::from_bytes([3; 32]);
    let mut compact = [3; 16];
    compact[6] = (compact[6] & 15) | 128;
    compact[8] = (compact[8] & 63) | 128;
    let id = RepresentationId::from_uuid(uuid::Uuid::from_bytes(compact)).expect("nonzero locator");
    ledger
        .admit_span(id, full, &source, &span, &mut parent)
        .expect("actual source metadata admission");
    assert!(
        ledger
            .admit_span(id, full, &source, &span, &mut parent)
            .is_err()
    );
    assert!(
        ledger
            .record_kernel(
                ledger::Stage::Fine,
                Caps {
                    nodes: 5,
                    vectors: 1,
                    discovered: 1
                },
                1,
                1,
                1
            )
            .is_err()
    );
    ledger
        .record_kernel(
            ledger::Stage::Fine,
            Caps {
                nodes: 4,
                vectors: 1,
                discovered: 1,
            },
            1,
            1,
            1,
        )
        .expect("actual finite counts");
    assert_eq!(
        ledger.finish().expect("exact frontier").counts.vector_reads,
        1
    );
    let cancellation = contextdb_recall::QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        5_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        cancellation,
    );
    assert!(
        QueryLedger::new(
            Caps {
                nodes: 4,
                vectors: 2,
                discovered: 2
            },
            &mut cancelled
        )
        .is_err()
    );
    assert_eq!(
        Caps {
            nodes: 0,
            vectors: 0,
            discovered: 0
        }
        .fair_share(65)
        .expect("no invented quota"),
        Caps {
            nodes: 0,
            vectors: 0,
            discovered: 0
        }
    );
}
