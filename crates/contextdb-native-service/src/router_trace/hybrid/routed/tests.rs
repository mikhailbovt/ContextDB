//! Shape tests only. Native acceptance and source authority are tested by the owner.
use super::super::{HybridRouteKind, HybridRouteObservation};
use super::*;
use crate::raw_index::dense::graph::segments::types::AcceptedPublicationRef;
use contextdb_core::{ModelCallId, ObservationId};
use contextdb_recall::QueryCancellation;
use contextdb_service::{ErrorCode, OwnedHybridLimits, OwnedRoutedLimits};
use std::time::Duration;

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::from_bytes([byte; 32])
}
fn budget() -> QueryBudget {
    QueryBudget::new(
        10_000_000,
        64 * 1024 * 1024,
        Duration::from_secs(10),
        QueryCancellation::default(),
    )
}
fn compact(byte: u8) -> uuid::Uuid {
    let mut bytes = [byte; 16];
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    uuid::Uuid::from_bytes(bytes)
}
fn accepted(global_commit: u64) -> AcceptedPublicationRef {
    AcceptedPublicationRef {
        global_commit,
        event_digest: "a".repeat(64),
        request_digest: "b".repeat(64),
        response_digest: "c".repeat(64),
    }
}
fn path(
    kind: HybridDensePathKind,
    ordinal: Option<u64>,
    fresh: bool,
) -> HybridDensePathObservation {
    HybridDensePathObservation {
        kind,
        ordinal,
        has_work: true,
        max_node_reads: if fresh { 0 } else { 16 },
        max_vector_reads: 16,
        max_discovered: 16,
        max_work: if fresh { 128 } else { 0 },
        node_reads: u64::from(!fresh),
        vector_reads: 1,
        discovered: 1,
        work: u64::from(fresh),
        completion: HybridDensePathCompletion::Complete,
    }
}
fn fixture() -> (
    HybridRoutedDenseWitness,
    HybridRouteObservation,
    OwnedHybridIntent,
) {
    let base = PrefixSegmentBaseRefV2 {
        publication: accepted(10),
        receipt_digest: digest(1),
        content_digest: digest(2),
    };
    let segment = DirectoryRouterFinePathV1::Segment {
        ordinal: 65,
        publication: accepted(80),
        receipt_digest: digest(3),
        content_digest: digest(4),
    };
    let base_path = DirectoryRouterFinePathV1::Base { base: base.clone() };
    let score = |byte, target, value: f32| HybridCoarseScore {
        representation_id: RepresentationId::from_uuid(compact(byte)).expect("compact identity"),
        identity_digest: digest(byte),
        path: target,
        fine_partition_digest: digest(5),
        policy_domain: "d".repeat(64),
        score_bits: value.to_bits(),
    };
    let witness = HybridRoutedDenseWitness {
        binding: HybridRoutedBinding {
            generation: 1,
            generation_digest: digest(6),
            base,
            directory: Some(PrefixSegmentDirectoryRefV2 {
                count: 65,
                global_commit: 90,
                request_digest: "e".repeat(64),
                response_digest: "f".repeat(64),
                content_digest: digest(7),
            }),
            router: DirectoryRouterRefV1 {
                serial: 1,
                global_commit: 100,
                request_digest: "a".repeat(64),
                response_digest: "b".repeat(64),
                receipt_digest: digest(8),
                content_digest: digest(9),
            },
        },
        coverage_count: 66,
        coverage_digest: digest(10),
        recipe_revision: crate::raw_index::dense::graph::routing::types::RECIPE_REVISION.into(),
        quota_revision: ROUTED_QUOTA_REVISION.into(),
        source_profile_digest: digest(11),
        source_space_id: VectorSpaceId::from_uuid(compact(11)).expect("source space"),
        coarse_space_digest: digest(12),
        coarse_space_id: VectorSpaceId::from_uuid(compact(12)).expect("coarse space"),
        covered_dense_commitment: digest(13),
        observed_dense_commitment: digest(14),
        proven_dense_commitment: digest(14),
        base_through: 1,
        covered_through: 3,
        proven_through: 4,
        observed_dense_through: 4,
        raw_through: 4,
        coarse: HybridCoarseObservation {
            has_work: true,
            max_node_reads: 16,
            max_vector_reads: 16,
            max_discovered: 16,
            node_reads: 2,
            vector_reads: 3,
            discovered: 3,
            completion: HybridDensePathCompletion::Complete,
            scores: vec![
                score(20, base_path.clone(), 0.2),
                score(21, segment.clone(), 0.9),
                score(22, segment.clone(), 0.8),
            ],
        },
        selected_paths: vec![segment, base_path],
        selection_complete: true,
        unvisited_paths: true,
        paths: vec![
            path(HybridDensePathKind::Segment, Some(65), false),
            path(HybridDensePathKind::Base, None, false),
            path(HybridDensePathKind::FreshTail, None, true),
        ],
    };
    let route = HybridRouteObservation {
        route: HybridRouteKind::Dense,
        admitted_sources: BTreeSet::new(),
        ranked_sources: 0,
        completion: HybridCompletion::Complete,
        source_coverage_incomplete: false,
        raw_lag: false,
        dense_lag: false,
        tail_witness_complete: true,
        tail_scoring_complete: true,
        node_reads: 4,
        vector_reads: 6,
        discovered: 6,
        tail_vector_reads: 1,
        dense_witness: None,
        segmented_dense_witness: None,
        routed_dense_witness: None,
    };
    let intent = OwnedHybridIntent {
        call_id: ModelCallId::new(),
        request_event: ObservationId::new(),
        interaction_sequence: 1,
        attempt: 0,
        limits: OwnedHybridLimits {
            routed: Some(OwnedRoutedLimits {
                max_fine_paths: 2,
                coarse_node_reads: 16,
                coarse_vector_reads: 16,
                coarse_discovered: 16,
                coarse_ef_search: 16,
            }),
            ..Default::default()
        },
    };
    (witness, route, intent)
}

#[test]
fn actual_score_order_can_select_ordinal_65_then_base_without_prefix_reinterpretation() {
    let (mut witness, route, intent) = fixture();
    witness
        .validate(&route, &intent, 10, &mut budget())
        .expect("arbitrary actual ranked paths");
    witness.selected_paths.swap(0, 1);
    assert_eq!(
        witness
            .validate(&route, &intent, 10, &mut budget())
            .expect_err("rank order")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn normal_target_beam_keeps_local_complete_and_unvisited_paths_explicit() {
    let (mut witness, mut route, mut intent) = fixture();
    intent
        .limits
        .routed
        .as_mut()
        .expect("routed")
        .max_fine_paths = 1;
    witness.selected_paths.pop();
    witness.paths.remove(1);
    witness.selection_complete = false;
    route.node_reads -= 1;
    route.vector_reads -= 1;
    route.discovered -= 1;
    witness
        .validate(&route, &intent, 10, &mut budget())
        .expect("beam is ordinary retrieval");
    witness.selection_complete = true;
    assert!(
        witness
            .validate(&route, &intent, 10, &mut budget())
            .is_err()
    );
}

#[test]
fn unused_assignments_recycle_but_actual_coarse_fine_fresh_counts_share_one_cap() {
    let (mut witness, route, intent) = fixture();
    for path in &mut witness.paths {
        path.max_vector_reads = 240;
        path.max_discovered = 240;
    }
    witness
        .validate(&route, &intent, 10, &mut budget())
        .expect("sum assigned can exceed total");
    witness.paths[0].max_vector_reads = 254;
    assert!(
        witness
            .validate(&route, &intent, 10, &mut budget())
            .is_err()
    );
    let (mut witness, route, intent) = fixture();
    witness.coarse.scores[2].representation_id = witness.coarse.scores[1].representation_id;
    assert!(
        witness
            .validate(&route, &intent, 10, &mut budget())
            .is_err()
    );
}

#[test]
fn base_only_needs_no_fabricated_directory_and_decoder_refuses_unbounded_scores() {
    let (mut witness, mut route, intent) = fixture();
    witness.binding.directory = None;
    witness.coverage_count = 1;
    witness.covered_through = witness.base_through;
    witness.selected_paths.remove(0);
    witness.paths.remove(0);
    witness.unvisited_paths = false;
    witness
        .coarse
        .scores
        .retain(|score| matches!(score.path, DirectoryRouterFinePathV1::Base { .. }));
    witness.coarse.vector_reads = 1;
    witness.coarse.discovered = 1;
    route.node_reads -= 1;
    route.vector_reads -= 3;
    route.discovered -= 3;
    witness
        .validate(&route, &intent, 10, &mut budget())
        .expect("base-only owner shape");
    let one = serde_json::to_string(&witness.coarse.scores[0]).expect("score");
    let oversized = format!(
        "[{}]",
        std::iter::repeat_n(one, 4097).collect::<Vec<_>>().join(",")
    );
    let mut deserializer = serde_json::Deserializer::from_str(&oversized);
    assert!(scores(&mut deserializer).is_err());
}
