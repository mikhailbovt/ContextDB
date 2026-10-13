//! Owner-admitted per-step query processing. No callback is a storage lease.

use super::fusion::{SourceRoute, SourceRouteInput};
use super::*;
use crate::owned::OwnedQueryAdmission;
use crate::router_trace::hybrid::routed::ROUTED_HYBRID_OBSERVATION_REVISION;
use crate::router_trace::hybrid::segments::SEGMENTED_HYBRID_OBSERVATION_REVISION;
use crate::router_trace::hybrid::{
    HYBRID_OBSERVATION_REVISION, HybridCompletion, HybridDenseWitness, HybridPreflightObservation,
    HybridRouteKind, HybridRouteObservation, HybridRouteRank, HybridSelectedSource,
    HybridVectorReceipt, OwnedHybridObservation,
};
use contextdb_service::{
    CaptureReceipt, DENSE_QUERY_PREFLIGHT_BYTE_LIMITS, DenseQueryCues, EmbeddedText,
    EmbeddingTextKind, OwnedHybridIntent, RawBm25Query, TextEmbeddingAdapter, TextEmbeddingProfile,
    TokenizedText, dense_step_query_with_byte_limit,
};

pub(super) struct OwnedHybridGuard {
    context: AuthenticatedRequestContext,
    context_cost: crate::budgeted::auth::ContextCost,
    principal: String,
    checkpoint: CaptureReceipt,
    model_profile: ModelProfile,
    intent: OwnedHybridIntent,
    checkpoint_digest: ContentDigest,
    fence: PrepareFence,
    profile: TextEmbeddingProfile,
    graph_digest: ContentDigest,
    segmented_view:
        Option<crate::raw_index::dense::graph::segments::query::VerifiedSegmentQueryView>,
    routed_view: Option<crate::raw_index::dense::graph::routing::query::VerifiedRoutedQueryView>,
}
impl std::fmt::Debug for OwnedHybridGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedHybridGuard")
            .field("checkpoint_digest", &self.checkpoint_digest)
            .field("graph_digest", &self.graph_digest)
            .field(
                "segmented_view",
                &self.segmented_view.as_ref().map(|view| view.identity()),
            )
            .field(
                "routed_view",
                &self.routed_view.as_ref().map(|view| view.identity()),
            )
            .finish_non_exhaustive()
    }
}

pub(super) struct OwnedHybridQuery {
    pub guard: OwnedHybridGuard,
    pub admission: OwnedQueryAdmission,
    pub input_base_digest: ContentDigest,
    pub profile: TextEmbeddingProfile,
    pub preflights: Vec<(usize, DenseQueryCues, TokenizedText)>,
    pub embedded: EmbeddedText,
    pub lexical: Option<RawBm25Query>,
    pub lexical_omitted_terms: u64,
}

pub(super) struct OwnedHybridDiscovery {
    pub hits: Vec<contextdb_recall::IndexedHit>,
    pub frontier: BTreeSet<contextdb_core::ObservationId>,
    pub priors: BTreeMap<contextdb_core::ObservationId, u64>,
    pub bm25: Option<contextdb_service::RawBm25Page>,
    pub observation: OwnedHybridObservation,
    pub incomplete: bool,
}

impl OwnedHybridQuery {
    pub fn cues(&self) -> &DenseQueryCues {
        &self
            .preflights
            .last()
            .expect("a final exact preflight is required")
            .1
    }
    pub fn intent(&self) -> &OwnedHybridIntent {
        &self.guard.intent
    }
}

impl NativeService {
    pub(super) fn discover_owned_hybrid_query(
        &self,
        request: &PrepareContextRequest,
        query: &OwnedHybridQuery,
        budget: &mut QueryBudget,
    ) -> ServiceResult<OwnedHybridDiscovery> {
        self.check_owned_hybrid_guard(&query.guard, budget)?;
        let provider = self.indexed_recall_provider(&request.context);
        let view = provider.open_bm25_view(Some(query.guard.fence.known_at), budget)?;
        let (bm25, lexical_hits, lexical_frontier) = if let Some(lexical) = &query.lexical {
            let discovered = provider.bm25_candidates_with_frontier(&view, lexical, budget)?;
            budget
                .charge(1, discovered.page.hits.len() as u64 * 4096)
                .map_err(budget_error)?;
            let hits = discovered
                .page
                .hits
                .iter()
                .map(|hit| contextdb_recall::IndexedHit {
                    source: hit.source.clone(),
                    matches: hit.matches.clone(),
                })
                .collect::<Vec<_>>();
            (Some(discovered.page), hits, discovered.admitted_sources)
        } else {
            (None, Vec::new(), BTreeMap::new())
        };
        let mut lexical_observation = route_observation(
            HybridRouteKind::Bm25,
            &lexical_frontier,
            &lexical_hits,
            budget,
        )?;
        lexical_observation.source_coverage_incomplete = query.lexical_omitted_terms > 0;
        if let Some(page) = &bm25 {
            lexical_observation.completion = match page.completion {
                contextdb_service::RawBm25Completion::Complete => HybridCompletion::Complete,
                contextdb_service::RawBm25Completion::RankedLimit => HybridCompletion::RankedLimit,
                contextdb_service::RawBm25Completion::PostingLimit => {
                    HybridCompletion::PostingLimit
                }
                contextdb_service::RawBm25Completion::WorkLimit => HybridCompletion::WorkLimit,
                contextdb_service::RawBm25Completion::ByteLimit => HybridCompletion::ByteLimit,
            };
            lexical_observation.source_coverage_incomplete |=
                page.profile_status != contextdb_service::RawBm25ProfileStatus::Supported;
            lexical_observation.raw_lag =
                page.profile_status == contextdb_service::RawBm25ProfileStatus::TailOverflow;
        }
        self.check_owned_hybrid_guard(&query.guard, budget)?;
        let limits = query.intent().limits;
        let (dense_hits, dense_frontier, dense_observation) = if let Some(routed) = limits.routed {
            let pinned = query
                .guard
                .routed_view
                .as_ref()
                .ok_or_else(|| stale("owned routed query admission absent"))?;
            let mut dense = self.search_original_spans_routed_in_view(
                &request.context,
                &query.cues().text,
                &query.embedded,
                crate::DenseRoutedQueryLimits {
                    graph: crate::DenseGraphQueryLimits {
                        limit: limits.sources as usize,
                        max_node_reads: limits.node_reads as usize,
                        max_vector_reads: limits.vector_reads as usize,
                        max_discovered: limits.discovered as usize,
                        ef_search: limits.ef_search as usize,
                    },
                    max_fine_paths: routed.max_fine_paths as usize,
                    coarse_node_reads: routed.coarse_node_reads as usize,
                    coarse_vector_reads: routed.coarse_vector_reads as usize,
                    coarse_discovered: routed.coarse_discovered as usize,
                    coarse_ef_search: routed.coarse_ef_search as usize,
                    max_tail_work: limits.tail_work as usize,
                    max_tail_vectors: limits.tail_vectors as usize,
                },
                pinned,
                budget,
            )?;
            if dense.view_identity != pinned.identity() {
                return Err(stale("owned routed search differs from the callback view"));
            }
            let hits = segmented_source_hits(std::mem::take(&mut dense.hits), budget)?;
            let frontier = std::mem::take(&mut dense.admitted_sources);
            let mut observation =
                route_observation(HybridRouteKind::Dense, &frontier, &hits, budget)?;
            observation.completion = match dense.completion {
                crate::DenseRoutedQueryCompletion::Complete => HybridCompletion::Complete,
                crate::DenseRoutedQueryCompletion::TailWorkLimit => HybridCompletion::TailWorkLimit,
                crate::DenseRoutedQueryCompletion::TailVectorLimit => {
                    HybridCompletion::TailVectorLimit
                }
                crate::DenseRoutedQueryCompletion::NodeLimit => HybridCompletion::BaseLimit,
                crate::DenseRoutedQueryCompletion::VectorLimit => HybridCompletion::VectorLimit,
                crate::DenseRoutedQueryCompletion::DiscoveryLimit => {
                    HybridCompletion::DiscoveryLimit
                }
                crate::DenseRoutedQueryCompletion::DenseLag => HybridCompletion::DenseLag,
                crate::DenseRoutedQueryCompletion::RawLag => HybridCompletion::RawLag,
            };
            observation.source_coverage_incomplete = dense.permitted_tail_omissions
                || dense.completion != crate::DenseRoutedQueryCompletion::Complete;
            observation.raw_lag = dense.raw_lag;
            observation.dense_lag = dense.dense_lag;
            observation.tail_witness_complete = dense.tail_witness_complete;
            observation.tail_scoring_complete = dense.tail_scoring_complete;
            observation.node_reads = dense.node_reads;
            observation.vector_reads = dense.vector_reads;
            observation.discovered = dense.discovered;
            observation.tail_vector_reads = dense.tail_vector_reads;
            observation.routed_dense_witness = Some(dense.witness);
            (hits, frontier, observation)
        } else if let Some(segments) = limits.segments {
            let mut dense = self.search_original_spans_segmented(
                &request.context,
                &query.cues().text,
                &query.embedded,
                crate::DenseSegmentQueryLimits {
                    graph: crate::DenseGraphQueryLimits {
                        limit: limits.sources as usize,
                        max_node_reads: limits.node_reads as usize,
                        max_vector_reads: limits.vector_reads as usize,
                        max_discovered: limits.discovered as usize,
                        ef_search: limits.ef_search as usize,
                    },
                    max_segments: segments.max_segments as usize,
                    max_tail_work: limits.tail_work as usize,
                    max_tail_vectors: limits.tail_vectors as usize,
                },
                budget,
            )?;
            let hits = segmented_source_hits(std::mem::take(&mut dense.hits), budget)?;
            let frontier = std::mem::take(&mut dense.admitted_sources);
            let mut observation =
                route_observation(HybridRouteKind::Dense, &frontier, &hits, budget)?;
            observation.completion = match dense.completion {
                crate::DenseSegmentQueryCompletion::Complete => HybridCompletion::Complete,
                crate::DenseSegmentQueryCompletion::SegmentSelectionLimit => {
                    HybridCompletion::SegmentSelectionLimit
                }
                crate::DenseSegmentQueryCompletion::TailWorkLimit => {
                    HybridCompletion::TailWorkLimit
                }
                crate::DenseSegmentQueryCompletion::TailVectorLimit => {
                    HybridCompletion::TailVectorLimit
                }
                crate::DenseSegmentQueryCompletion::NodeLimit => HybridCompletion::BaseLimit,
                crate::DenseSegmentQueryCompletion::VectorLimit => HybridCompletion::VectorLimit,
                crate::DenseSegmentQueryCompletion::DiscoveryLimit => {
                    HybridCompletion::DiscoveryLimit
                }
                crate::DenseSegmentQueryCompletion::DenseLag => HybridCompletion::DenseLag,
                crate::DenseSegmentQueryCompletion::RawLag => HybridCompletion::RawLag,
            };
            observation.source_coverage_incomplete = dense.permitted_tail_omissions
                || dense.completion != crate::DenseSegmentQueryCompletion::Complete;
            observation.raw_lag = dense.raw_lag;
            observation.dense_lag = dense.dense_lag;
            observation.tail_witness_complete = dense.tail_witness_complete;
            observation.tail_scoring_complete = dense.tail_scoring_complete;
            observation.node_reads = dense.node_reads;
            observation.vector_reads = dense.vector_reads;
            observation.discovered = dense.discovered;
            observation.tail_vector_reads = dense.tail_vector_reads;
            observation.segmented_dense_witness = Some(dense.witness);
            (hits, frontier, observation)
        } else {
            let mut dense = self.search_original_spans_with_tail(
                &request.context,
                &query.cues().text,
                &query.embedded,
                crate::DenseGraphTailQueryLimits {
                    graph: crate::DenseGraphQueryLimits {
                        limit: limits.sources as usize,
                        max_node_reads: limits.node_reads as usize,
                        max_vector_reads: limits.vector_reads as usize,
                        max_discovered: limits.discovered as usize,
                        ef_search: limits.ef_search as usize,
                    },
                    max_tail_work: limits.tail_work as usize,
                    max_tail_vectors: limits.tail_vectors as usize,
                },
                budget,
            )?;
            // Move exact source/span observations; vectors and compact ANN IDs are
            // already authenticated by the owner query and never grant disclosure.
            budget
                .charge(1, dense.hits.len() as u64 * 512)
                .map_err(budget_error)?;
            let dense_hits = std::mem::take(&mut dense.hits)
                .into_iter()
                .map(|hit| contextdb_recall::IndexedHit {
                    source: hit.source,
                    matches: vec![hit.span],
                })
                .collect::<Vec<_>>();
            let dense_frontier = std::mem::take(&mut dense.admitted_sources);
            let mut dense_observation =
                route_observation(HybridRouteKind::Dense, &dense_frontier, &dense_hits, budget)?;
            dense_observation.completion = match dense.completion {
                crate::DenseGraphTailCompletion::Complete => HybridCompletion::Complete,
                crate::DenseGraphTailCompletion::DenseLag => HybridCompletion::DenseLag,
                crate::DenseGraphTailCompletion::RawLag => HybridCompletion::RawLag,
                crate::DenseGraphTailCompletion::TailWorkLimit => HybridCompletion::TailWorkLimit,
                crate::DenseGraphTailCompletion::TailVectorLimit => {
                    HybridCompletion::TailVectorLimit
                }
                crate::DenseGraphTailCompletion::VectorLimit => HybridCompletion::VectorLimit,
                crate::DenseGraphTailCompletion::DiscoveryLimit => HybridCompletion::DiscoveryLimit,
                crate::DenseGraphTailCompletion::BaseLimit => HybridCompletion::BaseLimit,
            };
            dense_observation.source_coverage_incomplete = dense.permitted_tail_omissions;
            dense_observation.raw_lag = dense.raw_lag;
            dense_observation.dense_lag = dense.dense_lag;
            dense_observation.tail_witness_complete = dense.tail_witness_complete;
            dense_observation.tail_scoring_complete = dense.tail_scoring_complete;
            dense_observation.node_reads = dense.node_reads;
            dense_observation.vector_reads = dense.vector_reads;
            dense_observation.discovered = dense.discovered;
            dense_observation.tail_vector_reads = dense.tail_vector_reads;
            dense_observation.dense_witness = Some(HybridDenseWitness {
                graph_digest: dense.graph_digest,
                observed_dense_commitment: dense.observed_dense_commitment,
                proven_dense_commitment: dense.proven_dense_commitment,
                base_through: dense.base_through,
                observed_dense_through: dense.observed_dense_through,
                proven_through: dense.proven_through,
                raw_through: dense.raw_through,
            });
            (dense_hits, dense_frontier, dense_observation)
        };

        // Eight fixed owner-admitted seeds: sampled current/working originals,
        // then lexical rank and dense rank. No unprojected version is invented.
        // A bounded one-hop route is not a guarantee of associative recall.
        budget.charge(1, 128 * 1024).map_err(budget_error)?;
        let mut seed_ids = BTreeSet::new();
        let mut current_ids = Vec::with_capacity(8);
        for fragment in &query.cues().fragments {
            if current_ids.len() == 8 {
                break;
            }
            let source = fragment
                .source
                .as_ref()
                .ok_or_else(|| invalid("owned causal seed source absent"))?;
            if seed_ids.insert(source.event_id) {
                current_ids.push(source.event_id);
            }
        }
        self.check_owned_hybrid_guard(&query.guard, budget)?;
        let current_seeds = provider.causal_owned_query_seeds(&view, &current_ids, budget)?;
        let mut seeds = current_seeds.seeds;
        seeds.reserve(8 - seeds.len());
        for hit in lexical_hits.iter().chain(&dense_hits) {
            if seeds.len() == 8 {
                break;
            }
            if seed_ids.insert(hit.source.event_id) {
                let version = hit.source.source_version.as_ref().map_or(0, String::len);
                budget
                    .charge(1, 1024 + version as u64 * 4)
                    .map_err(budget_error)?;
                seeds.push(hit.source.clone());
            }
        }
        self.check_owned_hybrid_guard(&query.guard, budget)?;
        let causal = provider.causal_candidates(&view, &seeds, budget)?;
        let mut causal_observation = route_observation(
            HybridRouteKind::Causal,
            &causal.admitted_sources,
            &causal.hits,
            budget,
        )?;
        causal_observation.completion = match causal.completion {
            crate::indexed_provider::CausalCompletion::Complete => HybridCompletion::Complete,
            crate::indexed_provider::CausalCompletion::RawLag => HybridCompletion::RawLag,
            crate::indexed_provider::CausalCompletion::UnprojectedSource => {
                HybridCompletion::UnprojectedSource
            }
            crate::indexed_provider::CausalCompletion::CandidateLimit => {
                HybridCompletion::CandidateLimit
            }
            crate::indexed_provider::CausalCompletion::PostingLimit => {
                HybridCompletion::PostingLimit
            }
            crate::indexed_provider::CausalCompletion::WorkLimit => HybridCompletion::WorkLimit,
            crate::indexed_provider::CausalCompletion::ByteLimit => HybridCompletion::ByteLimit,
            crate::indexed_provider::CausalCompletion::UnsupportedProfile => {
                HybridCompletion::UnsupportedProfile
            }
        };
        causal_observation.raw_lag = causal.raw_lag;
        causal_observation.source_coverage_incomplete =
            causal.source_coverage_incomplete || current_seeds.unprojected;
        if current_seeds.unprojected && causal_observation.completion == HybridCompletion::Complete
        {
            causal_observation.completion = HybridCompletion::UnprojectedSource;
        }
        let fusion = fusion::fuse_sources(
            vec![
                SourceRouteInput {
                    route: SourceRoute::Bm25,
                    hits: lexical_hits,
                    admitted_sources: lexical_frontier,
                },
                SourceRouteInput {
                    route: SourceRoute::Dense,
                    hits: dense_hits,
                    admitted_sources: dense_frontier,
                },
                SourceRouteInput {
                    route: SourceRoute::Causal,
                    hits: causal.hits,
                    admitted_sources: causal.admitted_sources,
                },
            ],
            limits.sources,
            budget,
        )?;
        budget.charge(1, 512 * 1024).map_err(budget_error)?;
        let mut frontier: BTreeSet<_> = fusion.admitted_sources.into_keys().collect();
        for (_, cues, _) in &query.preflights {
            for fragment in &cues.fragments {
                let source = fragment
                    .source
                    .as_ref()
                    .ok_or_else(|| invalid("accepted query source absent"))?;
                frontier.insert(source.event_id);
                if frontier.len() > 256 {
                    return Err(crate::exhausted(
                        "hybrid query plus route frontier exceeds 256 sources",
                    ));
                }
            }
        }
        let mut hits = Vec::with_capacity(fusion.selected.len());
        let mut priors = BTreeMap::new();
        let mut selected = Vec::with_capacity(fusion.selected.len());
        for source in fusion.selected {
            let id = source.hit.source.event_id;
            // Existing R0 utility begins at one million. RRF is a small fixed
            // routing preference, not a calibrated usefulness probability.
            priors.insert(
                id,
                1_000_000_u64
                    .checked_add(source.routing_micros)
                    .ok_or_else(|| crate::exhausted("hybrid routing prior overflows"))?,
            );
            selected.push(HybridSelectedSource {
                event_id: id,
                routing_micros: source.routing_micros,
                route_ranks: source
                    .route_ranks
                    .into_iter()
                    .map(|rank| HybridRouteRank {
                        route: route_kind(rank.route),
                        rank: rank.rank,
                    })
                    .collect(),
            });
            hits.push(source.hit);
        }
        let routes = vec![lexical_observation, dense_observation, causal_observation];
        let incomplete = fusion.ranked_out
            || routes.iter().any(|route| {
                route.completion != HybridCompletion::Complete || route.source_coverage_incomplete
            });
        let mut preflights = Vec::with_capacity(query.preflights.len());
        for (limit, cues, tokens) in &query.preflights {
            preflights.push(HybridPreflightObservation::from_sample(
                *limit as u32,
                cues,
                tokens.clone(),
                budget,
            )?);
        }
        let observation = OwnedHybridObservation {
            revision: if limits.routed.is_some() {
                ROUTED_HYBRID_OBSERVATION_REVISION
            } else if limits.segments.is_some() {
                SEGMENTED_HYBRID_OBSERVATION_REVISION
            } else {
                HYBRID_OBSERVATION_REVISION
            }
            .into(),
            intent: query.intent().clone(),
            checkpoint_receipt: query.guard.checkpoint.clone(),
            checkpoint_digest: query.admission.checkpoint_digest,
            checkpoint_revision: query.admission.checkpoint.revision,
            pack_id: request.pack_id,
            known_at: query.guard.fence.known_at,
            authorization_epoch: query.guard.fence.authorization_epoch,
            input_base_digest: query.input_base_digest,
            base_digest: query.input_base_digest,
            embedding_profile: query.profile.clone(),
            profile_digest: query.embedded.profile_digest,
            sampler_revision: contextdb_service::DENSE_QUERY_REFINEMENT_REVISION.into(),
            fusion_revision: fusion.revision.into(),
            preflights,
            vector: HybridVectorReceipt::from_embedded(&query.embedded, budget)?,
            routes,
            selected,
            ranked_out: fusion.ranked_out,
        };
        self.check_owned_hybrid_guard(&query.guard, budget)?;
        Ok(OwnedHybridDiscovery {
            hits,
            frontier,
            priors,
            bm25,
            observation,
            incomplete,
        })
    }

    pub(super) fn check_owned_hybrid_guard(
        &self,
        guard: &OwnedHybridGuard,
        budget: &mut QueryBudget,
    ) -> ServiceResult<OwnedQueryAdmission> {
        budget.charge(1, 16384).map_err(budget_error)?;
        guard.context_cost.require_capability(
            &guard.context,
            Capability::ModelProcessing,
            budget,
        )?;
        // The context is immutable and owner-private. Its exact binding was
        // computed and charged before cloning it into this guard.
        if guard.principal != guard.fence.principal
            || self.preparation_wall_time()? >= guard.fence.valid_until
        {
            return Err(stale("owned query principal or validity changed"));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(guard.context.request.workspace_id.as_bytes());
        crate::budgeted::metadata(&snapshot, budget, |reader| {
            // The legacy prepare fence checks epochs, not the actual journal.
            // Query processing additionally pins the accepted workspace head.
            self.validate_prepare_epochs_in(reader, &guard.context, &guard.fence)
        })?;
        crate::budgeted::metadata(&snapshot, budget, |reader| {
            self.require_custody_ready(reader, &workspace)?;
            let state = self.workspace_state(reader, &guard.context.request.workspace_id)?;
            if state.watermarks.journal != guard.fence.known_at {
                return Err(stale("owned query workspace advanced during preparation"));
            }
            Ok(())
        })?;
        let admission = self.admit_owned_query(
            &snapshot,
            &guard.context,
            &guard.checkpoint,
            &guard.model_profile,
            guard.intent.call_id,
            guard.intent.request_event,
            guard.intent.interaction_sequence,
            budget,
        )?;
        if admission.checkpoint_digest != guard.checkpoint_digest {
            return Err(stale("owned query checkpoint changed during preparation"));
        }
        if guard.intent.limits.segments.is_some() != guard.segmented_view.is_some() {
            return Err(stale(
                "owned query segmented admission differs from its intent",
            ));
        }
        if guard.intent.limits.routed.is_some() != guard.routed_view.is_some() {
            return Err(stale(
                "owned query routed admission differs from its intent",
            ));
        }
        let graph_digest = if let Some(view) = &guard.routed_view {
            self.check_routed_query_view(&guard.context, view, budget)?;
            guard.graph_digest
        } else if let Some(view) = &guard.segmented_view {
            self.check_segment_query_view(&guard.context, view, budget)?;
            guard.graph_digest
        } else {
            self.admit_owned_query_embedding_profile(&guard.context, &guard.profile, budget)?
        };
        if graph_digest != guard.graph_digest {
            return Err(stale(
                "owned query immutable graph changed during preparation",
            ));
        }
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&current, budget, |reader| {
            self.validate_prepare_epochs_in(reader, &guard.context, &guard.fence)?;
            self.require_custody_ready(reader, &workspace)?;
            if self
                .workspace_state(reader, &guard.context.request.workspace_id)?
                .watermarks
                .journal
                != guard.fence.known_at
            {
                return Err(stale(
                    "owned query workspace advanced before a processing callback",
                ));
            }
            Ok(())
        })?;
        budget.check().map_err(budget_error)?;
        Ok(admission)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The native handoff pins its actual preparation snapshot and serving view"
    )]
    pub(super) fn encode_owned_hybrid_query(
        &self,
        request: &PrepareContextRequest,
        fence: &PrepareFence,
        intent: OwnedHybridIntent,
        encoder: &dyn TextEmbeddingAdapter,
        admitted_routed_view: Option<
            crate::raw_index::dense::graph::routing::query::VerifiedRoutedQueryView,
        >,
        preparation_snapshot: &crate::encryption::NativeSnapshot,
        budget: &mut QueryBudget,
    ) -> ServiceResult<OwnedHybridQuery> {
        // Encoder settings are fixed native metadata, never caller vector data.
        encoder.profile().validate()?;
        budget.charge(1, 65536).map_err(budget_error)?;
        let profile = encoder.profile().clone();
        let checkpoint = request
            .after_receipt
            .as_ref()
            .ok_or_else(|| invalid("owned query checkpoint absent"))?;
        let fresh_snapshot;
        let snapshot = if admitted_routed_view.is_some() {
            preparation_snapshot
        } else {
            fresh_snapshot = self
                .engine
                .begin_read(SnapshotSelector::Latest)
                .map_err(storage_error)?;
            &fresh_snapshot
        };
        let admission = self.admit_owned_query(
            snapshot,
            &request.context,
            checkpoint,
            &request.model_profile,
            intent.call_id,
            intent.request_event,
            intent.interaction_sequence,
            budget,
        )?;
        self.validate_owned_query_base(&admission, &request.base, budget)?;
        if request.base.control.iter().any(|message| {
            matches!(
                message.id.as_str(),
                "contextdb.bm25-discovery-status.v1" | "contextdb.hybrid-discovery-status.v1"
            )
        }) {
            return Err(invalid(
                "owned query base uses a reserved native status identity",
            ));
        }
        intent.limits.validate()?;
        let (graph_digest, segmented_view, routed_view) = if intent.limits.routed.is_some() {
            let (graph, view) = if let Some(view) = admitted_routed_view {
                if view.known_at() != fence.known_at {
                    return Err(stale(
                        "owned routed handoff differs from preparation knowledge",
                    ));
                }
                self.check_owned_routed_query_embedding_profile(&profile, &view, budget)?;
                self.check_routed_query_view(&request.context, &view, budget)?;
                (view.identity(), view)
            } else {
                self.admit_owned_routed_query_embedding_profile(&request.context, &profile, budget)?
            };
            (graph, None, Some(view))
        } else if intent.limits.segments.is_some() {
            let (graph, view) = self.admit_owned_segmented_query_embedding_profile(
                &request.context,
                &profile,
                budget,
            )?;
            (graph, Some(view), None)
        } else {
            (
                self.admit_owned_query_embedding_profile(&request.context, &profile, budget)?,
                None,
                None,
            )
        };
        let context_cost =
            crate::budgeted::auth::ContextCost::for_context(&request.context, budget)?;
        let principal = context_cost.binding_digest(&request.context, budget)?;
        if principal != fence.principal {
            return Err(stale("owned query caller binding changed"));
        }
        let guard = OwnedHybridGuard {
            context: context_cost.clone_context(&request.context, budget)?,
            context_cost,
            principal,
            checkpoint: checkpoint.clone(),
            model_profile: request.model_profile.clone(),
            intent,
            checkpoint_digest: admission.checkpoint_digest,
            fence: fence.clone(),
            profile: profile.clone(),
            graph_digest,
            segmented_view,
            routed_view,
        };
        let input_base_digest =
            router::canonical_digest(&request.base, budget).map_err(service_error)?;
        budget
            .charge(
                1,
                4 * size_of::<(usize, DenseQueryCues, TokenizedText)>() as u64,
            )
            .map_err(budget_error)?;
        let mut preflights = Vec::with_capacity(4);
        for byte_limit in DENSE_QUERY_PREFLIGHT_BYTE_LIMITS {
            let cues = dense_step_query_with_byte_limit(&request.base, byte_limit, budget)?;
            if cues.text.is_empty() || cues.fragments.is_empty() {
                return Err(invalid(
                    "owned query has no source-backed current observations",
                ));
            }
            let current = self.check_owned_hybrid_guard(&guard, budget)?;
            self.prove_owned_query_sample(
                &current,
                &request.base,
                &request.context,
                &cues,
                budget,
            )?;
            self.check_owned_hybrid_guard(&guard, budget)?;
            ensure_profile(encoder, &profile, budget)?;
            let measured = encoder.measure_tokens(EmbeddingTextKind::Query, &cues.text, budget)?;
            // A callback can mutate external state. Re-admit before interpreting
            // or using its result, with this exact original parent allowance.
            self.check_owned_hybrid_guard(&guard, budget)?;
            ensure_profile(encoder, &profile, budget)?;
            measured.validate(&profile, EmbeddingTextKind::Query, &cues.text, budget)?;
            let fits = measured.fits_inference_limit(&profile, budget)?;
            preflights.push((byte_limit, cues, measured));
            if fits {
                break;
            }
        }
        let (_, final_cues, measured) = preflights
            .last()
            .ok_or_else(|| invalid("owned query preflight absent"))?;
        if !measured.fits_inference_limit(&profile, budget)? {
            return Err(ServiceError::new(
                contextdb_service::ErrorCode::ResourceExhausted,
                "owned query cannot fit the declared finite tokenizer refinements",
                false,
            ));
        }
        let current = self.check_owned_hybrid_guard(&guard, budget)?;
        self.prove_owned_query_sample(
            &current,
            &request.base,
            &request.context,
            final_cues,
            budget,
        )?;
        self.check_owned_hybrid_guard(&guard, budget)?;
        ensure_profile(encoder, &profile, budget)?;
        // Exactly one final forward. No failed-forward capacity probe or retry.
        let embedded = encoder.embed(EmbeddingTextKind::Query, &final_cues.text, budget)?;
        self.check_owned_hybrid_guard(&guard, budget)?;
        ensure_profile(encoder, &profile, budget)?;
        embedded.validate(&profile, EmbeddingTextKind::Query, &final_cues.text, budget)?;
        if embedded.token_count != measured.token_count
            || embedded.tokens_digest != measured.tokens_digest
            || embedded.input_digest != measured.input_digest
            || embedded.text_digest != measured.text_digest
            || embedded.profile_digest != measured.profile_digest
        {
            return Err(invalid(
                "owned query forward differs from its exact tokenizer preflight",
            ));
        }
        let (lexical, lexical_omitted_terms) =
            lexical_query(final_cues, guard.intent.limits.sources, budget)?;
        Ok(OwnedHybridQuery {
            guard,
            admission,
            input_base_digest,
            profile,
            preflights,
            embedded,
            lexical,
            lexical_omitted_terms,
        })
    }

    fn prove_owned_query_sample(
        &self,
        admission: &OwnedQueryAdmission,
        base: &OutgoingBase,
        context: &AuthenticatedRequestContext,
        cues: &DenseQueryCues,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.validate_owned_query_base(admission, base, budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        for fragment in &cues.fragments {
            budget.charge(1, 0).map_err(budget_error)?;
            let message = base
                .current
                .iter()
                .chain(&base.working)
                .find(|message| message.id == fragment.message_id)
                .ok_or_else(|| invalid("owned query fragment message absent"))?;
            self.validate_owned_query_source(
                admission,
                &message.id,
                message.zone,
                message.role,
                fragment.source.as_ref(),
                budget,
            )?;
            let source = fragment
                .source
                .as_ref()
                .ok_or_else(|| invalid("owned query fragment source absent"))?;
            let selected = message
                .text
                .get(fragment.message_start as usize..fragment.message_end as usize)
                .ok_or_else(|| invalid("owned query message excerpt is not UTF-8"))?;
            let query_part = cues
                .text
                .get(fragment.query_start as usize..fragment.query_end as usize)
                .ok_or_else(|| invalid("owned query sampled excerpt is not UTF-8"))?;
            if selected != query_part
                || ContentDigest::from_bytes(*blake3::hash(selected.as_bytes()).as_bytes())
                    != source.span_digest
                || source.end.checked_sub(source.start) != Some(selected.len() as u64)
            {
                return Err(invalid(
                    "owned query rendering does not match its original range",
                ));
            }
            let admitted =
                self.admit_captured_original(&snapshot, context, source.event_id, budget)?;
            let bytes =
                self.source_span_from_authorized_original(&admitted, source, false, budget)?;
            if bytes != selected.as_bytes() {
                return Err(invalid(
                    "owned query selected text differs from captured bytes",
                ));
            }
        }
        budget.check().map_err(budget_error)
    }
}

fn ensure_profile(
    encoder: &dyn TextEmbeddingAdapter,
    profile: &TextEmbeddingProfile,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    budget.charge(1, 16384).map_err(budget_error)?;
    encoder.profile().validate()?;
    if encoder.profile() != profile {
        return Err(invalid("owned query encoder profile changed"));
    }
    Ok(())
}

fn route_kind(route: SourceRoute) -> HybridRouteKind {
    match route {
        SourceRoute::Bm25 => HybridRouteKind::Bm25,
        SourceRoute::Dense => HybridRouteKind::Dense,
        SourceRoute::Causal => HybridRouteKind::Causal,
    }
}

/// Preserve the first (best) global dense rank while retaining every scored
/// span of that source. Fusion consumes sources, rather than counting spans as
/// independent candidates or additional segment votes.
fn segmented_source_hits(
    hits: Vec<crate::DenseGraphHit>,
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<contextdb_recall::IndexedHit>> {
    if hits.len() > 4096 {
        return Err(crate::exhausted(
            "segmented owned span observations exceed the query cap",
        ));
    }
    let sources = hits.len().min(100);
    let tree_bytes = sources * 2 * (12 * size_of::<(contextdb_core::ObservationId, usize)>() + 512);
    budget
        .charge(
            hits.len() as u64 * 16 + 1,
            (tree_bytes
                + sources * 2 * size_of::<contextdb_recall::IndexedHit>()
                + hits.len() * (4 * size_of::<OriginalSourceSpan>() + 512)) as u64,
        )
        .map_err(budget_error)?;
    let observations = hits
        .into_iter()
        .map(|hit| contextdb_recall::IndexedHit {
            source: hit.source,
            matches: vec![hit.span],
        })
        .collect::<Vec<_>>();
    frontier::union_raw_hits(vec![observations], budget)
}

fn route_observation(
    route: HybridRouteKind,
    sources: &BTreeMap<contextdb_core::ObservationId, RawSource>,
    hits: &[contextdb_recall::IndexedHit],
    budget: &mut QueryBudget,
) -> ServiceResult<HybridRouteObservation> {
    if sources.len() > 256 || hits.len() > 256 {
        return Err(crate::exhausted(
            "hybrid route exceeds the bounded source frontier",
        ));
    }
    budget
        .charge(sources.len() as u64 + hits.len() as u64 + 1, 128 * 1024)
        .map_err(budget_error)?;
    let admitted_sources = sources.keys().copied().collect();
    let ranked_sources: BTreeSet<_> = hits.iter().map(|hit| hit.source.event_id).collect();
    Ok(HybridRouteObservation {
        route,
        admitted_sources,
        ranked_sources: ranked_sources.len() as u32,
        completion: HybridCompletion::Complete,
        source_coverage_incomplete: false,
        raw_lag: false,
        dense_lag: false,
        tail_witness_complete: false,
        tail_scoring_complete: false,
        node_reads: 0,
        vector_reads: 0,
        discovered: 0,
        tail_vector_reads: 0,
        dense_witness: None,
        segmented_dense_witness: None,
        routed_dense_witness: None,
    })
}

/// Fixed lexical sampling of exact cue fragments, excluding host labels/gaps.
/// Additional terms are explicitly observed as omissions; no input is truncated
/// by the BM25 provider or by the neural backend.
fn lexical_query(
    cues: &DenseQueryCues,
    limit: u32,
    budget: &mut QueryBudget,
) -> ServiceResult<(Option<RawBm25Query>, u64)> {
    budget
        .charge(cues.text.len() as u64 + 1, 128 * 1024)
        .map_err(budget_error)?;
    let mut terms = BTreeSet::new();
    let mut bytes = 0_usize;
    let mut omitted = 0_u64;
    for fragment in &cues.fragments {
        let text = cues
            .text
            .get(fragment.query_start as usize..fragment.query_end as usize)
            .ok_or_else(|| invalid("owned lexical cue range invalid"))?;
        for term in text
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|term| !term.is_empty())
        {
            let word = term.to_lowercase();
            if terms.contains(&word) {
                continue;
            }
            if word.len() > 256
                || terms.len() >= contextdb_index::MAX_RAW_QUERY_TERMS
                || bytes + word.len() + 1 > contextdb_index::MAX_RAW_QUERY_BYTES
            {
                omitted += 1;
                continue;
            }
            bytes += word.len() + 1;
            terms.insert(word);
        }
    }
    if terms.is_empty() {
        return Ok((None, omitted));
    }
    let text = terms.into_iter().collect::<Vec<_>>().join(" ");
    Ok((
        Some(RawBm25Query {
            text,
            filter: contextdb_core::RawFilter::default(),
            limit,
        }),
        omitted,
    ))
}

#[cfg(test)]
mod tests;
