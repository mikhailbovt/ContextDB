//! Owner-admitted directory routing and genuine source scoring under one budget.
use super::*;
use crate::raw_index::dense::{DenseDocument, DenseVector};
use crate::router_trace::hybrid::routed::{
    HybridCoarseObservation, HybridCoarseScore, HybridRoutedBinding, HybridRoutedDenseWitness,
    ROUTED_QUOTA_REVISION,
};
use crate::router_trace::hybrid::segments::{
    HybridDensePathCompletion, HybridDensePathKind, HybridDensePathObservation,
};
use contextdb_core::{
    ContentDigest, ObservationId, OriginalSourceSpan, RawSource, RepresentationId,
};
use contextdb_service::{EmbeddedText, EmbeddingTextKind, ServiceError};
use ledger::{Caps, QueryLedger};
use std::mem::size_of;

mod fine;
mod fresh;
mod ledger;
mod reader;
mod recency;
mod selection;
mod traverse;
mod view;
pub(crate) use view::VerifiedRoutedQueryView;

/// Finite traversal allowances shared by routing, fine paths and fresh vectors.
#[derive(Clone, Copy, Debug)]
pub struct DenseRoutedQueryLimits {
    /// Total node/vector/discovery caps and final distinct source limit.
    pub graph: DenseGraphQueryLimits,
    /// Distinct targets selected from actual coarse scores, from one through 64.
    pub max_fine_paths: usize,
    /// Coarse subcap within the total node allowance.
    pub coarse_node_reads: usize,
    /// Coarse subcap within the total vector allowance.
    pub coarse_vector_reads: usize,
    /// Coarse subcap within the total discovery allowance.
    pub coarse_discovered: usize,
    /// Per-coarse-partition best-first beam.
    pub coarse_ef_search: usize,
    /// Complete fresh capture work admitted, from one through 128.
    pub max_tail_work: usize,
    /// Fresh vector subcap, from one through 256.
    pub max_tail_vectors: usize,
}
/// Local stopping status; complete never claims exhaustive semantic recall.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenseRoutedQueryCompletion {
    /// All selected traversals reached their local stopping condition.
    Complete,
    /// The complete fresh interval was not admitted.
    TailWorkLimit,
    /// Permitted fresh vectors reached their declared subcap.
    TailVectorLimit,
    /// A coarse or fine partition reached its assigned node cap.
    NodeLimit,
    /// A coarse, fine or fresh path reached its assigned vector cap.
    VectorLimit,
    /// A coarse, fine or fresh path reached its assigned discovery cap.
    DiscoveryLimit,
    /// Dense projection remains behind raw projection.
    DenseLag,
    /// Accepted capture work remains behind raw projection.
    RawLag,
}
/// Discovery observations with one global dense rank, never a disclosure lease.
#[derive(Clone, PartialEq, Serialize)]
pub struct DenseRoutedQueryResult {
    /// Actual finite fine/fresh span observations for selected distinct sources.
    pub hits: Vec<DenseGraphHit>,
    /// Local traversal status, independent of learned retrieval quality.
    pub completion: DenseRoutedQueryCompletion,
    /// Complete fresh interval admission succeeded.
    pub tail_witness_complete: bool,
    /// All permitted fresh vectors were scored.
    pub tail_scoring_complete: bool,
    /// Current dense projection is behind raw projection.
    pub dense_lag: bool,
    /// Current raw projection is behind accepted work.
    pub raw_lag: bool,
    /// Permitted fresh observations contain omissions or upstream partial bytes.
    pub permitted_tail_omissions: bool,
    /// Total actual node reads, including coarse routing.
    pub node_reads: u64,
    /// Total actual full-vector reads, including coarse routing and fresh work.
    pub vector_reads: u64,
    /// Total actual scored distinct representation discoveries.
    pub discovered: u64,
    /// Actual coarse node reads.
    pub coarse_node_reads: u64,
    /// Actual coarse centroid vector reads.
    pub coarse_vector_reads: u64,
    /// Actual distinct scored coarse identities.
    pub coarse_discovered: u64,
    /// Actual fresh vector reads.
    pub tail_vector_reads: u64,
    #[serde(skip_serializing)]
    pub(crate) view_identity: ContentDigest,
    #[serde(skip_serializing)]
    pub(crate) admitted_sources: BTreeMap<ObservationId, RawSource>,
    #[serde(skip_serializing)]
    pub(crate) witness: HybridRoutedDenseWitness,
}
impl std::fmt::Debug for DenseRoutedQueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DenseRoutedQueryResult")
            .field("hits", &self.hits)
            .field("completion", &self.completion)
            .field("node_reads", &self.node_reads)
            .field("vector_reads", &self.vector_reads)
            .field("coarse_vector_reads", &self.coarse_vector_reads)
            .finish_non_exhaustive()
    }
}
fn validate_limits(limits: DenseRoutedQueryLimits) -> ServiceResult<()> {
    super::super::query::validate_limits(limits.graph)?;
    if !(1..=64).contains(&limits.max_fine_paths)
        || !(1..=128).contains(&limits.max_tail_work)
        || !(1..=256).contains(&limits.max_tail_vectors)
        || limits.max_tail_vectors > limits.graph.max_vector_reads
        || limits.coarse_node_reads == 0
        || limits.coarse_node_reads > limits.graph.max_node_reads
        || limits.coarse_vector_reads == 0
        || limits.coarse_vector_reads > limits.graph.max_vector_reads
        || limits.coarse_discovered == 0
        || limits.coarse_discovered > limits.graph.max_discovered
        || limits.coarse_ef_search == 0
        || limits.coarse_ef_search > limits.coarse_discovered
    {
        return Err(crate::invalid(
            "routed coarse, path or fresh limits invalid",
        ));
    }
    Ok(())
}

impl NativeService {
    /// Point-only routing over the complete accepted directory, then selected
    /// genuine fine paths and a complete fresh interval. No graph is built here.
    pub fn search_original_spans_routed(
        &self,
        context: &AuthenticatedRequestContext,
        query_text: &str,
        embedded: &EmbeddedText,
        limits: DenseRoutedQueryLimits,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DenseRoutedQueryResult> {
        validate_limits(limits)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let view = self.routed_query_view(&snapshot, context, parent)?;
        self.check_routed_query_view(context, &view, parent)?;
        embedded.validate(
            &view.current_dense().profile,
            EmbeddingTextKind::Query,
            query_text,
            parent,
        )?;
        let fresh = fresh::admit_routed_fresh(
            self,
            &snapshot,
            context,
            &view,
            limits.max_tail_work,
            parent,
        )?;
        let mut ledger = QueryLedger::new(
            Caps {
                nodes: limits.graph.max_node_reads,
                vectors: limits.graph.max_vector_reads,
                discovered: limits.graph.max_discovered,
            },
            parent,
        )?;
        let available = ledger.remaining().reserve(
            !view.allowed_cohorts().is_empty(),
            fresh.complete && fresh.has_vectors,
        );
        let coarse_caps = available.min(Caps {
            nodes: limits.coarse_node_reads,
            vectors: limits.coarse_vector_reads,
            discovered: limits.coarse_discovered,
        });
        let coarse = traverse::search_coarse(
            self,
            &snapshot,
            context,
            &view,
            embedded,
            coarse_caps,
            limits.coarse_ef_search,
            &mut ledger,
            parent,
        )?;
        let (selected_paths, selection_complete) =
            selection::select_paths(&coarse.scores, limits.max_fine_paths, parent)?;
        parent
            .charge(
                selected_paths.len() as u64 + 1,
                (selected_paths.len() + 1) as u64 * size_of::<HybridDensePathObservation>() as u64
                    + 256,
            )
            .map_err(budget_error)?;
        let mut paths = Vec::with_capacity(selected_paths.len() + 1);
        let mut hits = Vec::new();
        for (index, path) in selected_paths.iter().enumerate() {
            self.check_routed_query_view(context, &view, parent)?;
            let admitted = self.resolve_routed_fine_path(&snapshot, &view, path, parent)?;
            parent
                .charge(coarse.scores.len() as u64 + 1, 0)
                .map_err(budget_error)?;
            for score in &coarse.scores {
                if score.path.ordinal() != path.ordinal() {
                    continue;
                }
                let bytes = crypto::metered_json_len(&score.path, parent, ROW_BYTES)?;
                parent
                    .charge(
                        bytes as u64 * 2 + admitted.summaries().len() as u64 * 64 + 1,
                        0,
                    )
                    .map_err(budget_error)?;
                if score.path != *path
                    || admitted
                        .summaries()
                        .iter()
                        .find(|c| c.policy_domain == score.policy_domain)
                        .is_none_or(|c| c.partition_digest != score.fine_partition_digest)
                {
                    return Err(integrity(
                        "routed scored target differs from accepted fine partition control",
                    ));
                }
            }
            let available = ledger
                .remaining()
                .reserve(false, fresh.complete && fresh.has_vectors);
            let assigned = available.fair_share(selected_paths.len() - index)?;
            let (found, observation) = traverse::search_fine(
                self,
                &snapshot,
                context,
                &view,
                &admitted,
                embedded,
                assigned,
                limits.graph.ef_search,
                &mut ledger,
                parent,
            )?;
            append_hits(&mut hits, found, parent)?;
            paths.push(observation);
        }
        let remaining = ledger.remaining();
        let assigned = Caps {
            nodes: 0,
            vectors: remaining.vectors.min(limits.max_tail_vectors),
            discovered: remaining.discovered,
        };
        let (found, fresh_path, tail_scoring_complete) = traverse::score_fresh(
            self,
            &snapshot,
            context,
            &view,
            embedded,
            &fresh,
            assigned,
            limits.max_tail_work,
            &mut ledger,
            parent,
        )?;
        let fresh_completion = fresh_path.completion;
        append_hits(&mut hits, found, parent)?;
        paths.push(fresh_path);
        self.check_routed_query_view(context, &view, parent)?;
        let raw_lag = self.tail_raw_lag(
            &snapshot,
            view.workspace(),
            view.generation().through,
            parent,
        )?;
        let dense_lag = view.current_dense().through < view.generation().through;
        let mut completion = if fresh.complete {
            DenseRoutedQueryCompletion::Complete
        } else {
            DenseRoutedQueryCompletion::TailWorkLimit
        };
        if completion == DenseRoutedQueryCompletion::Complete {
            if !tail_scoring_complete {
                completion = if fresh_completion == HybridDensePathCompletion::DiscoveryLimit {
                    DenseRoutedQueryCompletion::DiscoveryLimit
                } else if assigned.vectors < limits.max_tail_vectors {
                    DenseRoutedQueryCompletion::VectorLimit
                } else {
                    DenseRoutedQueryCompletion::TailVectorLimit
                };
            } else if let Some(limit) = std::iter::once(coarse.completion)
                .chain(paths.iter().map(|p| p.completion))
                .find(|c| *c != HybridDensePathCompletion::Complete)
            {
                completion = match limit {
                    HybridDensePathCompletion::NodeLimit => DenseRoutedQueryCompletion::NodeLimit,
                    HybridDensePathCompletion::VectorLimit => {
                        DenseRoutedQueryCompletion::VectorLimit
                    }
                    HybridDensePathCompletion::DiscoveryLimit => {
                        DenseRoutedQueryCompletion::DiscoveryLimit
                    }
                    HybridDensePathCompletion::WorkLimit => {
                        DenseRoutedQueryCompletion::TailWorkLimit
                    }
                    HybridDensePathCompletion::Complete => DenseRoutedQueryCompletion::Complete,
                };
            } else if raw_lag {
                completion = DenseRoutedQueryCompletion::RawLag;
            } else if dense_lag {
                completion = DenseRoutedQueryCompletion::DenseLag;
            }
        }
        let height = u64::from(usize::BITS - hits.len().max(1).leading_zeros());
        parent
            .charge(hits.len() as u64 * (height * 4 + 32) + 1, 256 * 2048 + 8192)
            .map_err(budget_error)?;
        hits.sort_unstable_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then(a.representation_id.cmp(&b.representation_id))
        });
        let mut chosen = BTreeSet::new();
        // Keep all visited ranges for each selected source. A source receives
        // its sole dense rank from its best finite span, never segment votes.
        hits.retain(|h| {
            chosen.contains(&h.source.event_id)
                || (chosen.len() < limits.graph.limit && chosen.insert(h.source.event_id))
        });
        let generation_bytes = crypto::metered_encode(view.generation(), parent, ROW_BYTES)?;
        let fields_bytes =
            crypto::metered_json_len(&view.router().manifest.coverage, parent, ROW_BYTES)?;
        parent
            .charge(
                generation_bytes.len() as u64 + 1,
                fields_bytes as u64 * 8 + 32768,
            )
            .map_err(budget_error)?;
        let m = &view.router().manifest;
        let observed = view.current_dense();
        let proven = if fresh.complete { observed } else { &m.covered };
        let witness = HybridRoutedDenseWitness {
            binding: HybridRoutedBinding {
                generation: view.generation().number,
                generation_digest: ContentDigest::from_bytes(
                    *blake3::hash(&generation_bytes).as_bytes(),
                ),
                base: m.coverage.base.clone(),
                directory: m.coverage.directory.clone(),
                router: view
                    .generation()
                    .dense_directory_router
                    .as_ref()
                    .ok_or_else(stale_index)?
                    .clone(),
            },
            coverage_count: m.coverage_count,
            coverage_digest: m.coverage_digest,
            recipe_revision: m.recipe.revision.clone(),
            quota_revision: ROUTED_QUOTA_REVISION.to_owned(),
            source_profile_digest: m.source_profile_digest,
            coarse_space_digest: m.coarse_space_digest,
            coarse_space_id: m.coarse_space_id,
            source_space_id: observed.vector_space_id,
            covered_dense_commitment: m.covered.commitment,
            observed_dense_commitment: observed.commitment,
            proven_dense_commitment: proven.commitment,
            base_through: view.base().manifest.prefix.through,
            covered_through: m.covered.through,
            proven_through: proven.through,
            observed_dense_through: observed.through,
            raw_through: view.generation().through,
            coarse,
            unvisited_paths: (selected_paths.len() as u64) < m.coverage_count,
            selected_paths,
            selection_complete,
            paths,
        };
        self.check_routed_query_view(context, &view, parent)?;
        let ledger = ledger.finish()?;
        Ok(DenseRoutedQueryResult {
            hits,
            completion,
            tail_witness_complete: fresh.complete,
            tail_scoring_complete,
            dense_lag,
            raw_lag,
            permitted_tail_omissions: fresh.omissions,
            node_reads: ledger.counts.node_reads,
            vector_reads: ledger.counts.vector_reads,
            discovered: ledger.counts.discovered,
            coarse_node_reads: ledger.coarse.node_reads,
            coarse_vector_reads: ledger.coarse.vector_reads,
            coarse_discovered: ledger.coarse.discovered,
            tail_vector_reads: ledger.tail_vector_reads,
            view_identity: view.identity(),
            admitted_sources: ledger.admitted_sources,
            witness,
        })
    }
}
#[cfg(test)]
mod tests;
fn append_hits(
    hits: &mut Vec<DenseGraphHit>,
    found: Vec<DenseGraphHit>,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    let length = hits
        .len()
        .checked_add(found.len())
        .ok_or_else(|| integrity("routed hit count overflow"))?;
    parent
        .charge(
            found.len() as u64 + 1,
            length as u64 * size_of::<DenseGraphHit>() as u64 * 2 + 256,
        )
        .map_err(budget_error)?;
    hits.extend(found);
    Ok(())
}
