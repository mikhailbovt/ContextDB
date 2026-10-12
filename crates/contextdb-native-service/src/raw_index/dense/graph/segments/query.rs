//! One owner view, global traversal allowance and dense rank across immutable paths.
use super::super::tail::AuthenticatedDensePrefixAnchor;
use super::types::{DenseSegmentPublication, SegCohort};
use super::*;
use crate::router_trace::hybrid::segments::{
    HybridDensePathCompletion, HybridDensePathKind, HybridDensePathObservation,
    HybridSegmentBaseIdentity, HybridSegmentDirectoryIdentity, HybridSegmentLatestIdentity,
    HybridSegmentedDenseWitness,
};
use contextdb_index::AnnPartitionQueryCompletionV2;
use ledger::{Caps, QueryLedger};

mod fresh;
mod ledger;
mod reader;
mod traverse;
mod view;
pub(crate) use view::VerifiedSegmentQueryView;

/// One bounded operation; reaching the ordinal cap is explicitly incomplete.
#[derive(Clone, Copy, Debug)]
pub struct DenseSegmentQueryLimits {
    /// Global node, vector and discovery caps shared by every immutable path.
    pub graph: DenseGraphQueryLimits,
    /// Immutable segment ordinals admitted, from one through 64.
    pub max_segments: usize,
    /// Accepted fresh capture work, from one through 128.
    pub max_tail_work: usize,
    /// Permitted fresh vector reads within the global cap, from one through 256.
    pub max_tail_vectors: usize,
}

/// Local traversal coverage. Complete is not exhaustive semantic recall.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenseSegmentQueryCompletion {
    /// All selected paths and fresh scoring reached their local stopping condition.
    Complete,
    /// Accepted directory ordinals remain outside this bounded operation.
    SegmentSelectionLimit,
    /// Complete fresh dense interval was not proved.
    TailWorkLimit,
    /// Permitted fresh scoring reached its local cap.
    TailVectorLimit,
    /// An immutable path reached its assigned node cap.
    NodeLimit,
    /// An immutable or fresh path reached its assigned vector cap.
    VectorLimit,
    /// An immutable or fresh path reached its assigned discovery cap.
    DiscoveryLimit,
    /// Dense projection remains behind the accepted raw prefix.
    DenseLag,
    /// Accepted capture work remains behind raw projection.
    RawLag,
}

/// Authenticated discovery observations; they grant no disclosure lease.
#[derive(Clone, PartialEq, Serialize)]
pub struct DenseSegmentQueryResult {
    /// Globally ranked span observations, with one rank per distinct source.
    pub hits: Vec<DenseGraphHit>,
    /// Declared local path status, never a quality score.
    pub completion: DenseSegmentQueryCompletion,
    /// Whether the complete fresh dense interval was reproduced.
    pub tail_witness_complete: bool,
    /// Whether all permitted fresh vectors were scored.
    pub tail_scoring_complete: bool,
    /// Dense projection is behind raw projection.
    pub dense_lag: bool,
    /// Accepted work is behind raw projection.
    pub raw_lag: bool,
    /// Genuine permitted fresh omissions or upstream partial observations.
    pub permitted_tail_omissions: bool,
    /// Actual kernel node reads across all admitted immutable paths.
    pub node_reads: u64,
    /// Actual immutable and fresh full-vector reads.
    pub vector_reads: u64,
    /// Actual immutable and fresh representation discoveries.
    pub discovered: u64,
    /// Actual fresh full-vector reads.
    pub tail_vector_reads: u64,
    #[serde(skip_serializing)]
    pub(crate) admitted_sources: BTreeMap<ObservationId, RawSource>,
    #[serde(skip_serializing)]
    pub(crate) witness: HybridSegmentedDenseWitness,
}
impl std::fmt::Debug for DenseSegmentQueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DenseSegmentQueryResult")
            .field("hits", &self.hits)
            .field("completion", &self.completion)
            .field("tail_witness_complete", &self.tail_witness_complete)
            .field("tail_scoring_complete", &self.tail_scoring_complete)
            .field("node_reads", &self.node_reads)
            .field("vector_reads", &self.vector_reads)
            .finish_non_exhaustive()
    }
}

impl NativeService {
    /// Query the accepted base, bounded immutable ordinals and complete fresh
    /// prefix under one operation allowance. Unvisited ordinals stay explicit;
    /// this routing profile does not claim scalable whole-database recall.
    pub fn search_original_spans_segmented(
        &self,
        context: &AuthenticatedRequestContext,
        query_text: &str,
        embedded: &EmbeddedText,
        limits: DenseSegmentQueryLimits,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseSegmentQueryResult> {
        super::super::query::validate_limits(limits.graph)?;
        if !(1..=64).contains(&limits.max_segments)
            || !(1..=128).contains(&limits.max_tail_work)
            || !(1..=256).contains(&limits.max_tail_vectors)
            || limits.max_tail_vectors > limits.graph.max_vector_reads
        {
            return Err(crate::invalid(
                "segmented query ordinal and fresh limits invalid",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let view = self.segment_query_view(&snapshot, context, budget)?;
        self.check_segment_query_view(context, &view, budget)?;
        embedded.validate(
            &view.profile_dense().profile,
            EmbeddingTextKind::Query,
            query_text,
            budget,
        )?;
        let fresh = fresh::admit_fresh(
            self,
            &snapshot,
            context,
            &view,
            limits.max_tail_work,
            budget,
        )?;
        let head = &view.head().publication().directory.head;
        let selected_count = head.count.min(limits.max_segments as u64) as usize;
        budget
            .charge(
                selected_count as u64 + 1,
                (selected_count + 2) as u64 * size_of::<HybridDensePathObservation>() as u64 * 2
                    + 8192,
            )
            .map_err(budget_error)?;
        let selected_ordinals: Vec<u64> = (1..=selected_count as u64).collect();
        let mut paths = Vec::with_capacity(selected_count + 2);
        let mut ledger = QueryLedger::new(
            Caps {
                nodes: limits.graph.max_node_reads,
                vectors: limits.graph.max_vector_reads,
                discovered: limits.graph.max_discovered,
            },
            budget,
        )?;
        let mut hits = Vec::new();
        for index in 0..=selected_count {
            self.check_segment_query_view(context, &view, budget)?;
            let delta = if index == 0 {
                None
            } else {
                let publication = self.accepted_segment_for_ordinal(
                    &snapshot,
                    view.workspace(),
                    view.generation().number,
                    index as u64,
                    budget,
                )?;
                admit_selected(&view, &publication, index as u64, budget)?;
                Some(publication)
            };
            let mut available = ledger.remaining();
            // Reserve one genuine fresh scoring opportunity rather than letting
            // early immutable paths spend every vector/discovery slot.
            if fresh.complete && fresh.has_work {
                available.vectors = available.vectors.saturating_sub(1);
                available.discovered = available.discovered.saturating_sub(1);
            }
            let assigned = available.fair_share(selected_count + 1 - index)?;
            let (found, path) = traverse::search_path(
                self,
                &snapshot,
                context,
                &view,
                delta.as_ref(),
                embedded,
                assigned,
                limits.graph.ef_search,
                &mut ledger,
                budget,
            )?;
            append_hits(&mut hits, found, budget)?;
            paths.push(path);
        }
        let remaining = ledger.remaining();
        let assigned = Caps {
            nodes: 0,
            vectors: remaining.vectors.min(limits.max_tail_vectors),
            discovered: remaining.discovered,
        };
        let (found, path, tail_scoring_complete) = fresh::score_fresh(
            self,
            &snapshot,
            context,
            &view,
            embedded,
            &fresh,
            assigned,
            limits.max_tail_work,
            &mut ledger,
            budget,
        )?;
        let tail_local_limit = path.completion;
        append_hits(&mut hits, found, budget)?;
        paths.push(path);
        self.check_segment_query_view(context, &view, budget)?;
        let raw_lag = self.tail_raw_lag(
            &snapshot,
            view.workspace(),
            view.generation().through,
            budget,
        )?;
        let dense_lag = view.profile_dense().through < view.generation().through;
        let selection_complete = selected_count as u64 == head.count;
        let mut completion = if fresh.complete {
            DenseSegmentQueryCompletion::Complete
        } else {
            DenseSegmentQueryCompletion::TailWorkLimit
        };
        if completion == DenseSegmentQueryCompletion::Complete {
            if !tail_scoring_complete {
                completion = if tail_local_limit == HybridDensePathCompletion::DiscoveryLimit {
                    DenseSegmentQueryCompletion::DiscoveryLimit
                } else if assigned.vectors < limits.max_tail_vectors {
                    DenseSegmentQueryCompletion::VectorLimit
                } else {
                    DenseSegmentQueryCompletion::TailVectorLimit
                };
            } else if let Some(path) = paths
                .iter()
                .find(|p| p.completion != HybridDensePathCompletion::Complete)
            {
                completion = match path.completion {
                    HybridDensePathCompletion::Complete => DenseSegmentQueryCompletion::Complete,
                    HybridDensePathCompletion::NodeLimit => DenseSegmentQueryCompletion::NodeLimit,
                    HybridDensePathCompletion::VectorLimit => {
                        DenseSegmentQueryCompletion::VectorLimit
                    }
                    HybridDensePathCompletion::DiscoveryLimit => {
                        DenseSegmentQueryCompletion::DiscoveryLimit
                    }
                    HybridDensePathCompletion::WorkLimit => {
                        DenseSegmentQueryCompletion::TailWorkLimit
                    }
                };
            } else if !selection_complete {
                completion = DenseSegmentQueryCompletion::SegmentSelectionLimit;
            } else if raw_lag {
                completion = DenseSegmentQueryCompletion::RawLag;
            } else if dense_lag {
                completion = DenseSegmentQueryCompletion::DenseLag;
            }
        }
        let height = u64::from(usize::BITS - hits.len().max(1).leading_zeros());
        // In-place sorting needs no temporary hit array. The fixed supplier cap
        // also bounds every possible selected-source tree split before insert.
        budget
            .charge(hits.len() as u64 * (height * 4 + 32) + 1, 256 * 2048 + 8192)
            .map_err(budget_error)?;
        hits.sort_unstable_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then(a.representation_id.cmp(&b.representation_id))
        });
        let mut selected_sources = BTreeSet::new();
        // Retain all visited spans for chosen sources. The first occurrence is
        // the source's sole best dense rank; no per-segment vote is created.
        hits.retain(|hit| {
            selected_sources.contains(&hit.source.event_id)
                || (selected_sources.len() < limits.graph.limit
                    && selected_sources.insert(hit.source.event_id))
        });
        budget.charge(1, 32768).map_err(budget_error)?;
        let reference = view
            .generation()
            .dense_segments
            .as_ref()
            .ok_or_else(stale_index)?;
        let base = &head.base;
        let observed = view.profile_dense();
        let proven = if fresh.complete {
            observed
        } else {
            view.head().covered()
        };
        let witness = HybridSegmentedDenseWitness {
            base: HybridSegmentBaseIdentity {
                global_commit: base.publication.global_commit,
                event_digest: base.publication.event_digest.clone(),
                request_digest: base.publication.request_digest.clone(),
                response_digest: base.publication.response_digest.clone(),
                receipt_digest: base.receipt_digest,
                graph_digest: base.graph_digest,
            },
            head: HybridSegmentDirectoryIdentity {
                count: reference.count,
                global_commit: reference.global_commit,
                request_digest: reference.request_digest.clone(),
                response_digest: reference.response_digest.clone(),
                content_digest: reference.content_digest,
            },
            latest: HybridSegmentLatestIdentity {
                ordinal: head.latest.ordinal,
                global_commit: head.latest.global_commit,
                manifest_digest: head.latest.manifest_digest,
                receipt_digest: head.latest.receipt_digest,
            },
            covered_dense_commitment: head.covered.commitment,
            observed_dense_commitment: observed.commitment,
            proven_dense_commitment: proven.commitment,
            base_through: view.base().manifest.dense.through,
            covered_through: head.covered.through,
            observed_dense_through: observed.through,
            proven_through: proven.through,
            raw_through: view.generation().through,
            quota_revision: crate::router_trace::hybrid::segments::SEGMENT_QUOTA_REVISION.into(),
            selected_ordinals,
            selection_complete,
            paths,
        };
        self.check_segment_query_view(context, &view, budget)?;
        let ledger = ledger.finish();
        Ok(DenseSegmentQueryResult {
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
            tail_vector_reads: ledger.counts.tail_vector_reads,
            admitted_sources: ledger.admitted_sources,
            witness,
        })
    }
}

fn append_hits(
    hits: &mut Vec<DenseGraphHit>,
    found: Vec<DenseGraphHit>,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    budget
        .charge(
            found.len() as u64 + 1,
            (hits.len() + found.len()) as u64 * size_of::<DenseGraphHit>() as u64 * 2 + 256,
        )
        .map_err(budget_error)?;
    hits.extend(found);
    Ok(())
}

fn admit_selected(
    view: &VerifiedSegmentQueryView,
    publication: &DenseSegmentPublication,
    ordinal: u64,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    budget.charge(1, 32768).map_err(budget_error)?;
    let manifest = &publication.delta.manifest;
    let latest = &view.head().publication().delta.manifest;
    if manifest.ordinal != ordinal
        || manifest.ordinal > latest.ordinal
        || manifest.base != latest.base
        || manifest.after.through > view.head().covered().through
        || manifest.after.sources > view.head().covered().sources
        || manifest.after.spans > view.head().covered().spans
        || manifest.after.profile != latest.after.profile
        || manifest.after.profile_digest != latest.after.profile_digest
        || manifest.after.vector_space_id != latest.after.vector_space_id
        || manifest.binding.generation != latest.binding.generation
        || manifest.binding.custody_version != latest.binding.custody_version
        || manifest.binding.analyzer != latest.binding.analyzer
        || manifest.binding.bm25 != latest.binding.bm25
        || manifest.binding.authorization_epoch != latest.binding.authorization_epoch
        || manifest.binding.removal_through != latest.binding.removal_through
        || (ordinal == latest.ordinal && publication != view.head().publication())
    {
        return Err(integrity(
            "selected segment is outside the accepted current directory",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
