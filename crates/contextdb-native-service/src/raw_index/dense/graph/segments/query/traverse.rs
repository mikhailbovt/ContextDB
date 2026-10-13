//! Bounded policy-cohort scheduling inside one assigned immutable path.
use super::ledger::{Caps, QueryLedger};
use super::reader::{Namespace, search_partition};
use super::view::VerifiedSegmentQueryView;
use super::*;

enum Cohort {
    Base(GraphCohort, AnnPartitionManifestV2),
    Segment(SegCohort, AnnPartitionManifestV2),
}

#[allow(
    clippy::too_many_arguments,
    reason = "owner view, assigned caps and the single ledger remain explicit"
)]
pub(super) fn search_path<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedSegmentQueryView,
    delta: Option<&DenseSegmentPublication>,
    query: &EmbeddedText,
    assigned: Caps,
    ef_search: usize,
    ledger: &mut QueryLedger,
    budget: &mut QueryBudget,
) -> ServiceResult<(Vec<DenseGraphHit>, HybridDensePathObservation)> {
    let summaries = delta.map_or(&view.base().manifest.cohorts, |p| &p.delta.manifest.cohorts);
    budget
        .charge(
            summaries.len() as u64 + 1,
            summaries.len() as u64 * size_of::<Cohort>() as u64 + 4096,
        )
        .map_err(budget_error)?;
    let mut cohorts = Vec::with_capacity(summaries.len());
    for summary in summaries {
        native.check_segment_query_view(context, view, budget)?;
        budget.charge(1, 1024).map_err(budget_error)?;
        let (cohort, policies) = match delta {
            None => {
                let row: GraphCohort = native
                    .graph_read(
                        snapshot,
                        &native.keyspaces.continuous,
                        &cohort_key(
                            view.workspace(),
                            view.generation().number,
                            &summary.policy_domain,
                        ),
                        budget,
                    )?
                    .ok_or_else(|| integrity("segmented query immutable base cohort absent"))?;
                let partition = native.check_graph_cohort(&view.base().manifest, &row, budget)?;
                let allowed = row
                    .policies
                    .iter()
                    .all(|p| crate::policy_allows(&context.request, p));
                (Cohort::Base(row, partition), allowed)
            }
            Some(publication) => {
                let manifest = &publication.delta.manifest;
                let row: SegCohort = native
                    .graph_read(
                        snapshot,
                        &native.keyspaces.continuous,
                        &types::segment_cohort_key(
                            view.workspace(),
                            view.generation().number,
                            manifest.ordinal,
                            &summary.policy_domain,
                        )?,
                        budget,
                    )?
                    .ok_or_else(|| integrity("segmented query immutable delta cohort absent"))?;
                let partition =
                    native.check_segment_cohort(view.workspace(), manifest, &row, budget)?;
                let allowed = row
                    .policies
                    .iter()
                    .all(|p| crate::policy_allows(&context.request, p));
                (Cohort::Segment(row, partition), allowed)
            }
        };
        if policies {
            cohorts.push(cohort);
        }
    }
    let before = ledger.counts();
    let mut completion = HybridDensePathCompletion::Complete;
    let mut hits = Vec::new();
    let has_work = !cohorts.is_empty();
    for (index, cohort) in cohorts.iter().enumerate() {
        let counts = ledger.counts();
        let available = Caps {
            nodes: assigned.nodes - (counts.node_reads - before.node_reads) as usize,
            vectors: assigned.vectors - (counts.vector_reads - before.vector_reads) as usize,
            discovered: assigned.discovered - (counts.discovered - before.discovered) as usize,
        };
        let quota = available.fair_share(cohorts.len() - index)?;
        if let Some(limit) = no_quota(quota) {
            completion = limit;
            break;
        }
        let (namespace, partition) = match cohort {
            Cohort::Base(row, partition) => (
                Namespace::Base {
                    receipt: view.base(),
                    cohort: row,
                },
                partition,
            ),
            Cohort::Segment(row, partition) => (
                Namespace::Delta {
                    manifest: &delta
                        .expect("segment cohort requires admitted publication")
                        .delta
                        .manifest,
                    cohort: row,
                },
                partition,
            ),
        };
        let found = search_partition(
            native, snapshot, context, view, namespace, partition, query, quota, ef_search, ledger,
            budget,
        )?;
        ledger.record_kernel(
            quota,
            found.node_reads,
            found.vector_reads,
            found.discovered,
        )?;
        append_hits(&mut hits, found.hits, budget)?;
        if found.completion != AnnPartitionQueryCompletionV2::Complete {
            let actual = match found.completion {
                AnnPartitionQueryCompletionV2::Complete => HybridDensePathCompletion::Complete,
                AnnPartitionQueryCompletionV2::NodeLimit => HybridDensePathCompletion::NodeLimit,
                AnnPartitionQueryCompletionV2::VectorLimit => {
                    HybridDensePathCompletion::VectorLimit
                }
                AnnPartitionQueryCompletionV2::DiscoveryLimit => {
                    HybridDensePathCompletion::DiscoveryLimit
                }
            };
            if completion == HybridDensePathCompletion::Complete {
                completion = actual;
            }
            // Remaining admitted cohorts can still use their fair share. The
            // first genuine local limit remains visible in the path receipt.
        }
    }
    let after = ledger.counts();
    Ok((
        hits,
        HybridDensePathObservation {
            kind: if delta.is_some() {
                HybridDensePathKind::Segment
            } else {
                HybridDensePathKind::Base
            },
            ordinal: delta.map(|p| p.delta.manifest.ordinal),
            has_work,
            max_node_reads: assigned.nodes as u32,
            max_vector_reads: assigned.vectors as u32,
            max_discovered: assigned.discovered as u32,
            max_work: 0,
            node_reads: after.node_reads - before.node_reads,
            vector_reads: after.vector_reads - before.vector_reads,
            discovered: after.discovered - before.discovered,
            work: 0,
            completion,
        },
    ))
}

pub(super) fn no_quota(caps: Caps) -> Option<HybridDensePathCompletion> {
    if caps.nodes == 0 {
        Some(HybridDensePathCompletion::NodeLimit)
    } else if caps.vectors == 0 {
        Some(HybridDensePathCompletion::VectorLimit)
    } else if caps.discovered == 0 {
        Some(HybridDensePathCompletion::DiscoveryLimit)
    } else {
        None
    }
}
