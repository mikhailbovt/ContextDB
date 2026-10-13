//! Fair actual-use quotas across permitted partitions and complete fresh work.
use super::*;
use crate::raw_index::dense::graph::{prefix_segments_v2, prefix_v2};
use crate::raw_index::dense::vector_key as source_vector_key;
use contextdb_index::{AnnPartitionManifestV2, AnnPartitionQueryCompletionV2};
use fine::VerifiedRoutedFinePath;
use ledger::{Caps, QueryLedger, Stage};
use reader::{FineCohort, Namespace, search_partition};
use view::VerifiedRoutedQueryView;

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
fn completion(value: AnnPartitionQueryCompletionV2) -> HybridDensePathCompletion {
    match value {
        AnnPartitionQueryCompletionV2::Complete => HybridDensePathCompletion::Complete,
        AnnPartitionQueryCompletionV2::NodeLimit => HybridDensePathCompletion::NodeLimit,
        AnnPartitionQueryCompletionV2::VectorLimit => HybridDensePathCompletion::VectorLimit,
        AnnPartitionQueryCompletionV2::DiscoveryLimit => HybridDensePathCompletion::DiscoveryLimit,
    }
}
fn remaining_assigned(
    assigned: Caps,
    before: ledger::Counts,
    ledger: &QueryLedger,
) -> ServiceResult<Caps> {
    let now = ledger.counts();
    let subtract = |cap: usize, actual: u64| -> ServiceResult<usize> {
        cap.checked_sub(
            usize::try_from(actual).map_err(|_| integrity("routed local counter overflow"))?,
        )
        .ok_or_else(|| integrity("routed local quota exceeded"))
    };
    Ok(Caps {
        nodes: subtract(assigned.nodes, now.node_reads - before.node_reads)?,
        vectors: subtract(assigned.vectors, now.vector_reads - before.vector_reads)?,
        discovered: subtract(assigned.discovered, now.discovered - before.discovered)?,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "one admitted view and shared operation allowance remain explicit"
)]
pub(super) fn search_coarse<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedRoutedQueryView,
    query: &EmbeddedText,
    assigned: Caps,
    ef_search: usize,
    ledger: &mut QueryLedger,
    parent: &mut QueryBudget,
) -> ServiceResult<HybridCoarseObservation> {
    let before = ledger.counts();
    let cohorts = view.allowed_cohorts();
    let capacity = assigned
        .vectors
        .min(assigned.discovered)
        .min(MAX_REPRESENTATIVES);
    parent
        .charge(
            1,
            capacity as u64 * size_of::<HybridCoarseScore>() as u64 + 256,
        )
        .map_err(budget_error)?;
    let mut scores = Vec::with_capacity(capacity);
    let mut status = HybridDensePathCompletion::Complete;
    for (index, cohort) in cohorts.iter().enumerate() {
        native.check_routed_query_view(context, view, parent)?;
        let quota =
            remaining_assigned(assigned, before, ledger)?.fair_share(cohorts.len() - index)?;
        if let Some(limit) = no_quota(quota) {
            if status == HybridDensePathCompletion::Complete {
                status = limit;
            }
            break;
        }
        // The view authenticated this control row and admitted its complete
        // conjunction before the encoder. Decode only that permitted partition.
        let partition = native.check_router_cohort(
            view.workspace(),
            &view.router().manifest,
            cohort,
            parent,
        )?;
        let found = search_partition(
            native,
            snapshot,
            context,
            view,
            Namespace::Coarse { cohort },
            &partition,
            query,
            quota,
            ef_search,
            ledger,
            parent,
        )?;
        ledger.record_kernel(
            Stage::Coarse,
            quota,
            found.node_reads,
            found.vector_reads,
            found.discovered,
        )?;
        if scores.len() + found.scores.len() > capacity || !found.hits.is_empty() {
            return Err(integrity(
                "routed coarse score/source kind or prepaid bound differs",
            ));
        }
        scores.extend(found.scores);
        if status == HybridDensePathCompletion::Complete {
            status = completion(found.completion);
        }
    }
    let after = ledger.counts();
    Ok(HybridCoarseObservation {
        has_work: !cohorts.is_empty(),
        max_node_reads: assigned.nodes as u32,
        max_vector_reads: assigned.vectors as u32,
        max_discovered: assigned.discovered as u32,
        node_reads: after.node_reads - before.node_reads,
        vector_reads: after.vector_reads - before.vector_reads,
        discovered: after.discovered - before.discovered,
        completion: status,
        scores,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "accepted fine path, current view and assigned caps remain explicit"
)]
pub(super) fn search_fine<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedRoutedQueryView,
    path: &VerifiedRoutedFinePath,
    query: &EmbeddedText,
    assigned: Caps,
    ef_search: usize,
    ledger: &mut QueryLedger,
    parent: &mut QueryBudget,
) -> ServiceResult<(Vec<DenseGraphHit>, HybridDensePathObservation)> {
    let summaries = path.summaries();
    parent
        .charge(
            summaries.len() as u64 + 1,
            summaries.len() as u64 * size_of::<(FineCohort, AnnPartitionManifestV2)>() as u64
                + 4096,
        )
        .map_err(budget_error)?;
    let mut cohorts = Vec::with_capacity(summaries.len());
    for summary in summaries {
        native.check_routed_query_view(context, view, parent)?;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let cohort = match path {
            VerifiedRoutedFinePath::Base { receipt, .. } => {
                let row: prefix_v2::types::PrefixCohortV2 = native
                    .graph_read(
                        snapshot,
                        &native.keyspaces.continuous,
                        &prefix_v2::types::cohort_key(
                            view.workspace(),
                            view.generation().number,
                            &summary.policy_domain,
                        )?,
                        parent,
                    )?
                    .ok_or_else(|| integrity("routed fine base control absent"))?;
                native.check_prefix_cohort_control(
                    view.workspace(),
                    &receipt.manifest,
                    &row,
                    parent,
                )?;
                FineCohort::Base(row)
            }
            VerifiedRoutedFinePath::Segment { publication, .. } => {
                let row: prefix_segments_v2::types::PrefixSegCohortV2 = native
                    .graph_read(
                        snapshot,
                        &native.keyspaces.continuous,
                        &prefix_segments_v2::types::segment_cohort_key(
                            view.workspace(),
                            view.generation().number,
                            publication.delta.manifest.ordinal,
                            &summary.policy_domain,
                        )?,
                        parent,
                    )?
                    .ok_or_else(|| integrity("routed fine segment control absent"))?;
                native.check_prefix_segment_cohort_control(
                    view.workspace(),
                    &publication.delta.manifest,
                    &row,
                    parent,
                )?;
                FineCohort::Segment(row)
            }
        };
        reader::charge_policy(context, cohort.policies(), parent)?;
        if cohort
            .policies()
            .iter()
            .any(|p| !crate::policy_allows(&context.request, p))
        {
            continue;
        }
        let partition = match (&cohort, path) {
            (FineCohort::Base(row), VerifiedRoutedFinePath::Base { receipt, .. }) => {
                native.check_prefix_cohort(view.workspace(), &receipt.manifest, row, parent)?
            }
            (FineCohort::Segment(row), VerifiedRoutedFinePath::Segment { publication, .. }) => {
                native.check_prefix_segment_cohort(
                    view.workspace(),
                    &publication.delta.manifest,
                    row,
                    parent,
                )?
            }
            _ => return Err(integrity("routed fine control family differs")),
        };
        cohorts.push((cohort, partition));
    }
    let before = ledger.counts();
    let mut status = HybridDensePathCompletion::Complete;
    let mut hits = Vec::new();
    for (index, (cohort, partition)) in cohorts.iter().enumerate() {
        let quota =
            remaining_assigned(assigned, before, ledger)?.fair_share(cohorts.len() - index)?;
        if let Some(limit) = no_quota(quota) {
            if status == HybridDensePathCompletion::Complete {
                status = limit;
            }
            break;
        }
        let found = search_partition(
            native,
            snapshot,
            context,
            view,
            Namespace::Fine { path, cohort },
            partition,
            query,
            quota,
            ef_search,
            ledger,
            parent,
        )?;
        ledger.record_kernel(
            Stage::Fine,
            quota,
            found.node_reads,
            found.vector_reads,
            found.discovered,
        )?;
        if !found.scores.is_empty() {
            return Err(integrity("routed fine path emitted coarse identity"));
        }
        append_hits(&mut hits, found.hits, parent)?;
        if status == HybridDensePathCompletion::Complete {
            status = completion(found.completion);
        }
    }
    let after = ledger.counts();
    Ok((
        hits,
        HybridDensePathObservation {
            kind: if path.path().ordinal() == 0 {
                HybridDensePathKind::Base
            } else {
                HybridDensePathKind::Segment
            },
            ordinal: if path.path().ordinal() == 0 {
                None
            } else {
                Some(path.path().ordinal())
            },
            has_work: !cohorts.is_empty(),
            max_node_reads: assigned.nodes as u32,
            max_vector_reads: assigned.vectors as u32,
            max_discovered: assigned.discovered as u32,
            max_work: 0,
            node_reads: after.node_reads - before.node_reads,
            vector_reads: after.vector_reads - before.vector_reads,
            discovered: after.discovered - before.discovered,
            work: 0,
            completion: status,
        },
    ))
}

fn fresh_fence(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    view: &VerifiedRoutedQueryView,
    document: &DenseDocument,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    native.check_routed_query_view(context, view, parent)?;
    let current = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(storage_error)?;
    native.authorized_capture_policy_with_budget(
        &current,
        context,
        document.source.event_id,
        parent,
    )?;
    native.authorize_derived_custody_with_budget(
        &current,
        context,
        document.source.event_id,
        parent,
    )?;
    let policies =
        native.stored_custody_policies_with_budget(&current, document.source.event_id, parent)?;
    reader::charge_policy(context, &policies, parent)?;
    if policies
        .iter()
        .any(|p| !crate::policy_allows(&context.request, p))
    {
        return Err(crate::permission_denied());
    }
    let encoded = crypto::metered_encode(&policies, parent, ROW_BYTES)?;
    parent
        .charge(encoded.len() as u64 + 1, 0)
        .map_err(budget_error)?;
    if digest_bytes(&encoded) != document.policy_domain {
        return Err(stale_index());
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "complete fresh witness and shared ledger retain one parent"
)]
pub(super) fn score_fresh<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedRoutedQueryView,
    query: &EmbeddedText,
    fresh: &fresh::RoutedFreshInput,
    assigned: Caps,
    max_work: usize,
    ledger: &mut QueryLedger,
    parent: &mut QueryBudget,
) -> ServiceResult<(Vec<DenseGraphHit>, HybridDensePathObservation, bool)> {
    let before = ledger.counts();
    let capacity = assigned.vectors.min(assigned.discovered);
    parent
        .charge(1, capacity as u64 * size_of::<DenseGraphHit>() as u64 + 256)
        .map_err(budget_error)?;
    let mut hits = Vec::with_capacity(capacity);
    let mut complete = fresh.complete;
    let mut status = if complete {
        HybridDensePathCompletion::Complete
    } else {
        HybridDensePathCompletion::WorkLimit
    };
    if !fresh.complete && !fresh.documents.is_empty() {
        return Err(integrity("routed fresh partial work has documents"));
    }
    for (document, _) in &fresh.documents {
        fresh_fence(native, context, view, document, parent)?;
        ledger.add_fresh_source(&document.source, parent)?;
        if !complete {
            continue;
        }
        for (ordinal, span) in document.spans.iter().enumerate() {
            let counts = ledger.counts();
            if counts.vector_reads - before.vector_reads >= assigned.vectors as u64 {
                status = HybridDensePathCompletion::VectorLimit;
                complete = false;
                break;
            }
            if counts.discovered - before.discovered >= assigned.discovered as u64 {
                status = HybridDensePathCompletion::DiscoveryLimit;
                complete = false;
                break;
            }
            fresh_fence(native, context, view, document, parent)?;
            let identity = crypto::metered_encode(
                &(
                    "native-span-ann-member/v1",
                    &native.database_id,
                    view.workspace(),
                    view.generation().number,
                    &document.source,
                    document.event_digest,
                    document.commit,
                    ordinal as u32,
                    &span.span,
                    &document.policy_domain,
                    document.profile_digest,
                    span.vector_digest,
                ),
                parent,
                ROW_BYTES,
            )?;
            parent
                .charge(identity.len() as u64 + 1, 0)
                .map_err(budget_error)?;
            let full = ContentDigest::from_bytes(*blake3::hash(&identity).as_bytes());
            let mut compact = [0; 16];
            compact.copy_from_slice(&full.as_bytes()[..16]);
            compact[6] = (compact[6] & 15) | 128;
            compact[8] = (compact[8] & 63) | 128;
            let id =
                RepresentationId::from_uuid(uuid::Uuid::from_bytes(compact)).map_err(ann_error)?;
            ledger.admit_span(id, full, &document.source, &span.span, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let vector: DenseVector = native
                .graph_read(
                    snapshot,
                    &native.keyspaces.continuous,
                    &source_vector_key(
                        view.workspace(),
                        view.generation().number,
                        document.source.event_id,
                        ordinal as u32,
                    ),
                    parent,
                )?
                .ok_or_else(|| integrity("routed fresh vector absent"))?;
            let bytes = crypto::metered_json_len(&vector, parent, ROW_BYTES)?;
            parent
                .charge(1, bytes as u64 * 4 + 8192)
                .map_err(budget_error)?;
            native.check_dense_vector_token(&vector)?;
            if vector.source != document.source
                || vector.event_digest != document.event_digest
                || vector.commit != document.commit
                || vector.ordinal != ordinal as u32
                || vector.span != span.span
                || vector.policy_domain != document.policy_domain
                || vector.profile_digest != view.current_dense().profile_digest
                || vector.vector_digest != span.vector_digest
                || vector.input_digest.as_bytes() == &[0; 32]
            {
                return Err(integrity(
                    "routed fresh vector full original binding differs",
                ));
            }
            let values = super::super::super::query::query_vector_values(
                &view.current_dense().profile,
                vector,
                parent,
            )?;
            let score = tail::tail_cosine(&query.values, &values, parent)?;
            ledger.record_fresh_vector()?;
            let bytes =
                crypto::metered_json_len(&(&document.source, &span.span), parent, ROW_BYTES)?;
            parent
                .charge(
                    1,
                    bytes as u64 * 4 + size_of::<DenseGraphHit>() as u64 + 256,
                )
                .map_err(budget_error)?;
            hits.push(DenseGraphHit {
                representation_id: id,
                source: document.source.clone(),
                span: span.span.clone(),
                score,
            });
        }
    }
    let after = ledger.counts();
    Ok((
        hits,
        HybridDensePathObservation {
            kind: HybridDensePathKind::FreshTail,
            ordinal: None,
            has_work: fresh.has_work,
            max_node_reads: 0,
            max_vector_reads: assigned.vectors as u32,
            max_discovered: assigned.discovered as u32,
            max_work: max_work as u32,
            node_reads: 0,
            vector_reads: after.vector_reads - before.vector_reads,
            discovered: after.discovered - before.discovered,
            work: fresh.work,
            completion: status,
        },
        complete,
    ))
}
