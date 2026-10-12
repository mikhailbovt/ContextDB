//! Complete permitted fresh documents before scoring; no partial prefix is used.
use super::ledger::{Caps, QueryLedger};
use super::view::VerifiedSegmentQueryView;
use super::*;

pub(super) struct FreshDocument {
    document: DenseDocument,
    policies: Vec<AccessPolicy>,
}
pub(super) struct FreshInput {
    documents: Vec<FreshDocument>,
    pub(super) complete: bool,
    pub(super) work_items: u32,
    pub(super) has_work: bool,
    pub(super) omissions: bool,
}

pub(super) fn admit_fresh<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedSegmentQueryView,
    max_work: usize,
    budget: &mut QueryBudget,
) -> ServiceResult<FreshInput> {
    let witness = native.dense_prefix_witness(
        snapshot,
        view.workspace(),
        view.generation(),
        AuthenticatedDensePrefixAnchor::accepted_segment(view.head()),
        max_work,
        true,
        budget,
    )?;
    if !witness.complete {
        return Ok(FreshInput {
            documents: Vec::new(),
            complete: false,
            work_items: witness.work_items,
            has_work: true,
            omissions: false,
        });
    }
    let mut documents = Vec::new();
    let mut has_work = false;
    let mut omissions = false;
    for document in witness.documents {
        native.check_segment_query_view(context, view, budget)?;
        let policies = native.stored_custody_policies_with_budget(
            snapshot,
            document.source.event_id,
            budget,
        )?;
        budget
            .charge(policies.len() as u64 + 1, ROW_BYTES as u64 * 2)
            .map_err(budget_error)?;
        if canonical_digest(&policies)? != document.policy_domain {
            return Err(integrity(
                "segmented fresh document compound policy differs",
            ));
        }
        if policies
            .iter()
            .any(|p| !crate::policy_allows(&context.request, p))
        {
            continue;
        }
        fresh_fence(native, context, view, &document, &policies, budget)?;
        has_work |= !document.spans.is_empty();
        omissions |= matches!(
            document.omission,
            Some(DenseOmission::Unavailable | DenseOmission::NonText | DenseOmission::TooLarge)
        ) || document.source.upstream_truncated
            || document.source.coverage != contextdb_core::EventCoverage::CompleteObservation;
        budget
            .charge(1, size_of::<FreshDocument>() as u64 * 2 + 256)
            .map_err(budget_error)?;
        documents.push(FreshDocument { document, policies });
    }
    Ok(FreshInput {
        documents,
        complete: true,
        work_items: witness.work_items,
        has_work,
        omissions,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "admitted prefix, assigned caps and shared ledger remain explicit"
)]
pub(super) fn score_fresh<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedSegmentQueryView,
    query: &EmbeddedText,
    fresh: &FreshInput,
    assigned: Caps,
    max_work: usize,
    ledger: &mut QueryLedger,
    budget: &mut QueryBudget,
) -> ServiceResult<(Vec<DenseGraphHit>, HybridDensePathObservation, bool)> {
    let before = ledger.counts();
    let capacity = assigned.vectors.min(assigned.discovered);
    budget
        .charge(1, capacity as u64 * size_of::<DenseGraphHit>() as u64 + 256)
        .map_err(budget_error)?;
    let mut hits = Vec::with_capacity(capacity);
    let mut completion = if fresh.complete {
        HybridDensePathCompletion::Complete
    } else {
        HybridDensePathCompletion::WorkLimit
    };
    let mut scoring_complete = fresh.complete;
    for input in &fresh.documents {
        fresh_fence(
            native,
            context,
            view,
            &input.document,
            &input.policies,
            budget,
        )?;
        // The whole permitted frontier survives a scoring limit, including
        // genuine omissions; no placeholder representation is manufactured.
        ledger.add_tail_source(&input.document.source, budget)?;
        if !scoring_complete {
            continue;
        }
        for (ordinal, span) in input.document.spans.iter().enumerate() {
            let counts = ledger.counts();
            if counts.vector_reads - before.vector_reads >= assigned.vectors as u64 {
                completion = HybridDensePathCompletion::VectorLimit;
                scoring_complete = false;
                break;
            }
            if counts.discovered - before.discovered >= assigned.discovered as u64 {
                completion = HybridDensePathCompletion::DiscoveryLimit;
                scoring_complete = false;
                break;
            }
            fresh_fence(
                native,
                context,
                view,
                &input.document,
                &input.policies,
                budget,
            )?;
            let (full, id) =
                fresh_identity(native, view, &input.document, ordinal as u32, span, budget)?;
            ledger.admit_tail(id, full, &input.document.source, &span.span, budget)?;
            budget.charge(1, 1024).map_err(budget_error)?;
            let vector: DenseVector = native
                .graph_read(
                    snapshot,
                    &native.keyspaces.continuous,
                    &vector_key(
                        view.workspace(),
                        view.generation().number,
                        input.document.source.event_id,
                        ordinal as u32,
                    ),
                    budget,
                )?
                .ok_or_else(|| integrity("segmented fresh exact vector absent"))?;
            budget
                .charge(1, ROW_BYTES as u64 * 4)
                .map_err(budget_error)?;
            native.check_dense_vector_token(&vector)?;
            if vector.source != input.document.source
                || vector.event_digest != input.document.event_digest
                || vector.commit != input.document.commit
                || vector.ordinal != ordinal as u32
                || vector.span != span.span
                || vector.policy_domain != input.document.policy_domain
                || vector.profile_digest != view.profile_dense().profile_digest
                || vector.vector_digest != span.vector_digest
            {
                return Err(integrity(
                    "segmented fresh vector differs from full tagged original plan",
                ));
            }
            let values = super::super::super::query::query_vector_values(
                &view.profile_dense().profile,
                vector,
                budget,
            )?;
            let score = tail::tail_cosine(&query.values, &values, budget)?;
            ledger.record_tail_vector()?;
            let bytes =
                crypto::metered_json_len(&(&input.document.source, &span.span), budget, ROW_BYTES)?;
            budget
                .charge(
                    1,
                    bytes as u64 * 4 + size_of::<DenseGraphHit>() as u64 * 2 + 256,
                )
                .map_err(budget_error)?;
            hits.push(DenseGraphHit {
                representation_id: id,
                source: input.document.source.clone(),
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
            work: u64::from(fresh.work_items),
            completion,
        },
        scoring_complete,
    ))
}

fn fresh_fence(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    view: &VerifiedSegmentQueryView,
    document: &DenseDocument,
    policies: &[AccessPolicy],
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    native.check_segment_query_view(context, view, budget)?;
    let current = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(storage_error)?;
    native.authorized_capture_policy_with_budget(
        &current,
        context,
        document.source.event_id,
        budget,
    )?;
    native.authorize_derived_custody_with_budget(
        &current,
        context,
        document.source.event_id,
        budget,
    )?;
    if native.stored_custody_policies_with_budget(&current, document.source.event_id, budget)?
        != policies
    {
        return Err(stale_index());
    }
    Ok(())
}

fn fresh_identity(
    native: &NativeService,
    view: &VerifiedSegmentQueryView,
    document: &DenseDocument,
    ordinal: u32,
    span: &DenseSpan,
    budget: &mut QueryBudget,
) -> ServiceResult<(ContentDigest, RepresentationId)> {
    // These exact identity fields already belong to an authenticated complete
    // document. No fake vector/receipt is built to derive the compact locator.
    let bytes = crypto::metered_encode(
        &(
            "native-span-ann-member/v1",
            &native.database_id,
            view.workspace(),
            view.generation().number,
            &document.source,
            document.event_digest,
            document.commit,
            ordinal,
            &span.span,
            &document.policy_domain,
            document.profile_digest,
            span.vector_digest,
        ),
        budget,
        ROW_BYTES,
    )?;
    let full = digest(&bytes);
    let mut compact = [0; 16];
    compact.copy_from_slice(&full.as_bytes()[..16]);
    compact[6] = (compact[6] & 15) | 128;
    compact[8] = (compact[8] & 63) | 128;
    let id = RepresentationId::from_uuid(uuid::Uuid::from_bytes(compact)).map_err(ann_error)?;
    Ok((full, id))
}
