//! Bounded work batches; graph maintenance remains an explicit operator action.
use super::*;
use contextdb_native_service::{DenseProjectionReceipt, NativeRoutedMaintenanceTarget};

fn stale() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "routed preparation requires current accepted prefix and directory router; run explicit maintenance",
        false,
    )
}
fn capacity() -> ServiceError {
    ServiceError::new(
        ErrorCode::ResourceExhausted,
        "routed fresh capacity requires explicit maintenance before another model step",
        true,
    )
}
fn integrity() -> ServiceError {
    ServiceError::new(
        ErrorCode::IntegrityFailure,
        "routed maintenance target changed its accepted generation, roots or profile",
        false,
    )
}
fn allowance(parent: &mut QueryBudget, work: u64, bytes: u64) -> ServiceResult<()> {
    parent.charge(work, bytes).map_err(|_| {
        ServiceError::new(
            ErrorCode::BudgetExhausted,
            "routed preparation parent allowance exhausted",
            false,
        )
    })
}

fn admit<'a>(
    status: &'a NativeRoutedMaintenanceTarget,
    encoder: &dyn TextEmbeddingAdapter,
    limits: OwnedHybridLimits,
    parent: &mut QueryBudget,
) -> ServiceResult<(&'a DenseProjectionReceipt, &'a DenseProjectionReceipt, u64)> {
    let dense = status.dense.as_ref().ok_or_else(stale)?;
    let covered = status.covered.as_ref().ok_or_else(stale)?;
    if status.base.is_none() || status.router.is_none() || !status.router_matches_directory {
        return Err(stale());
    }
    if status.directory.is_some() != status.directory_ref.is_some() {
        return Err(integrity());
    }
    // Compatibility metadata is strictly bounded before digest allocations.
    allowance(parent, 1, 32 * 1024)?;
    encoder.profile().validate()?;
    if encoder.profile() != &dense.profile
        || dense.profile != covered.profile
        || dense.profile_digest != covered.profile_digest
        || dense.profile.digest()? != dense.profile_digest
        || dense.generation != status.generation
        || covered.generation != status.generation
        || dense.authorization_epoch != status.authorization_epoch
        || covered.authorization_epoch != status.authorization_epoch
    {
        return Err(integrity());
    }
    let work_upper = status
        .raw_through
        .checked_sub(covered.through)
        .ok_or_else(integrity)?;
    let fresh_spans = dense
        .spans
        .checked_sub(covered.spans)
        .ok_or_else(integrity)?;
    if work_upper > u64::from(limits.tail_work) || fresh_spans > u64::from(limits.tail_vectors) {
        return Err(capacity());
    }
    Ok((dense, covered, fresh_spans))
}

/// Compare two already admitted native targets; this creates no authority.
pub(super) fn check_progress(
    before: &NativeRoutedMaintenanceTarget,
    after: &NativeRoutedMaintenanceTarget,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    let dense = before.dense.as_ref().ok_or_else(stale)?;
    let current = after.dense.as_ref().ok_or_else(stale)?;
    allowance(parent, 64, 128 * 1024)?;
    if after.generation != before.generation
        || after.authorization_epoch != before.authorization_epoch
        || after.raw_through != before.raw_through
        || after.raw_sources != before.raw_sources
        || after.base != before.base
        || after.directory != before.directory
        || after.directory_ref != before.directory_ref
        || after.covered != before.covered
        || after.router != before.router
        || current.profile != dense.profile
        || current.profile_digest != dense.profile_digest
        || current.sources < dense.sources
        || current.spans < dense.spans
        || current.embedded_sources < dense.embedded_sources
        || current.omitted_sources < dense.omitted_sources
        || current.through < dense.through
    {
        return Err(integrity());
    }
    if current.through <= dense.through || current.global_commit <= dense.global_commit {
        return Err(capacity());
    }
    Ok(())
}

pub(super) fn advance(
    owner: &NativeService,
    context: &AuthenticatedRequestContext,
    encoder: &dyn TextEmbeddingAdapter,
    limits: OwnedHybridLimits,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    allowance(parent, 1, 256)?;
    limits.validate()?;
    if limits.routed.is_none() || limits.segments.is_some() {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "routed preparation requires only the explicit routed profile",
            false,
        ));
    }
    let mut raw_caught_up = false;
    for _ in 0..HYBRID_MAX_BATCHES {
        let raw = owner.project_originals_bm25(context, false, HYBRID_BATCH_EVENTS, parent)?;
        if raw.caught_up {
            raw_caught_up = true;
            break;
        }
    }
    if !raw_caught_up {
        return Err(capacity());
    }
    let mut before = owner.original_span_routed_maintenance_target(context, parent)?;
    for _ in 0..ROUTED_MAX_BATCHES {
        let (dense, _, fresh_spans) = admit(&before, encoder, limits, parent)?;
        if dense.caught_up && before.dense_matches_raw {
            return Ok(());
        }
        // CaptureWork includes omitted controls, not just vectors. Charge each
        // real batch to the same parent and recompute its worst-case capacity.
        let batch = (u64::from(limits.tail_vectors) - fresh_spans) / 64;
        let batch = batch.min(u64::from(ROUTED_BATCH_EVENTS)) as u32;
        if batch == 0 {
            return Err(capacity());
        }
        owner.project_original_spans(context, encoder, batch, parent)?;
        let after = owner.original_span_routed_maintenance_target(context, parent)?;
        let (current, _, _) = admit(&after, encoder, limits, parent)?;
        check_progress(&before, &after, parent)?;
        if current.caught_up && after.dense_matches_raw {
            return Ok(());
        }
        before = after;
    }
    Err(capacity())
}
