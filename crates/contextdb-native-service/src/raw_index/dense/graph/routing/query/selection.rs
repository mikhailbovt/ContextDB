//! Distinct immutable targets from every actual coarse score, before any beam.
use super::*;

pub(super) fn select_paths(
    scores: &[HybridCoarseScore],
    limit: usize,
    parent: &mut QueryBudget,
) -> ServiceResult<(Vec<DirectoryRouterFinePathV1>, bool)> {
    if !(1..=64).contains(&limit) || scores.len() > MAX_REPRESENTATIVES {
        return Err(crate::invalid("routed distinct path beam is invalid"));
    }
    let height = u64::from(usize::BITS - scores.len().max(1).leading_zeros());
    parent
        .charge(
            scores.len() as u64 * (height * 16 + 64) + 1,
            scores.len() as u64 * size_of::<&HybridCoarseScore>() as u64 + 256,
        )
        .map_err(budget_error)?;
    for score in scores {
        parent.check().map_err(budget_error)?;
        let bytes = crypto::metered_json_len(&score.path, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 * 16 + 1, 0)
            .map_err(budget_error)?;
        score.path.validate()?;
        if !f32::from_bits(score.score_bits).is_finite() {
            return Err(integrity("routed distinct selection has nonfinite score"));
        }
    }
    let mut ranked: Vec<&HybridCoarseScore> = scores.iter().collect();
    // Adjacent full-path equality catches an ordinal alias; within one target
    // the first row is its genuine maximum observed score, with stable ID ties.
    ranked.sort_unstable_by(|a, b| {
        a.path
            .ordinal()
            .cmp(&b.path.ordinal())
            .then_with(|| f32::from_bits(b.score_bits).total_cmp(&f32::from_bits(a.score_bits)))
            .then(a.representation_id.cmp(&b.representation_id))
    });
    for pair in ranked.windows(2) {
        if pair[0].path.ordinal() == pair[1].path.ordinal() && pair[0].path != pair[1].path {
            return Err(integrity(
                "routed coarse observations alias one fine ordinal",
            ));
        }
    }
    ranked.dedup_by(|a, b| a.path.ordinal() == b.path.ordinal());
    ranked.sort_unstable_by(|a, b| {
        f32::from_bits(b.score_bits)
            .total_cmp(&f32::from_bits(a.score_bits))
            .then(a.representation_id.cmp(&b.representation_id))
    });
    let complete = ranked.len() <= limit;
    let count = ranked.len().min(limit);
    let mut bytes = 0_u64;
    for score in ranked.iter().take(count) {
        bytes = bytes
            .checked_add(crypto::metered_json_len(&score.path, parent, ROW_BYTES)? as u64 * 4)
            .ok_or_else(|| integrity("routed selected path sizing overflow"))?;
    }
    parent
        .charge(
            count as u64 + 1,
            bytes + count as u64 * size_of::<DirectoryRouterFinePathV1>() as u64 + 256,
        )
        .map_err(budget_error)?;
    Ok((
        ranked
            .into_iter()
            .take(count)
            .map(|score| score.path.clone())
            .collect(),
        complete,
    ))
}
