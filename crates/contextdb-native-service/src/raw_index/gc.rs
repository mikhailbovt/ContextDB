//! Incremental reclamation of unreachable raw-index generations.

#[cfg(test)]
mod tests;

use super::*;

const MAX_RECLAIM_ROWS: u32 = 1024;
const MAX_RECLAIM_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reclaiming {
    pub generation: u64,
    pub removed_rows: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copies: Option<NativeRawCopyReceipt>,
}

/// Logical index-row reclamation, not a physical erasure receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawReclaimProgress {
    /// Selected obsolete generation; absent when no generation can be reclaimed.
    pub generation: Option<u64>,
    /// Rows removed in this call, excluding the final generation manifest.
    pub removed_rows: u32,
    /// Total rows removed from this selected generation across calls.
    pub total_removed_rows: u64,
    /// This generation is reclaimed, or no generation was eligible.
    pub finished: bool,
    /// Remaining manifests, including an unfinished reclamation job.
    pub retained_generations: u32,
    /// Independently retained pre-deletion observations, when an authority is
    /// available. Absence on a legacy page is not proof of historical coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copies: Option<NativeRawCopyReceipt>,
}

impl NativeService {
    /// Reclaim 1..1024 rows from one obsolete raw-index generation.
    /// Active and current building generations are protected. An unfinished
    /// build with obsolete authorization/format may be abandoned. Original
    /// capture, journal and revocation records are never removed by this API.
    pub fn reclaim_raw_generations(
        &self,
        context: &AuthenticatedRequestContext,
        max_rows: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RawReclaimProgress> {
        require_capability(context, Capability::Admin)?;
        if !(1..=MAX_RECLAIM_ROWS).contains(&max_rows) {
            return Err(super::super::invalid(
                "raw reclamation batch must contain 1..1024 rows",
            ));
        }
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let expected: IndexState = self
            .raw_value(&snapshot, &state_key(&workspace))?
            .unwrap_or_default();
        let mut retained = retained_generations(&expected)?;
        let mut state = expected.clone();
        let epoch = self.raw_authorization_epoch(&snapshot, &workspace)?;
        let job = if let Some(job) = &state.reclaiming {
            Some(job.clone())
        } else {
            let mut selected = None;
            for &number in &retained {
                budget.charge(1, 0).map_err(budget_error)?;
                if state.active == Some(number) {
                    continue;
                }
                if state.building == Some(number) {
                    let generation: Generation = self
                        .raw_value(&snapshot, &generation_key(&workspace, number))?
                        .ok_or_else(|| integrity("building raw manifest absent"))?;
                    if generation.authorization_epoch == epoch
                        && generation.custody_version == super::super::custody::CUSTODY_VERSION
                        && generation.analyzer == RAW_ANALYZER
                    {
                        continue;
                    }
                    state.building = None;
                }
                selected = Some(Reclaiming {
                    generation: number,
                    removed_rows: 0,
                    copies: None,
                });
                break;
            }
            selected
        };
        let Some(mut job) = job else {
            return Ok(RawReclaimProgress {
                generation: None,
                removed_rows: 0,
                total_removed_rows: 0,
                finished: true,
                retained_generations: retained.len() as u32,
                copies: None,
            });
        };
        let prefix = generation_prefix(&workspace, job.generation);
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: max_rows as usize,
                    max_bytes: MAX_RECLAIM_BYTES,
                },
            )
            .map_err(storage_error)?;
        for entry in &page.entries {
            budget
                .charge(1, (entry.key.len() + entry.value.len()) as u64)
                .map_err(budget_error)?;
        }
        let finished = page.continuation.is_none();
        let observation = self
            .suppression
            .as_ref()
            .filter(|ledger| ledger.supports_removal())
            .map(|_| {
                self.observe_raw_copies(
                    &snapshot,
                    &context.request.workspace_id,
                    &job,
                    &page.entries,
                    finished,
                    budget,
                )
            })
            .transpose()?;
        let removed_rows = page.entries.len() as u32;
        job.removed_rows = job
            .removed_rows
            .checked_add(u64::from(removed_rows))
            .ok_or_else(|| exhausted("raw reclamation row count overflow"))?;
        let mut progress = RawReclaimProgress {
            generation: Some(job.generation),
            removed_rows,
            total_removed_rows: job.removed_rows,
            finished,
            retained_generations: (retained.len() - usize::from(finished)) as u32,
            copies: None,
        };
        drop(snapshot);
        #[cfg(test)]
        BEFORE_COPY_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let current: IndexState = self
            .raw_value(&tx, &state_key(&workspace))?
            .unwrap_or_default();
        if current != expected {
            return Err(stale_index());
        }
        if let Some(observation) = &observation {
            if self.global_head(&tx)? != observation.native_commit {
                return Err(stale_index());
            }
            self.enable_capture_extension(&mut tx, COPY_FEATURE)?;
            let receipt = self
                .suppression
                .as_ref()
                .ok_or_else(|| integrity("raw copy authority absent"))?
                .retain_raw_copy_witness(observation, budget)?;
            job.copies = Some(receipt.clone());
            progress.copies = Some(receipt);
        }
        self.enable_capture_extension(&mut tx, GC_FEATURE)?;
        for entry in page.entries {
            budget.check().map_err(budget_error)?;
            tx.delete(&self.keyspaces.continuous, entry.key)
                .map_err(storage_error)?;
        }
        if finished {
            retained.remove(&job.generation);
            tx.delete(
                &self.keyspaces.continuous,
                generation_key(&workspace, job.generation),
            )
            .map_err(storage_error)?;
            state.reclaiming = None;
        } else {
            state.reclaiming = Some(job);
        }
        state.retained = Some(retained);
        retained_generations(&state)?;
        tx.put(
            &self.keyspaces.continuous,
            state_key(&workspace),
            encode(&state)?,
        )
        .map_err(storage_error)?;
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        let digest = canonical_digest(&(&workspace, frame.global_commit, &progress))?;
        self.finish_frame(
            &mut tx,
            &frame,
            if progress.copies.is_some() {
                "raw_reclamation_with_copies"
            } else {
                "raw_reclamation"
            },
            digest.as_bytes(),
            &digest,
            &progress,
        )?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(progress)
    }
}

pub(crate) fn retained_generations(state: &IndexState) -> ServiceResult<BTreeSet<u64>> {
    let retained = match &state.retained {
        Some(retained) => retained.clone(),
        None if state.next <= MAX_GENERATIONS => (1..=state.next).collect(),
        None => return Err(integrity("legacy raw generation count invalid")),
    };
    if retained.len() > MAX_GENERATIONS as usize
        || retained
            .iter()
            .any(|number| *number == 0 || *number > state.next)
        || (state.active.is_some() && state.active == state.building)
        || state
            .active
            .into_iter()
            .chain(state.building)
            .any(|number| !retained.contains(&number))
        || state.reclaiming.as_ref().is_some_and(|job| {
            !retained.contains(&job.generation)
                || Some(job.generation) == state.active
                || Some(job.generation) == state.building
        })
    {
        return Err(integrity("raw generation retention state invalid"));
    }
    Ok(retained)
}

#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_COPY_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
