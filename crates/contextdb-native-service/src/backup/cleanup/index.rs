use super::*;
use crate::raw_index::{self, Generation, IndexState, retained_generations};

impl NativeService {
    pub(super) fn advance_backup_index_cleanup(
        &self,
        context: &AuthenticatedRequestContext,
        sources: &[crate::NativeDeletionSource],
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let state: IndexState = self
            .raw_value(&snapshot, &raw_index::state_key(&workspace))?
            .unwrap_or_default();
        let mut affected = false;
        let mut obsolete = state.reclaiming.is_some();
        let mut stale_build = false;
        let epoch = self.raw_authorization_epoch(&snapshot, &workspace)?;
        for number in retained_generations(&state)? {
            let generation: Generation = self
                .raw_value(&snapshot, &raw_index::generation_key(&workspace, number))?
                .ok_or_else(|| integrity("archive cleanup found a missing index generation"))?;
            budget
                .charge(1, encode(&generation)?.len() as u64)
                .map_err(raw_index::budget_error)?;
            obsolete |= state.active != Some(number) && state.building != Some(number);
            if state.building == Some(number) {
                stale_build = generation.authorization_epoch != epoch
                    || generation.custody_version != crate::custody::CUSTODY_VERSION
                    || generation.analyzer != contextdb_index::RAW_ANALYZER;
            }
            for source in sources {
                budget.charge(1, 0).map_err(raw_index::budget_error)?;
                affected |= (generation.through >= source.receipt.workspace_commit
                    && !self.source_prepared_at(
                        &snapshot,
                        &workspace,
                        source.receipt.event_id,
                        generation.removal_through,
                        budget,
                    )?)
                    || snapshot
                        .get(
                            &self.keyspaces.continuous,
                            &raw_index::doc_key(&workspace, number, source.receipt.event_id),
                        )
                        .map_err(storage_error)?
                        .is_some();
            }
        }
        drop(snapshot);
        if obsolete || stale_build {
            return Ok(self
                .reclaim_raw_generations(context, 1024, budget)?
                .generation
                .is_some());
        }
        if affected {
            self.project_originals(context, state.building.is_none(), 256, budget)?;
            return Ok(true);
        }
        Ok(false)
    }
}
