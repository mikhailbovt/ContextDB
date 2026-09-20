//! Activate retained origin requirements before the first generic record.

use super::*;

/// The first retained provenance checkpoint for a workspace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordSourceWorkspaceReceipt {
    /// Independently retained authority that owns the checkpoint.
    pub authority_id: uuid::Uuid,
    /// Commitment to the workspace identity.
    pub workspace_digest: String,
    /// First workspace-local provenance epoch.
    pub epoch: u64,
    /// Exact retained checkpoint commitment.
    pub digest: String,
}

impl NativeService {
    /// Require captured origins before creating any generic record in this
    /// workspace. Existing unclassified records require explicit migration.
    /// Call `maintain_record_sources` to apply the retained checkpoint before
    /// using the workspace. Repeated calls return its original checkpoint.
    pub fn initialize_record_sources(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordSourceWorkspaceReceipt> {
        require_capability(context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        validate_identifier(&context.request.workspace_id, "record source workspace")?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("record provenance requires retained authority"))?;
        if !ledger.supports_record_sources() {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "record provenance requires a version 3 authority",
                false,
            ));
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        if ledger.current_record_sources(&workspace)?.is_none() {
            self.require_no_record_history(&snapshot, &world, budget)?;
        }
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let latest = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self.workspace_state(&latest, &context.request.workspace_id)? != world {
            return Err(pending(
                "workspace changed while initializing record provenance",
            ));
        }
        let checkpoint = ledger.register_record_sources_workspace(&workspace, budget)?;
        #[cfg(test)]
        AFTER_AUTHORITY_SYNC.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        Ok(NativeRecordSourceWorkspaceReceipt {
            authority_id: ledger.authority_id(),
            workspace_digest: workspace,
            epoch: checkpoint.epoch,
            digest: checkpoint.digest,
        })
    }

    fn require_no_record_history<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        world: &WorkspaceState,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        // Walk only this workspace's accepted history. Hash-only legacy writes
        // also count; missing record projections cannot imply an empty history.
        for commit in 1..=world.watermarks.journal {
            let bytes = snapshot
                .get(
                    &self.keyspaces.workspace_map,
                    &workspace_map_key(&world.workspace_digest, commit),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record initialization lost a workspace commit"))?;
            budget
                .charge(1, bytes.len() as u64)
                .map_err(raw_index::budget_error)?;
            let mapping: CommitMap = decode(&bytes, "record initialization workspace commit")?;
            validate_workspace_state(&mapping.state, &world.workspace_digest)?;
            if mapping.schema_version != SCHEMA_VERSION
                || mapping.global_commit == 0
                || mapping.state.latest_global_commit != mapping.global_commit
                || mapping.state.watermarks.journal != commit
                || (commit == world.watermarks.journal && mapping.state != *world)
            {
                return Err(integrity("record initialization workspace mapping differs"));
            }
            let bytes = snapshot
                .get(&self.keyspaces.events, &mapping.global_commit.to_be_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record initialization lost an accepted event"))?;
            budget
                .charge(1, bytes.len() as u64)
                .map_err(raw_index::budget_error)?;
            let event: StoredEvent = decode(&bytes, "record initialization accepted history")?;
            if event.schema_version != SCHEMA_VERSION
                || event.global_commit != mapping.global_commit
                || event.workspace_digest != world.workspace_digest
                || event.workspace_commit != commit
                || event.event_digest != event_digest(&event)?
            {
                return Err(integrity("record initialization accepted history differs"));
            }
            if !event.accepted_records.is_empty()
                || matches!(
                    event.operation.as_str(),
                    "publish_memory" | "propose_memory" | "correct" | "retract"
                )
            {
                return Err(unsupported(
                    "existing records require explicit provenance migration",
                ));
            }
        }
        // Also reject unjournaled legacy projections or a missing workspace head.
        let mut after: Option<Vec<u8>> = None;
        loop {
            budget.check().map_err(raw_index::budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.policy_history,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 256,
                        max_bytes: 512 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in &page.entries {
                budget
                    .charge(1, row.value.len() as u64)
                    .map_err(raw_index::budget_error)?;
                let policy: StoredPolicy = decode(&row.value, "record initialization policy")?;
                validate_stored_policy(&policy)?;
                if digest_bytes(policy.access.workspace_id.as_bytes()) == world.workspace_digest {
                    return Err(unsupported(
                        "existing records require explicit provenance migration",
                    ));
                }
            }
            after = page.continuation;
            if after.is_none() {
                break;
            }
        }
        Ok(())
    }
}
