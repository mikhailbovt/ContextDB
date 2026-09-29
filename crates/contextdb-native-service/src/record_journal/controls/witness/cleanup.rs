//! Administrative discovery without inferring missing record origins.

use super::pruning::mutation_address;
use super::*;

impl NativeService {
    pub(crate) fn advance_removal_record(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        selected: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("record cleanup requires retained origins"))?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let mut after = None;
        loop {
            budget.check().map_err(raw_index::budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.policy_history,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 256,
                        max_bytes: 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                budget
                    .charge(1, row.value.len() as u64)
                    .map_err(raw_index::budget_error)?;
                let policy: StoredPolicy = decode(&row.value, "archive record cleanup policy")?;
                validate_stored_policy(&policy)?;
                if row.key != history_key(&policy.record_digest, policy.revision) {
                    return Err(integrity("archive record cleanup policy address differs"));
                }
                if digest_bytes(policy.access.workspace_id.as_bytes()) != workspace {
                    continue;
                }
                let binding = ledger
                    .retained_record_sources(&workspace, &policy.record_digest, policy.revision)?
                    .ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::EvidenceRequired,
                            "classify every generic revision before archive cleanup",
                            false,
                        )
                    })?;
                let origin = binding.record_control()?;
                self.verify_local_record_origin(&snapshot, origin, budget)?;
                let Some(removed_source) = origin
                    .sources
                    .keys()
                    .find(|id| selected.contains(id))
                    .copied()
                else {
                    continue;
                };
                let mut access = policy.access.clone();
                access.retrievable = true;
                if !policy_allows(&context.request, &access) {
                    return Err(permission_denied());
                }
                if self
                    .pruned_record(&snapshot, &policy.record_digest, policy.revision, budget)?
                    .is_some()
                {
                    continue;
                }
                for global in std::iter::once(policy.transaction_from).chain(policy.transaction_to)
                {
                    let event = self.recovery_global_event(&snapshot, global, budget)?;
                    let key = mutation_address(global, &policy.record_digest, policy.revision);
                    let reference = event
                        .accepted_records
                        .iter()
                        .find(|reference| reference.key == key)
                        .ok_or_else(|| {
                            unsupported(
                                "archive record cleanup requires replayable mutation history",
                            )
                        })?;
                    if self
                        .budgeted_record_mutation_control(
                            &snapshot,
                            &event,
                            reference,
                            self.record_control_activation(&snapshot)?,
                            Some(budget),
                        )?
                        .is_none()
                    {
                        if !self.has_record_control_preparation(&snapshot, global)? {
                            self.prepare_record_controls(context, event.workspace_commit, budget)?;
                            return Ok(true);
                        }
                        self.prepared_record_controls(&snapshot, &event, budget)?;
                    }
                }
                let bytes = read_bytes(
                    &snapshot,
                    &self.keyspaces.content_history,
                    &history_key(&policy.record_digest, policy.revision),
                    MAX_BYTES,
                    budget,
                )?;
                let record = self.decode_content(&bytes, &policy)?;
                let witness = self.prepare_record_removal(
                    context,
                    request,
                    &record.document.id,
                    policy.revision,
                    removed_source,
                    budget,
                )?;
                self.prune_record_revision(context, &witness, budget)?;
                return Ok(true);
            }
            let Some(next) = page.continuation else {
                break;
            };
            after = Some(next);
        }
        Ok(false)
    }
}
