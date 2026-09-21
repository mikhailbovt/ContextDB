//! Verify owned native and archive obligations before accepting current key refusal.

use super::*;
use uuid::Uuid;

#[cfg(test)]
mod tests;

impl NativeService {
    /// Retire 1..256 exclusively owned v4 keys after their tracked native copies
    /// are removed and all selected archive obligations have available replacements.
    /// The service derives current ownership/use/preservation evidence; serialized
    /// caller reports never authorize this mutation. Mixed assertion keys require
    /// their independent-version preservation contract and are not owned selections.
    ///
    /// Current refusal survives native restore and covers old snapshots and new
    /// native publication/import. It does not destroy wrapped keys, erase external
    /// copies, finish deletion or reopen disclosure. Exact accepted retries return
    /// the same receipt. An uncertain custody Sync requires authority recovery.
    pub fn retire_removal_keys(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        selection: &NativeRemovalKeySelection,
        key_ids: &BTreeSet<Uuid>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeKeyRetirement> {
        if !(1..=256).contains(&key_ids.len()) || key_ids.iter().any(Uuid::is_nil) {
            return Err(invalid(
                "key retirement requires 1..256 distinct key identities",
            ));
        }
        let report = self.read_removal_backup_inventory(context, request, selection, budget)?;
        let mut allocations = BTreeMap::new();
        for disposition in report.dispositions.values().flatten() {
            budget.charge(1, 0).map_err(raw_index::budget_error)?;
            if key_ids.contains(&disposition.allocation.key_id) {
                if disposition.action != NativeOwnedKeyAction::AssessRetainedCopies {
                    return Err(invalid(
                        "selected key still has prepared or acknowledged native copies",
                    ));
                }
                allocations.insert(
                    disposition.allocation.key_id,
                    disposition.allocation.clone(),
                );
            }
        }
        if allocations.keys().ne(key_ids.iter()) {
            return Err(invalid(
                "key retirement contains identities outside retained ownership",
            ));
        }
        let mut targets = BTreeSet::new();
        let archives: BTreeMap<_, _> = report
            .backups
            .archives
            .iter()
            .map(|archive| (archive.registration.sequence, archive))
            .collect();
        for status in report.preservation.values() {
            budget.charge(1, 0).map_err(raw_index::budget_error)?;
            match status {
                NativeBackupPreservation::NotRequired => {}
                NativeBackupPreservation::Preserved { path, artifact } => {
                    let target = archives
                        .get(&path.target_sequence)
                        .ok_or_else(|| integrity("key retirement preservation target is absent"))?;
                    if target
                        .artifact
                        .as_ref()
                        .is_none_or(|progress| !progress.complete || progress.receipt != *artifact)
                    {
                        return Err(integrity("key retirement preservation artifact differs"));
                    }
                    targets.insert(target.registration.archive_digest.clone());
                }
                _ => return Err(invalid("selected archive preservation remains unresolved")),
            }
        }
        let (revision, digest, usage) = match &report.key_inventory {
            NativeRemovalKeyInventory::Originals(primary) => (
                primary.allocation_revision,
                primary.allocation_digest.clone(),
                witness::tracked(primary)?,
            ),
            NativeRemovalKeyInventory::Owned(owned) => (
                owned.allocation_revision,
                owned.allocation_digest.clone(),
                &owned.native_use,
            ),
        };
        let report_bytes = encode(&report)?;
        budget
            .charge(1, report_bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        let value = NativeKeyRetirement {
            receipt: NativeKeyRetirementReceipt {
                authority_id: usage.authority_id,
                sequence: 0,
                digest: String::new(),
            },
            workspace_digest: digest_bytes(context.request.workspace_id.as_bytes()),
            request: request.clone(),
            selection: selection.clone(),
            keys: allocations.into_values().collect(),
            evidence: NativeKeyRetirementEvidence {
                allocation_revision: revision,
                allocation_digest: digest,
                use_revision: usage.revision,
                use_digest: usage.revision_digest.clone(),
                backups: report.backups.frontier.clone(),
                report_digest: digest_bytes(&report_bytes),
            },
        };
        #[cfg(test)]
        BEFORE_RETIREMENT_FENCE.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        self.engine
            .keys
            .as_ref()
            .ok_or_else(|| unsupported("key retirement requires retained custody"))?
            .accept_key_retirement(value, usage, &targets, budget)
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_RETIREMENT_FENCE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
