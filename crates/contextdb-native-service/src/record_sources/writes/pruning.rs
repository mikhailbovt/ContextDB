use super::*;
use crate::suppression::RemovalCheckpoint;

impl NativeService {
    pub(crate) fn retain_record_write_validations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        witness: &NativeRecordRemovalWitnessReceipt,
        policy: &StoredPolicy,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<u64, RemovalCheckpoint>> {
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("record pruning authority absent"))?;
        let mut validations = BTreeMap::new();
        for global in std::iter::once(policy.transaction_from).chain(policy.transaction_to) {
            let event = self.recovery_global_event(snapshot, global, budget)?;
            if !is_source_write(&event.operation) {
                continue;
            }
            let intent = self.budgeted_record_write_intent(snapshot, &event, &mut Some(budget))?;
            // Every member is authorized before checking complete group bodies.
            for origin in intent
                .origins
                .iter()
                .chain(intent.group.iter().flat_map(|group| &group.previous))
            {
                let bytes = control_bytes(
                    snapshot,
                    &self.keyspaces.policy_history,
                    &history_key(&origin.record_digest, origin.revision),
                    MAX_INTENT_BYTES,
                    &mut Some(budget),
                )?
                .ok_or_else(|| integrity("record validation member policy absent"))?;
                let member: StoredPolicy = decode(&bytes, "record validation member policy")?;
                validate_stored_policy(&member)?;
                if member.record_digest != origin.record_digest
                    || member.revision != origin.revision
                    || digest_bytes(member.access.workspace_id.as_bytes()) != event.workspace_digest
                {
                    return Err(integrity("record validation member identity differs"));
                }
                let mut access = member.access;
                access.retrievable = true;
                if !policy_allows(&context.request, &access) {
                    return Err(permission_denied());
                }
            }
            self.verified_record_write_intent(snapshot, &event, budget)?;
            let completion = self
                .budgeted_record_write_completion(snapshot, &event, &mut Some(budget))?
                .ok_or_else(|| integrity("record pruning requires a completed source handoff"))?;
            let publication = completion
                .accepted_record_write_completion
                .as_ref()
                .ok_or_else(|| integrity("record source completion declaration absent"))?;
            self.verify_record_write_bindings(&intent, &publication.through, budget)?;
            validations.insert(
                global,
                ledger.retain_record_write_validation(witness, &event, budget)?,
            );
        }
        Ok(validations)
    }

    pub(super) fn record_write_has_pruned_members<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("record pruning authority absent"))?;
        let mut removed = false;
        let mut remaining = Vec::new();
        for reference in &event.accepted_records {
            let (record, revision) = record_journal::controls::witness::pruning::mutation_identity(
                event.global_commit,
                &reference.key,
            )?;
            if let Some(pruned) = self.pruned_record(snapshot, record, revision, budget)? {
                pruned.check_write(ledger, event, budget)?;
                removed = true;
            } else {
                remaining.push(reference.clone());
            }
        }
        if removed && !remaining.is_empty() {
            self.record_group_records(
                snapshot,
                event.global_commit,
                &event.workspace_digest,
                &remaining,
                budget,
            )?;
        }
        Ok(removed)
    }
}
