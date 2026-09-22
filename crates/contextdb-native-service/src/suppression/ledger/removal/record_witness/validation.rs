//! Retain the result of checking a complete source-aware write before any of its
//! bodies are erased. The exact event and intent commitments preserve that proof
//! across native restore; they never authorize a different or modified group.

use super::*;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::suppression::ledger::removal) struct RecordWriteValidation {
    request: RemovalCheckpoint,
    witness: RemovalCheckpoint,
    workspace: String,
    global_commit: u64,
    workspace_commit: u64,
    event_digest: String,
    intent_digest: String,
}

impl RecordWriteValidation {
    pub(in crate::suppression::ledger::removal) fn validate(
        &self,
        sequence: u64,
    ) -> ServiceResult<()> {
        for digest in [
            &self.request.digest,
            &self.witness.digest,
            &self.workspace,
            &self.event_digest,
            &self.intent_digest,
        ] {
            valid_digest(digest)?;
        }
        if self.request.sequence == 0
            || self.witness.sequence <= self.request.sequence
            || self.witness.sequence >= sequence
            || self.global_commit == 0
            || self.workspace_commit == 0
        {
            return Err(integrity(
                "record write validation has an invalid acceptance order",
            ));
        }
        Ok(())
    }

    pub(in crate::suppression::ledger::removal) fn key(&self) -> Vec<u8> {
        format!(
            "removal/record-validation/{}/{:020}/{:020}",
            self.workspace, self.request.sequence, self.global_commit
        )
        .into_bytes()
    }

    fn matches(&self, event: &StoredEvent) -> ServiceResult<bool> {
        Ok(self.global_commit == event.global_commit
            && self.workspace_commit == event.workspace_commit
            && self.workspace == event.workspace_digest
            && self.event_digest == event.event_digest
            && event.event_digest == event_digest(event)?
            && event
                .accepted_record_write
                .as_ref()
                .is_some_and(|intent| intent.digest == self.intent_digest)
            && crate::record_sources::writes::is_source_write(&event.operation))
    }
}

impl NativeSuppressionLedger {
    pub(crate) fn retain_record_write_validation(
        &self,
        witness_receipt: &NativeRecordRemovalWitnessReceipt,
        write: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RemovalCheckpoint> {
        self.require_removal_authority()?;
        if witness_receipt.authority_id != self.authority_id() {
            return Err(invalid(
                "record write validation belongs to another authority",
            ));
        }
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let witness = RemovalCheckpoint {
            sequence: witness_receipt.witness_sequence,
            digest: witness_receipt.digest.clone(),
        };
        let (declaration, control) = self.record_witness_at(&tx, &witness, budget)?;
        if witness_receipt.removal_sequence != declaration.request.sequence
            || witness_receipt.record_digest != declaration.record_digest
            || witness_receipt.revision != declaration.revision
            || witness_receipt.mutation_commit != declaration.mutation_commit
        {
            return Err(integrity("record validation witness receipt differs"));
        }
        let validation = RecordWriteValidation {
            request: declaration.request.clone(),
            witness,
            workspace: declaration.workspace.clone(),
            global_commit: write.global_commit,
            workspace_commit: write.workspace_commit,
            event_digest: write.event_digest.clone(),
            intent_digest: write
                .accepted_record_write
                .as_ref()
                .ok_or_else(|| integrity("record validation lacks an accepted intent"))?
                .digest
                .clone(),
        };
        if !control.covers_mutation(write.global_commit) || !validation.matches(write)? {
            return Err(integrity(
                "record write validation is unrelated to its removal witness",
            ));
        }
        if let Some((checkpoint, operation)) = self.find_retained_control(
            &tx,
            &validation.workspace,
            &validation.request,
            &validation.key(),
            budget,
        )? {
            let Operation::RecordValidation {
                validation: previous,
            } = operation
            else {
                return Err(integrity("record validation locator has another operation"));
            };
            // Another affected revision can retain the same checked group first.
            if !previous.matches(write)? {
                return Err(integrity(
                    "record write validation changed its accepted group",
                ));
            }
            self.verify_record_validation(&tx, &checkpoint, &previous, budget)?;
            return Ok(checkpoint);
        }
        let checkpoint = self.append_removal_event(
            &mut tx,
            Operation::RecordValidation {
                validation: validation.clone(),
            },
        )?;
        tx.put(&self.rows, validation.key(), encode(&checkpoint)?)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(checkpoint)
    }

    pub(crate) fn check_record_write_validation(
        &self,
        checkpoint: &RemovalCheckpoint,
        write: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.require_removal_authority()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let event = self.budgeted_removal_event(&snapshot, checkpoint.sequence, budget)?;
        let Operation::RecordValidation { validation } = &event.operation else {
            return Err(integrity(
                "retained record validation has another operation",
            ));
        };
        if event.checkpoint() != *checkpoint
            || !validation.matches(write)?
            || self.find_retained_control(
                &snapshot,
                &validation.workspace,
                &validation.request,
                &validation.key(),
                budget,
            )? != Some((checkpoint.clone(), event.operation.clone()))
        {
            return Err(integrity(
                "record validation differs from current accepted history",
            ));
        }
        self.verify_record_validation(&snapshot, checkpoint, validation, budget)
    }

    fn verify_record_validation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        checkpoint: &RemovalCheckpoint,
        validation: &RecordWriteValidation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        validation.validate(checkpoint.sequence)?;
        let (declaration, witness) =
            self.record_witness_at(snapshot, &validation.witness, budget)?;
        if declaration.workspace != validation.workspace
            || declaration.request != validation.request
            || !witness.covers_mutation(validation.global_commit)
        {
            return Err(integrity(
                "record write validation lost its covered removal mutation",
            ));
        }
        Ok(())
    }

    pub(in crate::suppression::ledger::removal) fn verify_record_validation_rows<
        S: ReadSnapshot,
    >(
        &self,
        snapshot: &S,
        event: &Event,
        validation: &RecordWriteValidation,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        self.verify_record_validation(
            snapshot,
            &event.checkpoint(),
            validation,
            &mut inventory::verification_budget(),
        )?;
        if expected
            .insert(validation.key(), encode(&event.checkpoint())?)
            .is_some()
        {
            return Err(integrity("duplicate retained record write validation"));
        }
        Ok(())
    }
}
