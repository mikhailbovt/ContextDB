//! A witness is part of the existing independent removal chain. Its accepted
//! request and full blob remain required even when no native body survives.

use super::*;
use crate::record_journal::controls::witness::{MAX_WITNESS_BYTES, RecordRemovalWitness};
use crate::suppression::ledger::record_sources::RecordSourceEntry;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordWitnessDeclaration {
    request: RemovalCheckpoint,
    workspace: String,
    record_digest: String,
    revision: u32,
    mutation_commit: u64,
    origin: RecordSourcesCheckpoint,
    removed_source: ObservationId,
    witness_digest: String,
}

impl RecordWitnessDeclaration {
    pub(super) fn validate(&self, accepted_sequence: u64) -> ServiceResult<()> {
        for digest in [
            &self.request.digest,
            &self.workspace,
            &self.record_digest,
            &self.origin.digest,
            &self.witness_digest,
        ] {
            valid_digest(digest)?;
        }
        if self.request.sequence == 0
            || self.request.sequence >= accepted_sequence
            || self.revision == 0
            || self.mutation_commit == 0
            || self.origin.epoch == 0
        {
            return Err(integrity("retained record witness declaration is invalid"));
        }
        Ok(())
    }

    fn key(&self) -> Vec<u8> {
        format!(
            "removal/record-witness/{}/{:020}/{}/{:010}/{:020}",
            self.workspace,
            self.request.sequence,
            self.record_digest,
            self.revision,
            self.mutation_commit
        )
        .into_bytes()
    }
}

impl NativeSuppressionLedger {
    pub(crate) fn retain_record_removal_witness(
        &self,
        request: &RemovalCheckpoint,
        removed_source: ObservationId,
        origin: &RecordSourceEntry,
        witness: &RecordRemovalWitness,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RemovalCheckpoint> {
        self.require_removal_authority()?;
        witness.validate(origin.record_control()?)?;
        let bytes = encode(witness)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(exhausted("record witness exceeds its bounded profile"));
        }
        let policy = witness.policy();
        let declaration = RecordWitnessDeclaration {
            request: request.clone(),
            workspace: origin.record_control()?.workspace.clone(),
            record_digest: policy.record_digest.clone(),
            revision: policy.revision,
            mutation_commit: policy.transaction_to.unwrap_or(policy.transaction_from),
            origin: origin.checkpoint.clone(),
            removed_source,
            witness_digest: digest_bytes(&bytes),
        };
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        self.verify_record_witness_origin(&tx, &declaration, witness, budget)?;
        if let Some((checkpoint, previous)) = self.find_record_witness(&tx, &declaration, budget)? {
            if previous != declaration {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "record removal witness already has another source or control",
                    false,
                ));
            }
            let retained = self.load_record_witness(&tx, &checkpoint, &previous, budget)?;
            if retained != *witness {
                return Err(integrity(
                    "record witness retry differs from retained metadata",
                ));
            }
            return Ok(checkpoint);
        }
        let accepted = self.append_removal_event(
            &mut tx,
            Operation::RecordWitness {
                witness: declaration.clone(),
            },
        )?;
        tx.put(&self.rows, declaration.key(), encode(&accepted)?)
            .map_err(storage_error)?;
        tx.put(&self.rows, blob_key(accepted.sequence), bytes)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(accepted)
    }

    // Follow the accepted suffix even on retries: a lost index is never absence
    // evidence. No history is restarted, and all work shares the caller's budget.
    fn find_record_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        wanted: &RecordWitnessDeclaration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<(RemovalCheckpoint, RecordWitnessDeclaration)>> {
        let head = self.removal_global_head(snapshot)?;
        if wanted.request.sequence == 0 || wanted.request.sequence > head.sequence {
            return Err(integrity(
                "record witness removal request is outside retained history",
            ));
        }
        let request = self.budgeted_removal_event(snapshot, wanted.request.sequence, budget)?;
        if request.checkpoint() != wanted.request
            || !matches!(&request.operation, Operation::Request { intent, .. } if intent.workspace == wanted.workspace)
        {
            return Err(integrity("record witness removal request differs"));
        }
        let key = wanted.key();
        let mut previous = request.checkpoint();
        let mut found = None;
        for sequence in wanted.request.sequence..head.sequence {
            let event = self.budgeted_removal_event(snapshot, sequence + 1, budget)?;
            if event.previous != previous.digest {
                return Err(integrity("record witness retained suffix is discontinuous"));
            }
            if let Operation::RecordWitness { witness } = &event.operation
                && witness.key() == key
            {
                if found.is_some() {
                    return Err(integrity("duplicate retained record witness"));
                }
                found = Some((event.checkpoint(), witness.clone()));
            }
            previous = event.checkpoint();
        }
        if previous != head {
            return Err(integrity("record witness retained terminal differs"));
        }
        let locator = snapshot.get(&self.rows, &key).map_err(storage_error)?;
        if let Some(bytes) = &locator {
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        }
        if locator
            != found
                .as_ref()
                .map(|(checkpoint, _)| encode(checkpoint))
                .transpose()?
        {
            return Err(integrity(
                "record witness locator differs from accepted history",
            ));
        }
        Ok(found)
    }

    fn budgeted_removal_event<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        sequence: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Event> {
        let bytes = snapshot
            .get(&self.rows, &event_key(sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retained witness event absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > 1024 * 1024 {
            return Err(exhausted("retained witness event exceeds its bound"));
        }
        self.decode_removal_event(&bytes, sequence)
    }

    fn load_record_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        checkpoint: &RemovalCheckpoint,
        declaration: &RecordWitnessDeclaration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RecordRemovalWitness> {
        declaration.validate(checkpoint.sequence)?;
        let bytes = snapshot
            .get(&self.rows, &blob_key(checkpoint.sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("independent record witness absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES || digest_bytes(&bytes) != declaration.witness_digest {
            return Err(integrity(
                "independent record witness differs from its accepted digest",
            ));
        }
        let witness: RecordRemovalWitness = decode(&bytes, "independent record witness")?;
        self.verify_record_witness_origin(snapshot, declaration, &witness, budget)?;
        Ok(witness)
    }

    fn verify_record_witness_origin<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        declaration: &RecordWitnessDeclaration,
        witness: &RecordRemovalWitness,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let origin = self
            .retained_record_sources_at(
                snapshot,
                &declaration.workspace,
                &declaration.record_digest,
                declaration.revision,
            )?
            .ok_or_else(|| integrity("record witness has no retained origin"))?;
        let source = self.removal_source_at(
            snapshot,
            &declaration.workspace,
            &declaration.request,
            declaration.removed_source,
            budget,
        )?;
        let policy = witness.policy();
        if origin.checkpoint != declaration.origin
            || policy.record_digest != declaration.record_digest
            || policy.revision != declaration.revision
            || policy.transaction_to.unwrap_or(policy.transaction_from)
                != declaration.mutation_commit
            || origin
                .record_control()?
                .sources
                .get(&declaration.removed_source)
                != Some(&source.control_digest)
        {
            return Err(integrity(
                "record witness origin or removal binding differs",
            ));
        }
        witness.validate(origin.record_control()?)
    }

    pub(super) fn verify_record_witness_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &Event,
        declaration: &RecordWitnessDeclaration,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        let mut budget = inventory::verification_budget();
        let witness =
            self.load_record_witness(snapshot, &event.checkpoint(), declaration, &mut budget)?;
        if expected
            .insert(declaration.key(), encode(&event.checkpoint())?)
            .is_some()
        {
            return Err(integrity("retained witness repeats a revision mutation"));
        }
        expected.insert(blob_key(event.sequence), encode(&witness)?);
        Ok(())
    }
}

fn blob_key(sequence: u64) -> Vec<u8> {
    format!("removal/record-witness-blob/{sequence:020}").into_bytes()
}

#[cfg(test)]
mod tests;
