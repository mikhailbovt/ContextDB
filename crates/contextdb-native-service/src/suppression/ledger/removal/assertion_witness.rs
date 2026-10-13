//! Mixed assertion ownership accepted in the independent removal journal.

use super::*;
use crate::NativeAssertionRemovalWitnessReceipt;

#[cfg(test)]
mod tests;
use crate::assertions::retention::witness::{AssertionRemovalWitness, MAX_WITNESS_BYTES};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssertionWitnessDeclaration {
    request: RemovalCheckpoint,
    workspace: String,
    assertion_commit: u64,
    scope: contextdb_core::ScopeId,
    selected: BTreeSet<usize>,
    witness_digest: String,
}

impl AssertionWitnessDeclaration {
    pub(super) fn validate(&self, sequence: u64) -> ServiceResult<()> {
        for digest in [&self.request.digest, &self.workspace, &self.witness_digest] {
            valid_digest(digest)?;
        }
        if self.request.sequence == 0
            || self.request.sequence >= sequence
            || self.assertion_commit == 0
            || self.selected.is_empty()
            || self.selected.iter().any(|ordinal| *ordinal >= 64)
        {
            return Err(integrity("assertion witness declaration is invalid"));
        }
        Ok(())
    }

    pub(super) fn key(&self) -> Vec<u8> {
        format!(
            "removal/assertion-witness/{}/{:020}/{:020}",
            self.workspace, self.request.sequence, self.assertion_commit
        )
        .into_bytes()
    }
}

impl NativeSuppressionLedger {
    pub(crate) fn retain_assertion_removal_witness(
        &self,
        request: &RemovalCheckpoint,
        witness: &AssertionRemovalWitness,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RemovalCheckpoint> {
        self.require_assertion_witness_authority()?;
        let workspace = digest_bytes(witness.workspace().as_bytes());
        witness.validate(&self.identity.database, &workspace)?;
        let bytes = encode(witness)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(exhausted("assertion witness exceeds 5 MiB"));
        }
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let declaration = AssertionWitnessDeclaration {
            request: request.clone(),
            workspace: workspace.clone(),
            assertion_commit: witness.assertion_commit(),
            scope: witness.scope(),
            selected: self.assertion_witness_selection(&tx, request, witness, budget)?,
            witness_digest: digest_bytes(&bytes),
        };
        if let Some((checkpoint, operation)) =
            self.find_retained_control(&tx, &workspace, request, &declaration.key(), budget)?
        {
            let Operation::AssertionWitness { witness: previous } = operation else {
                return Err(integrity("assertion witness locator has another operation"));
            };
            if previous != declaration {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "assertion removal witness already has different ownership",
                    false,
                ));
            }
            if self.load_assertion_witness(&tx, &checkpoint, &previous, budget)? != *witness {
                return Err(integrity(
                    "assertion witness retry differs from retained controls",
                ));
            }
            return Ok(checkpoint);
        }
        let accepted = self.append_removal_event(
            &mut tx,
            Operation::AssertionWitness {
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

    pub(crate) fn read_assertion_removal_witness(
        &self,
        receipt: &NativeAssertionRemovalWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(AssertionRemovalWitness, BTreeSet<usize>)> {
        self.require_assertion_witness_authority()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let checkpoint = RemovalCheckpoint {
            sequence: receipt.witness_sequence,
            digest: receipt.digest.clone(),
        };
        let event = self.budgeted_removal_event(&snapshot, checkpoint.sequence, budget)?;
        let Operation::AssertionWitness {
            witness: declaration,
        } = &event.operation
        else {
            return Err(integrity("assertion witness receipt has another operation"));
        };
        if event.checkpoint() != checkpoint
            || receipt.authority_id != self.authority_id()
            || receipt.removal_sequence != declaration.request.sequence
            || receipt.assertion_commit != declaration.assertion_commit
            || receipt.scope != declaration.scope
            || self.find_retained_control(
                &snapshot,
                &declaration.workspace,
                &declaration.request,
                &declaration.key(),
                budget,
            )? != Some((checkpoint.clone(), event.operation.clone()))
        {
            return Err(integrity(
                "assertion witness receipt differs from retained acceptance",
            ));
        }
        Ok((
            self.load_assertion_witness(&snapshot, &checkpoint, declaration, budget)?,
            declaration.selected.clone(),
        ))
    }

    fn require_assertion_witness_authority(&self) -> ServiceResult<()> {
        if !self.supports_record_sources() {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "assertion witnesses require a version 3 removal authority",
                false,
            ));
        }
        Ok(())
    }

    fn assertion_witness_selection<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        request: &RemovalCheckpoint,
        witness: &AssertionRemovalWitness,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeSet<usize>> {
        let workspace = digest_bytes(witness.workspace().as_bytes());
        witness.validate(&self.identity.database, &workspace)?;
        let event = self.budgeted_removal_event(snapshot, request.sequence, budget)?;
        let Operation::Request { intent, .. } = &event.operation else {
            return Err(integrity("assertion witness has no removal request"));
        };
        if event.checkpoint() != *request || intent.workspace != workspace {
            return Err(integrity("assertion witness request binding differs"));
        }
        // Inspect the complete accepted source set: a missing membership locator
        // cannot turn a selected source into an apparently independent mutation.
        let inventory = self.read_removal_inventory(snapshot, intent, budget)?;
        let sources = inventory
            .sources
            .iter()
            .map(|source| source.receipt.event_id)
            .collect();
        let selected = witness.selected(&sources);
        if selected.is_empty() {
            return Err(integrity(
                "assertion witness has no selected source mutation",
            ));
        }
        Ok(selected)
    }

    fn load_assertion_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        checkpoint: &RemovalCheckpoint,
        declaration: &AssertionWitnessDeclaration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AssertionRemovalWitness> {
        let bytes = snapshot
            .get(&self.rows, &blob_key(checkpoint.sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("independent assertion witness is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES || digest_bytes(&bytes) != declaration.witness_digest {
            return Err(integrity(
                "assertion witness differs from its accepted commitment",
            ));
        }
        let witness: AssertionRemovalWitness = decode(&bytes, "independent assertion witness")?;
        if digest_bytes(witness.workspace().as_bytes()) != declaration.workspace
            || witness.assertion_commit() != declaration.assertion_commit
            || witness.scope() != declaration.scope
            || self.assertion_witness_selection(snapshot, &declaration.request, &witness, budget)?
                != declaration.selected
        {
            return Err(integrity(
                "assertion witness source or publication binding differs",
            ));
        }
        Ok(witness)
    }

    pub(super) fn verify_assertion_witness_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &Event,
        declaration: &AssertionWitnessDeclaration,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        self.require_assertion_witness_authority()?;
        let witness = self.load_assertion_witness(
            snapshot,
            &event.checkpoint(),
            declaration,
            &mut inventory::verification_budget(),
        )?;
        if expected
            .insert(declaration.key(), encode(&event.checkpoint())?)
            .is_some()
        {
            return Err(integrity("assertion witness repeats an accepted batch"));
        }
        expected.insert(blob_key(event.sequence), encode(&witness)?);
        Ok(())
    }
}

fn blob_key(sequence: u64) -> Vec<u8> {
    format!("removal/assertion-witness-blob/{sequence:020}").into_bytes()
}
