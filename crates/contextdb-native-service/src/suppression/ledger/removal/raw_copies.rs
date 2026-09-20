//! Pre-reclamation observations in the independently retained authority.

use super::*;
use crate::raw_index::copies::{MAX_WITNESS_BYTES, NativeRawCopyReceipt, NativeRawCopyWitness};

mod discovery;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawCopyDeclaration {
    pub(super) workspace: String,
    witness_digest: String,
}

impl RawCopyDeclaration {
    pub(super) fn validate(&self) -> ServiceResult<()> {
        valid_digest(&self.workspace)?;
        valid_digest(&self.witness_digest)
    }
}

impl NativeSuppressionLedger {
    pub(crate) fn retain_raw_copy_witness(
        &self,
        witness: &NativeRawCopyWitness,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawCopyReceipt> {
        self.require_removal_authority()?;
        witness.validate(&self.identity.database)?;
        let bytes = encode(witness)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let workspace = digest_bytes(witness.workspace_id.as_bytes());
        if self.removal_head(&tx, &workspace)?.is_none() {
            return Err(integrity("raw copy workspace was not registered"));
        }
        let head = self.removal_global_head(&tx)?;
        self.verify_raw_copy_predecessor(
            &tx,
            witness,
            head.sequence
                .checked_add(1)
                .ok_or_else(|| exhausted("retention sequence overflow"))?,
            budget,
        )?;
        let accepted = self.append_removal_event(
            &mut tx,
            Operation::RawCopies {
                observation: RawCopyDeclaration {
                    workspace,
                    witness_digest: digest_bytes(&bytes),
                },
            },
        )?;
        tx.put(&self.rows, blob_key(accepted.sequence), bytes)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        #[cfg(test)]
        AFTER_RETAIN.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        // A cancelled acknowledgement can leave an observation without a native
        // GC. It remains true observation evidence, never a deletion receipt.
        budget.check().map_err(budget_error)?;
        Ok(NativeRawCopyReceipt {
            authority_id: self.authority_id(),
            sequence: accepted.sequence,
            digest: accepted.digest,
        })
    }

    pub(crate) fn read_raw_copy_witness(
        &self,
        receipt: &NativeRawCopyReceipt,
        workspace_id: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawCopyWitness> {
        self.require_removal_authority()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (event, declaration) =
            self.raw_copy_acceptance(&snapshot, receipt, workspace_id, budget)?;
        let witness =
            self.load_raw_copy_witness(&snapshot, event.sequence, &declaration, budget)?;
        self.verify_raw_copy_predecessor(&snapshot, &witness, event.sequence, budget)?;
        Ok(witness)
    }

    fn raw_copy_acceptance<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &NativeRawCopyReceipt,
        workspace_id: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(Event, RawCopyDeclaration)> {
        if receipt.authority_id != self.authority_id()
            || receipt.sequence == 0
            || receipt.sequence > self.removal_global_head(snapshot)?.sequence
        {
            return Err(integrity("raw copy receipt is outside retained authority"));
        }
        let event = self.budgeted_removal_event(snapshot, receipt.sequence, budget)?;
        let Operation::RawCopies { observation } = &event.operation else {
            return Err(integrity("raw copy receipt has another operation"));
        };
        if event.digest != receipt.digest || observation.workspace != workspace_id {
            return Err(integrity("raw copy receipt or workspace differs"));
        }
        Ok((event.clone(), observation.clone()))
    }

    fn load_raw_copy_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        sequence: u64,
        declaration: &RawCopyDeclaration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawCopyWitness> {
        let bytes = snapshot
            .get(&self.rows, &blob_key(sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retained raw copy witness absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES || digest_bytes(&bytes) != declaration.witness_digest {
            return Err(integrity("raw copy witness commitment differs"));
        }
        let witness: NativeRawCopyWitness = decode(&bytes, "retained raw copy witness")?;
        witness.validate(&self.identity.database)?;
        if digest_bytes(witness.workspace_id.as_bytes()) != declaration.workspace {
            return Err(integrity("raw copy witness crosses workspaces"));
        }
        Ok(witness)
    }

    fn verify_raw_copy_predecessor<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        witness: &NativeRawCopyWitness,
        sequence: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if let Some(previous) = &witness.previous {
            if previous.sequence >= sequence {
                return Err(integrity("raw copy predecessor is not earlier acceptance"));
            }
            let (event, declaration) = self.raw_copy_acceptance(
                snapshot,
                previous,
                &digest_bytes(witness.workspace_id.as_bytes()),
                budget,
            )?;
            let parent =
                self.load_raw_copy_witness(snapshot, event.sequence, &declaration, budget)?;
            if parent.generation != witness.generation
                || parent.generation_digest != witness.generation_digest
                || parent.finished
                || parent.removed_before.checked_add(parent.row_count())
                    != Some(witness.removed_before)
            {
                return Err(integrity("raw copy predecessor or row prefix differs"));
            }
        }
        Ok(())
    }

    pub(super) fn verify_raw_copy_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &Event,
        declaration: &RawCopyDeclaration,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        let mut budget = inventory::verification_budget();
        let witness =
            self.load_raw_copy_witness(snapshot, event.sequence, declaration, &mut budget)?;
        self.verify_raw_copy_predecessor(snapshot, &witness, event.sequence, &mut budget)?;
        expected.insert(blob_key(event.sequence), encode(&witness)?);
        Ok(())
    }
}

fn blob_key(sequence: u64) -> Vec<u8> {
    format!("removal/raw-copy-blob/{sequence:020}").into_bytes()
}

#[cfg(test)]
thread_local! {
    static AFTER_RETAIN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
