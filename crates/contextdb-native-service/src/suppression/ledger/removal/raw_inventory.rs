//! Request-bound inspection pages have their own operation and retry identity.

use super::*;
use crate::raw_index::copies::MAX_WITNESS_BYTES;
use crate::raw_index::inventory::{NativeRawIndexInventoryReceipt, NativeRawIndexInventoryWitness};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawIndexDeclaration {
    request: RemovalCheckpoint,
    workspace: String,
    identity: String,
    witness_digest: String,
}

impl RawIndexDeclaration {
    pub(super) fn validate(&self, sequence: u64) -> ServiceResult<()> {
        for digest in [
            &self.request.digest,
            &self.workspace,
            &self.identity,
            &self.witness_digest,
        ] {
            valid_digest(digest)?;
        }
        if self.request.sequence == 0 || self.request.sequence >= sequence {
            return Err(integrity(
                "raw index inspection request is not earlier acceptance",
            ));
        }
        Ok(())
    }

    pub(super) fn key(&self) -> Vec<u8> {
        format!(
            "removal/raw-index/{}/{:020}/{}",
            self.workspace, self.request.sequence, self.identity
        )
        .into_bytes()
    }
}

impl NativeSuppressionLedger {
    pub(crate) fn retain_raw_index_inventory(
        &self,
        witness: &NativeRawIndexInventoryWitness,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawIndexInventoryReceipt> {
        self.require_removal_authority()?;
        witness.validate(&self.identity.database)?;
        let bytes = encode(witness)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let declaration = RawIndexDeclaration {
            request: RemovalCheckpoint {
                sequence: witness.request.sequence,
                digest: witness.request.digest.clone(),
            },
            workspace: digest_bytes(witness.workspace_id.as_bytes()),
            identity: witness.identity_digest()?,
            witness_digest: digest_bytes(&bytes),
        };
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        self.verify_raw_index_request(&tx, witness, budget)?;
        self.verify_raw_index_predecessor(&tx, witness, u64::MAX, budget)?;
        if let Some((accepted, operation)) = self.find_retained_control(
            &tx,
            &declaration.workspace,
            &declaration.request,
            &declaration.key(),
            budget,
        )? {
            if operation
                != (Operation::RawIndexInventory {
                    witness: declaration.clone(),
                })
            {
                return Err(integrity(
                    "raw index inspection retry changed its observed page",
                ));
            }
            if self.load_raw_index_inventory(&tx, &accepted, &declaration, budget)? != *witness {
                return Err(integrity("raw index inspection retained page differs"));
            }
            return Ok(self.raw_index_receipt(accepted));
        }
        let accepted = self.append_removal_event(
            &mut tx,
            Operation::RawIndexInventory {
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
        #[cfg(test)]
        AFTER_RETAIN.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        budget.check().map_err(budget_error)?;
        Ok(self.raw_index_receipt(accepted))
    }

    pub(crate) fn read_raw_index_inventory(
        &self,
        receipt: &NativeRawIndexInventoryReceipt,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawIndexInventoryWitness> {
        self.require_removal_authority()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (checkpoint, declaration, witness) =
            self.raw_index_inventory_at(&snapshot, receipt, workspace, budget)?;
        let found = self.find_retained_control(
            &snapshot,
            workspace,
            &declaration.request,
            &declaration.key(),
            budget,
        )?;
        if found
            != Some((
                checkpoint.clone(),
                Operation::RawIndexInventory {
                    witness: declaration,
                },
            ))
        {
            return Err(integrity("raw index inspection lost its exact acceptance"));
        }
        self.verify_raw_index_request(&snapshot, &witness, budget)?;
        self.verify_raw_index_predecessor(&snapshot, &witness, checkpoint.sequence, budget)?;
        Ok(witness)
    }

    pub(crate) fn walk_raw_index_inventory(
        &self,
        receipt: &NativeRawIndexInventoryReceipt,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
        mut visit: impl FnMut(NativeRawIndexInventoryWitness, &mut QueryBudget) -> ServiceResult<()>,
    ) -> ServiceResult<(NativeRawIndexSnapshot, u32)> {
        self.require_removal_authority()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (checkpoint, declaration, terminal) =
            self.raw_index_inventory_at(&snapshot, receipt, workspace, budget)?;
        if !terminal.finished || terminal.request != *request {
            return Err(invalid(
                "raw key selection requires the terminal page of this removal request",
            ));
        }
        let found = self.find_retained_control(
            &snapshot,
            workspace,
            &declaration.request,
            &declaration.key(),
            budget,
        )?;
        if found
            != Some((
                checkpoint,
                Operation::RawIndexInventory {
                    witness: declaration,
                },
            ))
        {
            return Err(integrity("raw key selection lost its terminal acceptance"));
        }
        let controls = self.verify_raw_index_request(&snapshot, &terminal, budget)?;
        let anchor = terminal.snapshot.clone();
        let mut next = Some(receipt.clone());
        let mut count = 0;
        let mut addresses = BTreeSet::new();
        while let Some(current) = next {
            if count == 65_536 {
                return Err(exhausted(
                    "raw key inventory exceeds 65536 inspection pages",
                ));
            }
            let (checkpoint, declaration, witness) =
                self.raw_index_inventory_at(&snapshot, &current, workspace, budget)?;
            if witness.request != *request
                || witness.snapshot != anchor
                || snapshot
                    .get(&self.rows, &declaration.key())
                    .map_err(storage_error)?
                    != Some(encode(&checkpoint)?)
            {
                return Err(integrity(
                    "raw key inventory page changed its request, snapshot or locator",
                ));
            }
            verify_selected_sources(&witness, &controls, budget)?;
            self.verify_raw_index_predecessor(&snapshot, &witness, checkpoint.sequence, budget)?;
            for row in &witness.rows {
                budget
                    .charge(1, row.address_digest.len() as u64)
                    .map_err(budget_error)?;
                if !addresses.insert(row.address_digest.clone()) {
                    return Err(integrity(
                        "raw index inventory repeats an address within one snapshot",
                    ));
                }
            }
            next = witness.previous.clone();
            visit(witness, budget)?;
            count += 1;
        }
        Ok((anchor, count))
    }

    fn raw_index_receipt(&self, checkpoint: RemovalCheckpoint) -> NativeRawIndexInventoryReceipt {
        NativeRawIndexInventoryReceipt {
            authority_id: self.authority_id(),
            sequence: checkpoint.sequence,
            digest: checkpoint.digest,
        }
    }

    fn raw_index_inventory_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &NativeRawIndexInventoryReceipt,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(
        RemovalCheckpoint,
        RawIndexDeclaration,
        NativeRawIndexInventoryWitness,
    )> {
        if receipt.authority_id != self.authority_id()
            || receipt.sequence == 0
            || receipt.sequence > self.removal_global_head(snapshot)?.sequence
        {
            return Err(integrity(
                "raw index inspection receipt is outside retained history",
            ));
        }
        let event = self.budgeted_removal_event(snapshot, receipt.sequence, budget)?;
        let Operation::RawIndexInventory {
            witness: declaration,
        } = &event.operation
        else {
            return Err(integrity(
                "raw index inspection receipt has another operation",
            ));
        };
        if event.digest != receipt.digest || declaration.workspace != workspace {
            return Err(integrity(
                "raw index inspection receipt or workspace differs",
            ));
        }
        let witness =
            self.load_raw_index_inventory(snapshot, &event.checkpoint(), declaration, budget)?;
        Ok((event.checkpoint(), declaration.clone(), witness))
    }

    fn load_raw_index_inventory<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        checkpoint: &RemovalCheckpoint,
        declaration: &RawIndexDeclaration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawIndexInventoryWitness> {
        let bytes = snapshot
            .get(&self.rows, &blob_key(checkpoint.sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("raw index inspection blob absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES || digest_bytes(&bytes) != declaration.witness_digest {
            return Err(integrity("raw index inspection blob commitment differs"));
        }
        let witness: NativeRawIndexInventoryWitness = decode(&bytes, "raw index inspection")?;
        witness.validate(&self.identity.database)?;
        if witness.identity_digest()? != declaration.identity
            || digest_bytes(witness.workspace_id.as_bytes()) != declaration.workspace
            || witness.request.sequence != declaration.request.sequence
            || witness.request.digest != declaration.request.digest
        {
            return Err(integrity("raw index inspection declaration differs"));
        }
        Ok(witness)
    }

    fn verify_raw_index_request<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        witness: &NativeRawIndexInventoryWitness,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<ObservationId, NativeRawSourceControl>> {
        let event = self.budgeted_removal_event(snapshot, witness.request.sequence, budget)?;
        let Operation::Request { intent, .. } = &event.operation else {
            return Err(integrity(
                "raw index inspection does not reference a removal request",
            ));
        };
        if intent.workspace != digest_bytes(witness.workspace_id.as_bytes())
            || retention::removal_receipt(self, &event.checkpoint(), intent) != witness.request
        {
            return Err(integrity("raw index inspection removal request differs"));
        }
        let indexed = snapshot
            .get(&self.rows, &request_key(&intent.workspace, event.sequence))
            .map_err(storage_error)?;
        if indexed != Some(encode(&event.checkpoint())?) {
            return Err(integrity("raw index inspection request locator differs"));
        }
        let lineage = self.read_removal_inventory(snapshot, intent, budget)?;
        let mut controls = BTreeMap::new();
        for source in lineage.sources {
            budget.charge(1, 0).map_err(budget_error)?;
            controls.insert(
                source.receipt.event_id,
                NativeRawSourceControl {
                    capture_commit: source.receipt.workspace_commit,
                    event_digest: source.receipt.event_digest,
                    control_digest: source.control_digest,
                },
            );
        }
        verify_selected_sources(witness, &controls, budget)?;
        Ok(controls)
    }

    fn verify_raw_index_predecessor<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        witness: &NativeRawIndexInventoryWitness,
        sequence: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let Some(previous) = &witness.previous else {
            return Ok(());
        };
        if previous.sequence >= sequence {
            return Err(integrity("raw index inspection predecessor is not earlier"));
        }
        let (_, _, parent) = self.raw_index_inventory_at(
            snapshot,
            previous,
            &digest_bytes(witness.workspace_id.as_bytes()),
            budget,
        )?;
        let (generation, rows, after) = if parent.generation_finished {
            (parent.generation_index.checked_add(1), Some(0), None)
        } else {
            (
                Some(parent.generation_index),
                parent.rows_before.checked_add(parent.row_count()),
                parent.last_digest,
            )
        };
        if parent.finished
            || parent.snapshot != witness.snapshot
            || parent.request != witness.request
            || generation != Some(witness.generation_index)
            || rows != Some(witness.rows_before)
            || after != witness.after_digest
        {
            return Err(integrity("raw index inspection page chain differs"));
        }
        Ok(())
    }

    pub(super) fn verify_raw_index_inventory_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &Event,
        declaration: &RawIndexDeclaration,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        let mut budget = inventory::verification_budget();
        let witness =
            self.load_raw_index_inventory(snapshot, &event.checkpoint(), declaration, &mut budget)?;
        self.verify_raw_index_request(snapshot, &witness, &mut budget)?;
        self.verify_raw_index_predecessor(snapshot, &witness, event.sequence, &mut budget)?;
        if expected
            .insert(declaration.key(), encode(&event.checkpoint())?)
            .is_some()
        {
            return Err(integrity("duplicate raw index inspection acceptance"));
        }
        expected.insert(blob_key(event.sequence), encode(&witness)?);
        Ok(())
    }
}

fn blob_key(sequence: u64) -> Vec<u8> {
    format!("removal/raw-index-blob/{sequence:020}").into_bytes()
}

#[cfg(test)]
thread_local! {
    static AFTER_RETAIN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn verify_selected_sources(
    witness: &NativeRawIndexInventoryWitness,
    controls: &BTreeMap<ObservationId, NativeRawSourceControl>,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    for (id, observed) in &witness.sources {
        budget.charge(1, 0).map_err(budget_error)?;
        if controls
            .get(id)
            .is_some_and(|expected| expected != observed)
        {
            return Err(integrity(
                "raw index inspection source differs from retained removal",
            ));
        }
    }
    Ok(())
}
