//! Primary-version decisions retained independently of native pruning and restore.

use super::*;
use crate::retention::keys::witness::{MAX_WITNESS_BYTES, tracked};
use crate::{
    NativePrimaryKeyInventory, NativePrimaryKeyRemovalReceipt, NativeRemovalRequestReceipt,
};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrimaryKeyDeclaration {
    workspace: String,
    request: RemovalCheckpoint,
    identity: String,
    witness_digest: String,
}

impl PrimaryKeyDeclaration {
    fn from_inventory(inventory: &NativePrimaryKeyInventory, bytes: &[u8]) -> ServiceResult<Self> {
        let usage = tracked(inventory)?;
        Ok(Self {
            workspace: digest_bytes(inventory.workspace_id.as_bytes()),
            request: RemovalCheckpoint {
                sequence: inventory.request.sequence,
                digest: inventory.request.digest.clone(),
            },
            identity: canonical_digest(&(
                "primary-key-witness/v1",
                inventory.custody_authority_id,
                inventory.allocation_revision,
                &inventory.allocation_digest,
                usage.revision,
                &usage.revision_digest,
            ))?,
            witness_digest: digest_bytes(bytes),
        })
    }

    pub(super) fn validate(&self, sequence: u64) -> ServiceResult<()> {
        for digest in [
            &self.workspace,
            &self.request.digest,
            &self.identity,
            &self.witness_digest,
        ] {
            valid_digest(digest)?;
        }
        if self.request.sequence == 0 || self.request.sequence >= sequence {
            return Err(integrity(
                "primary key witness request is not earlier acceptance",
            ));
        }
        Ok(())
    }

    pub(super) fn key(&self) -> Vec<u8> {
        format!(
            "removal/primary-keys/{}/{:020}/{}",
            self.workspace, self.request.sequence, self.identity
        )
        .into_bytes()
    }
}

impl NativeSuppressionLedger {
    // Only the service calls this, after complete custody replay and while holding
    // its publication fence. This ledger also independently verifies source owners.
    pub(crate) fn retain_primary_key_witness(
        &self,
        inventory: &NativePrimaryKeyInventory,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePrimaryKeyRemovalReceipt> {
        self.require_removal_authority()?;
        let bytes = encode(inventory)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(exhausted("primary key witness exceeds 5 MiB"));
        }
        let declaration = PrimaryKeyDeclaration::from_inventory(inventory, &bytes)?;
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        self.validate_primary_key_ownership(&tx, inventory, budget)?;
        if let Some((checkpoint, operation)) = self.find_retained_control(
            &tx,
            &declaration.workspace,
            &declaration.request,
            &declaration.key(),
            budget,
        )? {
            if operation
                != (Operation::PrimaryKeys {
                    witness: declaration.clone(),
                })
            {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "primary key frontier already has different evidence",
                    false,
                ));
            }
            if self.load_primary_key_witness(&tx, &checkpoint, &declaration, budget)? != *inventory
            {
                return Err(integrity("primary key witness retry differs"));
            }
            return Ok(primary_receipt(
                self,
                &checkpoint,
                declaration.request.sequence,
            ));
        }
        let accepted = self.append_removal_event(
            &mut tx,
            Operation::PrimaryKeys {
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
        Ok(primary_receipt(
            self,
            &accepted,
            declaration.request.sequence,
        ))
    }

    pub(crate) fn read_primary_key_witness(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativePrimaryKeyRemovalReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePrimaryKeyInventory> {
        self.require_removal_authority()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let event = self.budgeted_removal_event(&snapshot, receipt.witness_sequence, budget)?;
        let Operation::PrimaryKeys {
            witness: declaration,
        } = &event.operation
        else {
            return Err(integrity("primary witness receipt has another operation"));
        };
        if *receipt != primary_receipt(self, &event.checkpoint(), declaration.request.sequence)
            || declaration.workspace != digest_bytes(context.request.workspace_id.as_bytes())
            || declaration.request
                != (RemovalCheckpoint {
                    sequence: request.sequence,
                    digest: request.digest.clone(),
                })
            || self.find_retained_control(
                &snapshot,
                &declaration.workspace,
                &declaration.request,
                &declaration.key(),
                budget,
            )? != Some((event.checkpoint(), event.operation.clone()))
        {
            return Err(integrity("primary witness receipt or request differs"));
        }
        let inventory =
            self.load_primary_key_witness(&snapshot, &event.checkpoint(), declaration, budget)?;
        if inventory.request != *request {
            return Err(integrity("primary witness retained request differs"));
        }
        Ok(inventory)
    }

    fn load_primary_key_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        checkpoint: &RemovalCheckpoint,
        declaration: &PrimaryKeyDeclaration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePrimaryKeyInventory> {
        let bytes = snapshot
            .get(&self.rows, &blob_key(checkpoint.sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("independent primary key witness is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES || digest_bytes(&bytes) != declaration.witness_digest {
            return Err(integrity(
                "primary key witness differs from accepted commitment",
            ));
        }
        let inventory: NativePrimaryKeyInventory = decode(&bytes, "primary key witness")?;
        if PrimaryKeyDeclaration::from_inventory(&inventory, &bytes)? != *declaration {
            return Err(integrity(
                "primary key witness frontier or owner binding differs",
            ));
        }
        self.validate_primary_key_ownership(snapshot, &inventory, budget)?;
        Ok(inventory)
    }

    fn validate_primary_key_ownership<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        report: &NativePrimaryKeyInventory,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let event = self.budgeted_removal_event(snapshot, report.request.sequence, budget)?;
        let Operation::Request { intent, .. } = &event.operation else {
            return Err(integrity("primary key witness has no retained request"));
        };
        let sources = self.read_removal_inventory(snapshot, intent, budget)?;
        let usage = tracked(report)?;
        if report.request != retention::removal_receipt(self, &event.checkpoint(), intent)
            || report.database_id != sources.database_id
            || report.workspace_id != sources.workspace_id
            || report.custody_authority_id.is_nil()
            || report.custody_authority_id != usage.authority_id
            || report.sources.keys().copied().collect::<BTreeSet<_>>()
                != sources.sources.iter().map(|s| s.receipt.event_id).collect()
            || (report.allocation_revision == 0) != report.allocation_digest.is_none()
            || (usage.revision == 0) != usage.revision_digest.is_none()
        {
            return Err(integrity("primary key witness retained ownership differs"));
        }
        for digest in report
            .allocation_digest
            .iter()
            .chain(usage.revision_digest.iter())
        {
            valid_digest(digest)?;
        }
        let space = Keyspaces::new()?.observations_content;
        let mut addresses = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for (source, allocations) in &report.sources {
            let address = encryption::address(
                &space,
                digest_bytes(source.to_string().as_bytes()).as_bytes(),
            );
            addresses.insert(address.clone());
            for allocation in allocations {
                budget.charge(1, 0).map_err(budget_error)?;
                valid_digest(&allocation.descriptor_digest)?;
                if allocation.address_digest != address
                    || allocation.key_id.is_nil()
                    || allocation.allocation_sequence == 0
                    || allocation.allocation_sequence > report.allocation_revision
                    || !keys.insert(allocation.key_id)
                {
                    return Err(integrity(
                        "primary key allocation owner or identity differs",
                    ));
                }
            }
            let owned: BTreeSet<_> = allocations.iter().map(|key| key.key_id).collect();
            let history = usage
                .addresses
                .get(&address)
                .ok_or_else(|| integrity("primary key use address is absent"))?;
            for version in history
                .transitions
                .iter()
                .flat_map(|change| change.before.iter().chain(change.after.iter()))
                .chain(history.acknowledged.values())
            {
                budget.charge(1, 0).map_err(budget_error)?;
                if !owned.contains(&version.key_id) {
                    return Err(integrity("primary key use lacks its selected allocation"));
                }
            }
        }
        if addresses != usage.addresses.keys().cloned().collect() {
            return Err(integrity("primary key use address coverage differs"));
        }
        Ok(())
    }

    pub(super) fn verify_primary_key_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &Event,
        declaration: &PrimaryKeyDeclaration,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        let inventory = self.load_primary_key_witness(
            snapshot,
            &event.checkpoint(),
            declaration,
            &mut inventory::verification_budget(),
        )?;
        if expected
            .insert(declaration.key(), encode(&event.checkpoint())?)
            .is_some()
        {
            return Err(integrity(
                "primary key witness repeats an accepted frontier",
            ));
        }
        expected.insert(blob_key(event.sequence), encode(&inventory)?);
        Ok(())
    }
}

fn primary_receipt(
    ledger: &NativeSuppressionLedger,
    checkpoint: &RemovalCheckpoint,
    removal_sequence: u64,
) -> NativePrimaryKeyRemovalReceipt {
    NativePrimaryKeyRemovalReceipt {
        authority_id: ledger.authority_id(),
        removal_sequence,
        witness_sequence: checkpoint.sequence,
        digest: checkpoint.digest.clone(),
    }
}

fn blob_key(sequence: u64) -> Vec<u8> {
    format!("removal/primary-keys-blob/{sequence:020}").into_bytes()
}
