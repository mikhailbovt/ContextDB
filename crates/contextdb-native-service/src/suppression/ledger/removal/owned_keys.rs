//! Owned-version decisions retained independently of native pruning and restore.

use super::*;
use crate::raw_index::copies::{discovery, keys::RawKeyFamilies};
use crate::retention::keys::witness::MAX_WITNESS_BYTES;
use crate::{
    NativeOwnedKeyInventory, NativeOwnedKeyOwner, NativeOwnedKeyRemovalReceipt,
    NativeRemovalRequestReceipt,
};

#[cfg(test)]
mod raw_tests;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnedKeyDeclaration {
    workspace: String,
    request: RemovalCheckpoint,
    identity: String,
    witness_digest: String,
}

impl OwnedKeyDeclaration {
    fn from_inventory(inventory: &NativeOwnedKeyInventory, bytes: &[u8]) -> ServiceResult<Self> {
        let usage = &inventory.native_use;
        Ok(Self {
            workspace: digest_bytes(inventory.workspace_id.as_bytes()),
            request: RemovalCheckpoint {
                sequence: inventory.request.sequence,
                digest: inventory.request.digest.clone(),
            },
            identity: canonical_digest(&(
                "owned-key-witness/v1",
                inventory.owner.identity()?,
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
                "owned key witness request is not earlier acceptance",
            ));
        }
        Ok(())
    }

    pub(super) fn key(&self) -> Vec<u8> {
        format!(
            "removal/owned-keys/{}/{:020}/{}",
            self.workspace, self.request.sequence, self.identity
        )
        .into_bytes()
    }
}

impl NativeSuppressionLedger {
    // Only the service calls this, after complete custody replay and while holding
    // its publication fence. This ledger also independently verifies source owners.
    pub(crate) fn retain_owned_key_witness(
        &self,
        inventory: &NativeOwnedKeyInventory,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalReceipt> {
        self.require_removal_authority()?;
        let bytes = encode(inventory)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(exhausted("owned key witness exceeds 5 MiB"));
        }
        let declaration = OwnedKeyDeclaration::from_inventory(inventory, &bytes)?;
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        self.validate_owned_key_ownership(&tx, inventory, budget)?;
        if let Some((checkpoint, operation)) = self.find_retained_control(
            &tx,
            &declaration.workspace,
            &declaration.request,
            &declaration.key(),
            budget,
        )? {
            if operation
                != (Operation::OwnedKeys {
                    witness: declaration.clone(),
                })
            {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "owned key frontier already has different evidence",
                    false,
                ));
            }
            if self.load_owned_key_witness(&tx, &checkpoint, &declaration, budget)? != *inventory {
                return Err(integrity("owned key witness retry differs"));
            }
            return Ok(owned_receipt(
                self,
                &checkpoint,
                declaration.request.sequence,
            ));
        }
        let accepted = self.append_removal_event(
            &mut tx,
            Operation::OwnedKeys {
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
        Ok(owned_receipt(self, &accepted, declaration.request.sequence))
    }

    pub(crate) fn read_owned_key_witness(
        &self,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativeOwnedKeyRemovalReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyInventory> {
        self.require_removal_authority()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let event = self.budgeted_removal_event(&snapshot, receipt.witness_sequence, budget)?;
        let Operation::OwnedKeys {
            witness: declaration,
        } = &event.operation
        else {
            return Err(integrity("owned witness receipt has another operation"));
        };
        if *receipt != owned_receipt(self, &event.checkpoint(), declaration.request.sequence)
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
            return Err(integrity("owned witness receipt or request differs"));
        }
        let inventory =
            self.load_owned_key_witness(&snapshot, &event.checkpoint(), declaration, budget)?;
        if inventory.request != *request {
            return Err(integrity("owned witness retained request differs"));
        }
        Ok(inventory)
    }

    fn load_owned_key_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        checkpoint: &RemovalCheckpoint,
        declaration: &OwnedKeyDeclaration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyInventory> {
        let bytes = snapshot
            .get(&self.rows, &blob_key(checkpoint.sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("independent owned key witness is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_WITNESS_BYTES || digest_bytes(&bytes) != declaration.witness_digest {
            return Err(integrity(
                "owned key witness differs from accepted commitment",
            ));
        }
        let inventory: NativeOwnedKeyInventory = decode(&bytes, "owned key witness")?;
        if OwnedKeyDeclaration::from_inventory(&inventory, &bytes)? != *declaration {
            return Err(integrity(
                "owned key witness frontier or owner binding differs",
            ));
        }
        let owner_sequence = match &inventory.owner {
            NativeOwnedKeyOwner::Payload { .. } => None,
            NativeOwnedKeyOwner::Record { witness, .. } => Some(witness.witness_sequence),
            NativeOwnedKeyOwner::ReclaimedRaw { frontier, .. } => Some(frontier.sequence),
            NativeOwnedKeyOwner::InspectedRaw { inventory, .. } => Some(inventory.sequence),
        };
        if owner_sequence.is_some_and(|sequence| sequence >= checkpoint.sequence) {
            return Err(integrity(
                "owned key witness precedes retained owner evidence",
            ));
        }
        self.validate_owned_key_ownership(snapshot, &inventory, budget)?;
        Ok(inventory)
    }

    fn validate_owned_key_ownership<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        report: &NativeOwnedKeyInventory,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let event = self.budgeted_removal_event(snapshot, report.request.sequence, budget)?;
        let Operation::Request { intent, .. } = &event.operation else {
            return Err(integrity("owned key witness has no retained request"));
        };
        let sources = self.read_removal_inventory(snapshot, intent, budget)?;
        let usage = &report.native_use;
        if report.request != retention::removal_receipt(self, &event.checkpoint(), intent)
            || report.database_id != sources.database_id
            || report.workspace_id != sources.workspace_id
            || report.custody_authority_id.is_nil()
            || report.custody_authority_id != usage.authority_id
            || (report.allocation_revision == 0) != report.allocation_digest.is_none()
            || (usage.revision == 0) != usage.revision_digest.is_none()
        {
            return Err(integrity("owned key witness retained ownership differs"));
        }
        for digest in report
            .allocation_digest
            .iter()
            .chain(usage.revision_digest.iter())
        {
            valid_digest(digest)?;
        }
        let groups = match &report.owner {
            NativeOwnedKeyOwner::Payload { payload, chunks } => {
                let retained = self.removal_payload(
                    &intent.workspace,
                    &event.checkpoint(),
                    payload.block_id,
                    budget,
                )?;
                if *payload != retained {
                    return Err(integrity(
                        "owned key payload differs from retained ownership",
                    ));
                }
                select_groups(payload::keys::chunk_addresses(payload)?, chunks)?
            }
            NativeOwnedKeyOwner::Record { witness, bodies } => {
                if witness.authority_id != self.authority_id()
                    || witness.removal_sequence != report.request.sequence
                {
                    return Err(integrity("owned key record has another removal request"));
                }
                let retained = self.read_record_removal_witness(witness, budget)?;
                if retained.policy().access.workspace_id != report.workspace_id {
                    return Err(integrity("owned key record workspace differs"));
                }
                select_groups(retained.key_addresses()?, bodies)?
            }
            NativeOwnedKeyOwner::ReclaimedRaw {
                frontier,
                sources: reported,
                witnesses,
            } => {
                let controls = discovery::source_controls(&sources, budget)?;
                let mut families = RawKeyFamilies::new(controls.keys().copied());
                let mut expected = Vec::new();
                self.walk_raw_copy_prefix_at(
                    snapshot,
                    &intent.workspace,
                    frontier,
                    budget,
                    |receipt, witness, budget| {
                        for copy in
                            discovery::select_copies(vec![(receipt, witness)], &controls, budget)?
                        {
                            expected.push(copy.witness);
                            if expected.len() > 65_536 {
                                return Err(exhausted(
                                    "raw key witness exceeds 65536 observation pages",
                                ));
                            }
                            for row in copy.rows {
                                families.observe(row)?;
                            }
                        }
                        Ok(())
                    },
                )?;
                if *witnesses != expected {
                    return Err(integrity(
                        "raw key witness observation-page coverage differs",
                    ));
                }
                families.verify_owned_inventory(reported, usage, budget)?
            }
            NativeOwnedKeyOwner::InspectedRaw {
                snapshot: observed,
                inventory,
                inspected_pages,
                sources: reported,
            } => {
                let selected: BTreeSet<_> =
                    sources.sources.iter().map(|s| s.receipt.event_id).collect();
                let mut families = RawKeyFamilies::new(selected.iter().copied());
                let (actual, pages) = self.walk_raw_index_inventory_at(
                    snapshot,
                    inventory,
                    &intent.workspace,
                    &report.request,
                    budget,
                    |page, budget| {
                        budget
                            .charge(page.rows.len() as u64, 0)
                            .map_err(budget_error)?;
                        for row in page.rows {
                            if row.source.is_some_and(|source| selected.contains(&source)) {
                                families.observe(row)?;
                            }
                        }
                        Ok(())
                    },
                )?;
                if actual != *observed || pages != *inspected_pages {
                    return Err(integrity("raw key witness inspection coverage differs"));
                }
                families.verify_owned_inventory(reported, usage, budget)?
            }
        };
        if groups.keys().ne(usage.addresses.keys()) {
            return Err(integrity("owned key use address coverage differs"));
        }
        let mut keys = BTreeSet::new();
        for (address, allocations) in groups {
            for allocation in allocations {
                budget.charge(1, 0).map_err(budget_error)?;
                valid_digest(&allocation.descriptor_digest)?;
                if allocation.address_digest != address
                    || allocation.key_id.is_nil()
                    || allocation.allocation_sequence == 0
                    || allocation.allocation_sequence > report.allocation_revision
                    || !keys.insert(allocation.key_id)
                {
                    return Err(integrity("owned key allocation owner or identity differs"));
                }
            }
            let owned: BTreeSet<_> = allocations.iter().map(|key| key.key_id).collect();
            for version in usage.addresses[&address]
                .transitions
                .iter()
                .flat_map(|change| change.before.iter().chain(change.after.iter()))
                .chain(usage.addresses[&address].acknowledged.values())
            {
                budget.charge(1, 0).map_err(budget_error)?;
                if !owned.contains(&version.key_id) {
                    return Err(integrity("owned key use lacks its selected allocation"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn verify_owned_key_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &Event,
        declaration: &OwnedKeyDeclaration,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        let inventory = self.load_owned_key_witness(
            snapshot,
            &event.checkpoint(),
            declaration,
            &mut inventory::verification_budget(),
        )?;
        if expected
            .insert(declaration.key(), encode(&event.checkpoint())?)
            .is_some()
        {
            return Err(integrity("owned key witness repeats an accepted frontier"));
        }
        expected.insert(blob_key(event.sequence), encode(&inventory)?);
        Ok(())
    }
}

fn owned_receipt(
    ledger: &NativeSuppressionLedger,
    checkpoint: &RemovalCheckpoint,
    removal_sequence: u64,
) -> NativeOwnedKeyRemovalReceipt {
    NativeOwnedKeyRemovalReceipt {
        authority_id: ledger.authority_id(),
        removal_sequence,
        witness_sequence: checkpoint.sequence,
        digest: checkpoint.digest.clone(),
    }
}

fn blob_key(sequence: u64) -> Vec<u8> {
    format!("removal/owned-keys-blob/{sequence:020}").into_bytes()
}

fn select_groups<T: Ord>(
    expected: BTreeMap<String, T>,
    provided: &BTreeMap<T, Vec<NativeKeyAllocation>>,
) -> ServiceResult<BTreeMap<String, &Vec<NativeKeyAllocation>>> {
    if expected.len() != provided.len() {
        return Err(integrity("owned key body or chunk coverage differs"));
    }
    expected
        .into_iter()
        .map(|(address, owner)| {
            let allocations = provided
                .get(&owner)
                .ok_or_else(|| integrity("owned key body or chunk family absent"))?;
            Ok((address, allocations))
        })
        .collect()
}
