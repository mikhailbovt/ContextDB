//! Complete native-use history for addresses selected by retained ownership.

use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};

use super::*;
use journal::UseVisit;

mod budget;
use budget::BudgetedSnapshot;
#[cfg(test)]
mod tests;

const MAX_SELECTED: usize = 65_536;
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// One final address change and its independently retained native outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseTransition {
    /// Preparation and outcome, shared with the exact-receipt catalog contract.
    pub transaction: NativeKeyUseTransaction,
    /// Acknowledged value at the preparation's base; not an aborted after-value.
    pub before: Option<NativeKeyUseVersion>,
    /// Intended final value. Prepared outcomes may already contain durable data.
    pub after: Option<NativeKeyUseVersion>,
}

/// Complete tracked transitions for one selected address in this authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseAddressInventory {
    /// Preparation order across registered native instances, including aborts.
    pub transitions: Vec<NativeKeyUseTransition>,
    /// Last acknowledged value in each instance where one remains. Pending values,
    /// old snapshots and external copies are not represented as erased or absent.
    pub acknowledged: BTreeMap<Uuid, NativeKeyUseVersion>,
}

/// Native-use evidence joined to independently selected ownership addresses.
/// This covers the retained v4 journal, not legacy or external physical copies.
/// Shared addresses can include independently needed versions; no key is retired.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseInventory {
    /// Supplied current custody authority; outside authorities remain separate.
    pub authority_id: Uuid,
    /// Complete native-use journal frontier verified with both index directions.
    pub revision: u64,
    /// Authenticated frontier digest, absent only for an unused authority.
    pub revision_digest: Option<String>,
    /// Every selected address, including empty tracked histories. Allocation and
    /// removal-request frontiers are supplied by the enclosing inventory.
    pub addresses: BTreeMap<String, NativeKeyUseAddressInventory>,
}

impl NativeCustodyKeys {
    /// The service supplies only addresses/keys selected from authorized retained
    /// ownership. Legacy v3 returns None rather than inventing native-use history.
    pub(crate) fn selected_native_use_inventory(
        &self,
        selected: &BTreeMap<String, BTreeSet<Uuid>>,
        allocation_revision: u64,
        allocation_digest: Option<&str>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<NativeKeyUseInventory>> {
        if !self.tracks_native_use() {
            return Ok(None);
        }
        if selected.len() > MAX_SELECTED {
            return Err(crate::exhausted(
                "native-use inventory exceeds 65536 addresses",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        let view = BudgetedSnapshot::new(snapshot, budget);
        let result = (|| {
            view.charge(selected.len() as u64, (selected.len() * 64) as u64)?;
            if !self.matches_key_frontier(&view, allocation_revision, allocation_digest)? {
                return Err(view.reject(stale()));
            }
            let head = self.use_head(&view)?;
            let mut inventory = NativeKeyUseInventory {
                authority_id: self.authority_id(),
                revision: head.sequence,
                revision_digest: head.digest.clone(),
                addresses: selected
                    .keys()
                    .map(|address| {
                        (
                            address.clone(),
                            NativeKeyUseAddressInventory {
                                transitions: Vec::new(),
                                acknowledged: BTreeMap::new(),
                            },
                        )
                    })
                    .collect(),
            };
            let mut positions: BTreeMap<u64, Vec<(String, usize)>> = BTreeMap::new();
            let mut count = 0;
            let mut report_bytes = selected.len() * 128;
            self.visit_native_use(&view, |event| {
                match event {
                    UseVisit::Change(pending, change) => {
                        let Some(allocated) = selected.get(&change.address_digest) else {
                            return Ok(());
                        };
                        for version in change.before.iter().chain(change.after.iter()) {
                            if !allocated.contains(&version.key_id) {
                                return Err(failure(
                                    "selected native use has no matching allocation",
                                ));
                            }
                        }
                        let transition = NativeKeyUseTransition {
                            transaction: NativeKeyUseTransaction {
                                preparation: self.inventory_use_receipt(&pending.checkpoint)?,
                                native_instance: pending.preparation.previous.instance,
                                transaction_id: pending.preparation.transaction,
                                base_native_sequence: pending.preparation.previous.native_sequence,
                                intended_native_sequence: pending.expected()?.native_sequence,
                                pages: pending.preparation.pages,
                                changed_addresses: pending.preparation.changes,
                                outcome: NativeKeyUseOutcome::Prepared,
                                resolution: None,
                            },
                            before: change.before.clone(),
                            after: change.after.clone(),
                        };
                        // Reserve the later outcome and acknowledged projection too.
                        let bytes = encode(&transition)?.len() + 768;
                        count += 1;
                        report_bytes += bytes;
                        if count > MAX_SELECTED || report_bytes > MAX_REPORT_BYTES {
                            return Err(view.reject(crate::exhausted(
                                "native-use inventory exceeds 65536 transitions or 32 MiB",
                            )));
                        }
                        view.charge(1, bytes as u64)?;
                        let address = inventory
                            .addresses
                            .get_mut(&change.address_digest)
                            .ok_or_else(|| failure("native-use selection address is absent"))?;
                        positions
                            .entry(pending.checkpoint.sequence)
                            .or_default()
                            .push((change.address_digest.clone(), address.transitions.len()));
                        address.transitions.push(transition);
                    }
                    UseVisit::Outcome(pending, committed, outcome) => {
                        let receipt = self.inventory_use_receipt(outcome)?;
                        for (key, position) in positions
                            .remove(&pending.checkpoint.sequence)
                            .unwrap_or_default()
                        {
                            view.charge(1, 0)?;
                            let address = inventory
                                .addresses
                                .get_mut(&key)
                                .ok_or_else(|| failure("native-use outcome address absent"))?;
                            let change = &mut address.transitions[position];
                            change.transaction.outcome = if committed {
                                NativeKeyUseOutcome::Committed
                            } else {
                                NativeKeyUseOutcome::Aborted
                            };
                            change.transaction.resolution = Some(receipt.clone());
                            if committed {
                                let instance = pending.preparation.previous.instance;
                                if let Some(after) = &change.after {
                                    address.acknowledged.insert(instance, after.clone());
                                } else {
                                    address.acknowledged.remove(&instance);
                                }
                            }
                        }
                    }
                }
                Ok(())
            })?;
            let bytes = encode(&inventory)?.len();
            if bytes > MAX_REPORT_BYTES {
                return Err(view.reject(crate::exhausted("native-use inventory exceeds 32 MiB")));
            }
            view.charge(0, bytes as u64)?;
            Ok(inventory)
        })();
        let inventory = view.complete(result)?;
        #[cfg(test)]
        BEFORE_INVENTORY_FRONTIER.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        // Both frontiers are checked in one fresh independent snapshot. Backup-only
        // activity is allowed; allocation or native-use changes require a restart.
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        let view = BudgetedSnapshot::new(snapshot, budget);
        let result = (|| {
            let head = self.use_head(&view)?;
            if head.sequence != inventory.revision
                || head.digest != inventory.revision_digest
                || !self.matches_key_frontier(&view, allocation_revision, allocation_digest)?
            {
                return Err(view.reject(stale()));
            }
            Ok(())
        })();
        view.complete(result)?;
        Ok(Some(inventory))
    }

    fn inventory_use_receipt(
        &self,
        checkpoint: &UseCheckpoint,
    ) -> contextdb_storage::Result<NativeKeyUseReceipt> {
        validate_checkpoint(checkpoint, false)?;
        Ok(NativeKeyUseReceipt {
            authority_id: self.authority_id(),
            sequence: checkpoint.sequence,
            digest: checkpoint
                .digest
                .clone()
                .ok_or_else(|| failure("native-use receipt digest absent"))?,
        })
    }
}

fn stale() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "key allocation or native-use history changed; restart inventory",
        true,
    )
}

#[cfg(test)]
thread_local! {
    static BEFORE_INVENTORY_FRONTIER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
