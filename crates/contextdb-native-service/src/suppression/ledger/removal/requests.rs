//! Discover requests from ordered history and exact forward/reverse locators.

use super::*;
use crate::{NativeRemovalRequestInventory, retention::removal_receipt};

impl NativeSuppressionLedger {
    pub(crate) fn removal_requests(
        &self,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRemovalRequestInventory> {
        self.require_removal_authority()?;
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.removal_global_head(&snapshot)?;
        let mut previous = genesis(&self.identity)?;
        let mut workspaces = BTreeMap::new();
        let mut expected = BTreeMap::new();
        let mut requests = Vec::new();
        let mut retained_bytes = 0;
        let mut after = None;
        loop {
            budget.check().map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.rows,
                    ScanPageRequest {
                        prefix: b"removal/event/",
                        start_after: after.as_deref(),
                        max_entries: 64,
                        max_bytes: 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                budget
                    .charge(1, (row.key.len() + row.value.len()) as u64)
                    .map_err(budget_error)?;
                let sequence = previous
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| exhausted("removal discovery sequence overflow"))?;
                if row.key != event_key(sequence) || sequence > head.sequence {
                    return Err(integrity(
                        "removal discovery journal has undeclared positions",
                    ));
                }
                let event = self.decode_removal_event(&row.value, sequence)?;
                if event.previous != previous.digest {
                    return Err(integrity("removal discovery journal is discontinuous"));
                }
                match &event.operation {
                    Operation::Register { workspace } => {
                        let genesis = self.removal_genesis(workspace)?;
                        reserve(
                            workspace.len() + encode(&genesis)?.len(),
                            &mut retained_bytes,
                            budget,
                        )?;
                        if workspaces.insert(workspace.clone(), genesis).is_some() {
                            return Err(integrity(
                                "removal discovery workspace was registered twice",
                            ));
                        }
                    }
                    Operation::Request { intent, .. } => {
                        if workspaces.get(&intent.workspace) != Some(&intent.previous) {
                            return Err(integrity(
                                "removal discovery request forks retained history",
                            ));
                        }
                        let checkpoint = event.checkpoint();
                        for key in [
                            request_key(&intent.workspace, sequence),
                            retry_key(&intent.workspace, &intent.retry_key),
                        ] {
                            let value = encode(&checkpoint)?;
                            reserve(key.len() + value.len(), &mut retained_bytes, budget)?;
                            if expected.insert(key, value).is_some() {
                                return Err(integrity(
                                    "removal discovery reused a request locator",
                                ));
                            }
                        }
                        if intent.workspace == workspace {
                            let receipt = removal_receipt(self, &checkpoint, intent);
                            reserve(encode(&receipt)?.len(), &mut retained_bytes, budget)?;
                            requests.push(receipt);
                        }
                        workspaces.insert(intent.workspace.clone(), checkpoint);
                    }
                    _ => {}
                }
                previous = event.checkpoint();
            }
            let Some(next) = page.continuation else { break };
            after = Some(next);
        }
        if previous != head {
            return Err(integrity("removal discovery terminal differs"));
        }
        for (workspace, checkpoint) in workspaces {
            let key = current_key(&workspace);
            let value = encode(&checkpoint)?;
            reserve(key.len() + value.len(), &mut retained_bytes, budget)?;
            expected.insert(key, value);
        }
        for prefix in [
            b"removal/current/".as_slice(),
            b"removal/request/",
            b"removal/retry/",
        ] {
            let mut after = None;
            loop {
                budget.check().map_err(budget_error)?;
                let page = snapshot
                    .scan_prefix_page(
                        &self.rows,
                        ScanPageRequest {
                            prefix,
                            start_after: after.as_deref(),
                            max_entries: 64,
                            max_bytes: 1024 * 1024,
                        },
                    )
                    .map_err(storage_error)?;
                for row in page.entries {
                    budget
                        .charge(1, (row.key.len() + row.value.len()) as u64)
                        .map_err(budget_error)?;
                    if expected.remove(&row.key).as_ref() != Some(&row.value) {
                        return Err(integrity("removal discovery locator differs from history"));
                    }
                }
                let Some(next) = page.continuation else { break };
                after = Some(next);
            }
        }
        if !expected.is_empty() {
            return Err(integrity("removal discovery lost accepted locators"));
        }
        let result = NativeRemovalRequestInventory {
            authority_id: self.authority_id(),
            sequence: head.sequence,
            digest: head.digest.clone(),
            requests,
        };
        retention::keys::charge_report(&result, budget)?;
        #[cfg(test)]
        BEFORE_DISCOVERY_FENCE.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        let _guard = self.lock_removal_frontier(&head, budget)?;
        Ok(result)
    }
}

fn reserve(bytes: usize, total: &mut usize, budget: &mut QueryBudget) -> ServiceResult<()> {
    *total = total
        .checked_add(bytes)
        .filter(|value| *value <= 32 * 1024 * 1024)
        .ok_or_else(|| exhausted("removal discovery exceeds 32 MiB"))?;
    budget.charge(1, bytes as u64).map_err(budget_error)
}

#[cfg(test)]
type DiscoveryHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    static BEFORE_DISCOVERY_FENCE: std::cell::RefCell<Option<DiscoveryHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests;
