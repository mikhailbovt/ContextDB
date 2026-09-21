//! Reconcile retained selection with a complete current native source history.

use super::*;
use crate::NativeRemovalRequestReceipt;

#[cfg(test)]
mod tests;

/// Local presence of an independently retained removal selection. Absence here
/// concerns this verified native history only, not backups or other instances.
/// This read-only report is not a pruning authorization or completion receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRemovalLocalInventory {
    /// Exact request whose source and payload identities were independently read.
    pub request: NativeRemovalRequestReceipt,
    /// Workspace inspected under current Admin authority.
    pub workspace_id: String,
    /// Complete local workspace prefix rechecked before return.
    pub workspace_commit: u64,
    /// Current native authorization epoch at that prefix.
    pub authorization_epoch: u64,
    /// Exact retained source controls present here, in acceptance order.
    pub sources: Vec<NativeDeletionSource>,
    /// Retained selected source IDs absent from this accepted local history.
    pub absent_sources: BTreeSet<ObservationId>,
    /// Exclusively selected blocks staged here, even before an owning capture.
    pub payloads: Vec<OriginalPayloadRef>,
    /// Exclusively selected block IDs absent from this local staging history.
    pub absent_payloads: BTreeSet<ContentBlockId>,
    /// Present referenced blocks that the retained authority keeps independent.
    pub retained_shared_payloads: Vec<OriginalPayloadRef>,
}

impl NativeService {
    /// Inspect the present and absent parts of an exact retained removal request.
    /// Unlike initial request discovery, older local histories may lack its roots.
    /// Every present selected control must still match its original acceptance;
    /// newly discovered descendants or owners require separate authority expansion.
    /// Native publication and the complete workspace graph are checked under one
    /// shared budget. Serialized reports never authorize destructive operations.
    pub fn read_original_removal_local_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRemovalLocalInventory> {
        let retained = self.read_original_removal_inventory(context, request, budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        let graph = self.read_source_graph(&snapshot, &world, budget)?;
        let mut selected = BTreeSet::new();
        let mut absent_sources = BTreeSet::new();
        let mut expected = BTreeMap::new();
        for source in &retained.sources {
            budget.charge(1, 0).map_err(budget_error)?;
            let id = source.receipt.event_id;
            expected.insert(id, source);
            if graph.nodes.contains_key(&id) {
                selected.insert(id);
            } else {
                self.require_absent_capture(&snapshot, id, budget)?;
                absent_sources.insert(id);
            }
        }
        let (sources, released, shared) = graph.closure(&selected, budget)?;
        for source in &sources {
            budget.charge(1, 0).map_err(budget_error)?;
            if expected.get(&source.receipt.event_id).copied() != Some(source) {
                return Err(expansion_required());
            }
        }
        let mut blocks: BTreeMap<_, _> = released
            .into_iter()
            .chain(shared)
            .map(|block| (block.block_id, block))
            .collect();
        let mut absent_payloads = BTreeSet::new();
        for payload in &retained.payloads {
            budget.charge(1, 0).map_err(budget_error)?;
            match graph.staged.get(&payload.block_id) {
                Some(local) if local == payload => {
                    blocks.insert(payload.block_id, local.clone());
                }
                Some(_) => {
                    return Err(integrity(
                        "local staged payload differs from retained selection",
                    ));
                }
                None => {
                    self.require_absent_payload(&snapshot, payload.block_id, budget)?;
                    absent_payloads.insert(payload.block_id);
                }
            }
        }
        let selected_payloads: BTreeMap<_, _> =
            retained.payloads.iter().map(|p| (p.block_id, p)).collect();
        let kept_payloads: BTreeMap<_, _> = retained
            .retained_shared_payloads
            .iter()
            .map(|p| (p.block_id, p))
            .collect();
        let mut payloads = Vec::new();
        let mut retained_shared_payloads = Vec::new();
        for block in blocks.into_values() {
            budget.charge(1, 0).map_err(budget_error)?;
            if selected_payloads.get(&block.block_id).copied() == Some(&block) {
                for owner in graph.owners.get(&block.block_id).into_iter().flatten() {
                    budget.charge(1, 0).map_err(budget_error)?;
                    if !selected.contains(owner) {
                        return Err(expansion_required());
                    }
                }
                payloads.push(block);
            } else if kept_payloads.get(&block.block_id).copied() == Some(&block) {
                retained_shared_payloads.push(block);
            } else {
                return Err(expansion_required());
            }
        }
        let report = NativeRemovalLocalInventory {
            request: request.clone(),
            workspace_id: context.request.workspace_id.clone(),
            workspace_commit: world.watermarks.journal,
            authorization_epoch: self
                .raw_authorization_epoch(&snapshot, &world.workspace_digest)?,
            sources,
            absent_sources,
            payloads,
            absent_payloads,
            retained_shared_payloads,
        };
        retention::keys::charge_report(&report, budget)?;
        #[cfg(test)]
        BEFORE_CURRENT_CHECK.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if current.sequence() != snapshot.sequence()
            || self.workspace_state(&current, &context.request.workspace_id)? != world
        {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "workspace changed during local removal inspection; inspect again",
                true,
            ));
        }
        budget.check().map_err(budget_error)?;
        Ok(report)
    }
}

fn expansion_required() -> ServiceError {
    ServiceError::new(
        ErrorCode::EvidenceRequired,
        "local removal requires retained coverage of this branch's complete source lineage",
        false,
    )
}
