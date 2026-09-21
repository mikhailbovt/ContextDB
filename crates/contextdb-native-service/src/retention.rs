//! Explicit retention workflow. External intent precedes every native cleanup.

use contextdb_core::ObservationId;
use contextdb_recall::QueryBudget;
use suppression::{RemovalCheckpoint, RemovalIntent};

use super::*;

pub(crate) mod keys;
mod preparation;
mod pruning;
pub use keys::{
    NativeOwnedKeyAction, NativeOwnedKeyDisposition, NativeOwnedKeyInventory, NativeOwnedKeyOwner,
    NativeOwnedKeyRemovalReceipt, NativeOwnedKeyRemovalWitness, NativePrimaryKeyAction,
    NativePrimaryKeyDisposition, NativePrimaryKeyInventory, NativePrimaryKeyRemovalReceipt,
    NativePrimaryKeyRemovalWitness,
};
pub use preparation::NativeRemovalPreparationReceipt;
pub(super) use preparation::RemovalPreparationPublication;
pub use pruning::NativeSourcePruningReceipt;
pub(super) use pruning::audit_budget;
pub(super) use pruning::{PRUNING_FEATURE, SourcePruningPublication};

pub(super) const RETENTION_FEATURE: &str = "continuous-retention-authority-v1";

/// Durable intent to remove originals and their dependent data.
/// This acknowledges a closed disclosure gate, not completed removal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRemovalRequestReceipt {
    /// Independently retained authority required after restart or restore.
    pub authority_id: uuid::Uuid,
    /// Position in that authority's retention journal, not a native commit.
    pub sequence: u64,
    /// Content-free request commitment in that authority.
    pub digest: String,
    /// Native workspace prefix whose source lineage was inspected.
    pub inspected_workspace_commit: u64,
    /// Explicit source IDs. The executor also follows their derived copies.
    pub roots: BTreeSet<ObservationId>,
}

impl NativeService {
    /// Durably request explicit removal after inspecting source dependencies.
    /// The external Sync closes disclosure even if no native cleanup is published
    /// before a crash. Repeating the exact retry key returns this same receipt.
    pub fn request_original_removal(
        &self,
        context: &AuthenticatedRequestContext,
        roots: &BTreeSet<ObservationId>,
        idempotency_key: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRemovalRequestReceipt> {
        require_capability(context, Capability::Admin)?;
        validate_identifier(idempotency_key, "retention request retry key")?;
        if !(1..=256).contains(&roots.len()) {
            return Err(invalid("retention requires 1..256 roots"));
        }
        let ledger = self.suppression.as_ref().ok_or_else(|| {
            unsupported("retention requires the current external suppression authority")
        })?;
        ledger.require_removal_authority()?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let retry_key = canonical_digest(&("original_removal/v1", &workspace, idempotency_key))?;
        let request_digest = canonical_digest(&(context.authorization_binding_digest()?, roots))?;
        if let Some((checkpoint, intent)) =
            ledger.removal_request(&workspace, &retry_key, &request_digest)?
        {
            return Ok(removal_receipt(ledger, &checkpoint, &intent));
        }
        let inspected = self.inspect_original_deletion(context, roots, budget)?;
        let _guard = self.lock_index_publication(budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self
            .workspace_state(&snapshot, &context.request.workspace_id)?
            .watermarks
            .journal
            != inspected.workspace_commit
        {
            return Err(removal_pending());
        }
        let previous = ledger
            .current_removal(&workspace)?
            .ok_or_else(|| integrity("native workspace lacks retention registration"))?;
        let intent = RemovalIntent {
            workspace,
            roots: inspected
                .sources
                .iter()
                .filter(|source| roots.contains(&source.receipt.event_id))
                .map(|source| source.receipt.clone())
                .collect(),
            native_commit: inspected.workspace_commit,
            lineage_digest: inspected.digest,
            retry_key,
            request_digest,
            previous,
        };
        #[cfg(test)]
        BEFORE_INTENT_SYNC.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let (checkpoint, accepted) = ledger.request_removal(intent, &inspected, budget)?;
        #[cfg(test)]
        AFTER_INTENT_SYNC.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        Ok(removal_receipt(ledger, &checkpoint, &accepted))
    }

    /// Recover the exact source inventory acknowledged with this request, even
    /// when the local database was restored from an older archive. This is the
    /// retained inspection prefix, not a fresh scan or a removal-completion proof.
    pub fn read_original_removal_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeDeletionLineage> {
        require_capability(context, Capability::Admin)?;
        let ledger = self.suppression.as_ref().ok_or_else(|| {
            unsupported("retention inventory requires the retained suppression authority")
        })?;
        if receipt.authority_id != ledger.authority_id() {
            return Err(invalid(
                "removal request belongs to another retained authority",
            ));
        }
        let checkpoint = RemovalCheckpoint {
            sequence: receipt.sequence,
            digest: receipt.digest.clone(),
        };
        let (intent, inventory) = ledger.retained_removal_inventory(
            &digest_bytes(context.request.workspace_id.as_bytes()),
            &checkpoint,
            budget,
        )?;
        if removal_receipt(ledger, &checkpoint, &intent) != *receipt {
            return Err(invalid("removal request receipt fields differ"));
        }
        Ok(inventory)
    }

    pub(super) fn require_removal_current<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<()> {
        let Some(ledger) = &self.suppression else {
            return Ok(());
        };
        if !ledger.supports_removal() {
            return Ok(());
        }
        let required = ledger.current_removal(workspace)?;
        let Some(required) = required else {
            return if snapshot
                .get(&self.keyspaces.workspace, workspace.as_bytes())
                .map_err(storage_error)?
                .is_none()
            {
                Ok(())
            } else {
                Err(integrity(
                    "native workspace lost its retained removal registration",
                ))
            };
        };
        // Only a verified cleanup publication may reopen this gate. Merely
        // writing an applied cursor is never a completion acknowledgement.
        if required.sequence != 0 {
            return Err(removal_pending());
        }
        Ok(())
    }
}

pub(crate) fn removal_receipt(
    ledger: &NativeSuppressionLedger,
    checkpoint: &RemovalCheckpoint,
    intent: &RemovalIntent,
) -> NativeRemovalRequestReceipt {
    NativeRemovalRequestReceipt {
        authority_id: ledger.authority_id(),
        sequence: checkpoint.sequence,
        digest: checkpoint.digest.clone(),
        inspected_workspace_commit: intent.native_commit,
        roots: intent.roots.iter().map(|source| source.event_id).collect(),
    }
}

fn removal_pending() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "current retention removal must finish before disclosure",
        true,
    )
}

#[cfg(test)]
thread_local! {
    static AFTER_INTENT_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static BEFORE_INTENT_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}

#[cfg(test)]
mod tests;
