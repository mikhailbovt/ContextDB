//! Current suppression is owned outside the restoreable native authority.

mod ledger;
#[cfg(test)]
pub(crate) mod tests;
mod verify;

use super::{raw_index::budget_error, *};
use contextdb_core::ObservationId;
use contextdb_recall::QueryBudget;
use ledger::Checkpoint;
pub use ledger::NativeSuppressionLedger;
pub(crate) use ledger::{RecordSourceControl, RecordSourcesCheckpoint};
pub(crate) use ledger::{RemovalCheckpoint, RemovalIntent};

pub(super) const SUPPRESSION_FEATURE: &str = "continuous-external-suppression-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SuppressionPublication {
    from: Checkpoint,
    through: Checkpoint,
}

/// Progress importing current external denials into a restored native authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionProgress {
    /// Exact external authority epoch applied in this workspace.
    pub through: u64,
    /// External entries consumed by this call, at most 256.
    pub processed: u32,
    /// Native source permissions have caught up with the current authority.
    /// Inherited custody propagation and index rebuilding may still be pending.
    pub caught_up: bool,
}

impl NativeService {
    /// Open with an independently retained suppression authority. New databases
    /// bind its identity permanently. Existing unbound nonempty databases need
    /// explicit migration; they cannot silently acquire an empty policy ledger.
    pub fn open_with_suppression(
        path: impl AsRef<Path>,
        database_id: impl Into<String>,
        token_key: [u8; 32],
        suppression: std::sync::Arc<NativeSuppressionLedger>,
    ) -> ServiceResult<Self> {
        Self::open_internal(path, database_id.into(), token_key, Some(suppression), None)
    }

    pub(super) fn verify_suppression_binding(&self, manifest: &Manifest) -> ServiceResult<()> {
        if manifest.suppression_authority
            != self
                .suppression
                .as_ref()
                .map(|ledger| ledger.authority_id())
        {
            return Err(integrity(
                "native store requires its exact current external suppression authority",
            ));
        }
        if manifest.features.contains(retention::RETENTION_FEATURE)
            != self
                .suppression
                .as_ref()
                .is_some_and(|ledger| ledger.supports_removal())
        {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "native retention authority format differs; explicit migration is required",
                false,
            ));
        }
        if manifest.features.contains(record_sources::FEATURE)
            && !self
                .suppression
                .as_ref()
                .is_some_and(|ledger| ledger.supports_record_sources())
        {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "native record provenance requires its version 3 retained authority",
                false,
            ));
        }
        Ok(())
    }

    fn suppression_applied<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<Checkpoint> {
        let ledger = self.suppression.as_ref().ok_or_else(|| {
            unsupported("current external suppression authority is not configured")
        })?;
        self.raw_value(snapshot, &applied_key(workspace))?
            .map_or_else(|| ledger.genesis(workspace), Ok)
    }

    pub(super) fn require_suppression_current<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<()> {
        self.require_suppression_prefix_current(snapshot, workspace)?;
        self.require_removal_current(snapshot, workspace)?;
        self.require_record_sources_current(snapshot, workspace)?;
        Ok(())
    }

    pub(super) fn require_suppression_prefix_current<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<()> {
        if let Some(ledger) = &self.suppression
            && self.suppression_applied(snapshot, workspace)? != ledger.current(workspace)?
        {
            return Err(pending());
        }
        Ok(())
    }

    pub(super) fn require_unsuppressed_identity(
        &self,
        workspace: &str,
        id: ObservationId,
    ) -> ServiceResult<()> {
        if let Some(ledger) = &self.suppression
            && ledger.denied(workspace, id)?
        {
            return Err(permission_denied());
        }
        Ok(())
    }

    // The external Sync precedes native publication. A failure or cancellation
    // between the two leaves a durable epoch mismatch, closing disclosure even
    // after restart. Bounded maintenance finishes that accepted denial.
    pub(super) fn record_external_revocation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
        budget: &QueryBudget,
    ) -> ServiceResult<Option<Checkpoint>> {
        let Some(ledger) = &self.suppression else {
            return Ok(None);
        };
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        self.require_suppression_current(snapshot, &workspace)?;
        let receipt = self.captured_receipt_metadata(snapshot, id)?;
        if receipt.workspace_id.to_string() != context.request.workspace_id {
            return Err(permission_denied());
        }
        let expected = self.suppression_applied(snapshot, &workspace)?;
        #[cfg(test)]
        BEFORE_EXTERNAL_COMMIT.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        // Compare under the external publication owner as well: another native
        // replica may have advanced the authority after our first read.
        let denial = ledger.deny(&workspace, id, receipt.event_digest, &expected, budget)?;
        #[cfg(test)]
        AFTER_EXTERNAL_COMMIT.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        Ok(Some(denial.checkpoint()))
    }

    pub(super) fn publish_suppression_checkpoint<T: WriteTransaction>(
        &self,
        tx: &mut T,
        context: &AuthenticatedRequestContext,
        through: Checkpoint,
    ) -> ServiceResult<()> {
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let from = self.suppression_applied(tx, &workspace)?;
        if through.epoch <= from.epoch {
            return Ok(());
        }
        let publication = SuppressionPublication { from, through };
        tx.put(
            &self.keyspaces.continuous,
            applied_key(&workspace),
            encode(&publication.through)?,
        )
        .map_err(storage_error)?;
        let frame = self.begin_frame(tx, &context.request.workspace_id, false)?;
        let digest = canonical_digest(&(&workspace, &publication))?;
        self.finish_frame(
            tx,
            &frame,
            "suppression_reconcile",
            digest.as_bytes(),
            &digest,
            &publication,
        )
    }

    /// Apply 1..256 durable external denials. Analysis is outside publication;
    /// a concurrent local reconciler rejects the complete attempt. Independent
    /// capture remains available while disclosure is closed by an epoch mismatch.
    pub fn maintain_suppression(
        &self,
        context: &AuthenticatedRequestContext,
        max_entries: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<SuppressionProgress> {
        require_capability(context, Capability::Admin)?;
        if !(1..=256).contains(&max_entries) {
            return Err(invalid("suppression batch must contain 1..256 entries"));
        }
        budget.check().map_err(budget_error)?;
        let ledger = self.suppression.as_ref().ok_or_else(|| {
            unsupported("current external suppression authority is not configured")
        })?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let from = self.suppression_applied(&snapshot, &workspace)?;
        let entries = ledger.batch(&workspace, &from, max_entries, budget)?;
        drop(snapshot);
        let Some(last) = entries.last() else {
            return Ok(SuppressionProgress {
                through: from.epoch,
                processed: 0,
                caught_up: ledger.current(&workspace)? == from,
            });
        };
        let through = last.checkpoint();
        #[cfg(test)]
        BEFORE_NATIVE_PUBLISH.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if self.suppression_applied(&tx, &workspace)? != from {
            return Err(pending());
        }
        for entry in &entries {
            budget.check().map_err(budget_error)?;
            // A denial can refer to an original captured after this backup.
            // Its ID stays denied externally, including future recapture attempts.
            budget.charge(1, 0).map_err(budget_error)?;
            if let Some(policy_bytes) = tx
                .get(
                    &self.keyspaces.observations_policy,
                    digest_bytes(entry.event_id.to_string().as_bytes()).as_bytes(),
                )
                .map_err(storage_error)?
            {
                budget
                    .charge(1, policy_bytes.len() as u64)
                    .map_err(budget_error)?;
                let receipt = self.captured_receipt_metadata(&tx, entry.event_id)?;
                budget
                    .charge(0, encode(&receipt)?.len() as u64)
                    .map_err(budget_error)?;
                if receipt.event_digest != entry.event_digest
                    || receipt.workspace_id.to_string() != context.request.workspace_id
                {
                    return Err(integrity(
                        "external suppression source differs from the restored original",
                    ));
                }
                let digest = canonical_digest(&(ledger.authority_id(), &entry.digest))?;
                self.revoke_original_in_transaction(
                    &mut tx,
                    context,
                    entry.event_id,
                    digest.as_bytes(),
                    &digest,
                )?;
            }
        }
        self.publish_suppression_checkpoint(&mut tx, context, through.clone())?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(SuppressionProgress {
            through: through.epoch,
            processed: entries.len() as u32,
            caught_up: ledger.current(&workspace)? == through,
        })
    }
}

fn applied_key(workspace: &str) -> Vec<u8> {
    format!("suppression/applied/{workspace}").into_bytes()
}
fn pending() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "current external suppression must be reconciled before disclosure",
        true,
    )
}

#[cfg(test)]
thread_local! {
    static AFTER_EXTERNAL_COMMIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_EXTERNAL_COMMIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_NATIVE_PUBLISH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
