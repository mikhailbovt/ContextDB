//! Retained intent and observed namespace removal for one sealed native worker.

use super::budget::BudgetedSnapshot;
use super::*;
use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};
use contextdb_storage_fjall::ClosedFjallDirectory;

#[cfg(test)]
mod tests;

/// Immutable scope of controlled directory disposal. No other native, archive,
/// key, media remnant or external copy is covered by this binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupWorkerDisposalBinding {
    /// Exact prior permanent publication fence.
    pub seal: NativeBackupWorkerSeal,
    /// Digest of the canonical managed directory, never a caller path authority.
    pub directory_digest: String,
    /// Authorized continuation from the sealed job's clean result.
    pub preservation_path: Vec<NativeBackupReplacementReceipt>,
    /// Complete preserved bytes whose keys stay held until directory removal.
    pub preservation_artifact: NativeBackupArtifactReceipt,
}

/// Independent acceptance of intent or observed directory absence. This records
/// local namespace disposition, not secure media erasure or global deletion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupWorkerDisposal {
    /// Authority retaining this result outside the worker directory.
    pub authority_id: Uuid,
    /// Native-use journal position.
    pub sequence: u64,
    /// Exact event commitment.
    pub digest: String,
    /// Immutable worker, directory and preservation authority.
    pub binding: NativeBackupWorkerDisposalBinding,
    /// False reserves intent; true observes absence after that retained intent.
    pub directory_absent: bool,
}

impl NativeBackupWorkerDisposal {
    pub(super) fn checkpoint(&self) -> UseCheckpoint {
        UseCheckpoint {
            sequence: self.sequence,
            digest: Some(self.digest.clone()),
        }
    }
}

pub(super) fn receipt(
    authority_id: Uuid,
    checkpoint: &UseCheckpoint,
    binding: NativeBackupWorkerDisposalBinding,
    directory_absent: bool,
) -> contextdb_storage::Result<NativeBackupWorkerDisposal> {
    validate_checkpoint(checkpoint, false)?;
    Ok(NativeBackupWorkerDisposal {
        authority_id,
        sequence: checkpoint.sequence,
        digest: checkpoint
            .digest
            .clone()
            .ok_or_else(|| failure("worker disposal has no commitment"))?,
        binding,
        directory_absent,
    })
}

impl NativeCustodyKeys {
    // Scheduling hints only: dispose_worker independently verifies the full use
    // chain and rechecks this exact state under publication before filesystem work.
    pub(crate) fn pending_backup_worker_disposals(
        &self,
        workspace: &str,
        request: &crate::NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<(NativeBackupRegistration, NativeBackupWorkerDisposal)>> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        let catalog = self.selected_backup_keys_at(&snapshot, &BTreeMap::new(), budget)?;
        let view = BudgetedSnapshot::new(snapshot, budget);
        let result = (|| {
            let mut pending = Vec::new();
            for job in catalog.jobs {
                if job.binding.workspace_digest != workspace
                    || job.binding.request != *request
                    || job.terminal.is_none()
                {
                    continue;
                }
                if let Some(disposal) =
                    self.worker_disposal_at(&view, job.binding.worker_instance)?
                    && !disposal.directory_absent
                    && disposal.binding.seal.job == job.receipt
                {
                    pending.push((job.binding.original, disposal));
                }
            }
            Ok(pending)
        })();
        let pending = view.complete(result)?;
        crate::retention::keys::charge_report(&pending, budget)?;
        Ok(pending)
    }

    pub(crate) fn require_current_worker_disposal(
        &self,
        instance: Uuid,
        expected: Option<&NativeBackupWorkerDisposal>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        let view = BudgetedSnapshot::new(snapshot, budget);
        let result = (|| {
            if self.worker_disposal_at(&view, instance)?.as_ref() != expected {
                return Err(view.reject(ServiceError::new(
                    ErrorCode::IndexTooStale,
                    "worker disposal changed before publication; repeat inspection",
                    true,
                )));
            }
            Ok(())
        })();
        view.complete(result)
    }
    pub(in crate::encryption::keys) fn worker_disposal_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        instance: Uuid,
    ) -> contextdb_storage::Result<Option<NativeBackupWorkerDisposal>> {
        Ok(self.use_state(snapshot, instance)?.disposal)
    }

    pub(super) fn verify_disposal_binding<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        binding: &NativeBackupWorkerDisposalBinding,
    ) -> contextdb_storage::Result<LocalMarker> {
        valid_digest(&binding.directory_digest)?;
        if binding.preservation_path.len() > 256 || binding.seal.authority_id != self.authority_id()
        {
            return Err(failure("worker disposal scope or ancestry differs"));
        }
        let event = self.use_event(snapshot, binding.seal.sequence)?;
        let UseOperation::Seal { previous, job } = event.change else {
            return Err(failure("worker disposal lacks its retained seal"));
        };
        if sealing::receipt(self.authority_id(), &event.checkpoint, &previous, &job)?
            != binding.seal
        {
            return Err(failure("worker disposal seal differs"));
        }
        self.verify_worker_seal_job(snapshot, &job, previous.instance)?;
        Ok(previous)
    }

    pub(crate) fn backup_worker_disposal(
        &self,
        instance: Uuid,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<NativeBackupWorkerDisposal>> {
        self.backup_worker_seal(instance, budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        self.selected_backup_keys_at(&snapshot, &BTreeMap::new(), budget)?;
        self.worker_disposal_at(&snapshot, instance)
            .map_err(crate::storage_error)
    }

    // Called only under the existing custody publication fence. Actual backend
    // lock ownership proves that no storage handle or cloned snapshot remains.
    pub(crate) fn lock_closed_backup_worker(
        &self,
        path: &Path,
        seal: &NativeBackupWorkerSeal,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<ClosedFjallDirectory>> {
        budget.check().map_err(crate::raw_index::budget_error)?;
        let Some(native) = FjallStorage::try_open_existing(path).map_err(crate::storage_error)?
        else {
            return Ok(None);
        };
        let snapshot = native
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        let view = BudgetedSnapshot::new(snapshot, budget);
        let result = self.read_local_marker(&view);
        let marker = view.complete(result)?;
        let authority = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        let view = BudgetedSnapshot::new(authority, budget);
        let result = self.use_state(&view, seal.worker_instance);
        let state = view.complete(result)?;
        if state.sealed.as_ref() != Some(seal) || state.marker != marker || state.pending.is_some()
        {
            return Err(crate::integrity(
                "closed directory differs from its sealed worker",
            ));
        }
        drop(native);
        budget.check().map_err(crate::raw_index::budget_error)?;
        ClosedFjallDirectory::try_acquire(path).map_err(crate::storage_error)
    }

    // The caller holds the custody queue from inspection through filesystem work.
    pub(crate) fn retain_worker_disposal(
        &self,
        proof: crate::backup::VerifiedWorkerDisposal,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupWorkerDisposal> {
        let (binding, directory_absent) = proof.into_parts();
        let mut tx = self.engine.begin_write().map_err(crate::storage_error)?;
        let catalog = self.selected_backup_keys_at(&tx, &BTreeMap::new(), budget)?;
        let mut state = self
            .use_state(&tx, binding.seal.worker_instance)
            .map_err(crate::storage_error)?;
        let marker = self
            .verify_disposal_binding(&tx, &binding)
            .map_err(crate::storage_error)?;
        if state.marker != marker
            || state.sealed.as_ref() != Some(&binding.seal)
            || state.pending.is_some()
        {
            return Err(crate::integrity(
                "worker disposal requires its reconciled sealed state",
            ));
        }
        if let Some(prior) = &state.disposal {
            if prior.binding != binding {
                return Err(crate::integrity(
                    "worker disposal retry changes its binding",
                ));
            }
            if prior.directory_absent || !directory_absent {
                return Ok(prior.clone());
            }
        } else if directory_absent {
            return Err(crate::integrity(
                "directory absence cannot create disposal intent",
            ));
        }
        self.verify_worker_disposal_preservation(&tx, &binding, budget)?;
        if !catalog.archives.iter().any(|archive| {
            archive.keys_available
                && archive.artifact.as_ref().is_some_and(|artifact| {
                    artifact.complete && artifact.receipt == binding.preservation_artifact
                })
        }) {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "worker disposal requires currently readable preservation",
                false,
            ));
        }
        let mut head = self.use_head(&tx).map_err(crate::storage_error)?;
        let prepared = state
            .disposal
            .as_ref()
            .map(NativeBackupWorkerDisposal::checkpoint);
        let accepted = self
            .append_use_event(
                &mut tx,
                &mut head,
                UseOperation::Disposal {
                    binding: Box::new(binding.clone()),
                    prepared,
                },
            )
            .map_err(crate::storage_error)?;
        let value = receipt(self.authority_id(), &accepted, binding, directory_absent)
            .map_err(crate::storage_error)?;
        state.disposal = Some(value.clone());
        journal::advance_state(&mut state, &accepted).map_err(crate::storage_error)?;
        self.put_use_state(&mut tx, &state)
            .map_err(crate::storage_error)?;
        crate::retention::keys::charge_report(&value, budget)?;
        #[cfg(test)]
        BEFORE_DISPOSAL_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        crate::require_sync(
            tx.commit(Durability::Sync)
                .map_err(crate::storage_error)?
                .durability,
        )?;
        #[cfg(test)]
        AFTER_DISPOSAL_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        Ok(value)
    }
}

#[cfg(test)]
type DisposalHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    pub(crate) static BEFORE_DISPOSAL_SYNC: std::cell::RefCell<Option<DisposalHook>> = const { std::cell::RefCell::new(None) };
    pub(crate) static AFTER_DISPOSAL_SYNC: std::cell::RefCell<Option<DisposalHook>> = const { std::cell::RefCell::new(None) };
}
