//! Permanent worker publication fence; copy history and key obligations remain.

use super::*;
use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};

#[cfg(test)]
mod tests;

/// Independently retained seal of one exact completed archive worker. This stops
/// future native publication; it proves neither physical erasure nor key disposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupWorkerSeal {
    /// Current custody authority, outside the worker directory.
    pub authority_id: Uuid,
    /// Seal's position in the required native-use journal.
    pub sequence: u64,
    /// Exact native-use event commitment.
    pub digest: String,
    /// Permanently fenced instance, never reused for a new worker.
    pub worker_instance: Uuid,
    /// Reconciled native physical sequence when sealed.
    pub native_sequence: u64,
    /// Exact independently accepted terminal job; its preserved result was readable.
    pub job: NativeBackupCleanupJobReceipt,
}

pub(super) fn receipt(
    authority_id: Uuid,
    checkpoint: &UseCheckpoint,
    marker: &LocalMarker,
    job: &NativeBackupCleanupJobReceipt,
) -> contextdb_storage::Result<NativeBackupWorkerSeal> {
    validate_checkpoint(checkpoint, false)?;
    Ok(NativeBackupWorkerSeal {
        authority_id,
        sequence: checkpoint.sequence,
        digest: checkpoint
            .digest
            .clone()
            .ok_or_else(|| failure("worker seal has no digest"))?,
        worker_instance: marker.instance,
        native_sequence: marker.native_sequence,
        job: job.clone(),
    })
}

impl NativeCustodyKeys {
    pub(in crate::encryption::keys) fn worker_seal_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        instance: Uuid,
    ) -> contextdb_storage::Result<Option<NativeBackupWorkerSeal>> {
        Ok(self.use_state(snapshot, instance)?.sealed)
    }

    pub(crate) fn seal_backup_worker(
        &self,
        proof: crate::backup::sealing::VerifiedBackupWorkerSeal,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupWorkerSeal> {
        use crate::{integrity, raw_index::budget_error, storage_error};
        let (job, frontier, native_sequence) = proof.into_parts();
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let catalog = self.selected_backup_keys_at(&tx, &BTreeMap::new(), budget)?;
        let mut state = self
            .use_state(&tx, job.binding.worker_instance)
            .map_err(storage_error)?;
        if let Some(seal) = state.sealed {
            if seal.job != job.receipt {
                return Err(integrity(
                    "worker was sealed after a different completed job",
                ));
            }
            return Ok(seal);
        }
        if catalog.frontier != frontier {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "archive frontier changed before worker sealing; retry",
                true,
            ));
        }
        if catalog
            .jobs
            .iter()
            .rev()
            .find(|value| value.binding.original == job.binding.original)
            != Some(&job)
            || job.terminal.is_none()
            || state.pending.is_some()
            || state.marker.native_sequence != native_sequence
        {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "worker sealing requires its latest completed job and reconciled native state",
                false,
            ));
        }
        let (target, _, artifact) = job.next_source()?;
        if !catalog.archives.iter().any(|archive| {
            archive.contents.as_ref() == Some(&target)
                && archive.keys_available
                && archive
                    .artifact
                    .as_ref()
                    .is_some_and(|value| value.complete && value.receipt == artifact)
        }) {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "worker sealing requires a complete currently readable result",
                false,
            ));
        }
        self.verify_worker_seal_job(&tx, &job.receipt, state.marker.instance)
            .map_err(storage_error)?;
        let mut head = self.use_head(&tx).map_err(storage_error)?;
        let accepted = self
            .append_use_event(
                &mut tx,
                &mut head,
                UseOperation::Seal {
                    previous: state.marker.clone(),
                    job: job.receipt.clone(),
                },
            )
            .map_err(storage_error)?;
        let seal = receipt(self.authority_id(), &accepted, &state.marker, &job.receipt)
            .map_err(storage_error)?;
        state.sealed = Some(seal.clone());
        journal::advance_state(&mut state, &accepted).map_err(storage_error)?;
        self.put_use_state(&mut tx, &state).map_err(storage_error)?;
        crate::retention::keys::charge_report(&seal, budget)?;
        #[cfg(test)]
        BEFORE_SEAL_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        crate::require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        #[cfg(test)]
        AFTER_SEAL_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        Ok(seal)
    }
}

#[cfg(test)]
type SealHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    pub(crate) static BEFORE_SEAL_SYNC: std::cell::RefCell<Option<SealHook>> = const { std::cell::RefCell::new(None) };
    pub(crate) static AFTER_SEAL_SYNC: std::cell::RefCell<Option<SealHook>> = const { std::cell::RefCell::new(None) };
}
