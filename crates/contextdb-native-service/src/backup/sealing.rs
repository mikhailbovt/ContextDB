//! Verify the actual terminal worker before permanently fencing publication.

use super::*;
use crate::{
    NativeBackupCleanupJob, NativeBackupCleanupJobReceipt, NativeBackupFrontier,
    NativeBackupWorkerSeal, NativeRemovalRequestReceipt,
};
use contextdb_recall::QueryBudget;
use contextdb_service::AuthenticatedRequestContext;

#[cfg(test)]
mod tests;

pub(crate) struct VerifiedBackupWorkerSeal {
    job: NativeBackupCleanupJob,
    frontier: NativeBackupFrontier,
    native_sequence: u64,
}

impl VerifiedBackupWorkerSeal {
    pub(crate) fn into_parts(self) -> (NativeBackupCleanupJob, NativeBackupFrontier, u64) {
        (self.job, self.frontier, self.native_sequence)
    }
}

impl NativeService {
    /// Read a seal through any authorized owner, including when the worker can no
    /// longer open. The exact retained request and job remain required.
    pub fn read_removal_backup_worker_seal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativeBackupCleanupJobReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<NativeBackupWorkerSeal>> {
        let job = self.read_removal_backup_job(context, request, receipt, budget)?;
        let seal = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?
            .backup_worker_seal(job.binding.worker_instance, budget)?;
        if seal.as_ref().is_some_and(|value| value.job != job.receipt) {
            return Err(integrity(
                "worker was sealed after a different completed job",
            ));
        }
        crate::retention::keys::charge_report(&seal, budget)?;
        Ok(seal)
    }

    /// Permanently fence this exact completed worker after verifying its native
    /// bytes still match the accepted terminal result and preservation is readable.
    /// Retries recover the independent receipt after an uncertain Sync. Retain the
    /// directory: sealing does not dispose copies or permit an unverified replacement.
    pub fn seal_removal_backup_worker(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativeBackupCleanupJobReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupWorkerSeal> {
        let job = self.read_removal_backup_job(context, request, receipt, budget)?;
        let _job_guard = self
            .backup_jobs
            .enter(|| budget.check().map_err(crate::raw_index::budget_error))?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        if let Some(seal) = keys.backup_worker_seal(job.binding.worker_instance, budget)? {
            if seal.job != job.receipt {
                return Err(integrity(
                    "worker was sealed after a different completed job",
                ));
            }
            crate::retention::keys::charge_report(&seal, budget)?;
            return Ok(seal);
        }
        let _native_guard = self.lock_index_publication(budget)?;
        if self.engine.registered_instance().map_err(storage_error)? != job.binding.worker_instance
        {
            return Err(integrity(
                "worker sealing requires the job's actual native instance",
            ));
        }
        if job.terminal.is_none() {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "worker sealing requires a completed cleanup job",
                false,
            ));
        }
        let (catalog, _) = keys.selected_backup_keys_for_request(
            &BTreeMap::new(),
            &digest_bytes(context.request.workspace_id.as_bytes()),
            request,
            budget,
        )?;
        let native_sequence = self.engine.head_sequence().map_err(storage_error)?;
        let (_, current) = self.build_native_backup()?;
        budget
            .charge(1, current.bytes.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        if self.engine.head_sequence().map_err(storage_error)? != native_sequence
            || job.terminal_archive_digest.as_ref() != Some(&current.digest)
        {
            return Err(integrity("worker changed after its completed cleanup job"));
        }
        #[cfg(test)]
        BEFORE_WORKER_SEAL.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        keys.seal_backup_worker(
            VerifiedBackupWorkerSeal {
                job,
                frontier: catalog.frontier,
                native_sequence,
            },
            budget,
        )
    }
}

#[cfg(test)]
type SealHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    static BEFORE_WORKER_SEAL: std::cell::RefCell<Option<SealHook>> = const { std::cell::RefCell::new(None) };
}
