//! Restartable execution bound to one retained input and registered native worker.

use super::*;
use crate::{
    NativeBackupCleanupJob, NativeBackupCleanupJobBinding, NativeBackupCleanupJobReceipt,
    NativeBackupFrontier, NativeBackupRegistration, NativeRemovalRequestReceipt,
};
use contextdb_recall::QueryBudget;
use contextdb_service::AuthenticatedRequestContext;
use serde::{Deserialize, Serialize};

#[cfg(test)]
pub(crate) mod tests;

/// One bounded job advance. Intermediate work lives in existing native journals;
/// binding, verified import and terminal acceptance use the independent job journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupCleanupJobProgress {
    /// Latest independently retained job state.
    pub job: NativeBackupCleanupJob,
    /// Work accepted by this call, or the immutable terminal result on a retry.
    pub progress: NativeBackupCleanupProgress,
}

// Constructible only after the service checks the worker or finishes real cleanup.
pub(crate) struct VerifiedBackupJob {
    value: NativeBackupCleanupJob,
    frontier: Option<NativeBackupFrontier>,
    removal: Option<scopes::ArchiveRemovalFence>,
}

impl VerifiedBackupJob {
    pub(crate) fn into_parts(
        self,
    ) -> (
        NativeBackupCleanupJob,
        Option<NativeBackupFrontier>,
        Option<scopes::ArchiveRemovalFence>,
    ) {
        (self.value, self.frontier, self.removal)
    }
}

impl NativeService {
    /// Reserve an archive cleanup job on a pristine, separately opened encrypted
    /// worker. Retain its directory: retries must use this registered instance.
    /// The fixed input is imported on first advance.
    /// No host path or caller checkpoint supplies authority.
    ///
    /// A lost start response is recovered by repeating this call. An unfinished
    /// request cannot be replaced. After completion, a new request starts from the
    /// previous result, preserving prior authorized removals. A fresh replacement
    /// requires the exact retained seal of the latest completed worker. It imports
    /// that job's clean input once; an unsealed lost worker or a different workspace
    /// cannot be reassigned through this API.
    pub fn start_removal_backup_job(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &NativeBackupRegistration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJob> {
        self.start_backup_job(context, request, original, None, budget)
    }

    /// Host-only admission with fresh Admin and exact retained requests for every
    /// input scope. A workspace change requires the exact prior worker seal.
    pub fn start_removal_backup_job_with_scope_authority(
        &self,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        original: &NativeBackupRegistration,
        resolver: &NativeArchiveScopeResolver<'_>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJob> {
        let scopes =
            self.archive_job_scope_frame(resolver, workspace, request, original, budget)?;
        let context = scopes.context_for(&digest_bytes(workspace.as_bytes()), request)?;
        self.start_backup_job(context, request, original, Some(&scopes), budget)
    }

    fn start_backup_job(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &NativeBackupRegistration,
        scopes: Option<&scopes::VerifiedArchiveScopes>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJob> {
        self.read_original_removal_inventory(context, request, budget)?;
        let _job_guard = self
            .backup_jobs
            .enter(|| budget.check().map_err(crate::raw_index::budget_error))?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let (catalog, replacements) = if scopes.is_some() {
            keys.selected_backup_keys_for_authority(&BTreeMap::new(), request, budget)?
        } else {
            keys.selected_backup_keys_for_request(&BTreeMap::new(), &workspace, request, budget)?
        };
        let instance = self.engine.registered_instance().map_err(storage_error)?;
        if let Some(job) = catalog.jobs.iter().find(|job| {
            job.binding.original == *original
                && job.binding.request == *request
                && job.binding.workspace_digest == workspace
        }) {
            require_job_scopes(job, scopes)?;
            require_worker(job, instance)?;
            return Ok(job.clone());
        }
        let prior = catalog
            .jobs
            .iter()
            .rev()
            .find(|job| job.binding.original.archive_digest == original.archive_digest);
        let mut worker_seal = None;
        let (source, source_path, source_artifact) = if let Some(prior) = prior {
            require_job_scopes(prior, scopes)?;
            if (scopes.is_none() && prior.binding.workspace_digest != workspace)
                || prior.binding.original != *original
                || prior.binding.request.authority_id != request.authority_id
            {
                return Err(integrity(
                    "archive worker belongs to another original or scope",
                ));
            }
            if let Some(scopes) = scopes {
                scopes.context_for(&prior.binding.workspace_digest, &prior.binding.request)?;
            }
            let (source, path, artifact) = prior.next_source()?;
            if prior.binding.worker_instance != instance {
                let seal = keys
                    .backup_worker_seal(prior.binding.worker_instance, budget)?
                    .ok_or_else(|| {
                        integrity("archive replacement requires its prior worker seal")
                    })?;
                if seal.job != prior.receipt {
                    return Err(integrity(
                        "archive replacement seal differs from its latest job",
                    ));
                }
                worker_seal = Some(seal);
            }
            if prior.binding.workspace_digest != workspace && worker_seal.is_none() {
                return Err(integrity(
                    "workspace continuation requires a fresh sealed worker",
                ));
            }
            self.read_fixed_job_input(context, request, &path, &artifact, scopes, budget)?;
            (source, path, artifact)
        } else {
            let input = if let Some(scopes) = scopes {
                self.removal_backup_input_authorized(
                    context,
                    request,
                    original,
                    Some(scopes),
                    budget,
                )?
            } else {
                self.read_removal_backup_input(context, request, original, budget)?
            };
            (input.target, input.replacements, input.artifact)
        };
        let scope_continuation = if let Some(scopes) = scopes {
            scope_continuation(
                &workspace,
                request,
                prior,
                &source_path,
                &replacements,
                scopes,
                budget,
            )?
        } else {
            None
        };
        let _native_guard = self.lock_index_publication(budget)?;
        let restore_at = if prior.is_none() || worker_seal.is_some() {
            let snapshot = self
                .engine
                .begin_read(SnapshotSelector::Latest)
                .map_err(storage_error)?;
            self.require_pristine_restore_target(&snapshot)?;
            Some(self.engine.head_sequence().map_err(storage_error)?)
        } else {
            let (_, current) = self.build_native_backup()?;
            budget
                .charge(1, current.bytes.len() as u64)
                .map_err(crate::raw_index::budget_error)?;
            if prior.and_then(|job| job.terminal_archive_digest.as_ref()) != Some(&current.digest) {
                return Err(integrity(
                    "archive worker changed after its prior terminal result",
                ));
            }
            None
        };
        let job = NativeBackupCleanupJob {
            receipt: NativeBackupCleanupJobReceipt {
                authority_id: keys.authority_id(),
                sequence: 0,
                digest: String::new(),
            },
            binding: NativeBackupCleanupJobBinding {
                workspace_digest: workspace,
                request: request.clone(),
                original: original.clone(),
                source,
                source_path,
                source_artifact,
                worker_instance: instance,
                worker_seal,
                scope_continuation,
                restore_at,
            },
            initialized: restore_at.is_none(),
            terminal: None,
            terminal_archive_digest: None,
        };
        keys.accept_backup_job(
            VerifiedBackupJob {
                value: job,
                frontier: Some(catalog.frontier),
                removal: self.job_removal_fence(scopes),
            },
            budget,
        )
    }

    /// Resolve an exact accepted start or finish receipt to the latest job state.
    /// Current Admin and exact retained request are checked before reading custody.
    /// This may inspect another worker; advancing always requires the bound instance.
    pub fn read_removal_backup_job(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativeBackupCleanupJobReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJob> {
        self.read_original_removal_inventory(context, request, budget)?;
        self.engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?
            .backup_cleanup_job(
                receipt,
                &digest_bytes(context.request.workspace_id.as_bytes()),
                request,
                budget,
            )
    }

    /// Import once or advance one existing cleanup operation using the job's fixed
    /// input. Reopen this worker and repeat with its start receipt after uncertainty.
    /// A terminal retry returns the accepted result without importing or pruning.
    /// The result is historical logical cleanup, never all-copy deletion admission.
    pub fn advance_removal_backup_job(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativeBackupCleanupJobReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJobProgress> {
        self.advance_backup_job(context, request, receipt, None, budget)
    }

    /// Advance a retained mixed-scope job using a fresh host operation frame.
    pub fn advance_removal_backup_job_with_scope_authority(
        &self,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativeBackupCleanupJobReceipt,
        resolver: &NativeArchiveScopeResolver<'_>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJobProgress> {
        let current = resolver.context(workspace, budget)?;
        let job = self.read_removal_backup_job(&current, request, receipt, budget)?;
        let scopes = self.archive_job_scope_frame(
            resolver,
            workspace,
            request,
            &job.binding.original,
            budget,
        )?;
        let context = scopes.context_for(&digest_bytes(workspace.as_bytes()), request)?;
        self.advance_backup_job(context, request, receipt, Some(&scopes), budget)
    }

    fn advance_backup_job(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativeBackupCleanupJobReceipt,
        scopes: Option<&scopes::VerifiedArchiveScopes>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJobProgress> {
        self.read_original_removal_inventory(context, request, budget)?;
        let _job_guard = self
            .backup_jobs
            .enter(|| budget.check().map_err(crate::raw_index::budget_error))?;
        let mut job = self.read_removal_backup_job(context, request, receipt, budget)?;
        require_job_scopes(&job, scopes)?;
        require_worker(
            &job,
            self.engine.registered_instance().map_err(storage_error)?,
        )?;
        if let Some(progress) = job.terminal.clone() {
            return Ok(NativeBackupCleanupJobProgress { job, progress });
        }
        let source = self.read_fixed_job_input(
            context,
            request,
            &job.binding.source_path,
            &job.binding.source_artifact,
            scopes,
            budget,
        )?;
        if !job.initialized {
            return self.initialize_backup_job(context, job, source, scopes, budget);
        }
        let (progress, digest) =
            self.advance_removal_backup_for_job(context, request, &source, budget)?;
        if matches!(
            progress.stage,
            NativeBackupCleanupStage::Available | NativeBackupCleanupStage::Unchanged
        ) {
            job.terminal = Some(progress.clone());
            job.terminal_archive_digest = digest;
            #[cfg(test)]
            BEFORE_JOB_FINISH.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
            job = self
                .engine
                .keys
                .as_ref()
                .ok_or_else(|| integrity("archive custody absent"))?
                .accept_backup_job(
                    VerifiedBackupJob {
                        value: job,
                        frontier: None,
                        removal: self.job_removal_fence(scopes),
                    },
                    budget,
                )?;
        }
        Ok(NativeBackupCleanupJobProgress { job, progress })
    }

    fn initialize_backup_job(
        &self,
        context: &AuthenticatedRequestContext,
        mut job: NativeBackupCleanupJob,
        source: BackupResponse,
        scopes: Option<&scopes::VerifiedArchiveScopes>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJobProgress> {
        let start = job
            .binding
            .restore_at
            .ok_or_else(|| integrity("archive job lacks its import binding"))?;
        let digest = source.digest.clone();
        if self.engine.head_sequence().map_err(storage_error)? == start {
            budget.check().map_err(crate::raw_index::budget_error)?;
            self.restore_native_backup(RestoreBackupRequest {
                context: context.clone(),
                format: source.format,
                digest: source.digest,
                bytes: source.bytes,
            })?;
        }
        // A crash after native Sync but before custody acknowledgement is recovered
        // by checking that exact import. Other host writes cannot stand in for it.
        let _guard = self.lock_index_publication(budget)?;
        if start.checked_add(1) != Some(self.engine.head_sequence().map_err(storage_error)?) {
            return Err(integrity(
                "archive job worker does not contain its exact initial import",
            ));
        }
        let (_, current) = self.build_native_backup()?;
        budget
            .charge(1, current.bytes.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        if current.digest != digest {
            return Err(integrity(
                "archive job imported bytes differ from its fixed input",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace_commit = self
            .workspace_state(&snapshot, &context.request.workspace_id)?
            .watermarks
            .journal;
        job.initialized = true;
        job = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?
            .accept_backup_job(
                VerifiedBackupJob {
                    value: job,
                    frontier: None,
                    removal: self.job_removal_fence(scopes),
                },
                budget,
            )?;
        Ok(NativeBackupCleanupJobProgress {
            job,
            progress: NativeBackupCleanupProgress {
                stage: NativeBackupCleanupStage::Restored,
                workspace_commit,
                replacement: None,
                artifact: None,
            },
        })
    }

    pub(super) fn read_fixed_job_input(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        path: &[crate::NativeBackupReplacementReceipt],
        artifact: &crate::NativeBackupArtifactReceipt,
        scopes: Option<&scopes::VerifiedArchiveScopes>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BackupResponse> {
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        let (catalog, replacements) = if scopes.is_some() {
            keys.selected_backup_keys_for_authority(&BTreeMap::new(), request, budget)?
        } else {
            keys.selected_backup_keys_for_request(
                &BTreeMap::new(),
                &digest_bytes(context.request.workspace_id.as_bytes()),
                request,
                budget,
            )?
        };
        let mut verified = Vec::new();
        let mut by_sequence = BTreeMap::new();
        for proof in &replacements {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            by_sequence.insert(proof.receipt.sequence, proof);
        }
        for receipt in path {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            let proof = by_sequence
                .get(&receipt.sequence)
                .copied()
                .filter(|proof| proof.receipt == *receipt)
                .ok_or_else(|| integrity("archive job ancestry is absent from its scope"))?;
            verified.push(proof.clone());
        }
        if let Some(scopes) = scopes {
            self.verify_backup_replacement_requests_with_scopes(
                scopes, request, &verified, budget,
            )?;
            scopes.require_frontier(self, budget)?;
        } else {
            self.verify_backup_replacement_requests(context, request, &verified, budget)?;
        }
        let backup = keys.read_archive_artifact(artifact, budget)?;
        self.verify_encrypted_archive(&backup, budget)?;
        let _guard = keys.lock_backup_frontier(&catalog.frontier, budget)?;
        if let Some(scopes) = scopes {
            scopes.require_frontier(self, budget)?;
        }
        Ok(backup)
    }

    fn job_removal_fence(
        &self,
        scopes: Option<&scopes::VerifiedArchiveScopes>,
    ) -> Option<scopes::ArchiveRemovalFence> {
        scopes.and_then(|scopes| {
            self.suppression
                .as_ref()
                .map(|ledger| (ledger.clone(), scopes.removal_frontier.clone()))
        })
    }
}

fn require_worker(job: &NativeBackupCleanupJob, instance: uuid::Uuid) -> ServiceResult<()> {
    if job.binding.worker_instance != instance {
        return Err(integrity(
            "archive cleanup requires its exact registered worker",
        ));
    }
    Ok(())
}

pub(super) fn require_job_scopes(
    job: &NativeBackupCleanupJob,
    scopes: Option<&scopes::VerifiedArchiveScopes>,
) -> ServiceResult<()> {
    if let Some(continuation) = &job.binding.scope_continuation {
        let scopes = scopes.ok_or_else(|| {
            ServiceError::new(
                ErrorCode::EvidenceRequired,
                "mixed archive jobs require fresh host authority for every retained scope",
                false,
            )
        })?;
        scopes.context_for(&job.binding.workspace_digest, &job.binding.request)?;
        for request in &continuation.requests {
            scopes.context_for(&request.workspace_digest, &request.request)?;
        }
    }
    Ok(())
}

fn scope_continuation(
    workspace: &str,
    request: &NativeRemovalRequestReceipt,
    prior: Option<&NativeBackupCleanupJob>,
    path: &[crate::NativeBackupReplacementReceipt],
    proofs: &[crate::NativeBackupReplacement],
    scopes: &scopes::VerifiedArchiveScopes,
    budget: &mut QueryBudget,
) -> ServiceResult<Option<crate::NativeBackupScopeContinuation>> {
    Ok(
        scopes::path_scope_requests(workspace, request, path, proofs, prior, scopes, budget)?.map(
            |requests| crate::NativeBackupScopeContinuation {
                previous_job: prior.map(|prior| prior.receipt.clone()),
                requests,
            },
        ),
    )
}

#[cfg(test)]
type FinishHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    static BEFORE_JOB_FINISH: std::cell::RefCell<Option<FinishHook>> = const { std::cell::RefCell::new(None) };
}
