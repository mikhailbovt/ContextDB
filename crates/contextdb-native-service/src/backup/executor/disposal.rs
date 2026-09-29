//! Bounded local namespace disposal; historical copy and key evidence is retained.

use super::*;
use crate::{
    NativeBackupWorkerDisposal, NativeBackupWorkerDisposalBinding, NativeBackupWorkerSeal,
};
use contextdb_storage_fjall::ClosedFjallDirectory;

mod files;

// Only this executor constructs acceptance after actual exclusion/absence checks.
pub(crate) struct VerifiedWorkerDisposal {
    binding: NativeBackupWorkerDisposalBinding,
    directory_absent: bool,
}

impl VerifiedWorkerDisposal {
    pub(crate) fn into_parts(self) -> (NativeBackupWorkerDisposalBinding, bool) {
        (self.binding, self.directory_absent)
    }
}

/// One controlled filesystem operation. Directory absence does not certify media,
/// key, cached plaintext or external-copy destruction, or global removal admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeArchiveWorkerDisposalProgress {
    /// An existing backend owner or snapshot still holds the directory lock.
    AwaitingHandles {
        /// Permanent fence whose directory remains in use.
        seal: NativeBackupWorkerSeal,
    },
    /// Intent is synchronized; native files have not yet been removed.
    Prepared {
        /// Independent worker/path/preservation binding.
        disposal: Box<NativeBackupWorkerDisposal>,
    },
    /// At most the requested number of filesystem entries were removed.
    Removing {
        /// Retained intent, still holding preservation keys.
        disposal: Box<NativeBackupWorkerDisposal>,
        /// Entries unlinked by this call; not securely erased bytes.
        removed_entries: u32,
    },
    /// Both managed names are currently absent following the retained intent.
    DirectoryAbsent {
        /// Retained observation, independently readable after uncertainty.
        disposal: Box<NativeBackupWorkerDisposal>,
    },
}

impl NativeArchiveCleanup<'_> {
    pub(super) fn pending_worker_disposals(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<u64, (NativeBackupRegistration, NativeBackupWorkerDisposal)>> {
        let keys = self
            .owner
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        Ok(keys
            .pending_backup_worker_disposals(&workspace, request, budget)?
            .into_iter()
            .map(|(original, disposal)| (disposal.binding.seal.sequence, (original, disposal)))
            .collect())
    }

    pub(super) fn resume_worker_disposal(
        &mut self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        pending: BTreeMap<u64, (NativeBackupRegistration, NativeBackupWorkerDisposal)>,
        resolver: Option<&NativeArchiveScopeResolver<'_>>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveCleanupAction> {
        let request_key = (request.authority_id, request.sequence);
        let schedule = self
            .schedules
            .get_mut(&request_key)
            .ok_or_else(|| integrity("worker disposal scheduling has no request"))?;
        let Some((&sequence, (original, disposal))) = pending
            .iter()
            .find(|(sequence, _)| **sequence > schedule.disposal_after)
            .or_else(|| pending.first_key_value())
        else {
            return Err(integrity(
                "worker disposal scheduling lost its pending intent",
            ));
        };
        schedule.disposal_after = sequence;
        schedule.prefer_archive = true;
        let progress = if let Some(resolver) = resolver {
            self.dispose_worker_with_scope_authority(
                &context.request.workspace_id,
                request,
                &disposal.binding.seal.job,
                resolver,
                16,
                budget,
            )?
        } else {
            self.dispose_worker(context, request, &disposal.binding.seal.job, 16, budget)?
        };
        Ok(NativeArchiveCleanupAction::DisposalAdvanced {
            original: original.clone(),
            progress: Box::new(progress),
        })
    }

    /// Dispose one permanently sealed worker's managed directory in bounded
    /// portions. The host must retain exclusive administrative custody of this
    /// namespace. Current Admin/exact request, complete readable preservation and
    /// actual backend lock/instance checks precede any intent or filesystem change.
    ///
    /// Repeat the exact job/root after interruption. Intent precedes quarantine and
    /// unlink; completion follows observed absence. Old jobs, seals and copy history
    /// remain. A completed retry checks both names again, since a historical
    /// observation cannot authorize a claim about a restored or externally copied
    /// directory. Neither this operation nor its receipts are a media erasure API.
    pub fn dispose_worker(
        &mut self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        job: &NativeBackupCleanupJobReceipt,
        max_entries: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveWorkerDisposalProgress> {
        self.dispose_worker_authorized(context, request, job, max_entries, None, budget)
    }

    /// Dispose a sealed generation whose preservation traverses freshly
    /// authorized workspace requests. The immutable intent records exact scopes.
    pub fn dispose_worker_with_scope_authority(
        &mut self,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        job: &NativeBackupCleanupJobReceipt,
        resolver: &NativeArchiveScopeResolver<'_>,
        max_entries: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveWorkerDisposalProgress> {
        let scopes = self
            .owner
            .archive_available_scope_frame(resolver, workspace, request, budget)?;
        let context = scopes.context_for(&digest_bytes(workspace.as_bytes()), request)?;
        self.dispose_worker_authorized(context, request, job, max_entries, Some(&scopes), budget)
    }

    fn dispose_worker_authorized(
        &mut self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        job: &NativeBackupCleanupJobReceipt,
        max_entries: u32,
        scopes: Option<&scopes::VerifiedArchiveScopes>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveWorkerDisposalProgress> {
        if !(1..=256).contains(&max_entries) {
            return Err(crate::invalid(
                "worker disposal accepts 1..256 entries per call",
            ));
        }
        let job = self
            .owner
            .read_removal_backup_job(context, request, job, budget)?;
        jobs::require_job_scopes(&job, scopes)?;
        let keys = self
            .owner
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        let seal = keys
            .backup_worker_seal(job.binding.worker_instance, budget)?
            .filter(|seal| seal.job == job.receipt)
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::EvidenceRequired,
                    "worker disposal requires its exact completed seal",
                    false,
                )
            })?;
        let (catalog, replacements) = if let Some(scopes) = scopes {
            let (catalog, replacements) =
                keys.selected_backup_keys_for_authority(&BTreeMap::new(), request, budget)?;
            let mut authorized = Vec::new();
            for proof in replacements {
                budget
                    .charge(1, 0)
                    .map_err(crate::raw_index::budget_error)?;
                if scopes
                    .context_for(&proof.workspace_digest, &proof.request)
                    .is_ok()
                {
                    authorized.push(proof);
                }
            }
            self.owner.verify_backup_replacement_requests_with_scopes(
                scopes,
                request,
                &authorized,
                budget,
            )?;
            (catalog, authorized)
        } else {
            let (catalog, replacements) = keys.selected_backup_keys_for_request(
                &BTreeMap::new(),
                &digest_bytes(context.request.workspace_id.as_bytes()),
                request,
                budget,
            )?;
            self.owner.verify_backup_replacement_requests(
                context,
                request,
                &replacements,
                budget,
            )?;
            (catalog, replacements)
        };
        let generation = catalog
            .jobs
            .iter()
            .any(|job| {
                job.binding.worker_instance == seal.worker_instance
                    && job.binding.worker_seal.is_some()
            })
            .then_some(seal.worker_instance);
        let path = self.existing_worker_path(&job.binding.original, generation, budget)?;
        let directory_digest = directory_digest(&path)?;
        let prior = keys.backup_worker_disposal(seal.worker_instance, budget)?;
        if let Some(prior) = &prior
            && let Some(required) = &prior.binding.preservation_scope_requests
        {
            let scopes = scopes.ok_or_else(|| ServiceError::new(
                ErrorCode::EvidenceRequired,
                "mixed worker disposal requires fresh host authority for its retained preservation",
                false,
            ))?;
            for required in required {
                scopes.context_for(&required.workspace_digest, &required.request)?;
            }
        }
        if self
            .worker
            .as_ref()
            .is_some_and(|(opened, _)| *opened == path)
        {
            self.worker = None;
        }
        if let Some(prior) = &prior
            && (prior.binding.seal != seal || prior.binding.directory_digest != directory_digest)
        {
            return Err(integrity(
                "worker disposal root or seal differs from its retained intent",
            ));
        }
        let preservation = if prior.is_none() {
            Some(self.worker_disposal_input(context, request, &job, &catalog, scopes, budget)?)
        } else {
            None
        };
        #[cfg(test)]
        BEFORE_DISPOSAL_PUBLICATION.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        let _publication = keys.lock_backup_frontier(&catalog.frontier, budget)?;
        let _removal = scopes
            .map(|scopes| {
                self.owner
                    .suppression
                    .as_ref()
                    .ok_or_else(|| integrity("archive scope authority absent"))?
                    .lock_removal_frontier(&scopes.removal_frontier, budget)
            })
            .transpose()?;
        keys.require_current_worker_disposal(seal.worker_instance, prior.as_ref(), budget)?;
        let Some(disposal) = prior else {
            let Some(_closed) = keys.lock_closed_backup_worker(&path, &seal, budget)? else {
                return report(
                    NativeArchiveWorkerDisposalProgress::AwaitingHandles { seal },
                    budget,
                );
            };
            let input =
                preservation.ok_or_else(|| integrity("worker disposal preservation absent"))?;
            let preservation_scope_requests = scopes
                .map(|scopes| {
                    scopes::path_scope_requests(
                        &job.binding.workspace_digest,
                        &job.binding.request,
                        &input.replacements,
                        &replacements,
                        Some(&job),
                        scopes,
                        budget,
                    )
                })
                .transpose()?
                .flatten();
            let binding = NativeBackupWorkerDisposalBinding {
                seal,
                directory_digest,
                preservation_path: input.replacements,
                preservation_artifact: input.artifact,
                preservation_scope_requests,
            };
            let disposal = keys.retain_worker_disposal(
                VerifiedWorkerDisposal {
                    binding,
                    directory_absent: false,
                },
                budget,
            )?;
            return report(
                NativeArchiveWorkerDisposalProgress::Prepared {
                    disposal: Box::new(disposal),
                },
                budget,
            );
        };
        let quarantine = files::quarantine_path(&path, &disposal)?;
        self.require_worker_path(&quarantine)?;
        let source_exists = files::exists(&path)?;
        let quarantine_exists = files::exists(&quarantine)?;
        if disposal.directory_absent {
            if source_exists || quarantine_exists {
                return Err(ServiceError::new(
                    ErrorCode::EvidenceRequired,
                    "disposed worker directory reappeared; its historical observation is not current absence",
                    false,
                ));
            }
            return report(
                NativeArchiveWorkerDisposalProgress::DirectoryAbsent {
                    disposal: Box::new(disposal),
                },
                budget,
            );
        }
        if source_exists && quarantine_exists {
            return Err(integrity("worker source and quarantine both exist"));
        }
        let closed = if source_exists {
            let Some(closed) = keys.lock_closed_backup_worker(&path, &seal, budget)? else {
                return report(
                    NativeArchiveWorkerDisposalProgress::AwaitingHandles { seal },
                    budget,
                );
            };
            #[cfg(test)]
            BEFORE_QUARANTINE.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
            self.require_worker_path(&path)?;
            // Windows can refuse a rename while the backend lock file is open.
            // Custody and the permanent seal exclude cooperating native opens
            // across this gap; reacquire and verify before unlinking any data.
            drop(closed);
            std::fs::rename(&path, &quarantine)
                .map_err(|_| integrity("worker quarantine rename failed"))?;
            self.require_worker_path(&quarantine)?;
            #[cfg(test)]
            AFTER_QUARANTINE.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
            let Some(closed) = keys.lock_closed_backup_worker(&quarantine, &seal, budget)? else {
                return report(
                    NativeArchiveWorkerDisposalProgress::AwaitingHandles { seal },
                    budget,
                );
            };
            Some(closed)
        } else if quarantine_exists {
            if files::exists(&quarantine.join("lock"))? {
                let Some(closed) =
                    ClosedFjallDirectory::try_acquire(&quarantine).map_err(storage_error)?
                else {
                    return report(
                        NativeArchiveWorkerDisposalProgress::AwaitingHandles { seal },
                        budget,
                    );
                };
                Some(closed)
            } else {
                if std::fs::read_dir(&quarantine)
                    .map_err(|_| integrity("worker quarantine cannot be inspected"))?
                    .next()
                    .is_some()
                {
                    return Err(integrity("partial worker quarantine lost its backend lock"));
                }
                None
            }
        } else {
            None
        };
        let removed_entries = if files::exists(&quarantine)? {
            files::remove_portion(&quarantine, closed, max_entries, budget)?
        } else {
            0
        };
        if files::exists(&path)? {
            return Err(integrity("worker source reappeared during disposal"));
        }
        if files::exists(&quarantine)? {
            return report(
                NativeArchiveWorkerDisposalProgress::Removing {
                    disposal: Box::new(disposal),
                    removed_entries,
                },
                budget,
            );
        }
        #[cfg(test)]
        BEFORE_DISPOSAL_FINISH.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        let disposal = keys.retain_worker_disposal(
            VerifiedWorkerDisposal {
                binding: disposal.binding,
                directory_absent: true,
            },
            budget,
        )?;
        report(
            NativeArchiveWorkerDisposalProgress::DirectoryAbsent {
                disposal: Box::new(disposal),
            },
            budget,
        )
    }

    fn worker_disposal_input(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        sealed: &NativeBackupCleanupJob,
        catalog: &crate::NativeBackupKeyInventory,
        scopes: Option<&scopes::VerifiedArchiveScopes>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupRecoveryInput> {
        let (source, prefix, _) = sealed.next_source()?;
        if let Some(scopes) = scopes
            && let Some(latest) = catalog
                .jobs
                .iter()
                .rev()
                .find(|job| job.binding.original == sealed.binding.original)
            && latest.receipt != sealed.receipt
            && latest.terminal.is_some()
            && scopes
                .context_for(&latest.binding.workspace_digest, &latest.binding.request)
                .is_ok()
            && jobs::require_job_scopes(latest, Some(scopes)).is_ok()
        {
            let (target, path, artifact) = latest.next_source()?;
            if !path.starts_with(&prefix) {
                return Err(integrity(
                    "worker disposal successor changes its sealed ancestry",
                ));
            }
            if catalog.archives.iter().any(|archive| {
                archive.contents.as_ref() == Some(&target)
                    && archive.keys_available
                    && archive
                        .artifact
                        .as_ref()
                        .is_some_and(|value| value.complete && value.receipt == artifact)
            }) {
                let replacements = path[prefix.len()..].to_vec();
                if replacements.len() > 256 {
                    return Err(exhausted("worker disposal preservation exceeds 256 edges"));
                }
                let backup = self.owner.read_fixed_job_input(
                    context,
                    request,
                    &path,
                    &artifact,
                    Some(scopes),
                    budget,
                )?;
                return Ok(NativeBackupRecoveryInput {
                    original: source.registration,
                    target,
                    replacements,
                    artifact,
                    backup,
                });
            }
        }
        self.owner.removal_backup_input_authorized(
            context,
            request,
            &source.registration,
            scopes,
            budget,
        )
    }
}

fn directory_digest(path: &Path) -> ServiceResult<String> {
    canonical_digest(&(
        "contextdb/managed-worker-directory/v1",
        path.to_str()
            .ok_or_else(|| crate::invalid("worker path is not Unicode"))?,
    ))
}

fn report(
    value: NativeArchiveWorkerDisposalProgress,
    budget: &mut QueryBudget,
) -> ServiceResult<NativeArchiveWorkerDisposalProgress> {
    crate::retention::keys::charge_report(&value, budget)?;
    Ok(value)
}

#[cfg(test)]
type DisposalHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_DISPOSAL_PUBLICATION: std::cell::RefCell<Option<DisposalHook>> = const { std::cell::RefCell::new(None) };
    pub(super) static BEFORE_QUARANTINE: std::cell::RefCell<Option<DisposalHook>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_QUARANTINE: std::cell::RefCell<Option<DisposalHook>> = const { std::cell::RefCell::new(None) };
    pub(super) static BEFORE_DISPOSAL_FINISH: std::cell::RefCell<Option<DisposalHook>> = const { std::cell::RefCell::new(None) };
}
