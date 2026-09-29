//! Operation-scoped host authentication from exact retained dependencies.

use super::*;
use crate::raw_index::budget_error;

impl NativeService {
    pub(crate) fn archive_scope_frame(
        &self,
        resolver: &NativeArchiveScopeResolver<'_>,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedArchiveScopes> {
        let required = self.archive_scope_requirements(resolver, workspace, request, budget)?;
        resolver.verify(self, &required, budget)
    }

    pub(crate) fn archive_available_scope_frame(
        &self,
        resolver: &NativeArchiveScopeResolver<'_>,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedArchiveScopes> {
        let required = self.archive_scope_requirements(resolver, workspace, request, budget)?;
        let current = ArchiveScopeRequirement {
            workspace_digest: digest_bytes(workspace.as_bytes()),
            request: request.clone(),
        };
        resolver.verify_available(self, &required, &current, budget)
    }

    fn archive_scope_requirements(
        &self,
        resolver: &NativeArchiveScopeResolver<'_>,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<ArchiveScopeRequirement>> {
        let current = ArchiveScopeRequirement {
            workspace_digest: digest_bytes(workspace.as_bytes()),
            request: request.clone(),
        };
        // Authenticate the current request before any cross-scope catalog read.
        let _current = resolver.verify(self, std::slice::from_ref(&current), budget)?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        let (catalog, replacements) =
            keys.selected_backup_keys_for_authority(&BTreeMap::new(), request, budget)?;
        let mut required = BTreeMap::from([(
            (current.workspace_digest.clone(), current.request.sequence),
            current,
        )]);
        let requests = replacements
            .into_iter()
            .map(|proof| ArchiveScopeRequirement {
                workspace_digest: proof.workspace_digest,
                request: proof.request,
            })
            .chain(catalog.jobs.into_iter().filter_map(|job| {
                (job.binding.request.authority_id == request.authority_id).then_some(
                    ArchiveScopeRequirement {
                        workspace_digest: job.binding.workspace_digest,
                        request: job.binding.request,
                    },
                )
            }));
        for scope in requests {
            budget.charge(1, 0).map_err(budget_error)?;
            let key = (scope.workspace_digest.clone(), scope.request.sequence);
            if let Some(prior) = required.get(&key) {
                if prior.request != scope.request {
                    return Err(integrity(
                        "archive scope repeats a request with different fields",
                    ));
                }
            } else {
                required.insert(key, scope);
            }
        }
        Ok(required.into_values().collect())
    }

    pub(crate) fn archive_job_scope_frame(
        &self,
        resolver: &NativeArchiveScopeResolver<'_>,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        original: &crate::NativeBackupRegistration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedArchiveScopes> {
        let current = ArchiveScopeRequirement {
            workspace_digest: digest_bytes(workspace.as_bytes()),
            request: request.clone(),
        };
        let _current = resolver.verify(self, std::slice::from_ref(&current), budget)?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        let (catalog, replacements) =
            keys.selected_backup_keys_for_authority(&BTreeMap::new(), request, budget)?;
        if !catalog
            .archives
            .iter()
            .any(|archive| archive.registration == *original)
        {
            return Err(integrity(
                "archive job requires its exact original issuance",
            ));
        }
        let selected = catalog
            .jobs
            .iter()
            .find(|job| {
                job.binding.original == *original
                    && job.binding.request == *request
                    && job.binding.workspace_digest == current.workspace_digest
            })
            .or_else(|| {
                catalog
                    .jobs
                    .iter()
                    .rev()
                    .find(|job| job.binding.original == *original)
            });
        let Some(job) = selected else {
            // First admission selects only routes with fresh grants. Unrelated
            // denied branches cannot prevent work on this original.
            return self.archive_available_scope_frame(resolver, workspace, request, budget);
        };
        let mut required = vec![
            current,
            ArchiveScopeRequirement {
                workspace_digest: job.binding.workspace_digest.clone(),
                request: job.binding.request.clone(),
            },
        ];
        if let Some(continuation) = &job.binding.scope_continuation {
            required.extend(
                continuation
                    .requests
                    .iter()
                    .map(|scope| ArchiveScopeRequirement {
                        workspace_digest: scope.workspace_digest.clone(),
                        request: scope.request.clone(),
                    }),
            );
        }
        let path = if job.binding.request == *request {
            job.binding.source_path.clone()
        } else {
            // An unfinished predecessor never permits an original fallback.
            job.next_source()?.1
        };
        let by_sequence: BTreeMap<_, _> = replacements
            .iter()
            .map(|proof| (proof.receipt.sequence, proof))
            .collect();
        for receipt in path {
            budget.charge(1, 0).map_err(budget_error)?;
            let proof = by_sequence
                .get(&receipt.sequence)
                .filter(|proof| proof.receipt == receipt)
                .ok_or_else(|| integrity("archive job scope ancestry is absent"))?;
            required.push(ArchiveScopeRequirement {
                workspace_digest: proof.workspace_digest.clone(),
                request: proof.request.clone(),
            });
        }
        resolver.verify(self, &required, budget)
    }
}
