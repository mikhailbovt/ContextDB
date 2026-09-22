use super::*;
use crate::{NativeBackupKeyInventory, NativeBackupReplacement};

pub(super) fn inventory(
    owner: &NativeService,
    context: &AuthenticatedRequestContext,
    request: &NativeRemovalRequestReceipt,
    budget: &mut QueryBudget,
) -> ServiceResult<NativeArchiveCleanupInventory> {
    owner.read_original_removal_inventory(context, request, budget)?;
    let keys = owner
        .engine
        .keys
        .as_ref()
        .ok_or_else(|| integrity("archive custody absent"))?;
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let (catalog, replacements) =
        keys.selected_backup_keys_for_request(&BTreeMap::new(), &workspace, request, budget)?;
    owner.verify_backup_replacement_requests(context, request, &replacements, budget)?;
    let archives = entries(&catalog, &replacements, &workspace, request, budget)?;
    let report = NativeArchiveCleanupInventory {
        request: request.clone(),
        frontier: catalog.frontier,
        archives,
    };
    crate::retention::keys::charge_report(&report, budget)?;
    let _guard = keys.lock_backup_frontier(&report.frontier, budget)?;
    Ok(report)
}

fn entries(
    catalog: &NativeBackupKeyInventory,
    replacements: &[NativeBackupReplacement],
    workspace: &str,
    request: &NativeRemovalRequestReceipt,
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<NativeArchiveCleanupEntry>> {
    let recovery = recovery::recovery_from_inventory(catalog, replacements, budget)?;
    let mut latest = BTreeMap::new();
    let mut current = BTreeMap::new();
    let mut clean = BTreeMap::new();
    let mut owners = BTreeMap::new();
    let by_sequence: BTreeMap<_, _> = replacements
        .iter()
        .map(|proof| (proof.receipt.sequence, proof))
        .collect();
    let by_archive: BTreeMap<_, _> = catalog
        .archives
        .iter()
        .map(|archive| (archive.registration.sequence, archive))
        .collect();
    let mut outputs = BTreeMap::<_, Vec<_>>::new();
    for proof in replacements {
        budget
            .charge(1, 0)
            .map_err(crate::raw_index::budget_error)?;
        outputs
            .entry((
                proof.source.registration.sequence,
                proof.request.digest.as_str(),
            ))
            .or_default()
            .push(proof);
    }
    for job in &catalog.jobs {
        budget
            .charge(1, 0)
            .map_err(crate::raw_index::budget_error)?;
        latest.insert(job.binding.original.sequence, job);
        if job.binding.workspace_digest == workspace
            && job.binding.request.authority_id == request.authority_id
        {
            let original = job.binding.original.sequence;
            let mut assign = |sequence| {
                if sequence != original {
                    owners.entry(sequence).or_insert(original);
                }
            };
            assign(job.binding.source.registration.sequence);
            for receipt in &job.binding.source_path {
                budget
                    .charge(1, 0)
                    .map_err(crate::raw_index::budget_error)?;
                let proof = by_sequence
                    .get(&receipt.sequence)
                    .filter(|proof| proof.receipt == *receipt)
                    .ok_or_else(|| integrity("archive worker ancestry disappeared"))?;
                assign(proof.target.registration.sequence);
            }
            if job.terminal.is_some() {
                assign(job.next_source()?.0.registration.sequence);
            } else {
                // Defer partial outputs while this owner is running. After finish,
                // only its exact accepted ancestry/target stays an owned alias;
                // divergent branches still require their own verified cleanup.
                for proof in outputs
                    .get(&(
                        job.binding.source.registration.sequence,
                        job.binding.request.digest.as_str(),
                    ))
                    .into_iter()
                    .flatten()
                {
                    budget
                        .charge(1, 0)
                        .map_err(crate::raw_index::budget_error)?;
                    if proof.source != job.binding.source || proof.request != job.binding.request {
                        return Err(integrity(
                            "active archive output belongs to a different input or request",
                        ));
                    }
                    assign(proof.target.registration.sequence);
                }
            }
        }
        if job.binding.workspace_digest == workspace && job.binding.request == *request {
            current.insert(job.binding.original.sequence, job);
            if job.terminal.is_some() {
                let (source, _, _) = job.next_source()?;
                clean.insert(source.registration.sequence, &job.receipt);
            }
        }
    }
    let clean = coverage::CleanCoverage::new(catalog, replacements, clean, budget)?;
    let routes = routing::ArchiveRoutes::new(
        catalog,
        replacements,
        |sequence| clean.contains(sequence),
        budget,
    )?;
    let mut result = Vec::new();
    let mut report_bytes = 0;
    for archive in recovery {
        let sequence = archive.original.sequence;
        let prior = latest.get(&sequence).copied();
        let job = current.get(&sequence).copied();
        let route = routes.best(sequence, &mut report_bytes, budget)?;
        let state = if let Some(active) = prior.filter(|job| job.terminal.is_none()) {
            if active.binding.workspace_digest == workspace && active.binding.request == *request {
                NativeArchiveCleanupState::Running {
                    job: active.receipt.clone(),
                    worker_instance: active.binding.worker_instance,
                }
            } else {
                NativeArchiveCleanupState::WorkerBusy
            }
        } else if let Some(prior) = prior.filter(|_| job.is_none()) {
            if prior.binding.workspace_digest != workspace
                || prior.binding.request.authority_id != request.authority_id
            {
                NativeArchiveCleanupState::WorkerScopeRequired
            } else {
                classify(previous_input(&by_archive, prior)?)
            }
        } else if let Some(route) = route.filter(|route| route.artifact.is_some()) {
            let (job, clean_path) =
                clean.proof(route.path.target_sequence, &mut report_bytes, budget)?;
            NativeArchiveCleanupState::Covered {
                job,
                path: route.path,
                clean_path,
                artifact: route
                    .artifact
                    .ok_or_else(|| integrity("clean archive artifact disappeared"))?,
            }
        } else if let Some(done) = job.filter(|job| job.terminal.is_some()) {
            NativeArchiveCleanupState::CompletedUnavailable {
                job: done.receipt.clone(),
            }
        } else if let Some(original_sequence) = owners.get(&sequence) {
            NativeArchiveCleanupState::WaitingForOwner {
                original_sequence: *original_sequence,
            }
        } else {
            classify(archive.state)
        };
        let entry = NativeArchiveCleanupEntry {
            original: archive.original,
            state,
        };
        routing::reserve(&entry, &mut report_bytes, budget)?;
        result.push(entry);
    }
    Ok(result)
}

fn classify(input: NativeBackupRecoveryState) -> NativeArchiveCleanupState {
    match &input {
        NativeBackupRecoveryState::Available { path, .. } if path.replacements.len() > 256 => {
            NativeArchiveCleanupState::AncestryLimit
        }
        NativeBackupRecoveryState::Available { .. } => NativeArchiveCleanupState::Ready { input },
        _ => NativeArchiveCleanupState::AwaitingInput { input },
    }
}

fn previous_input(
    archives: &BTreeMap<u64, &crate::NativeBackupKeyArchive>,
    job: &NativeBackupCleanupJob,
) -> ServiceResult<NativeBackupRecoveryState> {
    let (target, replacements, artifact) = job.next_source()?;
    let archive = archives
        .get(&target.registration.sequence)
        .filter(|archive| archive.contents.as_ref() == Some(&target))
        .ok_or_else(|| integrity("archive worker's previous result is absent"))?;
    if !archive.keys_available {
        return Ok(NativeBackupRecoveryState::KeysUnavailable);
    }
    let path = NativeBackupPreservationPath {
        target_sequence: target.registration.sequence,
        replacements,
    };
    if archive
        .artifact
        .as_ref()
        .is_some_and(|value| value.complete && value.receipt == artifact)
    {
        Ok(NativeBackupRecoveryState::Available {
            target,
            path,
            artifact,
        })
    } else {
        Ok(NativeBackupRecoveryState::AwaitingArtifact { target, path })
    }
}
