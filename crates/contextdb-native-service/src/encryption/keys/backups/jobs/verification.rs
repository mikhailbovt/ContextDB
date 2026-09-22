use super::*;

impl NativeCustodyKeys {
    pub(in crate::encryption::keys::backups) fn walk_backup_jobs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        head: &Head,
        expected: &mut BTreeSet<Vec<u8>>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<NativeBackupCleanupJob>> {
        let mut jobs = BTreeMap::<Vec<u8>, NativeBackupCleanupJob>::new();
        let mut originals = BTreeMap::<String, NativeBackupCleanupJob>::new();
        let mut workers = BTreeMap::<Uuid, String>::new();
        let mut previous = None;
        let mut bytes = 0usize;
        let end = head.jobs.as_ref().map_or(0, |receipt| receipt.sequence);
        for sequence in 1..=end {
            let key = event_key(sequence);
            let event: JobEvent = self.read_job_record(snapshot, &key, budget)?;
            let value = &event.value;
            value.receipt.validate(self).map_err(storage_error)?;
            if value.receipt.sequence != sequence
                || event.previous != previous
                || event.commitment()? != value.receipt.digest
                || (sequence == end && head.jobs.as_ref() != Some(&value.receipt))
            {
                return Err(integrity("archive job chain or terminal differs"));
            }
            self.verify_job_dependencies(snapshot, value, budget)?;
            let index = job_key(&value.binding);
            let prior = jobs.get(&index);
            if event.prior.as_ref() != prior.map(|job| &job.receipt) {
                return Err(integrity("archive job predecessor differs"));
            }
            require_transition(
                value,
                prior,
                originals.get(&value.binding.original.archive_digest),
                &workers,
            )?;
            bytes = bytes
                .checked_add(encode(value).map_err(storage_error)?.len())
                .ok_or_else(|| crate::exhausted("archive job inventory size overflow"))?;
            if bytes > 32 * 1024 * 1024 {
                return Err(crate::exhausted("archive job inventory exceeds 32 MiB"));
            }
            previous = Some(value.receipt.digest.clone());
            workers.insert(
                value.binding.worker_instance,
                value.binding.original.archive_digest.clone(),
            );
            originals.insert(value.binding.original.archive_digest.clone(), value.clone());
            jobs.insert(index, event.value);
            expected.insert(key);
        }
        for (key, job) in &jobs {
            let receipt: NativeBackupCleanupJobReceipt =
                self.read_job_record(snapshot, key, budget)?;
            if receipt != job.receipt {
                return Err(integrity("archive job request index differs"));
            }
            expected.insert(key.clone());
        }
        for (digest, job) in originals {
            let key = original_key(&digest);
            let receipt: NativeBackupCleanupJobReceipt =
                self.read_job_record(snapshot, &key, budget)?;
            if receipt != job.receipt {
                return Err(integrity("archive job original index differs"));
            }
            expected.insert(key);
        }
        for (instance, digest) in workers {
            let key = worker_key(instance);
            let actual: String = self.read_job_record(snapshot, &key, budget)?;
            if actual != digest {
                return Err(integrity("archive job worker index differs"));
            }
            expected.insert(key);
        }
        let mut jobs: Vec<_> = jobs.into_values().collect();
        jobs.sort_by_key(|job| job.receipt.sequence);
        Ok(jobs)
    }

    pub(super) fn verify_job_dependencies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        job: &NativeBackupCleanupJob,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let binding = &job.binding;
        if job.terminal.is_some() != job.terminal_archive_digest.is_some()
            || (job.terminal.is_some() && !job.initialized)
        {
            return Err(integrity("archive job result lacks its native digest"));
        }
        if let Some(digest) = &job.terminal_archive_digest {
            valid_digest(digest).map_err(storage_error)?;
        }
        valid_digest(&binding.workspace_digest).map_err(storage_error)?;
        valid_digest(&binding.request.digest).map_err(storage_error)?;
        if binding.worker_instance.is_nil()
            || binding.source_path.len() > 256
            || binding.restore_at == Some(0)
            || binding.request.authority_id.is_nil()
            || binding.request.sequence == 0
            || binding.request.roots.is_empty()
        {
            return Err(integrity("archive job worker or ancestry bound differs"));
        }
        budget.charge(1, 0).map_err(budget_error)?;
        self.require_worker_job_before_seal(
            snapshot,
            binding.worker_instance,
            job.receipt.sequence,
        )
        .map_err(storage_error)?;
        let mut source = self
            .find_contents(snapshot, &binding.original.archive_digest, budget)?
            .ok_or_else(|| integrity("archive job original contents are absent"))?
            .inventory();
        if source.registration != binding.original {
            return Err(integrity("archive job original issuance differs"));
        }
        for receipt in &binding.source_path {
            let proof = self.replacement_at(snapshot, receipt, budget)?;
            if proof.source != source
                || proof.workspace_digest != binding.workspace_digest
                || proof.request.authority_id != binding.request.authority_id
            {
                return Err(integrity("archive job source ancestry or scope differs"));
            }
            source = proof.target;
        }
        let artifact = self.artifact_at(snapshot, &binding.source_artifact, budget)?;
        if source != binding.source || artifact.contents != source || !artifact.complete {
            return Err(integrity(
                "archive job input is not the complete accepted artifact",
            ));
        }
        if let Some(result) = &job.terminal {
            match (&result.stage, &result.replacement, &result.artifact) {
                (NativeBackupCleanupStage::Unchanged, None, None) => {}
                (NativeBackupCleanupStage::Available, Some(proof), Some(artifact)) => {
                    if job.terminal_archive_digest.as_ref()
                        != Some(&proof.target.registration.archive_digest)
                        || proof.request != binding.request
                        || proof.workspace_digest != binding.workspace_digest
                        || proof.source != source
                        || artifact.contents != proof.target
                        || !artifact.complete
                        || self.replacement_at(snapshot, &proof.receipt, budget)? != *proof
                        || self.artifact_at(snapshot, &artifact.receipt, budget)? != *artifact
                    {
                        return Err(integrity(
                            "archive job result differs from accepted cleanup",
                        ));
                    }
                }
                _ => {
                    return Err(integrity(
                        "archive job terminal is not completed logical cleanup",
                    ));
                }
            }
        }
        budget.check().map_err(budget_error)
    }

    pub(super) fn read_job_record<S: ReadSnapshot, T: serde::de::DeserializeOwned>(
        &self,
        snapshot: &S,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<T> {
        budget.check().map_err(budget_error)?;
        let bytes = snapshot
            .get(&self.rows, key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("archive job control is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_EVENT_BYTES + 64 {
            return Err(integrity("archive job control exceeds 256 KiB"));
        }
        self.open_backup_record(key, &bytes).map_err(storage_error)
    }

    // Native-use replay calls this without recursively replaying worker state.
    // The complete backup verifier separately checks every job dependency and
    // rejects any later job on the sealed instance.
    pub(in crate::encryption::keys) fn verify_worker_seal_job<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &NativeBackupCleanupJobReceipt,
        instance: Uuid,
    ) -> contextdb_storage::Result<()> {
        receipt.validate(self)?;
        let head = self.backup_head(snapshot)?;
        if head
            .jobs
            .as_ref()
            .is_none_or(|last| receipt.sequence > last.sequence)
        {
            return Err(failure("worker seal references an unretained job"));
        }
        let key = event_key(receipt.sequence);
        let bytes = snapshot
            .get(&self.rows, &key)?
            .ok_or_else(|| failure("worker seal job is absent"))?;
        if bytes.len() > MAX_EVENT_BYTES + 64 {
            return Err(failure("worker seal job exceeds its control bound"));
        }
        let event: JobEvent = self.open_backup_record(&key, &bytes)?;
        if event.value.receipt != *receipt
            || event
                .commitment()
                .map_err(|_| failure("worker seal job cannot be verified"))?
                != receipt.digest
            || event.value.binding.worker_instance != instance
            || !event.value.initialized
            || event.value.terminal.is_none()
            || event.value.terminal_archive_digest.is_none()
        {
            return Err(failure("worker seal requires its exact completed job"));
        }
        Ok(())
    }
}

pub(super) fn require_transition(
    job: &NativeBackupCleanupJob,
    prior: Option<&NativeBackupCleanupJob>,
    original: Option<&NativeBackupCleanupJob>,
    workers: &BTreeMap<Uuid, String>,
) -> ServiceResult<()> {
    let binding = &job.binding;
    if workers
        .get(&binding.worker_instance)
        .is_some_and(|digest| *digest != binding.original.archive_digest)
    {
        return Err(integrity("archive worker is bound to another original"));
    }
    if let Some(prior) = prior {
        if prior.binding != *binding
            || prior.terminal.is_some()
            || !job.initialized
            || prior.initialized != job.terminal.is_some()
        {
            return Err(integrity(
                "archive job changes its binding or terminal result",
            ));
        }
    } else {
        if job.terminal.is_some() || job.initialized != original.is_some() {
            return Err(integrity("archive job lacks its accepted start"));
        }
        if let Some(original) = original {
            let (source, path, artifact) = original.next_source()?;
            if binding.restore_at.is_some()
                || binding.original != original.binding.original
                || binding.worker_instance != original.binding.worker_instance
                || binding.workspace_digest != original.binding.workspace_digest
                || binding.request.authority_id != original.binding.request.authority_id
                || binding.source != source
                || binding.source_path != path
                || binding.source_artifact != artifact
            {
                return Err(integrity(
                    "archive job does not continue its prior worker and result",
                ));
            }
        } else if binding.restore_at.is_none() {
            return Err(integrity(
                "initial archive job lacks its pristine import binding",
            ));
        }
    }
    Ok(())
}
