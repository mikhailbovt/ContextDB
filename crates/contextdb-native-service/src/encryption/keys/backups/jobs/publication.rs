use super::*;

impl NativeCustodyKeys {
    pub(crate) fn backup_cleanup_job(
        &self,
        receipt: &NativeBackupCleanupJobReceipt,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJob> {
        receipt.validate(self).map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let event: JobEvent =
            self.read_job_record(&snapshot, &event_key(receipt.sequence), budget)?;
        if event.value.receipt != *receipt
            || event.value.binding.workspace_digest != workspace
            || event.value.binding.request != *request
        {
            return Err(integrity("archive job receipt or request differs"));
        }
        let report = self.selected_backup_keys_at(&snapshot, &BTreeMap::new(), budget)?;
        report
            .jobs
            .into_iter()
            .find(|job| job.binding == event.value.binding)
            .ok_or_else(|| integrity("archive job is not retained"))
    }

    // Only the native service constructs this token after source/worker checks or
    // an actual terminal coordinator result. Public serialized jobs grant no authority.
    pub(crate) fn accept_backup_job(
        &self,
        proof: crate::backup::jobs::VerifiedBackupJob,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupJob> {
        let (mut value, frontier) = proof.into_parts();
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let report = self.selected_backup_keys_at(&tx, &BTreeMap::new(), budget)?;
        let index = job_key(&value.binding);
        let prior = report
            .jobs
            .iter()
            .find(|job| job_key(&job.binding) == index);
        if let Some(prior) = prior {
            if prior.binding != value.binding {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "archive job retry changes its accepted binding or result",
                    false,
                ));
            }
            if prior.initialized == value.initialized
                && prior.terminal == value.terminal
                && prior.terminal_archive_digest == value.terminal_archive_digest
            {
                return Ok(prior.clone());
            }
        }
        if frontier.is_some_and(|frontier| frontier != report.frontier) {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "archive job input frontier changed; retry admission",
                true,
            ));
        }
        let original = report.jobs.iter().rev().find(|job| {
            job.binding.original.archive_digest == value.binding.original.archive_digest
        });
        let workers = report
            .jobs
            .iter()
            .map(|job| {
                (
                    job.binding.worker_instance,
                    job.binding.original.archive_digest.clone(),
                )
            })
            .collect();
        verification::require_transition(&value, prior, original, &workers)?;
        self.verify_job_dependencies(&tx, &value, budget)?;
        let target = value
            .terminal
            .as_ref()
            .and_then(|result| result.artifact.as_ref())
            .map_or(&value.binding.source, |artifact| &artifact.contents);
        if !report
            .archives
            .iter()
            .any(|archive| archive.contents.as_ref() == Some(target) && archive.keys_available)
        {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "archive job requires a currently readable accepted input or result",
                false,
            ));
        }
        let mut head = self.backup_head(&tx).map_err(storage_error)?;
        value.receipt.sequence = head
            .jobs
            .as_ref()
            .map_or(0, |receipt| receipt.sequence)
            .checked_add(1)
            .ok_or_else(|| crate::exhausted("archive job sequence exhausted"))?;
        let mut event = JobEvent {
            previous: head.jobs.as_ref().map(|receipt| receipt.digest.clone()),
            prior: prior.map(|job| job.receipt.clone()),
            value,
        };
        event.value.receipt.digest = event.commitment()?;
        let encoded = encode(&event).map_err(storage_error)?;
        budget
            .charge(1, encoded.len() as u64)
            .map_err(budget_error)?;
        if encoded.len() > MAX_EVENT_BYTES {
            return Err(crate::exhausted("archive job control exceeds 256 KiB"));
        }
        let key = event_key(event.value.receipt.sequence);
        tx.put(
            &self.rows,
            key.clone(),
            self.seal_backup_record(&key, &event)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        let binding = &event.value.binding;
        for key in [index, original_key(&binding.original.archive_digest)] {
            tx.put(
                &self.rows,
                key.clone(),
                self.seal_backup_record(&key, &event.value.receipt)
                    .map_err(storage_error)?,
            )
            .map_err(storage_error)?;
        }
        let key = worker_key(binding.worker_instance);
        tx.put(
            &self.rows,
            key.clone(),
            self.seal_backup_record(&key, &binding.original.archive_digest)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        head.jobs = Some(event.value.receipt.clone());
        tx.put(
            &self.rows,
            HEAD.to_vec(),
            self.seal_backup_record(HEAD, &head)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        #[cfg(test)]
        BEFORE_JOB_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        crate::require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        #[cfg(test)]
        AFTER_JOB_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        Ok(event.value)
    }
}

#[cfg(test)]
type PublicationHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_JOB_SYNC: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_JOB_SYNC: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
}
