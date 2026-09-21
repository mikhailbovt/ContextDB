use super::*;

impl NativeCustodyKeys {
    // The native service verifies the complete issued archive before supplying
    // bytes. Every partial publication still checks current custody and membership.
    pub(crate) fn retain_archive_artifact(
        &self,
        backup: &BackupResponse,
        contents: &NativeBackupContentsInventory,
        from: u32,
        max_pages: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupArtifactProgress> {
        self.require_backup_contents()?;
        if !(1..=MAX_BATCH_PAGES).contains(&max_pages) {
            return Err(invalid(
                "archive retention requires 1..16 pages per publication",
            ));
        }
        if backup.digest != contents.registration.archive_digest
            || backup.bytes.len() as u64 != contents.registration.encoded_bytes
            || backup.bytes.len() > crate::backup::MAX_BACKUP_BYTES
            || backup.commit_seq != contents.registration.native_commit
            || backup.format != crate::NATIVE_ENCRYPTED_BACKUP_FORMAT
            || crate::digest_bytes(&backup.bytes) != backup.digest
        {
            return Err(integrity("retained bytes differ from accepted archive"));
        }
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let report = self.selected_backup_keys_at(&tx, &BTreeMap::new(), budget)?;
        let previous = report
            .archives
            .into_iter()
            .find(|archive| archive.registration.archive_digest == backup.digest)
            .ok_or_else(|| integrity("archive artifact requires original issuance"))?;
        if previous.contents.as_ref() != Some(contents) {
            return Err(integrity("archive artifact contents changed"));
        }
        let index = index_key(&backup.digest, from);
        if let Some(bytes) = tx.get(&self.rows, &index).map_err(storage_error)? {
            let receipt: NativeBackupArtifactReceipt = self
                .open_backup_record(&index, &bytes)
                .map_err(storage_error)?;
            let event: ArtifactEvent =
                self.read_artifact_record(&tx, &event_key(receipt.sequence), budget)?;
            if event.contents != *contents
                || event.from != from
                || event.requested_pages != max_pages
            {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "archive portion retry changes its accepted bound",
                    false,
                ));
            }
            self.compare_artifact_prefix(&tx, contents, &backup.bytes, event.through, budget)?;
            budget.check().map_err(budget_error)?;
            return Ok(event.progress());
        }
        let through_before = previous
            .artifact
            .as_ref()
            .map_or(0, |progress| progress.stored_pages);
        let pages = backup.bytes.len().div_ceil(CHUNK_BYTES) as u32;
        if from != through_before || from >= pages {
            return Err(invalid(
                "archive portion must continue its accepted byte prefix",
            ));
        }
        // Comparing the accepted prefix to these exact verified bytes also catches
        // a rehashed false partial artifact before it can become complete.
        self.compare_artifact_prefix(&tx, contents, &backup.bytes, from, budget)?;
        let chain = if let Some(progress) = &previous.artifact {
            let prior: ArtifactEvent =
                self.read_artifact_record(&tx, &event_key(progress.receipt.sequence), budget)?;
            prior.chain
        } else {
            genesis(contents)?
        };
        let mut head = self.backup_head(&tx).map_err(storage_error)?;
        let mut event = ArtifactEvent {
            sequence: head
                .artifacts
                .as_ref()
                .map_or(0, |receipt| receipt.sequence)
                .checked_add(1)
                .ok_or_else(|| crate::exhausted("archive artifact sequence exhausted"))?,
            previous: head
                .artifacts
                .as_ref()
                .map(|receipt| receipt.digest.clone()),
            prior: previous.artifact.map(|progress| progress.receipt),
            contents: contents.clone(),
            from,
            through: from.saturating_add(max_pages).min(pages),
            requested_pages: max_pages,
            chain,
            digest: String::new(),
        };
        for page in from..event.through {
            let offset = page as usize * CHUNK_BYTES;
            let bytes = &backup.bytes[offset..(offset + CHUNK_BYTES).min(backup.bytes.len())];
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
            let key = chunk_key(&backup.digest, page);
            let sealed = seal(
                &self.master.0,
                &self.backup_aad(&key).map_err(storage_error)?,
                bytes,
            )
            .map_err(storage_error)?;
            tx.put(&self.rows, key, sealed).map_err(storage_error)?;
            event.chain = append_chunk(&event.chain, page, bytes)?;
        }
        event.digest = event.commitment()?;
        let receipt = event.receipt();
        let key = event_key(event.sequence);
        let encoded = encode(&event).map_err(storage_error)?;
        budget
            .charge(1, encoded.len() as u64)
            .map_err(budget_error)?;
        if encoded.len() > MAX_HEADER_BYTES {
            return Err(crate::exhausted("archive artifact control exceeds 64 KiB"));
        }
        tx.put(
            &self.rows,
            key.clone(),
            self.seal_backup_record(&key, &event)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        for key in [index, latest_key(&backup.digest)] {
            tx.put(
                &self.rows,
                key.clone(),
                self.seal_backup_record(&key, &receipt)
                    .map_err(storage_error)?,
            )
            .map_err(storage_error)?;
        }
        head.artifacts = Some(receipt);
        tx.put(
            &self.rows,
            HEAD.to_vec(),
            self.seal_backup_record(HEAD, &head)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        #[cfg(test)]
        BEFORE_ARTIFACT_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        crate::require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        #[cfg(test)]
        AFTER_ARTIFACT_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        Ok(event.progress())
    }

    fn compare_artifact_prefix<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        contents: &NativeBackupContentsInventory,
        bytes: &[u8],
        through: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for page in 0..through {
            let actual = self.read_artifact_chunk(snapshot, contents, page, budget)?;
            let offset = page as usize * CHUNK_BYTES;
            if Some(actual.as_slice()) != bytes.get(offset..(offset + CHUNK_BYTES).min(bytes.len()))
            {
                return Err(integrity(
                    "retained archive prefix differs from verified input",
                ));
            }
        }
        Ok(())
    }
}
