use super::*;

impl NativeCustodyKeys {
    pub(in crate::encryption::keys::backups) fn walk_backup_artifacts<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        head: &Head,
        expected: &mut BTreeSet<Vec<u8>>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<String, ArtifactState>> {
        let mut states: BTreeMap<String, ArtifactState> = BTreeMap::new();
        let mut previous = None;
        let end = head
            .artifacts
            .as_ref()
            .map_or(0, |receipt| receipt.sequence);
        for sequence in 1..=end {
            let key = event_key(sequence);
            let event: ArtifactEvent = self.read_artifact_record(snapshot, &key, budget)?;
            let receipt = event.receipt();
            receipt.validate(self).map_err(storage_error)?;
            let size = event.contents.registration.encoded_bytes;
            let total_pages = size.div_ceil(CHUNK_BYTES as u64);
            if event.sequence != sequence
                || event.previous != previous
                || size == 0
                || size > crate::backup::MAX_BACKUP_BYTES as u64
                || !(1..=MAX_BATCH_PAGES).contains(&event.requested_pages)
                || u64::from(event.from) >= total_pages
                || u64::from(event.through)
                    != (u64::from(event.from) + u64::from(event.requested_pages)).min(total_pages)
                || event.digest != event.commitment()?
            {
                return Err(integrity("archive artifact journal shape or chain differs"));
            }
            let actual = self.find_contents(snapshot, &receipt.archive_digest, budget)?;
            if actual.as_ref().map(|value| value.inventory()).as_ref() != Some(&event.contents) {
                return Err(integrity(
                    "retained archive lost its complete issued membership",
                ));
            }
            let indexed: NativeBackupArtifactReceipt = self.read_artifact_record(
                snapshot,
                &index_key(&receipt.archive_digest, event.from),
                budget,
            )?;
            if indexed != receipt || (sequence == end && head.artifacts.as_ref() != Some(&receipt))
            {
                return Err(integrity("archive artifact index or terminal differs"));
            }
            let state = if let Some(state) = states.get_mut(&receipt.archive_digest) {
                if event.prior.as_ref() != Some(&state.progress.receipt)
                    || event.contents != state.progress.contents
                    || event.from != state.progress.stored_pages
                {
                    return Err(integrity(
                        "archive artifact prefix changes accepted progress",
                    ));
                }
                state
            } else {
                if event.prior.is_some() || event.from != 0 {
                    return Err(integrity("archive artifact lacks its initial prefix"));
                }
                states
                    .entry(receipt.archive_digest.clone())
                    .or_insert(ArtifactState {
                        progress: event.progress(),
                        chain: genesis(&event.contents)?,
                        hash: blake3::Hasher::new(),
                    })
            };
            for page in event.from..event.through {
                let bytes = self.read_artifact_chunk(snapshot, &event.contents, page, budget)?;
                state.chain = append_chunk(&state.chain, page, &bytes)?;
                state.hash.update(&bytes);
                if !expected.insert(chunk_key(&receipt.archive_digest, page)) {
                    return Err(integrity("archive artifact overwrites a retained chunk"));
                }
            }
            state.progress = event.progress();
            if state.chain != event.chain
                || (state.progress.complete
                    && state.hash.finalize().to_hex().as_str() != receipt.archive_digest)
            {
                return Err(integrity(
                    "archive artifact bytes differ from accepted archive",
                ));
            }
            expected.insert(key);
            expected.insert(index_key(&receipt.archive_digest, event.from));
            previous = Some(receipt.digest);
        }
        for (archive, state) in &states {
            let key = latest_key(archive);
            let latest: NativeBackupArtifactReceipt =
                self.read_artifact_record(snapshot, &key, budget)?;
            if latest != state.progress.receipt {
                return Err(integrity("archive artifact latest progress differs"));
            }
            expected.insert(key);
        }
        budget.check().map_err(budget_error)?;
        Ok(states)
    }

    pub(super) fn read_artifact_record<S: ReadSnapshot, T: serde::de::DeserializeOwned>(
        &self,
        snapshot: &S,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<T> {
        budget.check().map_err(budget_error)?;
        let bytes = snapshot
            .get(&self.rows, key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("archive artifact record is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_HEADER_BYTES + 64 {
            return Err(integrity("archive artifact control exceeds its bound"));
        }
        self.open_backup_record(key, &bytes).map_err(storage_error)
    }

    pub(super) fn read_artifact_chunk<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        contents: &NativeBackupContentsInventory,
        page: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Zeroizing<Vec<u8>>> {
        let offset = u64::from(page) * CHUNK_BYTES as u64;
        let size = contents.registration.encoded_bytes;
        if offset >= size {
            return Err(integrity("archive chunk ordinal exceeds its length"));
        }
        let key = chunk_key(&contents.registration.archive_digest, page);
        budget.check().map_err(budget_error)?;
        let sealed = snapshot
            .get(&self.rows, &key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retained archive chunk is absent"))?;
        budget
            .charge(1, sealed.len() as u64)
            .map_err(budget_error)?;
        if sealed.len() > CHUNK_BYTES + 64 {
            return Err(integrity("retained archive chunk exceeds 256 KiB"));
        }
        let bytes = open(
            &self.master.0,
            &self.backup_aad(&key).map_err(storage_error)?,
            &sealed,
        )
        .map_err(storage_error)?;
        if bytes.len() as u64 != (size - offset).min(CHUNK_BYTES as u64) {
            return Err(integrity("retained archive chunk length differs"));
        }
        Ok(bytes)
    }
}
