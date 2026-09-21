use std::collections::BTreeSet;

use super::*;

impl NativeCustodyKeys {
    // An older v4 registration may have no contents sidecar. Missing issuance
    // indices still cannot turn that archive into a fresh, duplicate acceptance.
    pub(super) fn verify_new_issuance<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.walk_issuance(snapshot, budget, |_, _| Ok(()))
    }

    pub(super) fn walk_issuance<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
        mut visit: impl FnMut(&NativeBackupRegistration, &mut QueryBudget) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        let head = self.backup_head(snapshot).map_err(storage_error)?;
        let mut previous = None;
        for sequence in 1..=head.sequence {
            let entry: NativeBackupRegistration = self.read_contents_record(
                snapshot,
                &issued_key(sequence),
                MAX_HEADER_BYTES,
                budget,
            )?;
            if entry.sequence != sequence
                || entry.previous_archive_digest != previous
                || self
                    .find_backup(snapshot, &entry.archive_digest)
                    .map_err(storage_error)?
                    .as_ref()
                    != Some(&entry)
            {
                return Err(integrity(
                    "archive issuance history or lookup is incomplete",
                ));
            }
            budget.charge(1, 0).map_err(budget_error)?;
            visit(&entry, budget)?;
            previous = Some(entry.archive_digest);
        }
        let tail = snapshot
            .scan_prefix_page(
                &self.rows,
                ScanPageRequest {
                    prefix: ISSUED,
                    start_after: Some(&issued_key(head.sequence)),
                    max_entries: 1,
                    max_bytes: MAX_HEADER_BYTES + 64,
                },
            )
            .map_err(storage_error)?;
        for row in &tail.entries {
            budget
                .charge(1, (row.key.len() + row.value.len()) as u64)
                .map_err(budget_error)?;
        }
        if previous != head.digest || !tail.entries.is_empty() || tail.continuation.is_some() {
            return Err(integrity("archive issuance terminal differs"));
        }
        budget.check().map_err(budget_error)
    }

    fn read_contents_record<S: ReadSnapshot, T: serde::de::DeserializeOwned>(
        &self,
        snapshot: &S,
        key: &[u8],
        limit: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<T> {
        budget.check().map_err(budget_error)?;
        let bytes = snapshot
            .get(&self.rows, key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retained archive contents record is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > limit + 64 {
            return Err(integrity("archive contents record exceeds its limit"));
        }
        self.open_backup_record(key, &bytes).map_err(storage_error)
    }

    pub(super) fn walk_contents_events<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        head: &Head,
        budget: &mut QueryBudget,
        mut visit: impl FnMut(&ContentsEvent, &mut QueryBudget) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        let mut previous = None;
        let mut seen = BTreeSet::new();
        let end = head.contents.as_ref().map_or(0, |receipt| receipt.sequence);
        for sequence in 1..=end {
            let event: ContentsEvent = self.read_contents_record(
                snapshot,
                &event_key(sequence),
                MAX_HEADER_BYTES,
                budget,
            )?;
            let expected_pages = event.rows.div_ceil(PAGE_ROWS as u64);
            if event.sequence != sequence
                || event.previous != previous
                || event.rows > crate::backup::MAX_BACKUP_ENTRIES as u64
                || u64::from(event.pages) != expected_pages
                || event.digest != event.commitment().map_err(storage_error)?
                || !seen.insert(event.registration.archive_digest.clone())
            {
                return Err(integrity(
                    "archive contents acceptance chain or shape differs",
                ));
            }
            event.receipt().validate(self).map_err(storage_error)?;
            valid_digest(&event.contents_digest).map_err(storage_error)?;
            let actual = self
                .find_backup(snapshot, &event.registration.archive_digest)
                .map_err(storage_error)?;
            if actual.as_ref() != Some(&event.registration) {
                return Err(integrity("archive contents lost its original issuance"));
            }
            budget
                .charge(
                    1,
                    encode(&event.registration).map_err(storage_error)?.len() as u64,
                )
                .map_err(budget_error)?;
            let indexed: NativeBackupContentsReceipt = self.read_contents_record(
                snapshot,
                &index_key(&event.registration.archive_digest),
                MAX_HEADER_BYTES,
                budget,
            )?;
            if indexed != event.receipt()
                || (sequence == end && head.contents.as_ref() != Some(&indexed))
            {
                return Err(integrity("archive contents index or terminal differs"));
            }
            previous = Some(event.digest.clone());
            visit(&event, budget)?;
        }
        let tail = snapshot
            .scan_prefix_page(
                &self.rows,
                ScanPageRequest {
                    prefix: EVENTS,
                    start_after: Some(&event_key(end)),
                    max_entries: 1,
                    max_bytes: MAX_HEADER_BYTES + 64,
                },
            )
            .map_err(storage_error)?;
        for entry in &tail.entries {
            budget
                .charge(1, (entry.key.len() + entry.value.len()) as u64)
                .map_err(budget_error)?;
        }
        if !tail.entries.is_empty() || tail.continuation.is_some() {
            return Err(integrity(
                "archive contents history exceeds its accepted terminal",
            ));
        }
        budget.check().map_err(budget_error)
    }

    pub(super) fn find_contents<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        digest: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<ContentsEvent>> {
        let head = self.backup_head(snapshot).map_err(storage_error)?;
        budget
            .charge(1, encode(&head).map_err(storage_error)?.len() as u64)
            .map_err(budget_error)?;
        let mut found = None;
        self.walk_contents_events(snapshot, &head, budget, |event, _| {
            if event.registration.archive_digest == digest {
                found = Some(event.clone());
            }
            Ok(())
        })?;
        if found.is_none()
            && snapshot
                .get(&self.rows, &index_key(digest))
                .map_err(storage_error)?
                .is_some()
        {
            return Err(integrity("archive contents locator has no accepted event"));
        }
        Ok(found)
    }

    pub(super) fn read_copy_page<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &ContentsEvent,
        page: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CopyPage> {
        if page >= event.pages {
            return Err(integrity(
                "archive contents page is outside accepted coverage",
            ));
        }
        let stored: CopyPage = self.read_contents_record(
            snapshot,
            &page_key(event.sequence, page),
            MAX_PAGE_BYTES,
            budget,
        )?;
        let rows = (event.rows - u64::from(page) * PAGE_ROWS as u64).min(PAGE_ROWS as u64);
        if stored.copies.len() as u64 != rows
            || stored.digest != stored.commitment(page).map_err(storage_error)?
            || (page + 1 == event.pages && stored.digest != event.contents_digest)
        {
            return Err(integrity(
                "archive contents page count or commitment differs",
            ));
        }
        valid_digest(&stored.previous).map_err(storage_error)?;
        for copy in &stored.copies {
            budget.charge(1, 0).map_err(budget_error)?;
            copy.validate().map_err(storage_error)?;
        }
        Ok(stored)
    }

    pub(in crate::encryption::keys::backups) fn verify_backup_contents<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        head: &Head,
        expected: &mut BTreeSet<Vec<u8>>,
    ) -> contextdb_storage::Result<()> {
        if self.identity.version < 4 {
            return if head.contents.is_none() {
                Ok(())
            } else {
                Err(failure("legacy authority has archive contents"))
            };
        }
        let mut budget = QueryBudget::new(
            u64::MAX,
            u64::MAX,
            std::time::Duration::from_secs(300),
            Default::default(),
        );
        self.walk_contents_events(snapshot, head, &mut budget, |event, budget| {
            expected.insert(event_key(event.sequence));
            expected.insert(index_key(&event.registration.archive_digest));
            let mut previous = contents_genesis(&event.registration).map_err(storage_error)?;
            let mut addresses = BTreeSet::new();
            for page in 0..event.pages {
                let stored = self.read_copy_page(snapshot, event, page, budget)?;
                if stored.previous != previous {
                    return Err(integrity("archive contents page predecessor differs"));
                }
                for copy in &stored.copies {
                    if !addresses.insert(copy.address_digest.clone()) {
                        return Err(integrity("archive contents repeats a row"));
                    }
                }
                previous = stored.digest;
                expected.insert(page_key(event.sequence, page));
            }
            if previous != event.contents_digest || addresses.len() as u64 != event.rows {
                return Err(integrity("archive contents coverage is incomplete"));
            }
            Ok(())
        })
        .map_err(|_| failure("archive contents verification failed"))
    }
}
