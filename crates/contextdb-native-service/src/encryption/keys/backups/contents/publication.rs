use std::collections::BTreeSet;

use contextdb_service::BackupResponse;

use super::*;

impl NativeCustodyKeys {
    // The service validates the exact bounded archive before this call. Copy
    // observations are decoded under this custody guard; no arbitrary JSON ingress.
    pub(crate) fn accept_backup_contents(
        &self,
        archive: &BackupResponse,
        logical_digest: &str,
        copies: impl Iterator<Item = ServiceResult<NativeBackupKeyCopy>>,
        allow_issue: bool,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupContentsInventory> {
        self.require_backup_contents()?;
        valid_digest(&archive.digest).map_err(storage_error)?;
        valid_digest(logical_digest).map_err(storage_error)?;
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        // Validate before staging a fresh registration; corruption cannot be
        // mistaken for a missing sidecar and silently replace an earlier receipt.
        let existing = self.find_contents(&tx, &archive.digest, budget)?;
        if self
            .find_backup(&tx, &archive.digest)
            .map_err(storage_error)?
            .is_none()
        {
            if !allow_issue {
                return Err(invalid(
                    "archive contents backfill requires its original issuance",
                ));
            }
            self.verify_new_issuance(&tx, budget)?;
        }
        let (registration, _) = self
            .stage_backup_registration(
                &mut tx,
                &archive.digest,
                archive.commit_seq,
                logical_digest,
                archive.bytes.len() as u64,
            )
            .map_err(storage_error)?;
        let mut head = self.backup_head(&tx).map_err(storage_error)?;
        let sequence = if let Some(event) = &existing {
            event.sequence
        } else {
            head.contents
                .as_ref()
                .map_or(0, |receipt| receipt.sequence)
                .checked_add(1)
                .ok_or_else(|| crate::exhausted("archive contents sequence exhausted"))?
        };
        let mut previous = contents_genesis(&registration).map_err(storage_error)?;
        let mut addresses = BTreeSet::new();
        let mut pending = Vec::with_capacity(PAGE_ROWS);
        let mut pages = 0;
        for copy in copies {
            let copy = copy?;
            copy.validate().map_err(storage_error)?;
            budget
                .charge(1, encode(&copy).map_err(storage_error)?.len() as u64)
                .map_err(budget_error)?;
            if !addresses.insert(copy.address_digest.clone()) {
                return Err(integrity("archive contains repeated row ownership"));
            }
            if addresses.len() > crate::backup::MAX_BACKUP_ENTRIES {
                return Err(crate::exhausted("archive contents row limit exceeded"));
            }
            pending.push(copy);
            if pending.len() == PAGE_ROWS {
                previous = self.stage_copy_page(
                    &mut tx,
                    sequence,
                    pages,
                    CopyPage {
                        previous,
                        digest: String::new(),
                        copies: std::mem::take(&mut pending),
                    },
                    existing.as_ref(),
                    budget,
                )?;
                pages += 1;
            }
        }
        if !pending.is_empty() {
            previous = self.stage_copy_page(
                &mut tx,
                sequence,
                pages,
                CopyPage {
                    previous,
                    digest: String::new(),
                    copies: pending,
                },
                existing.as_ref(),
                budget,
            )?;
            pages += 1;
        }
        if let Some(event) = existing {
            if event.registration != registration
                || event.pages != pages
                || event.rows != addresses.len() as u64
                || event.contents_digest != previous
            {
                return Err(integrity(
                    "archive contents retry changed complete membership",
                ));
            }
            budget.check().map_err(budget_error)?;
            return Ok(event.inventory());
        }
        let mut event = ContentsEvent {
            sequence,
            previous: head.contents.as_ref().map(|receipt| receipt.digest.clone()),
            registration,
            rows: addresses.len() as u64,
            pages,
            contents_digest: previous,
            digest: String::new(),
        };
        event.digest = event.commitment().map_err(storage_error)?;
        let receipt = event.receipt();
        let event_key = event_key(sequence);
        let index_key = index_key(&archive.digest);
        tx.put(
            &self.rows,
            event_key.clone(),
            self.seal_backup_record(&event_key, &event)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.rows,
            index_key.clone(),
            self.seal_backup_record(&index_key, &receipt)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        head.contents = Some(receipt);
        tx.put(
            &self.rows,
            HEAD.to_vec(),
            self.seal_backup_record(HEAD, &head)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        crate::require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(event.inventory())
    }

    fn stage_copy_page<T: WriteTransaction>(
        &self,
        tx: &mut T,
        sequence: u64,
        page: u32,
        mut stored: CopyPage,
        existing: Option<&ContentsEvent>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<String> {
        stored.digest = stored.commitment(page).map_err(storage_error)?;
        let encoded = encode(&stored).map_err(storage_error)?;
        budget
            .charge(1, encoded.len() as u64)
            .map_err(budget_error)?;
        if encoded.len() > MAX_PAGE_BYTES {
            return Err(crate::exhausted("archive copy page exceeds 256 KiB"));
        }
        if let Some(event) = existing {
            if self.read_copy_page(tx, event, page, budget)? != stored {
                return Err(integrity("archive contents retry page differs"));
            }
        } else {
            let key = page_key(sequence, page);
            tx.put(
                &self.rows,
                key.clone(),
                self.seal_backup_record(&key, &stored)
                    .map_err(storage_error)?,
            )
            .map_err(storage_error)?;
        }
        Ok(stored.digest)
    }
}
