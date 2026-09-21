//! Complete archive coverage for keys selected by independently verified ownership.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[cfg(test)]
mod tests;

/// Archive histories and current refusal at one custody inspection. Backfill,
/// replacement acceptance and key retirement change this frontier even when no
/// new archive is issued.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupFrontier {
    /// Current independent custody authority.
    pub authority_id: Uuid,
    /// Complete issuance frontier, independent of native and allocation sequences.
    pub issued_sequence: u64,
    /// Last issued archive, absent only before any issuance.
    pub issued_digest: Option<String>,
    /// Last accepted complete membership, including later backfills.
    pub contents: Option<NativeBackupContentsReceipt>,
    /// Latest independently accepted replacement provenance, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacements: Option<NativeBackupReplacementReceipt>,
    /// Latest retained archive-byte progress, including incomplete artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<NativeBackupArtifactReceipt>,
    /// Current key refusal at this inspection, independent of archive issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirements: Option<NativeKeyRetirementReceipt>,
}

/// One issued archive's relation to the selected key allocations. An empty copy
/// list establishes absence of selected keys only within an archive whose contents
/// are present. It establishes neither physical absence nor absence of other keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupKeyArchive {
    /// Original, independently retained issuance.
    pub registration: NativeBackupRegistration,
    /// Complete verified membership. None leaves this entire archive unknown.
    pub contents: Option<NativeBackupContentsInventory>,
    /// Exact copies using selected keys, in the archive's original row order.
    /// They need not appear in a selected native-use history; no instance is inferred.
    pub copies: Vec<NativeBackupKeyCopy>,
    /// Actual independently retained archive bytes; absence is not availability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<NativeBackupArtifactProgress>,
    /// Every key in complete membership is currently usable, including unselected
    /// data. False for unknown membership or any retired key. This is bound to the
    /// enclosing refusal frontier, not a guarantee about physical archive copies.
    #[serde(default)]
    pub keys_available: bool,
}

/// Complete issued-archive coverage at one immutable frontier. No archive bytes,
/// decryption material, physical-copy count or destruction evidence is returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupKeyInventory {
    /// Verified histories; future publication must recheck this frontier.
    pub frontier: NativeBackupFrontier,
    /// Every issued archive, including unknown legacy contents and no-match archives.
    pub archives: Vec<NativeBackupKeyArchive>,
}

impl Head {
    fn frontier(
        &self,
        authority_id: Uuid,
        retirements: Option<NativeKeyRetirementReceipt>,
    ) -> NativeBackupFrontier {
        NativeBackupFrontier {
            authority_id,
            issued_sequence: self.sequence,
            issued_digest: self.digest.clone(),
            contents: self.contents.clone(),
            replacements: self.replacements.clone(),
            artifacts: self.artifacts.clone(),
            retirements,
        }
    }
}

impl NativeCustodyKeys {
    // The caller holds custody publication authority and already verified the
    // complete archive catalog/frontier. Check every target row, including keys
    // outside the selected removal family: retained bytes alone are not readable
    // preservation if another accepted retirement made their keys unavailable.
    pub(crate) fn require_backup_available_keys<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        targets: &BTreeSet<String>,
        retiring: &BTreeSet<Uuid>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for target in targets {
            let contents = self
                .find_contents(snapshot, target, budget)?
                .ok_or_else(|| integrity("preservation target membership is absent"))?;
            for page in 0..contents.pages {
                let copy_page = self.read_copy_page(snapshot, &contents, page, budget)?;
                for copy in copy_page.copies {
                    budget.charge(1, 0).map_err(budget_error)?;
                    if retiring.contains(&copy.version.key_id) {
                        return Err(invalid("preservation target still uses a selected key"));
                    }
                    drop(self.admit_key(copy.version.key_id).map_err(storage_error)?);
                }
            }
        }
        Ok(())
    }

    // Selection comes only from the service's authorized, fully verified key
    // inventories. In particular, an address alone does not select other keys.
    #[cfg(test)]
    pub(crate) fn selected_backup_keys(
        &self,
        selected: &BTreeMap<Uuid, String>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupKeyInventory> {
        self.require_backup_contents()?;
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.selected_backup_keys_at(&snapshot, selected, budget)
    }

    pub(crate) fn selected_backup_keys_for_request(
        &self,
        selected: &BTreeMap<Uuid, String>,
        workspace: &str,
        request: &crate::NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(NativeBackupKeyInventory, Vec<NativeBackupReplacement>)> {
        self.require_backup_contents()?;
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.select_backup_keys_at(&snapshot, selected, Some((workspace, request)), budget)
    }

    pub(in crate::encryption::keys::backups) fn selected_backup_keys_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        selected: &BTreeMap<Uuid, String>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupKeyInventory> {
        self.select_backup_keys_at(snapshot, selected, None, budget)
            .map(|(inventory, _)| inventory)
    }

    fn select_backup_keys_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        selected: &BTreeMap<Uuid, String>,
        request: Option<(&str, &crate::NativeRemovalRequestReceipt)>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(NativeBackupKeyInventory, Vec<NativeBackupReplacement>)> {
        // Keep the classification coherent while walking all memberships. The
        // caller rechecks this frontier under custody publication before use.
        let retired = self.current_retirements().map_err(storage_error)?;
        let head = self.backup_head(snapshot).map_err(storage_error)?;
        budget
            .charge(1, encode(&head).map_err(storage_error)?.len() as u64)
            .map_err(budget_error)?;
        let mut expected = BTreeSet::from([HEAD.to_vec()]);
        let mut archives = BTreeMap::new();
        let mut report_bytes = 0;
        self.walk_issuance(snapshot, budget, |entry, budget| {
            expected.insert(issued_key(entry.sequence));
            expected.insert(super::super::index_key(&entry.archive_digest));
            reserve(&mut report_bytes, entry, budget)?;
            archives.insert(
                entry.sequence,
                NativeBackupKeyArchive {
                    registration: entry.clone(),
                    contents: None,
                    copies: Vec::new(),
                    artifact: None,
                    keys_available: false,
                },
            );
            Ok(())
        })?;
        self.walk_contents_events(snapshot, &head, budget, |event, budget| {
            let archive = archives
                .get_mut(&event.registration.sequence)
                .ok_or_else(|| integrity("archive membership has no issued catalog entry"))?;
            if archive.registration != event.registration || archive.contents.is_some() {
                return Err(integrity("archive membership issuance differs"));
            }
            let inventory = event.inventory();
            reserve(&mut report_bytes, &inventory, budget)?;
            archive.contents = Some(inventory);
            archive.keys_available = true;
            expected.insert(event_key(event.sequence));
            expected.insert(index_key(&event.registration.archive_digest));
            let mut previous = contents_genesis(&event.registration).map_err(storage_error)?;
            let mut addresses = BTreeSet::new();
            for page in 0..event.pages {
                let stored = self.read_copy_page(snapshot, event, page, budget)?;
                if stored.previous != previous {
                    return Err(integrity("archive key inventory page chain differs"));
                }
                for copy in stored.copies {
                    if !addresses.insert(copy.address_digest.clone()) {
                        return Err(integrity("archive key inventory repeats an address"));
                    }
                    archive.keys_available &= !retired.contains(copy.version.key_id);
                    if let Some(address) = selected.get(&copy.version.key_id) {
                        if address != &copy.address_digest {
                            return Err(integrity(
                                "archived key belongs to another selected address",
                            ));
                        }
                        reserve(&mut report_bytes, &copy, budget)?;
                        archive.copies.push(copy);
                    }
                }
                previous = stored.digest;
                expected.insert(page_key(event.sequence, page));
            }
            if previous != event.contents_digest || addresses.len() as u64 != event.rows {
                return Err(integrity("archive key inventory coverage is incomplete"));
            }
            Ok(())
        })?;
        let mut replacements = Vec::new();
        self.walk_backup_replacements(snapshot, &head, budget, |event, budget| {
            event.add_expected_keys(&mut expected);
            if request.is_some_and(|(workspace, request)| {
                event.value.workspace_digest == workspace
                    && event.value.request.authority_id == request.authority_id
            }) {
                reserve(&mut report_bytes, &event.value, budget)?;
                replacements.push(event.value.clone());
            }
            Ok(())
        })?;
        for (_, state) in self.walk_backup_artifacts(snapshot, &head, &mut expected, budget)? {
            let archive = archives
                .get_mut(&state.progress.contents.registration.sequence)
                .ok_or_else(|| integrity("retained artifact has no issuance"))?;
            reserve(&mut report_bytes, &state.progress, budget)?;
            archive.artifact = Some(state.progress);
        }
        // Reverse closure includes unknown legacy archives: orphan pages or
        // locators cannot silently turn lost accepted contents into unknown.
        let mut after = None;
        loop {
            budget.check().map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.rows,
                    ScanPageRequest {
                        prefix: b"backup/",
                        start_after: after.as_deref(),
                        max_entries: 256,
                        max_bytes: 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in &page.entries {
                budget
                    .charge(1, (row.key.len() + row.value.len()) as u64)
                    .map_err(budget_error)?;
                if !expected.remove(&row.key) {
                    return Err(integrity(
                        "archive key inventory has undeclared custody rows",
                    ));
                }
            }
            let Some(next) = page.continuation else { break };
            after = Some(next);
        }
        if !expected.is_empty() {
            return Err(integrity(
                "archive key inventory lost accepted custody rows",
            ));
        }
        let report = NativeBackupKeyInventory {
            frontier: head.frontier(self.authority_id(), retired.frontier()),
            archives: archives.into_values().collect(),
        };
        crate::retention::keys::charge_report(&report, budget)?;
        Ok((report, replacements))
    }

    // Caller holds the same custody publication guard as native and archive
    // writers. Issuance alone misses backfill, byte retention and key retirement.
    pub(crate) fn require_backup_frontier(
        &self,
        expected: &NativeBackupFrontier,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.backup_head(&snapshot).map_err(storage_error)?;
        budget
            .charge(1, encode(&head).map_err(storage_error)?.len() as u64)
            .map_err(budget_error)?;
        let retired = self.retirement_frontier().map_err(storage_error)?;
        if head.frontier(self.authority_id(), retired) != *expected {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "archive custody frontier changed; restart inventory",
                true,
            ));
        }
        Ok(())
    }
}

fn reserve<T: Serialize>(
    total: &mut usize,
    value: &T,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    // Include surrounding field names, optional wrappers and vector delimiters.
    let bytes = encode(value).map_err(storage_error)?.len() + 128;
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| crate::exhausted("archive inventory size overflow"))?;
    if *total > 32 * 1024 * 1024 {
        return Err(crate::exhausted("archive key inventory exceeds 32 MiB"));
    }
    budget.charge(1, bytes as u64).map_err(budget_error)
}
