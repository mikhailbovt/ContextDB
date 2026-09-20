//! Retained provenance survives native restore. Version 3 requires a permanent
//! global genesis, so losing the complete registry cannot imply legacy access.

use super::*;

pub(super) const HEAD: &[u8] = b"record-sources/head";
const DOMAIN: &str = "contextdb/retained-record-sources/v1";
const MAX_CONTROL_BYTES: usize = 256 * 1024;
const MAX_PAGE_BYTES: usize = 384 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordSourcesCheckpoint {
    pub epoch: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordSourceControl {
    pub workspace: String,
    pub record_digest: String,
    pub revision: u32,
    pub transaction_from: u64,
    pub birth_digest: String,
    pub document_digest: String,
    pub scopes: BTreeSet<String>,
    pub sources: BTreeMap<ObservationId, ContentDigest>,
}

impl RecordSourceControl {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        validate_control(self)
    }
}

// The untagged record variant preserves the exact existing v3 binding bytes.
// Registration is a distinct control, never a fictitious record with no origins.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum RecordSourceDeclaration {
    Record(RecordSourceControl),
    Workspace(RecordSourceWorkspace),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordSourceWorkspace {
    workspace: String,
    registration: bool,
}

impl RecordSourceDeclaration {
    pub(crate) fn workspace(&self) -> &str {
        match self {
            Self::Record(control) => &control.workspace,
            Self::Workspace(control) => &control.workspace,
        }
    }

    pub(crate) fn record(&self) -> Option<&RecordSourceControl> {
        match self {
            Self::Record(control) => Some(control),
            Self::Workspace(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordSourceEntry {
    pub global_sequence: u64,
    pub previous_global: String,
    pub previous: RecordSourcesCheckpoint,
    pub checkpoint: RecordSourcesCheckpoint,
    pub control: RecordSourceDeclaration,
}

impl RecordSourceEntry {
    pub(crate) fn record_control(&self) -> ServiceResult<&RecordSourceControl> {
        self.control
            .record()
            .ok_or_else(|| integrity("record locator points to workspace registration"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    sequence: u64,
    digest: String,
    workspaces: BTreeMap<String, RecordSourcesCheckpoint>,
    checksum: String,
}

pub(super) fn genesis(identity: &Identity) -> ServiceResult<Head> {
    let mut head = Head {
        sequence: 0,
        digest: canonical_digest(&(DOMAIN, identity))?,
        workspaces: BTreeMap::new(),
        checksum: String::new(),
    };
    head.checksum = head_checksum(identity, &head)?;
    Ok(head)
}

fn head_checksum(identity: &Identity, head: &Head) -> ServiceResult<String> {
    canonical_digest(&(
        DOMAIN,
        "head",
        identity,
        head.sequence,
        &head.digest,
        &head.workspaces,
    ))
}

impl NativeSuppressionLedger {
    pub(crate) fn supports_record_sources(&self) -> bool {
        self.identity.version >= 3
    }

    pub(crate) fn record_sources_genesis(
        &self,
        workspace: &str,
    ) -> ServiceResult<RecordSourcesCheckpoint> {
        Ok(RecordSourcesCheckpoint {
            epoch: 0,
            digest: canonical_digest(&(DOMAIN, &self.identity, workspace))?,
        })
    }

    fn record_sources_head<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<Head> {
        if !self.supports_record_sources() {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "record provenance requires explicit migration to a version 3 retained authority",
                false,
            ));
        }
        let head: Head = decode(
            &snapshot
                .get(&self.rows, HEAD)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("retained record source genesis is absent"))?,
            "record source head",
        )?;
        if head.workspaces.len() > 1024
            || head.checksum != head_checksum(&self.identity, &head)?
            || (head.sequence == 0 && head != genesis(&self.identity)?)
            || (head.sequence > 0 && head.workspaces.is_empty())
        {
            return Err(integrity("retained record source head is invalid"));
        }
        Ok(head)
    }

    pub(crate) fn current_record_sources(
        &self,
        workspace: &str,
    ) -> ServiceResult<Option<RecordSourcesCheckpoint>> {
        if !self.supports_record_sources() {
            return Ok(None);
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        Ok(self
            .record_sources_head(&snapshot)?
            .workspaces
            .get(workspace)
            .cloned())
    }

    fn read_record_source_entry<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        sequence: u64,
    ) -> ServiceResult<RecordSourceEntry> {
        let entry: RecordSourceEntry = decode(
            &snapshot
                .get(&self.rows, &entry_key(sequence))
                .map_err(storage_error)?
                .ok_or_else(|| integrity("retained record source entry absent"))?,
            "record source entry",
        )?;
        match &entry.control {
            RecordSourceDeclaration::Record(control) => validate_control(control)?,
            RecordSourceDeclaration::Workspace(control) => {
                if !control.registration
                    || blake3::Hash::from_hex(&control.workspace).is_err()
                    || entry.previous != self.record_sources_genesis(&control.workspace)?
                {
                    return Err(integrity("record workspace registration is invalid"));
                }
            }
        }
        if sequence == 0
            || entry.global_sequence != sequence
            || entry.checkpoint.epoch
                != entry
                    .previous
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| integrity("record source epoch overflow"))?
            || entry.checkpoint.digest != entry_digest(&self.identity, &entry)?
        {
            return Err(integrity("retained record source entry binding differs"));
        }
        Ok(entry)
    }

    pub(crate) fn retained_record_sources(
        &self,
        workspace: &str,
        record: &str,
        revision: u32,
    ) -> ServiceResult<Option<RecordSourceEntry>> {
        if !self.supports_record_sources() {
            return Ok(None);
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.record_sources_head(&snapshot)?;
        let Some(bytes) = snapshot
            .get(&self.rows, &record_key(workspace, record, revision))
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let sequence: u64 = decode(&bytes, "record source locator")?;
        let entry = self.read_record_source_entry(&snapshot, sequence)?;
        let control = entry.record_control()?;
        if sequence > head.sequence
            || control.workspace != workspace
            || control.record_digest != record
            || control.revision != revision
            || head
                .workspaces
                .get(workspace)
                .is_none_or(|cp| cp.epoch < entry.checkpoint.epoch)
        {
            return Err(integrity(
                "record source locator points to another declaration",
            ));
        }
        Ok(Some(entry))
    }

    pub(crate) fn record_identity_retained(
        &self,
        workspace: &str,
        record: &str,
    ) -> ServiceResult<bool> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.record_sources_head(&snapshot)?;
        let prefix = format!("record-sources/record/{workspace}/{record}/");
        let page = snapshot
            .scan_prefix_page(
                &self.rows,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: 1,
                    max_bytes: 1024,
                },
            )
            .map_err(storage_error)?;
        let Some(row) = page.entries.first() else {
            return Ok(false);
        };
        let sequence: u64 = decode(&row.value, "retained record identity locator")?;
        let entry = self.read_record_source_entry(&snapshot, sequence)?;
        let control = entry.record_control()?;
        if row.key != record_key(workspace, record, control.revision)
            || self
                .retained_record_sources(workspace, record, control.revision)?
                .as_ref()
                != Some(&entry)
        {
            return Err(integrity("retained record identity locator differs"));
        }
        Ok(true)
    }

    pub(crate) fn bind_record_origin(
        &self,
        control: &RecordSourceControl,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RecordSourceEntry> {
        validate_control(control)?;
        budget
            .charge(1, encode(control)?.len() as u64)
            .map_err(budget_error)?;
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let mut head = self.record_sources_head(&tx)?;
        let key = record_key(&control.workspace, &control.record_digest, control.revision);
        if let Some(bytes) = tx.get(&self.rows, &key).map_err(storage_error)? {
            let entry =
                self.read_record_source_entry(&tx, decode(&bytes, "record source retry")?)?;
            if entry.record_control()? != control {
                return Err(invalid(
                    "record revision already has a different retained source declaration",
                ));
            }
            return Ok(entry);
        }
        if head.workspaces.len() >= 1024 && !head.workspaces.contains_key(&control.workspace) {
            return Err(exhausted("retained record source workspace bound exceeded"));
        }
        let previous = head
            .workspaces
            .get(&control.workspace)
            .cloned()
            .unwrap_or(self.record_sources_genesis(&control.workspace)?);
        let mut entry = RecordSourceEntry {
            global_sequence: head
                .sequence
                .checked_add(1)
                .ok_or_else(|| exhausted("record source journal exhausted"))?,
            previous_global: head.digest,
            checkpoint: RecordSourcesCheckpoint {
                epoch: previous
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| exhausted("record source epoch exhausted"))?,
                digest: String::new(),
            },
            previous,
            control: RecordSourceDeclaration::Record(control.clone()),
        };
        entry.checkpoint.digest = entry_digest(&self.identity, &entry)?;
        head.sequence = entry.global_sequence;
        head.digest = entry.checkpoint.digest.clone();
        head.workspaces
            .insert(control.workspace.clone(), entry.checkpoint.clone());
        head.checksum = head_checksum(&self.identity, &head)?;
        tx.put(
            &self.rows,
            entry_key(entry.global_sequence),
            encode(&entry)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.rows,
            workspace_key(&control.workspace, entry.checkpoint.epoch),
            encode(&entry.global_sequence)?,
        )
        .map_err(storage_error)?;
        tx.put(&self.rows, key, encode(&entry.global_sequence)?)
            .map_err(storage_error)?;
        tx.put(&self.rows, HEAD.to_vec(), encode(&head)?)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(entry)
    }

    pub(crate) fn register_record_sources_workspace(
        &self,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RecordSourcesCheckpoint> {
        if blake3::Hash::from_hex(workspace).is_err() {
            return Err(invalid("record source workspace digest invalid"));
        }
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let mut head = self.record_sources_head(&tx)?;
        if head.workspaces.contains_key(workspace) {
            let sequence: u64 = decode(
                &tx.get(&self.rows, &workspace_key(workspace, 1))
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("record workspace first entry absent"))?,
                "record workspace registration",
            )?;
            let first = self.read_record_source_entry(&tx, sequence)?;
            if first.control.workspace() != workspace
                || first.checkpoint.epoch != 1
                || first.previous != self.record_sources_genesis(workspace)?
                || sequence > head.sequence
            {
                return Err(integrity("record workspace registration points elsewhere"));
            }
            budget
                .charge(1, encode(&first)?.len() as u64)
                .map_err(budget_error)?;
            return Ok(first.checkpoint);
        }
        if head.workspaces.len() >= 1024 {
            return Err(exhausted("retained record source workspace bound exceeded"));
        }
        let mut entry = RecordSourceEntry {
            global_sequence: head
                .sequence
                .checked_add(1)
                .ok_or_else(|| exhausted("record source journal exhausted"))?,
            previous_global: head.digest,
            previous: self.record_sources_genesis(workspace)?,
            checkpoint: RecordSourcesCheckpoint {
                epoch: 1,
                digest: String::new(),
            },
            control: RecordSourceDeclaration::Workspace(RecordSourceWorkspace {
                workspace: workspace.to_owned(),
                registration: true,
            }),
        };
        entry.checkpoint.digest = entry_digest(&self.identity, &entry)?;
        head.sequence = entry.global_sequence;
        head.digest = entry.checkpoint.digest.clone();
        head.workspaces
            .insert(workspace.to_owned(), entry.checkpoint.clone());
        head.checksum = head_checksum(&self.identity, &head)?;
        let encoded = encode(&entry)?;
        budget
            .charge(1, encoded.len() as u64)
            .map_err(budget_error)?;
        tx.put(&self.rows, entry_key(entry.global_sequence), encoded)
            .map_err(storage_error)?;
        tx.put(
            &self.rows,
            workspace_key(workspace, 1),
            encode(&entry.global_sequence)?,
        )
        .map_err(storage_error)?;
        tx.put(&self.rows, HEAD.to_vec(), encode(&head)?)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(entry.checkpoint)
    }

    pub(crate) fn record_sources_batch(
        &self,
        workspace: &str,
        after: &RecordSourcesCheckpoint,
        limit: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<RecordSourceEntry>> {
        if !(1..=256).contains(&limit) {
            return Err(invalid("record source page requires 1..256 entries"));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.record_sources_head(&snapshot)?;
        let current = head
            .workspaces
            .get(workspace)
            .cloned()
            .unwrap_or(self.record_sources_genesis(workspace)?);
        if after.epoch > current.epoch
            || (after.epoch == 0 && *after != self.record_sources_genesis(workspace)?)
        {
            return Err(integrity("record source applied epoch is invalid"));
        }
        let mut previous = after.clone();
        let mut entries = Vec::new();
        let mut page_bytes = 0;
        for epoch in after.epoch.saturating_add(1)
            ..=current.epoch.min(after.epoch.saturating_add(limit as u64))
        {
            let sequence: u64 = decode(
                &snapshot
                    .get(&self.rows, &workspace_key(workspace, epoch))
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("record source workspace page absent"))?,
                "record source workspace page",
            )?;
            let entry = self.read_record_source_entry(&snapshot, sequence)?;
            let entry_bytes = encode(&entry)?.len();
            if !entries.is_empty() && page_bytes + entry_bytes > MAX_PAGE_BYTES {
                break;
            }
            budget.charge(1, entry_bytes as u64).map_err(budget_error)?;
            if entry.control.workspace() != workspace
                || entry.checkpoint.epoch != epoch
                || entry.previous != previous
                || sequence > head.sequence
            {
                return Err(integrity("record source workspace chain skips an entry"));
            }
            previous = entry.checkpoint.clone();
            page_bytes += entry_bytes;
            entries.push(entry);
        }
        if previous.epoch == current.epoch && previous != current {
            return Err(integrity("record source page terminal differs"));
        }
        Ok(entries)
    }

    pub(super) fn verify_record_source_ledger<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> ServiceResult<()> {
        if !self.supports_record_sources() {
            return Ok(());
        }
        let head = self.record_sources_head(snapshot)?;
        let mut calculated = genesis(&self.identity)?;
        for sequence in 1..=head.sequence {
            let entry = self.read_record_source_entry(snapshot, sequence)?;
            let workspace = entry.control.workspace().to_owned();
            let previous = calculated
                .workspaces
                .get(&workspace)
                .cloned()
                .unwrap_or(self.record_sources_genesis(&workspace)?);
            if entry.previous_global != calculated.digest || entry.previous != previous {
                return Err(integrity("record source workspace journal forks"));
            }
            if let Some(control) = entry.control.record()
                && expected
                    .insert(
                        record_key(&workspace, &control.record_digest, control.revision),
                        encode(&sequence)?,
                    )
                    .is_some()
            {
                return Err(integrity(
                    "record source journal forks or repeats a revision",
                ));
            }
            expected.insert(entry_key(sequence), encode(&entry)?);
            expected.insert(
                workspace_key(&workspace, entry.checkpoint.epoch),
                encode(&sequence)?,
            );
            calculated.sequence = sequence;
            calculated.digest = entry.checkpoint.digest.clone();
            calculated.workspaces.insert(workspace, entry.checkpoint);
        }
        calculated.checksum = head_checksum(&self.identity, &calculated)?;
        if calculated != head {
            return Err(integrity(
                "record source terminal or workspace index differs",
            ));
        }
        expected.insert(HEAD.to_vec(), encode(&head)?);
        Ok(())
    }
}

fn validate_control(control: &RecordSourceControl) -> ServiceResult<()> {
    for digest in [
        &control.workspace,
        &control.record_digest,
        &control.birth_digest,
        &control.document_digest,
    ] {
        if blake3::Hash::from_hex(digest).is_err() {
            return Err(integrity("record source digest invalid"));
        }
    }
    if control.revision == 0
        || control.transaction_from == 0
        || !(1..=64).contains(&control.sources.len())
        || control.scopes.len() > MAX_POLICY_VALUES
        || encode(control)?.len() > MAX_CONTROL_BYTES
    {
        return Err(invalid(
            "record source declaration exceeds its bounded profile",
        ));
    }
    for scope in &control.scopes {
        validate_identifier(scope, "record source scope")?;
    }
    Ok(())
}
fn entry_digest(identity: &Identity, entry: &RecordSourceEntry) -> ServiceResult<String> {
    canonical_digest(&(
        DOMAIN,
        identity,
        entry.global_sequence,
        &entry.previous_global,
        &entry.previous,
        entry.checkpoint.epoch,
        &entry.control,
    ))
}
fn entry_key(sequence: u64) -> Vec<u8> {
    format!("record-sources/event/{sequence:020}").into_bytes()
}
fn record_key(workspace: &str, record: &str, revision: u32) -> Vec<u8> {
    format!("record-sources/record/{workspace}/{record}/{revision:010}").into_bytes()
}
fn workspace_key(workspace: &str, epoch: u64) -> Vec<u8> {
    format!("record-sources/workspace/{workspace}/{epoch:020}").into_bytes()
}

#[cfg(test)]
mod tests;
