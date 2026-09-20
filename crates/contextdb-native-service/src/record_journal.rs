//! Accepted record mutations for the pre-existing native graph/memory API.
//! The original hash-only prefix stays readable; every new record write retains
//! its actual logical bytes, including closures and incident-edge changes.

use super::*;

pub(crate) mod controls;
pub(crate) use controls::CONTROL_FEATURE;
pub use controls::preparation::NativeRecordControlPreparationReceipt;

pub(super) const RECORD_FEATURE: &str = "continuous-record-mutations-v1";
const ACTIVATED: &[u8] = b"semantic/activated";
pub(super) const MAX_WRITES: usize = 1024;
pub(super) const MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordMutationRef {
    pub(crate) key: Vec<u8>,
    pub(crate) digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) control_digest: Option<String>,
}

impl NativeService {
    pub(super) fn journal_record<T: WriteTransaction>(
        &self,
        tx: &mut T,
        record: &MemoryRecord,
    ) -> ServiceResult<()> {
        let commit = record.transaction_to.unwrap_or(record.transaction_from);
        if tx
            .get(&self.keyspaces.continuous, ACTIVATED)
            .map_err(storage_error)?
            .is_none()
        {
            let mut manifest = self.raw_manifest(tx)?;
            manifest.features.insert(RECORD_FEATURE.into());
            manifest.checksum = manifest_checksum(&manifest)?;
            tx.put(
                &self.keyspaces.meta,
                META_MANIFEST_KEY.to_vec(),
                encode(&manifest)?,
            )
            .map_err(storage_error)?;
            tx.put(
                &self.keyspaces.continuous,
                ACTIVATED.to_vec(),
                encode(&commit)?,
            )
            .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            mutation_key(commit, record),
            encode(record)?,
        )
        .map_err(storage_error)
    }

    pub(super) fn accepted_record_mutations<T: WriteTransaction>(
        &self,
        tx: &mut T,
        frame: &CommitFrame,
    ) -> ServiceResult<Vec<RecordMutationRef>> {
        let prefix = mutation_prefix(frame.global_commit);
        let page = tx
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: MAX_WRITES + 1,
                    max_bytes: MAX_BYTES,
                },
            )
            .map_err(storage_error)?;
        if page.entries.len() > MAX_WRITES || page.continuation.is_some() {
            return Err(exhausted(
                "native record mutation exceeds the bounded journal batch",
            ));
        }
        let mut result = Vec::new();
        let mut control_bytes = 0usize;
        for entry in page.entries {
            let record: MemoryRecord = decode(&entry.value, "accepted record mutation")?;
            if digest_bytes(record.document.access.workspace_id.as_bytes())
                != frame.workspace_digest
            {
                return Err(integrity("native record mutation crosses workspaces"));
            }
            for scope in &record.document.access.scopes {
                tx.put(
                    &self.keyspaces.continuous,
                    capture::scope_key(&frame.workspace_digest, scope),
                    encode(&frame.state.watermarks.journal)?,
                )
                .map_err(storage_error)?;
            }
            let control_digest =
                self.retain_record_control(tx, frame, &record, &mut control_bytes)?;
            result.push(RecordMutationRef {
                key: entry.key,
                digest: digest_bytes(&entry.value),
                control_digest: Some(control_digest),
            });
        }
        Ok(result)
    }

    pub(super) fn verify_record_mutations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        let activated: Option<u64> = self.raw_value(snapshot, ACTIVATED)?;
        let mut expected_keys = BTreeSet::new();
        let mut latest = BTreeMap::<Vec<u8>, MemoryRecord>::new();
        let control_activation = self.record_control_activation(snapshot)?;
        let mut expected_controls = BTreeSet::new();
        let mut first_control = None;
        let prepared = self.verify_record_control_preparations(snapshot)?;
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if activated.is_some() != manifest.features.contains(RECORD_FEATURE) {
            return Err(integrity("record journal feature and activation disagree"));
        }
        for entry in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&entry.value, "record mutation journal")?;
            let writes_records = owns_record_mutations(&event.operation);
            if !event.accepted_records.is_empty()
                && (!writes_records || activated.is_none_or(|first| first > event.global_commit))
            {
                return Err(integrity(
                    "record mutation reference has an invalid publication owner",
                ));
            }
            if writes_records
                && activated.is_some_and(|first| first <= event.global_commit)
                && event.accepted_records.is_empty()
            {
                return Err(integrity(
                    "semantic journal lost its accepted record payloads",
                ));
            }
            if event.accepted_records.len() > MAX_WRITES {
                return Err(integrity("record journal exceeds its publication bound"));
            }
            for reference in &event.accepted_records {
                let bytes = snapshot
                    .get(&self.keyspaces.continuous, &reference.key)
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("accepted record payload absent"))?;
                let record: MemoryRecord = decode(&bytes, "accepted record mutation")?;
                let policy = policy_for(&record)?;
                validate_stored_policy(&policy)?;
                let control =
                    self.record_mutation_control(snapshot, &event, reference, control_activation)?;
                if control.is_some() {
                    expected_controls.insert(controls::control_key(&reference.key)?);
                    first_control.get_or_insert(event.global_commit);
                }
                if let Some(control) = control.as_ref().or_else(|| prepared.get(&reference.key))
                    && *control != controls::RecordControl::from_record(&record)?
                {
                    return Err(integrity("record control differs from accepted payload"));
                }
                if reference.digest != digest_bytes(&bytes)
                    || mutation_key(event.global_commit, &record) != reference.key
                    || record.transaction_to.unwrap_or(record.transaction_from)
                        != event.global_commit
                    || digest_bytes(record.document.access.workspace_id.as_bytes())
                        != event.workspace_digest
                    || !expected_keys.insert(reference.key.clone())
                {
                    return Err(integrity("accepted record mutation binding invalid"));
                }
                latest.insert(history_key(&policy.record_digest, policy.revision), record);
            }
        }
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"semantic/")
            .map_err(storage_error)?;
        if actual.len() != expected_keys.len() + usize::from(activated.is_some())
            || actual
                .iter()
                .any(|entry| entry.key != ACTIVATED && !expected_keys.contains(&entry.key))
        {
            return Err(integrity(
                "orphaned or missing accepted record journal data",
            ));
        }
        if first_control != control_activation {
            return Err(integrity(
                "record control activation is not its first accepted mutation",
            ));
        }
        self.verify_record_control_keys(snapshot, &expected_controls, control_activation)?;
        for (key, record) in latest {
            let stored: StoredContent = decode(
                &snapshot
                    .get(&self.keyspaces.content_history, &key)
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("journaled record revision absent"))?,
                "journaled record revision",
            )?;
            if record != stored.record {
                return Err(integrity(
                    "record projection differs from accepted mutations",
                ));
            }
        }
        // Reverse closure also catches deletion of an entire accepted-write group.
        for entry in snapshot
            .scan_prefix(&self.keyspaces.content_history, b"")
            .map_err(storage_error)?
        {
            let stored: StoredContent = decode(&entry.value, "record reverse journal closure")?;
            let commit = stored
                .record
                .transaction_to
                .unwrap_or(stored.record.transaction_from);
            if activated.is_some_and(|first| first <= commit)
                && !expected_keys.contains(&mutation_key(commit, &stored.record))
            {
                return Err(integrity(
                    "record revision has no accepted semantic payload",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn record_scope_epochs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<Vec<u8>, u64>> {
        let mut epochs = BTreeMap::<Vec<u8>, u64>::new();
        let control_activation = self.record_control_activation(snapshot)?;
        let prepared = self.verify_record_control_preparations(snapshot)?;
        for entry in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&entry.value, "record scope event")?;
            if let Some(publication) = &event.accepted_record_sources {
                for scope in &publication.scopes {
                    let epoch = epochs
                        .entry(capture::scope_key(&event.workspace_digest, scope))
                        .or_default();
                    *epoch = (*epoch).max(event.workspace_commit);
                }
            }
            if let Some(publication) = &event.accepted_record_write_completion {
                for scope in &publication.scopes {
                    let epoch = epochs
                        .entry(capture::scope_key(&event.workspace_digest, scope))
                        .or_default();
                    *epoch = (*epoch).max(event.workspace_commit);
                }
            }
            for reference in &event.accepted_records {
                let control =
                    self.record_mutation_control(snapshot, &event, reference, control_activation)?;
                if let Some(control) = control.as_ref().or_else(|| prepared.get(&reference.key)) {
                    for scope in &control.policy.access.scopes {
                        let epoch = epochs
                            .entry(capture::scope_key(&event.workspace_digest, scope))
                            .or_default();
                        *epoch = (*epoch).max(event.workspace_commit);
                    }
                    continue;
                }
                let record: MemoryRecord = decode(
                    &snapshot
                        .get(&self.keyspaces.continuous, &reference.key)
                        .map_err(storage_error)?
                        .ok_or_else(|| integrity("accepted scope mutation absent"))?,
                    "record scope payload",
                )?;
                for scope in &record.document.access.scopes {
                    let epoch = epochs
                        .entry(capture::scope_key(&event.workspace_digest, scope))
                        .or_default();
                    *epoch = (*epoch).max(event.workspace_commit);
                }
            }
        }
        Ok(epochs)
    }
}

fn owns_record_mutations(operation: &str) -> bool {
    matches!(
        operation,
        "publish_memory" | "propose_memory" | "correct" | "retract"
    ) || record_sources::writes::is_source_write(operation)
}

fn mutation_prefix(global: u64) -> String {
    format!("semantic/record/{global:020}/")
}
fn mutation_key(global: u64, record: &MemoryRecord) -> Vec<u8> {
    format!(
        "{}{}/{:010}",
        mutation_prefix(global),
        digest_bytes(record.document.id.as_bytes()),
        record.revision
    )
    .into_bytes()
}
