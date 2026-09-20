//! Add accepted controls to pre-control journal entries without rewriting history.

use contextdb_recall::QueryBudget;

use super::*;

#[cfg(test)]
mod tests;
mod verify;

pub(crate) const FEATURE: &str = "continuous-record-control-preparation-v1";
const OPERATION: &str = "record_controls_prepare";
const PREFIX: &[u8] = b"record-prepared/";

/// Preparation only: original record bodies and receipts are still required.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordControlPreparationReceipt {
    /// Workspace commit whose complete mutation group was prepared.
    pub record_commit: u64,
    /// Workspace commit that accepted the controls.
    pub prepared_at: u64,
    /// Number of original births and closures, at most 1024.
    pub mutations: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlPreparation {
    source_global: u64,
    source_commit: u64,
    source_event_digest: String,
    workspace_commit: u64,
    controls: Vec<RecordMutationRef>,
}

impl ControlPreparation {
    fn receipt(&self) -> NativeRecordControlPreparationReceipt {
        NativeRecordControlPreparationReceipt {
            record_commit: self.source_commit,
            prepared_at: self.workspace_commit,
            mutations: self.controls.len() as u32,
        }
    }

    fn request_digest(&self, workspace: &str) -> ServiceResult<String> {
        canonical_digest(&(
            FEATURE,
            OPERATION,
            workspace,
            self.source_global,
            self.source_commit,
            &self.source_event_digest,
        ))
    }
}

impl NativeService {
    /// Retain verified controls for one complete pre-control mutation group.
    /// Requires Admin and access to every revision's policy. Analysis is bounded
    /// by the shared budget and 1024 mutations/16 MiB each of bodies and controls.
    /// Publication uses a workspace CAS and one Sync. Exact retries follow the
    /// accepted journal even if the idempotency cache is unavailable.
    /// Hash-only history needs explicit migration; no body is erased here.
    pub fn prepare_record_controls(
        &self,
        context: &AuthenticatedRequestContext,
        record_commit: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordControlPreparationReceipt> {
        require_capability(context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        if record_commit == 0 {
            return Err(invalid(
                "record preparation requires an accepted workspace commit",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let world = self.recovery_workspace(&snapshot, &workspace, budget)?;
        if record_commit > world.watermarks.journal {
            return Err(not_found());
        }
        let (source_map, source) =
            self.recovery_event(&snapshot, &workspace, record_commit, budget)?;
        self.require_legacy_record_group(&snapshot, &source)?;

        // The index is not absence evidence. A lost locator cannot authorize a
        // second preparation; validate all later declarations before publication.
        let mut existing = None;
        let mut previous = source.global_commit;
        let mut last_world = source_map.state;
        for commit in record_commit..world.watermarks.journal {
            let (mapping, event) =
                self.recovery_event(&snapshot, &workspace, commit + 1, budget)?;
            if event.global_commit <= previous {
                return Err(integrity("record preparation history regressed"));
            }
            previous = event.global_commit;
            last_world = mapping.state;
            if let Some(publication) = declaration(&event)?
                && publication.source_global == source.global_commit
            {
                if existing.is_some() {
                    return Err(integrity("duplicate accepted record preparation"));
                }
                existing = Some(event);
            }
        }
        if last_world != world {
            return Err(integrity(
                "record preparation frontier differs from its accepted map",
            ));
        }

        let controls = self.prepare_legacy_controls(&snapshot, context, &source, budget)?;
        let references: Vec<_> = source
            .accepted_records
            .iter()
            .map(|reference| {
                let mut prepared = reference.clone();
                prepared.control_digest = Some(digest_bytes(&controls[&reference.key]));
                prepared
            })
            .collect();
        if let Some(event) = existing {
            let publication =
                declaration(&event)?.ok_or_else(|| integrity("preparation absent"))?;
            let verified = self.verify_prepared_group(&snapshot, &event, &source, budget)?;
            if publication.controls != references || verified.len() != controls.len() {
                return Err(integrity(
                    "prepared controls differ from original record bodies",
                ));
            }
            return Ok(publication.receipt());
        }
        if snapshot
            .get(&self.keyspaces.continuous, &group_key(source.global_commit))
            .map_err(storage_error)?
            .is_some()
        {
            return Err(integrity(
                "record preparation locator has no accepted publication",
            ));
        }
        let orphan = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prepared_prefix(source.global_commit),
                    start_after: None,
                    max_entries: 1,
                    max_bytes: MAX_BYTES,
                },
            )
            .map_err(storage_error)?;
        if !orphan.entries.is_empty() || orphan.continuation.is_some() {
            return Err(integrity("unaccepted record preparation controls exist"));
        }
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if self.workspace_state(&tx, &context.request.workspace_id)? != world
            || self
                .recovery_event(&tx, &workspace, record_commit, budget)?
                .1
                != source
        {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "workspace changed while preparing record controls",
                true,
            ));
        }
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        let publication = ControlPreparation {
            source_global: source.global_commit,
            source_commit: source.workspace_commit,
            source_event_digest: source.event_digest.clone(),
            workspace_commit: frame.state.watermarks.journal,
            controls: references,
        };
        let mut manifest = self.raw_manifest(&tx)?;
        manifest.features.insert(FEATURE.into());
        manifest.checksum = manifest_checksum(&manifest)?;
        tx.put(
            &self.keyspaces.meta,
            META_MANIFEST_KEY.to_vec(),
            encode(&manifest)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.keyspaces.continuous,
            group_key(source.global_commit),
            encode(&frame.global_commit)?,
        )
        .map_err(storage_error)?;
        for (key, bytes) in controls {
            tx.put(&self.keyspaces.continuous, prepared_key(&key)?, bytes)
                .map_err(storage_error)?;
        }
        let digest = publication.request_digest(&workspace)?;
        self.finish_frame(
            &mut tx,
            &frame,
            OPERATION,
            digest.as_bytes(),
            &digest,
            &publication,
        )?;
        budget.check().map_err(raw_index::budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(publication.receipt())
    }

    fn require_legacy_record_group<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
    ) -> ServiceResult<()> {
        if event.accepted_records.is_empty() {
            return Err(unsupported(
                "preparation requires full accepted record mutations; hash-only history needs migration",
            ));
        }
        if event.accepted_records.len() > MAX_WRITES
            || !(matches!(
                event.operation.as_str(),
                "publish_memory" | "propose_memory" | "correct" | "retract"
            ) || record_sources::writes::is_source_write(&event.operation))
        {
            return Err(integrity("record preparation has an invalid source group"));
        }
        let activated: Option<u64> = self.raw_value(snapshot, record_journal::ACTIVATED)?;
        if !self
            .raw_manifest(snapshot)?
            .features
            .contains(RECORD_FEATURE)
            || activated.is_none_or(|first| first == 0 || first > event.global_commit)
        {
            return Err(integrity(
                "record preparation lost its original journal activation",
            ));
        }
        if self
            .record_control_activation(snapshot)?
            .is_some_and(|first| first <= event.global_commit)
            || event
                .accepted_records
                .iter()
                .any(|reference| reference.control_digest.is_some())
        {
            return Err(invalid(
                "record group already requires controls at original acceptance",
            ));
        }
        Ok(())
    }

    fn prepare_legacy_controls<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        source: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut controls = BTreeMap::new();
        let mut body_bytes = 0usize;
        let mut control_bytes = 0usize;
        for reference in &source.accepted_records {
            let suffix = reference
                .key
                .strip_prefix(mutation_prefix(source.global_commit).as_bytes())
                .ok_or_else(|| integrity("record preparation mutation address differs"))?;
            let address = std::str::from_utf8(suffix)
                .map_err(|_| integrity("record mutation address is invalid"))?;
            let (record_digest, revision) = address
                .split_once('/')
                .ok_or_else(|| integrity("record mutation address is invalid"))?;
            let revision: u32 = revision
                .parse()
                .map_err(|_| integrity("record mutation revision is invalid"))?;
            if blake3::Hash::from_hex(record_digest).is_err()
                || address != format!("{record_digest}/{revision:010}")
            {
                return Err(integrity("record mutation address is not canonical"));
            }
            let policy_key = history_key(record_digest, revision);
            // Labels are checked before arbitrary record bodies are decoded.
            let policy: StoredPolicy = decode(
                &required_bytes(
                    snapshot,
                    &self.keyspaces.policy_history,
                    &policy_key,
                    budget,
                )?,
                "record preparation policy",
            )?;
            validate_stored_policy(&policy)?;
            if policy_key != history_key(&policy.record_digest, policy.revision)
                || digest_bytes(policy.access.workspace_id.as_bytes()) != source.workspace_digest
            {
                return Err(integrity("record preparation policy address differs"));
            }
            if !policy_allows(&context.request, &policy.access) {
                return Err(ServiceError::new(
                    ErrorCode::PermissionDenied,
                    "record preparation policy denies access",
                    false,
                ));
            }
            let bytes =
                required_bytes(snapshot, &self.keyspaces.continuous, &reference.key, budget)?;
            body_bytes = body_bytes.saturating_add(bytes.len());
            if body_bytes > MAX_BYTES {
                return Err(exhausted(
                    "record preparation bodies exceed the group bound",
                ));
            }
            if digest_bytes(&bytes) != reference.digest {
                return Err(integrity("record preparation body differs from acceptance"));
            }
            let record: MemoryRecord = decode(&bytes, "record preparation original")?;
            let control = RecordControl::from_record(&record)?;
            control.validate_binding(source, reference)?;
            if control.policy.access != policy.access {
                return Err(integrity(
                    "record preparation label differs from accepted body",
                ));
            }
            let bytes = encode(&control)?;
            budget
                .charge(1, bytes.len() as u64)
                .map_err(raw_index::budget_error)?;
            control_bytes = control_bytes.saturating_add(bytes.len());
            if control_bytes > MAX_BYTES {
                return Err(exhausted(
                    "record preparation controls exceed the group bound",
                ));
            }
            if controls.insert(reference.key.clone(), bytes).is_some() {
                return Err(integrity("duplicate accepted record mutation"));
            }
        }
        Ok(controls)
    }
}

fn required_bytes<S: ReadSnapshot>(
    snapshot: &S,
    space: &Keyspace,
    key: &[u8],
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<u8>> {
    let bytes = snapshot
        .get(space, key)
        .map_err(storage_error)?
        .ok_or_else(|| integrity("record preparation metadata or body absent"))?;
    budget
        .charge(1, bytes.len() as u64)
        .map_err(raw_index::budget_error)?;
    if bytes.len() > MAX_BYTES {
        return Err(exhausted("record preparation row exceeds its bound"));
    }
    Ok(bytes)
}

fn declaration(event: &StoredEvent) -> ServiceResult<Option<&ControlPreparation>> {
    if event.operation != OPERATION {
        if event.accepted_record_control_preparation.is_some() {
            return Err(integrity("record preparation has an invalid journal owner"));
        }
        return Ok(None);
    }
    let publication = event
        .accepted_record_control_preparation
        .as_ref()
        .ok_or_else(|| integrity("record preparation declaration absent"))?;
    if publication.controls.is_empty()
        || publication.controls.len() > MAX_WRITES
        || publication.source_global == 0
        || publication.source_global >= event.global_commit
        || publication.source_commit == 0
        || publication.source_commit >= event.workspace_commit
        || publication.workspace_commit != event.workspace_commit
        || blake3::Hash::from_hex(&publication.source_event_digest).is_err()
        || event.event_digest != event_digest(event)?
        || event.request_digest != publication.request_digest(&event.workspace_digest)?
        || event.response_digest != canonical_digest(publication)?
        || !event.accepted_records.is_empty()
    {
        return Err(integrity(
            "record preparation declaration differs from acceptance",
        ));
    }
    Ok(Some(publication))
}

fn group_key(global: u64) -> Vec<u8> {
    format!("record-prepared/group/{global:020}").into_bytes()
}
fn prepared_prefix(global: u64) -> Vec<u8> {
    format!("record-prepared/control/{global:020}/").into_bytes()
}
fn prepared_key(mutation: &[u8]) -> ServiceResult<Vec<u8>> {
    let suffix = mutation
        .strip_prefix(b"semantic/record/")
        .ok_or_else(|| integrity("prepared record address invalid"))?;
    Ok([b"record-prepared/control/", suffix].concat())
}

#[cfg(test)]
thread_local! { static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default(); }
