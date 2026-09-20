//! Record origins live in the retained authority. Native progress is replayable;
//! restoring an older database cannot restore an older provenance policy.

use super::*;
use crate::suppression::{RecordSourceControl, RecordSourcesCheckpoint};
use contextdb_core::ObservationId;
use contextdb_recall::QueryBudget;

pub(crate) const FEATURE: &str = "continuous-record-sources-v1";

/// Durable host declaration of one record revision's captured origins.
/// This is an authority receipt, not a native commit or deletion receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordSourceReceipt {
    /// Independently retained authority that accepted this declaration.
    pub authority_id: uuid::Uuid,
    /// Workspace-local position in its record provenance journal.
    pub epoch: u64,
    /// Exact authority commitment.
    pub digest: String,
    /// Commitment to the logical record ID, without copying arbitrary names.
    pub record_digest: String,
    /// Exact record revision.
    pub revision: u32,
}

/// Bounded native catch-up with current retained record provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordSourceProgress {
    /// Applied workspace-local authority epoch.
    pub through: u64,
    /// Entries verified in this call.
    pub processed: u32,
    /// Native progress matches the current authority. Unclassified records remain
    /// unavailable; this does not claim complete migration or deletion.
    pub caught_up: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordSourcesPublication {
    pub from: RecordSourcesCheckpoint,
    pub through: RecordSourcesCheckpoint,
    pub scopes: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Applied {
    through: RecordSourcesCheckpoint,
    native_global_commit: u64,
}

impl NativeService {
    /// Declare complete captured origins for an existing revision. This is a
    /// trusted host assertion, never inference from an empty evidence list or
    /// similar text. Each origin must precede the accepted record. The external
    /// Sync closes native disclosure until `maintain_record_sources` catches up.
    /// Later unclassified revisions remain unavailable in this workspace.
    pub fn bind_record_sources(
        &self,
        context: &AuthenticatedRequestContext,
        record_id: &str,
        revision: u32,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordSourceReceipt> {
        require_capability(context, Capability::Admin)?;
        validate_identifier(record_id, "record source identity")?;
        if revision == 0 || !(1..=64).contains(&sources.len()) {
            return Err(invalid(
                "record provenance requires a revision and 1..64 captured origins",
            ));
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("record provenance requires retained authority"))?;
        if !ledger.supports_record_sources() {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "record provenance requires a version 3 authority",
                false,
            ));
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let record_digest = digest_bytes(record_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        let policy: StoredPolicy = decode(
            &snapshot
                .get(
                    &self.keyspaces.policy_history,
                    &history_key(&record_digest, revision),
                )
                .map_err(storage_error)?
                .ok_or_else(not_found)?,
            "record origin policy",
        )?;
        validate_stored_policy(&policy)?;
        if !policy_allows(&context.request, &policy.access)
            || policy.record_digest != record_digest
            || policy.revision != revision
        {
            return Err(permission_denied());
        }
        let birth = self.record_birth(&snapshot, &policy, budget)?;
        self.require_custody_rebuilt(&snapshot, &workspace)?;
        let mut controls = BTreeMap::new();
        for id in sources {
            let source_policy: StoredObservationPolicy = decode(
                &snapshot
                    .get(
                        &self.keyspaces.observations_policy,
                        digest_bytes(id.to_string().as_bytes()).as_bytes(),
                    )
                    .map_err(storage_error)?
                    .ok_or_else(not_found)?,
                "record captured origin",
            )?;
            if source_policy.accepted_global_commit >= policy.transaction_from {
                return Err(invalid("record origin was captured after the record"));
            }
            let mut labels = self.stored_custody_policies(&snapshot, *id)?;
            labels.push(source_policy.access);
            for mut label in labels {
                // Administrative provenance repair may run after revocation,
                // without returning original bytes or reopening ordinary reads.
                label.retrievable = true;
                if !policy_allows(&context.request, &label) {
                    return Err(permission_denied());
                }
            }
            let origin = self.verified_capture_control(&snapshot, *id, budget)?;
            if origin.receipt.workspace_id.to_string() != context.request.workspace_id {
                return Err(permission_denied());
            }
            controls.insert(*id, origin.control_digest);
        }
        let control = RecordSourceControl {
            workspace,
            record_digest,
            revision,
            transaction_from: policy.transaction_from,
            birth_digest: digest_bytes(&encode(&birth)?),
            document_digest: canonical_digest(&birth.document)?,
            scopes: policy.access.scopes.clone(),
            sources: controls,
        };
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let latest = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self.workspace_state(&latest, &context.request.workspace_id)? != world {
            return Err(pending("workspace changed while binding record origins"));
        }
        let entry = ledger.bind_record_origin(&control, budget)?;
        #[cfg(test)]
        AFTER_AUTHORITY_SYNC.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        Ok(NativeRecordSourceReceipt {
            authority_id: ledger.authority_id(),
            epoch: entry.checkpoint.epoch,
            digest: entry.checkpoint.digest,
            record_digest: entry.control.record_digest,
            revision,
        })
    }

    /// Verify at most 256 retained declarations, then compare the native workspace
    /// and publish one durable applied prefix. No provenance is inferred for an
    /// unclassified record, including a record restored from a legacy archive.
    pub fn maintain_record_sources(
        &self,
        context: &AuthenticatedRequestContext,
        max_entries: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordSourceProgress> {
        require_capability(context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("record source authority absent"))?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        let from = self.record_sources_applied(&snapshot, &workspace)?;
        let entries = ledger.record_sources_batch(&workspace, &from, max_entries, budget)?;
        if entries.is_empty() {
            return Ok(NativeRecordSourceProgress {
                through: from.epoch,
                processed: 0,
                caught_up: match ledger.current_record_sources(&workspace)? {
                    Some(current) => current == from,
                    None => from.epoch == 0,
                },
            });
        }
        // Exact accepted history prevents a missing local record from being
        // misreported as a legitimate post-backup absence.
        self.verify_record_mutations(&snapshot)?;
        let mut scopes = BTreeSet::new();
        for entry in &entries {
            self.verify_local_record_origin(&snapshot, &entry.control, budget)?;
            scopes.extend(entry.control.scopes.iter().cloned());
        }
        let through = entries
            .last()
            .ok_or_else(|| integrity("record source page vanished"))?
            .checkpoint
            .clone();
        let publication = RecordSourcesPublication {
            from: from.clone(),
            through: through.clone(),
            scopes,
        };
        #[cfg(test)]
        BEFORE_APPLY.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if self.workspace_state(&tx, &context.request.workspace_id)? != world
            || self.record_sources_applied(&tx, &workspace)? != from
        {
            return Err(pending(
                "workspace changed while applying record provenance",
            ));
        }
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        for scope in &publication.scopes {
            tx.put(
                &self.keyspaces.continuous,
                capture::scope_key(&workspace, scope),
                encode(&frame.state.watermarks.journal)?,
            )
            .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            applied_key(&workspace),
            encode(&Applied {
                through: through.clone(),
                native_global_commit: frame.global_commit,
            })?,
        )
        .map_err(storage_error)?;
        self.enable_capture_extension(&mut tx, FEATURE)?;
        let digest = canonical_digest(&(FEATURE, &workspace, &publication))?;
        self.finish_frame(
            &mut tx,
            &frame,
            "record_sources_reconcile",
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
        Ok(NativeRecordSourceProgress {
            through: through.epoch,
            processed: entries.len() as u32,
            caught_up: ledger.current_record_sources(&workspace)?.as_ref() == Some(&through),
        })
    }

    pub(crate) fn require_record_sources_current<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<()> {
        let Some(ledger) = &self.suppression else {
            return Ok(());
        };
        let applied = self.record_sources_applied(snapshot, workspace)?;
        match ledger.current_record_sources(workspace)? {
            Some(required) if applied != required => {
                return Err(pending(
                    "current record provenance must be applied before disclosure",
                ));
            }
            None if applied.epoch != 0 => {
                return Err(integrity(
                    "retained workspace provenance disappeared after native application",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn record_sources_applied<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<RecordSourcesCheckpoint> {
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("record source authority absent"))?;
        let Some(bytes) = snapshot
            .get(&self.keyspaces.continuous, &applied_key(workspace))
            .map_err(storage_error)?
        else {
            return ledger.record_sources_genesis(workspace);
        };
        let applied: Applied = decode(&bytes, "applied record origins")?;
        let event: StoredEvent = decode(
            &snapshot
                .get(
                    &self.keyspaces.events,
                    &applied.native_global_commit.to_be_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record provenance application absent"))?,
            "record provenance application",
        )?;
        if event.operation != "record_sources_reconcile"
            || event.workspace_digest != workspace
            || event.event_digest != event_digest(&event)?
            || event
                .accepted_record_sources
                .as_ref()
                .is_none_or(|publication| publication.through != applied.through)
        {
            return Err(integrity("record provenance progress is not journal-bound"));
        }
        Ok(applied.through)
    }

    pub(crate) fn record_source_policies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
    ) -> ServiceResult<Vec<AccessPolicy>> {
        let Some(ledger) = &self.suppression else {
            return Ok(Vec::new());
        };
        let workspace = digest_bytes(policy.access.workspace_id.as_bytes());
        self.require_record_sources_current(snapshot, &workspace)?;
        if ledger.current_record_sources(&workspace)?.is_none() {
            return Ok(Vec::new());
        }
        let binding = ledger
            .retained_record_sources(&workspace, &policy.record_digest, policy.revision)?
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::EvidenceRequired,
                    "record revision has no declared captured origins",
                    false,
                )
            })?;
        if binding.control.transaction_from != policy.transaction_from {
            return Err(integrity("record provenance refers to another acceptance"));
        }
        self.require_custody_ready(snapshot, &workspace)?;
        let mut policies = Vec::new();
        for id in binding.control.sources.keys() {
            let source: StoredObservationPolicy = decode(
                &snapshot
                    .get(
                        &self.keyspaces.observations_policy,
                        digest_bytes(id.to_string().as_bytes()).as_bytes(),
                    )
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("record origin policy absent"))?,
                "record origin policy",
            )?;
            if source.access.workspace_id != policy.access.workspace_id {
                return Err(integrity("record origin crosses workspaces"));
            }
            policies.push(source.access);
            policies.extend(self.stored_custody_policies(snapshot, *id)?);
        }
        Ok(policies)
    }

    pub(crate) fn authorize_record_sources<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &RequestContext,
        policy: &StoredPolicy,
    ) -> ServiceResult<()> {
        if self
            .record_source_policies(snapshot, policy)?
            .iter()
            .any(|source| !policy_allows(context, source))
        {
            return Err(permission_denied());
        }
        Ok(())
    }

    // Existing mutation ports have no origin parameter. Their atomic source-aware
    // replacements must classify every new revision and copied incident edge.
    pub(crate) fn require_legacy_record_writer<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
    ) -> ServiceResult<()> {
        self.require_record_sources_current(snapshot, &digest_bytes(workspace_id.as_bytes()))?;
        if let Some(ledger) = &self.suppression
            && ledger
                .current_record_sources(&digest_bytes(workspace_id.as_bytes()))?
                .is_some()
        {
            return Err(unsupported(
                "source-aware record publication is required in this workspace",
            ));
        }
        Ok(())
    }

    fn verify_local_record_origin<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        control: &RecordSourceControl,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let Some(bytes) = snapshot
            .get(
                &self.keyspaces.policy_history,
                &history_key(&control.record_digest, control.revision),
            )
            .map_err(storage_error)?
        else {
            // verify_record_mutations already establishes exact reverse closure;
            // a revision accepted only after this archive is legitimately absent.
            if snapshot
                .get(
                    &self.keyspaces.content_history,
                    &history_key(&control.record_digest, control.revision),
                )
                .map_err(storage_error)?
                .is_some()
            {
                return Err(integrity("declared record lost its policy projection"));
            }
            return Ok(());
        };
        let policy: StoredPolicy = decode(&bytes, "declared record policy")?;
        if policy.transaction_from != control.transaction_from
            || digest_bytes(policy.access.workspace_id.as_bytes()) != control.workspace
        {
            return Err(integrity(
                "record provenance acceptance differs from local history",
            ));
        }
        let birth = self.record_birth(snapshot, &policy, budget)?;
        if digest_bytes(&encode(&birth)?) != control.birth_digest
            || canonical_digest(&birth.document)? != control.document_digest
            || birth.document.access.scopes != control.scopes
        {
            return Err(integrity(
                "record content differs from its retained provenance",
            ));
        }
        for (id, digest) in &control.sources {
            let origin = self.verified_capture_control(snapshot, *id, budget)?;
            if origin.control_digest != *digest
                || digest_bytes(origin.receipt.workspace_id.to_string().as_bytes())
                    != control.workspace
            {
                return Err(integrity("record captured-origin control differs"));
            }
        }
        Ok(())
    }
    fn record_birth<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
        budget: &mut QueryBudget,
    ) -> ServiceResult<MemoryRecord> {
        let key = format!(
            "semantic/record/{:020}/{}/{:010}",
            policy.transaction_from, policy.record_digest, policy.revision
        )
        .into_bytes();
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &key)
            .map_err(storage_error)?
            .ok_or_else(|| {
                unsupported("record provenance requires its original accepted mutation bytes")
            })?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        let birth: MemoryRecord = decode(&bytes, "record birth mutation")?;
        let event: StoredEvent = decode(
            &snapshot
                .get(
                    &self.keyspaces.events,
                    &policy.transaction_from.to_be_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record birth journal absent"))?,
            "record birth journal",
        )?;
        if !event
            .accepted_records
            .iter()
            .any(|reference| reference.key == key && reference.digest == digest_bytes(&bytes))
            || event.event_digest != event_digest(&event)?
            || event.workspace_digest != digest_bytes(policy.access.workspace_id.as_bytes())
            || birth.transaction_from != policy.transaction_from
            || birth.transaction_to.is_some()
            || birth.revision != policy.revision
            || digest_bytes(birth.document.id.as_bytes()) != policy.record_digest
        {
            return Err(integrity("record birth differs from its accepted journal"));
        }
        let current = self.load_content(snapshot, policy)?;
        if birth.document != current.document {
            return Err(integrity("record revision changed its original document"));
        }
        Ok(birth)
    }
}

impl NativeService {
    pub(crate) fn verify_record_source_progress<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        let mut expected = BTreeMap::new();
        let mut prefixes = BTreeMap::<String, RecordSourcesCheckpoint>::new();
        let mut budget = retention::audit_budget();
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&row.value, "record provenance progress")?;
            let Some(publication) = &event.accepted_record_sources else {
                if event.operation == "record_sources_reconcile" {
                    return Err(integrity("record source application lost its reference"));
                }
                continue;
            };
            let ledger = self
                .suppression
                .as_ref()
                .ok_or_else(|| integrity("record source authority missing"))?;
            let from = prefixes
                .get(&event.workspace_digest)
                .cloned()
                .unwrap_or(ledger.record_sources_genesis(&event.workspace_digest)?);
            let count = publication
                .through
                .epoch
                .checked_sub(from.epoch)
                .ok_or_else(|| integrity("record source progress regressed"))?;
            if event.operation != "record_sources_reconcile"
                || from != publication.from
                || !(1..=256).contains(&count)
                || event.event_digest != event_digest(&event)?
                || event.response_digest != digest_bytes(&encode(publication)?)
                || event.request_digest
                    != canonical_digest(&(FEATURE, &event.workspace_digest, publication))?
            {
                return Err(integrity("record provenance application binding differs"));
            }
            let entries = ledger.record_sources_batch(
                &event.workspace_digest,
                &from,
                count as usize,
                &mut budget,
            )?;
            let mut scopes = BTreeSet::new();
            for entry in &entries {
                self.verify_local_record_origin(snapshot, &entry.control, &mut budget)?;
                scopes.extend(entry.control.scopes.iter().cloned());
            }
            if entries.last().map(|entry| &entry.checkpoint) != Some(&publication.through)
                || scopes != publication.scopes
            {
                return Err(integrity(
                    "record provenance application skips retained declarations",
                ));
            }
            prefixes.insert(event.workspace_digest.clone(), publication.through.clone());
            expected.insert(
                applied_key(&event.workspace_digest),
                encode(&Applied {
                    through: publication.through.clone(),
                    native_global_commit: event.global_commit,
                })?,
            );
        }
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record source manifest absent"))?,
            "record source manifest",
        )?;
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"record-source-applied/")
            .map_err(storage_error)?;
        if manifest.features.contains(FEATURE) == expected.is_empty()
            || actual.len() != expected.len()
            || actual
                .iter()
                .any(|row| expected.get(&row.key) != Some(&row.value))
        {
            return Err(integrity(
                "record source progress differs from its accepted history",
            ));
        }
        Ok(())
    }
}

fn applied_key(workspace: &str) -> Vec<u8> {
    format!("record-source-applied/{workspace}").into_bytes()
}
fn pending(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::IndexTooStale, message, true)
}
pub(crate) fn source_unavailable(error: &ServiceError) -> bool {
    matches!(
        error.code,
        ErrorCode::PermissionDenied | ErrorCode::EvidenceRequired | ErrorCode::NotFound
    )
}

#[cfg(test)]
thread_local! {
    static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static AFTER_AUTHORITY_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static BEFORE_APPLY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}

#[cfg(test)]
mod tests;
