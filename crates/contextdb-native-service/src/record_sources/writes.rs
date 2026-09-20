//! Native acceptance precedes retained origin transfer. An accepted intent and
//! a separate journal-bound completion keep interrupted groups undisclosed.

use super::*;
use contextdb_core::ContentDigest;

mod recovery;
#[cfg(test)]
mod tests;
mod verify;

pub(crate) const WRITE_FEATURE: &str = "continuous-record-source-writes-v1";
const COMPLETE: &str = "record_write_complete";
const PUBLISH: &str = "publish_memory_from_sources";
const MAX_INTENT_BYTES: usize = 16 * 1024 * 1024;

/// A completed handoff of one accepted mutation group to retained provenance.
/// This does not override current source permissions or certify deletion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordWriteReceipt {
    /// Original workspace-local mutation commit, unchanged by recovery.
    pub commit_seq: u64,
    /// Workspace-local commit that durably completed the handoff.
    pub completed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordWriteRef {
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWriteIntent {
    global_commit: u64,
    workspace: String,
    request_digest: String,
    idempotency_key: Vec<u8>,
    records: Vec<record_journal::RecordMutationRef>,
    origins: Vec<RecordSourceControl>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordWriteCompletion {
    write_global_commit: u64,
    intent_digest: String,
    through: RecordSourcesCheckpoint,
    pub(crate) scopes: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedWrite {
    global_commit: u64,
    publication: RecordWriteCompletion,
}

pub(crate) struct PreparedWrite {
    world: WorkspaceState,
    through: RecordSourcesCheckpoint,
    sources: BTreeMap<ObservationId, ContentDigest>,
}

impl NativeService {
    /// Publish explicit memory from the complete captured inputs supplied by a
    /// trusted host. Requires Admin in addition to normal publication grants.
    /// An interrupted call may already be accepted: retry the identical request
    /// or resume its workspace commit. Ordinary reads wait for full completion.
    pub fn publish_memory_from_sources(
        &self,
        request: PublishMemoryRequest,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        let context = request.context.clone();
        let response = self.publish_explicit_memory_inner(request, Some((sources, budget)))?;
        #[cfg(test)]
        after_native_sync();
        if let Err(mut error) = self.complete_record_source_write(
            &context,
            response.commit_seq,
            Some(&response),
            budget,
        ) {
            error.partial_result_refs = vec![format!(
                "record-write:{}:{}",
                digest_bytes(context.request.workspace_id.as_bytes()),
                response.commit_seq
            )]
            .into_boxed_slice();
            error.safe_next_action =
                Some("Retry the identical request or resume the accepted workspace commit.".into());
            return Err(error);
        }
        Ok(response)
    }

    pub(crate) fn prepare_record_write(
        &self,
        context: &AuthenticatedRequestContext,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PreparedWrite> {
        require_capability(context, Capability::Admin)?;
        if !(1..=64).contains(&sources.len()) {
            return Err(invalid("record publication requires 1..64 captured inputs"));
        }
        // Check source authority before activating a previously legacy workspace.
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.prepare_record_inputs(&snapshot, context, sources, budget)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("record provenance requires retained authority"))?;
        if ledger
            .current_record_sources(&digest_bytes(context.request.workspace_id.as_bytes()))?
            .is_none()
        {
            self.initialize_record_sources(context, budget)?;
        }
        while !self
            .maintain_record_sources(context, 256, budget)?
            .caught_up
        {}
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        let sources = self.prepare_record_inputs(&snapshot, context, sources, budget)?;
        Ok(PreparedWrite {
            through: self.record_sources_applied(&snapshot, &world.workspace_digest)?,
            world,
            sources,
        })
    }

    fn prepare_record_inputs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<ObservationId, ContentDigest>> {
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        self.require_suppression_prefix_current(snapshot, &workspace)?;
        self.require_removal_current(snapshot, &workspace)?;
        self.require_custody_rebuilt(snapshot, &workspace)?;
        let mut inputs = BTreeMap::new();
        for id in sources {
            self.authorize_record_write_input(snapshot, context, *id)?;
            let origin = self.verified_capture_control(snapshot, *id, budget)?;
            if origin.receipt.workspace_id.to_string() != context.request.workspace_id {
                return Err(permission_denied());
            }
            inputs.insert(*id, origin.control_digest);
        }
        Ok(inputs)
    }

    fn authorize_record_write_input<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
    ) -> ServiceResult<()> {
        self.require_unsuppressed_identity(
            &digest_bytes(context.request.workspace_id.as_bytes()),
            id,
        )?;
        let source: StoredObservationPolicy = decode(
            &snapshot
                .get(
                    &self.keyspaces.observations_policy,
                    digest_bytes(id.to_string().as_bytes()).as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(not_found)?,
            "record write input policy",
        )?;
        if !policy_allows(&context.request, &source.access)
            || self
                .stored_custody_policies(snapshot, id)?
                .iter()
                .any(|label| !policy_allows(&context.request, label))
        {
            return Err(permission_denied());
        }
        Ok(())
    }

    pub(crate) fn check_record_write_preparation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        prepared: &PreparedWrite,
    ) -> ServiceResult<()> {
        let workspace = &prepared.world.workspace_digest;
        if self.workspace_state(snapshot, &context.request.workspace_id)? != prepared.world
            || self.record_sources_applied(snapshot, workspace)? != prepared.through
        {
            return Err(pending(
                "workspace changed while preparing record publication",
            ));
        }
        self.require_suppression_current(snapshot, workspace)?;
        self.require_custody_ready(snapshot, workspace)?;
        for id in prepared.sources.keys() {
            self.authorize_record_write_input(snapshot, context, *id)?;
        }
        Ok(())
    }

    pub(crate) fn stage_record_write<T: WriteTransaction>(
        &self,
        tx: &mut T,
        frame: &CommitFrame,
        request: (&str, &[u8]),
        prepared: PreparedWrite,
        record: &MemoryRecord,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("record source authority absent"))?
            .record_identity_retained(
                &frame.workspace_digest,
                &digest_bytes(record.document.id.as_bytes()),
            )?
        {
            return Err(invalid(
                "record identity is reserved by retained provenance",
            ));
        }
        budget
            .charge(1, encode(record)?.len() as u64)
            .map_err(raw_index::budget_error)?;
        let intent = RecordWriteIntent {
            global_commit: frame.global_commit,
            workspace: frame.workspace_digest.clone(),
            request_digest: request.0.into(),
            idempotency_key: request.1.into(),
            records: self.accepted_record_mutations(tx, frame)?,
            origins: vec![RecordSourceControl {
                workspace: frame.workspace_digest.clone(),
                record_digest: digest_bytes(record.document.id.as_bytes()),
                revision: record.revision,
                transaction_from: frame.global_commit,
                birth_digest: canonical_digest(record)?,
                document_digest: canonical_digest(&record.document)?,
                scopes: record.document.access.scopes.clone(),
                sources: prepared.sources,
            }],
        };
        for control in &intent.origins {
            control.validate()?;
        }
        let bytes = encode(&intent)?;
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(exhausted("record source intent exceeds its bounded group"));
        }
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        self.enable_capture_extension(tx, WRITE_FEATURE)?;
        tx.put(
            &self.keyspaces.continuous,
            intent_key(frame.global_commit),
            bytes,
        )
        .map_err(storage_error)
    }

    pub(crate) fn accepted_record_write<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        frame: &CommitFrame,
        operation: &str,
        request_digest: &str,
        idempotency_key: &[u8],
        records: &[record_journal::RecordMutationRef],
    ) -> ServiceResult<Option<RecordWriteRef>> {
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &intent_key(frame.global_commit))
            .map_err(storage_error)?;
        if operation != PUBLISH {
            if bytes.is_some() {
                return Err(integrity("unexpected record source intent"));
            }
            return Ok(None);
        }
        let bytes = bytes.ok_or_else(|| integrity("record publication lost its source intent"))?;
        let intent: RecordWriteIntent = decode(&bytes, "record source intent")?;
        if intent.global_commit != frame.global_commit
            || intent.workspace != frame.workspace_digest
            || intent.request_digest != request_digest
            || intent.idempotency_key != idempotency_key
            || intent.records != records
            || intent.origins.len() != 1
            || records.len() != 1
            || bytes.len() > MAX_INTENT_BYTES
        {
            return Err(integrity(
                "record source intent differs from the accepted group",
            ));
        }
        Ok(Some(RecordWriteRef {
            digest: digest_bytes(&bytes),
        }))
    }
}

fn intent_key(global: u64) -> Vec<u8> {
    format!("record-write/intent/{global:020}").into_bytes()
}
fn completion_key(global: u64) -> Vec<u8> {
    format!("record-write/complete/{global:020}").into_bytes()
}

#[cfg(test)]
thread_local! {
    static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static AFTER_NATIVE_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static AFTER_ORIGIN_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
    static BEFORE_COMPLETION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}

#[cfg(test)]
pub(crate) fn before_publication() {
    BEFORE_PUBLICATION.with(|hook| {
        if let Some(hook) = hook.take() {
            hook();
        }
    });
}
#[cfg(test)]
fn after_native_sync() {
    AFTER_NATIVE_SYNC.with(|hook| {
        if let Some(hook) = hook.take() {
            hook();
        }
    });
}
