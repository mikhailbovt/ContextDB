//! Native acceptance precedes retained origin transfer. An accepted intent and
//! a separate journal-bound completion keep interrupted groups undisclosed.

use super::*;
use contextdb_core::ContentDigest;

mod groups;
mod recovery;
#[cfg(test)]
mod tests;
mod verify;

pub(crate) use groups::GroupRequest;

pub(crate) const WRITE_FEATURE: &str = "continuous-record-source-writes-v1";
const COMPLETE: &str = "record_write_complete";
const PUBLISH: &str = "publish_memory_from_sources";
pub(crate) const PROPOSE: &str = "propose_memory_from_sources";
pub(crate) const RETRACT: &str = "retract_from_sources";
pub(crate) const CORRECT: &str = "correct_memory_from_sources";
pub(crate) const GROUP_FEATURE: &str = "continuous-record-source-groups-v1";
pub(crate) const CORRECTION_FEATURE: &str = "continuous-record-source-corrections-v1";
const MAX_INTENT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) type Inputs<'a> = (&'a BTreeSet<ObservationId>, &'a mut QueryBudget);

pub(crate) fn is_source_write(operation: &str) -> bool {
    matches!(operation, PUBLISH | PROPOSE | RETRACT | CORRECT)
}

pub(crate) trait WriteResponse: Serialize + DeserializeOwned + Clone {
    fn mutation(&self) -> &MutationResponse;
    fn mutation_mut(&mut self) -> &mut MutationResponse;
}

impl WriteResponse for MutationResponse {
    fn mutation(&self) -> &MutationResponse {
        self
    }
    fn mutation_mut(&mut self) -> &mut MutationResponse {
        self
    }
}

impl WriteResponse for ProposeMemoryResponse {
    fn mutation(&self) -> &MutationResponse {
        &self.mutation
    }
    fn mutation_mut(&mut self) -> &mut MutationResponse {
        &mut self.mutation
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group: Option<groups::RecordWriteGroup>,
}

impl RecordWriteIntent {
    fn scopes(&self) -> BTreeSet<String> {
        self.group.as_ref().map_or_else(
            || {
                self.origins
                    .iter()
                    .flat_map(|control| control.scopes.iter().cloned())
                    .collect()
            },
            |group| group.scopes.clone(),
        )
    }
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
        self.finish_source_write(&context, &response, budget)?;
        Ok(response)
    }

    /// Atomically propose quarantined candidates and links, retaining the input
    /// origins of copied superseded revisions. Requires trusted host Admin.
    pub fn propose_memory_from_sources(
        &self,
        request: ProposeMemoryRequest,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ProposeMemoryResponse> {
        require_capability(&request.context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        let context = request.context.clone();
        let response = self.propose_memory_atomic_inner(request, Some((sources, budget)))?;
        self.finish_source_write(&context, &response, budget)?;
        Ok(response)
    }

    /// Retract a record and its incident links as one source-aware group. The
    /// new revision retains its old body origins; hard deletion is separate.
    pub fn retract_from_sources(
        &self,
        request: ForgetRequest,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        let context = request.context.clone();
        let response = self.retract_memory_inner(request, Some((sources, budget)))?;
        self.finish_source_write(&context, &response, budget)?;
        Ok(response)
    }

    /// Correct a record from complete trusted-host inputs. Rewired hierarchy
    /// edges also retain the origins of the metadata copied from each old edge.
    /// All births and closures stay undisclosed until the group is complete.
    pub fn correct_memory_from_sources(
        &self,
        request: CorrectRequest,
        sources: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Admin)?;
        budget.check().map_err(raw_index::budget_error)?;
        let context = request.context.clone();
        let response = self.correct_memory_inner(request, Some((sources, budget)))?;
        self.finish_source_write(&context, &response, budget)?;
        Ok(response)
    }

    fn finish_source_write<R: WriteResponse>(
        &self,
        context: &AuthenticatedRequestContext,
        response: &R,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        #[cfg(test)]
        after_native_sync();
        let mut original = response.clone();
        original.mutation_mut().replayed = false;
        let digest = canonical_digest(&original)?;
        let mutation = response.mutation();
        if let Err(mut error) = self.complete_record_source_write(
            context,
            mutation.commit_seq,
            Some((&mutation.request_digest, &digest)),
            budget,
        ) {
            error.partial_result_refs = vec![format!(
                "record-write:{}:{}",
                digest_bytes(context.request.workspace_id.as_bytes()),
                mutation.commit_seq
            )]
            .into_boxed_slice();
            error.safe_next_action =
                Some("Retry the identical request or resume the accepted workspace commit.".into());
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn prepare_record_write_or_replay<R: WriteResponse>(
        &self,
        context: &AuthenticatedRequestContext,
        operation: &'static str,
        idempotency_key: &[u8],
        request_digest: &str,
        inputs: &mut Option<Inputs<'_>>,
    ) -> ServiceResult<(Option<PreparedWrite>, Option<R>)> {
        let Some((sources, budget)) = inputs.as_mut() else {
            return Ok((None, None));
        };
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if let Some(mut replay) =
            self.replay::<R, _>(&snapshot, idempotency_key, operation, request_digest)?
        {
            replay.mutation_mut().replayed = true;
            return Ok((None, Some(replay)));
        }
        Ok((
            Some(self.prepare_record_write(context, sources, budget)?),
            None,
        ))
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
            group: None,
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
        if !is_source_write(operation) {
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
            || (operation == PUBLISH
                && (intent.origins.len() != 1 || records.len() != 1 || intent.group.is_some()))
            || (operation != PUBLISH && intent.group.is_none())
            || ((operation == CORRECT)
                != intent
                    .group
                    .as_ref()
                    .is_some_and(|group| group.is_correction()))
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
