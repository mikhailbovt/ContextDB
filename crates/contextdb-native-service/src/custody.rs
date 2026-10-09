//! Materialized disclosure restrictions, rebuilt in bounded capture order.
//!
//! Conversation depth does not enter read-time authorization: equivalent labels
//! are deduplicated at capture. Revocation closes the workspace disclosure gate
//! until a forward pass has propagated current restrictions to every descendant.

#[cfg(test)]
mod tests;
mod verify;

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    ContentDigest, EventEnvelope, EventKind, EventPayload, EventProvenance, ObservationId,
    OriginalPayloadRef, RequestPart,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, Capability, ErrorCode, ServiceError, ServiceResult,
};
use contextdb_storage::{
    Durability, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine, WriteTransaction,
};
use serde::{Deserialize, Serialize};

use super::{
    NativeService, StoredObservationPolicy, canonical_digest, decode, digest_bytes, encode,
    exhausted, integrity, invalid, permission_denied, policy_allows, raw_index::budget_error,
    require_capability, require_sync, storage_error,
};

pub(super) const CUSTODY_FEATURE: &str = "continuous-derived-custody-v1";
pub(super) const CUSTODY_VERSION: u16 = 1;
const MAX_LABELS: usize = 128;
const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyState {
    version: u16,
    /// Captures through this position have current transitive restrictions.
    through: u64,
    authorization_epoch: u64,
    pending: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inputs {
    pub(super) sources: BTreeSet<ObservationId>,
    pub(super) payloads: Vec<OriginalPayloadRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) trace_controls: Option<crate::router_trace::controls::RouterTraceControls>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyRecord {
    version: u16,
    event_id: ObservationId,
    workspace: String,
    commit: u64,
    event_digest: ContentDigest,
    inputs: Inputs,
    /// Canonical-digest order, unique by complete policy, never an ACL union.
    policies: Vec<AccessPolicy>,
    /// Current generic/state permissions remain independent from copied labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trace_controls: Option<crate::router_trace::controls::RouterTraceControls>,
}

/// Bounded administrative migration/revocation progress, not physical deletion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyProgress {
    /// Highest capture position whose inherited restrictions are current.
    pub through: u64,
    /// Capture records processed by this call, at most the requested batch.
    pub processed: u32,
    /// Current workspace revocation epoch.
    pub authorization_epoch: u64,
    /// Custody is current; retention and index gates may still close disclosure.
    pub caught_up: bool,
}

impl NativeService {
    /// Rebuild 1..256 original custody records, including legacy captures.
    /// Analysis runs outside publication authority. A concurrent revocation or
    /// repair rejects the complete attempt; retry with the remaining budget.
    pub fn maintain_custody(
        &self,
        context: &AuthenticatedRequestContext,
        max_events: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CustodyProgress> {
        require_capability(context, Capability::Admin)?;
        if !(1..=256).contains(&max_events) {
            return Err(invalid("custody batch must contain 1..256 captures"));
        }
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let expected = self.custody_state(&snapshot, &workspace)?;
        let epoch = self.raw_authorization_epoch(&snapshot, &workspace)?;
        let mut state = expected.clone().unwrap_or(CustodyState {
            version: CUSTODY_VERSION,
            through: 0,
            authorization_epoch: epoch,
            pending: true,
        });
        if !state.pending {
            return Ok(progress(&state, 0));
        }
        let page = self.custody_work(&snapshot, &workspace, state.through, max_events as usize)?;
        let mut records = BTreeMap::new();
        for entry in page.entries {
            budget
                .charge(1, entry.value.len() as u64)
                .map_err(budget_error)?;
            let work: super::capture::CaptureWork = decode(&entry.value, "custody work")?;
            let control = self.verified_capture_control(&snapshot, work.event_id, budget)?;
            if work.workspace_commit <= state.through
                || self.capture_work_for_receipt(&snapshot, &control.receipt)? != work
                || entry.key != super::capture::work_key(&workspace, work.workspace_commit)
                || control.receipt.workspace_id.to_string() != context.request.workspace_id
            {
                return Err(integrity("custody outbox differs from its original"));
            }
            let record = self.build_control_custody_record(
                &snapshot,
                &control.receipt,
                control.recovery.inputs,
                &records,
                Some(budget),
            )?;
            budget
                .charge(0, encode(&record)?.len() as u64)
                .map_err(budget_error)?;
            records.insert(work.event_id, record);
            state.through = work.workspace_commit;
        }
        let processed = records.len() as u32;
        #[cfg(test)]
        BEFORE_PUBLISH.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if self.custody_state(&tx, &workspace)? != expected
            || self.raw_authorization_epoch(&tx, &workspace)? != epoch
        {
            return Err(pending());
        }
        // Captures may arrive during analysis. Test the tail again under the
        // publication owner, so a concurrent append cannot escape the barrier.
        state.pending = !self
            .custody_work(&tx, &workspace, state.through, 1)?
            .entries
            .is_empty();
        self.enable_capture_extension(&mut tx, CUSTODY_FEATURE)?;
        for record in records.into_values() {
            budget.check().map_err(budget_error)?;
            self.put_custody_record(&mut tx, &record)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            state_key(&workspace),
            encode(&state)?,
        )
        .map_err(storage_error)?;
        let result = progress(&state, processed);
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        let digest = canonical_digest(&(&workspace, frame.global_commit, &result))?;
        self.finish_frame(
            &mut tx,
            &frame,
            "custody_rebuild",
            digest.as_bytes(),
            &digest,
            &result,
        )?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(result)
    }

    pub(super) fn publish_capture_custody<T: WriteTransaction>(
        &self,
        tx: &mut T,
        context: &AuthenticatedRequestContext,
        event: &EventEnvelope,
        commit: u64,
    ) -> ServiceResult<()> {
        let workspace = digest_bytes(event.workspace_id.to_string().as_bytes());
        let mut state = self.custody_state(tx, &workspace)?.unwrap_or(CustodyState {
            version: CUSTODY_VERSION,
            through: 0,
            authorization_epoch: self.raw_authorization_epoch(tx, &workspace)?,
            // Called before this capture's outbox row is inserted. New stores
            // are ready; legacy stores remain closed until explicit migration.
            pending: !self.custody_work(tx, &workspace, 0, 1)?.entries.is_empty(),
        });
        let record = self.build_custody_record(tx, event, commit, &BTreeMap::new(), None)?;
        if !record.inputs.sources.is_empty() {
            self.require_custody_ready(tx, &workspace)?;
        }
        if record
            .policies
            .iter()
            .any(|policy| !policy_allows(&context.request, policy))
        {
            return Err(permission_denied());
        }
        if let Some(controls) = &record.trace_controls {
            self.authorize_router_trace_controls(tx, context, controls, &mut trace_budget())?;
        }
        self.enable_capture_extension(tx, CUSTODY_FEATURE)?;
        self.put_custody_record(tx, &record)?;
        if !state.pending {
            state.through = commit;
        }
        tx.put(
            &self.keyspaces.continuous,
            state_key(&workspace),
            encode(&state)?,
        )
        .map_err(storage_error)
    }

    pub(super) fn invalidate_custody<T: WriteTransaction>(
        &self,
        tx: &mut T,
        workspace: &str,
        source_commit: u64,
        epoch: u64,
    ) -> ServiceResult<()> {
        let through = self
            .custody_state(tx, workspace)?
            .map_or(0, |state| state.through);
        let state = CustodyState {
            version: CUSTODY_VERSION,
            through: through.min(source_commit.saturating_sub(1)),
            authorization_epoch: epoch,
            pending: true,
        };
        self.enable_capture_extension(tx, CUSTODY_FEATURE)?;
        tx.put(
            &self.keyspaces.continuous,
            state_key(workspace),
            encode(&state)?,
        )
        .map_err(storage_error)
    }

    pub(super) fn require_custody_ready<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<()> {
        self.require_suppression_current(snapshot, workspace)?;
        self.require_custody_rebuilt(snapshot, workspace)
    }

    // Maintenance can rebuild while retention intentionally closes disclosure.
    pub(super) fn require_custody_rebuilt<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<()> {
        self.require_suppression_prefix_current(snapshot, workspace)?;
        match self.custody_state(snapshot, workspace)? {
            Some(state) if !state.pending => Ok(()),
            None if self
                .custody_work(snapshot, workspace, 0, 1)?
                .entries
                .is_empty() =>
            {
                Ok(())
            }
            _ => Err(pending()),
        }
    }

    pub(super) fn authorize_derived_custody<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
    ) -> ServiceResult<()> {
        self.authorize_derived_custody_with_budget(snapshot, context, id, &mut trace_budget())
            .map(|_| ())
    }

    pub(crate) fn authorize_derived_custody_with_budget<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<crate::router_trace::controls::RouterTraceControls>> {
        self.authorize_derived_custody_inputs(snapshot, context, id, None, budget)
    }

    pub(crate) fn authorize_derived_custody_with_inputs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
        inputs: &Inputs,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<crate::router_trace::controls::RouterTraceControls>> {
        self.authorize_derived_custody_inputs(snapshot, context, id, Some(inputs), budget)
    }

    fn authorize_derived_custody_inputs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
        expected: Option<&Inputs>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<crate::router_trace::controls::RouterTraceControls>> {
        let controls =
            self.admit_derived_custody_inputs(snapshot, context, id, expected, budget)?;
        if let Some(controls) = &controls {
            self.authorize_router_trace_controls(snapshot, context, controls, budget)?;
        }
        Ok(controls)
    }

    /// Current copied labels only; the enclosing control frontier verifies all
    /// immutable material after every direct and inherited label is admitted.
    pub(crate) fn admit_derived_custody_controls<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<crate::router_trace::controls::RouterTraceControls>> {
        self.admit_derived_custody_inputs(snapshot, context, id, None, budget)
    }

    fn admit_derived_custody_inputs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
        expected: Option<&Inputs>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<crate::router_trace::controls::RouterTraceControls>> {
        budget.check().map_err(budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        self.require_custody_ready(snapshot, &workspace)?;
        let record = self.custody_record_inner(snapshot, id, Some(budget))?;
        if expected.is_some_and(|inputs| *inputs != record.inputs) {
            return Err(integrity(
                "accepted trace custody inputs differ from recovery",
            ));
        }
        if let Some(direct) = &record.inputs.trace_controls {
            let retained = record
                .trace_controls
                .as_ref()
                .ok_or_else(|| integrity("accepted trace lacks its complete origin custody"))?;
            budget
                .charge(1, (retained.byte_length()? as u64).saturating_mul(2))
                .map_err(budget_error)?;
            let mut whole = record
                .trace_controls
                .clone()
                .ok_or_else(|| integrity("accepted trace lacks its complete origin custody"))?;
            whole.union_checked(direct)?;
            if Some(&whole) != record.trace_controls.as_ref() {
                return Err(integrity(
                    "accepted trace custody omits direct protected origins",
                ));
            }
        }
        if record.workspace != workspace
            || record
                .policies
                .iter()
                .any(|policy| !policy_allows(&context.request, policy))
        {
            return Err(permission_denied());
        }
        Ok(record.trace_controls)
    }

    // Administrative reconstruction of an archived prefix is independent of
    // current disclosure admission. verify_custody_records checks these rows.
    pub(super) fn stored_custody_policies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
    ) -> ServiceResult<Vec<AccessPolicy>> {
        Ok(self.custody_record(snapshot, id)?.policies)
    }

    pub(crate) fn stored_custody_policies_with_budget<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<AccessPolicy>> {
        Ok(self
            .custody_record_inner(snapshot, id, Some(budget))?
            .policies)
    }

    pub(crate) fn stored_router_trace_controls<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
    ) -> ServiceResult<Option<crate::router_trace::controls::RouterTraceControls>> {
        Ok(self.custody_record(snapshot, id)?.trace_controls)
    }

    fn build_custody_record<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
        commit: u64,
        overlay: &BTreeMap<ObservationId, CustodyRecord>,
        budget: Option<&mut QueryBudget>,
    ) -> ServiceResult<CustodyRecord> {
        self.build_custody_inputs(
            snapshot,
            CustodyRecord {
                version: CUSTODY_VERSION,
                event_id: event.event_id,
                workspace: digest_bytes(event.workspace_id.to_string().as_bytes()),
                commit,
                event_digest: super::capture::content_digest_of(event)?,
                inputs: inputs(event)?,
                policies: Vec::new(),
                trace_controls: None,
            },
            overlay,
            budget,
        )
    }

    fn build_control_custody_record<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &contextdb_service::CaptureReceipt,
        inputs: Inputs,
        overlay: &BTreeMap<ObservationId, CustodyRecord>,
        budget: Option<&mut QueryBudget>,
    ) -> ServiceResult<CustodyRecord> {
        self.build_custody_inputs(
            snapshot,
            CustodyRecord {
                version: CUSTODY_VERSION,
                event_id: receipt.event_id,
                workspace: digest_bytes(receipt.workspace_id.to_string().as_bytes()),
                commit: receipt.workspace_commit,
                event_digest: receipt.event_digest,
                inputs,
                policies: Vec::new(),
                trace_controls: None,
            },
            overlay,
            budget,
        )
    }

    fn build_custody_inputs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        mut record: CustodyRecord,
        overlay: &BTreeMap<ObservationId, CustodyRecord>,
        mut budget: Option<&mut QueryBudget>,
    ) -> ServiceResult<CustodyRecord> {
        let policy: StoredObservationPolicy = decode(
            &snapshot
                .get(
                    &self.keyspaces.observations_policy,
                    digest_bytes(record.event_id.to_string().as_bytes()).as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("custody source policy absent"))?,
            "custody source policy",
        )?;
        let workspace = &record.workspace;
        let inputs = &record.inputs;
        let mut trace_controls = inputs.trace_controls.clone();
        if let Some(controls) = &trace_controls {
            controls.validate()?;
            if !controls.originals.is_subset(&inputs.sources) {
                return Err(integrity(
                    "router trace originals are absent from custody inputs",
                ));
            }
        }
        let mut labels = BTreeMap::new();
        charge(&mut budget, 1, encode(&policy)?.len() as u64)?;
        insert_label(&mut labels, policy.access, workspace)?;
        for source in &inputs.sources {
            charge(&mut budget, 1, 0)?;
            let parent = if let Some(parent) = overlay.get(source) {
                parent.clone()
            } else {
                self.custody_record(snapshot, *source)?
            };
            charge(&mut budget, 1, encode(&parent)?.len() as u64)?;
            if parent.workspace != *workspace || parent.commit >= record.commit {
                return Err(integrity(
                    "custody dependency crosses workspace or capture order",
                ));
            }
            if let Some(controls) = &parent.trace_controls {
                if let Some(union) = &mut trace_controls {
                    union.union_checked(controls)?;
                } else {
                    trace_controls = Some(controls.clone());
                }
            }
            for policy in parent.policies {
                charge(&mut budget, 1, 0)?;
                insert_label(&mut labels, policy, workspace)?;
            }
        }
        for payload in &inputs.payloads {
            charge(&mut budget, 1, 0)?;
            let policy = self.payload_index_policy(snapshot, payload)?;
            charge(&mut budget, 0, encode(&policy)?.len() as u64)?;
            insert_label(&mut labels, policy, workspace)?;
        }
        if let Some(controls) = &trace_controls {
            let policies = if let Some(shared) = budget.as_deref_mut() {
                self.router_trace_historical_policies(snapshot, controls, shared)?
            } else {
                self.router_trace_historical_policies(snapshot, controls, &mut trace_budget())?
            };
            for policy in policies {
                charge(&mut budget, 1, 0)?;
                insert_label(&mut labels, policy, workspace)?;
            }
        }
        record.version = if trace_controls.is_some() {
            2
        } else {
            CUSTODY_VERSION
        };
        record.trace_controls = trace_controls;
        record.policies = labels.into_values().collect();
        if encode(&record)?.len() > MAX_RECORD_BYTES {
            return Err(exhausted("capture custody metadata exceeds 1 MiB"));
        }
        Ok(record)
    }

    fn custody_state<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<Option<CustodyState>> {
        let state: Option<CustodyState> = self.raw_value(snapshot, &state_key(workspace))?;
        if let Some(state) = &state
            && (state.version != CUSTODY_VERSION
                || state.authorization_epoch
                    != self.raw_authorization_epoch(snapshot, workspace)?)
        {
            return Err(integrity(
                "custody state version or authorization epoch differs",
            ));
        }
        Ok(state)
    }

    fn custody_record<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
    ) -> ServiceResult<CustodyRecord> {
        self.custody_record_inner(snapshot, id, None)
    }

    fn custody_record_inner<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
        mut budget: Option<&mut QueryBudget>,
    ) -> ServiceResult<CustodyRecord> {
        if let Some(shared) = budget.as_deref_mut() {
            shared.check().map_err(budget_error)?;
        }
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &record_key(id))
            .map_err(storage_error)?
            .ok_or_else(pending)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(integrity("custody record exceeds its stored byte bound"));
        }
        if let Some(shared) = budget.as_deref_mut() {
            shared.charge(0, bytes.len() as u64).map_err(budget_error)?;
        }
        let record: CustodyRecord = decode(&bytes, "custody source record")?;
        let receipt = if let Some(shared) = budget {
            self.capture_recovery_metadata(snapshot, id, shared)?.0
        } else {
            self.captured_receipt_metadata(snapshot, id)?
        };
        if record.version
            != if record.trace_controls.is_some() {
                2
            } else {
                CUSTODY_VERSION
            }
            || record.event_id != id
            || record.commit == 0
            || record.commit != receipt.workspace_commit
            || record.event_digest != receipt.event_digest
            || record.workspace != digest_bytes(receipt.workspace_id.to_string().as_bytes())
            || record.policies.is_empty()
            || record.policies.len() > MAX_LABELS
            || record.inputs.sources.len() > super::CAPTURE_MAX_REQUEST_PARTS + 64
            || record.inputs.payloads.len() > super::CAPTURE_MAX_REQUEST_PARTS
        {
            return Err(integrity("custody record binding or bounds invalid"));
        }
        if let Some(controls) = &record.trace_controls {
            controls.validate()?;
            let manifest: super::Manifest = decode(
                &snapshot
                    .get(&self.keyspaces.meta, super::META_MANIFEST_KEY)
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("router custody native manifest is absent"))?,
                "router custody native manifest",
            )?;
            if !manifest
                .features
                .contains(crate::router_trace::TRACE_FEATURE)
            {
                return Err(integrity("router custody format feature is absent"));
            }
        }
        if record.inputs.trace_controls.is_some() && record.trace_controls.is_none() {
            return Err(integrity(
                "router trace custody lost its transitive controls",
            ));
        }
        let mut labels = BTreeMap::new();
        for policy in &record.policies {
            insert_label(&mut labels, policy.clone(), &record.workspace)?;
        }
        if labels.into_values().collect::<Vec<_>>() != record.policies {
            return Err(integrity(
                "custody labels are not unique canonical restrictions",
            ));
        }
        Ok(record)
    }

    fn put_custody_record<T: WriteTransaction>(
        &self,
        tx: &mut T,
        record: &CustodyRecord,
    ) -> ServiceResult<()> {
        tx.put(
            &self.keyspaces.continuous,
            record_key(record.event_id),
            encode(record)?,
        )
        .map_err(storage_error)
    }

    fn custody_work<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        through: u64,
        max_entries: usize,
    ) -> ServiceResult<contextdb_storage::ScanPage> {
        let prefix = format!("outbox/{workspace}/").into_bytes();
        let after = [prefix.as_slice(), &through.to_be_bytes()].concat();
        snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: Some(&after),
                    max_entries,
                    max_bytes: 2 * 1024 * 1024,
                },
            )
            .map_err(storage_error)
    }
}

pub(super) fn inputs(event: &EventEnvelope) -> ServiceResult<Inputs> {
    inputs_with_trace_controls(event, crate::router_trace::trace_controls(event)?)
}

pub(crate) fn inputs_with_trace_controls(
    event: &EventEnvelope,
    mut trace_controls: Option<crate::router_trace::controls::RouterTraceControls>,
) -> ServiceResult<Inputs> {
    let mut inputs = Inputs::default();
    // A declared revision is not a declassification grant, even when the host
    // retains full replacement bytes. Safe transformation needs its own proof.
    inputs.sources.extend(event.supersedes_event_id);
    match &event.payload {
        EventPayload::Staged { reference, .. } => inputs.payloads.push(reference.clone()),
        EventPayload::Assembly { manifest } => {
            for part in &manifest.parts {
                match part {
                    RequestPart::Source { span } | RequestPart::JsonStringSource { span, .. } => {
                        inputs.sources.insert(span.event_id);
                    }
                    RequestPart::StoredNovel { payload } => inputs.payloads.push(payload.clone()),
                    RequestPart::Novel { .. } => (),
                }
            }
            if manifest.router_trace.is_some() {
                let controls = trace_controls
                    .take()
                    .ok_or_else(|| integrity("router trace input controls are absent"))?;
                controls.validate()?;
                inputs.sources.extend(&controls.originals);
                inputs.trace_controls = Some(controls);
            }
        }
        _ => (),
    }
    match &event.provenance {
        Some(EventProvenance::ModelOutput {
            request_event_id, ..
        }) => {
            inputs.sources.insert(*request_event_id);
        }
        Some(EventProvenance::Tool {
            request_event_id, ..
        }) => {
            if event.kind == EventKind::ToolRequested {
                // Runtime intent arguments derive from their captured proposal.
                inputs.sources.extend(&event.parent_event_ids);
            } else {
                inputs.sources.insert(*request_event_id);
            }
        }
        Some(EventProvenance::OwnedCheckpoint { .. }) => {
            let checkpoint = super::owned::decode_checkpoint(event)?;
            inputs
                .sources
                .extend(checkpoint.required_sources().map(|span| span.event_id));
            inputs.sources.extend(checkpoint.last_model_output);
            if let Some(call) = checkpoint.pending_model {
                if call.wire_digest.is_some() {
                    inputs.sources.insert(call.request_event);
                }
                inputs.sources.extend(call.interrupted_output);
            }
            if let Some(tool) = checkpoint.pending_tool {
                inputs.sources.insert(tool.proposal.event_id);
            }
        }
        // Ordinary causal links on independent observations are not data inputs.
        _ => (),
    }
    if inputs.sources.contains(&event.event_id) {
        return Err(invalid("capture custody cannot depend on itself"));
    }
    if trace_controls.is_some() {
        return Err(integrity("non-router event was supplied trace controls"));
    }
    Ok(inputs)
}

// Public original reads have no caller QueryBudget. Their extra typed control
// work is still bounded; prepare/admission use the caller's shared allowance.
fn trace_budget() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        16 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        Default::default(),
    )
}

fn insert_label(
    labels: &mut BTreeMap<String, AccessPolicy>,
    policy: AccessPolicy,
    workspace: &str,
) -> ServiceResult<()> {
    if digest_bytes(policy.workspace_id.as_bytes()) != workspace {
        return Err(integrity("custody policy crosses workspaces"));
    }
    labels.insert(canonical_digest(&policy)?, policy);
    if labels.len() > MAX_LABELS {
        return Err(exhausted(
            "capture requires more than 128 distinct custody restrictions",
        ));
    }
    Ok(())
}

fn state_key(workspace: &str) -> Vec<u8> {
    format!("custody/state/{workspace}").into_bytes()
}
fn record_key(id: ObservationId) -> Vec<u8> {
    format!("custody/source/{id}").into_bytes()
}
fn progress(state: &CustodyState, processed: u32) -> CustodyProgress {
    CustodyProgress {
        through: state.through,
        processed,
        authorization_epoch: state.authorization_epoch,
        caught_up: !state.pending,
    }
}
fn pending() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "workspace disclosure requires bounded custody migration or revocation propagation",
        true,
    )
}

fn charge(budget: &mut Option<&mut QueryBudget>, work: u64, bytes: u64) -> ServiceResult<()> {
    if let Some(budget) = budget {
        budget.charge(work, bytes).map_err(budget_error)?;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static BEFORE_PUBLISH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}
