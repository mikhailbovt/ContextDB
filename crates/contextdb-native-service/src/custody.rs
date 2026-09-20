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
    sources: BTreeSet<ObservationId>,
    payloads: Vec<OriginalPayloadRef>,
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
    /// Disclosure can resume; a stale raw generation still needs rebuilding.
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
            let original = self.load_captured_original(&snapshot, work.event_id)?;
            budget
                .charge(0, encode(&original.event)?.len() as u64)
                .map_err(budget_error)?;
            if work.workspace_commit <= state.through
                || work.workspace_commit != original.receipt.workspace_commit
                || work.event_digest != original.receipt.event_digest
                || original.event.workspace_id.to_string() != context.request.workspace_id
            {
                return Err(integrity("custody outbox differs from its original"));
            }
            let record = self.build_custody_record(
                &snapshot,
                &original.event,
                work.workspace_commit,
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
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        self.require_custody_ready(snapshot, &workspace)?;
        let record = self.custody_record(snapshot, id)?;
        if record.workspace != workspace
            || record
                .policies
                .iter()
                .any(|policy| !policy_allows(&context.request, policy))
        {
            return Err(permission_denied());
        }
        Ok(())
    }

    pub(super) fn derived_custody_policies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
    ) -> ServiceResult<Vec<AccessPolicy>> {
        let record = self.custody_record(snapshot, id)?;
        self.require_custody_ready(snapshot, &record.workspace)?;
        Ok(record.policies)
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

    fn build_custody_record<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
        commit: u64,
        overlay: &BTreeMap<ObservationId, CustodyRecord>,
        mut budget: Option<&mut QueryBudget>,
    ) -> ServiceResult<CustodyRecord> {
        let policy: StoredObservationPolicy = decode(
            &snapshot
                .get(
                    &self.keyspaces.observations_policy,
                    digest_bytes(event.event_id.to_string().as_bytes()).as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("custody source policy absent"))?,
            "custody source policy",
        )?;
        let workspace = digest_bytes(event.workspace_id.to_string().as_bytes());
        let inputs = inputs(event)?;
        let mut labels = BTreeMap::new();
        charge(&mut budget, 1, encode(&policy)?.len() as u64)?;
        insert_label(&mut labels, policy.access, &workspace)?;
        for source in &inputs.sources {
            charge(&mut budget, 1, 0)?;
            let parent = if let Some(parent) = overlay.get(source) {
                parent.clone()
            } else {
                self.custody_record(snapshot, *source)?
            };
            charge(&mut budget, 1, encode(&parent)?.len() as u64)?;
            if parent.workspace != workspace || parent.commit >= commit {
                return Err(integrity(
                    "custody dependency crosses workspace or capture order",
                ));
            }
            for policy in parent.policies {
                charge(&mut budget, 1, 0)?;
                insert_label(&mut labels, policy, &workspace)?;
            }
        }
        for payload in &inputs.payloads {
            charge(&mut budget, 1, 0)?;
            let policy = self.payload_index_policy(snapshot, payload)?;
            charge(&mut budget, 0, encode(&policy)?.len() as u64)?;
            insert_label(&mut labels, policy, &workspace)?;
        }
        let record = CustodyRecord {
            version: CUSTODY_VERSION,
            event_id: event.event_id,
            workspace,
            commit,
            event_digest: super::capture::content_digest_of(event)?,
            inputs,
            policies: labels.into_values().collect(),
        };
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
        let record: CustodyRecord = self
            .raw_value(snapshot, &record_key(id))?
            .ok_or_else(pending)?;
        let receipt = self.captured_receipt_metadata(snapshot, id)?;
        if record.version != CUSTODY_VERSION
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
    Ok(inputs)
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
