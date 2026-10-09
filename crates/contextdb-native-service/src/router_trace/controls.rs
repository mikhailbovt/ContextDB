//! Exact trace lineage. Historical identity and current disclosure are separate.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{ObservationId, StateKey, TimestampMicros};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AccessPolicy, AssertionMutation, AuthenticatedRequestContext, ErrorCode, MemoryRecordKind,
    ServiceError, ServiceResult, StateView,
};
use contextdb_storage::{ReadSnapshot, ScanPageRequest};
use serde::{Deserialize, Serialize};

use crate::{
    NativeService, StoredPolicy, assertions::MutationLabel, canonical_digest, decode, digest_bytes,
    encode, exhausted, history_key, integrity, permission_denied, policy_allows,
    raw_index::budget_error, storage_error, suppression::RecordSourceControl,
    validate_stored_policy,
};

const MAX_CONTROLS: usize = 512;
const MAX_MUTATIONS: usize = 2048;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_SOURCES: usize = crate::CAPTURE_MAX_REQUEST_PARTS + 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraceRecordControl {
    pub(crate) kind: MemoryRecordKind,
    pub(crate) authority_id: uuid::Uuid,
    pub(crate) declaration_digest: String,
    pub(crate) control: RecordSourceControl,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraceStateMutationControl {
    pub(crate) label_key: Vec<u8>,
    pub(crate) commit: u64,
    pub(crate) body_digest: String,
    pub(crate) sources: BTreeSet<ObservationId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraceStateControl {
    pub(crate) workspace: String,
    pub(crate) key: StateKey,
    pub(crate) authority_commit: u64,
    pub(crate) authority_digest: String,
    pub(crate) mutations: Vec<TraceStateMutationControl>,
}

/// Exact direct inputs or their bounded transitive union. No field is a grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouterTraceControls {
    pub(crate) version: u16,
    pub(crate) originals: BTreeSet<ObservationId>,
    pub(crate) records: Vec<TraceRecordControl>,
    pub(crate) states: Vec<TraceStateControl>,
}

impl Default for RouterTraceControls {
    fn default() -> Self {
        Self {
            version: 1,
            originals: BTreeSet::new(),
            records: Vec::new(),
            states: Vec::new(),
        }
    }
}

impl RouterTraceControls {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        if self.version != 1 {
            return Err(integrity("router trace control version is unsupported"));
        }
        if self.originals.len() > MAX_SOURCES
            || self.records.len().saturating_add(self.states.len()) > MAX_CONTROLS
            || self
                .states
                .iter()
                .map(|state| state.mutations.len())
                .sum::<usize>()
                > MAX_MUTATIONS
        {
            return Err(exhausted(
                "router trace control inventory exceeds its bound",
            ));
        }
        // Guard variable-sized policy/scope fields before existing inner
        // validators serialize any individual retained control.
        self.byte_length()?;
        let mut record_keys = BTreeSet::new();
        for record in &self.records {
            record.control.validate()?;
            if record.authority_id.is_nil()
                || !is_digest(&record.declaration_digest)
                || !record_keys.insert((&record.control.record_digest, record.control.revision))
                || !record
                    .control
                    .sources
                    .keys()
                    .all(|id| self.originals.contains(id))
            {
                return Err(integrity(
                    "router record controls are incomplete or duplicated",
                ));
            }
        }
        let mut state_keys = BTreeSet::new();
        for state in &self.states {
            if !is_digest(&state.workspace)
                || !is_digest(&state.authority_digest)
                || state.authority_commit == 0
                || !state_keys.insert((canonical_digest(&state.key)?, state.authority_commit))
            {
                return Err(integrity("router state authority controls are invalid"));
            }
            let prefix = state_prefix(&state.workspace, &state.key)?;
            let mut labels = BTreeSet::new();
            for mutation in &state.mutations {
                if !mutation.label_key.starts_with(prefix.as_bytes())
                    || mutation.label_key.len() > prefix.len() + 32
                    || mutation.commit == 0
                    || !is_digest(&mutation.body_digest)
                    || mutation.sources.is_empty()
                    || !mutation.sources.is_subset(&self.originals)
                    || !labels.insert(&mutation.label_key)
                {
                    return Err(integrity("router state mutation controls are invalid"));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn byte_length(&self) -> ServiceResult<usize> {
        let mut counter = ControlCounter {
            bytes: 0,
            overflow: false,
        };
        if serde_json::to_writer(&mut counter, self).is_err() {
            return Err(if counter.overflow {
                exhausted("router trace controls exceed one MiB")
            } else {
                integrity("router trace controls cannot be encoded")
            });
        }
        Ok(counter.bytes)
    }

    pub(crate) fn union_checked(&mut self, other: &Self) -> ServiceResult<()> {
        self.validate()?;
        other.validate()?;
        let mut union = self.clone();
        union.originals.extend(&other.originals);
        let mut records = BTreeMap::new();
        for record in self.records.iter().chain(&other.records) {
            let key = (
                record.control.record_digest.clone(),
                record.control.revision,
            );
            if records
                .insert(key, record.clone())
                .is_some_and(|old| old != *record)
            {
                return Err(integrity("router record identity has conflicting controls"));
            }
        }
        union.records = records.into_values().collect();
        let mut states = BTreeMap::<_, TraceStateControl>::new();
        for state in self.states.iter().chain(&other.states) {
            let key = (canonical_digest(&state.key)?, state.authority_commit);
            if let Some(old) = states.get_mut(&key) {
                if old.workspace != state.workspace
                    || old.authority_digest != state.authority_digest
                {
                    return Err(integrity("router state identity has conflicting authority"));
                }
                let mut mutations = BTreeMap::new();
                for mutation in old.mutations.iter().chain(&state.mutations) {
                    if mutations
                        .insert(mutation.label_key.clone(), mutation.clone())
                        .is_some_and(|previous| previous != *mutation)
                    {
                        return Err(integrity("router state identity has conflicting mutation"));
                    }
                }
                old.mutations = mutations.into_values().collect();
            } else {
                let mut state = state.clone();
                state
                    .mutations
                    .sort_by(|a, b| a.label_key.cmp(&b.label_key));
                states.insert(key, state);
            }
        }
        union.states = states.into_values().collect();
        union.validate()?;
        *self = union;
        Ok(())
    }
}

impl NativeService {
    /// Complete current labels before the generic provider loads record content.
    pub(crate) fn router_record_policies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        policy: &StoredPolicy,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<AccessPolicy>> {
        budget.check().map_err(budget_error)?;
        let record = self.router_record_metadata(snapshot, policy, budget)?;
        let historical = self.router_record_policy(snapshot, &record, budget)?;
        let mut controls = RouterTraceControls::default();
        controls.originals.extend(record.control.sources.keys());
        let mut policies = BTreeMap::new();
        policies.insert(canonical_digest(&policy.access)?, policy.access.clone());
        policies.insert(canonical_digest(&historical.access)?, historical.access);
        budget.charge(1, 0).map_err(budget_error)?;
        let current_bytes = snapshot
            .get(&self.keyspaces.policy_head, policy.record_digest.as_bytes())
            .map_err(storage_error)?
            .ok_or_else(unavailable_origin)?;
        budget
            .charge(0, current_bytes.len() as u64)
            .map_err(budget_error)?;
        let current: StoredPolicy = decode(&current_bytes, "router provider current policy")?;
        validate_stored_policy(&current)?;
        if current.record_digest != policy.record_digest
            || current.revision < policy.revision
            || current.access.workspace_id != policy.access.workspace_id
        {
            return Err(integrity("router provider current policy identity changed"));
        }
        policies.insert(canonical_digest(&current.access)?, current.access);
        for id in &controls.originals.clone() {
            budget.check().map_err(budget_error)?;
            let source = self.authorized_capture_policy(snapshot, context, *id)?;
            budget
                .charge(1, encode(&source)?.len() as u64)
                .map_err(budget_error)?;
            policies.insert(canonical_digest(&source.access)?, source.access);
            for inherited in self.stored_custody_policies(snapshot, *id)? {
                budget
                    .charge(1, encode(&inherited)?.len() as u64)
                    .map_err(budget_error)?;
                policies.insert(canonical_digest(&inherited)?, inherited);
            }
            if let Some(inherited) = self.stored_router_trace_controls(snapshot, *id)? {
                budget
                    .charge(1, inherited.byte_length()? as u64)
                    .map_err(budget_error)?;
                controls.union_checked(&inherited)?;
            }
            if policies.len() > 128 {
                return Err(exhausted(
                    "router record labels exceed custody policy bound",
                ));
            }
        }
        if policies
            .values()
            .any(|label| !policy_allows(&context.request, label))
        {
            return Err(permission_denied());
        }
        // This policy frontier precedes the provider's complete-corpus ceiling.
        // Verify inherited trace controls now, but defer this record's immutable
        // body to router_record_control after that ceiling admits the corpus.
        self.authorize_router_trace_controls(snapshot, context, &controls, budget)?;
        if self
            .pruned_record(snapshot, &policy.record_digest, policy.revision, budget)?
            .is_some()
        {
            return Err(unavailable_origin());
        }
        Ok(policies.into_values().collect())
    }

    /// Called with the exact policy actually materialized by the native owner.
    pub(crate) fn router_record_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
        budget: &mut QueryBudget,
    ) -> ServiceResult<TraceRecordControl> {
        let control = self.router_record_metadata(snapshot, policy, budget)?;
        self.verify_router_record(snapshot, &control, budget)?;
        if self
            .pruned_record(snapshot, &policy.record_digest, policy.revision, budget)?
            .is_some()
        {
            return Err(unavailable_origin());
        }
        // A declaration for a revision in an older/later archive is not proof
        // that this preparation actually has the complete immutable material.
        let record = self.load_content(snapshot, policy)?;
        budget
            .charge(1, encode(&record)?.len() as u64)
            .map_err(budget_error)?;
        Ok(control)
    }

    fn router_record_metadata<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
        budget: &mut QueryBudget,
    ) -> ServiceResult<TraceRecordControl> {
        validate_stored_policy(policy)?;
        let workspace = digest_bytes(policy.access.workspace_id.as_bytes());
        self.require_record_sources_current(snapshot, &workspace)?;
        self.require_record_write_complete(snapshot, policy)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(missing_record_authority)?;
        if !ledger.supports_record_sources() || ledger.current_record_sources(&workspace)?.is_none()
        {
            return Err(missing_record_authority());
        }
        let entry = ledger
            .retained_record_sources(&workspace, &policy.record_digest, policy.revision)?
            .ok_or_else(missing_record_authority)?;
        let control = TraceRecordControl {
            kind: policy.kind,
            authority_id: ledger.authority_id(),
            declaration_digest: entry.checkpoint.digest.clone(),
            control: entry.record_control()?.clone(),
        };
        budget
            .charge(1, encode(&entry)?.len() as u64)
            .map_err(budget_error)?;
        self.router_record_policy(snapshot, &control, budget)?;
        Ok(control)
    }

    /// Binds the exact already-authorized state view; it never resolves again.
    pub(crate) fn router_state_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        key: &StateKey,
        view: &StateView,
        budget: &mut QueryBudget,
    ) -> ServiceResult<TraceStateControl> {
        let binding: crate::assertions::query::StateBinding =
            self.open_private_cursor(b"contextdb/state-view/v1", &view.binding)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        if binding.key != *key
            || binding.principal != context.authorization_binding_digest()?
            || binding.policy_digest != canonical_digest(&view.authority)?
        {
            return Err(integrity(
                "router state view differs from its owner binding",
            ));
        }
        let authority = self
            .authority_at(snapshot, &workspace, key, binding.known_at, budget)?
            .ok_or_else(|| integrity("router state authority is absent"))?;
        if authority.policy != view.authority {
            return Err(integrity("router state view authority changed"));
        }
        let mut expected = BTreeSet::new();
        for assertion in &view.assertions {
            expected.insert(canonical_digest(&AssertionMutation::Assert {
                assertion: Box::new(assertion.clone()),
            })?);
        }
        for retraction in &view.retractions {
            expected.insert(canonical_digest(&AssertionMutation::Retract {
                retraction: retraction.clone(),
            })?);
        }
        let prefix = state_prefix(&workspace, key)?;
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: 513,
                    max_bytes: 4 * 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        if page.entries.len() > 512 || page.continuation.is_some() {
            return Err(exhausted("router state origin history exceeds its bound"));
        }
        let mut mutations = Vec::new();
        for entry in page.entries {
            budget
                .charge(1, entry.value.len() as u64)
                .map_err(budget_error)?;
            let label: MutationLabel = decode(&entry.value, "router state label")?;
            if label.commit <= binding.known_at && expected.remove(&label.body_digest) {
                self.authorize_state_label(snapshot, context, &label, budget)?;
                let mutation = self.read_state_mutation(snapshot, &label, budget)?;
                if mutation.key() != key || canonical_digest(&mutation)? != label.body_digest {
                    return Err(integrity("router state material differs from its label"));
                }
                mutations.push(TraceStateMutationControl {
                    label_key: entry.key,
                    commit: label.commit,
                    body_digest: label.body_digest,
                    sources: label.sources,
                });
            }
        }
        if !expected.is_empty() {
            return Err(integrity(
                "router state view omitted immutable origin controls",
            ));
        }
        let control = TraceStateControl {
            workspace,
            key: key.clone(),
            authority_commit: authority.commit,
            authority_digest: canonical_digest(&authority)?,
            mutations,
        };
        self.verify_router_state(snapshot, &control, budget)?;
        Ok(control)
    }

    pub(crate) fn verify_router_trace_controls<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        controls: &RouterTraceControls,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        controls.validate()?;
        budget
            .charge(1, controls.byte_length()? as u64)
            .map_err(budget_error)?;
        for record in &controls.records {
            self.verify_router_record(snapshot, record, budget)?;
        }
        for state in &controls.states {
            self.verify_router_state(snapshot, state, budget)?;
        }
        Ok(())
    }

    pub(crate) fn authorize_router_trace_controls<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        controls: &RouterTraceControls,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        controls.validate()?;
        budget
            .charge(1, controls.byte_length()? as u64)
            .map_err(budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        self.require_custody_ready(snapshot, &workspace)?;
        for id in &controls.originals {
            budget.charge(1, 0).map_err(budget_error)?;
            self.authorized_capture_policy(snapshot, context, *id)?;
        }
        for record in &controls.records {
            if record.control.workspace != workspace {
                return Err(permission_denied());
            }
            self.require_record_sources_current(snapshot, &workspace)?;
            let historical = self.router_record_policy(snapshot, record, budget)?;
            let bytes = snapshot
                .get(
                    &self.keyspaces.policy_head,
                    record.control.record_digest.as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(unavailable_origin)?;
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
            let current: StoredPolicy = decode(&bytes, "router current record policy")?;
            validate_stored_policy(&current)?;
            if current.record_digest != record.control.record_digest
                || current.revision < historical.revision
                || digest_bytes(current.access.workspace_id.as_bytes()) != workspace
            {
                return Err(integrity("router current record policy identity changed"));
            }
            if !policy_allows(&context.request, &historical.access)
                || !policy_allows(&context.request, &current.access)
            {
                return Err(permission_denied());
            }
            self.authorize_record_sources(snapshot, &context.request, &historical)?;
            if self
                .pruned_record(
                    snapshot,
                    &historical.record_digest,
                    historical.revision,
                    budget,
                )?
                .is_some()
            {
                return Err(unavailable_origin());
            }
        }
        let now = current_time()?;
        for state in &controls.states {
            if state.workspace != workspace {
                return Err(permission_denied());
            }
            let historical = self
                .authority_at(
                    snapshot,
                    &workspace,
                    &state.key,
                    state.authority_commit,
                    budget,
                )?
                .ok_or_else(unavailable_origin)?;
            let current = self
                .authority_at(snapshot, &workspace, &state.key, u64::MAX, budget)?
                .ok_or_else(unavailable_origin)?;
            if !policy_allows(&context.request, &historical.access)
                || !policy_allows(&context.request, &current.access)
            {
                return Err(permission_denied());
            }
            for mutation in &state.mutations {
                let label = self.router_mutation_label(snapshot, state, mutation, budget)?;
                if label.pruned_at.is_some() {
                    return Err(unavailable_origin());
                }
                if label.envelope.as_ref().is_some_and(|envelope| {
                    !crate::assertions::query::envelope_allows(context, envelope, now)
                }) {
                    return Err(permission_denied());
                }
                self.authorize_state_label(snapshot, context, &label, budget)?;
            }
        }
        // Only after all current labels allow this principal may immutable
        // native material be loaded for its historical integrity checks.
        self.verify_router_trace_controls(snapshot, controls, budget)
    }

    /// Historical policies are stable reconstruction inputs. Current policies
    /// are checked above and never silently replace accepted custody labels.
    pub(crate) fn router_trace_historical_policies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        controls: &RouterTraceControls,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<AccessPolicy>> {
        self.verify_router_trace_controls(snapshot, controls, budget)?;
        let mut policies = Vec::new();
        for record in &controls.records {
            policies.push(self.router_record_policy(snapshot, record, budget)?.access);
        }
        for state in &controls.states {
            policies.push(
                self.authority_at(
                    snapshot,
                    &state.workspace,
                    &state.key,
                    state.authority_commit,
                    budget,
                )?
                .ok_or_else(|| integrity("router historical authority is absent"))?
                .access,
            );
        }
        Ok(policies)
    }

    fn router_record_policy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        record: &TraceRecordControl,
        budget: &mut QueryBudget,
    ) -> ServiceResult<StoredPolicy> {
        let bytes = snapshot
            .get(
                &self.keyspaces.policy_history,
                &history_key(&record.control.record_digest, record.control.revision),
            )
            .map_err(storage_error)?
            .ok_or_else(|| integrity("router record history is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let policy: StoredPolicy = decode(&bytes, "router historical record policy")?;
        validate_stored_policy(&policy)?;
        if policy.record_digest != record.control.record_digest
            || policy.revision != record.control.revision
            || policy.kind != record.kind
            || policy.transaction_from != record.control.transaction_from
            || digest_bytes(policy.access.workspace_id.as_bytes()) != record.control.workspace
            || policy.access.scopes != record.control.scopes
        {
            return Err(integrity(
                "router record control differs from exact history",
            ));
        }
        Ok(policy)
    }

    fn verify_router_record<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        record: &TraceRecordControl,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let policy = self.router_record_policy(snapshot, record, budget)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(missing_record_authority)?;
        if ledger.authority_id() != record.authority_id {
            return Err(integrity("router record retained authority changed"));
        }
        let entry = ledger
            .retained_record_sources(
                &record.control.workspace,
                &record.control.record_digest,
                record.control.revision,
            )?
            .ok_or_else(missing_record_authority)?;
        budget
            .charge(1, encode(&entry)?.len() as u64)
            .map_err(budget_error)?;
        if entry.checkpoint.digest != record.declaration_digest
            || entry.record_control()? != &record.control
        {
            return Err(integrity("router record retained declaration changed"));
        }
        self.verify_local_record_origin(snapshot, &record.control, budget)?;
        self.require_record_write_complete(snapshot, &policy)
    }

    fn verify_router_state<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        state: &TraceStateControl,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let authority = self
            .authority_at(
                snapshot,
                &state.workspace,
                &state.key,
                state.authority_commit,
                budget,
            )?
            .ok_or_else(|| integrity("router historical state authority is absent"))?;
        if authority.commit != state.authority_commit
            || canonical_digest(&authority)? != state.authority_digest
        {
            return Err(integrity("router historical state authority changed"));
        }
        for mutation in &state.mutations {
            self.router_mutation_label(snapshot, state, mutation, budget)?;
        }
        Ok(())
    }

    fn router_mutation_label<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        state: &TraceStateControl,
        mutation: &TraceStateMutationControl,
        budget: &mut QueryBudget,
    ) -> ServiceResult<MutationLabel> {
        let prefix = state_prefix(&state.workspace, &state.key)?;
        if !mutation.label_key.starts_with(prefix.as_bytes()) {
            return Err(integrity("router state label belongs to another slot"));
        }
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &mutation.label_key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("router state label is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let label: MutationLabel = decode(&bytes, "router state lineage label")?;
        if label.commit != mutation.commit
            || label.body_digest != mutation.body_digest
            || label.sources != mutation.sources
        {
            return Err(integrity("router state lineage label changed"));
        }
        Ok(label)
    }
}

fn state_prefix(workspace: &str, key: &StateKey) -> ServiceResult<String> {
    Ok(format!(
        "state/slot/{workspace}/{}/",
        canonical_digest(key)?
    ))
}
fn is_digest(value: &str) -> bool {
    value.len() == 64 && blake3::Hash::from_hex(value).is_ok()
}
fn missing_record_authority() -> ServiceError {
    ServiceError::new(
        ErrorCode::EvidenceRequired,
        "router trace requires registered exact retained record origins",
        false,
    )
}
fn unavailable_origin() -> ServiceError {
    ServiceError::new(
        ErrorCode::EvidenceRequired,
        "router trace origin is unavailable",
        false,
    )
}
fn current_time() -> ServiceResult<TimestampMicros> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| integrity("router authorization clock is unavailable"))?
        .as_micros();
    Ok(TimestampMicros(i64::try_from(micros).map_err(|_| {
        integrity("router authorization clock overflow")
    })?))
}

struct ControlCounter {
    bytes: usize,
    overflow: bool,
}
impl std::io::Write for ControlCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BYTES.saturating_sub(self.bytes) {
            self.overflow = true;
            return Err(std::io::Error::other("router controls exceed bound"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
