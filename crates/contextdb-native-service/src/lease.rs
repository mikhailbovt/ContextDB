//! Bounded process-local leases. Scope epochs are coalesced subscriptions written
//! by the same native publication owner; notification polling is never admission.

use std::collections::BTreeMap;

use contextdb_context::OutgoingAssemblyManifest;
use contextdb_continuity::PendingToolInvocation;
use contextdb_core::{
    ContentDigest, EventPayload, ModelCallId, ObservationId, OriginalSourceSpan, TimestampMicros,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    CaptureReceipt, ContextLease, ContextLeasePort, ContextLeaseStatus, PreparedContext,
    ToolAdmissionClass,
};

use super::prepare::PrepareFence;
use super::raw_index::budget_error;
use super::*;

mod dispatch;

const SEAL_DOMAIN: &[u8] = b"contextdb/prepared-admission/v1";
const MAX_LEASES: usize = 64;
const MAX_LEASE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparationSeal {
    instance: uuid::Uuid,
    issued_tick: u64,
    issued_wall: TimestampMicros,
    fence_digest: String,
    assembly_digest: String,
    wire_digest: ContentDigest,
    wire_bytes: u64,
    current: bool,
    external: bool,
    pending_interpretation: bool,
    capability_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trace_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin_digest: Option<ContentDigest>,
}

#[derive(Clone, Debug)]
struct ModelAdmission {
    request: ObservationId,
    call: ModelCallId,
    run: contextdb_core::AgentRunId,
    working_digest: String,
}

#[derive(Clone, Debug)]
struct LeaseRecord {
    seal: PreparationSeal,
    fence: PrepareFence,
    originals: Vec<OriginalSourceSpan>,
    bytes: u64,
    model: Option<ModelAdmission>,
    trace_controls: Option<router_trace::controls::RouterTraceControls>,
}

#[derive(Debug, Default)]
pub(super) struct LeaseRegistry {
    entries: BTreeMap<String, LeaseRecord>,
}

impl NativeService {
    pub(super) fn lease_tick(&self) -> ServiceResult<u64> {
        u64::try_from(self.lease_started.elapsed().as_micros())
            .map_err(|_| expired("owner monotonic clock overflow"))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "seal binds distinct preparation authority fields"
    )]
    pub(super) fn seal_preparation(
        &self,
        assembly: &OutgoingAssemblyManifest,
        fence: &PrepareFence,
        issued_tick: u64,
        issued_wall: TimestampMicros,
        current: bool,
        external: bool,
        pending_interpretation: bool,
        wire_bytes: u64,
        capability_digest: String,
        trace: Option<&contextdb_service::PreparedRouterTrace>,
    ) -> ServiceResult<String> {
        self.seal_private_cursor(
            SEAL_DOMAIN,
            &PreparationSeal {
                instance: self.lease_instance,
                issued_tick,
                issued_wall,
                fence_digest: canonical_digest(fence)?,
                assembly_digest: canonical_digest(assembly)?,
                wire_digest: assembly.wire_digest,
                wire_bytes,
                current,
                external,
                pending_interpretation,
                capability_digest,
                trace_digest: trace.map(|trace| trace.trace_digest),
                origin_digest: trace.map(|trace| trace.origin_closure_digest),
            },
        )
    }

    fn lease_record_from_prepared(
        &self,
        context: &AuthenticatedRequestContext,
        prepared: &PreparedContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<LeaseRecord> {
        require_capability(context, Capability::Runtime)?;
        budget
            .charge(1, prepared.outgoing.wire.len() as u64)
            .map_err(budget_error)?;
        if prepared.outgoing.wire.len() > 16 * 1024 * 1024
            || prepared.assembly.read_set.originals.len() > 2048
        {
            return Err(exhausted("lease exceeds the bounded assembly profile"));
        }
        let seal: PreparationSeal =
            self.open_private_cursor(SEAL_DOMAIN, &prepared.admission_token)?;
        let binding = &prepared.assembly.read_set.binding;
        let fence: PrepareFence =
            self.open_private_cursor(prepare::PREPARE_DOMAIN, &binding.snapshot)?;
        let assembly_bytes = encode(&prepared.assembly)?;
        budget
            .charge(1, assembly_bytes.len() as u64)
            .map_err(budget_error)?;
        if canonical_digest(&fence)? != seal.fence_digest
            || digest_bytes(&assembly_bytes) != seal.assembly_digest
            || binding.snapshot != binding.authorization
            || binding.snapshot != binding.state
            || binding.valid_until != Some(fence.valid_until)
            || prepared.assembly.wire_digest != seal.wire_digest
            || prepared.outgoing.wire.len() as u64 != seal.wire_bytes
            || ContentDigest::from_bytes(*blake3::hash(&prepared.outgoing.wire).as_bytes())
                != seal.wire_digest
            || prepared.assembly.read_set.scopes != context.request.scopes
            || fence
                .scopes
                .keys()
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>()
                != context.request.scopes
        {
            return Err(invalid(
                "prepared assembly differs from its native admission seal",
            ));
        }
        let mut trace_bytes = 0;
        let trace_controls = match &prepared.router_trace {
            Some(trace) => {
                if seal.trace_digest != Some(trace.trace_digest)
                    || seal.origin_digest != Some(trace.origin_closure_digest)
                    || trace.seal != prepared.admission_token
                    || trace.wire_digest != seal.wire_digest
                    || trace.wire_byte_length != seal.wire_bytes
                {
                    return Err(invalid(
                        "prepared trace differs from its native admission seal",
                    ));
                }
                let envelope = router_trace::prepared_envelope(trace, budget)?;
                if envelope.native_view != fence || envelope.manifest.assembly != prepared.assembly
                {
                    return Err(invalid("prepared trace belongs to another native view"));
                }
                trace_bytes = trace.canonical_json.len() as u64;
                Some(envelope.origins)
            }
            None if seal.trace_digest.is_none() && seal.origin_digest.is_none() => None,
            None => {
                return Err(invalid(
                    "prepared trace was stripped from its sealed assembly",
                ));
            }
        };
        let record = LeaseRecord {
            seal,
            fence,
            originals: prepared.assembly.read_set.originals.clone(),
            bytes: assembly_bytes.len() as u64 + trace_bytes,
            model: None,
            trace_controls,
        };
        self.check_lease_principal(context, &record)?;
        Ok(record)
    }

    pub(super) fn validate_prepared_capture<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        request: &contextdb_service::CaptureRequest,
        prepared: &PreparedContext,
        checkpoint: Option<&CaptureReceipt>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let trace = prepared
            .router_trace
            .as_ref()
            .ok_or_else(|| invalid("prepared capture requires a protected trace"))?;
        let record = self.lease_record_from_prepared(&request.context, prepared, budget)?;
        self.check_lease_clock(&record)?;
        self.check_lease_policy(snapshot, &request.context, &record, budget)?;
        if !self.lease_scopes_current(snapshot, &request.context, &record, budget)? {
            return Err(changed("scope changed before prepared capture"));
        }
        self.verify_router_trace_controls(
            snapshot,
            record
                .trace_controls
                .as_ref()
                .ok_or_else(|| invalid("prepared controls absent"))?,
            budget,
        )?;
        let state = self.current_owned_checkpoint(
            snapshot,
            &request.context,
            checkpoint
                .ok_or_else(|| invalid("prepared capture requires the current owned checkpoint"))?,
        )?;
        let pending = state
            .pending_model
            .as_ref()
            .ok_or_else(|| invalid("run has no pending model request"))?;
        if prepared.assembly.model_profile_digest
            != contextdb_context::router::canonical_digest(&state.model_profile, budget)
                .map_err(router_trace::trace_error)?
            || record.seal.external != state.model_profile.external_processing
        {
            return Err(invalid(
                "prepared reader profile differs from the owned run",
            ));
        }
        let EventPayload::Assembly { manifest } = &request.event.payload else {
            return Err(invalid(
                "prepared capture requires a model request manifest",
            ));
        };
        if request.event.kind != contextdb_core::EventKind::ModelRequested
            || request.event.role != contextdb_core::EventRole::Host
            || request.event.run_id != Some(state.identity.run_id)
            || request.event.session_id != Some(state.identity.session_id)
            || request.event.scope_ids != state.identity.scopes
            || request.event.producer_sequence != state.next_sequence
            || request.event.producer_id != state.producer_id
            || request.event.event_id != pending.request_event
            || manifest.model_call_id != pending.call_id
            || pending.wire_digest.is_some()
            || pending.interrupted_output.is_some()
            || manifest.wire_digest != record.seal.wire_digest
            || manifest.byte_length != record.seal.wire_bytes
            || manifest
                .parts
                .iter()
                .any(|part| matches!(part, contextdb_core::RequestPart::StoredNovel { .. }))
            || manifest.router_trace.as_deref() != Some(&trace.attach(pending.call_id, budget)?)
        {
            return Err(invalid(
                "prepared capture differs from the owned intent and native seal",
            ));
        }
        Ok(())
    }

    fn check_lease_clock(&self, record: &LeaseRecord) -> ServiceResult<()> {
        let now = wall_time()?;
        let duration = record
            .fence
            .valid_until
            .0
            .checked_sub(record.seal.issued_wall.0)
            .and_then(|duration| u64::try_from(duration).ok())
            .ok_or_else(|| expired("lease applicability interval is invalid"))?;
        let deadline = record
            .seal
            .issued_tick
            .checked_add(duration)
            .ok_or_else(|| expired("lease deadline overflow"))?;
        if record.seal.instance != self.lease_instance
            || now < record.seal.issued_wall
            || now >= record.fence.valid_until
            || self.lease_tick()? >= deadline
        {
            return Err(expired(
                "context lease expired or its clock became uncertain",
            ));
        }
        Ok(())
    }

    fn check_lease_principal(
        &self,
        context: &AuthenticatedRequestContext,
        record: &LeaseRecord,
    ) -> ServiceResult<()> {
        for capability in [
            Capability::Runtime,
            Capability::ReadEvidence,
            Capability::RawEvidence,
        ] {
            require_capability(context, capability)?;
        }
        if record.fence.principal != context.authorization_binding_digest()?
            || record.seal.capability_digest != canonical_digest(&context.capability_grants)?
        {
            return Err(permission_denied());
        }
        if record.seal.external {
            require_capability(context, Capability::ModelProcessing)?;
        }
        Ok(())
    }

    fn check_lease_policy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        record: &LeaseRecord,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.charge(1, 0).map_err(budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        self.require_suppression_current(snapshot, &workspace)?;
        if self.raw_authorization_epoch(snapshot, &workspace)? != record.fence.authorization_epoch {
            return Err(changed("source permissions changed after preparation"));
        }
        for span in &record.originals {
            self.check_captured_payload_version(
                snapshot,
                context,
                span.event_id,
                span.payload_digest,
                budget,
            )?;
        }
        if let Some(controls) = &record.trace_controls {
            self.authorize_router_trace_controls(snapshot, context, controls, budget)?;
        }
        Ok(())
    }

    fn lease_scopes_current<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        record: &LeaseRecord,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        for (scope, epoch) in &record.fence.scopes {
            budget.charge(1, 0).map_err(budget_error)?;
            if self.scope_epoch(snapshot, &workspace, *scope)? != *epoch {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn lease_registry(&self) -> ServiceResult<MutexGuard<'_, LeaseRegistry>> {
        self.leases
            .lock()
            .map_err(|_| integrity("context lease registry poisoned"))
    }
}

impl ContextLeasePort for NativeService {
    fn register_context_lease(
        &self,
        context: &AuthenticatedRequestContext,
        prepared: &PreparedContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ContextLease> {
        let record = self.lease_record_from_prepared(context, prepared, budget)?;
        self.check_lease_principal(context, &record)?;
        // Every semantic/capture/policy writer uses this same owner lock. The
        // subscription exists before any later relevant epoch can be published.
        let _publication = self.lock_index_publication(budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.check_lease_clock(&record)?;
        self.check_lease_policy(&snapshot, context, &record, budget)?;
        if !self.lease_scopes_current(&snapshot, context, &record, budget)? {
            return Err(changed("scope changed before lease registration"));
        }
        let mut registry = self.lease_registry()?;
        registry
            .entries
            .retain(|_, entry| self.check_lease_clock(entry).is_ok());
        if registry.entries.len() >= MAX_LEASES
            || registry
                .entries
                .values()
                .map(|entry| entry.bytes)
                .sum::<u64>()
                .saturating_add(record.bytes)
                > MAX_LEASE_BYTES
        {
            return Err(exhausted(
                "release unused context leases before registering more",
            ));
        }
        let mut token_bytes = [0; 32];
        getrandom::fill(&mut token_bytes)
            .map_err(|_| integrity("lease identity entropy unavailable"))?;
        let lease = ContextLease {
            token: encode_hex(&token_bytes),
            valid_until: record.fence.valid_until,
        };
        registry.entries.insert(lease.token.clone(), record);
        Ok(lease)
    }

    fn context_lease_status(
        &self,
        context: &AuthenticatedRequestContext,
        lease: &ContextLease,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ContextLeaseStatus> {
        require_capability(context, Capability::Runtime)?;
        let _publication = self.lock_index_publication(budget)?;
        let registry = self.lease_registry()?;
        let Some(record) = registry.entries.get(&lease.token) else {
            return Ok(ContextLeaseStatus::Expired);
        };
        self.check_lease_principal(context, record)?;
        if self.check_lease_clock(record).is_err() {
            return Ok(ContextLeaseStatus::Expired);
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if !self.lease_scopes_current(&snapshot, context, record, budget)? {
            return Ok(ContextLeaseStatus::Invalidated);
        }
        match self.check_lease_policy(&snapshot, context, record, budget) {
            Ok(()) => Ok(ContextLeaseStatus::Current),
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::IndexTooStale | ErrorCode::PermissionDenied
                ) =>
            {
                Ok(ContextLeaseStatus::Invalidated)
            }
            Err(error) => Err(error),
        }
    }

    fn release_context_lease(
        &self,
        context: &AuthenticatedRequestContext,
        lease: &ContextLease,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        require_capability(context, Capability::Runtime)?;
        let _publication = self.lock_index_publication(budget)?;
        let mut registry = self.lease_registry()?;
        if let Some(record) = registry.entries.get(&lease.token) {
            self.check_lease_principal(context, record)?;
        }
        registry.entries.remove(&lease.token);
        Ok(())
    }

    fn admit_model(
        &self,
        context: &AuthenticatedRequestContext,
        lease: &ContextLease,
        checkpoint: &CaptureReceipt,
        call: ModelCallId,
        request: &CaptureReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.admit_model_dispatch(context, lease, checkpoint, call, request, budget)
    }

    fn admit_tool(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        planned: &PendingToolInvocation,
        action_digest: ContentDigest,
        class: ToolAdmissionClass,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.admit_tool_dispatch(context, checkpoint, planned, action_digest, class, budget)
    }
}

fn wall_time() -> ServiceResult<TimestampMicros> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| expired("wall clock is unavailable"))?;
    Ok(TimestampMicros(
        i64::try_from(elapsed.as_micros()).map_err(|_| expired("wall clock overflow"))?,
    ))
}
fn changed(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::IndexTooStale, message, true).with_context(
        vec![],
        Some("context_lease_invalidated".into()),
        Some("prepare current context and replan".into()),
        None,
    )
}
fn expired(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::ContinuationExpired, message, false).with_context(
        vec![],
        Some("context_lease_expired".into()),
        Some("prepare and register a new context lease".into()),
        None,
    )
}
