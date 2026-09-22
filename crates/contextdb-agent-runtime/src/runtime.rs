use std::{collections::BTreeSet, sync::Arc, time::Instant};

use contextdb_capture::{CaptureHost, PendingToolCapture};
use contextdb_context::*;
use contextdb_continuity::*;
use contextdb_core::*;
use contextdb_recall::{IndexedQuery, QueryBudget};
use contextdb_service::*;

use super::{
    CacheResidencyController, CacheResidencyPolicy, ModelDispatchFence, ModelReconciliation,
    PreparationHook, ReaderAdapter, ReaderOutcome, ReaderReply, RollingPolicy, RuntimeMeasurements,
    StepMeasurement, charge, context_error, conversation_routes, exhausted, invalid, rolling,
    telemetry::{self, Telemetry},
};

mod drive;
mod model_output;
mod persistence;
mod tools;
pub use drive::*;
pub use tools::QueuedTool;

/// Host configuration. Changing control text changes the next complete request.
#[derive(Clone, Debug)]
pub struct RuntimeSettings {
    /// Trusted host control and tool-definition messages only.
    pub control: Vec<OutgoingMessage>,
    /// Authenticated context use.
    pub purpose: PackPurpose,
    /// Additional recalled context, including all mandatory closure.
    pub memory_budget: ContextBudgets,
    /// Complete wire and input ceiling after output/safety reservation.
    pub outgoing_budget: OutgoingBudget,
    /// High/low thresholds and bounded retry policy.
    pub rolling: RollingPolicy,
    /// Optional measured cache hysteresis. Fixed thresholds are the default profile.
    pub cache_residency: Option<CacheResidencyPolicy>,
    /// Metadata limits for automatic raw discovery, such as a replay input cutoff.
    /// Default selects all authorized originals. Explicit expansion routes and
    /// mandatory current state remain separate; this is not an access policy.
    pub automatic_recall_filter: RawFilter,
}
impl RuntimeSettings {
    fn validate(&self, profile: &ModelProfile) -> ServiceResult<()> {
        profile.validate().map_err(context_error)?;
        if self.automatic_recall_filter.event_ids.len() > 64 {
            return Err(invalid(
                "automatic recall identity filter exceeds 64 originals",
            ));
        }
        if let Some(range) = self.automatic_recall_filter.recorded_range {
            range
                .validate()
                .map_err(|_| invalid("automatic recall time range is invalid"))?;
        }
        self.rolling
            .validate(self.outgoing_budget.max_input_tokens)?;
        if let Some(cache) = self.cache_residency {
            cache.validate(self.rolling, self.outgoing_budget.max_input_tokens)?;
        }
        if self
            .outgoing_budget
            .max_input_tokens
            .checked_add(self.outgoing_budget.safety_tokens)
            .is_none_or(|tokens| tokens > profile.available_input_tokens())
            || self.outgoing_budget.max_wire_bytes == 0
            || self.outgoing_budget.max_wire_bytes > 16 * 1024 * 1024
            || self.control.len() > 32
            || self.control.iter().any(|item| {
                !matches!(
                    item.zone,
                    OutgoingZone::Control | OutgoingZone::ToolDefinitions
                ) || !item.originals.is_empty()
                    || !item.tool_calls.is_empty()
                    || item.tool_result.is_some()
            })
        {
            return Err(invalid(
                "runtime settings exceed the reader or control profile",
            ));
        }
        Ok(())
    }
}

/// Stable creation request. Retain these values across an uncertain start receipt.
#[derive(Clone, Debug)]
pub struct StartRun {
    /// Host-established owner and exact scopes.
    pub identity: OwnedRunIdentity,
    /// Initial reader contract.
    pub model_profile: ModelProfile,
    /// Fixed first checkpoint time for exact retries.
    pub recorded_at: TimestampMicros,
}

#[derive(Clone, Debug)]
enum PendingCapture {
    Conversation(CaptureRequest),
    ModelRequest {
        request: CaptureRequest,
        prepared: Box<PreparedContext>,
    },
}
impl PendingCapture {
    fn request(&self) -> &CaptureRequest {
        match self {
            Self::Conversation(request) | Self::ModelRequest { request, .. } => request,
        }
    }
}

#[derive(Debug)]
enum CallPhase {
    Ready,
    Planned,
    Captured {
        prepared: Box<PreparedContext>,
        receipt: CaptureReceipt,
    },
    Unknown,
}

/// A model step is returned only after output capture and checkpoint receipt.
/// Tool calls, when present, leave the interaction open until their results arrive.
#[derive(Debug)]
pub struct CompletedTurn {
    /// Exact captured visible model text.
    pub reply: ReaderReply,
    /// Durable output identity for deduplicated presentation.
    pub output_receipt: CaptureReceipt,
    /// Complete request and discovery evidence used for this call.
    pub prepared: PreparedContext,
    /// Number of completed groups removed from resident history in this step.
    pub evicted_groups: usize,
}

/// A recovered response retains its own receipt; no fresh preparation is invented.
#[derive(Debug)]
pub struct RecoveredReply {
    /// Actual recovered and captured output.
    pub reply: ReaderReply,
    /// Durable result occurrence.
    pub output_receipt: CaptureReceipt,
}

/// Owns mutable message residency and operational state; the native owner remains
/// the only publication authority. All failed capture/checkpoint requests stay
/// resident until acknowledged. No automatic replay of an uncertain model call.
pub struct OwnedAgentRuntime<S: ?Sized> {
    owner: Arc<S>,
    context: AuthenticatedRequestContext,
    state: OwnedRunCheckpoint,
    checkpoint_receipt: CaptureReceipt,
    settings: RuntimeSettings,
    pending_capture: Option<PendingCapture>,
    pending_checkpoint: Option<SaveRunCheckpointRequest>,
    pending_tool_capture: Option<Box<PendingToolCapture>>,
    phase: CallPhase,
    telemetry: Telemetry,
    cache_controller: CacheResidencyController,
}
impl<S: ?Sized> std::fmt::Debug for OwnedAgentRuntime<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedAgentRuntime")
            .field("run", &self.state.identity.run_id)
            .field("revision", &self.state.revision)
            .field("hot_groups", &self.state.groups.len())
            .field("capture_pending", &self.pending_capture.is_some())
            .field("checkpoint_pending", &self.pending_checkpoint.is_some())
            .finish_non_exhaustive()
    }
}

impl<S: OwnedRunPort + PrepareContextPort + PayloadPort + ?Sized> OwnedAgentRuntime<S> {
    /// Publish the initial checkpoint before accepting conversational input.
    pub fn start(
        owner: Arc<S>,
        context: AuthenticatedRequestContext,
        start: StartRun,
        settings: RuntimeSettings,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        settings.validate(&start.model_profile)?;
        owner.recover_record_writes(&context, budget)?;
        let run_uuid = start.identity.run_id.as_uuid();
        let checkpoint = OwnedRunCheckpoint {
            version: 1,
            identity: start.identity,
            revision: 1,
            producer_id: StreamId::from_uuid(run_uuid)
                .map_err(|_| invalid("run producer invalid"))?,
            next_sequence: 2,
            recorded_at: start.recorded_at,
            model_profile: start.model_profile,
            groups: vec![],
            obligations: vec![],
            pending_model: None,
            pending_tool: None,
            last_model_output: None,
            status: OwnedRunStatus::Active,
        };
        let saved = owner.save_run_checkpoint(
            SaveRunCheckpointRequest {
                context: context.clone(),
                idempotency_key: format!("run/{}/checkpoint/1", checkpoint.identity.run_id),
                event_id: ObservationId::from_uuid(run_uuid)
                    .map_err(|_| invalid("run event invalid"))?,
                expected_revision: 0,
                checkpoint,
            },
            budget,
        )?;
        Ok(Self {
            owner,
            context,
            state: saved.checkpoint,
            checkpoint_receipt: saved.receipt,
            settings,
            pending_capture: None,
            pending_checkpoint: None,
            pending_tool_capture: None,
            phase: CallPhase::Ready,
            telemetry: Telemetry::default(),
            cache_controller: CacheResidencyController::default(),
        })
    }

    /// Rehydrate an unchanged run head and its bounded uncheckpointed capture tail.
    /// A captured request without a result becomes Unknown, never an automatic call.
    pub fn resume(
        owner: Arc<S>,
        context: AuthenticatedRequestContext,
        run: AgentRunId,
        settings: RuntimeSettings,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        owner.recover_record_writes(&context, budget)?;
        let saved = owner
            .load_run_checkpoint(&context, run, budget)?
            .ok_or_else(|| {
                ServiceError::new(ErrorCode::NotFound, "owned run has no checkpoint", false)
            })?;
        settings.validate(&saved.checkpoint.model_profile)?;
        let tail = owner.read_run_tail(&context, &saved.receipt, budget)?;
        if tail.more {
            return Err(exhausted(
                "uncheckpointed tail requires explicit paged recovery",
            ));
        }
        let mut runtime = Self {
            owner,
            context,
            state: saved.checkpoint,
            checkpoint_receipt: saved.receipt,
            settings,
            pending_capture: None,
            pending_checkpoint: None,
            pending_tool_capture: None,
            phase: CallPhase::Ready,
            telemetry: Telemetry::resumed(),
            cache_controller: CacheResidencyController::default(),
        };
        if let Some(pending) = &runtime.state.pending_model {
            runtime.phase = if pending.wire_digest.is_some() {
                CallPhase::Unknown
            } else {
                CallPhase::Planned
            };
        }
        let changed = !tail.events.is_empty();
        for original in tail.events {
            runtime.apply_original(&original)?;
        }
        // No request receipt after the planned checkpoint proves no permitted send.
        if matches!(runtime.phase, CallPhase::Planned) {
            runtime.state.pending_model = None;
            runtime.phase = CallPhase::Ready;
            runtime.save_checkpoint(now, budget)?;
        } else if changed && runtime.checkpoint_position_available() {
            runtime.save_checkpoint(now, budget)?;
        }
        rolling::rehydrate(
            runtime.owner.as_ref(),
            &runtime.context,
            &runtime.state,
            &runtime.settings.control,
            budget,
        )?;
        Ok(runtime)
    }

    /// Source-addressed operational state; no hidden reasoning or lossy summary.
    pub fn checkpoint(&self) -> &OwnedRunCheckpoint {
        &self.state
    }

    /// True means outcome reconciliation is required before any further model call.
    pub fn model_outcome_unknown(&self) -> bool {
        matches!(self.phase, CallPhase::Unknown)
    }

    /// Drain bounded process-local measurements for a complete host run report.
    /// Keep failed steps and missing counters; never price missing history as free.
    pub fn drain_measurements(&mut self) -> RuntimeMeasurements {
        self.telemetry.drain()
    }

    /// Capture a complete user message before it can become hot context.
    pub fn accept_user(
        &mut self,
        text: String,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CaptureReceipt> {
        self.ensure_active()?;
        if !matches!(self.phase, CallPhase::Ready)
            || self
                .state
                .groups
                .last()
                .is_some_and(|group| !group.complete)
        {
            return Err(invalid(
                "finish or reconcile the current interaction before accepting another",
            ));
        }
        if text.is_empty() || text.len() > 1024 * 1024 {
            return Err(invalid(
                "current text requires 1..1048576 bytes; larger inputs need a range adapter",
            ));
        }
        if self.state.groups.len() == 64
            && rolling::evict(&mut self.state, self.settings.rolling) == 0
        {
            return Err(exhausted(
                "no complete interaction group can leave the hot window",
            ));
        }
        let request = self.event(
            EventKind::MessageCreated,
            EventRole::User,
            text,
            now,
            ObservationId::new(),
        )?;
        self.pending_capture = Some(PendingCapture::Conversation(request));
        let receipt = self.flush_capture(budget)?;
        self.save_checkpoint(now, budget)?;
        Ok(receipt)
    }

    /// Reattempt only retained local persistence. This never repeats a model call.
    pub fn retry_persistence(
        &mut self,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CaptureReceipt> {
        if self.pending_tool_capture.is_some() {
            self.retry_tool_persistence(now, budget)?;
            return Ok(self.checkpoint_receipt.clone());
        }
        if self.pending_capture.is_none() && self.pending_checkpoint.is_none() {
            return Ok(self.checkpoint_receipt.clone());
        }
        if self.pending_capture.is_some() {
            self.flush_capture(budget)?;
        }
        if matches!(self.phase, CallPhase::Captured { .. }) && self.pending_checkpoint.is_none() {
            return Ok(self.checkpoint_receipt.clone());
        }
        self.save_checkpoint(now, budget)?;
        Ok(self.checkpoint_receipt.clone())
    }

    /// Switch readers only at a known boundary; the next request is fully rebuilt.
    pub fn switch_reader(
        &mut self,
        reader: &dyn ReaderAdapter,
        settings: RuntimeSettings,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.ensure_active()?;
        if !matches!(self.phase, CallPhase::Ready) || self.state.pending_tool.is_some() {
            return Err(invalid(
                "reconcile pending model work before switching readers",
            ));
        }
        validate_reader(reader)?;
        settings.validate(&reader.profile())?;
        self.validate_reader_protocol(&reader.profile())?;
        self.state.model_profile = reader.profile();
        self.cache_controller = CacheResidencyController::default();
        self.settings = settings;
        self.save_checkpoint(now, budget)
    }

    /// Add a source-backed obligation; terminal obligations have explicit unpinning.
    pub fn add_obligation(
        &mut self,
        obligation: ScopedObligation,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.ensure_active()?;
        if !matches!(self.phase, CallPhase::Ready) || self.state.pending_tool.is_some() {
            return Err(invalid("pending call freezes working state"));
        }
        let mut next = self.state.clone();
        next.obligations.push(obligation);
        next.validate()
            .map_err(|_| invalid("invalid or excessive obligation"))?;
        self.state = next;
        self.save_checkpoint(now, budget)
    }

    /// Release an obligation's active source pin without deleting its original.
    pub fn close_obligation(
        &mut self,
        id: &str,
        status: ObligationStatus,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.ensure_active()?;
        if !matches!(self.phase, CallPhase::Ready) || self.state.pending_tool.is_some() {
            return Err(invalid("pending call freezes working state"));
        }
        self.state
            .close_obligation(id, status)
            .map_err(|_| invalid("invalid obligation transition"))?;
        let mut retained_terminal = 0;
        self.state.obligations.reverse();
        self.state.obligations.retain(|item| {
            if item.status == ObligationStatus::Open {
                true
            } else {
                retained_terminal += 1;
                retained_terminal <= 32
            }
        });
        self.state.obligations.reverse();
        self.save_checkpoint(now, budget)
    }

    /// Terminate a known run. Cancellation releases open obligations; completion
    /// requires them already closed. Uncertain calls must first be reconciled.
    pub fn finish(
        &mut self,
        status: OwnedRunStatus,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.ensure_active()?;
        if status == OwnedRunStatus::Active
            || !matches!(self.phase, CallPhase::Ready)
            || self.state.pending_tool.is_some()
        {
            return Err(invalid(
                "terminal transition requires a known model boundary",
            ));
        }
        let mut next = self.state.clone();
        if status == OwnedRunStatus::Cancelled {
            for item in &mut next.obligations {
                if item.status == ObligationStatus::Open {
                    item.status = ObligationStatus::Cancelled;
                }
            }
        } else if next.groups.iter().any(|group| !group.complete) {
            return Err(invalid("complete the current interaction before finishing"));
        }
        // Termination releases residency, including proposals that were never
        // dispatched. Prior checkpoints and original events remain immutable.
        next.groups.clear();
        next.last_model_output = None;
        next.status = status;
        next.validate()
            .map_err(|_| invalid("terminal run retains pending obligations"))?;
        self.state = next;
        self.save_checkpoint(now, budget)
    }

    /// Automatically rotate, discover, compile, capture, fence and send one turn.
    /// Extra discovery routes are bounded host/model expansion requests; ordinary
    /// turns always derive their own lexical routes without a user search command.
    pub fn step(
        &mut self,
        reader: &dyn ReaderAdapter,
        fence: &dyn ModelDispatchFence,
        hook: &dyn PreparationHook,
        extra_routes: &[IndexedQuery],
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CompletedTurn> {
        let started = Instant::now();
        let work = budget.remaining_work();
        let bytes = budget.remaining_bytes();
        let mut measurement = StepMeasurement {
            run: Some(self.state.identity.run_id),
            ..StepMeasurement::default()
        };
        let result = self.step_measured(
            reader,
            fence,
            hook,
            extra_routes,
            now,
            budget,
            &mut measurement,
        );
        measurement.elapsed_micros = telemetry::elapsed(started);
        measurement.work_units = work.saturating_sub(budget.remaining_work());
        measurement.charged_bytes = bytes.saturating_sub(budget.remaining_bytes());
        measurement.error = result.as_ref().err().map(|error| error.code);
        measurement.outcome_unknown = self.model_outcome_unknown();
        self.telemetry.push(measurement);
        result
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "step instrumentation shares the bounded attempt"
    )]
    fn step_measured(
        &mut self,
        reader: &dyn ReaderAdapter,
        fence: &dyn ModelDispatchFence,
        hook: &dyn PreparationHook,
        extra_routes: &[IndexedQuery],
        now: TimestampMicros,
        budget: &mut QueryBudget,
        measurement: &mut StepMeasurement,
    ) -> ServiceResult<CompletedTurn> {
        self.ensure_active()?;
        validate_reader(reader)?;
        self.owner.recover_record_writes(&self.context, budget)?;
        self.validate_reader_protocol(&reader.profile())?;
        if reader.profile() != self.state.model_profile {
            return Err(invalid("reader switch requires an explicit checkpoint"));
        }
        if extra_routes.len() > 8 {
            return Err(exhausted("expansion exceeds eight routes"));
        }
        if matches!(self.phase, CallPhase::Unknown) {
            return Err(unknown());
        }
        if self.state.pending_tool.is_some() || self.has_outstanding_tools() {
            return Err(invalid(
                "complete or reconcile the pending tool protocol before the next model call",
            ));
        }
        if self.state.groups.last().is_none_or(|group| group.complete) {
            return Err(invalid("no current interaction awaits a model response"));
        }
        let mut removed = 0;
        let (rolling_policy, reason) = self.cache_controller.select(
            self.settings.rolling,
            self.settings.cache_residency,
            self.settings.outgoing_budget.max_input_tokens,
        )?;
        measurement.residency_reason = reason;
        measurement.rotation_high_tokens = rolling_policy.high_tokens;
        if matches!(self.phase, CallPhase::Ready | CallPhase::Planned) {
            if self.state.pending_model.is_none() {
                self.state.pending_model = Some(PendingModelCall {
                    call_id: ModelCallId::new(),
                    request_event: ObservationId::new(),
                    wire_digest: None,
                    interrupted_output: None,
                });
                self.phase = CallPhase::Planned;
                self.save_checkpoint(now, budget)?;
            }
            let mut prepared = None;
            for attempt in 0..self.settings.rolling.max_prepare_attempts {
                let started = Instant::now();
                let rotation = rolling::rotate(
                    self.owner.as_ref(),
                    &self.context,
                    &mut self.state,
                    &self.settings.control,
                    reader,
                    rolling_policy,
                    budget,
                );
                measurement.rotation_micros += telemetry::elapsed(started);
                let (base, evicted) = rotation?;
                removed += evicted;
                measurement.evicted_groups += evicted as u32;
                if evicted != 0 {
                    self.save_checkpoint(now, budget)?;
                }
                let started = Instant::now();
                let hook_result = hook.before_prepare(&self.context, budget);
                measurement.preparation_hook_micros += telemetry::elapsed(started);
                hook_result?;
                let mut routes = extra_routes.to_vec();
                for mut route in conversation_routes(&base) {
                    route.filter = self.settings.automatic_recall_filter.clone();
                    if routes.len() == 8 {
                        break;
                    }
                    if !routes.contains(&route) {
                        routes.push(route);
                    }
                }
                let request = PrepareContextRequest {
                    context: self.context.clone(),
                    pack_id: ContextPackId::new(),
                    purpose: self.settings.purpose,
                    known_at: None,
                    valid_at: None,
                    after_receipt: Some(self.checkpoint_receipt.clone()),
                    raw_queries: routes,
                    required_facets: vec![],
                    memory_budget: self.settings.memory_budget,
                    model_profile: self.state.model_profile.clone(),
                    base,
                    outgoing_budget: self.settings.outgoing_budget,
                    explicit_memory_request: false,
                };
                let started = Instant::now();
                measurement.prepare_attempts += 1;
                let preparation =
                    self.owner
                        .prepare_context(request, reader.tokenizer(), reader, budget);
                measurement.prepare_micros += telemetry::elapsed(started);
                match preparation {
                    Ok(result) => {
                        if measurement.prepare_attempts == 1 {
                            measurement.scorer_micros = Some(result.scorer_micros);
                        }
                        prepared = Some(result);
                        break;
                    }
                    Err(error)
                        if matches!(
                            error.code,
                            ErrorCode::BudgetExhausted | ErrorCode::ResourceExhausted
                        ) && attempt + 1 < self.settings.rolling.max_prepare_attempts =>
                    {
                        charge(budget, 1, 0)?;
                        let evicted = rolling::evict(&mut self.state, self.settings.rolling);
                        if evicted == 0 {
                            return Err(error);
                        }
                        removed += evicted;
                        measurement.evicted_groups += evicted as u32;
                        self.save_checkpoint(now, budget)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            let prepared =
                prepared.ok_or_else(|| exhausted("bounded context preparation did not fit"))?;
            let pending = self
                .state
                .pending_model
                .as_ref()
                .ok_or_else(|| invalid("model intent absent"))?;
            let manifest = reader.capture_manifest(
                pending.call_id,
                &prepared.messages,
                &prepared.outgoing,
                budget,
            )?;
            if manifest.model_call_id != pending.call_id
                || manifest.wire_digest != prepared.assembly.wire_digest
                || manifest.byte_length != prepared.outgoing.wire.len() as u64
            {
                return Err(invalid(
                    "reader capture manifest differs from the prepared wire",
                ));
            }
            telemetry::manifest_counts(&manifest, measurement);
            let mut request = self.event(
                EventKind::ModelRequested,
                EventRole::Host,
                String::new(),
                now,
                pending.request_event,
            )?;
            request.event.payload = EventPayload::Assembly { manifest };
            self.pending_capture = Some(PendingCapture::ModelRequest {
                request,
                prepared: Box::new(prepared),
            });
            self.flush_capture(budget)?;
        }
        let CallPhase::Captured { prepared, receipt } = &self.phase else {
            return Err(unknown());
        };
        let call = self
            .state
            .pending_model
            .as_ref()
            .ok_or_else(|| invalid("model intent absent"))?
            .clone();
        measurement.call = Some(call.call_id);
        if let Err(error) = fence.before_model(
            &self.context,
            &self.checkpoint_receipt,
            call.call_id,
            receipt,
            prepared,
            budget,
        ) {
            self.state.pending_model = None;
            self.phase = CallPhase::Ready;
            self.save_checkpoint(now, budget)?;
            return Err(error);
        }
        let prepared = (**prepared).clone();
        self.telemetry.wire(&prepared.outgoing.wire, measurement);
        // From this point an error or process loss is an uncertain provider outcome.
        self.phase = CallPhase::Unknown;
        measurement.dispatched = true;
        let started = Instant::now();
        let outcome = reader.complete(call.call_id, &prepared.outgoing);
        measurement.reader_micros = Some(telemetry::elapsed(started));
        let usage = reader.usage(call.call_id);
        if usage.validate().is_ok() {
            measurement.usage = usage;
        } else {
            measurement.invalid_usage = true;
        }
        self.cache_controller.observe(&measurement.usage);
        let reply = match outcome {
            Ok(ReaderOutcome::Completed(reply)) => reply,
            Ok(ReaderOutcome::Interrupted(output)) => {
                self.capture_interruption(&call, output, now, budget)?;
                return Err(unknown());
            }
            Err(_) => {
                self.save_checkpoint(now, budget)?;
                return Err(unknown());
            }
        };
        let output_receipt = self.capture_reply(&call, &reply, now, budget)?;
        Ok(CompletedTurn {
            reply,
            output_receipt,
            prepared,
            evicted_groups: removed,
        })
    }

    /// Resolve an uncertain captured request without ever resending it.
    pub fn reconcile_model(
        &mut self,
        reader: &dyn ReaderAdapter,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<RecoveredReply>> {
        self.ensure_active()?;
        if !matches!(self.phase, CallPhase::Unknown) || reader.profile() != self.state.model_profile
        {
            return Err(invalid("no matching uncertain reader attempt"));
        }
        if !reader.capabilities().can_reconcile {
            return Err(unknown());
        }
        let call = self
            .state
            .pending_model
            .as_ref()
            .ok_or_else(|| invalid("model intent absent"))?
            .clone();
        let wire = call
            .wire_digest
            .ok_or_else(|| invalid("captured model wire absent"))?;
        match reader.reconcile(call.call_id, wire)? {
            ModelReconciliation::Completed { wire_digest, reply } if wire_digest == wire => {
                let output_receipt = self.capture_reply(&call, &reply, now, budget)?;
                Ok(Some(RecoveredReply {
                    reply,
                    output_receipt,
                }))
            }
            ModelReconciliation::NotAccepted { wire_digest } if wire_digest == wire => {
                if call.interrupted_output.is_some() {
                    return Err(invalid(
                        "provider denied acceptance despite captured output",
                    ));
                }
                self.state.pending_model = None;
                self.phase = CallPhase::Ready;
                self.save_checkpoint(now, budget)?;
                Ok(None)
            }
            ModelReconciliation::Unknown => Err(unknown()),
            _ => Err(invalid(
                "provider reconciliation belongs to another request",
            )),
        }
    }

    fn ensure_active(&self) -> ServiceResult<()> {
        if self.pending_capture.is_some()
            || self.pending_checkpoint.is_some()
            || self.pending_tool_capture.is_some()
        {
            return Err(ServiceError::new(
                ErrorCode::Unavailable,
                "retry retained persistence before further work",
                true,
            ));
        }
        if self.state.status != OwnedRunStatus::Active {
            return Err(invalid("run is terminal"));
        }
        Ok(())
    }
}

fn validate_reader(reader: &dyn ReaderAdapter) -> ServiceResult<()> {
    let capabilities = reader.capabilities();
    if capabilities.history_contract.trim().is_empty()
        || capabilities.history_contract.len() > 4096
        || reader.profile().tokenizer_id != reader.tokenizer().id()
        || reader.tokenizer_id() != reader.tokenizer().id()
    {
        return Err(invalid(
            "reader lacks a compatible documented clean-request contract",
        ));
    }
    reader.profile().validate().map_err(context_error)
}
fn unknown() -> ServiceError {
    ServiceError::new(
        ErrorCode::ProviderUnavailable,
        "model outcome is unknown; reconcile the captured attempt before continuing",
        false,
    )
}
