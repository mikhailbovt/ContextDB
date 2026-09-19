//! Bounded owned loop, including model-requested original-context expansion.

use contextdb_capture::{
    ExternalTool, ToolAction, ToolObservation, ToolOutcome, ToolReconciliation, ToolReplaySafety,
};

use super::*;
use crate::ToolDispatchFence;

/// Reserved pure operation. Arguments are JSON encoding of up to eight IndexedQuery values.
pub const MEMORY_EXPAND_OPERATION: &str = "contextdb.memory.expand";

/// Host registry; model-provided names never construct arbitrary executable targets.
pub trait RuntimeToolRegistry: std::fmt::Debug + Send + Sync {
    /// Return only a host-authorized adapter for this exact operation.
    fn resolve(&self, operation: &str) -> Option<Arc<dyn ExternalTool>>;
}

/// Text and memory-expansion profile with no external side-effect capabilities.
#[derive(Debug, Default)]
pub struct NoExternalTools;
impl RuntimeToolRegistry for NoExternalTools {
    fn resolve(&self, _: &str) -> Option<Arc<dyn ExternalTool>> {
        None
    }
}

/// Explicit host execution capabilities, supplied independently of model text.
#[derive(Debug)]
pub struct ExecutionAdapters<'a> {
    /// Exact reader/encoder/tokenizer contract.
    pub reader: &'a dyn ReaderAdapter,
    /// Native model disclosure admission.
    pub model_fence: &'a dyn ModelDispatchFence,
    /// Native action admission immediately before a registered target.
    pub tool_fence: &'a dyn ToolDispatchFence,
    /// Bounded authorized host interpretation and projection maintenance.
    pub preparation: &'a dyn PreparationHook,
    /// Registered external operations; memory expansion is built in.
    pub tools: &'a dyn RuntimeToolRegistry,
}

/// Fresh and recovered answers carry distinct evidence; neither invents a model call.
#[derive(Debug)]
pub enum InteractionAnswer {
    /// Answer produced by a newly captured complete request.
    Generated(Box<CompletedTurn>),
    /// Answer recovered from a prior uncertain provider attempt.
    Recovered(Box<RecoveredReply>),
}
impl InteractionAnswer {
    /// Visible response, independently of whether it needed recovery.
    pub fn reply(&self) -> &ReaderReply {
        match self {
            Self::Generated(turn) => &turn.reply,
            Self::Recovered(turn) => &turn.reply,
        }
    }
}

impl<S: OwnedRunPort + PrepareContextPort + PayloadPort + ?Sized> OwnedAgentRuntime<S> {
    /// Drive a captured current interaction through bounded model/tool cycles.
    /// Current input and protocol are retained. Exhaustion returns a resumable
    /// boundary; provider/action uncertainty is reconciled rather than replayed.
    pub fn drive(
        &mut self,
        adapters: &ExecutionAdapters<'_>,
        max_model_calls: u8,
        now: TimestampMicros,
        budget: &mut QueryBudget,
    ) -> ServiceResult<InteractionAnswer> {
        if max_model_calls == 0 || max_model_calls > 8 {
            return Err(invalid("drive allows one to eight new model calls"));
        }
        self.retry_persistence(now, budget)?;
        self.ensure_active()?;
        if let Some(recovered) = self.completed_reply(budget)? {
            return Ok(InteractionAnswer::Recovered(Box::new(recovered)));
        }
        if self.model_outcome_unknown()
            && let Some(recovered) = self.reconcile_model(adapters.reader, now, budget)?
            && recovered.reply.tool_calls.is_empty()
        {
            return Ok(InteractionAnswer::Recovered(Box::new(recovered)));
        }
        let mut tool_steps = 0_u32;
        for _ in 0..max_model_calls {
            while let Some(queued) = self.next_tool(budget)? {
                if tool_steps == 32 {
                    return Err(exhausted("bounded drive tool allowance exhausted"));
                }
                tool_steps += 1;
                let operation = &queued.requested.action.operation;
                let target: Arc<dyn ExternalTool> = if operation == MEMORY_EXPAND_OPERATION {
                    // Validate before recording execution; no LLM grants or arbitrary handlers.
                    expansion_queries(&queued.requested.action)?;
                    Arc::new(ExpansionTarget::new(&queued.requested)?)
                } else {
                    adapters.tools.resolve(operation).ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::PermissionDenied,
                            "model requested an operation absent from the host registry",
                            false,
                        )
                    })?
                };
                let result = self.execute_next_tool(
                    operation,
                    target.as_ref(),
                    adapters.tool_fence,
                    now,
                    budget,
                )?;
                if result == ToolOutcome::Unknown {
                    return Err(ServiceError::new(
                        ErrorCode::ProviderUnavailable,
                        "external action outcome remains unknown; reconcile before continuing",
                        false,
                    ));
                }
            }
            let routes = self.expansion_routes(budget)?;
            let step = self.step(
                adapters.reader,
                adapters.model_fence,
                adapters.preparation,
                &routes,
                now,
                budget,
            )?;
            if step.reply.tool_calls.is_empty() {
                return Ok(InteractionAnswer::Generated(Box::new(step)));
            }
        }
        Err(exhausted(
            "bounded drive model allowance exhausted; pending protocol is checkpointed",
        ))
    }

    /// The most recent successful expansion specifies the next discovery frontier.
    /// Recover it from originals after restart; failed/blocked requests do not apply.
    fn expansion_routes(&self, budget: &mut QueryBudget) -> ServiceResult<Vec<IndexedQuery>> {
        let Some(group) = self.state.groups.last() else {
            return Ok(vec![]);
        };
        let mut completed = BTreeSet::new();
        for message in group
            .messages
            .iter()
            .filter(|message| message.role == OutgoingRole::Tool)
        {
            charge(budget, 1, 0)?;
            let original = self.owner.read_original(ReadOriginalRequest {
                context: self.context.clone(),
                event_id: message.source.event_id,
                after_receipt: None,
            })?;
            if original.event.kind == EventKind::ToolCompleted
                && let Some(id) = &message.tool_result
            {
                completed.insert(id.clone());
            }
        }
        for message in group
            .messages
            .iter()
            .rev()
            .filter(|message| !message.tool_calls.is_empty())
        {
            charge(budget, 1, message.source.end - message.source.start)?;
            let bytes = self
                .owner
                .read_original_span(&self.context, &message.source)?;
            let response: ReaderReply = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("expansion proposal protocol invalid"))?;
            for tool in response.tool_calls.iter().rev() {
                if tool.action.operation == MEMORY_EXPAND_OPERATION
                    && completed.contains(&tool.call_id.to_string())
                {
                    return expansion_queries(&tool.action);
                }
            }
        }
        Ok(vec![])
    }

    fn completed_reply(&self, budget: &mut QueryBudget) -> ServiceResult<Option<RecoveredReply>> {
        if self.state.groups.last().is_none_or(|group| !group.complete) {
            return Ok(None);
        }
        let Some(event_id) = self.state.last_model_output else {
            return Ok(None);
        };
        charge(budget, 1, 0)?;
        let original = self.owner.read_original(ReadOriginalRequest {
            context: self.context.clone(),
            event_id,
            after_receipt: None,
        })?;
        let source = RawSource::from(&original.event);
        let size = source
            .byte_length
            .ok_or_else(|| invalid("complete reply original unavailable"))?;
        let digest = source
            .payload_digest
            .ok_or_else(|| invalid("complete reply digest unavailable"))?;
        charge(budget, 1, size)?;
        let bytes = self.owner.read_original_span(
            &self.context,
            &OriginalSourceSpan {
                event_id,
                payload_digest: digest,
                start: 0,
                end: size,
                span_digest: digest,
            },
        )?;
        let Some(EventProvenance::ModelOutput { format, .. }) = original.event.provenance else {
            return Err(invalid("completed reply provenance missing"));
        };
        let reply = match format {
            ModelOutputFormat::PlainText => ReaderReply::text(
                String::from_utf8(bytes).map_err(|_| invalid("completed reply is not UTF-8"))?,
            ),
            ModelOutputFormat::ProtocolJson => serde_json::from_slice(&bytes)
                .map_err(|_| invalid("completed reply protocol invalid"))?,
            ModelOutputFormat::OpaquePartial => {
                return Err(invalid("partial output cannot complete an interaction"));
            }
        };
        if !reply.tool_calls.is_empty() {
            return Err(invalid(
                "terminal interaction retains uncompleted tool protocol",
            ));
        }
        Ok(Some(RecoveredReply {
            reply,
            output_receipt: original.receipt,
        }))
    }
}

fn expansion_queries(action: &ToolAction) -> ServiceResult<Vec<IndexedQuery>> {
    if action.operation != MEMORY_EXPAND_OPERATION
        || action.input.len() > 32 * 1024
        || action.expected_target_version.is_some()
    {
        return Err(invalid(
            "memory expansion requires bounded query JSON and no external target precondition",
        ));
    }
    let queries: Vec<IndexedQuery> = serde_json::from_slice(&action.input)
        .map_err(|_| invalid("memory expansion query JSON invalid"))?;
    if queries.is_empty() || queries.len() > 8 {
        return Err(invalid("memory expansion requires one to eight routes"));
    }
    Ok(queries)
}

// This operation validates a source-addressed request for the next compiler pass.
// It has no external effect. Recovery recomputes this deterministic result; actual
// source reads still happen under fresh policy, shared budgets and the model fence.
struct ExpansionTarget {
    call_id: ToolCallId,
    action_digest: ContentDigest,
}
impl ExpansionTarget {
    fn new(tool: &crate::RequestedTool) -> ServiceResult<Self> {
        let bytes =
            serde_json::to_vec(&tool.action).map_err(|_| invalid("expansion encoding failed"))?;
        Ok(Self {
            call_id: tool.call_id,
            action_digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
        })
    }
    fn observation() -> ToolObservation {
        ToolObservation { outcome: ToolOutcome::Completed,
            bytes: Some(br#"{"context_expansion":"accepted_for_next_prepare","coverage":"not_yet_evaluated"}"#.to_vec()),
            media_type: "application/json".into(), upstream_truncated: false }
    }
}
impl ExternalTool for ExpansionTarget {
    fn replay_safety(&self) -> ToolReplaySafety {
        ToolReplaySafety::NoAutomaticReplay
    }
    fn execute(
        &self,
        _: &AuthenticatedRequestContext,
        call_id: ToolCallId,
        action: &ToolAction,
    ) -> ServiceResult<ToolObservation> {
        expansion_queries(action)?;
        if call_id != self.call_id
            || ContentDigest::from_bytes(
                *blake3::hash(
                    &serde_json::to_vec(action)
                        .map_err(|_| invalid("expansion encoding failed"))?,
                )
                .as_bytes(),
            ) != self.action_digest
        {
            return Err(invalid("expansion action binding differs"));
        }
        Ok(Self::observation())
    }
    fn reconcile(
        &self,
        _: &AuthenticatedRequestContext,
        call_id: ToolCallId,
        action_digest: ContentDigest,
    ) -> ServiceResult<ToolReconciliation> {
        if call_id != self.call_id || action_digest != self.action_digest {
            return Err(invalid("expansion reconciliation binding differs"));
        }
        Ok(ToolReconciliation::Observed {
            action_digest,
            observation: Self::observation(),
        })
    }
}
