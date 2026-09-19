use contextdb_capture::ToolAction;
use contextdb_context::{
    EncodedOutgoing, ModelProfile, OutgoingEncoder, OutgoingMessage, TokenCounter,
};
use contextdb_core::{ContentDigest, ModelCallId, ModelRequestManifest, ToolCallId};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, CaptureReceipt, PreparedContext, ServiceResult,
};
use serde::{Deserialize, Serialize};

/// Host-verified history contract. An opaque persistent conversation is excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderHistory {
    /// Every request is self-contained and includes all protocol bytes.
    Stateless,
    /// Every request replaces all prior provider state with these exact messages.
    Replaceable,
}

/// Adapter promises are explicit and must be established by integration tests.
#[derive(Clone, Debug)]
pub struct ReaderCapabilities {
    /// How a complete owned request replaces context.
    pub history: ReaderHistory,
    /// Human-readable reference to the adapter's tested clean-request behavior.
    pub history_contract: String,
    /// Provider-side outcome lookup is supported; false means uncertain calls stop.
    pub can_reconcile: bool,
}

/// Complete visible text and fully observed action proposals.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderReply {
    /// Exact visible output; hidden reasoning is never part of this type.
    pub text: String,
    /// Fully observed protocol actions, never tool-execution authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<RequestedTool>,
}

impl ReaderReply {
    /// A completed plain-text response with no pending protocol action.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            tool_calls: vec![],
        }
    }
}

/// Model-proposed action. The host registry and dispatch fence decide execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedTool {
    /// Stable action identity from this reader adapter's protocol mapping.
    pub call_id: ToolCallId,
    /// Exact observed operation, arguments and proposed target precondition.
    pub action: ToolAction,
}
impl std::fmt::Debug for ReaderReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderReply")
            .field("byte_length", &self.text.len())
            .field("tool_calls", &self.tool_calls.len())
            .finish()
    }
}

/// Buffered reader observation. A provider error is allowed only when it exposed
/// no output bytes; otherwise return Interrupted. Streaming adapters must persist
/// chunks before exposing them and require their own incremental capture contract.
#[derive(Debug)]
pub enum ReaderOutcome {
    /// The provider completed this response, including its action protocol.
    Completed(ReaderReply),
    /// Exact available output; no action inside these bytes may be dispatched.
    Interrupted(PartialReaderOutput),
}

/// Observed incomplete output, retained independently of provider recovery.
#[derive(Clone)]
pub struct PartialReaderOutput {
    /// Exact visible text or protocol bytes; never hidden reasoning.
    pub bytes: Vec<u8>,
    /// Source content type, not an instruction to execute or interpret the body.
    pub media_type: String,
}
impl std::fmt::Debug for PartialReaderOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialReaderOutput")
            .field("byte_length", &self.bytes.len())
            .field("media_type", &self.media_type)
            .finish()
    }
}

/// Authoritative provider recovery, bound to the exact transmitted request.
#[derive(Clone, Debug)]
pub enum ModelReconciliation {
    /// The provider recovered the visible result for this exact wire.
    Completed {
        /// Exact reconciled provider request.
        wire_digest: ContentDigest,
        /// Recovered visible result.
        reply: ReaderReply,
    },
    /// The provider established that these bytes were never accepted.
    NotAccepted {
        /// Exact request the provider confirmed it never accepted.
        wire_digest: ContentDigest,
    },
    /// Stop; the runtime must not invent a result or repeat the request.
    Unknown,
}

/// Provider-neutral reader. Encoder/tokenizer cover the whole actual request;
/// implementations must not attach hidden uncounted history at send time.
pub trait ReaderAdapter: OutgoingEncoder {
    /// Declared reader capacity, locality and renderer contract.
    fn profile(&self) -> ModelProfile;
    /// Verified history/recovery support, independent of scoring.
    fn capabilities(&self) -> ReaderCapabilities;
    /// The same counter supplied to the evidence compiler.
    fn tokenizer(&self) -> &dyn TokenCounter;
    /// Source-preserving exact request replay, including any escaping transforms.
    fn capture_manifest(
        &self,
        call: ModelCallId,
        messages: &[OutgoingMessage],
        wire: &EncodedOutgoing,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ModelRequestManifest>;
    /// Send only these captured bytes. Errors leave the outcome unknown and must
    /// never discard exposed output; use Interrupted when bytes were received.
    fn complete(
        &self,
        call: ModelCallId,
        request: &EncodedOutgoing,
    ) -> ServiceResult<ReaderOutcome>;
    /// Non-dispatching lookup of counters for this exact attempt, also after an
    /// error. Defaults to unknown, not zero. Adapters must include every billed
    /// input category and count reasoning once within total output.
    fn usage(&self, _call: ModelCallId) -> crate::ReaderUsage {
        crate::ReaderUsage::default()
    }
    /// Recover an uncertain attempt without dispatching it again.
    fn reconcile(
        &self,
        call: ModelCallId,
        wire_digest: ContentDigest,
    ) -> ServiceResult<ModelReconciliation>;
}

/// Required dispatch boundary. Preparation alone never authorizes disclosure.
/// Implementations register/check native policy, state, temporal and run fences.
pub trait ModelDispatchFence: std::fmt::Debug + Send + Sync {
    /// Called after durable request capture, immediately before the provider call.
    fn before_model(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        call: ModelCallId,
        request: &CaptureReceipt,
        prepared: &PreparedContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()>;
}

/// Required owner check immediately before an external target is invoked.
pub trait ToolDispatchFence: std::fmt::Debug + Send + Sync {
    /// Compare fresh constraints, source permissions, run revision and action bytes.
    /// A rejection is a known failed dispatch, never an unknown external effect.
    fn before_tool(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        planned: &contextdb_continuity::PendingToolInvocation,
        action: &ToolAction,
        class: contextdb_service::ToolAdmissionClass,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()>;
}

/// Optional host interpreter/index maintenance before preparation, outside the
/// publication lock. A pipeline must report unresolved input honestly.
pub trait PreparationHook: std::fmt::Debug + Send + Sync {
    /// Run bounded shared-budget host work; do not infer semantic authority.
    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()>;
}

/// Preserve conservative unknown markers when no interpreter is configured.
#[derive(Debug, Default)]
pub struct KeepUninterpreted;
impl PreparationHook for KeepUninterpreted {
    fn before_prepare(
        &self,
        _: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        super::charge(budget, 1, 0)
    }
}
