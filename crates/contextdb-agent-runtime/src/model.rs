use contextdb_context::{
    EncodedOutgoing, ModelProfile, OutgoingEncoder, OutgoingMessage, TokenCounter,
};
use contextdb_core::{ContentDigest, ModelCallId, ModelRequestManifest};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, CaptureReceipt, PreparedContext, ServiceResult,
};

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

/// Complete visible text. Provider errors with partial bytes must preserve those
/// bytes separately; an error alone never implies that no request was accepted.
#[derive(Clone, Eq, PartialEq)]
pub struct ReaderReply {
    /// Exact visible output; hidden reasoning is never part of this type.
    pub text: String,
}
impl std::fmt::Debug for ReaderReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderReply")
            .field("byte_length", &self.text.len())
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
    /// Send only these already-captured bytes. Errors leave the outcome unknown.
    fn complete(&self, call: ModelCallId, request: &EncodedOutgoing) -> ServiceResult<ReaderReply>;
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
