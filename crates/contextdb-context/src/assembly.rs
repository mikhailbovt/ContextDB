//! Whole-request compilation contracts. Provider bindings are opaque; a prepared
//! assembly is not a publication-owner lease or permission to dispatch a tool.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{ContentDigest, OriginalSourceSpan, TimestampMicros};
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};

use crate::{BlockId, CompileRequest, CompiledContext, ContextProvider, EvidenceHandle, Result};

/// Version of the ordered layout and source coverage rules.
pub const OUTGOING_LAYOUT: &str = "contextdb.outgoing.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutgoingZone {
    Control,
    ToolDefinitions,
    WorkingState,
    Memory,
    Evidence,
    HotHistory,
    CurrentTurn,
    ProviderContinuation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutgoingRole {
    System,
    Developer,
    User,
    Assistant,
    Tool,
}

/// Original bytes at these UTF-8 byte offsets in one rendered message. Merely
/// mentioning a source ID, URI or artifact handle does not establish coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisibleOriginal {
    pub span: OriginalSourceSpan,
    pub text_start: u64,
    pub text_end: u64,
}

/// One actual outgoing message, including provider protocol obligations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingMessage {
    pub id: BlockId,
    pub zone: OutgoingZone,
    pub role: OutgoingRole,
    pub text: String,
    pub originals: Vec<VisibleOriginal>,
    pub tool_calls: Vec<String>,
    pub tool_result: Option<String>,
}

/// Host-selected post-eviction H*. The compiler does not evict messages after
/// source coverage has been calculated. Changing any byte requires recompilation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingBase {
    pub control: Vec<OutgoingMessage>,
    pub hot: Vec<OutgoingMessage>,
    pub current: Vec<OutgoingMessage>,
}

/// Declared whole-request ceiling, independent of the additional-memory ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingBudget {
    pub max_input_tokens: u32,
    pub safety_tokens: u32,
    pub max_wire_bytes: u32,
}

/// Opaque principal/knowledge/current-policy/scope binding supplied by the owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyBinding {
    pub snapshot: String,
    pub authorization: String,
    pub state: String,
    pub valid_until: Option<TimestampMicros>,
}

/// Includes negative dependencies: a new assertion in any requested scope must
/// invalidate the binding even if no previous value was selected from that scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyReadSet {
    pub scopes: BTreeSet<String>,
    pub originals: Vec<OriginalSourceSpan>,
    pub selected_blocks: BTreeSet<BlockId>,
    pub binding: AssemblyBinding,
}

/// Provider-authored dependencies. Related-to edges are not hard dependencies.
/// Each support alternative is a complete sufficient set, not one extra quote.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDependencies {
    pub hard: BTreeSet<BlockId>,
    pub supports: Vec<BTreeSet<EvidenceHandle>>,
    pub complements: BTreeSet<BlockId>,
}

/// Extends the existing policy-first provider; implementations verify immutable
/// originals under their own current ACL, never under the referring claim's ACL.
pub trait AssemblyProvider: ContextProvider {
    fn binding(&self) -> Result<AssemblyBinding>;
    fn dependencies(&self, id: &BlockId) -> Result<EvidenceDependencies>;
    fn verify_original(
        &self,
        span: &OriginalSourceSpan,
        bytes: &[u8],
        budget: &mut QueryBudget,
    ) -> Result<()>;
    fn validate_read_set(&self, read_set: &AssemblyReadSet, budget: &mut QueryBudget)
    -> Result<()>;
}

/// Only authorized optional selection units reach a scorer. It has no API for
/// rewriting evidence, inventing IDs, changing mandatory state or granting rights.
#[derive(Clone, Debug)]
pub struct ScoringUnit {
    pub seeds: BTreeSet<BlockId>,
    pub closure: BTreeSet<BlockId>,
    pub marginal_tokens: u32,
    pub prior_utility_micros: u64,
    pub new_facets: BTreeSet<String>,
    pub adds_original_bytes: bool,
    pub raw_only: bool,
}

pub trait ContextScorer: std::fmt::Debug + Send + Sync {
    fn id(&self) -> &str;
    /// None means STOP for this optional unit, without removing mandatory closure.
    fn score(&self, unit: &ScoringUnit, budget: &mut QueryBudget) -> Result<Option<u64>>;
}

/// Deterministic R0 heuristic. Learned backends are intentionally not enabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct R0Scorer;

impl ContextScorer for R0Scorer {
    fn id(&self) -> &str {
        "contextdb.r0-closure.v1"
    }

    fn score(&self, unit: &ScoringUnit, budget: &mut QueryBudget) -> Result<Option<u64>> {
        charge(budget, 1, 0)?;
        if unit.raw_only && !unit.adds_original_bytes {
            return Ok(None);
        }
        let bonus = 1 + u64::try_from(unit.new_facets.len())
            .unwrap_or(u64::MAX)
            .min(8);
        let value = unit.prior_utility_micros.saturating_mul(bonus);
        Ok((value / u64::from(unit.marginal_tokens.max(1)) >= 100).then_some(value))
    }
}

#[derive(Clone, Debug)]
pub struct CompileAssemblyRequest {
    pub context: CompileRequest,
    pub base: OutgoingBase,
    pub budget: OutgoingBudget,
}

/// Counts cover the provider's complete request protocol, including tool schemas,
/// image/audio charges and any hidden continuation. An estimate cannot be Exact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestCountKind {
    Exact,
    ConservativeUpperBound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodedOutgoing {
    pub protocol: String,
    pub tokenizer: String,
    pub count_kind: RequestCountKind,
    pub input_tokens: u32,
    pub wire: Vec<u8>,
}

/// Trusted host integration. No opaque unaccounted provider history is allowed.
/// The compiler supplies every message in its final order and checks the result.
pub trait OutgoingEncoder: std::fmt::Debug + Send + Sync {
    fn id(&self) -> &str;
    fn tokenizer_id(&self) -> &str;
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> Result<EncodedOutgoing>;
}

/// Exact reference JSON protocol; this is not a third-party model token estimate.
#[derive(Debug)]
pub struct ReferenceOutgoingEncoder<'a>(pub &'a dyn crate::TokenCounter);

impl OutgoingEncoder for ReferenceOutgoingEncoder<'_> {
    fn id(&self) -> &str {
        "contextdb.reference-request-json.v1"
    }
    fn tokenizer_id(&self) -> &str {
        self.0.id()
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> Result<EncodedOutgoing> {
        charge(budget, 1, 0)?;
        let wire = serde_json::to_vec(messages).map_err(serialization)?;
        charge(budget, 0, wire.len() as u64)?;
        let text = std::str::from_utf8(&wire).map_err(serialization)?;
        Ok(EncodedOutgoing {
            protocol: self.id().into(),
            tokenizer: self.tokenizer_id().into(),
            count_kind: RequestCountKind::Exact,
            input_tokens: self.0.count_tokens(text)?,
            wire,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingOccurrence {
    pub id: BlockId,
    pub zone: OutgoingZone,
    pub role: OutgoingRole,
    pub digest: ContentDigest,
    pub originals: Vec<VisibleOriginal>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingAssemblyManifest {
    pub layout: String,
    pub encoder: String,
    pub model_profile_digest: ContentDigest,
    pub base_digest: ContentDigest,
    pub pack_digest: String,
    pub scorer: String,
    pub occurrences: Vec<OutgoingOccurrence>,
    pub read_set: AssemblyReadSet,
    pub input_tokens: u32,
    pub count_kind: RequestCountKind,
    pub reserved_output_tokens: u32,
    pub safety_tokens: u32,
    pub wire_digest: ContentDigest,
}

#[derive(Clone, Debug)]
pub struct CompiledAssembly {
    pub context: CompiledContext,
    pub messages: Vec<OutgoingMessage>,
    pub outgoing: EncodedOutgoing,
    pub manifest: OutgoingAssemblyManifest,
    pub optional_seeds: BTreeSet<BlockId>,
    pub selection_evaluations: u32,
}

pub(crate) fn charge(budget: &mut QueryBudget, work: u64, bytes: u64) -> Result<()> {
    budget.charge(work, bytes).map_err(|reason| {
        crate::ContextError::BudgetExceeded(format!("shared prepare allowance: {reason:?}"))
    })
}

pub(crate) fn serialization(error: impl std::fmt::Display) -> crate::ContextError {
    crate::ContextError::Serialization(error.to_string())
}

pub(crate) fn digest(value: &impl Serialize) -> Result<ContentDigest> {
    Ok(ContentDigest::from_bytes(
        *blake3::hash(&serde_json::to_vec(value).map_err(serialization)?).as_bytes(),
    ))
}

pub(crate) fn validate_message(message: &OutgoingMessage) -> Result<()> {
    use crate::ContextError::InvalidRequest;
    if message.text.len() > 1024 * 1024
        || message.originals.len() > 128
        || message.tool_calls.len() > 32
        || message.id.as_str().len() > 2048
    {
        return Err(InvalidRequest(
            "outgoing message exceeds supported bounds".into(),
        ));
    }
    let control = matches!(
        message.zone,
        OutgoingZone::Control | OutgoingZone::ToolDefinitions
    );
    if (matches!(message.role, OutgoingRole::System | OutgoingRole::Developer) && !control)
        || (control && !message.originals.is_empty())
    {
        return Err(InvalidRequest(
            "retrieved data cannot enter the trusted control channel".into(),
        ));
    }
    if matches!(
        message.zone,
        OutgoingZone::HotHistory | OutgoingZone::CurrentTurn | OutgoingZone::ProviderContinuation
    ) && message.originals.is_empty()
    {
        return Err(InvalidRequest(
            "outgoing history requires captured original attribution".into(),
        ));
    }
    let mut last_end = 0;
    for original in &message.originals {
        let span = &original.span;
        let start = usize::try_from(original.text_start).map_err(serialization)?;
        let end = usize::try_from(original.text_end).map_err(serialization)?;
        let Some(text) = message.text.get(start..end) else {
            return Err(InvalidRequest(
                "original occurrence is not an exact UTF-8 range".into(),
            ));
        };
        if original.text_start < last_end
            || span.end <= span.start
            || span.end - span.start != text.len() as u64
            || blake3::hash(text.as_bytes()).as_bytes() != span.span_digest.as_bytes()
        {
            return Err(InvalidRequest(
                "original occurrence content or offsets disagree".into(),
            ));
        }
        last_end = original.text_end;
    }
    if (message.role == OutgoingRole::Tool) != message.tool_result.is_some()
        || (!message.tool_calls.is_empty() && message.role != OutgoingRole::Assistant)
    {
        return Err(InvalidRequest(
            "tool protocol metadata disagrees with role".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_protocol(messages: &[OutgoingMessage]) -> Result<()> {
    let mut pending = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for message in messages {
        validate_message(message)?;
        if !ids.insert(&message.id) {
            return Err(crate::ContextError::InvalidRequest(
                "outgoing block IDs repeat".into(),
            ));
        }
        if let Some(result) = &message.tool_result {
            if !pending.remove(result) {
                return Err(crate::ContextError::InvalidRequest(
                    "orphan or duplicate tool result".into(),
                ));
            }
        } else if !pending.is_empty() {
            return Err(crate::ContextError::InvalidRequest(
                "unresolved tool group before next message".into(),
            ));
        }
        for call in &message.tool_calls {
            if call.is_empty() || call.len() > 2048 || !calls.insert(call.clone()) {
                return Err(crate::ContextError::InvalidRequest(
                    "invalid or repeated tool call identity".into(),
                ));
            }
            pending.insert(call.clone());
        }
    }
    if !pending.is_empty() {
        return Err(crate::ContextError::InvalidRequest(
            "outgoing request has an incomplete tool group".into(),
        ));
    }
    Ok(())
}

/// A byte-verified union inventory. Keys include immutable payload version.
pub(crate) type OriginalInventory =
    BTreeMap<(contextdb_core::ObservationId, ContentDigest), Vec<(u64, Vec<u8>)>>;
