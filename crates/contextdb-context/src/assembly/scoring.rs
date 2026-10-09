//! Borrowed semantic observations of the compiler's actual selection trial.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;

use contextdb_core::{ConflictState, EpistemicState};
use contextdb_recall::QueryBudget;
use serde::Serialize;
use serde::ser::{SerializeSeq, SerializeStruct};

use super::{
    OutgoingBase, OutgoingBudget, OutgoingMessage, RequestCountKind, charge, serialization,
};
use crate::{
    BlockId, ConflictResolution, ContextBlock, ContextBudgetUsage, ContextBudgets, ContextError,
    ContextPack, PackEvidence, Result,
};

/// Version of the strict model-facing text and numeric allowlist.
pub const SEMANTIC_SCORING_FEATURE_SCHEMA: &str = "contextdb.routing_features.semantic.v1";
/// Joint ceiling for one serialized semantic model input.
pub const MAX_SEMANTIC_SCORING_BYTES: usize = 2 * 1024 * 1024;

/// Explicitly opt in to text observations; the default scalar path is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticScoringProfile {
    /// The actual chosen representations, source union and complete trial cost.
    RenderedClosureV1,
}

/// Chosen preparation metadata, never a label or model input identity.
#[derive(Clone, Eq, PartialEq)]
pub struct SemanticVariantChoice {
    /// Host-only block correspondence; excluded from model features.
    pub block_id: BlockId,
    /// Actual sufficient alternative selected during this trial.
    pub alternative_index: u32,
    /// Whether preparation synthesized this marker instead of loading a source.
    pub generated: bool,
}

/// Exact prepared pack and outgoing messages already constructed by the compiler.
#[derive(Clone, Copy)]
pub struct SemanticAssemblyView<'a> {
    /// Prepared pack at this point in selection, not a predicted final pack.
    pub pack: &'a ContextPack,
    /// Exact outgoing order, including verified source coverage and protocol.
    pub messages: &'a [OutgoingMessage],
    /// Choices recorded by the existing variant selector, without rediscovery.
    pub chosen_variants: &'a [SemanticVariantChoice],
    /// Complete protocol count produced by the actual encoder.
    pub input_tokens: u32,
    /// Distinguishes exact counts from conservative complete-request bounds.
    pub count_kind: RequestCountKind,
    /// Length of the actual encoded request.
    pub wire_bytes: u64,
    /// Deduplicated original bytes added beyond post-eviction base coverage.
    pub added_original_bytes: u64,
}

/// Host-only correspondence. It is deliberately absent from the text projection.
#[derive(Clone, Copy)]
pub struct SemanticScoringIdentity<'a> {
    /// Optional candidate or complement bundle being evaluated.
    pub seed_ids: &'a BTreeSet<BlockId>,
    /// New hard closure beyond the already-selected base.
    pub closure_ids: &'a BTreeSet<BlockId>,
}

/// Allowance at this real callback, rather than a fresh model-operation budget.
#[derive(Clone, Copy, Debug)]
pub struct SemanticScoringBudget {
    /// Declared additional-memory and category ceilings.
    pub memory: ContextBudgets,
    /// Declared complete request ceiling, separate from additional memory.
    pub outgoing: OutgoingBudget,
    /// Actual current selected-base category charges.
    pub selected_usage: ContextBudgetUsage,
    /// Actual trial category charges after source union and rendering.
    pub trial_usage: ContextBudgetUsage,
    /// Remaining enclosing work, after authorization and trial construction.
    pub remaining_work: u64,
    /// Remaining enclosing byte allowance; no fresh model allowance is created.
    pub remaining_bytes: u64,
    /// Remaining shared and prepare cooperative timeout.
    pub remaining_timeout_micros: u64,
    /// Remaining aggregate scorer work across this entire selection.
    pub remaining_scorer_work: u64,
    /// Remaining aggregate scorer cooperative time.
    pub remaining_scorer_micros: u64,
    /// Unevaluated selection slots left in the declared ceiling.
    pub remaining_evaluations: u32,
    /// Signed exact trial-minus-selected delta; upper-bound differences are absent.
    pub exact_marginal_input_tokens: Option<i64>,
    /// False when this rendered trial exceeds only the outgoing ceiling.
    pub outgoing_fits: bool,
    /// Additional deduplicated original bytes relative to current selection.
    pub added_original_bytes: u64,
}

/// Read-only compiler material. Raw host views must not be serialized as features;
/// use `model_input_json` for the versioned allowlist instead.
#[non_exhaustive]
pub struct SemanticScoringUnit<'a> {
    /// Actual host-selected post-eviction zones and current protocol messages.
    pub base: &'a OutgoingBase,
    /// Mandatory closure and optional units already selected before this call.
    pub selected: SemanticAssemblyView<'a>,
    /// Actual rendered seed/bundle closure proposed by this call.
    pub trial: SemanticAssemblyView<'a>,
    /// Correspondence for host provenance and caches, never model text.
    pub identity: SemanticScoringIdentity<'a>,
    /// Numeric allowance and cost observations at the callback boundary.
    pub budget: SemanticScoringBudget,
}

impl SemanticScoringUnit<'_> {
    /// Strict bounded model features. IDs, digests, priors, report JSON and scorer
    /// observations remain outside this projection; associations use local slots.
    pub fn model_input_json(&self, budget: &mut QueryBudget) -> Result<Vec<u8>> {
        let base_messages = base_messages(self.base);
        let calls = base_messages
            .clone()
            .map(|message| message.tool_calls.len())
            .sum::<usize>();
        let messages = base_messages.count();
        let support_work = [self.selected, self.trial]
            .iter()
            .map(|view| {
                let blocks = view.pack.sections.iter().count();
                blocks
                    .saturating_mul(view.pack.evidence.len())
                    .saturating_add(blocks.saturating_mul(blocks).saturating_mul(2))
            })
            .sum::<usize>();
        // Slot lookup scans are bounded and charged before serialization/copies.
        charge(
            budget,
            1_u64
                .saturating_add(messages.saturating_mul(calls) as u64)
                .saturating_add(calls.saturating_mul(calls) as u64)
                .saturating_add(support_work as u64),
            0,
        )?;
        let mut output = FeatureWriter {
            bytes: Vec::new(),
            budget,
        };
        serde_json::to_writer(&mut output, &ModelInput(self)).map_err(|error| {
            if error.is_io() {
                ContextError::BudgetExceeded("bounded semantic feature serialization failed".into())
            } else {
                serialization(error)
            }
        })?;
        output.budget.check().map_err(|reason| {
            ContextError::BudgetExceeded(format!("shared semantic allowance: {reason:?}"))
        })?;
        Ok(output.bytes)
    }
}

impl fmt::Debug for SemanticScoringUnit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticScoringUnit")
            .field("seed_count", &self.identity.seed_ids.len())
            .field("closure_count", &self.identity.closure_ids.len())
            .field("selected_input_tokens", &self.selected.input_tokens)
            .field("trial_input_tokens", &self.trial.input_tokens)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SemanticVariantChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticVariantChoice")
            .field("alternative_index", &self.alternative_index)
            .field("generated", &self.generated)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SemanticAssemblyView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticAssemblyView")
            .field("blocks", &self.chosen_variants.len())
            .field("input_tokens", &self.input_tokens)
            .field("count_kind", &self.count_kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SemanticScoringIdentity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticScoringIdentity")
            .field("seed_count", &self.seed_ids.len())
            .field("closure_count", &self.closure_ids.len())
            .finish_non_exhaustive()
    }
}

struct FeatureWriter<'a> {
    bytes: Vec<u8>,
    budget: &'a mut QueryBudget,
}

impl Write for FeatureWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_SEMANTIC_SCORING_BYTES {
            return Err(std::io::Error::other("semantic feature ceiling exceeded"));
        }
        self.budget
            .charge(0, bytes.len() as u64)
            .map_err(|_| std::io::Error::other("shared semantic allowance exhausted"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn base_messages(base: &OutgoingBase) -> impl Iterator<Item = &OutgoingMessage> + Clone {
    base.control
        .iter()
        .chain(&base.working)
        .chain(&base.hot)
        .chain(&base.current)
}

fn call_slot(base: &OutgoingBase, call: &str) -> Option<usize> {
    base_messages(base)
        .flat_map(|message| &message.tool_calls)
        .position(|value| value == call)
}

struct ModelInput<'a>(&'a SemanticScoringUnit<'a>);
impl Serialize for ModelInput<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let unit = self.0;
        let mut state = serializer.serialize_struct("SemanticScoringInput", 7)?;
        state.serialize_field("format", SEMANTIC_SCORING_FEATURE_SCHEMA)?;
        state.serialize_field("base", &ModelBase(unit.base))?;
        state.serialize_field("selected", &ModelAssembly(unit.selected))?;
        state.serialize_field("trial", &ModelAssembly(unit.trial))?;
        state.serialize_field(
            "seed_slots",
            &BlockSlots(unit.trial.pack, unit.identity.seed_ids),
        )?;
        state.serialize_field(
            "closure_slots",
            &BlockSlots(unit.trial.pack, unit.identity.closure_ids),
        )?;
        state.serialize_field("budget", &ModelBudget(unit.budget))?;
        state.end()
    }
}

struct ModelBase<'a>(&'a OutgoingBase);
impl Serialize for ModelBase<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SemanticBase", 4)?;
        for (name, messages) in [
            ("control", &self.0.control),
            ("working", &self.0.working),
            ("hot", &self.0.hot),
            ("current", &self.0.current),
        ] {
            state.serialize_field(name, &ModelMessages(self.0, messages))?;
        }
        state.end()
    }
}

struct ModelMessages<'a>(&'a OutgoingBase, &'a [OutgoingMessage]);
impl Serialize for ModelMessages<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.1.len()))?;
        for message in self.1 {
            #[derive(Serialize)]
            struct Message<'a> {
                zone: super::OutgoingZone,
                role: super::OutgoingRole,
                text: &'a str,
                tool_calls: CallSlots<'a>,
                tool_result: Option<usize>,
            }
            sequence.serialize_element(&Message {
                zone: message.zone,
                role: message.role,
                text: &message.text,
                tool_calls: CallSlots(self.0, &message.tool_calls),
                tool_result: message
                    .tool_result
                    .as_deref()
                    .and_then(|call| call_slot(self.0, call)),
            })?;
        }
        sequence.end()
    }
}

struct CallSlots<'a>(&'a OutgoingBase, &'a [String]);
impl Serialize for CallSlots<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.1.len()))?;
        for call in self.1 {
            sequence.serialize_element(&call_slot(self.0, call))?;
        }
        sequence.end()
    }
}

struct ModelAssembly<'a>(SemanticAssemblyView<'a>);
impl Serialize for ModelAssembly<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SemanticAssembly", 8)?;
        state.serialize_field("blocks", &ModelBlocks(self.0))?;
        state.serialize_field("supports", &ModelSupports(&self.0.pack.evidence))?;
        state.serialize_field("rendered_originals", &ModelOriginals(self.0.messages))?;
        state.serialize_field("input_tokens", &self.0.input_tokens)?;
        state.serialize_field("count_kind", &self.0.count_kind)?;
        state.serialize_field("wire_bytes", &self.0.wire_bytes)?;
        state.serialize_field("added_original_bytes", &self.0.added_original_bytes)?;
        state.serialize_field("usage", &ModelUsage(self.0.pack.compilation.usage))?;
        state.end()
    }
}

struct ModelBlocks<'a>(SemanticAssemblyView<'a>);
impl Serialize for ModelBlocks<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for block in self.0.pack.sections.iter() {
            sequence.serialize_element(&ModelBlock(block, self.0))?;
        }
        sequence.end()
    }
}

struct ModelBlock<'a>(&'a ContextBlock, SemanticAssemblyView<'a>);
impl Serialize for ModelBlock<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let block = self.0;
        let mut state = serializer.serialize_struct(
            "SemanticBlock",
            13 + usize::from(block.conflict.is_some()) + usize::from(block.unknown.is_some()),
        )?;
        state.serialize_field("kind", &block.kind)?;
        #[derive(Serialize)]
        struct Representation<'a> {
            level: crate::CompressionLevel,
            summary: Option<&'a str>,
            fields: Option<&'a BTreeMap<String, String>>,
            omitted_facets: &'a BTreeSet<String>,
        }
        // Raw occurrence previews can contain compiler IDs, not source bytes.
        // The actual support/slices below carry their semantic material instead.
        let raw = block.kind == crate::PackBlockKind::RawObservation;
        state.serialize_field(
            "representation",
            &Representation {
                level: block.representation.level,
                summary: (!raw).then_some(block.representation.summary.as_str()),
                fields: (!raw).then_some(&block.representation.fields),
                omitted_facets: &block.representation.omitted_facets,
            },
        )?;
        state.serialize_field("exact_fragments", &block.exact_fragments)?;
        state.serialize_field("epistemic", &ModelEpistemic(block.epistemic))?;
        state.serialize_field("interpretation", &block.interpretation)?;
        state.serialize_field("source_class", &block.source_class)?;
        state.serialize_field("support", &block.support)?;
        state.serialize_field("valid_time", &block.valid_time)?;
        state.serialize_field("facets", &block.facets)?;
        state.serialize_field("support_slots", &SupportSlots(block, &self.1.pack.evidence))?;
        let directive = self
            .1
            .pack
            .use_directives
            .iter()
            .find(|item| item.block_id == block.id);
        state.serialize_field("use_action", &directive.map(|item| item.action))?;
        state.serialize_field("directive_reason", &directive.map(|item| item.reason_code))?;
        state.serialize_field(
            "alternative_index",
            &self
                .1
                .chosen_variants
                .iter()
                .find(|choice| choice.block_id == block.id)
                .map(|choice| choice.alternative_index),
        )?;
        if let Some(conflict) = &block.conflict {
            #[derive(Serialize)]
            struct Conflict<'a> {
                blocking: bool,
                alternatives: usize,
                resolved: bool,
                rationale: Option<&'a str>,
            }
            let rationale = match &conflict.resolution {
                ConflictResolution::Resolved { rationale, .. } => Some(rationale.as_str()),
                ConflictResolution::Unresolved => None,
            };
            state.serialize_field(
                "conflict",
                &Conflict {
                    blocking: conflict.blocking,
                    alternatives: conflict.alternatives.len(),
                    resolved: rationale.is_some(),
                    rationale,
                },
            )?;
        }
        if let Some(unknown) = &block.unknown {
            state.serialize_field("unknown", unknown)?;
        }
        state.end()
    }
}

struct ModelEpistemic(EpistemicState);
impl Serialize for ModelEpistemic {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SemanticEpistemicState", 4)?;
        state.serialize_field("basis", &self.0.basis)?;
        state.serialize_field("acceptance", &self.0.acceptance)?;
        #[derive(Serialize)]
        struct Conflict {
            state: &'static str,
        }
        let conflict = match self.0.conflict {
            ConflictState::None => "none",
            ConflictState::Disputed => "disputed",
            ConflictState::InConflict { .. } => "in_conflict",
            ConflictState::Resolved { .. } => "resolved",
        };
        state.serialize_field("conflict", &Conflict { state: conflict })?;
        state.serialize_field("lifecycle", &self.0.lifecycle)?;
        state.end()
    }
}

struct SupportSlots<'a>(&'a ContextBlock, &'a [PackEvidence]);
impl Serialize for SupportSlots<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for (index, item) in self.1.iter().enumerate() {
            if self.0.evidence_handles.contains(&item.id) {
                sequence.serialize_element(&index)?;
            }
        }
        sequence.end()
    }
}

struct BlockSlots<'a>(&'a ContextPack, &'a BTreeSet<BlockId>);
impl Serialize for BlockSlots<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for (index, block) in self.0.sections.iter().enumerate() {
            if self.1.contains(&block.id) {
                sequence.serialize_element(&index)?;
            }
        }
        sequence.end()
    }
}

struct ModelSupports<'a>(&'a [PackEvidence]);
impl Serialize for ModelSupports<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for evidence in self.0 {
            #[derive(Serialize)]
            struct Support<'a> {
                excerpt: Option<&'a str>,
                primary: bool,
                source_class: &'a crate::SourceClass,
                original_bytes: Option<u64>,
            }
            sequence.serialize_element(&Support {
                excerpt: evidence.excerpt.as_deref(),
                primary: evidence.primary,
                source_class: &evidence.source_class,
                original_bytes: evidence
                    .original_span
                    .as_ref()
                    .and_then(|span| span.end.checked_sub(span.start)),
            })?;
        }
        sequence.end()
    }
}

struct ModelOriginals<'a>(&'a [OutgoingMessage]);
impl Serialize for ModelOriginals<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for message in self.0 {
            for original in &message.originals {
                let text = message
                    .text
                    .get(original.text_start as usize..original.text_end as usize)
                    .ok_or_else(|| serde::ser::Error::custom("invalid rendered source slice"))?;
                #[derive(Serialize)]
                struct Original<'a> {
                    zone: super::OutgoingZone,
                    role: super::OutgoingRole,
                    text: &'a str,
                }
                sequence.serialize_element(&Original {
                    zone: message.zone,
                    role: message.role,
                    text,
                })?;
            }
        }
        sequence.end()
    }
}

struct ModelUsage(ContextBudgetUsage);
impl Serialize for ModelUsage {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SemanticUsage", 9)?;
        for (name, value) in [
            ("rendered_tokens", self.0.rendered_tokens),
            ("control_tokens", self.0.control_tokens),
            ("data_tokens", self.0.data_tokens),
            ("blocks", self.0.blocks),
            ("evidence_blocks", self.0.evidence_blocks),
            ("raw_evidence_tokens", self.0.raw_evidence_tokens),
            ("history_tokens", self.0.history_tokens),
            ("conflict_tokens", self.0.conflict_tokens),
            ("serialized_bytes", self.0.serialized_bytes),
        ] {
            state.serialize_field(name, &value)?;
        }
        state.end()
    }
}

struct ModelBudget(SemanticScoringBudget);
impl Serialize for ModelBudget {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let budget = self.0;
        let mut state = serializer.serialize_struct("SemanticBudget", 10)?;
        state.serialize_field("memory", &budget.memory)?;
        state.serialize_field("outgoing", &budget.outgoing)?;
        state.serialize_field("remaining_work", &budget.remaining_work)?;
        state.serialize_field("remaining_bytes", &budget.remaining_bytes)?;
        state.serialize_field("remaining_timeout_micros", &budget.remaining_timeout_micros)?;
        state.serialize_field("remaining_scorer_work", &budget.remaining_scorer_work)?;
        state.serialize_field("remaining_scorer_micros", &budget.remaining_scorer_micros)?;
        state.serialize_field("remaining_evaluations", &budget.remaining_evaluations)?;
        state.serialize_field(
            "exact_marginal_input_tokens",
            &budget.exact_marginal_input_tokens,
        )?;
        state.serialize_field("outgoing_fits", &budget.outgoing_fits)?;
        state.end()
    }
}
