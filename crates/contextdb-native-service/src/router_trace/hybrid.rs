//! Protected owner observations. They grant no processing, source or dispatch authority.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use contextdb_context::{BlockId, OutgoingBase};
use contextdb_core::{
    ContentDigest, ContextPackId, EventEnvelope, EventPayload, ObservationId, OriginalSourceSpan,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    CaptureReceipt, DENSE_QUERY_PREFLIGHT_BYTE_LIMITS, DENSE_QUERY_REFINEMENT_REVISION,
    DenseCueChannel, DenseQueryCues, EmbeddedText, EmbeddingTextKind,
    MAX_MEASURED_EMBEDDING_TOKENS, NATIVE_CAPTURE_DOMAIN, OwnedHybridIntent, ServiceResult,
    TextEmbeddingProfile, TokenizedText, dense_step_query_with_byte_limit,
};
use serde::{Deserialize, Serialize};

use super::{RouterEnvelope, trace_error};
use crate::{integrity, invalid, raw_index::budget_error};

pub(crate) mod routed;
pub(crate) mod segments;
pub(crate) use routed::HybridRoutedDenseWitness;
pub(crate) use routed::event_hybrid_query_modes;
pub(crate) use segments::HybridSegmentedDenseWitness;
#[cfg(test)]
pub(crate) use segments::event_has_segmented_hybrid;

pub(crate) const HYBRID_OBSERVATION_REVISION: &str = "contextdb.native-owned-hybrid-observation.v1";
pub(crate) const HYBRID_FEATURE: &str = "continuous-owned-hybrid-query-v1";
pub(crate) const HYBRID_FUSION_REVISION: &str = "native-source-rrf-equal-k60-micros-v1";
const MAX_SOURCES: usize = 256;
const MAX_FRAGMENTS: usize = 64;

/// Feature discovery only. Full protected envelope admission owns its encoding;
/// this marker neither reconstructs query bodies nor establishes authority.
pub(crate) fn event_has_hybrid(event: &EventEnvelope) -> ServiceResult<bool> {
    let Some(pages) = protected_pages(event)? else {
        return Ok(false);
    };
    #[derive(Deserialize)]
    struct Marker {
        #[serde(default)]
        owned_hybrid: Option<serde::de::IgnoredAny>,
    }
    let marker: Marker = serde_json::from_reader(pages)
        .map_err(|_| integrity("hybrid feature marker has malformed protected JSON"))?;
    Ok(marker.owned_hybrid.is_some())
}

fn protected_pages(event: &EventEnvelope) -> ServiceResult<Option<Pages<'_>>> {
    let EventPayload::Assembly { manifest } = &event.payload else {
        return Ok(None);
    };
    let Some(trace) = &manifest.router_trace else {
        return Ok(None);
    };
    trace
        .validate_for_model_request(manifest)
        .map_err(|_| integrity("hybrid feature marker has invalid protected pages"))?;
    Ok(Some(Pages {
        pages: &trace.pages,
        page: 0,
        offset: 0,
    }))
}

// Parse borrowed page bytes without concatenating the protected envelope.
struct Pages<'a> {
    pages: &'a [contextdb_core::RouterTracePage],
    page: usize,
    offset: usize,
}
impl Read for Pages<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while let Some(page) = self.pages.get(self.page) {
            let remaining = &page.text.as_bytes()[self.offset..];
            if remaining.is_empty() {
                self.page += 1;
                self.offset = 0;
                continue;
            }
            let count = output.len().min(remaining.len());
            output[..count].copy_from_slice(&remaining[..count]);
            self.offset += count;
            return Ok(count);
        }
        Ok(0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HybridCueChannel {
    User,
    Tool,
    Working,
    Assistant,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridCueFragment {
    pub channel: HybridCueChannel,
    pub message_id: BlockId,
    pub message_start: u64,
    pub message_end: u64,
    pub query_start: u32,
    pub query_end: u32,
    pub source: OriginalSourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridPreflightObservation {
    pub byte_limit: u32,
    pub cue_revision: String,
    pub text_digest: ContentDigest,
    pub text_bytes: u32,
    pub inspected_bytes: u64,
    pub omitted_bytes: u64,
    pub fragments: Vec<HybridCueFragment>,
    pub tokens: TokenizedText,
}

impl HybridPreflightObservation {
    pub(crate) fn from_sample(
        byte_limit: u32,
        cues: &DenseQueryCues,
        tokens: TokenizedText,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        if !DENSE_QUERY_PREFLIGHT_BYTE_LIMITS.contains(&(byte_limit as usize))
            || cues.revision != DENSE_QUERY_REFINEMENT_REVISION
            || cues.text.is_empty()
            || cues.text.len() > byte_limit as usize
            || cues.fragments.is_empty()
            || cues.fragments.len() > MAX_FRAGMENTS
        {
            return Err(invalid(
                "owned hybrid sample shape differs from fixed preflight",
            ));
        }
        budget
            .charge(1, cues.fragments.len() as u64 * 512 + 1024)
            .map_err(budget_error)?;
        let mut fragments = Vec::with_capacity(cues.fragments.len());
        for fragment in &cues.fragments {
            if fragment.message_id.as_str().len() > 256 {
                return Err(invalid("owned hybrid sampled message ID exceeds bound"));
            }
            budget
                .charge(
                    fragment.message_id.as_str().len() as u64 + 1,
                    fragment.message_id.as_str().len() as u64,
                )
                .map_err(budget_error)?;
            fragments.push(HybridCueFragment {
                channel: match fragment.channel {
                    DenseCueChannel::User => HybridCueChannel::User,
                    DenseCueChannel::Tool => HybridCueChannel::Tool,
                    DenseCueChannel::Working => HybridCueChannel::Working,
                    DenseCueChannel::Assistant => HybridCueChannel::Assistant,
                },
                message_id: fragment.message_id.clone(),
                message_start: fragment.message_start,
                message_end: fragment.message_end,
                query_start: fragment.query_start,
                query_end: fragment.query_end,
                source: fragment.source.clone().ok_or_else(|| {
                    invalid("owned hybrid sample has no authenticated original source")
                })?,
            });
        }
        Ok(Self {
            byte_limit,
            cue_revision: cues.revision.into(),
            text_digest: cues.text_digest,
            text_bytes: cues.text.len() as u32,
            inspected_bytes: cues.inspected_bytes,
            omitted_bytes: cues.omitted_bytes,
            fragments,
            tokens,
        })
    }
}

/// The accepted numerical receipt, without duplicating vectors or query text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridVectorReceipt {
    pub profile_digest: ContentDigest,
    pub kind: EmbeddingTextKind,
    pub text_digest: ContentDigest,
    pub input_digest: ContentDigest,
    pub tokens_digest: ContentDigest,
    pub token_count: u32,
    pub vector_digest: ContentDigest,
}
impl HybridVectorReceipt {
    pub(crate) fn from_embedded(
        value: &EmbeddedText,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        budget.charge(1, 512).map_err(budget_error)?;
        Ok(Self {
            profile_digest: value.profile_digest,
            kind: value.kind,
            text_digest: value.text_digest,
            input_digest: value.input_digest,
            tokens_digest: value.tokens_digest,
            token_count: value.token_count,
            vector_digest: value.vector_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HybridRouteKind {
    Bm25,
    Dense,
    Causal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HybridCompletion {
    Complete,
    RankedLimit,
    PostingLimit,
    WorkLimit,
    ByteLimit,
    DenseLag,
    RawLag,
    TailWorkLimit,
    TailVectorLimit,
    VectorLimit,
    DiscoveryLimit,
    BaseLimit,
    UnprojectedSource,
    CandidateLimit,
    UnsupportedProfile,
    SegmentSelectionLimit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridDenseWitness {
    pub graph_digest: ContentDigest,
    pub observed_dense_commitment: ContentDigest,
    pub proven_dense_commitment: ContentDigest,
    pub base_through: u64,
    pub observed_dense_through: u64,
    pub proven_through: u64,
    pub raw_through: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridRouteObservation {
    pub route: HybridRouteKind,
    pub admitted_sources: BTreeSet<ObservationId>,
    pub ranked_sources: u32,
    pub completion: HybridCompletion,
    pub source_coverage_incomplete: bool,
    pub raw_lag: bool,
    pub dense_lag: bool,
    pub tail_witness_complete: bool,
    pub tail_scoring_complete: bool,
    pub node_reads: u64,
    pub vector_reads: u64,
    pub discovered: u64,
    pub tail_vector_reads: u64,
    /// Exact owner index commitments, retained only inside protected metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dense_witness: Option<HybridDenseWitness>,
    /// Distinct segmented owner provenance; never a reader control block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segmented_dense_witness: Option<HybridSegmentedDenseWitness>,
    /// Arbitrary prefix-v2 routing provenance, separate from the ordinal-prefix profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routed_dense_witness: Option<HybridRoutedDenseWitness>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridRouteRank {
    pub route: HybridRouteKind,
    pub rank: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HybridSelectedSource {
    pub event_id: ObservationId,
    pub routing_micros: u64,
    pub route_ranks: Vec<HybridRouteRank>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedHybridObservation {
    pub revision: String,
    pub intent: OwnedHybridIntent,
    pub checkpoint_receipt: CaptureReceipt,
    pub checkpoint_digest: ContentDigest,
    pub checkpoint_revision: u64,
    pub pack_id: ContextPackId,
    pub known_at: u64,
    pub authorization_epoch: u64,
    /// Actual postrotation caller base; owner admission authenticates this fact.
    pub input_base_digest: ContentDigest,
    /// Final protected base after native controls, independently validated here.
    pub base_digest: ContentDigest,
    pub embedding_profile: TextEmbeddingProfile,
    pub profile_digest: ContentDigest,
    pub sampler_revision: String,
    pub fusion_revision: String,
    pub preflights: Vec<HybridPreflightObservation>,
    pub vector: HybridVectorReceipt,
    pub routes: Vec<HybridRouteObservation>,
    pub selected: Vec<HybridSelectedSource>,
    pub ranked_out: bool,
}

impl OwnedHybridObservation {
    pub(crate) fn validate(
        &self,
        envelope: &RouterEnvelope,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if envelope.trace_version()? != contextdb_core::ROUTER_REPLAY_TRACE_VERSION {
            return Err(integrity(
                "owned hybrid observation requires replay trace v2",
            ));
        }
        self.validate_shape(budget)?;
        if self.pack_id != envelope.request.pack_id
            || self.known_at != envelope.native_view.known_at
            || self.authorization_epoch != envelope.native_view.authorization_epoch
            || self.base_digest
                != contextdb_context::router::canonical_digest(&envelope.base, budget)
                    .map_err(trace_error)?
        {
            return Err(integrity(
                "owned hybrid observation differs from protected owner base or fence",
            ));
        }
        self.validate_preflights(
            &envelope.base,
            &envelope.retrieval_origins.originals,
            budget,
        )?;
        self.validate_routes(&envelope.retrieval_origins.originals, budget)?;
        contextdb_context::router::canonical_bytes(self, budget).map_err(trace_error)?;
        Ok(())
    }

    fn validate_shape(&self, budget: &mut QueryBudget) -> ServiceResult<()> {
        budget.check().map_err(budget_error)?;
        self.intent.validate()?;
        let expected_revision = if self.intent.limits.routed.is_some() {
            routed::ROUTED_HYBRID_OBSERVATION_REVISION
        } else if self.intent.limits.segments.is_some() {
            segments::SEGMENTED_HYBRID_OBSERVATION_REVISION
        } else {
            HYBRID_OBSERVATION_REVISION
        };
        if self.revision != expected_revision
            || self.sampler_revision != DENSE_QUERY_REFINEMENT_REVISION
            || self.fusion_revision != HYBRID_FUSION_REVISION
            || self.preflights.is_empty()
            || self.preflights.len() > 4
            || self.routes.len() != 3
            || self.selected.len() > self.intent.limits.sources as usize
            || self.checkpoint_revision == 0
            || self.checkpoint_receipt.workspace_commit == 0
            || self.checkpoint_receipt.workspace_commit > self.known_at
            || self.checkpoint_receipt.domain != NATIVE_CAPTURE_DOMAIN
            || self.checkpoint_receipt.database_id.is_empty()
            || self.checkpoint_receipt.database_id.len() > 256
            || self.checkpoint_receipt.token.is_empty()
            || self.checkpoint_receipt.token.len() > 65536
            || self.checkpoint_receipt.payload_digest != Some(self.checkpoint_digest)
            || self.checkpoint_receipt.event_id == self.intent.request_event
            || [
                self.checkpoint_digest,
                self.input_base_digest,
                self.base_digest,
                self.profile_digest,
            ]
            .into_iter()
            .any(zero)
        {
            return Err(integrity(
                "owned hybrid observation has invalid fixed identity or bounds",
            ));
        }
        self.embedding_profile.validate()?;
        budget
            .charge(
                8192,
                16384 + self.checkpoint_receipt.token.len() as u64 * 12,
            )
            .map_err(budget_error)?;
        if self.embedding_profile
            != TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(
                self.embedding_profile.backend_artifacts_digest,
            )
            || self.embedding_profile.digest()? != self.profile_digest
        {
            return Err(integrity(
                "owned hybrid encoder differs from fixed complete profile",
            ));
        }
        for p in &self.preflights {
            if p.fragments.is_empty()
                || p.fragments.len() > MAX_FRAGMENTS
                || p.cue_revision != DENSE_QUERY_REFINEMENT_REVISION
                || p.text_bytes == 0
                || p.text_bytes > p.byte_limit
                || p.inspected_bytes > u64::from(p.text_bytes)
                || p.tokens.kind != EmbeddingTextKind::Query
                || p.tokens.profile_digest != self.profile_digest
                || p.tokens.text_digest != p.text_digest
                || p.tokens.token_count == 0
                || p.tokens.token_count > MAX_MEASURED_EMBEDDING_TOKENS
                || [p.text_digest, p.tokens.input_digest, p.tokens.tokens_digest]
                    .into_iter()
                    .any(zero)
                || p.fragments
                    .iter()
                    .any(|f| f.message_id.as_str().len() > 256)
            {
                return Err(integrity(
                    "owned hybrid preflight shape or token receipt is invalid",
                ));
            }
            budget
                .charge(p.fragments.len() as u64 + 1, p.fragments.len() as u64 * 512)
                .map_err(budget_error)?;
        }
        Ok(())
    }

    fn validate_preflights(
        &self,
        base: &OutgoingBase,
        origins: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for (index, p) in self.preflights.iter().enumerate() {
            if p.byte_limit as usize != DENSE_QUERY_PREFLIGHT_BYTE_LIMITS[index] {
                return Err(integrity(
                    "owned hybrid preflight byte limits are not the declared ordered prefix",
                ));
            }
            let cues = dense_step_query_with_byte_limit(base, p.byte_limit as usize, budget)?;
            budget.charge(1, 512).map_err(budget_error)?;
            let expected = HybridPreflightObservation::from_sample(
                p.byte_limit,
                &cues,
                p.tokens.clone(),
                budget,
            )?;
            if expected != *p
                || p.fragments
                    .iter()
                    .any(|f| !origins.contains(&f.source.event_id))
            {
                return Err(integrity(
                    "owned hybrid preflight lost exact sampled bytes, ranges or origins",
                ));
            }
            p.tokens.validate(
                &self.embedding_profile,
                EmbeddingTextKind::Query,
                &cues.text,
                budget,
            )?;
            if self.preflights[..index].iter().any(|previous| {
                previous.tokens.input_digest == p.tokens.input_digest && previous.tokens != p.tokens
            }) {
                return Err(integrity(
                    "owned hybrid fixed tokenizer disagrees on identical exact input",
                ));
            }
            let final_sample = index + 1 == self.preflights.len();
            if (p.tokens.token_count <= self.embedding_profile.max_input_tokens) != final_sample {
                return Err(integrity(
                    "owned hybrid preflight did not stop at the first fitting exact input",
                ));
            }
        }
        let tokens = &self
            .preflights
            .last()
            .ok_or_else(|| integrity("owned hybrid final preflight absent"))?
            .tokens;
        if self.vector.kind != EmbeddingTextKind::Query
            || self.vector.profile_digest != tokens.profile_digest
            || self.vector.text_digest != tokens.text_digest
            || self.vector.input_digest != tokens.input_digest
            || self.vector.tokens_digest != tokens.tokens_digest
            || self.vector.token_count != tokens.token_count
            || zero(self.vector.vector_digest)
        {
            return Err(integrity(
                "owned hybrid single forward differs from final exact preflight",
            ));
        }
        Ok(())
    }

    fn validate_routes(
        &self,
        origins: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if self.routes.len() != 3 || self.selected.len() > self.intent.limits.sources as usize {
            return Err(integrity(
                "owned hybrid route or selected inventory exceeds profile",
            ));
        }
        let mut routes = BTreeMap::new();
        budget
            .charge(1, MAX_SOURCES as u64 * 128)
            .map_err(budget_error)?;
        let mut route_union = BTreeSet::new();
        for (index, route) in self.routes.iter().enumerate() {
            let expected = [
                HybridRouteKind::Bm25,
                HybridRouteKind::Dense,
                HybridRouteKind::Causal,
            ][index];
            if route.route != expected
                || route.admitted_sources.len() > MAX_SOURCES
                || route.ranked_sources as usize > route.admitted_sources.len()
                || route
                    .admitted_sources
                    .iter()
                    .any(|id| !origins.contains(id))
            {
                return Err(integrity(
                    "owned hybrid route inventory differs from inspected origin closure",
                ));
            }
            budget
                .charge(route.admitted_sources.len() as u64 + 1, 1024)
                .map_err(budget_error)?;
            route.validate(&self.intent, self.known_at, budget)?;
            if let Some(witness) = route.routed_dense_witness.as_ref() {
                budget.charge(8192, 16384).map_err(budget_error)?;
                if witness.source_profile_digest != self.profile_digest
                    || witness.source_space_id != self.embedding_profile.vector_space_id()?
                {
                    return Err(integrity(
                        "routed source space differs from the exact query encoder",
                    ));
                }
            }
            route_union.extend(route.admitted_sources.iter().copied());
            if route_union.len() > MAX_SOURCES {
                return Err(integrity(
                    "owned hybrid route union exceeds inspected source bound",
                ));
            }
            routes.insert(route.route, route);
        }
        let mut selected_ids = BTreeSet::new();
        let mut positions = BTreeSet::new();
        let mut previous: Option<(u64, ObservationId)> = None;
        for selected in &self.selected {
            budget.charge(4, 512).map_err(budget_error)?;
            if selected.route_ranks.is_empty()
                || selected.route_ranks.len() > 3
                || !selected_ids.insert(selected.event_id)
                || !origins.contains(&selected.event_id)
            {
                return Err(integrity(
                    "owned hybrid selected source inventory is invalid",
                ));
            }
            let mut total = 0_u64;
            let mut previous_route = None;
            for rank in &selected.route_ranks {
                let route = routes
                    .get(&rank.route)
                    .ok_or_else(|| integrity("owned hybrid selected route absent"))?;
                if rank.rank == 0
                    || rank.rank > route.ranked_sources
                    || !route.admitted_sources.contains(&selected.event_id)
                    || previous_route.is_some_and(|previous| previous >= rank.route)
                    || !positions.insert((rank.route, rank.rank))
                {
                    return Err(integrity(
                        "owned hybrid selected source route rank is inconsistent",
                    ));
                }
                previous_route = Some(rank.route);
                total = total
                    .checked_add(1_000_000 / (60 + u64::from(rank.rank)))
                    .ok_or_else(|| integrity("owned hybrid RRF total overflow"))?;
            }
            if total != selected.routing_micros
                || previous.is_some_and(|(score, id)| {
                    score < total || (score == total && id >= selected.event_id)
                })
            {
                return Err(integrity(
                    "owned hybrid fixed RRF values or stable source order differ",
                ));
            }
            previous = Some((total, selected.event_id));
        }
        if self.ranked_out && self.selected.len() != self.intent.limits.sources as usize {
            return Err(integrity(
                "owned hybrid ranked limit does not retain its declared source cap",
            ));
        }
        Ok(())
    }
}

impl HybridRouteObservation {
    fn validate(
        &self,
        intent: &OwnedHybridIntent,
        known_at: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        use HybridCompletion as C;
        let valid_completion = match self.route {
            HybridRouteKind::Bm25 => matches!(
                self.completion,
                C::Complete | C::RankedLimit | C::PostingLimit | C::WorkLimit | C::ByteLimit
            ),
            HybridRouteKind::Dense => matches!(
                self.completion,
                C::Complete
                    | C::DenseLag
                    | C::RawLag
                    | C::TailWorkLimit
                    | C::TailVectorLimit
                    | C::VectorLimit
                    | C::DiscoveryLimit
                    | C::BaseLimit
                    | C::SegmentSelectionLimit
            ),
            HybridRouteKind::Causal => matches!(
                self.completion,
                C::Complete
                    | C::RawLag
                    | C::UnprojectedSource
                    | C::CandidateLimit
                    | C::PostingLimit
                    | C::WorkLimit
                    | C::ByteLimit
                    | C::UnsupportedProfile
            ),
        };
        if !valid_completion {
            return Err(integrity(
                "owned hybrid route completion has the wrong route profile",
            ));
        }
        if self.route == HybridRouteKind::Dense {
            if intent.limits.routed.is_some() {
                if self.dense_witness.is_some()
                    || self.segmented_dense_witness.is_some()
                    || self.completion == C::SegmentSelectionLimit
                {
                    return Err(integrity(
                        "routed hybrid route carries another profile witness",
                    ));
                }
                self.routed_dense_witness
                    .as_ref()
                    .ok_or_else(|| {
                        integrity("routed hybrid route lacks protected routing witness")
                    })?
                    .validate(self, intent, known_at, budget)?;
            } else if intent.limits.segments.is_some() {
                if self.dense_witness.is_some()
                    || self.routed_dense_witness.is_some()
                    || self.completion == C::RankedLimit
                {
                    return Err(integrity(
                        "segmented hybrid route carries the old base witness",
                    ));
                }
                self.segmented_dense_witness
                    .as_ref()
                    .ok_or_else(|| {
                        integrity("segmented hybrid route has no protected segment witness")
                    })?
                    .validate(self, intent, known_at, budget)?;
            } else {
                if self.segmented_dense_witness.is_some()
                    || self.routed_dense_witness.is_some()
                    || matches!(self.completion, C::SegmentSelectionLimit | C::RankedLimit)
                {
                    return Err(integrity("old hybrid profile carries segmented provenance"));
                }
                let witness = self.dense_witness.as_ref().ok_or_else(|| {
                    integrity("owned hybrid dense route has no authenticated prefix witness")
                })?;
                if [
                    witness.graph_digest,
                    witness.observed_dense_commitment,
                    witness.proven_dense_commitment,
                ]
                .into_iter()
                .any(zero)
                    || witness.base_through > witness.proven_through
                    || witness.proven_through > witness.observed_dense_through
                    || witness.observed_dense_through > witness.raw_through
                    || witness.raw_through > known_at
                    || self.dense_lag != (witness.observed_dense_through < witness.raw_through)
                    || (self.tail_witness_complete
                        && witness.proven_through != witness.observed_dense_through)
                    || (!self.tail_witness_complete
                        && witness.proven_through != witness.base_through)
                    || (witness.proven_through == witness.observed_dense_through
                        && witness.proven_dense_commitment != witness.observed_dense_commitment)
                {
                    return Err(integrity(
                        "owned hybrid dense witness differs from its proved prefix or current cutoff",
                    ));
                }
            }
            if self.node_reads > u64::from(intent.limits.node_reads)
                || self.vector_reads > u64::from(intent.limits.vector_reads)
                || self.discovered > u64::from(intent.limits.discovered)
                || self.tail_vector_reads > u64::from(intent.limits.tail_vectors)
                || self.tail_vector_reads > self.vector_reads
                || (self.tail_scoring_complete && !self.tail_witness_complete)
                || (self.completion == C::Complete
                    && (self.raw_lag
                        || self.dense_lag
                        || !self.tail_witness_complete
                        || !self.tail_scoring_complete))
                || (self.completion == C::RawLag && !self.raw_lag)
                || (self.completion == C::DenseLag && !self.dense_lag)
                || (self.completion == C::TailWorkLimit
                    && (self.tail_witness_complete || self.tail_scoring_complete))
            {
                return Err(integrity(
                    "owned hybrid dense counters or projected-prefix completion disagree",
                ));
            }
        } else if self.dense_witness.is_some()
            || self.segmented_dense_witness.is_some()
            || self.routed_dense_witness.is_some()
            || self.dense_lag
            || self.tail_witness_complete
            || self.tail_scoring_complete
            || self.node_reads != 0
            || self.vector_reads != 0
            || self.discovered != 0
            || self.tail_vector_reads != 0
            || (self.route == HybridRouteKind::Causal
                && self.completion == C::Complete
                && self.raw_lag)
            || (self.completion == C::RawLag && !self.raw_lag)
        {
            return Err(integrity(
                "owned hybrid non-dense route carries dense or contradictory progress",
            ));
        }
        Ok(())
    }
}

fn zero(digest: ContentDigest) -> bool {
    digest == ContentDigest::from_bytes([0; 32])
}

#[cfg(test)]
mod tests;
