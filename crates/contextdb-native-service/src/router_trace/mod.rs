//! Owner-prepared query-time material, outside reader wire and independent roots.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::router::{
    AuthorizedRouterRequest, RouterManifest, RouterReplayObservation, RouterSelectionPlan,
    canonical_bytes, canonical_digest as router_digest,
};
use contextdb_context::{BlockId, ContextError, EvidenceHandle, OutgoingBase};
use contextdb_core::{ContentDigest, EventEnvelope, EventPayload};
use contextdb_recall::{IndexedCompletion, QueryBudget};
use serde::{Deserialize, Serialize};

use crate::prepare::PrepareFence;
use crate::{integrity, invalid};
use contextdb_service::{
    PrepareRecallQuery, PreparedRouterTrace, RouterTraceProfile, ServiceResult,
};

pub(crate) mod controls;
pub(crate) mod material;
mod read;
mod source_wire;
#[cfg(test)]
mod tests;
pub(super) const TRACE_FEATURE: &str = "continuous-router-trace-v1";
pub(super) const TRACE_REPLAY_FEATURE: &str = "continuous-router-trace-v2";
const FORMAT: &str = "contextdb.native_router_trace.v1";
const REPLAY_FORMAT: &str = "contextdb.native_router_trace.v2";

use controls::RouterTraceControls;

pub(super) use contextdb_context::router::RouterPreparedMaterial as PreparedMaterials;

/// Only native-generated diagnostic kinds may have no captured origin.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum NativeControlKind {
    Situation,
    PendingInterpretation,
    RequiredFacet,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnitOrigin {
    pub controls: RouterTraceControls,
    pub native_control: Option<NativeControlKind>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RouterEnvelope {
    format: String,
    pub request: AuthorizedRouterRequest,
    pub plan: RouterSelectionPlan,
    pub manifest: RouterManifest,
    pub native_view: PrepareFence,
    pub base: OutgoingBase,
    pub origins: RouterTraceControls,
    pub unit_origins: BTreeMap<BlockId, UnitOrigin>,
    pub evidence_origins: BTreeMap<EvidenceHandle, RouterTraceControls>,
    pub base_origins: RouterTraceControls,
    pub retrieval_origins: RouterTraceControls,
    pub materials: PreparedMaterials,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_observation: Option<RouterReplayObservation>,
    pub discovery: Vec<IndexedCompletion>,
    pub generic_query: Option<PrepareRecallQuery>,
    pub generic_discovery: Option<material::GenericRecallObservation>,
}

impl RouterEnvelope {
    #[allow(clippy::too_many_arguments, reason = "one protected prepared envelope")]
    pub(super) fn new(
        request: AuthorizedRouterRequest,
        plan: RouterSelectionPlan,
        manifest: RouterManifest,
        native_view: PrepareFence,
        base: OutgoingBase,
        unit_origins: BTreeMap<BlockId, UnitOrigin>,
        evidence_origins: BTreeMap<EvidenceHandle, RouterTraceControls>,
        materials: PreparedMaterials,
        discovery: Vec<IndexedCompletion>,
        retrieval_origins: RouterTraceControls,
        generic_query: Option<PrepareRecallQuery>,
        generic_discovery: Option<material::GenericRecallObservation>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        Self::new_for_profile(
            RouterTraceProfile::Required,
            None,
            request,
            plan,
            manifest,
            native_view,
            base,
            unit_origins,
            evidence_origins,
            materials,
            discovery,
            retrieval_origins,
            generic_query,
            generic_discovery,
            budget,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one explicit protected preparation profile"
    )]
    pub(super) fn new_for_profile(
        profile: RouterTraceProfile,
        replay_observation: Option<RouterReplayObservation>,
        request: AuthorizedRouterRequest,
        plan: RouterSelectionPlan,
        manifest: RouterManifest,
        native_view: PrepareFence,
        base: OutgoingBase,
        unit_origins: BTreeMap<BlockId, UnitOrigin>,
        evidence_origins: BTreeMap<EvidenceHandle, RouterTraceControls>,
        materials: PreparedMaterials,
        discovery: Vec<IndexedCompletion>,
        retrieval_origins: RouterTraceControls,
        generic_query: Option<PrepareRecallQuery>,
        generic_discovery: Option<material::GenericRecallObservation>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        let format = match profile {
            RouterTraceProfile::Required => FORMAT,
            RouterTraceProfile::RequiredReplayV2 => REPLAY_FORMAT,
            RouterTraceProfile::Off => return Err(invalid("Off has no protected router envelope")),
        };
        let mut base_origins = RouterTraceControls::default();
        base_origins.originals.extend(
            base.working
                .iter()
                .chain(&base.hot)
                .chain(&base.current)
                .flat_map(|message| message.originals.iter().map(|item| item.span.event_id)),
        );
        let mut origins = base_origins.clone();
        origins.union_checked(&retrieval_origins)?;
        for unit in unit_origins.values() {
            origins.union_checked(&unit.controls)?;
        }
        for evidence in evidence_origins.values() {
            origins.union_checked(evidence)?;
        }
        let envelope = Self {
            format: format.into(),
            request,
            plan,
            manifest,
            native_view,
            base,
            origins,
            unit_origins,
            evidence_origins,
            base_origins,
            retrieval_origins,
            materials,
            replay_observation,
            discovery,
            generic_query,
            generic_discovery,
        };
        envelope.validate(budget)?;
        Ok(envelope)
    }

    pub(super) fn validate(&self, budget: &mut QueryBudget) -> ServiceResult<()> {
        self.validate_material_profile()?;
        self.request.validate(budget).map_err(trace_error)?;
        self.plan
            .validate(&self.request, budget)
            .map_err(trace_error)?;
        self.origins.validate()?;
        match (&self.generic_query, &self.generic_discovery) {
            (None, None) => {}
            (Some(query), Some(discovery))
                if discovery.query_digest == crate::canonical_digest(query)?
                    && discovery.snapshot.commit_seq == self.native_view.known_at
                    && discovery.inspected_records <= 100 => {}
            _ => {
                return Err(integrity(
                    "generic routing observation differs from its prepared query",
                ));
            }
        }
        if self.manifest.request_digest != self.request.digest
            || self.manifest.candidate_digest != self.request.binding.candidates
            || self.manifest.plan_digest
                != router_digest(&self.plan, budget).map_err(trace_error)?
            || self.manifest.assembly.wire_digest != self.plan.wire_digest
            || self.manifest.assembly.read_set.binding != self.request.binding.owner
            || self.manifest.assembly.read_set.scopes != self.request.context.scopes
            || self.plan.input_tokens != self.manifest.assembly.input_tokens
            || self.plan.count_kind != self.manifest.assembly.count_kind
            || self.manifest.trained_weights.is_some()
            || self.manifest.training_dataset.is_some()
            || self.request.binding.control
                != router_digest(&self.base.control, budget).map_err(trace_error)?
            || self.request.binding.working
                != router_digest(&self.base.working, budget).map_err(trace_error)?
            || self.request.binding.hot
                != router_digest(&self.base.hot, budget).map_err(trace_error)?
            || self.request.binding.current
                != router_digest(&self.base.current, budget).map_err(trace_error)?
        {
            return Err(integrity("protected routing envelope commitments disagree"));
        }
        let units: BTreeSet<_> = self.request.units.iter().map(|unit| &unit.id).collect();
        let candidates: BTreeSet<_> = self
            .materials
            .candidates
            .iter()
            .map(|candidate| &candidate.id)
            .collect();
        let handles: BTreeSet<_> = self
            .request
            .units
            .iter()
            .flat_map(|unit| &unit.support_alternatives)
            .flat_map(|alternative| &alternative.evidence_handles)
            .collect();
        let evidence: BTreeSet<_> = self
            .materials
            .evidence
            .iter()
            .map(|item| &item.id)
            .collect();
        if units != candidates
            || candidates.len() != self.materials.candidates.len()
            || self.unit_origins.keys().collect::<BTreeSet<_>>() != units
            || handles != evidence
            || evidence.len() != self.materials.evidence.len()
            || self.evidence_origins.keys().collect::<BTreeSet<_>>() != handles
        {
            return Err(integrity(
                "protected material or origin inventory is incomplete",
            ));
        }
        let mut closure = self.base_origins.clone();
        let expected_base: BTreeSet<_> = self
            .base
            .working
            .iter()
            .chain(&self.base.hot)
            .chain(&self.base.current)
            .flat_map(|message| message.originals.iter().map(|item| item.span.event_id))
            .collect();
        if self.base_origins.originals != expected_base
            || !self.base_origins.records.is_empty()
            || !self.base_origins.states.is_empty()
        {
            return Err(integrity(
                "protected base origins differ from actual source spans",
            ));
        }
        closure.union_checked(&self.retrieval_origins)?;
        for (id, unit) in &self.unit_origins {
            unit.controls.validate()?;
            let empty = unit.controls.originals.is_empty()
                && unit.controls.records.is_empty()
                && unit.controls.states.is_empty();
            let candidate = self
                .materials
                .candidates
                .iter()
                .find(|candidate| &candidate.id == id)
                .ok_or_else(|| integrity("registered router material is absent"))?;
            let native_valid = unit.native_control.is_none_or(|kind| match kind {
                NativeControlKind::Situation => {
                    id.as_str() == "contextdb:situation"
                        && candidate.kind == contextdb_context::PackBlockKind::Situation
                        && candidate.mandatory
                }
                NativeControlKind::PendingInterpretation => {
                    candidate.kind == contextdb_context::PackBlockKind::Unknown
                        && candidate.mandatory
                        && self
                            .request
                            .context
                            .scopes
                            .iter()
                            .any(|scope| id.as_str() == format!("contextdb:pending:{scope}"))
                }
                NativeControlKind::RequiredFacet => {
                    candidate.kind == contextdb_context::PackBlockKind::Unknown
                        && candidate.mandatory
                        && candidate
                            .unknown
                            .as_ref()
                            .is_some_and(|unknown| unknown.blocking)
                        && candidate.representations.iter().any(|representation| {
                            representation
                                .fields
                                .get("missing_facet")
                                .is_some_and(|name| {
                                    self.request
                                        .context
                                        .required_facets
                                        .iter()
                                        .any(|facet| facet.name == *name)
                                        && id.as_str()
                                            == format!(
                                                "unknown:{}",
                                                &blake3::hash(name.as_bytes()).to_hex().to_string()
                                                    [..16]
                                            )
                                })
                        })
                }
            });
            if empty != unit.native_control.is_some() || !native_valid {
                return Err(integrity(
                    "routing material has unclassified native origins",
                ));
            }
            closure.union_checked(&unit.controls)?;
        }
        for item in &self.materials.evidence {
            let controls = &self.evidence_origins[&item.id];
            if item
                .original_span
                .as_ref()
                .is_some_and(|span| !controls.originals.contains(&span.event_id))
            {
                return Err(integrity("routing evidence lost its captured origin"));
            }
            closure.union_checked(controls)?;
        }
        if closure != self.origins {
            return Err(integrity("protected routing origin union is not complete"));
        }
        if self.trace_version()? == contextdb_core::ROUTER_REPLAY_TRACE_VERSION {
            // Static retained-material admission does not execute the selector or
            // establish a fresh wire/tokenizer replay. The owner seal binds it.
            contextdb_context::router::validate_router_material(
                &self.request,
                &self.materials,
                budget,
            )
            .map_err(replay_metadata_error)?;
            let preparation = self
                .materials
                .prepared_policy
                .as_ref()
                .and_then(|policy| policy.replay.as_ref())
                .ok_or_else(|| integrity("native router trace v2 preparation is absent"))?;
            contextdb_context::ContextCompiler::validate_router_replay_observation(
                &self.request,
                &self.manifest,
                preparation,
                self.replay_observation
                    .as_ref()
                    .ok_or_else(|| integrity("native router trace v2 observation is absent"))?,
                budget,
            )
            .map_err(replay_metadata_error)?;
        }
        canonical_bytes(self, budget).map_err(trace_error)?;
        Ok(())
    }

    fn validate_material_profile(&self) -> ServiceResult<()> {
        match self.trace_version()? {
            contextdb_core::ROUTER_TRACE_VERSION => {
                if self.materials.prepared_policy.is_some() {
                    return Err(integrity(
                        "native router trace v1 does not support prepared policy material",
                    ));
                }
                if self.replay_observation.is_some() {
                    return Err(integrity(
                        "native router trace v1 does not support replay observations",
                    ));
                }
            }
            contextdb_core::ROUTER_REPLAY_TRACE_VERSION => {
                if self
                    .materials
                    .prepared_policy
                    .as_ref()
                    .and_then(|policy| policy.replay.as_ref())
                    .is_none()
                    || self.replay_observation.is_none()
                {
                    return Err(integrity(
                        "native router trace v2 requires complete replay preparation and observation",
                    ));
                }
            }
            _ => unreachable!("trace_version admits only the explicit formats"),
        }
        Ok(())
    }

    pub(super) fn trace_version(&self) -> ServiceResult<u16> {
        match self.format.as_str() {
            FORMAT => Ok(contextdb_core::ROUTER_TRACE_VERSION),
            REPLAY_FORMAT => Ok(contextdb_core::ROUTER_REPLAY_TRACE_VERSION),
            _ => Err(integrity("native router trace format is unsupported")),
        }
    }
}

impl crate::NativeService {
    pub(super) fn prepare_router_envelope(
        &self,
        envelope: &RouterEnvelope,
        assembly: &contextdb_context::CompiledAssembly,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PreparedRouterTrace> {
        envelope.validate_material_profile()?;
        if envelope.trace_version()? == contextdb_core::ROUTER_REPLAY_TRACE_VERSION {
            envelope.validate(budget)?;
        }
        envelope
            .manifest
            .validate(&envelope.request, &envelope.plan, assembly, budget)
            .map_err(trace_error)?;
        let bytes = canonical_bytes(envelope, budget).map_err(trace_error)?;
        Ok(PreparedRouterTrace {
            version: envelope.trace_version()?,
            pack_id: envelope.request.pack_id,
            wire_digest: assembly.manifest.wire_digest,
            wire_byte_length: assembly.outgoing.wire.len() as u64,
            router_request_digest: envelope.request.digest,
            router_plan_digest: router_digest(&envelope.plan, budget).map_err(trace_error)?,
            router_manifest_digest: router_digest(&envelope.manifest, budget)
                .map_err(trace_error)?,
            origin_closure_digest: router_digest(&envelope.origins, budget).map_err(trace_error)?,
            trace_digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
            canonical_json: String::from_utf8(bytes)
                .map_err(|_| integrity("router canonical envelope is not UTF-8"))?,
            seal: String::new(), // Filled by the native admission seal before returning preparation.
        })
    }
}

pub(super) fn prepared_envelope(
    trace: &PreparedRouterTrace,
    budget: &mut QueryBudget,
) -> ServiceResult<RouterEnvelope> {
    trace.validate()?;
    budget
        .charge(1, trace.canonical_json.len() as u64)
        .map_err(crate::raw_index::budget_error)?;
    let envelope: RouterEnvelope = serde_json::from_str(&trace.canonical_json)
        .map_err(|_| integrity("prepared router envelope is malformed"))?;
    if canonical_bytes(&envelope, budget).map_err(trace_error)? != trace.canonical_json.as_bytes() {
        return Err(integrity("prepared router envelope is not canonical"));
    }
    envelope.validate(budget)?;
    if trace.version != envelope.trace_version()?
        || trace.pack_id != envelope.request.pack_id
        || trace.router_request_digest != envelope.request.digest
        || trace.router_plan_digest != router_digest(&envelope.plan, budget).map_err(trace_error)?
        || trace.router_manifest_digest
            != router_digest(&envelope.manifest, budget).map_err(trace_error)?
        || trace.origin_closure_digest
            != router_digest(&envelope.origins, budget).map_err(trace_error)?
        || trace.wire_digest != envelope.manifest.assembly.wire_digest
    {
        return Err(integrity("prepared trace differs from its envelope"));
    }
    Ok(envelope)
}

pub(super) fn decode_envelope(
    event: &EventEnvelope,
    budget: &mut QueryBudget,
) -> ServiceResult<Option<RouterEnvelope>> {
    let EventPayload::Assembly { manifest } = &event.payload else {
        return Ok(None);
    };
    let Some(trace) = &manifest.router_trace else {
        return Ok(None);
    };
    trace
        .validate_for_model_request(manifest)
        .map_err(|_| integrity("protected router attachment is invalid"))?;
    budget
        .charge(1, u64::from(trace.header.byte_length))
        .map_err(crate::raw_index::budget_error)?;
    let text = trace
        .canonical_json()
        .map_err(|_| integrity("protected router pages are invalid"))?;
    let envelope: RouterEnvelope = serde_json::from_str(&text)
        .map_err(|_| integrity("protected router envelope is malformed"))?;
    if canonical_bytes(&envelope, budget).map_err(trace_error)? != text.as_bytes() {
        return Err(integrity("protected router envelope is not canonical"));
    }
    envelope.validate(budget)?;
    let header = &trace.header;
    if header.version != envelope.trace_version()?
        || header.pack_id != envelope.request.pack_id
        || header.router_request_digest != envelope.request.digest
        || header.router_plan_digest
            != router_digest(&envelope.plan, budget).map_err(trace_error)?
        || header.router_manifest_digest
            != router_digest(&envelope.manifest, budget).map_err(trace_error)?
        || header.origin_closure_digest
            != router_digest(&envelope.origins, budget).map_err(trace_error)?
        || header.wire_digest != envelope.manifest.assembly.wire_digest
    {
        return Err(integrity(
            "protected router header differs from its envelope",
        ));
    }
    Ok(Some(envelope))
}

pub(crate) fn trace_controls(event: &EventEnvelope) -> ServiceResult<Option<RouterTraceControls>> {
    let mut budget = QueryBudget::new(
        500_000,
        64 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        contextdb_recall::QueryCancellation::default(),
    );
    Ok(decode_envelope(event, &mut budget)?.map(|envelope| envelope.origins))
}

pub(super) fn trace_error(error: ContextError) -> contextdb_service::ServiceError {
    match error {
        ContextError::BudgetExceeded(_) => {
            crate::exhausted("protected trace exceeded its shared profile")
        }
        _ => invalid("protected routing material is inconsistent"),
    }
}

fn replay_metadata_error(error: ContextError) -> contextdb_service::ServiceError {
    match error {
        ContextError::BudgetExceeded(_) => trace_error(error),
        _ => integrity("protected replay metadata differs from compiler commitments"),
    }
}
