//! Owner-prepared query-time material, outside reader wire and independent roots.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::router::{
    AuthorizedRouterRequest, RouterManifest, RouterSelectionPlan, canonical_bytes,
    canonical_digest as router_digest,
};
use contextdb_context::{BlockId, ContextError, EvidenceHandle, OutgoingBase};
use contextdb_core::{ContentDigest, EventEnvelope, EventPayload};
use contextdb_recall::{IndexedCompletion, QueryBudget};
use serde::{Deserialize, Serialize};

use crate::prepare::PrepareFence;
use crate::{integrity, invalid};
use contextdb_service::{PrepareRecallQuery, PreparedRouterTrace, ServiceResult};

pub(crate) mod controls;
pub(crate) mod material;
#[cfg(test)]
mod tests;
pub(super) const TRACE_FEATURE: &str = "continuous-router-trace-v1";
const FORMAT: &str = "contextdb.native_router_trace.v1";

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
            format: FORMAT.into(),
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
            discovery,
            generic_query,
            generic_discovery,
        };
        envelope.validate(budget)?;
        Ok(envelope)
    }

    pub(super) fn validate(&self, budget: &mut QueryBudget) -> ServiceResult<()> {
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
        if self.format != FORMAT
            || self.manifest.request_digest != self.request.digest
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
        canonical_bytes(self, budget).map_err(trace_error)?;
        Ok(())
    }
}

impl crate::NativeService {
    pub(super) fn prepare_router_envelope(
        &self,
        envelope: &RouterEnvelope,
        assembly: &contextdb_context::CompiledAssembly,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PreparedRouterTrace> {
        envelope
            .manifest
            .validate(&envelope.request, &envelope.plan, assembly, budget)
            .map_err(trace_error)?;
        let bytes = canonical_bytes(envelope, budget).map_err(trace_error)?;
        Ok(PreparedRouterTrace {
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
    if trace.pack_id != envelope.request.pack_id
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
    let text = trace
        .canonical_json()
        .map_err(|_| integrity("protected router pages are invalid"))?;
    budget
        .charge(1, text.len() as u64)
        .map_err(crate::raw_index::budget_error)?;
    let envelope: RouterEnvelope = serde_json::from_str(&text)
        .map_err(|_| integrity("protected router envelope is malformed"))?;
    if canonical_bytes(&envelope, budget).map_err(trace_error)? != text.as_bytes() {
        return Err(integrity("protected router envelope is not canonical"));
    }
    envelope.validate(budget)?;
    let header = &trace.header;
    if header.pack_id != envelope.request.pack_id
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
