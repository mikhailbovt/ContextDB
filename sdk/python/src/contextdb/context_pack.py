"""Typed policy-first ``POST /v1/context-pack`` wire contract."""

from __future__ import annotations

import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeAlias, TypeVar

from blake3 import blake3

from .domain import AuthenticatedRequestContext
from .errors import ProtocolError
from .models import JsonObject, _boolean, _mapping, _string, _string_tuple, _uint

CONTEXT_PACK_CANONICAL_ENCODING = "contextdb.context_pack.protobuf.v1"
CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM = "blake3-256"


class RecallMode(StrEnum):
    NEVER = "never"
    OPTIONAL = "optional"
    AUTO = "auto"
    REQUIRED = "required"
    IMPLICIT_CONTINUITY = "implicit_continuity"
    EXPLICIT = "explicit"
    ASSOCIATIVE = "associative"
    RELATIONAL = "relational"
    HISTORICAL = "historical"
    FORENSIC = "forensic"


class RecallIntent(StrEnum):
    CONTINUITY = "continuity"
    CURRENT_TRUTH = "current_truth"
    HISTORICAL_TRUTH = "historical_truth"
    ASSOCIATIVE = "associative"
    RELATIONAL = "relational"
    PROCEDURAL = "procedural"
    REFLECTIVE = "reflective"
    FORENSIC = "forensic"
    BOOTSTRAP = "bootstrap"
    PREFLIGHT = "preflight"


class PackPurpose(StrEnum):
    CONVERSATION = "conversation"
    CONTINUITY = "continuity"
    AUTOBIOGRAPHICAL = "autobiographical"
    KNOWLEDGE = "knowledge"
    HISTORICAL = "historical"
    REFLECTIVE = "reflective"
    ACTION = "action"
    HANDOFF = "handoff"
    BOOTSTRAP = "bootstrap"


class RendererKind(StrEnum):
    COMPACT = "compact"
    HOSTED_STRUCTURED = "hosted_structured"
    CHAT = "chat"
    CODING = "coding"
    CANONICAL_JSON = "canonical_json"


class StructuredFormat(StrEnum):
    COMPACT_TEXT = "compact_text"
    JSON = "json"
    MARKDOWN = "markdown"
    TOOL_RESULT = "tool_result"


class PositionProfile(StrEnum):
    BALANCED = "balanced"
    CRITICAL_FIRST = "critical_first"
    EVIDENCE_ADJACENT = "evidence_adjacent"
    SMALL_MODEL_EXPLICIT = "small_model_explicit"


class InstructionHierarchy(StrEnum):
    SEPARATED_CHANNELS = "separated_channels"
    SINGLE_PROMPT_DELIMITED = "single_prompt_delimited"


class PackStatus(StrEnum):
    SUFFICIENT = "sufficient"
    PARTIAL = "partial"
    NO_MEMORY = "no_memory"


class RecallStatus(StrEnum):
    SKIPPED = "skipped"
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class StopReason(StrEnum):
    GATE_SKIPPED = "gate_skipped"
    SUFFICIENT = "sufficient"
    NODE_BUDGET = "node_budget"
    GRAPH_BUDGET = "graph_budget"
    HOP_BUDGET = "hop_budget"
    TOKEN_BUDGET = "token_budget"
    DEADLINE = "deadline"
    NO_USEFUL_CANDIDATES = "no_useful_candidates"
    UNKNOWN_OR_CONFLICTED = "unknown_or_conflicted"
    CONTINUATION_BOUNDARY = "continuation_boundary"


class PackBlockKind(StrEnum):
    SITUATION = "situation"
    SELF_CONTEXT = "self_context"
    PARTICIPANT = "participant"
    SHARED_HISTORY = "shared_history"
    EPISODE = "episode"
    FACT = "fact"
    RELATIONSHIP = "relationship"
    PREFERENCE = "preference"
    BOUNDARY = "boundary"
    GOAL = "goal"
    DECISION = "decision"
    TIMELINE = "timeline"
    PROCEDURE = "procedure"
    CONSTRAINT = "constraint"
    OPEN_LOOP = "open_loop"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"
    RAW_OBSERVATION = "raw_observation"


class CompressionLevel(StrEnum):
    L0_ORIENTATION = "l0_orientation"
    L1_SUMMARY = "l1_summary"
    L2_STRUCTURED = "l2_structured"
    L3_EVIDENCE = "l3_evidence"
    L4_RAW = "l4_raw"


class ContentTrust(StrEnum):
    TRUSTED_SOURCE = "trusted_source"
    MIXED = "mixed"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class InstructionCapability(StrEnum):
    NONE = "none"
    HOST_TRUSTED = "host_trusted"


class InterpretationRule(StrEnum):
    FACTUAL_DATA = "factual_data"
    HISTORICAL_DATA = "historical_data"
    CONSTRAINT_DATA = "constraint_data"
    STYLE_SIGNAL = "style_signal"
    HYPOTHESIS_ONLY = "hypothesis_only"
    UNKNOWN_MARKER = "unknown_marker"
    CONFLICT_ALTERNATIVES = "conflict_alternatives"


class UseAction(StrEnum):
    MENTION_NATURALLY = "mention_naturally"
    USE_SILENTLY = "use_silently"
    CONSTRAINT_ONLY = "constraint_only"
    STYLE_ONLY = "style_only"


class DirectiveReason(StrEnum):
    POLICY_ALLOWS_MENTION = "policy_allows_mention"
    MENTION_DENIED = "mention_denied"
    EXPLICIT_REQUEST_REQUIRED = "explicit_request_required"
    CONSTRAINT_SEMANTICS = "constraint_semantics"
    STYLE_SEMANTICS = "style_semantics"


class OmissionReason(StrEnum):
    OUTSIDE_REQUESTED_SCOPE = "outside_requested_scope"
    FUTURE_TRANSACTION = "future_transaction"
    EPISTEMICALLY_INACTIVE = "epistemically_inactive"
    SECRET_REDACTED = "secret_redacted"
    UNSUPPORTED_UNDER_EVIDENCE_POLICY = "unsupported_under_evidence_policy"
    UNRESOLVED_CONFLICT_WITHOUT_MANIFEST = "unresolved_conflict_without_manifest"
    REDUNDANT = "redundant"
    BLOCK_BUDGET = "block_budget"
    TOKEN_BUDGET = "token_budget"
    EVIDENCE_BUDGET = "evidence_budget"
    HISTORY_BUDGET = "history_budget"
    CONFLICT_BUDGET = "conflict_budget"
    SERIALIZATION_BUDGET = "serialization_budget"
    SELECTION_EVALUATION_BUDGET = "selection_evaluation_budget"
    CONTINUATION_BOUNDARY = "continuation_boundary"


class NoMemoryReason(StrEnum):
    NO_AUTHORIZED_CANDIDATES = "no_authorized_candidates"
    NO_RELEVANT_CANDIDATES = "no_relevant_candidates"
    BUDGET_COULD_NOT_ADMIT_OPTIONAL_MEMORY = "budget_could_not_admit_optional_memory"


@dataclass(frozen=True, slots=True)
class OtherVariant:
    """The payload of Rust enum variants serialized as ``{"other": value}``."""

    value: str

    def to_wire(self) -> JsonObject:
        return {"other": self.value}


RecallIntentValue: TypeAlias = RecallIntent | OtherVariant
StringOrOther: TypeAlias = str | OtherVariant


@dataclass(frozen=True, slots=True)
class PackFacetRequirement:
    name: str
    minimum_confidence_micros: int
    require_evidence: bool

    def to_wire(self) -> JsonObject:
        return {
            "name": self.name,
            "minimum_confidence_micros": self.minimum_confidence_micros,
            "require_evidence": self.require_evidence,
        }


@dataclass(frozen=True, slots=True)
class RecallLimits:
    max_nodes_examined: int
    max_seed_candidates: int
    max_graph_hops: int
    max_frontier_per_hop: int
    max_evidence_units: int
    max_context_tokens: int
    deadline_micros: int

    def to_wire(self) -> JsonObject:
        return {
            "max_nodes_examined": self.max_nodes_examined,
            "max_seed_candidates": self.max_seed_candidates,
            "max_graph_hops": self.max_graph_hops,
            "max_frontier_per_hop": self.max_frontier_per_hop,
            "max_evidence_units": self.max_evidence_units,
            "max_context_tokens": self.max_context_tokens,
            "deadline_micros": self.deadline_micros,
        }


@dataclass(frozen=True, slots=True)
class ContextBudgets:
    hard_tokens: int
    soft_tokens: int
    max_blocks: int
    max_evidence_blocks: int
    max_raw_evidence_tokens: int
    max_history_tokens: int
    max_conflict_tokens: int
    max_serialized_bytes: int
    max_selection_evaluations: int

    def to_wire(self) -> JsonObject:
        return {
            "hard_tokens": self.hard_tokens,
            "soft_tokens": self.soft_tokens,
            "max_blocks": self.max_blocks,
            "max_evidence_blocks": self.max_evidence_blocks,
            "max_raw_evidence_tokens": self.max_raw_evidence_tokens,
            "max_history_tokens": self.max_history_tokens,
            "max_conflict_tokens": self.max_conflict_tokens,
            "max_serialized_bytes": self.max_serialized_bytes,
            "max_selection_evaluations": self.max_selection_evaluations,
        }

    @classmethod
    def from_wire(cls, value: Any) -> ContextBudgets:
        keys = {
            "hard_tokens",
            "soft_tokens",
            "max_blocks",
            "max_evidence_blocks",
            "max_raw_evidence_tokens",
            "max_history_tokens",
            "max_conflict_tokens",
            "max_serialized_bytes",
            "max_selection_evaluations",
        }
        obj = _mapping(value, "ContextPack budgets", keys)
        return cls(**{key: _uint32(obj[key], f"context_budgets.{key}") for key in keys})


@dataclass(frozen=True, slots=True)
class ModelProfile:
    id: str
    family: str
    tokenizer_id: str
    renderer: RendererKind
    max_context_tokens: int
    reserved_output_tokens: int
    preferred_structured_format: StructuredFormat
    supports_tool_results: bool
    supports_native_citations: bool
    supports_prompt_caching: bool
    position_profile: PositionProfile
    instruction_hierarchy: InstructionHierarchy
    max_schema_complexity: int
    external_processing: bool

    def to_wire(self) -> JsonObject:
        return {
            "id": self.id,
            "family": self.family,
            "tokenizer_id": self.tokenizer_id,
            "renderer": self.renderer.value,
            "max_context_tokens": self.max_context_tokens,
            "reserved_output_tokens": self.reserved_output_tokens,
            "preferred_structured_format": self.preferred_structured_format.value,
            "supports_tool_results": self.supports_tool_results,
            "supports_native_citations": self.supports_native_citations,
            "supports_prompt_caching": self.supports_prompt_caching,
            "position_profile": self.position_profile.value,
            "instruction_hierarchy": self.instruction_hierarchy.value,
            "max_schema_complexity": self.max_schema_complexity,
            "external_processing": self.external_processing,
        }


@dataclass(frozen=True, slots=True)
class SuppliedVector:
    space: str
    values: tuple[float, ...]

    def to_wire(self) -> JsonObject:
        return {"space": self.space, "values": list(self.values)}


@dataclass(frozen=True, slots=True)
class CompileContextPlan:
    pack_id: str
    query: str
    mode: RecallMode
    intent: RecallIntentValue
    purpose: PackPurpose
    at_commit: int | None
    now_micros: int
    required_facets: tuple[PackFacetRequirement, ...]
    recall_limits: RecallLimits
    context_budgets: ContextBudgets
    model_profile: ModelProfile
    explicit_memory_request: bool
    require_primary_evidence: bool
    include_evidence_quotes: bool
    permit_derived_only: bool
    max_projection_lag_commits: int
    allow_stale: bool
    query_vector: SuppliedVector | None
    continuation: str | None

    def to_wire(self) -> JsonObject:
        intent: Any = (
            self.intent.value if isinstance(self.intent, RecallIntent) else self.intent.to_wire()
        )
        return {
            "pack_id": self.pack_id,
            "query": self.query,
            "mode": self.mode.value,
            "intent": intent,
            "purpose": self.purpose.value,
            "at_commit": self.at_commit,
            "now_micros": self.now_micros,
            "required_facets": [item.to_wire() for item in self.required_facets],
            "recall_limits": self.recall_limits.to_wire(),
            "context_budgets": self.context_budgets.to_wire(),
            "model_profile": self.model_profile.to_wire(),
            "explicit_memory_request": self.explicit_memory_request,
            "require_primary_evidence": self.require_primary_evidence,
            "include_evidence_quotes": self.include_evidence_quotes,
            "permit_derived_only": self.permit_derived_only,
            "max_projection_lag_commits": self.max_projection_lag_commits,
            "allow_stale": self.allow_stale,
            "query_vector": None if self.query_vector is None else self.query_vector.to_wire(),
            "continuation": self.continuation,
        }


@dataclass(frozen=True, slots=True)
class CompileContextRequest:
    context: AuthenticatedRequestContext
    plan: CompileContextPlan

    def to_wire(self) -> JsonObject:
        return {"context": self.context.to_wire(), "plan": self.plan.to_wire()}


@dataclass(frozen=True, slots=True)
class RecallWatermarks:
    journal: int
    semantic: int
    lexical: int
    vector: Mapping[str, int]
    graph: int
    hierarchy: Mapping[str, int]

    @classmethod
    def from_wire(cls, value: Any) -> RecallWatermarks:
        obj = _mapping(
            value,
            "recall watermarks",
            {"journal", "semantic", "lexical", "vector", "graph", "hierarchy"},
        )
        return cls(
            journal=_uint(obj["journal"], "watermarks.journal"),
            semantic=_uint(obj["semantic"], "watermarks.semantic"),
            lexical=_uint(obj["lexical"], "watermarks.lexical"),
            vector=_uint_mapping(obj["vector"], "watermarks.vector"),
            graph=_uint(obj["graph"], "watermarks.graph"),
            hierarchy=_uint_mapping(obj["hierarchy"], "watermarks.hierarchy"),
        )


@dataclass(frozen=True, slots=True)
class ProviderSnapshot:
    database_id: str
    commit_seq: int
    watermarks: RecallWatermarks

    @classmethod
    def from_wire(cls, value: Any) -> ProviderSnapshot:
        obj = _mapping(value, "provider snapshot", {"database_id", "commit_seq", "watermarks"})
        return cls(
            database_id=_string(obj["database_id"], "snapshot.database_id"),
            commit_seq=_uint(obj["commit_seq"], "snapshot.commit_seq"),
            watermarks=RecallWatermarks.from_wire(obj["watermarks"]),
        )


@dataclass(frozen=True, slots=True)
class TimeRange:
    start: int
    end: int | None

    @classmethod
    def from_wire(cls, value: Any) -> TimeRange:
        obj = _mapping(value, "time range", {"start", "end"})
        return cls(
            _int64(obj["start"], "time_range.start"), _optional_int64(obj["end"], "time_range.end")
        )


@dataclass(frozen=True, slots=True)
class TemporalConstraint:
    kind: str
    range: TimeRange | None = None
    commit_seq: int | None = None
    valid_during: TimeRange | None = None
    known_at: int | None = None

    @classmethod
    def from_wire(cls, value: Any) -> TemporalConstraint:
        if not isinstance(value, Mapping):
            raise ProtocolError("invalid temporal constraint")
        kind = _string(value.get("kind"), "temporal constraint kind")
        keys = {
            "current": {"kind"},
            "valid_during": {"kind", "range"},
            "known_at": {"kind", "commit_seq"},
            "bitemporal": {"kind", "valid_during", "known_at"},
        }.get(kind)
        if keys is None or set(value) != keys:
            raise ProtocolError("invalid temporal constraint")
        return cls(
            kind=kind,
            range=TimeRange.from_wire(value["range"]) if kind == "valid_during" else None,
            commit_seq=_uint(value["commit_seq"], "temporal commit")
            if kind == "known_at"
            else None,
            valid_during=TimeRange.from_wire(value["valid_during"])
            if kind == "bitemporal"
            else None,
            known_at=_uint(value["known_at"], "temporal known_at")
            if kind == "bitemporal"
            else None,
        )


@dataclass(frozen=True, slots=True)
class BlockRepresentation:
    level: CompressionLevel
    summary: str
    fields: Mapping[str, str]
    omitted_facets: tuple[str, ...]

    @classmethod
    def from_wire(cls, value: Any) -> BlockRepresentation:
        obj = _mapping(
            value, "block representation", {"level", "summary", "fields", "omitted_facets"}
        )
        return cls(
            level=_enum(CompressionLevel, obj["level"], "compression level"),
            summary=_string(obj["summary"], "representation summary"),
            fields=_string_mapping(obj["fields"], "representation fields"),
            omitted_facets=_string_tuple(obj["omitted_facets"], "omitted facets"),
        )


@dataclass(frozen=True, slots=True)
class ExactFragment:
    label: str
    value: str

    @classmethod
    def from_wire(cls, value: Any) -> ExactFragment:
        obj = _mapping(value, "exact fragment", {"label", "value"})
        return cls(_string(obj["label"], "fragment label"), _string(obj["value"], "fragment value"))


@dataclass(frozen=True, slots=True)
class MemoryRef:
    kind: str
    id: str

    @classmethod
    def from_wire(cls, value: Any) -> MemoryRef:
        obj = _mapping(value, "memory ref", {"kind", "id"})
        kind = _string(obj["kind"], "memory ref kind")
        if kind not in {
            "observation",
            "episode_view",
            "artifact",
            "evidence",
            "node",
            "claim",
            "edge",
            "conflict_set",
        }:
            raise ProtocolError("invalid memory ref kind")
        return cls(kind, _string(obj["id"], "memory ref id"))


@dataclass(frozen=True, slots=True)
class Perspective:
    knower: str
    experiencer: str | None
    narrator: str
    role: StringOrOther

    @classmethod
    def from_wire(cls, value: Any) -> Perspective:
        obj = _mapping(value, "perspective", {"knower", "experiencer", "narrator", "role"})
        experiencer = obj["experiencer"]
        return cls(
            _string(obj["knower"], "perspective knower"),
            None if experiencer is None else _string(experiencer, "perspective experiencer"),
            _string(obj["narrator"], "perspective narrator"),
            _string_or_other(
                obj["role"],
                "epistemic role",
                {
                    "experiencer",
                    "witness",
                    "asserter",
                    "interpreter",
                    "verifier",
                    "external_reporter",
                    "fictional_narrator",
                },
            ),
        )


@dataclass(frozen=True, slots=True)
class ConflictState:
    state: str
    set_id: str | None

    @classmethod
    def from_wire(cls, value: Any) -> ConflictState:
        if not isinstance(value, Mapping):
            raise ProtocolError("invalid conflict state")
        state = _string(value.get("state"), "conflict state")
        keys = {"state"} if state in {"none", "disputed"} else {"state", "set_id"}
        if state not in {"none", "disputed", "in_conflict", "resolved"} or set(value) != keys:
            raise ProtocolError("invalid conflict state")
        return cls(state, _string(value["set_id"], "conflict set") if "set_id" in value else None)


@dataclass(frozen=True, slots=True)
class EpistemicState:
    basis: str
    acceptance: str
    conflict: ConflictState
    lifecycle: str

    @classmethod
    def from_wire(cls, value: Any) -> EpistemicState:
        obj = _mapping(value, "epistemic state", {"basis", "acceptance", "conflict", "lifecycle"})
        basis = _choice(
            obj["basis"],
            "epistemic basis",
            {
                "observation",
                "actor_assertion",
                "model_inference",
                "deterministic_derivation",
                "human_adjudication",
                "hypothesis",
            },
        )
        acceptance = _choice(
            obj["acceptance"],
            "acceptance",
            {"proposed", "validated", "accepted", "consolidated", "rejected"},
        )
        lifecycle = _choice(
            obj["lifecycle"],
            "lifecycle",
            {"active", "historical", "superseded", "retracted", "suppressed", "deleted"},
        )
        return cls(basis, acceptance, ConflictState.from_wire(obj["conflict"]), lifecycle)


@dataclass(frozen=True, slots=True)
class SupportState:
    state: str
    reason: str | None

    @classmethod
    def from_wire(cls, value: Any) -> SupportState:
        if not isinstance(value, Mapping):
            raise ProtocolError("invalid support state")
        state = _string(value.get("state"), "support state")
        expected = {"state"} if state == "supported" else {"state", "reason"}
        if state not in {"supported", "unsupported"} or set(value) != expected:
            raise ProtocolError("invalid support state")
        return cls(state, _string(value["reason"], "support reason") if "reason" in value else None)


@dataclass(frozen=True, slots=True)
class ConflictResolution:
    state: str
    winner: str | None
    rationale: str | None

    @classmethod
    def from_wire(cls, value: Any) -> ConflictResolution:
        if not isinstance(value, Mapping):
            raise ProtocolError("invalid conflict resolution")
        state = _string(value.get("state"), "conflict resolution")
        expected = {"state"} if state == "unresolved" else {"state", "winner", "rationale"}
        if state not in {"unresolved", "resolved"} or set(value) != expected:
            raise ProtocolError("invalid conflict resolution")
        return cls(
            state,
            _string(value["winner"], "conflict winner") if "winner" in value else None,
            _string(value["rationale"], "conflict rationale") if "rationale" in value else None,
        )


@dataclass(frozen=True, slots=True)
class ConflictDescriptor:
    set_id: str
    alternatives: tuple[str, ...]
    resolution: ConflictResolution
    blocking: bool

    @classmethod
    def from_wire(cls, value: Any) -> ConflictDescriptor:
        obj = _mapping(
            value, "conflict descriptor", {"set_id", "alternatives", "resolution", "blocking"}
        )
        return cls(
            _string(obj["set_id"], "conflict set"),
            _string_tuple(obj["alternatives"], "conflict alternatives"),
            ConflictResolution.from_wire(obj["resolution"]),
            _boolean(obj["blocking"], "conflict blocking"),
        )


@dataclass(frozen=True, slots=True)
class UnknownDescriptor:
    question: str
    reason: str
    blocking: bool

    @classmethod
    def from_wire(cls, value: Any) -> UnknownDescriptor:
        obj = _mapping(value, "unknown descriptor", {"question", "reason", "blocking"})
        return cls(
            _string(obj["question"], "unknown question"),
            _string(obj["reason"], "unknown reason"),
            _boolean(obj["blocking"], "unknown blocking"),
        )


@dataclass(frozen=True, slots=True)
class ContextBlock:
    id: str
    kind: PackBlockKind
    representation: BlockRepresentation
    exact_fragments: tuple[ExactFragment, ...]
    memory_refs: tuple[MemoryRef, ...]
    claim_ids: tuple[str, ...]
    evidence_handles: tuple[str, ...]
    facets: tuple[str, ...]
    scopes: tuple[str, ...]
    valid_time: TimeRange | None
    known_at_commit: int
    perspective: Perspective | None
    epistemic: EpistemicState
    confidence_micros: int
    trust: ContentTrust
    instruction_capability: InstructionCapability
    source_class: StringOrOther
    taints: tuple[StringOrOther, ...]
    interpretation: InterpretationRule
    support: SupportState
    conflict: ConflictDescriptor | None
    unknown: UnknownDescriptor | None

    @classmethod
    def from_wire(cls, value: Any) -> ContextBlock:
        keys = {
            "id",
            "kind",
            "representation",
            "exact_fragments",
            "memory_refs",
            "claim_ids",
            "evidence_handles",
            "facets",
            "scopes",
            "valid_time",
            "known_at_commit",
            "perspective",
            "epistemic",
            "confidence_micros",
            "trust",
            "instruction_capability",
            "source_class",
            "taints",
            "interpretation",
            "support",
            "conflict",
            "unknown",
        }
        obj = _mapping(value, "context block", keys)
        capability = _enum(
            InstructionCapability, obj["instruction_capability"], "instruction capability"
        )
        if capability is not InstructionCapability.NONE:
            raise ProtocolError("recalled ContextPack data gained instruction capability")
        if obj["kind"] == "raw_observation" and (
            obj["claim_ids"] != []
            or not obj["evidence_handles"]
            or obj["interpretation"] != "historical_data"
            or obj["support"] != {"state": "supported"}
        ):
            raise ProtocolError(
                "raw observation must retain evidence without asserting current claims"
            )
        return cls(
            id=_string(obj["id"], "block id"),
            kind=_enum(PackBlockKind, obj["kind"], "block kind"),
            representation=BlockRepresentation.from_wire(obj["representation"]),
            exact_fragments=_parsed_tuple(
                obj["exact_fragments"], "exact fragments", ExactFragment.from_wire
            ),
            memory_refs=_parsed_tuple(obj["memory_refs"], "memory refs", MemoryRef.from_wire),
            claim_ids=_string_tuple(obj["claim_ids"], "claim ids"),
            evidence_handles=_string_tuple(obj["evidence_handles"], "evidence handles"),
            facets=_string_tuple(obj["facets"], "facets"),
            scopes=_string_tuple(obj["scopes"], "scopes"),
            valid_time=None
            if obj["valid_time"] is None
            else TimeRange.from_wire(obj["valid_time"]),
            known_at_commit=_uint(obj["known_at_commit"], "known_at_commit"),
            perspective=None
            if obj["perspective"] is None
            else Perspective.from_wire(obj["perspective"]),
            epistemic=EpistemicState.from_wire(obj["epistemic"]),
            confidence_micros=_uint32(obj["confidence_micros"], "confidence_micros"),
            trust=_enum(ContentTrust, obj["trust"], "content trust"),
            instruction_capability=capability,
            source_class=_string_or_other(
                obj["source_class"],
                "source class",
                {
                    "user_statement",
                    "shared_conversation",
                    "repository",
                    "tool_output",
                    "external_document",
                    "sensor",
                    "deterministic_derivation",
                    "model_generated",
                    "imported",
                },
            ),
            taints=_parsed_tuple(
                obj["taints"],
                "taints",
                lambda item: _string_or_other(
                    item,
                    "content taint",
                    {
                        "untrusted_instructions",
                        "external_content",
                        "user_controlled",
                        "generated",
                        "secret_like",
                        "personally_sensitive",
                    },
                ),
            ),
            interpretation=_enum(InterpretationRule, obj["interpretation"], "interpretation"),
            support=SupportState.from_wire(obj["support"]),
            conflict=None
            if obj["conflict"] is None
            else ConflictDescriptor.from_wire(obj["conflict"]),
            unknown=None if obj["unknown"] is None else UnknownDescriptor.from_wire(obj["unknown"]),
        )


@dataclass(frozen=True, slots=True)
class PackSections:
    situation: tuple[ContextBlock, ...]
    self_context: tuple[ContextBlock, ...]
    participants: tuple[ContextBlock, ...]
    shared_history: tuple[ContextBlock, ...]
    episodes: tuple[ContextBlock, ...]
    facts: tuple[ContextBlock, ...]
    relationships: tuple[ContextBlock, ...]
    preferences: tuple[ContextBlock, ...]
    boundaries: tuple[ContextBlock, ...]
    goals: tuple[ContextBlock, ...]
    decisions: tuple[ContextBlock, ...]
    timeline: tuple[ContextBlock, ...]
    procedures: tuple[ContextBlock, ...]
    constraints: tuple[ContextBlock, ...]
    open_loops: tuple[ContextBlock, ...]
    conflicts: tuple[ContextBlock, ...]
    unknowns: tuple[ContextBlock, ...]
    raw_observations: tuple[ContextBlock, ...] = ()

    @classmethod
    def from_wire(cls, value: Any) -> PackSections:
        keys = {
            "situation",
            "self_context",
            "participants",
            "shared_history",
            "episodes",
            "facts",
            "relationships",
            "preferences",
            "boundaries",
            "goals",
            "decisions",
            "timeline",
            "procedures",
            "constraints",
            "open_loops",
            "conflicts",
            "unknowns",
        }
        optional = (
            {"raw_observations"}
            if isinstance(value, Mapping) and "raw_observations" in value
            else set()
        )
        obj = _mapping(value, "ContextPack sections", keys | optional)
        return cls(
            **{
                key: _parsed_tuple(obj[key], f"sections.{key}", ContextBlock.from_wire)
                for key in keys
            },
            raw_observations=_parsed_tuple(
                obj.get("raw_observations", []), "sections.raw_observations", ContextBlock.from_wire
            ),
        )


@dataclass(frozen=True, slots=True)
class EvidenceSelector:
    kind: str
    start: int | None = None
    end: int | None = None
    pointer: str | None = None

    @classmethod
    def from_wire(cls, value: Any) -> EvidenceSelector:
        if not isinstance(value, Mapping):
            raise ProtocolError("invalid evidence selector")
        kind = _string(value.get("kind"), "evidence selector kind")
        if kind in {"text_bytes", "lines", "time_micros"}:
            if set(value) != {"kind", "start", "end"}:
                raise ProtocolError("invalid evidence selector")
            return cls(
                kind, _uint(value["start"], "selector start"), _uint(value["end"], "selector end")
            )
        if kind == "json_pointer":
            if set(value) != {"kind", "pointer"}:
                raise ProtocolError("invalid evidence selector")
            return cls(kind, pointer=_string(value["pointer"], "selector pointer"))
        if kind == "whole" and set(value) == {"kind"}:
            return cls(kind)
        raise ProtocolError("invalid evidence selector")


@dataclass(frozen=True, slots=True)
class OriginalSourceSpan:
    """Exact original version and UTF-8 byte range, independent of claim promotion."""

    event_id: str
    payload_digest: str
    start: int
    end: int
    span_digest: str

    @classmethod
    def from_wire(cls, value: Any) -> OriginalSourceSpan:
        obj = _mapping(
            value, "original span", {"event_id", "payload_digest", "start", "end", "span_digest"}
        )
        span = cls(
            _string(obj["event_id"], "event id"),
            _string(obj["payload_digest"], "payload digest"),
            _uint(obj["start"], "span start"),
            _uint(obj["end"], "span end"),
            _string(obj["span_digest"], "span digest"),
        )
        if span.end <= span.start or any(
            len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
            for digest in (span.payload_digest, span.span_digest)
        ):
            raise ProtocolError("invalid exact original span")
        return span


@dataclass(frozen=True, slots=True)
class PackEvidence:
    id: str
    source: str
    selector: EvidenceSelector
    excerpt: str | None
    claim_ids: tuple[str, ...]
    provenance_family: str
    primary: bool
    trust_micros: int
    source_class: StringOrOther
    taints: tuple[StringOrOther, ...]
    lineage: tuple[str, ...]
    original_span: OriginalSourceSpan | None = None

    @classmethod
    def from_wire(cls, value: Any) -> PackEvidence:
        obj = _mapping(
            value,
            "pack evidence",
            {
                "id",
                "source",
                "selector",
                "excerpt",
                "claim_ids",
                "provenance_family",
                "primary",
                "trust_micros",
                "source_class",
                "taints",
                "lineage",
            }
            | (
                {"original_span"}
                if isinstance(value, Mapping) and "original_span" in value
                else set()
            ),
        )
        excerpt = obj["excerpt"]
        selector = EvidenceSelector.from_wire(obj["selector"])
        span = (
            OriginalSourceSpan.from_wire(obj["original_span"]) if "original_span" in obj else None
        )
        if span is not None:
            if (
                not isinstance(excerpt, str)
                or len(excerpt.encode("utf-8")) != span.end - span.start
                or blake3(excerpt.encode("utf-8")).hexdigest() != span.span_digest
            ):
                raise ProtocolError("original span differs from exact evidence bytes")
            if selector.kind != "text_bytes" or (selector.start, selector.end) != (
                span.start,
                span.end,
            ):
                raise ProtocolError("original span differs from evidence selector")
        return cls(
            _string(obj["id"], "evidence id"),
            _string(obj["source"], "evidence source"),
            selector,
            None if excerpt is None else _string(excerpt, "evidence excerpt"),
            _string_tuple(obj["claim_ids"], "evidence claim ids"),
            _string(obj["provenance_family"], "provenance family"),
            _boolean(obj["primary"], "primary"),
            _uint32(obj["trust_micros"], "trust_micros"),
            _string_or_other(
                obj["source_class"],
                "source class",
                {
                    "user_statement",
                    "shared_conversation",
                    "repository",
                    "tool_output",
                    "external_document",
                    "sensor",
                    "deterministic_derivation",
                    "model_generated",
                    "imported",
                },
            ),
            _parsed_tuple(
                obj["taints"],
                "evidence taints",
                lambda item: _string_or_other(
                    item,
                    "content taint",
                    {
                        "untrusted_instructions",
                        "external_content",
                        "user_controlled",
                        "generated",
                        "secret_like",
                        "personally_sensitive",
                    },
                ),
            ),
            _string_tuple(obj["lineage"], "evidence lineage"),
            span,
        )


@dataclass(frozen=True, slots=True)
class UseDirective:
    block_id: str
    action: UseAction
    reason_code: DirectiveReason

    @classmethod
    def from_wire(cls, value: Any) -> UseDirective:
        obj = _mapping(value, "use directive", {"block_id", "action", "reason_code"})
        return cls(
            _string(obj["block_id"], "directive block"),
            _enum(UseAction, obj["action"], "use action"),
            _enum(DirectiveReason, obj["reason_code"], "directive reason"),
        )


@dataclass(frozen=True, slots=True)
class ScopeManifest:
    workspace: str
    subject: str
    scopes: tuple[str, ...]
    purpose: PackPurpose
    temporal_view: TemporalConstraint
    filter_digest: str

    @classmethod
    def from_wire(cls, value: Any) -> ScopeManifest:
        obj = _mapping(
            value,
            "scope manifest",
            {"workspace", "subject", "scopes", "purpose", "temporal_view", "filter_digest"},
        )
        return cls(
            _string(obj["workspace"], "scope workspace"),
            _string(obj["subject"], "scope subject"),
            _string_tuple(obj["scopes"], "scope list"),
            _enum(PackPurpose, obj["purpose"], "pack purpose"),
            TemporalConstraint.from_wire(obj["temporal_view"]),
            _string(obj["filter_digest"], "filter digest"),
        )


@dataclass(frozen=True, slots=True)
class GraphManifest:
    memory_refs: tuple[MemoryRef, ...]
    claim_ids: tuple[str, ...]
    conflict_sets: tuple[str, ...]

    @classmethod
    def from_wire(cls, value: Any) -> GraphManifest:
        obj = _mapping(value, "graph manifest", {"memory_refs", "claim_ids", "conflict_sets"})
        return cls(
            _parsed_tuple(obj["memory_refs"], "graph memory refs", MemoryRef.from_wire),
            _string_tuple(obj["claim_ids"], "graph claims"),
            _string_tuple(obj["conflict_sets"], "graph conflicts"),
        )


@dataclass(frozen=True, slots=True)
class BlockProvenance:
    block_id: str
    memory_refs: tuple[MemoryRef, ...]
    evidence_handles: tuple[str, ...]
    source_classes: tuple[StringOrOther, ...]

    @classmethod
    def from_wire(cls, value: Any) -> BlockProvenance:
        obj = _mapping(
            value,
            "block provenance",
            {"block_id", "memory_refs", "evidence_handles", "source_classes"},
        )
        return cls(
            _string(obj["block_id"], "provenance block"),
            _parsed_tuple(obj["memory_refs"], "provenance refs", MemoryRef.from_wire),
            _string_tuple(obj["evidence_handles"], "provenance evidence"),
            _parsed_tuple(
                obj["source_classes"],
                "source classes",
                lambda item: _string_or_other(
                    item,
                    "source class",
                    {
                        "user_statement",
                        "shared_conversation",
                        "repository",
                        "tool_output",
                        "external_document",
                        "sensor",
                        "deterministic_derivation",
                        "model_generated",
                        "imported",
                    },
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class ProvenanceManifest:
    compiler_version: str
    policy_filter_digest: str
    blocks: tuple[BlockProvenance, ...]
    evidence_sources: Mapping[str, str]

    @classmethod
    def from_wire(cls, value: Any) -> ProvenanceManifest:
        obj = _mapping(
            value,
            "provenance",
            {"compiler_version", "policy_filter_digest", "blocks", "evidence_sources"},
        )
        return cls(
            _string(obj["compiler_version"], "compiler version"),
            _string(obj["policy_filter_digest"], "policy filter digest"),
            _parsed_tuple(obj["blocks"], "provenance blocks", BlockProvenance.from_wire),
            _string_mapping(obj["evidence_sources"], "evidence sources"),
        )


@dataclass(frozen=True, slots=True)
class FreshnessManifest:
    snapshot: ProviderSnapshot
    warnings: tuple[str, ...]

    @classmethod
    def from_wire(cls, value: Any) -> FreshnessManifest:
        obj = _mapping(value, "freshness", {"snapshot", "warnings"})
        return cls(
            ProviderSnapshot.from_wire(obj["snapshot"]),
            _string_tuple(obj["warnings"], "freshness warnings"),
        )


@dataclass(frozen=True, slots=True)
class ContextBudgetUsage:
    rendered_tokens: int
    control_tokens: int
    data_tokens: int
    blocks: int
    evidence_blocks: int
    raw_evidence_tokens: int
    history_tokens: int
    conflict_tokens: int
    serialized_bytes: int
    selection_evaluations: int

    @classmethod
    def from_wire(cls, value: Any) -> ContextBudgetUsage:
        keys = {
            "rendered_tokens",
            "control_tokens",
            "data_tokens",
            "blocks",
            "evidence_blocks",
            "raw_evidence_tokens",
            "history_tokens",
            "conflict_tokens",
            "serialized_bytes",
            "selection_evaluations",
        }
        obj = _mapping(value, "ContextPack usage", keys)
        return cls(**{key: _uint32(obj[key], f"pack_usage.{key}") for key in keys})


@dataclass(frozen=True, slots=True)
class Omission:
    block_id: str
    reason: OmissionReason

    @classmethod
    def from_wire(cls, value: Any) -> Omission:
        obj = _mapping(value, "omission", {"block_id", "reason"})
        return cls(
            _string(obj["block_id"], "omitted block"),
            _enum(OmissionReason, obj["reason"], "omission reason"),
        )


@dataclass(frozen=True, slots=True)
class PackSufficiencyReport:
    sufficient: bool
    covered_facets: tuple[str, ...]
    missing_facets: tuple[str, ...]
    unresolved_conflicts: tuple[str, ...]
    blocking_unknowns: tuple[str, ...]
    unsupported_blocks: tuple[str, ...]

    @classmethod
    def from_wire(cls, value: Any) -> PackSufficiencyReport:
        obj = _mapping(
            value,
            "sufficiency",
            {
                "sufficient",
                "covered_facets",
                "missing_facets",
                "unresolved_conflicts",
                "blocking_unknowns",
                "unsupported_blocks",
            },
        )
        return cls(
            _boolean(obj["sufficient"], "sufficient"),
            _string_tuple(obj["covered_facets"], "covered facets"),
            _string_tuple(obj["missing_facets"], "missing facets"),
            _string_tuple(obj["unresolved_conflicts"], "unresolved conflicts"),
            _string_tuple(obj["blocking_unknowns"], "blocking unknowns"),
            _string_tuple(obj["unsupported_blocks"], "unsupported blocks"),
        )


@dataclass(frozen=True, slots=True)
class CompilationReport:
    compiler_version: str
    schema_version: str
    model_profile: str
    tokenizer: str
    renderer: RendererKind
    budget: ContextBudgets
    usage: ContextBudgetUsage
    soft_budget_exceeded: bool
    selected_blocks: tuple[str, ...]
    omissions: tuple[Omission, ...]
    sufficiency: PackSufficiencyReport

    @classmethod
    def from_wire(cls, value: Any) -> CompilationReport:
        obj = _mapping(
            value,
            "compilation",
            {
                "compiler_version",
                "schema_version",
                "model_profile",
                "tokenizer",
                "renderer",
                "budget",
                "usage",
                "soft_budget_exceeded",
                "selected_blocks",
                "omissions",
                "sufficiency",
            },
        )
        return cls(
            _string(obj["compiler_version"], "compiler version"),
            _string(obj["schema_version"], "schema version"),
            _string(obj["model_profile"], "model profile"),
            _string(obj["tokenizer"], "tokenizer"),
            _enum(RendererKind, obj["renderer"], "renderer"),
            ContextBudgets.from_wire(obj["budget"]),
            ContextBudgetUsage.from_wire(obj["usage"]),
            _boolean(obj["soft_budget_exceeded"], "soft budget"),
            _string_tuple(obj["selected_blocks"], "selected blocks"),
            _parsed_tuple(obj["omissions"], "omissions", Omission.from_wire),
            PackSufficiencyReport.from_wire(obj["sufficiency"]),
        )


@dataclass(frozen=True, slots=True)
class NoMemoryResult:
    reason: NoMemoryReason
    missing_facets: tuple[str, ...]

    @classmethod
    def from_wire(cls, value: Any) -> NoMemoryResult:
        obj = _mapping(value, "no memory", {"reason", "missing_facets"})
        return cls(
            _enum(NoMemoryReason, obj["reason"], "no-memory reason"),
            _string_tuple(obj["missing_facets"], "missing facets"),
        )


@dataclass(frozen=True, slots=True)
class ContextContinuationToken:
    opaque: str

    @classmethod
    def from_wire(cls, value: Any) -> ContextContinuationToken:
        obj = _mapping(value, "pack continuation", {"opaque"})
        return cls(_string(obj["opaque"], "pack continuation"))


@dataclass(frozen=True, slots=True)
class ContextPack:
    schema_version: str
    id: str
    status: PackStatus
    snapshot: ProviderSnapshot
    purpose: PackPurpose
    scope_manifest: ScopeManifest
    sections: PackSections
    evidence: tuple[PackEvidence, ...]
    use_directives: tuple[UseDirective, ...]
    graph_manifest: GraphManifest
    freshness: FreshnessManifest
    provenance: ProvenanceManifest
    continuation: ContextContinuationToken | None
    compilation: CompilationReport
    no_memory: NoMemoryResult | None

    @classmethod
    def from_wire(cls, value: Any) -> ContextPack:
        obj = _mapping(
            value,
            "ContextPack",
            {
                "schema_version",
                "id",
                "status",
                "snapshot",
                "purpose",
                "scope_manifest",
                "sections",
                "evidence",
                "use_directives",
                "graph_manifest",
                "freshness",
                "provenance",
                "continuation",
                "compilation",
                "no_memory",
            },
        )
        continuation = (
            None
            if obj["continuation"] is None
            else ContextContinuationToken.from_wire(obj["continuation"])
        )
        return cls(
            _string(obj["schema_version"], "pack schema"),
            _string(obj["id"], "pack id"),
            _enum(PackStatus, obj["status"], "pack status"),
            ProviderSnapshot.from_wire(obj["snapshot"]),
            _enum(PackPurpose, obj["purpose"], "pack purpose"),
            ScopeManifest.from_wire(obj["scope_manifest"]),
            PackSections.from_wire(obj["sections"]),
            _parsed_tuple(obj["evidence"], "pack evidence", PackEvidence.from_wire),
            _parsed_tuple(obj["use_directives"], "use directives", UseDirective.from_wire),
            GraphManifest.from_wire(obj["graph_manifest"]),
            FreshnessManifest.from_wire(obj["freshness"]),
            ProvenanceManifest.from_wire(obj["provenance"]),
            continuation,
            CompilationReport.from_wire(obj["compilation"]),
            None if obj["no_memory"] is None else NoMemoryResult.from_wire(obj["no_memory"]),
        )


@dataclass(frozen=True, slots=True)
class RenderedContextPayload:
    """Trusted compiler control and untrusted recalled data remain separate."""

    profile_id: str
    renderer: RendererKind
    trusted_control: str
    untrusted_data: str
    control_tokens: int
    data_tokens: int
    total_tokens: int

    @classmethod
    def from_wire(cls, value: Any) -> RenderedContextPayload:
        obj = _mapping(
            value,
            "rendered ContextPack",
            {
                "profile_id",
                "renderer",
                "trusted_control",
                "untrusted_data",
                "control_tokens",
                "data_tokens",
                "total_tokens",
            },
        )
        return cls(
            _string(obj["profile_id"], "render profile"),
            _enum(RendererKind, obj["renderer"], "renderer"),
            _string(obj["trusted_control"], "trusted control"),
            _string(obj["untrusted_data"], "untrusted data"),
            _uint32(obj["control_tokens"], "control tokens"),
            _uint32(obj["data_tokens"], "data tokens"),
            _uint32(obj["total_tokens"], "total tokens"),
        )


@dataclass(frozen=True, slots=True)
class RecallBudgetUsage:
    nodes_examined: int
    graph_edges_examined: int
    max_hop_reached: int
    evidence_units: int
    context_tokens: int

    @classmethod
    def from_wire(cls, value: Any) -> RecallBudgetUsage:
        obj = _mapping(
            value,
            "recall usage",
            {
                "nodes_examined",
                "graph_edges_examined",
                "max_hop_reached",
                "evidence_units",
                "context_tokens",
            },
        )
        return cls(
            _uint32(obj["nodes_examined"], "nodes examined"),
            _uint32(obj["graph_edges_examined"], "edges examined"),
            _uint8(obj["max_hop_reached"], "max hop"),
            _uint32(obj["evidence_units"], "evidence units"),
            _uint32(obj["context_tokens"], "context tokens"),
        )


@dataclass(frozen=True, slots=True)
class ContextPackTrace:
    trace_id: str
    snapshot: ProviderSnapshot
    filter_digest: str
    recall_status: RecallStatus
    stop_reason: StopReason
    recall_usage: RecallBudgetUsage
    pack_status: PackStatus
    pack_usage: ContextBudgetUsage
    selected_blocks: int
    evidence_blocks: int
    max_projection_lag_commits: int
    stale: bool
    freshness_warnings: tuple[str, ...]

    @classmethod
    def from_wire(cls, value: Any) -> ContextPackTrace:
        obj = _mapping(
            value,
            "ContextPack trace",
            {
                "trace_id",
                "snapshot",
                "filter_digest",
                "recall_status",
                "stop_reason",
                "recall_usage",
                "pack_status",
                "pack_usage",
                "selected_blocks",
                "evidence_blocks",
                "max_projection_lag_commits",
                "stale",
                "freshness_warnings",
            },
        )
        return cls(
            _string(obj["trace_id"], "trace id"),
            ProviderSnapshot.from_wire(obj["snapshot"]),
            _string(obj["filter_digest"], "filter digest"),
            _enum(RecallStatus, obj["recall_status"], "recall status"),
            _enum(StopReason, obj["stop_reason"], "stop reason"),
            RecallBudgetUsage.from_wire(obj["recall_usage"]),
            _enum(PackStatus, obj["pack_status"], "pack status"),
            ContextBudgetUsage.from_wire(obj["pack_usage"]),
            _uint32(obj["selected_blocks"], "selected blocks"),
            _uint32(obj["evidence_blocks"], "evidence blocks"),
            _uint(obj["max_projection_lag_commits"], "projection lag"),
            _boolean(obj["stale"], "stale"),
            _string_tuple(obj["freshness_warnings"], "freshness warnings"),
        )


@dataclass(frozen=True, slots=True)
class CompileContextResponse:
    context_pack: ContextPack
    canonical_encoding: str
    canonical_bytes: bytes
    canonical_digest_algorithm: str
    canonical_digest: str
    rendered: RenderedContextPayload
    continuation: str | None
    trace: ContextPackTrace

    @classmethod
    def from_wire(cls, value: Any) -> CompileContextResponse:
        obj = _mapping(
            value,
            "compile-context response",
            {
                "context_pack",
                "canonical_encoding",
                "canonical_bytes",
                "canonical_digest_algorithm",
                "canonical_digest",
                "rendered",
                "continuation",
                "trace",
            },
        )
        continuation = obj["continuation"]
        if continuation is not None and not isinstance(continuation, str):
            raise ProtocolError("invalid ContextPack continuation")
        response = cls(
            ContextPack.from_wire(obj["context_pack"]),
            _string(obj["canonical_encoding"], "canonical encoding"),
            _octets(obj["canonical_bytes"], "canonical bytes"),
            _string(obj["canonical_digest_algorithm"], "canonical digest algorithm"),
            _digest(obj["canonical_digest"], "canonical digest"),
            RenderedContextPayload.from_wire(obj["rendered"]),
            continuation,
            ContextPackTrace.from_wire(obj["trace"]),
        )
        if response.context_pack.snapshot != response.trace.snapshot:
            raise ProtocolError("ContextPack trace snapshot differs from the canonical pack")
        if response.context_pack.status is not response.trace.pack_status:
            raise ProtocolError("ContextPack trace status differs from the canonical pack")
        if (
            response.context_pack.purpose is not response.context_pack.scope_manifest.purpose
            or response.context_pack.snapshot != response.context_pack.freshness.snapshot
            or response.context_pack.scope_manifest.filter_digest != response.trace.filter_digest
            or response.context_pack.provenance.policy_filter_digest != response.trace.filter_digest
            or response.context_pack.compilation.usage != response.trace.pack_usage
        ):
            raise ProtocolError("ContextPack response has inconsistent canonical bindings")
        if (
            response.rendered.control_tokens + response.rendered.data_tokens
            != response.rendered.total_tokens
        ):
            raise ProtocolError("rendered ContextPack channel tokens do not add to the total")
        if response.canonical_encoding != CONTEXT_PACK_CANONICAL_ENCODING:
            raise ProtocolError("unsupported ContextPack canonical encoding")
        if response.canonical_digest_algorithm != CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM:
            raise ProtocolError("unsupported ContextPack canonical digest algorithm")
        if (
            len(response.canonical_bytes)
            != response.context_pack.compilation.usage.serialized_bytes
        ):
            raise ProtocolError("canonical bytes differ from the ContextPack serialized size")
        return response

    def verify_canonical_digest(self) -> None:
        """Raises ``ProtocolError`` unless exact canonical bytes match the digest."""
        if self.canonical_encoding != CONTEXT_PACK_CANONICAL_ENCODING:
            raise ProtocolError("unsupported ContextPack canonical encoding")
        if self.canonical_digest_algorithm != CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM:
            raise ProtocolError("unsupported ContextPack canonical digest algorithm")
        computed = blake3(self.canonical_bytes).hexdigest()
        if not hmac.compare_digest(computed, self.canonical_digest):
            raise ProtocolError("ContextPack canonical digest mismatch")


_EnumT = TypeVar("_EnumT", bound=StrEnum)
_ParsedT = TypeVar("_ParsedT")


def _enum(kind: type[_EnumT], value: Any, name: str) -> _EnumT:
    raw = _string(value, name)
    try:
        return kind(raw)
    except ValueError as error:
        raise ProtocolError(f"invalid {name}") from error


def _choice(value: Any, name: str, choices: set[str]) -> str:
    raw = _string(value, name)
    if raw not in choices:
        raise ProtocolError(f"invalid {name}")
    return raw


def _uint32(value: Any, name: str) -> int:
    result = _uint(value, name)
    if result > (1 << 32) - 1:
        raise ProtocolError(f"invalid {name}")
    return result


def _octets(value: Any, name: str) -> bytes:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 255
        for item in value
    ):
        raise ProtocolError(f"invalid {name}")
    return bytes(value)


def _digest(value: Any, name: str) -> str:
    result = _string(value, name)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise ProtocolError(f"invalid {name}")
    return result


def _uint8(value: Any, name: str) -> int:
    result = _uint(value, name)
    if result > 255:
        raise ProtocolError(f"invalid {name}")
    return result


def _int64(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -(1 << 63) <= value < (1 << 63):
        raise ProtocolError(f"invalid {name}")
    return value


def _optional_int64(value: Any, name: str) -> int | None:
    return None if value is None else _int64(value, name)


def _parsed_tuple(value: Any, name: str, parser: Callable[[Any], _ParsedT]) -> tuple[_ParsedT, ...]:
    if not isinstance(value, list):
        raise ProtocolError(f"invalid {name}")
    return tuple(parser(item) for item in value)


def _string_mapping(value: Any, name: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise ProtocolError(f"invalid {name}")
    return dict(value)


def _uint_mapping(value: Any, name: str) -> Mapping[str, int]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ProtocolError(f"invalid {name}")
    return {key: _uint(item, f"{name}.{key}") for key, item in value.items()}


def _string_or_other(value: Any, name: str, units: set[str]) -> StringOrOther:
    if isinstance(value, str):
        if value not in units:
            raise ProtocolError(f"invalid {name}")
        return value
    obj = _mapping(value, name, {"other"})
    return OtherVariant(_string(obj["other"], f"{name}.other"))


__all__ = [
    "BlockProvenance",
    "BlockRepresentation",
    "CompilationReport",
    "CompileContextPlan",
    "CompileContextRequest",
    "CompileContextResponse",
    "CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM",
    "CONTEXT_PACK_CANONICAL_ENCODING",
    "CompressionLevel",
    "ConflictDescriptor",
    "ConflictResolution",
    "ConflictState",
    "ContextBlock",
    "ContextBudgets",
    "ContextBudgetUsage",
    "ContextContinuationToken",
    "ContextPack",
    "ContextPackTrace",
    "ContentTrust",
    "DirectiveReason",
    "EpistemicState",
    "EvidenceSelector",
    "ExactFragment",
    "FreshnessManifest",
    "GraphManifest",
    "InstructionCapability",
    "InstructionHierarchy",
    "InterpretationRule",
    "MemoryRef",
    "ModelProfile",
    "NoMemoryReason",
    "NoMemoryResult",
    "Omission",
    "OmissionReason",
    "OtherVariant",
    "OriginalSourceSpan",
    "PackBlockKind",
    "PackEvidence",
    "PackFacetRequirement",
    "PackPurpose",
    "PackSections",
    "PackStatus",
    "PackSufficiencyReport",
    "Perspective",
    "PositionProfile",
    "ProvenanceManifest",
    "ProviderSnapshot",
    "RecallBudgetUsage",
    "RecallIntent",
    "RecallLimits",
    "RecallMode",
    "RecallStatus",
    "RecallWatermarks",
    "RenderedContextPayload",
    "RendererKind",
    "ScopeManifest",
    "StopReason",
    "StructuredFormat",
    "SuppliedVector",
    "SupportState",
    "TemporalConstraint",
    "TimeRange",
    "UnknownDescriptor",
    "UseAction",
    "UseDirective",
]
