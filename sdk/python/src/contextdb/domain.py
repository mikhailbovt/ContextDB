"""Authenticated v1 HTTP domain, streaming, runtime, and admin DTOs."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, TypeAlias, TypeVar

from .errors import ProtocolError
from .models import (
    AccessPolicy,
    Consent,
    JsonObject,
    ObserveResponse,
    RequestContext,
    Sensitivity,
    Watermarks,
    _boolean,
    _mapping,
    _string,
    _string_tuple,
    _uint,
    _wire_strings,
)


class Capability(StrEnum):
    OBSERVE = "observe"
    STREAM_INGEST = "stream_ingest"
    RECALL = "recall"
    CORRECT = "correct"
    FORGET = "forget"
    HARD_DELETE = "hard_delete"
    READ_MEMORY = "read_memory"
    TRAVERSE = "traverse"
    READ_EVIDENCE = "read_evidence"
    READ_CONFLICT = "read_conflict"
    SUBSCRIBE = "subscribe"
    RUNTIME = "runtime"
    MAINTENANCE = "maintenance"
    ADMIN = "admin"
    RAW_EVIDENCE = "raw_evidence"
    MODEL_PROCESSING = "model_processing"


class RuntimeCapabilityState(StrEnum):
    AVAILABLE = "available"
    COMPILED_ONLY = "compiled_only"
    UNSUPPORTED = "unsupported"


# Open-map keys stay strings for additive compatibility. This tuple names the
# stable schema-v1 candidate-only contract without closing the map to extensions.
CANDIDATE_RUNTIME_CAPABILITY_IDS_V1 = (
    "candidate_hierarchy_dag",
    "policy_first_candidate_recall",
    "policy_first_candidate_traversal",
    "quarantined_memory_proposals",
)


class AuthenticationEvidence(Protocol):
    """Application evidence DTO; never a transport credential source."""

    def to_wire(self) -> JsonObject: ...


@dataclass(frozen=True, slots=True)
class AuthenticatedChannel:
    channel_id: str
    peer_identity: str
    binding_digest: str

    def to_wire(self) -> JsonObject:
        return {
            "kind": "authenticated_channel",
            "channel_id": self.channel_id,
            "peer_identity": self.peer_identity,
            "binding_digest": self.binding_digest,
        }


@dataclass(frozen=True, slots=True)
class RequestSignature:
    algorithm: str
    key_id: str
    signature: str
    signed_context_digest: str

    def to_wire(self) -> JsonObject:
        return {
            "kind": "request_signature",
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "signature": self.signature,
            "signed_context_digest": self.signed_context_digest,
        }


@dataclass(frozen=True, slots=True)
class AuthenticatedRequestContext:
    request: RequestContext
    actor_id: str
    agent_id: str
    session_id: str | None
    capability_grants: frozenset[Capability]
    authentication: AuthenticationEvidence

    def to_wire(self) -> JsonObject:
        return {
            "request": self.request.to_wire(),
            "actor_id": self.actor_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "capability_grants": sorted(value.value for value in self.capability_grants),
            "authentication": self.authentication.to_wire(),
        }


class Compression(StrEnum):
    IDENTITY = "identity"
    GZIP = "gzip"
    ZSTD = "zstd"


@dataclass(frozen=True, slots=True)
class SourceRevisionManifest:
    source_id: str
    revision_id: str
    snapshot_id: str
    expected_items: int
    ordered_items_digest: str
    compression: Compression
    attributes: Mapping[str, str]

    def to_wire(self) -> JsonObject:
        return {
            "source_id": self.source_id,
            "revision_id": self.revision_id,
            "snapshot_id": self.snapshot_id,
            "expected_items": self.expected_items,
            "ordered_items_digest": self.ordered_items_digest,
            "compression": self.compression.value,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class StreamObservation:
    idempotency_key: str
    observation_id: str
    metadata: Mapping[str, Any]
    content: Any
    access: AccessPolicy

    def to_wire(self) -> JsonObject:
        return {
            "idempotency_key": self.idempotency_key,
            "observation_id": self.observation_id,
            "metadata": dict(self.metadata),
            "content": self.content,
            "access": self.access.to_wire(),
        }


@dataclass(frozen=True, slots=True)
class SnapshotComplete:
    snapshot_id: str
    item_count: int
    ordered_items_digest: str

    def to_wire(self) -> JsonObject:
        return {
            "snapshot_id": self.snapshot_id,
            "item_count": self.item_count,
            "ordered_items_digest": self.ordered_items_digest,
        }


IngestFramePayload: TypeAlias = SourceRevisionManifest | StreamObservation | SnapshotComplete


class IngestFrameKind(StrEnum):
    MANIFEST = "manifest"
    OBSERVATION = "observation"
    SNAPSHOT_COMPLETE = "snapshot_complete"


@dataclass(frozen=True, slots=True)
class IngestFrameValue:
    kind: IngestFrameKind
    value: IngestFramePayload

    def to_wire(self) -> JsonObject:
        return {"kind": self.kind.value, "value": self.value.to_wire()}


@dataclass(frozen=True, slots=True)
class IngestFrame:
    context: AuthenticatedRequestContext
    stream_id: str
    position: int
    resume_cursor: str | None
    value: IngestFrameValue

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "stream_id": self.stream_id,
            "position": self.position,
            "resume_cursor": self.resume_cursor,
            "value": self.value.to_wire(),
        }


class IngestDisposition(StrEnum):
    ACCEPTED = "accepted"
    REPLAYED = "replayed"
    SNAPSHOT_COMMITTED = "snapshot_committed"


@dataclass(frozen=True, slots=True)
class IngestAck:
    stream_id: str
    position: int
    disposition: IngestDisposition
    frame_digest: str
    resume_cursor: str
    commit_seq: int | None
    partial_result_refs: tuple[str, ...]
    lease_expires_at_ms: int | None = None

    @classmethod
    def from_wire(cls, value: Any) -> IngestAck:
        required = {
            "stream_id",
            "position",
            "disposition",
            "frame_digest",
            "resume_cursor",
            "commit_seq",
            "partial_result_refs",
        }
        allowed = required | {"lease_expires_at_ms"}
        if (
            not isinstance(value, Mapping)
            or not required.issubset(value)
            or not set(value).issubset(allowed)
        ):
            raise ProtocolError("invalid ingest acknowledgement object")
        obj = value
        return cls(
            stream_id=_string(obj["stream_id"], "stream_id"),
            position=_uint(obj["position"], "position"),
            disposition=_enum(IngestDisposition, obj["disposition"], "disposition"),
            frame_digest=_string(obj["frame_digest"], "frame_digest"),
            resume_cursor=_string(obj["resume_cursor"], "resume_cursor"),
            commit_seq=_optional_uint(obj["commit_seq"], "commit_seq"),
            partial_result_refs=_string_tuple(obj["partial_result_refs"], "partial_result_refs"),
            lease_expires_at_ms=(
                _uint(obj["lease_expires_at_ms"], "lease_expires_at_ms")
                if "lease_expires_at_ms" in obj
                else None
            ),
        )


class MemoryEventKind(StrEnum):
    NODE_CHANGED = "node_changed"
    CLAIM_CHANGED = "claim_changed"
    OPEN_LOOP_TRIGGERED = "open_loop_triggered"
    INDEX_WATERMARK_ADVANCED = "index_watermark_advanced"
    CONFLICT_RESOLVED = "conflict_resolved"
    SOURCE_INVALIDATED = "source_invalidated"
    OPERATION_PROGRESS = "operation_progress"
    SECURITY_EVENT = "security_event"
    OBSERVATION_ACCEPTED = "observation_accepted"
    RECORD_CHANGED = "record_changed"


@dataclass(frozen=True, slots=True)
class SubscribeRequest:
    context: AuthenticatedRequestContext
    filters: frozenset[MemoryEventKind]
    resume_cursor: str | None
    max_events: int

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "filters": sorted(value.value for value in self.filters),
            "resume_cursor": self.resume_cursor,
            "max_events": self.max_events,
        }


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    event_id: str
    commit_seq: int
    ordinal: int
    kind: MemoryEventKind
    object_refs: tuple[str, ...]
    attributes: Mapping[str, str]

    @classmethod
    def from_wire(cls, value: Any) -> MemoryEvent:
        obj = _mapping(
            value,
            "memory event",
            {"event_id", "commit_seq", "ordinal", "kind", "object_refs", "attributes"},
        )
        return cls(
            event_id=_string(obj["event_id"], "event_id"),
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
            ordinal=_uint32(obj["ordinal"], "ordinal"),
            kind=_enum(MemoryEventKind, obj["kind"], "event kind"),
            object_refs=_string_tuple(obj["object_refs"], "object_refs"),
            attributes=_string_mapping(obj["attributes"], "event attributes"),
        )


@dataclass(frozen=True, slots=True)
class SubscriptionPage:
    events: tuple[MemoryEvent, ...]
    resume_cursor: str
    caught_up: bool

    @classmethod
    def from_wire(cls, value: Any) -> SubscriptionPage:
        obj = _mapping(value, "subscription page", {"events", "resume_cursor", "caught_up"})
        events = obj["events"]
        if not isinstance(events, list):
            raise ProtocolError("invalid subscription events")
        return cls(
            events=tuple(MemoryEvent.from_wire(item) for item in events),
            resume_cursor=_string(obj["resume_cursor"], "resume_cursor"),
            caught_up=_boolean(obj["caught_up"], "caught_up"),
        )


class MemoryRecordKind(StrEnum):
    NODE = "node"
    CLAIM = "claim"
    EDGE = "edge"
    CONFLICT = "conflict"
    EVIDENCE = "evidence"
    CANDIDATE = "candidate"
    SEMANTIC_OBJECT = "semantic_object"
    RUNTIME_STATE = "runtime_state"
    DOMAIN_EXTENSION = "domain_extension"


class MemoryLifecycle(StrEnum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    RETRACTED = "retracted"
    SUPPRESSED = "suppressed"


@dataclass(frozen=True, slots=True)
class DomainTimeRange:
    from_: int | None
    to: int | None

    def to_wire(self) -> JsonObject:
        _optional_int128(self.from_, "valid_time.from")
        _optional_int128(self.to, "valid_time.to")
        return {"from": self.from_, "to": self.to}

    @classmethod
    def from_wire(cls, value: Any) -> DomainTimeRange:
        obj = _mapping(value, "domain time range", {"from", "to"})
        return cls(
            from_=_optional_int128(obj["from"], "valid_time.from"),
            to=_optional_int128(obj["to"], "valid_time.to"),
        )


@dataclass(frozen=True, slots=True)
class MemoryLinks:
    subject: str | None = None
    source: str | None = None
    target: str | None = None
    predicate: str | None = None
    conflict_set: str | None = None
    supersedes: frozenset[str] = frozenset()
    evidence: frozenset[str] = frozenset()
    conflict_members: frozenset[str] = frozenset()
    single_valued: bool = False

    def to_wire(self) -> JsonObject:
        return {
            "subject": self.subject,
            "source": self.source,
            "target": self.target,
            "predicate": self.predicate,
            "conflict_set": self.conflict_set,
            "supersedes": _wire_strings(self.supersedes),
            "evidence": _wire_strings(self.evidence),
            "conflict_members": _wire_strings(self.conflict_members),
            "single_valued": self.single_valued,
        }

    @classmethod
    def from_wire(cls, value: Any) -> MemoryLinks:
        obj = _mapping(
            value,
            "memory links",
            {
                "subject",
                "source",
                "target",
                "predicate",
                "conflict_set",
                "supersedes",
                "evidence",
                "conflict_members",
                "single_valued",
            },
        )
        return cls(
            subject=_optional_string(obj["subject"], "links.subject"),
            source=_optional_string(obj["source"], "links.source"),
            target=_optional_string(obj["target"], "links.target"),
            predicate=_optional_string(obj["predicate"], "links.predicate"),
            conflict_set=_optional_string(obj["conflict_set"], "links.conflict_set"),
            supersedes=frozenset(_string_tuple(obj["supersedes"], "links.supersedes")),
            evidence=frozenset(_string_tuple(obj["evidence"], "links.evidence")),
            conflict_members=frozenset(
                _string_tuple(obj["conflict_members"], "links.conflict_members")
            ),
            single_valued=_boolean(obj["single_valued"], "links.single_valued"),
        )


@dataclass(frozen=True, slots=True)
class MemoryDocument:
    id: str
    kind: MemoryRecordKind
    access: AccessPolicy
    valid_time: DomainTimeRange
    lifecycle: MemoryLifecycle
    links: MemoryLinks
    value: Any
    search_text: str | None
    vector: tuple[float, ...] | None
    attributes: Mapping[str, Any]

    def to_wire(self) -> JsonObject:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "access": self.access.to_wire(),
            "valid_time": self.valid_time.to_wire(),
            "lifecycle": self.lifecycle.value,
            "links": self.links.to_wire(),
            "value": self.value,
            "search_text": self.search_text,
            "vector": None if self.vector is None else list(self.vector),
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_wire(cls, value: Any) -> MemoryDocument:
        obj = _mapping(
            value,
            "memory document",
            {
                "id",
                "kind",
                "access",
                "valid_time",
                "lifecycle",
                "links",
                "value",
                "search_text",
                "vector",
                "attributes",
            },
        )
        vector = obj["vector"]
        parsed_vector: tuple[float, ...] | None = None
        if vector is not None:
            if not isinstance(vector, list):
                raise ProtocolError("invalid memory vector")
            parsed_vector = tuple(_finite_f32(item, "memory vector item") for item in vector)
        return cls(
            id=_string(obj["id"], "memory id"),
            kind=_enum(MemoryRecordKind, obj["kind"], "memory kind"),
            access=_access_from_wire(obj["access"]),
            valid_time=DomainTimeRange.from_wire(obj["valid_time"]),
            lifecycle=_enum(MemoryLifecycle, obj["lifecycle"], "memory lifecycle"),
            links=MemoryLinks.from_wire(obj["links"]),
            value=obj["value"],
            search_text=_optional_string(obj["search_text"], "search_text"),
            vector=parsed_vector,
            attributes=_json_mapping(obj["attributes"], "memory attributes"),
        )


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    document: MemoryDocument
    revision: int
    transaction_from: int
    transaction_to: int | None

    @classmethod
    def from_wire(cls, value: Any) -> MemoryRecord:
        obj = _mapping(
            value,
            "memory record",
            {"document", "revision", "transaction_from", "transaction_to"},
        )
        return cls(
            document=MemoryDocument.from_wire(obj["document"]),
            revision=_uint32(obj["revision"], "revision"),
            transaction_from=_uint(obj["transaction_from"], "transaction_from"),
            transaction_to=_optional_uint(obj["transaction_to"], "transaction_to"),
        )


@dataclass(frozen=True, slots=True)
class MutationResponse:
    commit_seq: int
    replayed: bool
    request_digest: str
    watermarks: Watermarks

    @classmethod
    def from_wire(cls, value: Any) -> MutationResponse:
        obj = _mapping(
            value,
            "mutation response",
            {"commit_seq", "replayed", "request_digest", "watermarks"},
        )
        return cls(
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
            replayed=_boolean(obj["replayed"], "replayed"),
            request_digest=_string(obj["request_digest"], "request_digest"),
            watermarks=Watermarks.from_wire(obj["watermarks"]),
        )


@dataclass(frozen=True, slots=True)
class HighLevelWriteRequest:
    context: AuthenticatedRequestContext
    idempotency_key: str
    target_subject_id: str
    session_id: str | None
    logical_id: str
    access: AccessPolicy
    payload: Any
    references: frozenset[str] = frozenset()

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "idempotency_key": self.idempotency_key,
            "target_subject_id": self.target_subject_id,
            "session_id": self.session_id,
            "logical_id": self.logical_id,
            "access": self.access.to_wire(),
            "payload": self.payload,
            "references": _wire_strings(self.references),
        }


@dataclass(frozen=True, slots=True)
class HighLevelQueryRequest:
    context: AuthenticatedRequestContext
    target_subject_id: str
    cue: str
    page_size: int
    at_commit: int | None = None
    continuation: str | None = None

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "target_subject_id": self.target_subject_id,
            "cue": self.cue,
            "page_size": self.page_size,
            "at_commit": self.at_commit,
            "continuation": self.continuation,
        }


@dataclass(frozen=True, slots=True)
class HighLevelControlRequest:
    context: AuthenticatedRequestContext
    idempotency_key: str
    target_subject_id: str
    target_id: str
    parameters: Any

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "idempotency_key": self.idempotency_key,
            "target_subject_id": self.target_subject_id,
            "target_id": self.target_id,
            "parameters": self.parameters,
        }


@dataclass(frozen=True, slots=True)
class HighLevelTransferRequest:
    context: AuthenticatedRequestContext
    idempotency_key: str
    target_subject_id: str
    format: str
    bytes: bytes
    digest: str

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "idempotency_key": self.idempotency_key,
            "target_subject_id": self.target_subject_id,
            "format": self.format,
            "bytes": list(self.bytes),
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class HighLevelMutationResponse:
    operation: str
    logical_id: str
    policy_result: str
    semantic_status: str
    receipt: ObserveResponse

    @classmethod
    def from_wire(cls, value: Any) -> HighLevelMutationResponse:
        obj = _mapping(
            value,
            "high-level mutation response",
            {"operation", "logical_id", "policy_result", "semantic_status", "receipt"},
        )
        policy_result = _string(obj["policy_result"], "policy_result")
        semantic_status = _string(obj["semantic_status"], "semantic_status")
        if policy_result != "accepted" or semantic_status != "pending":
            raise ProtocolError("invalid high-level mutation state")
        return cls(
            operation=_string(obj["operation"], "operation"),
            logical_id=_string(obj["logical_id"], "logical_id"),
            policy_result=policy_result,
            semantic_status=semantic_status,
            receipt=ObserveResponse.from_wire(obj["receipt"]),
        )


@dataclass(frozen=True, slots=True)
class CorrectRequest:
    context: AuthenticatedRequestContext
    idempotency_key: str
    target_id: str
    replacement: MemoryDocument

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "idempotency_key": self.idempotency_key,
            "target_id": self.target_id,
            "replacement": self.replacement.to_wire(),
        }


class ForgetMode(StrEnum):
    RETRACT = "retract"
    HARD_DELETE = "hard_delete"


@dataclass(frozen=True, slots=True)
class ForgetRequest:
    context: AuthenticatedRequestContext
    idempotency_key: str
    target_id: str
    mode: ForgetMode
    reason: str

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "idempotency_key": self.idempotency_key,
            "target_id": self.target_id,
            "mode": self.mode.value,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class GetMemoryRequest:
    context: AuthenticatedRequestContext
    record_id: str
    at_commit: int | None

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "record_id": self.record_id,
            "at_commit": self.at_commit,
        }


@dataclass(frozen=True, slots=True)
class GetTimelineRequest:
    context: AuthenticatedRequestContext
    record_id: str
    expected_kind: MemoryRecordKind
    at_commit: int | None
    max_revisions: int

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "record_id": self.record_id,
            "expected_kind": self.expected_kind.value,
            "at_commit": self.at_commit,
            "max_revisions": self.max_revisions,
        }


@dataclass(frozen=True, slots=True)
class TimelineResponse:
    revisions: tuple[MemoryRecord, ...]
    snapshot_seq: int
    watermarks: Watermarks

    @classmethod
    def from_wire(cls, value: Any) -> TimelineResponse:
        obj = _mapping(value, "timeline response", {"revisions", "snapshot_seq", "watermarks"})
        revisions = obj["revisions"]
        if not isinstance(revisions, list):
            raise ProtocolError("invalid timeline revisions")
        return cls(
            revisions=tuple(MemoryRecord.from_wire(item) for item in revisions),
            snapshot_seq=_uint(obj["snapshot_seq"], "snapshot_seq"),
            watermarks=Watermarks.from_wire(obj["watermarks"]),
        )


class TraverseDirection(StrEnum):
    OUTGOING = "outgoing"
    INCOMING = "incoming"
    BOTH = "both"


@dataclass(frozen=True, slots=True)
class TraverseRequest:
    context: AuthenticatedRequestContext
    start_ids: tuple[str, ...]
    direction: TraverseDirection
    predicate_ids: frozenset[str]
    max_hops: int
    max_nodes: int
    at_commit: int | None

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "start_ids": list(self.start_ids),
            "direction": self.direction.value,
            "predicate_ids": _wire_strings(self.predicate_ids),
            "max_hops": self.max_hops,
            "max_nodes": self.max_nodes,
            "at_commit": self.at_commit,
        }


@dataclass(frozen=True, slots=True)
class TraverseResponse:
    node_ids: tuple[str, ...]
    snapshot_seq: int
    authorized_candidates: int
    watermarks: Watermarks

    @classmethod
    def from_wire(cls, value: Any) -> TraverseResponse:
        obj = _mapping(
            value,
            "traverse response",
            {"node_ids", "snapshot_seq", "authorized_candidates", "watermarks"},
        )
        return cls(
            node_ids=_string_tuple(obj["node_ids"], "node_ids"),
            snapshot_seq=_uint(obj["snapshot_seq"], "snapshot_seq"),
            authorized_candidates=_uint(obj["authorized_candidates"], "authorized_candidates"),
            watermarks=Watermarks.from_wire(obj["watermarks"]),
        )


@dataclass(frozen=True, slots=True)
class RuntimeRequest:
    context: AuthenticatedRequestContext
    operation_id: str
    payload: Any

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "operation_id": self.operation_id,
            "payload": self.payload,
        }


@dataclass(frozen=True, slots=True)
class RuntimeResponse:
    operation_id: str
    payload: Any

    @classmethod
    def from_wire(cls, value: Any) -> RuntimeResponse:
        obj = _mapping(value, "runtime response", {"operation_id", "payload"})
        return cls(
            operation_id=_string(obj["operation_id"], "operation_id"), payload=obj["payload"]
        )


@dataclass(frozen=True, slots=True)
class MaintenanceRequest:
    context: AuthenticatedRequestContext
    operation_id: str
    payload: Any

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "operation_id": self.operation_id,
            "payload": self.payload,
        }


@dataclass(frozen=True, slots=True)
class MaintenanceResponse:
    operation_id: str
    payload: Any

    @classmethod
    def from_wire(cls, value: Any) -> MaintenanceResponse:
        obj = _mapping(value, "maintenance response", {"operation_id", "payload"})
        return cls(
            operation_id=_string(obj["operation_id"], "operation_id"), payload=obj["payload"]
        )


@dataclass(frozen=True, slots=True)
class GetStatusRequest:
    context: AuthenticatedRequestContext

    def to_wire(self) -> JsonObject:
        return {"context": self.context.to_wire()}


@dataclass(frozen=True, slots=True)
class CapabilityManifestV1:
    schema_version: int
    profile: str
    server_v1_release_ready: bool
    capabilities: Mapping[str, RuntimeCapabilityState]

    @classmethod
    def from_wire(cls, value: Any) -> CapabilityManifestV1:
        obj = _mapping(
            value,
            "capability manifest",
            {
                "schema_version",
                "profile",
                "server_v1_release_ready",
                "capabilities",
            },
        )
        version = _uint(obj["schema_version"], "capability manifest schema_version")
        if version != 1:
            raise ProtocolError("unsupported capability manifest schema_version")
        raw_capabilities = obj["capabilities"]
        if not isinstance(raw_capabilities, Mapping) or any(
            not isinstance(key, str) for key in raw_capabilities
        ):
            raise ProtocolError("invalid capability manifest capabilities")
        return cls(
            schema_version=version,
            profile=_string(obj["profile"], "capability manifest profile"),
            server_v1_release_ready=_boolean(
                obj["server_v1_release_ready"], "server_v1_release_ready"
            ),
            capabilities={
                key: _enum(
                    RuntimeCapabilityState,
                    state,
                    f"capability state for {key}",
                )
                for key, state in raw_capabilities.items()
            },
        )


@dataclass(frozen=True, slots=True)
class StatusResponse:
    schema_version: int
    profile: str
    commit_seq: int
    watermarks: Watermarks
    capability_manifest: CapabilityManifestV1

    @classmethod
    def from_wire(cls, value: Any) -> StatusResponse:
        obj = _mapping(
            value,
            "status response",
            {
                "schema_version",
                "profile",
                "commit_seq",
                "watermarks",
                "capability_manifest",
            },
        )
        version = _uint(obj["schema_version"], "schema_version")
        if version > (1 << 16) - 1:
            raise ProtocolError("invalid schema_version")
        profile = _string(obj["profile"], "profile")
        capability_manifest = CapabilityManifestV1.from_wire(obj["capability_manifest"])
        if capability_manifest.profile != profile:
            raise ProtocolError("status profile does not match capability manifest profile")
        return cls(
            schema_version=version,
            profile=profile,
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
            watermarks=Watermarks.from_wire(obj["watermarks"]),
            capability_manifest=capability_manifest,
        )


@dataclass(frozen=True, slots=True)
class CreateBackupRequest:
    context: AuthenticatedRequestContext

    def to_wire(self) -> JsonObject:
        return {"context": self.context.to_wire()}


@dataclass(frozen=True, slots=True)
class BackupResponse:
    format: str
    bytes: bytes
    digest: str
    commit_seq: int

    @classmethod
    def from_wire(cls, value: Any) -> BackupResponse:
        obj = _mapping(value, "backup response", {"format", "bytes", "digest", "commit_seq"})
        return cls(
            format=_string(obj["format"], "backup format"),
            bytes=_byte_array(obj["bytes"]),
            digest=_string(obj["digest"], "backup digest"),
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
        )


@dataclass(frozen=True, slots=True)
class RestoreBackupRequest:
    context: AuthenticatedRequestContext
    format: str
    bytes: bytes
    digest: str

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "format": self.format,
            "bytes": list(self.bytes),
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class RestoreBackupResponse:
    commit_seq: int
    watermarks: Watermarks

    @classmethod
    def from_wire(cls, value: Any) -> RestoreBackupResponse:
        obj = _mapping(value, "restore response", {"commit_seq", "watermarks"})
        return cls(
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
            watermarks=Watermarks.from_wire(obj["watermarks"]),
        )


@dataclass(frozen=True, slots=True)
class MigrateFormatRequest:
    context: AuthenticatedRequestContext
    target_format: str
    operation_id: str

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "target_format": self.target_format,
            "operation_id": self.operation_id,
        }


_EnumT = TypeVar("_EnumT", bound=StrEnum)


def _enum(kind: type[_EnumT], value: Any, name: str) -> _EnumT:
    raw = _string(value, name)
    try:
        return kind(raw)
    except ValueError as error:
        raise ProtocolError(f"invalid {name}") from error


def _optional_string(value: Any, name: str) -> str | None:
    return None if value is None else _string(value, name)


def _optional_uint(value: Any, name: str) -> int | None:
    return None if value is None else _uint(value, name)


def _uint32(value: Any, name: str) -> int:
    result = _uint(value, name)
    if result > (1 << 32) - 1:
        raise ProtocolError(f"invalid {name}")
    return result


def _optional_int128(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not -(1 << 127) <= value < (1 << 127)
    ):
        raise ProtocolError(f"invalid {name}")
    return value


def _finite_f32(value: Any, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or abs(value) > 3.4028235e38
    ):
        raise ProtocolError(f"invalid {name}")
    return float(value)


def _string_mapping(value: Any, name: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise ProtocolError(f"invalid {name}")
    return dict(value)


def _json_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ProtocolError(f"invalid {name}")
    return dict(value)


def _access_from_wire(value: Any) -> AccessPolicy:
    obj = _mapping(
        value,
        "access policy",
        {
            "workspace_id",
            "scopes",
            "owners",
            "audience",
            "audience_purpose_grants",
            "purposes",
            "sensitivity",
            "consent",
            "retrievable",
        },
    )
    grants = obj["audience_purpose_grants"]
    if not isinstance(grants, Mapping) or any(
        not isinstance(key, str) or not isinstance(items, list) for key, items in grants.items()
    ):
        raise ProtocolError("invalid audience_purpose_grants")
    parsed_grants = {
        key: frozenset(_string_tuple(items, f"audience_purpose_grants.{key}"))
        for key, items in grants.items()
    }
    return AccessPolicy(
        workspace_id=_string(obj["workspace_id"], "workspace_id"),
        scopes=frozenset(_string_tuple(obj["scopes"], "scopes")),
        owners=frozenset(_string_tuple(obj["owners"], "owners")),
        audience=frozenset(_string_tuple(obj["audience"], "audience")),
        audience_purpose_grants=parsed_grants,
        purposes=frozenset(_string_tuple(obj["purposes"], "purposes")),
        sensitivity=_enum(Sensitivity, obj["sensitivity"], "sensitivity"),
        consent=_enum(Consent, obj["consent"], "consent"),
        retrievable=_boolean(obj["retrievable"], "retrievable"),
    )


def _byte_array(value: Any) -> bytes:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 255
        for item in value
    ):
        raise ProtocolError("invalid archive bytes")
    return bytes(value)


__all__ = [
    "AuthenticatedChannel",
    "AuthenticatedRequestContext",
    "AuthenticationEvidence",
    "BackupResponse",
    "Capability",
    "CapabilityManifestV1",
    "CANDIDATE_RUNTIME_CAPABILITY_IDS_V1",
    "Compression",
    "CorrectRequest",
    "CreateBackupRequest",
    "DomainTimeRange",
    "ForgetMode",
    "ForgetRequest",
    "GetMemoryRequest",
    "GetStatusRequest",
    "GetTimelineRequest",
    "HighLevelControlRequest",
    "HighLevelMutationResponse",
    "HighLevelQueryRequest",
    "HighLevelTransferRequest",
    "HighLevelWriteRequest",
    "IngestAck",
    "IngestDisposition",
    "IngestFrame",
    "IngestFrameKind",
    "IngestFrameValue",
    "MaintenanceRequest",
    "MaintenanceResponse",
    "MemoryDocument",
    "MemoryEvent",
    "MemoryEventKind",
    "MemoryLifecycle",
    "MemoryLinks",
    "MemoryRecord",
    "MemoryRecordKind",
    "MigrateFormatRequest",
    "MutationResponse",
    "RequestSignature",
    "RestoreBackupRequest",
    "RestoreBackupResponse",
    "RuntimeRequest",
    "RuntimeCapabilityState",
    "RuntimeResponse",
    "SnapshotComplete",
    "SourceRevisionManifest",
    "StatusResponse",
    "StreamObservation",
    "SubscribeRequest",
    "SubscriptionPage",
    "TimelineResponse",
    "TraverseDirection",
    "TraverseRequest",
    "TraverseResponse",
]
