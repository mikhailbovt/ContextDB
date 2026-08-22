"""Canonical v1 HTTP models with strict response validation."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, TypeAlias

from .errors import ProtocolError

JsonObject: TypeAlias = dict[str, Any]


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"
    RESTRICTED = "restricted"


class Consent(StrEnum):
    GRANTED = "granted"
    UNKNOWN = "unknown"
    DENIED = "denied"


class ErrorCode(StrEnum):
    INVALID_SCOPE = "invalid_scope"
    UNAUTHORIZED = "unauthorized"
    AMBIGUOUS_IDENTITY = "ambiguous_identity"
    SNAPSHOT_EXPIRED = "snapshot_expired"
    INDEX_TOO_STALE = "index_too_stale"
    EVIDENCE_REQUIRED = "evidence_required"
    CONFLICT_UNRESOLVED = "conflict_unresolved"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CONTINUATION_EXPIRED = "continuation_expired"
    FORMAT_INCOMPATIBLE = "format_incompatible"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    DEGRADED_MODE = "degraded_mode"
    INVALID_ARGUMENT = "invalid_argument"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    INVALID_CONTINUATION = "invalid_continuation"
    INTEGRITY_FAILURE = "integrity_failure"
    UNAVAILABLE = "unavailable"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    UNSUPPORTED = "unsupported"


def _mapping(value: Any, name: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ProtocolError(f"invalid {name} object")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"invalid {name}")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ProtocolError(f"invalid {name}")
    return value


def _uint(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > (1 << 64) - 1:
        raise ProtocolError(f"invalid {name}")
    return value


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ProtocolError(f"invalid {name}")
    return tuple(value)


def _wire_strings(values: frozenset[str]) -> list[str]:
    return sorted(values)


@dataclass(frozen=True, slots=True)
class RequestContext:
    request_id: str
    workspace_id: str
    subject_id: str
    audiences: frozenset[str]
    scopes: frozenset[str]
    purpose: str
    clearance: Sensitivity

    def with_request_id(self, request_id: str) -> RequestContext:
        return replace(self, request_id=request_id)

    def to_wire(self) -> JsonObject:
        return {
            "request_id": self.request_id,
            "workspace_id": self.workspace_id,
            "subject_id": self.subject_id,
            "audiences": _wire_strings(self.audiences),
            "scopes": _wire_strings(self.scopes),
            "purpose": self.purpose,
            "clearance": self.clearance.value,
        }


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    workspace_id: str
    scopes: frozenset[str]
    owners: frozenset[str]
    audience: frozenset[str]
    audience_purpose_grants: Mapping[str, frozenset[str]]
    purposes: frozenset[str]
    sensitivity: Sensitivity
    consent: Consent
    retrievable: bool

    def to_wire(self) -> JsonObject:
        return {
            "workspace_id": self.workspace_id,
            "scopes": _wire_strings(self.scopes),
            "owners": _wire_strings(self.owners),
            "audience": _wire_strings(self.audience),
            "audience_purpose_grants": {
                key: _wire_strings(values)
                for key, values in sorted(self.audience_purpose_grants.items())
            },
            "purposes": _wire_strings(self.purposes),
            "sensitivity": self.sensitivity.value,
            "consent": self.consent.value,
            "retrievable": self.retrievable,
        }


@dataclass(frozen=True, slots=True)
class Watermarks:
    journal: int
    semantic: int
    lexical: int
    vector: int
    graph: int

    @classmethod
    def from_wire(cls, value: Any) -> Watermarks:
        obj = _mapping(
            value,
            "watermarks",
            {"journal", "semantic", "lexical", "vector", "graph"},
        )
        return cls(**{key: _uint(obj[key], f"watermarks.{key}") for key in obj})


@dataclass(frozen=True, slots=True)
class ObserveRequest:
    context: RequestContext
    idempotency_key: str
    observation_id: str
    metadata: Mapping[str, Any]
    content: Any
    access: AccessPolicy

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "idempotency_key": self.idempotency_key,
            "observation_id": self.observation_id,
            "metadata": dict(self.metadata),
            "content": self.content,
            "access": self.access.to_wire(),
        }


@dataclass(frozen=True, slots=True)
class ObserveResponse:
    commit_seq: int
    replayed: bool
    request_digest: str
    watermarks: Watermarks

    @classmethod
    def from_wire(cls, value: Any) -> ObserveResponse:
        obj = _mapping(
            value,
            "observe response",
            {"commit_seq", "replayed", "request_digest", "watermarks"},
        )
        return cls(
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
            replayed=_boolean(obj["replayed"], "replayed"),
            request_digest=_string(obj["request_digest"], "request_digest"),
            watermarks=Watermarks.from_wire(obj["watermarks"]),
        )


@dataclass(frozen=True, slots=True)
class RecallRequest:
    context: RequestContext
    query: str
    page_size: int
    at_commit: int | None = None
    continuation: str | None = None

    def to_wire(self) -> JsonObject:
        return {
            "context": self.context.to_wire(),
            "query": self.query,
            "page_size": self.page_size,
            "at_commit": self.at_commit,
            "continuation": self.continuation,
        }


@dataclass(frozen=True, slots=True)
class RecallHit:
    id: str
    score: float

    @classmethod
    def from_wire(cls, value: Any) -> RecallHit:
        obj = _mapping(value, "recall hit", {"id", "score"})
        score = obj["score"]
        if (
            isinstance(score, bool)
            or not isinstance(score, int | float)
            or not math.isfinite(score)
            or abs(score) > 3.4028235e38
        ):
            raise ProtocolError("invalid recall hit score")
        return cls(id=_string(obj["id"], "recall hit id"), score=float(score))


@dataclass(frozen=True, slots=True)
class RecallTrace:
    trace_id: str
    snapshot_seq: int
    operation: str
    authorized_candidates: int
    selected_ids: tuple[str, ...]
    watermarks: Watermarks

    @classmethod
    def from_wire(cls, value: Any) -> RecallTrace:
        obj = _mapping(
            value,
            "recall trace",
            {
                "trace_id",
                "snapshot_seq",
                "operation",
                "authorized_candidates",
                "selected_ids",
                "watermarks",
            },
        )
        return cls(
            trace_id=_string(obj["trace_id"], "trace_id"),
            snapshot_seq=_uint(obj["snapshot_seq"], "snapshot_seq"),
            operation=_string(obj["operation"], "operation"),
            authorized_candidates=_uint(obj["authorized_candidates"], "authorized_candidates"),
            selected_ids=_string_tuple(obj["selected_ids"], "selected_ids"),
            watermarks=Watermarks.from_wire(obj["watermarks"]),
        )

    def to_wire(self) -> JsonObject:
        return {
            "trace_id": self.trace_id,
            "snapshot_seq": self.snapshot_seq,
            "operation": self.operation,
            "authorized_candidates": self.authorized_candidates,
            "selected_ids": list(self.selected_ids),
            "watermarks": {
                "journal": self.watermarks.journal,
                "semantic": self.watermarks.semantic,
                "lexical": self.watermarks.lexical,
                "vector": self.watermarks.vector,
                "graph": self.watermarks.graph,
            },
        }


@dataclass(frozen=True, slots=True)
class RecallResponse:
    hits: tuple[RecallHit, ...]
    trace: RecallTrace
    continuation: str | None

    @classmethod
    def from_wire(cls, value: Any) -> RecallResponse:
        obj = _mapping(value, "recall response", {"hits", "trace", "continuation"})
        hits = obj["hits"]
        continuation = obj["continuation"]
        if not isinstance(hits, list) or (
            continuation is not None and not isinstance(continuation, str)
        ):
            raise ProtocolError("invalid recall response fields")
        return cls(
            hits=tuple(RecallHit.from_wire(hit) for hit in hits),
            trace=RecallTrace.from_wire(obj["trace"]),
            continuation=continuation,
        )


@dataclass(frozen=True, slots=True)
class ExplainRecallRequest:
    context: RequestContext
    trace: RecallTrace

    def to_wire(self) -> JsonObject:
        return {"context": self.context.to_wire(), "trace": self.trace.to_wire()}


@dataclass(frozen=True, slots=True)
class ExportRequest:
    context: RequestContext

    def to_wire(self) -> JsonObject:
        return {"context": self.context.to_wire()}


@dataclass(frozen=True, slots=True)
class ExportResponse:
    format: str
    bytes: bytes
    digest: str
    commit_seq: int

    @classmethod
    def from_wire(cls, value: Any) -> ExportResponse:
        obj = _mapping(value, "export response", {"format", "bytes", "digest", "commit_seq"})
        raw = obj["bytes"]
        if not isinstance(raw, list) or any(
            isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 255
            for item in raw
        ):
            raise ProtocolError("invalid archive bytes")
        return cls(
            format=_string(obj["format"], "archive format"),
            bytes=bytes(raw),
            digest=_string(obj["digest"], "archive digest"),
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
        )


@dataclass(frozen=True, slots=True)
class ImportRequest:
    context: RequestContext
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
class ImportResponse:
    commit_seq: int
    watermarks: Watermarks

    @classmethod
    def from_wire(cls, value: Any) -> ImportResponse:
        obj = _mapping(value, "import response", {"commit_seq", "watermarks"})
        return cls(
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
            watermarks=Watermarks.from_wire(obj["watermarks"]),
        )


@dataclass(frozen=True, slots=True)
class VerifyRequest:
    context: RequestContext
    deep: bool

    def to_wire(self) -> JsonObject:
        return {"context": self.context.to_wire(), "deep": self.deep}


@dataclass(frozen=True, slots=True)
class VerifyResponse:
    valid: bool
    commit_seq: int
    archive_digest: str | None

    @classmethod
    def from_wire(cls, value: Any) -> VerifyResponse:
        obj = _mapping(value, "verify response", {"valid", "commit_seq", "archive_digest"})
        digest = obj["archive_digest"]
        if digest is not None and not isinstance(digest, str):
            raise ProtocolError("invalid archive_digest")
        return cls(
            valid=_boolean(obj["valid"], "valid"),
            commit_seq=_uint(obj["commit_seq"], "commit_seq"),
            archive_digest=digest,
        )


__all__ = [
    "AccessPolicy",
    "Consent",
    "ErrorCode",
    "ExplainRecallRequest",
    "ExportRequest",
    "ExportResponse",
    "ImportRequest",
    "ImportResponse",
    "ObserveRequest",
    "ObserveResponse",
    "RecallHit",
    "RecallRequest",
    "RecallResponse",
    "RecallTrace",
    "RequestContext",
    "Sensitivity",
    "VerifyRequest",
    "VerifyResponse",
    "Watermarks",
]
