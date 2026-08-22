"""Stable ContextDB SDK errors."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_ERROR_STATUS = {
    "invalid_scope": 400,
    "unauthorized": 403,
    "ambiguous_identity": 400,
    "snapshot_expired": 410,
    "index_too_stale": 409,
    "evidence_required": 400,
    "conflict_unresolved": 409,
    "budget_exhausted": 413,
    "continuation_expired": 410,
    "format_incompatible": 422,
    "provider_unavailable": 503,
    "degraded_mode": 206,
    "invalid_argument": 400,
    "permission_denied": 403,
    "not_found": 404,
    "idempotency_conflict": 409,
    "invalid_continuation": 400,
    "integrity_failure": 422,
    "unavailable": 503,
    "resource_exhausted": 413,
    "unsupported": 501,
}


@dataclass(slots=True)
class ContextDbError(Exception):
    """A canonical service error returned by ContextDB."""

    code: str
    message: str
    retryable: bool
    status: int
    partial_result_refs: tuple[str, ...] = ()
    violated_policy: str | None = None
    safe_next_action: str | None = None
    trace_id: str | None = None

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    @classmethod
    def from_wire(cls, value: Mapping[str, Any], status: int) -> ContextDbError:
        required = {"code", "message", "retryable"}
        optional = {
            "partial_result_refs",
            "violated_policy",
            "safe_next_action",
            "trace_id",
        }
        if not required <= set(value) or not set(value) <= required | optional:
            raise ProtocolError("invalid ContextDB error envelope", status=status)
        code = value.get("code")
        message = value.get("message")
        retryable = value.get("retryable")
        if (
            not isinstance(code, str)
            or not isinstance(message, str)
            or not isinstance(retryable, bool)
        ):
            raise ProtocolError("invalid ContextDB error field types", status=status)
        if _ERROR_STATUS.get(code) != status:
            raise ProtocolError("error code and HTTP status disagree", status=status)
        refs = value.get("partial_result_refs", [])
        if not isinstance(refs, list) or any(not isinstance(item, str) for item in refs):
            raise ProtocolError("invalid partial_result_refs", status=status)
        optional_strings: dict[str, str | None] = {}
        for field in ("violated_policy", "safe_next_action", "trace_id"):
            field_value = value.get(field)
            if field_value is not None and not isinstance(field_value, str):
                raise ProtocolError(f"invalid {field}", status=status)
            optional_strings[field] = field_value
        return cls(
            code=code,
            message=message,
            retryable=retryable,
            status=status,
            partial_result_refs=tuple(refs),
            violated_policy=optional_strings["violated_policy"],
            safe_next_action=optional_strings["safe_next_action"],
            trace_id=optional_strings["trace_id"],
        )


class ProtocolError(Exception):
    """The HTTP peer did not follow the canonical v1 JSON contract."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class TransportError(Exception):
    """The request could not reach a conforming HTTP peer."""
