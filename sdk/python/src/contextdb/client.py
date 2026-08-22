"""Canonical ContextDB v1 HTTP client."""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.message import Message
from typing import Any, Protocol
from urllib.parse import urlsplit

from .context_pack import CompileContextRequest, CompileContextResponse
from .domain import (
    BackupResponse,
    CorrectRequest,
    CreateBackupRequest,
    ForgetRequest,
    GetMemoryRequest,
    GetStatusRequest,
    GetTimelineRequest,
    HighLevelControlRequest,
    HighLevelMutationResponse,
    HighLevelQueryRequest,
    HighLevelTransferRequest,
    HighLevelWriteRequest,
    IngestAck,
    IngestFrame,
    MaintenanceRequest,
    MaintenanceResponse,
    MemoryRecord,
    MigrateFormatRequest,
    MutationResponse,
    RestoreBackupRequest,
    RestoreBackupResponse,
    RuntimeRequest,
    RuntimeResponse,
    StatusResponse,
    SubscribeRequest,
    SubscriptionPage,
    TimelineResponse,
    TraverseRequest,
    TraverseResponse,
)
from .errors import ContextDbError, ProtocolError, TransportError
from .models import (
    ExplainRecallRequest,
    ExportRequest,
    ExportResponse,
    ImportRequest,
    ImportResponse,
    ObserveRequest,
    ObserveResponse,
    RecallRequest,
    RecallResponse,
    RecallTrace,
    VerifyRequest,
    VerifyResponse,
)

MAX_WIRE_BYTES = 16 * 1024 * 1024
OBSERVE_PATH = "/v1/observations"
INGEST_FRAME_PATH = "/v1/observations/ingest-frame"
CORRECT_PATH = "/v1/observations/correct"
FORGET_PATH = "/v1/observations/forget"
RECALL_PATH = "/v1/recall"
CONTEXT_PACK_PATH = "/v1/context-pack"
EXPLAIN_RECALL_PATH = "/v1/recall/explain"
SUBSCRIBE_PATH = "/v1/subscriptions/page"
GET_NODE_PATH = "/v1/memory/node"
TRAVERSE_PATH = "/v1/memory/traverse"
GET_TIMELINE_PATH = "/v1/memory/timeline"
GET_EVIDENCE_PATH = "/v1/memory/evidence"
GET_CONFLICT_PATH = "/v1/memory/conflict"
BOOTSTRAP_PATH = "/v1/runtime/bootstrap"
PREFLIGHT_PATH = "/v1/runtime/preflight"
POSTFLIGHT_PATH = "/v1/runtime/postflight"
CHECKPOINT_PATH = "/v1/runtime/checkpoint"
RESUME_PATH = "/v1/runtime/resume"
HANDOFF_PATH = "/v1/runtime/handoff"
CONSOLIDATE_PATH = "/v1/maintenance/consolidate"
REFLECT_PATH = "/v1/maintenance/reflect"
REINDEX_PATH = "/v1/maintenance/reindex"
COMPACT_PATH = "/v1/maintenance/compact"
GET_STATUS_PATH = "/v1/admin/status"
CREATE_BACKUP_PATH = "/v1/admin/backup"
RESTORE_BACKUP_PATH = "/v1/admin/restore"
MIGRATE_FORMAT_PATH = "/v1/admin/migrate"
EXPORT_PATH = "/v1/archive/export"
IMPORT_PATH = "/v1/archive/import"
VERIFY_PATH = "/v1/verify"
BEGIN_SESSION_PATH = "/v1/conversation/begin-session"
BEFORE_TURN_PATH = "/v1/conversation/before-turn"
AFTER_TURN_PATH = "/v1/conversation/after-turn"
RESOLVE_REFERENT_PATH = "/v1/conversation/resolve-referent"
RECALL_SHARED_HISTORY_PATH = "/v1/conversation/recall-shared-history"
END_SESSION_PATH = "/v1/conversation/end-session"
BOOTSTRAP_SUBJECT_PATH = "/v1/conversation/bootstrap-subject"
REMEMBER_PATH = "/v1/memory/remember"
PIN_PATH = "/v1/memory/pin"
SUPPRESS_PATH = "/v1/memory/suppress"
CHANGE_AUDIENCE_PATH = "/v1/memory/change-audience"
CHANGE_RETENTION_PATH = "/v1/memory/change-retention"
EXPLAIN_MEMORY_PATH = "/v1/memory/explain"
LIST_SUBJECT_MEMORIES_PATH = "/v1/memory/list-subject"
EXPORT_SUBJECT_PATH = "/v1/memory/export-subject"
IMPORT_SUBJECT_PATH = "/v1/memory/import-subject"
CREATE_MEMORY_SUBJECT_PATH = "/v1/subjects/create"
CREATE_RELATIONSHIP_SPACE_PATH = "/v1/relationship-spaces/create"
GET_CONTINUITY_PROFILE_PATH = "/v1/subjects/continuity-profile"
UPDATE_CONFIGURED_ROLE_PATH = "/v1/subjects/configured-role/update"
MIGRATE_AGENT_RUNTIME_PATH = "/v1/subjects/agent-runtime/migrate"
PUBLISH_TO_SHARED_MEMORY_PATH = "/v1/shared-memory/publish"
REVOKE_SHARED_MEMORY_PATH = "/v1/shared-memory/revoke"
INGEST_ARTIFACT_PATH = "/v1/artifacts/ingest"
ATTACH_ARTIFACT_TO_EPISODE_PATH = "/v1/artifacts/attach-to-episode"
ADD_DERIVED_REPRESENTATION_PATH = "/v1/artifacts/derived-representations"
ADD_EVIDENCE_SELECTOR_PATH = "/v1/artifacts/evidence-selectors"
GET_ARTIFACT_METADATA_PATH = "/v1/artifacts/metadata"
DELETE_ARTIFACT_LINEAGE_PATH = "/v1/artifacts/delete-lineage"

ROUTES = {
    "observe": OBSERVE_PATH,
    "ingest_frame": INGEST_FRAME_PATH,
    "correct": CORRECT_PATH,
    "forget": FORGET_PATH,
    "recall": RECALL_PATH,
    "compile_context": CONTEXT_PACK_PATH,
    "explain_recall": EXPLAIN_RECALL_PATH,
    "subscribe": SUBSCRIBE_PATH,
    "get_node": GET_NODE_PATH,
    "traverse": TRAVERSE_PATH,
    "get_timeline": GET_TIMELINE_PATH,
    "get_evidence": GET_EVIDENCE_PATH,
    "get_conflict": GET_CONFLICT_PATH,
    "bootstrap": BOOTSTRAP_PATH,
    "preflight": PREFLIGHT_PATH,
    "postflight": POSTFLIGHT_PATH,
    "checkpoint": CHECKPOINT_PATH,
    "resume": RESUME_PATH,
    "handoff": HANDOFF_PATH,
    "consolidate": CONSOLIDATE_PATH,
    "reflect": REFLECT_PATH,
    "reindex": REINDEX_PATH,
    "compact": COMPACT_PATH,
    "get_status": GET_STATUS_PATH,
    "create_backup": CREATE_BACKUP_PATH,
    "restore_backup": RESTORE_BACKUP_PATH,
    "migrate_format": MIGRATE_FORMAT_PATH,
    "export_archive": EXPORT_PATH,
    "import_archive": IMPORT_PATH,
    "verify": VERIFY_PATH,
    "begin_session": BEGIN_SESSION_PATH,
    "before_turn": BEFORE_TURN_PATH,
    "after_turn": AFTER_TURN_PATH,
    "resolve_referent": RESOLVE_REFERENT_PATH,
    "recall_shared_history": RECALL_SHARED_HISTORY_PATH,
    "end_session": END_SESSION_PATH,
    "bootstrap_subject": BOOTSTRAP_SUBJECT_PATH,
    "remember": REMEMBER_PATH,
    "pin": PIN_PATH,
    "suppress": SUPPRESS_PATH,
    "change_audience": CHANGE_AUDIENCE_PATH,
    "change_retention": CHANGE_RETENTION_PATH,
    "explain_memory": EXPLAIN_MEMORY_PATH,
    "list_subject_memories": LIST_SUBJECT_MEMORIES_PATH,
    "export_subject": EXPORT_SUBJECT_PATH,
    "import_subject": IMPORT_SUBJECT_PATH,
    "create_memory_subject": CREATE_MEMORY_SUBJECT_PATH,
    "create_relationship_space": CREATE_RELATIONSHIP_SPACE_PATH,
    "get_continuity_profile": GET_CONTINUITY_PROFILE_PATH,
    "update_configured_role": UPDATE_CONFIGURED_ROLE_PATH,
    "migrate_agent_runtime": MIGRATE_AGENT_RUNTIME_PATH,
    "publish_to_shared_memory": PUBLISH_TO_SHARED_MEMORY_PATH,
    "revoke_shared_memory": REVOKE_SHARED_MEMORY_PATH,
    "ingest_artifact": INGEST_ARTIFACT_PATH,
    "attach_artifact_to_episode": ATTACH_ARTIFACT_TO_EPISODE_PATH,
    "add_derived_representation": ADD_DERIVED_REPRESENTATION_PATH,
    "add_evidence_selector": ADD_EVIDENCE_SELECTOR_PATH,
    "get_artifact_metadata": GET_ARTIFACT_METADATA_PATH,
    "delete_artifact_lineage": DELETE_ARTIFACT_LINEAGE_PATH,
}


@dataclass(frozen=True, slots=True)
class HeaderProviderRequest:
    """Exact canonical HTTP material for one deployment-attestation decision."""

    path: str
    body: bytes


HeaderProvider = Callable[[HeaderProviderRequest], Mapping[str, str]]


class Transport(Protocol):
    def post(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


class HttpTransport:
    """Small urllib transport with bounded request/response bodies."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        bearer_token: str | None = None,
        headers: Mapping[str, str] | None = None,
        header_provider: HeaderProvider | None = None,
        max_wire_bytes: int = MAX_WIRE_BYTES,
        opener: Callable[[urllib.request.Request, float], Any] | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("base_url must be an http(s) origin/path without credentials")
        if timeout <= 0 or max_wire_bytes <= 0:
            raise ValueError("timeout and max_wire_bytes must be positive")
        if bearer_token is not None and ("\r" in bearer_token or "\n" in bearer_token):
            raise ValueError("invalid bearer token")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_wire_bytes = max_wire_bytes
        self._headers = dict(headers or {})
        if any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or "\r" in key
            or "\n" in key
            or "\r" in value
            or "\n" in value
            or key.lower() in {"host", "content-length", "transfer-encoding"}
            for key, value in self._headers.items()
        ):
            raise ValueError("invalid HTTP header")
        if any(key.lower() == "x-contextdb-gateway-attestation" for key in self._headers):
            raise ValueError("gateway attestation must be supplied by header_provider")
        if bearer_token:
            self._headers["Authorization"] = f"Bearer {bearer_token}"
        self._header_provider = header_provider
        default_opener = urllib.request.build_opener(_NoRedirect()).open
        self._opener = opener or (lambda request, timeout: default_opener(request, timeout=timeout))

    def post(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            encoded = json.dumps(
                body, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ProtocolError("request is not valid JSON") from error
        if len(encoded) > self._max_wire_bytes:
            raise ProtocolError("request exceeds the configured wire limit")
        headers = dict(self._headers)
        if self._header_provider is not None:
            try:
                dynamic = self._header_provider(HeaderProviderRequest(path=path, body=encoded))
            except Exception as error:
                raise TransportError("ContextDB header provider failed") from error
            if not isinstance(dynamic, Mapping) or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key
                or "\r" in key
                or "\n" in key
                or "\r" in value
                or "\n" in value
                or key.lower() in {"host", "content-length", "transfer-encoding"}
                for key, value in dynamic.items()
            ):
                raise ProtocolError("header provider returned an invalid HTTP header")
            headers.update(dynamic)
        for key in tuple(headers):
            if key.lower() in {"accept", "content-type"}:
                del headers[key]
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self._base_url}{path}", data=encoded, headers=headers, method="POST"
        )
        try:
            response = self._opener(request, self._timeout)
            with response:
                status = int(response.status)
                self._require_json_content_type(response.headers, status=status)
                raw = self._read_limited(response)
        except urllib.error.HTTPError as error:
            try:
                self._require_json_content_type(error.headers, status=error.code)
                raw = self._read_limited(error)
            except (OSError, TimeoutError) as read_error:
                raise TransportError("ContextDB response failed") from read_error
            finally:
                error.close()
            value = self._decode(raw, status=error.code)
            raise ContextDbError.from_wire(value, error.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise TransportError("ContextDB request failed") from error
        value = self._decode(raw, status=status)
        if status != 200:
            raise ContextDbError.from_wire(value, status)
        return value

    def _read_limited(self, response: Any) -> bytes:
        chunks: list[bytes] = []
        remaining = self._max_wire_bytes + 1
        while remaining > 0:
            chunk = response.read(min(64 * 1024, remaining))
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise ProtocolError("response body is not bytes")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > self._max_wire_bytes:
            raise ProtocolError("response exceeds the configured wire limit")
        return raw

    @staticmethod
    def _require_json_content_type(
        headers: Message | Mapping[str, str] | None, *, status: int
    ) -> None:
        if headers is None:
            raise ProtocolError("response Content-Type is not application/json", status=status)
        content_type = headers.get("Content-Type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise ProtocolError("response Content-Type is not application/json", status=status)

    @staticmethod
    def _decode(raw: bytes, *, status: int) -> Mapping[str, Any]:
        try:
            value = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, ValueError) as error:
            raise ProtocolError("response is not valid UTF-8 JSON", status=status) from error
        if not isinstance(value, Mapping):
            raise ProtocolError("response JSON must be an object", status=status)
        return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


class ContextDbClient:
    """Synchronous canonical v1 client over an injectable transport."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport

    @classmethod
    def http(cls, base_url: str, **kwargs: Any) -> ContextDbClient:
        return cls(HttpTransport(base_url, **kwargs))

    def observe(self, request: ObserveRequest) -> ObserveResponse:
        return ObserveResponse.from_wire(self.transport.post(OBSERVE_PATH, request.to_wire()))

    def ingest_frame(self, request: IngestFrame) -> IngestAck:
        return IngestAck.from_wire(self.transport.post(INGEST_FRAME_PATH, request.to_wire()))

    def correct(self, request: CorrectRequest) -> MutationResponse:
        return MutationResponse.from_wire(self.transport.post(CORRECT_PATH, request.to_wire()))

    def forget(self, request: ForgetRequest) -> MutationResponse:
        return MutationResponse.from_wire(self.transport.post(FORGET_PATH, request.to_wire()))

    def recall(self, request: RecallRequest) -> RecallResponse:
        return RecallResponse.from_wire(self.transport.post(RECALL_PATH, request.to_wire()))

    def compile_context(self, request: CompileContextRequest) -> CompileContextResponse:
        return CompileContextResponse.from_wire(
            self.transport.post(CONTEXT_PACK_PATH, request.to_wire())
        )

    def explain_recall(self, request: ExplainRecallRequest) -> RecallTrace:
        return RecallTrace.from_wire(self.transport.post(EXPLAIN_RECALL_PATH, request.to_wire()))

    def subscribe(self, request: SubscribeRequest) -> SubscriptionPage:
        return SubscriptionPage.from_wire(self.transport.post(SUBSCRIBE_PATH, request.to_wire()))

    def get_node(self, request: GetMemoryRequest) -> MemoryRecord:
        return MemoryRecord.from_wire(self.transport.post(GET_NODE_PATH, request.to_wire()))

    def traverse(self, request: TraverseRequest) -> TraverseResponse:
        return TraverseResponse.from_wire(self.transport.post(TRAVERSE_PATH, request.to_wire()))

    def get_timeline(self, request: GetTimelineRequest) -> TimelineResponse:
        return TimelineResponse.from_wire(self.transport.post(GET_TIMELINE_PATH, request.to_wire()))

    def get_evidence(self, request: GetMemoryRequest) -> MemoryRecord:
        return MemoryRecord.from_wire(self.transport.post(GET_EVIDENCE_PATH, request.to_wire()))

    def get_conflict(self, request: GetMemoryRequest) -> MemoryRecord:
        return MemoryRecord.from_wire(self.transport.post(GET_CONFLICT_PATH, request.to_wire()))

    def bootstrap(self, request: RuntimeRequest) -> RuntimeResponse:
        return RuntimeResponse.from_wire(self.transport.post(BOOTSTRAP_PATH, request.to_wire()))

    def preflight(self, request: RuntimeRequest) -> RuntimeResponse:
        return RuntimeResponse.from_wire(self.transport.post(PREFLIGHT_PATH, request.to_wire()))

    def postflight(self, request: RuntimeRequest) -> RuntimeResponse:
        return RuntimeResponse.from_wire(self.transport.post(POSTFLIGHT_PATH, request.to_wire()))

    def checkpoint(self, request: RuntimeRequest) -> RuntimeResponse:
        return RuntimeResponse.from_wire(self.transport.post(CHECKPOINT_PATH, request.to_wire()))

    def resume(self, request: RuntimeRequest) -> RuntimeResponse:
        return RuntimeResponse.from_wire(self.transport.post(RESUME_PATH, request.to_wire()))

    def handoff(self, request: RuntimeRequest) -> RuntimeResponse:
        return RuntimeResponse.from_wire(self.transport.post(HANDOFF_PATH, request.to_wire()))

    def consolidate(self, request: MaintenanceRequest) -> MaintenanceResponse:
        return MaintenanceResponse.from_wire(
            self.transport.post(CONSOLIDATE_PATH, request.to_wire())
        )

    def reflect(self, request: MaintenanceRequest) -> MaintenanceResponse:
        return MaintenanceResponse.from_wire(self.transport.post(REFLECT_PATH, request.to_wire()))

    def reindex(self, request: MaintenanceRequest) -> MaintenanceResponse:
        return MaintenanceResponse.from_wire(self.transport.post(REINDEX_PATH, request.to_wire()))

    def compact(self, request: MaintenanceRequest) -> MaintenanceResponse:
        return MaintenanceResponse.from_wire(self.transport.post(COMPACT_PATH, request.to_wire()))

    def get_status(self, request: GetStatusRequest) -> StatusResponse:
        return StatusResponse.from_wire(self.transport.post(GET_STATUS_PATH, request.to_wire()))

    def create_backup(self, request: CreateBackupRequest) -> BackupResponse:
        return BackupResponse.from_wire(self.transport.post(CREATE_BACKUP_PATH, request.to_wire()))

    def restore_backup(self, request: RestoreBackupRequest) -> RestoreBackupResponse:
        return RestoreBackupResponse.from_wire(
            self.transport.post(RESTORE_BACKUP_PATH, request.to_wire())
        )

    def migrate_format(self, request: MigrateFormatRequest) -> StatusResponse:
        return StatusResponse.from_wire(self.transport.post(MIGRATE_FORMAT_PATH, request.to_wire()))

    def export_archive(self, request: ExportRequest) -> ExportResponse:
        return ExportResponse.from_wire(self.transport.post(EXPORT_PATH, request.to_wire()))

    def import_archive(self, request: ImportRequest) -> ImportResponse:
        return ImportResponse.from_wire(self.transport.post(IMPORT_PATH, request.to_wire()))

    def verify(self, request: VerifyRequest) -> VerifyResponse:
        return VerifyResponse.from_wire(self.transport.post(VERIFY_PATH, request.to_wire()))

    def _high_level_write(
        self, path: str, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return HighLevelMutationResponse.from_wire(self.transport.post(path, request.to_wire()))

    def _high_level_query(self, path: str, request: HighLevelQueryRequest) -> RecallResponse:
        return RecallResponse.from_wire(self.transport.post(path, request.to_wire()))

    def _high_level_control(self, path: str, request: HighLevelControlRequest) -> MutationResponse:
        return MutationResponse.from_wire(self.transport.post(path, request.to_wire()))

    def begin_session(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return self._high_level_write(BEGIN_SESSION_PATH, request)

    def before_turn(self, request: HighLevelQueryRequest) -> RecallResponse:
        return self._high_level_query(BEFORE_TURN_PATH, request)

    def after_turn(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return self._high_level_write(AFTER_TURN_PATH, request)

    def resolve_referent(self, request: HighLevelQueryRequest) -> RecallResponse:
        return self._high_level_query(RESOLVE_REFERENT_PATH, request)

    def recall_shared_history(self, request: HighLevelQueryRequest) -> RecallResponse:
        return self._high_level_query(RECALL_SHARED_HISTORY_PATH, request)

    def end_session(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return self._high_level_write(END_SESSION_PATH, request)

    def bootstrap_subject(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return self._high_level_write(BOOTSTRAP_SUBJECT_PATH, request)

    def remember(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return self._high_level_write(REMEMBER_PATH, request)

    def pin(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(PIN_PATH, request)

    def suppress(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(SUPPRESS_PATH, request)

    def change_audience(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(CHANGE_AUDIENCE_PATH, request)

    def change_retention(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(CHANGE_RETENTION_PATH, request)

    def explain_memory(self, request: HighLevelQueryRequest) -> RecallResponse:
        return self._high_level_query(EXPLAIN_MEMORY_PATH, request)

    def list_subject_memories(self, request: HighLevelQueryRequest) -> RecallResponse:
        return self._high_level_query(LIST_SUBJECT_MEMORIES_PATH, request)

    def export_subject(self, request: HighLevelTransferRequest) -> ExportResponse:
        return ExportResponse.from_wire(self.transport.post(EXPORT_SUBJECT_PATH, request.to_wire()))

    def import_subject(self, request: HighLevelTransferRequest) -> ImportResponse:
        return ImportResponse.from_wire(self.transport.post(IMPORT_SUBJECT_PATH, request.to_wire()))

    def create_memory_subject(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return self._high_level_write(CREATE_MEMORY_SUBJECT_PATH, request)

    def create_relationship_space(
        self, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return self._high_level_write(CREATE_RELATIONSHIP_SPACE_PATH, request)

    def get_continuity_profile(self, request: HighLevelQueryRequest) -> RecallResponse:
        return self._high_level_query(GET_CONTINUITY_PROFILE_PATH, request)

    def update_configured_role(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(UPDATE_CONFIGURED_ROLE_PATH, request)

    def migrate_agent_runtime(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(MIGRATE_AGENT_RUNTIME_PATH, request)

    def publish_to_shared_memory(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(PUBLISH_TO_SHARED_MEMORY_PATH, request)

    def revoke_shared_memory(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(REVOKE_SHARED_MEMORY_PATH, request)

    def ingest_artifact(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return self._high_level_write(INGEST_ARTIFACT_PATH, request)

    def attach_artifact_to_episode(
        self, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return self._high_level_write(ATTACH_ARTIFACT_TO_EPISODE_PATH, request)

    def add_derived_representation(
        self, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return self._high_level_write(ADD_DERIVED_REPRESENTATION_PATH, request)

    def add_evidence_selector(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return self._high_level_write(ADD_EVIDENCE_SELECTOR_PATH, request)

    def get_artifact_metadata(self, request: HighLevelQueryRequest) -> RecallResponse:
        return self._high_level_query(GET_ARTIFACT_METADATA_PATH, request)

    def delete_artifact_lineage(self, request: HighLevelControlRequest) -> MutationResponse:
        return self._high_level_control(DELETE_ARTIFACT_LINEAGE_PATH, request)


class AsyncContextDbClient:
    """Async facade using a worker thread for the dependency-free transport."""

    def __init__(self, client: ContextDbClient) -> None:
        self.sync = client

    @classmethod
    def http(cls, base_url: str, **kwargs: Any) -> AsyncContextDbClient:
        return cls(ContextDbClient.http(base_url, **kwargs))

    async def observe(self, request: ObserveRequest) -> ObserveResponse:
        return await asyncio.to_thread(self.sync.observe, request)

    async def ingest_frame(self, request: IngestFrame) -> IngestAck:
        return await asyncio.to_thread(self.sync.ingest_frame, request)

    async def correct(self, request: CorrectRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.correct, request)

    async def forget(self, request: ForgetRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.forget, request)

    async def recall(self, request: RecallRequest) -> RecallResponse:
        return await asyncio.to_thread(self.sync.recall, request)

    async def compile_context(self, request: CompileContextRequest) -> CompileContextResponse:
        return await asyncio.to_thread(self.sync.compile_context, request)

    async def explain_recall(self, request: ExplainRecallRequest) -> RecallTrace:
        return await asyncio.to_thread(self.sync.explain_recall, request)

    async def subscribe(self, request: SubscribeRequest) -> SubscriptionPage:
        return await asyncio.to_thread(self.sync.subscribe, request)

    async def get_node(self, request: GetMemoryRequest) -> MemoryRecord:
        return await asyncio.to_thread(self.sync.get_node, request)

    async def traverse(self, request: TraverseRequest) -> TraverseResponse:
        return await asyncio.to_thread(self.sync.traverse, request)

    async def get_timeline(self, request: GetTimelineRequest) -> TimelineResponse:
        return await asyncio.to_thread(self.sync.get_timeline, request)

    async def get_evidence(self, request: GetMemoryRequest) -> MemoryRecord:
        return await asyncio.to_thread(self.sync.get_evidence, request)

    async def get_conflict(self, request: GetMemoryRequest) -> MemoryRecord:
        return await asyncio.to_thread(self.sync.get_conflict, request)

    async def bootstrap(self, request: RuntimeRequest) -> RuntimeResponse:
        return await asyncio.to_thread(self.sync.bootstrap, request)

    async def preflight(self, request: RuntimeRequest) -> RuntimeResponse:
        return await asyncio.to_thread(self.sync.preflight, request)

    async def postflight(self, request: RuntimeRequest) -> RuntimeResponse:
        return await asyncio.to_thread(self.sync.postflight, request)

    async def checkpoint(self, request: RuntimeRequest) -> RuntimeResponse:
        return await asyncio.to_thread(self.sync.checkpoint, request)

    async def resume(self, request: RuntimeRequest) -> RuntimeResponse:
        return await asyncio.to_thread(self.sync.resume, request)

    async def handoff(self, request: RuntimeRequest) -> RuntimeResponse:
        return await asyncio.to_thread(self.sync.handoff, request)

    async def consolidate(self, request: MaintenanceRequest) -> MaintenanceResponse:
        return await asyncio.to_thread(self.sync.consolidate, request)

    async def reflect(self, request: MaintenanceRequest) -> MaintenanceResponse:
        return await asyncio.to_thread(self.sync.reflect, request)

    async def reindex(self, request: MaintenanceRequest) -> MaintenanceResponse:
        return await asyncio.to_thread(self.sync.reindex, request)

    async def compact(self, request: MaintenanceRequest) -> MaintenanceResponse:
        return await asyncio.to_thread(self.sync.compact, request)

    async def get_status(self, request: GetStatusRequest) -> StatusResponse:
        return await asyncio.to_thread(self.sync.get_status, request)

    async def create_backup(self, request: CreateBackupRequest) -> BackupResponse:
        return await asyncio.to_thread(self.sync.create_backup, request)

    async def restore_backup(self, request: RestoreBackupRequest) -> RestoreBackupResponse:
        return await asyncio.to_thread(self.sync.restore_backup, request)

    async def migrate_format(self, request: MigrateFormatRequest) -> StatusResponse:
        return await asyncio.to_thread(self.sync.migrate_format, request)

    async def export_archive(self, request: ExportRequest) -> ExportResponse:
        return await asyncio.to_thread(self.sync.export_archive, request)

    async def import_archive(self, request: ImportRequest) -> ImportResponse:
        return await asyncio.to_thread(self.sync.import_archive, request)

    async def verify(self, request: VerifyRequest) -> VerifyResponse:
        return await asyncio.to_thread(self.sync.verify, request)

    async def begin_session(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.begin_session, request)

    async def before_turn(self, request: HighLevelQueryRequest) -> RecallResponse:
        return await asyncio.to_thread(self.sync.before_turn, request)

    async def after_turn(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.after_turn, request)

    async def resolve_referent(self, request: HighLevelQueryRequest) -> RecallResponse:
        return await asyncio.to_thread(self.sync.resolve_referent, request)

    async def recall_shared_history(self, request: HighLevelQueryRequest) -> RecallResponse:
        return await asyncio.to_thread(self.sync.recall_shared_history, request)

    async def end_session(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.end_session, request)

    async def bootstrap_subject(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.bootstrap_subject, request)

    async def remember(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.remember, request)

    async def pin(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.pin, request)

    async def suppress(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.suppress, request)

    async def change_audience(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.change_audience, request)

    async def change_retention(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.change_retention, request)

    async def explain_memory(self, request: HighLevelQueryRequest) -> RecallResponse:
        return await asyncio.to_thread(self.sync.explain_memory, request)

    async def list_subject_memories(self, request: HighLevelQueryRequest) -> RecallResponse:
        return await asyncio.to_thread(self.sync.list_subject_memories, request)

    async def export_subject(self, request: HighLevelTransferRequest) -> ExportResponse:
        return await asyncio.to_thread(self.sync.export_subject, request)

    async def import_subject(self, request: HighLevelTransferRequest) -> ImportResponse:
        return await asyncio.to_thread(self.sync.import_subject, request)

    async def create_memory_subject(
        self, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.create_memory_subject, request)

    async def create_relationship_space(
        self, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.create_relationship_space, request)

    async def get_continuity_profile(self, request: HighLevelQueryRequest) -> RecallResponse:
        return await asyncio.to_thread(self.sync.get_continuity_profile, request)

    async def update_configured_role(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.update_configured_role, request)

    async def migrate_agent_runtime(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.migrate_agent_runtime, request)

    async def publish_to_shared_memory(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.publish_to_shared_memory, request)

    async def revoke_shared_memory(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.revoke_shared_memory, request)

    async def ingest_artifact(self, request: HighLevelWriteRequest) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.ingest_artifact, request)

    async def attach_artifact_to_episode(
        self, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.attach_artifact_to_episode, request)

    async def add_derived_representation(
        self, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.add_derived_representation, request)

    async def add_evidence_selector(
        self, request: HighLevelWriteRequest
    ) -> HighLevelMutationResponse:
        return await asyncio.to_thread(self.sync.add_evidence_selector, request)

    async def get_artifact_metadata(self, request: HighLevelQueryRequest) -> RecallResponse:
        return await asyncio.to_thread(self.sync.get_artifact_metadata, request)

    async def delete_artifact_lineage(self, request: HighLevelControlRequest) -> MutationResponse:
        return await asyncio.to_thread(self.sync.delete_artifact_lineage, request)
