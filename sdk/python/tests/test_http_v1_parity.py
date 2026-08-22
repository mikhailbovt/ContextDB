from __future__ import annotations

import asyncio
import io
import json
import re
import unittest
import urllib.parse
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from contextdb import (
    CANDIDATE_RUNTIME_CAPABILITY_IDS_V1,
    AccessPolicy,
    AuthenticatedChannel,
    AuthenticatedRequestContext,
    Capability,
    CompileContextPlan,
    CompileContextRequest,
    Compression,
    Consent,
    ContextBudgets,
    CorrectRequest,
    CreateBackupRequest,
    DomainTimeRange,
    ExplainRecallRequest,
    ExportRequest,
    ForgetMode,
    ForgetRequest,
    GetMemoryRequest,
    GetStatusRequest,
    GetTimelineRequest,
    HeaderProviderRequest,
    HighLevelControlRequest,
    HighLevelQueryRequest,
    HighLevelTransferRequest,
    HighLevelWriteRequest,
    ImportRequest,
    IngestAck,
    IngestFrame,
    IngestFrameKind,
    IngestFrameValue,
    InstructionHierarchy,
    MaintenanceRequest,
    MemoryDocument,
    MemoryEventKind,
    MemoryLifecycle,
    MemoryLinks,
    MemoryRecordKind,
    MigrateFormatRequest,
    ModelProfile,
    ObserveRequest,
    PackPurpose,
    PositionProfile,
    RecallIntent,
    RecallLimits,
    RecallMode,
    RecallRequest,
    RendererKind,
    RequestContext,
    RequestSignature,
    RestoreBackupRequest,
    RuntimeRequest,
    Sensitivity,
    SourceRevisionManifest,
    StructuredFormat,
    SubscribeRequest,
    TraverseDirection,
    TraverseRequest,
    VerifyRequest,
)
from contextdb.client import ROUTES, AsyncContextDbClient, ContextDbClient, HttpTransport
from contextdb.errors import ProtocolError, TransportError


def request_context() -> RequestContext:
    return RequestContext(
        "request-1",
        "workspace-1",
        "subject-1",
        frozenset({"team"}),
        frozenset({"project"}),
        "assistant",
        Sensitivity.PRIVATE,
    )


def access_policy() -> AccessPolicy:
    return AccessPolicy(
        "workspace-1",
        frozenset({"project"}),
        frozenset({"subject-1"}),
        frozenset({"team"}),
        {"team": frozenset({"assistant"})},
        frozenset(),
        Sensitivity.PRIVATE,
        Consent.GRANTED,
        True,
    )


def authenticated_context() -> AuthenticatedRequestContext:
    return AuthenticatedRequestContext(
        request_context(),
        "actor-1",
        "agent-1",
        "session-1",
        frozenset(Capability),
        AuthenticatedChannel("channel-1", "actor-1", "a" * 64),
    )


def context_pack_request() -> CompileContextRequest:
    context = replace(
        authenticated_context(),
        request=replace(request_context(), purpose="conversation"),
        capability_grants=frozenset({Capability.RECALL}),
    )
    return CompileContextRequest(
        context,
        CompileContextPlan(
            "018f47b8-3158-7ad8-9227-63fc6f711e5f",
            "What should the assistant remember?",
            RecallMode.REQUIRED,
            RecallIntent.CURRENT_TRUTH,
            PackPurpose.CONVERSATION,
            None,
            0,
            (),
            RecallLimits(128, 64, 2, 64, 32, 2048, 5_000_000),
            ContextBudgets(2048, 1024, 32, 32, 512, 512, 512, 262144, 128),
            ModelProfile(
                "model:local-test",
                "reference",
                "contextdb.reference-tokenizer.v1",
                RendererKind.COMPACT,
                4096,
                1024,
                StructuredFormat.COMPACT_TEXT,
                False,
                False,
                False,
                PositionProfile.SMALL_MODEL_EXPLICIT,
                InstructionHierarchy.SINGLE_PROMPT_DELIMITED,
                32,
                False,
            ),
            True,
            False,
            False,
            True,
            0,
            False,
            None,
            None,
        ),
    )


def document() -> MemoryDocument:
    return MemoryDocument(
        "memory-1",
        MemoryRecordKind.NODE,
        access_policy(),
        DomainTimeRange(-1, None),
        MemoryLifecycle.ACTIVE,
        MemoryLinks(),
        {"text": "hello"},
        "hello",
        (0.25, 0.5),
        {"source": "test"},
    )


def watermarks() -> dict[str, int]:
    return {"journal": 7, "semantic": 7, "lexical": 7, "vector": 7, "graph": 7}


def record_wire() -> dict[str, Any]:
    return {
        "document": document().to_wire(),
        "revision": 1,
        "transaction_from": 7,
        "transaction_to": None,
    }


class ParityTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def post(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append((path, body))
        if path == ROUTES["observe"]:
            return {
                "commit_seq": 7,
                "replayed": False,
                "request_digest": "digest",
                "watermarks": watermarks(),
            }
        if path in {ROUTES["correct"], ROUTES["forget"]}:
            return {
                "commit_seq": 7,
                "replayed": False,
                "request_digest": "digest",
                "watermarks": watermarks(),
            }
        if path == ROUTES["ingest_frame"]:
            return {
                "stream_id": "stream-1",
                "position": 0,
                "disposition": "accepted",
                "frame_digest": "frame",
                "resume_cursor": "cursor",
                "commit_seq": None,
                "partial_result_refs": [],
            }
        if path == ROUTES["recall"]:
            return {"hits": [], "trace": trace_wire(), "continuation": None}
        if path == ROUTES["compile_context"]:
            fixture = cast(
                dict[str, Mapping[str, Any]],
                json.loads(
                    (Path(__file__).parents[2] / "fixtures" / "context_pack_v1.json").read_text(
                        encoding="utf-8"
                    )
                ),
            )
            return fixture["response"]
        if path == ROUTES["explain_recall"]:
            return trace_wire()
        if path == ROUTES["subscribe"]:
            return {
                "events": [
                    {
                        "event_id": "event-1",
                        "commit_seq": 7,
                        "ordinal": 0,
                        "kind": "record_changed",
                        "object_refs": ["memory-1"],
                        "attributes": {},
                    }
                ],
                "resume_cursor": "cursor",
                "caught_up": True,
            }
        if path in {ROUTES["get_node"], ROUTES["get_evidence"], ROUTES["get_conflict"]}:
            return record_wire()
        if path == ROUTES["traverse"]:
            return {
                "node_ids": ["memory-1"],
                "snapshot_seq": 7,
                "authorized_candidates": 1,
                "watermarks": watermarks(),
            }
        if path == ROUTES["get_timeline"]:
            return {"revisions": [record_wire()], "snapshot_seq": 7, "watermarks": watermarks()}
        if path in {
            ROUTES[name]
            for name in ("bootstrap", "preflight", "postflight", "checkpoint", "resume", "handoff")
        }:
            return {"operation_id": "operation-1", "payload": {"ok": True}}
        if path in {ROUTES[name] for name in ("consolidate", "reflect", "reindex", "compact")}:
            return {"operation_id": "operation-1", "payload": {"ok": True}}
        if path in {ROUTES["get_status"], ROUTES["migrate_format"]}:
            return {
                "schema_version": 1,
                "profile": "reference",
                "commit_seq": 7,
                "watermarks": watermarks(),
                "capability_manifest": {
                    "schema_version": 1,
                    "profile": "reference",
                    "server_v1_release_ready": False,
                    "capabilities": {
                        "background_semantic_adjudication": "unsupported",
                        "candidate_hierarchy_dag": "unsupported",
                        "consolidate": "unsupported",
                        "hard_delete": "unsupported",
                        "native_graph_store": "unsupported",
                        "observation_semantic_extraction": "unsupported",
                        "policy_first_candidate_recall": "unsupported",
                        "policy_first_candidate_traversal": "unsupported",
                        "quarantined_memory_proposals": "unsupported",
                        "reflect": "unsupported",
                        "status": "available",
                    },
                },
            }
        if path in {ROUTES["create_backup"], ROUTES["export_archive"]}:
            return {
                "format": "contextdb-logical-v1",
                "bytes": [0, 127, 255],
                "digest": "archive",
                "commit_seq": 7,
            }
        if path in {ROUTES["restore_backup"], ROUTES["import_archive"]}:
            return {"commit_seq": 7, "watermarks": watermarks()}
        if path == ROUTES["verify"]:
            return {"valid": True, "commit_seq": 7, "archive_digest": "archive"}
        high = json.loads(
            (
                Path(__file__).parents[3]
                / "crates/contextdb-conformance/tests/fixtures/high_level_v1_surface.json"
            ).read_text(encoding="utf-8")
        )["http_routes"]
        spec = high.get(path)
        if spec is not None:
            if spec["response"] == "high_level_mutation":
                return {
                    "operation": spec["operation"],
                    "logical_id": "logical-1",
                    "policy_result": "accepted",
                    "semantic_status": "pending",
                    "receipt": {
                        "commit_seq": 7,
                        "replayed": False,
                        "request_digest": "digest",
                        "watermarks": watermarks(),
                    },
                }
            if spec["response"] == "recall":
                return {"hits": [], "trace": trace_wire(), "continuation": None}
            if spec["response"] == "mutation":
                return {
                    "commit_seq": 7,
                    "replayed": False,
                    "request_digest": "digest",
                    "watermarks": watermarks(),
                }
            if spec["response"] == "export":
                return {
                    "format": "contextdb-subject-v1",
                    "bytes": [],
                    "digest": "digest",
                    "commit_seq": 7,
                }
            if spec["response"] == "import":
                return {"commit_seq": 7, "watermarks": watermarks()}
        raise AssertionError(path)


def trace_wire() -> dict[str, Any]:
    return {
        "trace_id": "trace",
        "snapshot_seq": 7,
        "operation": "lexical",
        "authorized_candidates": 0,
        "selected_ids": [],
        "watermarks": watermarks(),
    }


def request_set() -> dict[str, Any]:
    auth = authenticated_context()
    runtime = RuntimeRequest(auth, "operation-1", {"input": True})
    maintenance = MaintenanceRequest(auth, "operation-1", {"input": True})
    get = GetMemoryRequest(auth, "memory-1", None)
    exported = b"\x00\x7f\xff"
    high_write = HighLevelWriteRequest(
        auth,
        "key",
        "subject-1",
        "session-1",
        "logical-1",
        access_policy(),
        {"text": "hi"},
        frozenset(),
    )
    high_query = HighLevelQueryRequest(auth, "subject-1", "cue", 20)
    high_control = HighLevelControlRequest(auth, "key", "subject-1", "target-1", {})
    high_transfer = HighLevelTransferRequest(
        auth, "key", "subject-1", "contextdb-subject-v1", b"", ""
    )
    return {
        "observe": ObserveRequest(
            request_context(), "key", "observation-1", {}, {"text": "hi"}, access_policy()
        ),
        "ingest_frame": IngestFrame(
            auth,
            "stream-1",
            0,
            None,
            IngestFrameValue(
                IngestFrameKind.MANIFEST,
                SourceRevisionManifest(
                    "source-1", "revision-1", "snapshot-1", 0, "digest", Compression.IDENTITY, {}
                ),
            ),
        ),
        "correct": CorrectRequest(auth, "key", "memory-0", document()),
        "forget": ForgetRequest(auth, "key", "memory-1", ForgetMode.RETRACT, "requested"),
        "recall": RecallRequest(request_context(), "hello", 20),
        "compile_context": context_pack_request(),
        "subscribe": SubscribeRequest(auth, frozenset({MemoryEventKind.RECORD_CHANGED}), None, 20),
        "get": get,
        "timeline": GetTimelineRequest(auth, "memory-1", MemoryRecordKind.NODE, None, 20),
        "traverse": TraverseRequest(
            auth, ("memory-1",), TraverseDirection.BOTH, frozenset(), 2, 20, None
        ),
        "runtime": runtime,
        "maintenance": maintenance,
        "status": GetStatusRequest(auth),
        "backup": CreateBackupRequest(auth),
        "restore": RestoreBackupRequest(auth, "contextdb-logical-v1", exported, "archive"),
        "migrate": MigrateFormatRequest(auth, "contextdb-logical-v1", "operation-1"),
        "export": ExportRequest(request_context()),
        "import": ImportRequest(request_context(), "contextdb-logical-v1", exported, "archive"),
        "verify": VerifyRequest(request_context(), True),
        "high_write": high_write,
        "high_query": high_query,
        "high_control": high_control,
        "high_transfer": high_transfer,
    }


def call_sync(client: ContextDbClient) -> None:
    values = request_set()
    observed = client.observe(values["observe"])
    client.ingest_frame(values["ingest_frame"])
    client.correct(values["correct"])
    client.forget(values["forget"])
    recalled = client.recall(values["recall"])
    client.compile_context(values["compile_context"])
    client.explain_recall(ExplainRecallRequest(request_context(), recalled.trace))
    client.subscribe(values["subscribe"])
    client.get_node(values["get"])
    client.traverse(values["traverse"])
    client.get_timeline(values["timeline"])
    client.get_evidence(values["get"])
    client.get_conflict(values["get"])
    for name in ("bootstrap", "preflight", "postflight", "checkpoint", "resume", "handoff"):
        getattr(client, name)(values["runtime"])
    for name in ("consolidate", "reflect", "reindex", "compact"):
        getattr(client, name)(values["maintenance"])
    client.get_status(values["status"])
    client.create_backup(values["backup"])
    client.restore_backup(values["restore"])
    client.migrate_format(values["migrate"])
    client.export_archive(values["export"])
    client.import_archive(values["import"])
    client.verify(values["verify"])
    high_calls = (
        ("begin_session", "high_write"),
        ("before_turn", "high_query"),
        ("after_turn", "high_write"),
        ("resolve_referent", "high_query"),
        ("recall_shared_history", "high_query"),
        ("end_session", "high_write"),
        ("bootstrap_subject", "high_write"),
        ("remember", "high_write"),
        ("pin", "high_control"),
        ("suppress", "high_control"),
        ("change_audience", "high_control"),
        ("change_retention", "high_control"),
        ("explain_memory", "high_query"),
        ("list_subject_memories", "high_query"),
        ("export_subject", "high_transfer"),
        ("import_subject", "high_transfer"),
        ("create_memory_subject", "high_write"),
        ("create_relationship_space", "high_write"),
        ("get_continuity_profile", "high_query"),
        ("update_configured_role", "high_control"),
        ("migrate_agent_runtime", "high_control"),
        ("publish_to_shared_memory", "high_control"),
        ("revoke_shared_memory", "high_control"),
        ("ingest_artifact", "high_write"),
        ("attach_artifact_to_episode", "high_write"),
        ("add_derived_representation", "high_write"),
        ("add_evidence_selector", "high_write"),
        ("get_artifact_metadata", "high_query"),
        ("delete_artifact_lineage", "high_control"),
    )
    for name, request_name in high_calls:
        getattr(client, name)(values[request_name])
    if observed.commit_seq != 7:
        raise AssertionError("unexpected observation")


class HttpV1ParityTests(unittest.TestCase):
    def test_ingest_ack_lease_deadline_is_additive_and_u64_bounded(self) -> None:
        legacy_wire: dict[str, Any] = {
            "stream_id": "stream-1",
            "position": 0,
            "disposition": "accepted",
            "frame_digest": "frame",
            "resume_cursor": "cursor",
            "commit_seq": None,
            "partial_result_refs": [],
        }
        legacy = IngestAck.from_wire(legacy_wire)
        self.assertIsNone(legacy.lease_expires_at_ms)

        maximum = (1 << 64) - 1
        leased = IngestAck.from_wire({**legacy_wire, "lease_expires_at_ms": maximum})
        self.assertEqual(leased.lease_expires_at_ms, maximum)

        for invalid in (-1, 1 << 64, True, None):
            with self.subTest(invalid=invalid), self.assertRaises(ProtocolError):
                IngestAck.from_wire({**legacy_wire, "lease_expires_at_ms": invalid})
        with self.assertRaises(ProtocolError):
            IngestAck.from_wire({**legacy_wire, "unexpected": 1})

    def test_high_level_header_provider_receives_exact_fresh_wire_bytes(self) -> None:
        values = request_set()
        surface = json.loads(
            (
                Path(__file__).parents[3]
                / "crates/contextdb-conformance/tests/fixtures/high_level_v1_surface.json"
            ).read_text(encoding="utf-8")
        )["http_routes"]
        provider_bodies: list[bytes] = []
        sent_bodies: list[bytes] = []

        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __init__(self, body: bytes) -> None:
                self._body = io.BytesIO(body)

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                return self._body.read(size)

        def provider(request: HeaderProviderRequest) -> Mapping[str, str]:
            self.assertEqual(request.path, list(surface)[len(provider_bodies)])
            provider_bodies.append(request.body)
            return {
                "x-contextdb-gateway-id": "gateway-1",
                "x-contextdb-gateway-attestation": f"fresh-{len(provider_bodies)}",
            }

        def opener(request: Any, _: float) -> Response:
            path = urllib.parse.urlsplit(request.full_url).path
            sent_bodies.append(request.data)
            spec = surface[path]
            if spec["response"] == "high_level_mutation":
                body: Mapping[str, Any] = {
                    "operation": spec["operation"],
                    "logical_id": "logical-1",
                    "policy_result": "accepted",
                    "semantic_status": "pending",
                    "receipt": {
                        "commit_seq": 7,
                        "replayed": False,
                        "request_digest": "digest",
                        "watermarks": watermarks(),
                    },
                }
            elif spec["response"] == "recall":
                body = {"hits": [], "trace": trace_wire(), "continuation": None}
            elif spec["response"] == "mutation":
                body = {
                    "commit_seq": 7,
                    "replayed": False,
                    "request_digest": "digest",
                    "watermarks": watermarks(),
                }
            elif spec["response"] == "export":
                body = {
                    "format": "contextdb-subject-v1",
                    "bytes": [],
                    "digest": "digest",
                    "commit_seq": 7,
                }
            else:
                body = {"commit_seq": 7, "watermarks": watermarks()}
            return Response(json.dumps(body, separators=(",", ":")).encode())

        client = ContextDbClient(
            HttpTransport("https://contextdb.invalid", header_provider=provider, opener=opener)
        )
        request_by_kind = {
            "high_level_write": values["high_write"],
            "high_level_query": values["high_query"],
            "high_level_control": values["high_control"],
            "high_level_transfer": values["high_transfer"],
        }
        path_to_method = {path: name for name, path in ROUTES.items()}
        for path, spec in surface.items():
            getattr(client, path_to_method[path])(request_by_kind[spec["request"]])
        self.assertEqual(provider_bodies, sent_bodies)
        self.assertEqual(len(provider_bodies), 29)

    def test_sync_client_exercises_every_shared_route_and_exact_auth_body(self) -> None:
        transport = ParityTransport()
        call_sync(ContextDbClient(transport))
        self.assertEqual([path for path, _ in transport.calls], list(ROUTES.values()))
        ingest_body = transport.calls[1][1]
        self.assertEqual(ingest_body["context"], authenticated_context().to_wire())
        self.assertNotIn("x-contextdb-gateway-attestation", json.dumps(ingest_body))
        restore_body = transport.calls[25][1]
        self.assertEqual(restore_body["bytes"], [0, 127, 255])

    def test_shared_fixture_is_exact_and_documents_unexposed_surfaces(self) -> None:
        fixture = json.loads(
            (Path(__file__).parents[2] / "fixtures" / "http_v1_contract.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(fixture["routes"], ROUTES)
        self.assertEqual(
            tuple(fixture["candidate_runtime_capability_ids_v1"]),
            CANDIDATE_RUNTIME_CAPABILITY_IDS_V1,
        )
        self.assertEqual(len(fixture["routes"]), 59)
        legacy = set(fixture["legacy_request_context_routes"])
        authenticated = set(fixture["authenticated_context_routes"])
        attested = set(fixture["gateway_attestation_routes"])
        health = fixture["unauthenticated_non_sdk_routes"]
        self.assertFalse(legacy & authenticated)
        self.assertEqual(legacy | authenticated, set(ROUTES))
        self.assertEqual(attested, set(ROUTES))
        self.assertEqual(
            fixture["gateway_attestation_binding"],
            {
                "protocol": "v2 exact request; no legacy fallback",
                "transport": "http",
                "operation": "POST plus exact route path",
                "body": "exact serialized JSON bytes",
                "freshness": "issued/expires window with bounded clock skew",
                "replay": "unique 128-bit nonce consumed atomically",
            },
        )
        self.assertEqual(set(health), {"liveness", "readiness"})
        self.assertEqual(
            {(route["method"], route["path"]) for route in health.values()},
            {("GET", "/health/live"), ("GET", "/health/ready")},
        )
        self.assertTrue(fixture["health_boundary"]["content_free"])
        self.assertFalse(fixture["health_boundary"]["sdk_exposed"])
        self.assertFalse(fixture["health_boundary"]["gateway_attestation_required"])
        self.assertFalse(fixture["health_boundary"]["rfc_31_15_complete"])
        self.assertFalse(fixture["health_boundary"]["server_v1_profile_proven"])
        high_level = json.loads(
            (
                Path(__file__).parents[3]
                / "crates/contextdb-conformance/tests/fixtures/high_level_v1_surface.json"
            ).read_text(encoding="utf-8")
        )["http_routes"]
        inverse = {path: name for name, path in ROUTES.items()}
        self.assertEqual(
            set(high_level),
            set(list(ROUTES.values())[-fixture["high_level_surface"]["route_count"] :]),
        )
        for path, spec in high_level.items():
            operation = inverse[path]
            for capability in spec["capabilities"]:
                self.assertIn(operation, fixture["capability_routes"][capability])
        self.assertEqual(
            fixture["unexposed_service_operations"],
            {"observe_batch": "embedded trait convenience only; no HTTP route"},
        )
        self.assertEqual(fixture["authenticated_context"], authenticated_context().to_wire())
        self.assertEqual(
            fixture["request_signature_evidence"],
            RequestSignature("ed25519", "key-1", "b" * 128, "c" * 64).to_wire(),
        )
        router_source = (
            Path(__file__).parents[3] / "crates" / "contextdb-server" / "src" / "http.rs"
        ).read_text(encoding="utf-8")
        registered = re.findall(r'\.route\(\s*"([^"]+)"', router_source)
        expected_registered = set(ROUTES.values()) | {route["path"] for route in health.values()}
        self.assertEqual(set(registered), expected_registered)
        self.assertEqual(len(registered), len(expected_registered))

    def test_header_provider_is_per_request_and_canonical_headers_win(self) -> None:
        captured: dict[str, Any] = {}
        provider_calls = 0

        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __init__(self) -> None:
                self._body = io.BytesIO(b'{"valid":true,"commit_seq":0,"archive_digest":null}')

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                return self._body.read(size)

        def provider(request: HeaderProviderRequest) -> Mapping[str, str]:
            nonlocal provider_calls
            provider_calls += 1
            body = json.loads(request.body)
            captured["provider"] = (request.path, body["deep"])
            captured.setdefault("provider_bodies", []).append(request.body)
            return {
                "x-contextdb-gateway-id": "gateway-1",
                "x-contextdb-gateway-attestation": f"ephemeral-{provider_calls}",
                "Content-Type": "text/plain",
            }

        def opener(request: Any, _: float) -> Response:
            captured.setdefault("headers", []).append(dict(request.header_items()))
            captured.setdefault("wire_bodies", []).append(request.data)
            return Response()

        transport = HttpTransport(
            "https://contextdb.invalid", header_provider=provider, opener=opener
        )
        transport.post(ROUTES["verify"], {"context": request_context().to_wire(), "deep": True})
        transport.post(ROUTES["verify"], {"context": request_context().to_wire(), "deep": True})
        self.assertEqual(captured["provider"], (ROUTES["verify"], True))
        self.assertEqual(captured["provider_bodies"], captured["wire_bodies"])
        self.assertEqual(
            [item["X-contextdb-gateway-attestation"] for item in captured["headers"]],
            ["ephemeral-1", "ephemeral-2"],
        )
        self.assertEqual(captured["headers"][0]["Content-type"], "application/json")

    def test_authenticated_dto_does_not_derive_gateway_headers_and_provider_fails_closed(
        self,
    ) -> None:
        sent: list[dict[str, str]] = []

        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __init__(self) -> None:
                self._body = io.BytesIO(
                    b'{"stream_id":"stream-1","position":0,"disposition":"accepted",'
                    b'"frame_digest":"frame","resume_cursor":"cursor","commit_seq":null,'
                    b'"partial_result_refs":[]}'
                )

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def read(self, size: int = -1) -> bytes:
                return self._body.read(size)

        def opener(request: Any, _: float) -> Response:
            sent.append({key.lower(): value for key, value in request.header_items()})
            return Response()

        values = request_set()
        ContextDbClient(HttpTransport("https://contextdb.invalid", opener=opener)).ingest_frame(
            values["ingest_frame"]
        )
        self.assertNotIn("x-contextdb-gateway-id", sent[0])
        self.assertNotIn("x-contextdb-gateway-attestation", sent[0])

        attempted_send = False

        def must_not_send(_: Any, __: float) -> Response:
            nonlocal attempted_send
            attempted_send = True
            return Response()

        def fail_provider(_: HeaderProviderRequest) -> Mapping[str, str]:
            raise RuntimeError("no attestation")

        failing = HttpTransport(
            "https://contextdb.invalid",
            header_provider=fail_provider,
            opener=must_not_send,
        )
        with self.assertRaises(TransportError):
            failing.post(ROUTES["ingest_frame"], values["ingest_frame"].to_wire())
        self.assertFalse(attempted_send)

    def test_new_nested_responses_fail_closed(self) -> None:
        from contextdb import MemoryRecord, StatusResponse, SubscriptionPage

        bad_record = record_wire()
        bad_record["document"] = {**bad_record["document"], "secret": "leak"}
        with self.assertRaises(ProtocolError):
            MemoryRecord.from_wire(bad_record)
        with self.assertRaises(ProtocolError):
            SubscriptionPage.from_wire(
                {"events": [], "resume_cursor": "x", "caught_up": True, "extra": 1}
            )
        status: dict[str, Any] = {
            "schema_version": 1,
            "profile": "reference",
            "commit_seq": 1,
            "watermarks": watermarks(),
            "capability_manifest": {
                "schema_version": 1,
                "profile": "different-profile",
                "server_v1_release_ready": False,
                "capabilities": {"status": "available"},
            },
        }
        with self.assertRaises(ProtocolError):
            StatusResponse.from_wire(status)
        status["capability_manifest"]["profile"] = "reference"
        status["capability_manifest"]["capabilities"]["status"] = "maybe"
        with self.assertRaises(ProtocolError):
            StatusResponse.from_wire(status)


class AsyncHttpV1ParityTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_client_exposes_every_route(self) -> None:
        transport = ParityTransport()
        client = AsyncContextDbClient(ContextDbClient(transport))
        values = request_set()
        recalled = await client.recall(values["recall"])
        calls = [
            client.observe(values["observe"]),
            client.ingest_frame(values["ingest_frame"]),
            client.correct(values["correct"]),
            client.forget(values["forget"]),
            client.compile_context(values["compile_context"]),
            client.explain_recall(ExplainRecallRequest(request_context(), recalled.trace)),
            client.subscribe(values["subscribe"]),
            client.get_node(values["get"]),
            client.traverse(values["traverse"]),
            client.get_timeline(values["timeline"]),
            client.get_evidence(values["get"]),
            client.get_conflict(values["get"]),
            client.bootstrap(values["runtime"]),
            client.preflight(values["runtime"]),
            client.postflight(values["runtime"]),
            client.checkpoint(values["runtime"]),
            client.resume(values["runtime"]),
            client.handoff(values["runtime"]),
            client.consolidate(values["maintenance"]),
            client.reflect(values["maintenance"]),
            client.reindex(values["maintenance"]),
            client.compact(values["maintenance"]),
            client.get_status(values["status"]),
            client.create_backup(values["backup"]),
            client.restore_backup(values["restore"]),
            client.migrate_format(values["migrate"]),
            client.export_archive(values["export"]),
            client.import_archive(values["import"]),
            client.verify(values["verify"]),
            client.begin_session(values["high_write"]),
            client.before_turn(values["high_query"]),
            client.after_turn(values["high_write"]),
            client.resolve_referent(values["high_query"]),
            client.recall_shared_history(values["high_query"]),
            client.end_session(values["high_write"]),
            client.bootstrap_subject(values["high_write"]),
            client.remember(values["high_write"]),
            client.pin(values["high_control"]),
            client.suppress(values["high_control"]),
            client.change_audience(values["high_control"]),
            client.change_retention(values["high_control"]),
            client.explain_memory(values["high_query"]),
            client.list_subject_memories(values["high_query"]),
            client.export_subject(values["high_transfer"]),
            client.import_subject(values["high_transfer"]),
            client.create_memory_subject(values["high_write"]),
            client.create_relationship_space(values["high_write"]),
            client.get_continuity_profile(values["high_query"]),
            client.update_configured_role(values["high_control"]),
            client.migrate_agent_runtime(values["high_control"]),
            client.publish_to_shared_memory(values["high_control"]),
            client.revoke_shared_memory(values["high_control"]),
            client.ingest_artifact(values["high_write"]),
            client.attach_artifact_to_episode(values["high_write"]),
            client.add_derived_representation(values["high_write"]),
            client.add_evidence_selector(values["high_write"]),
            client.get_artifact_metadata(values["high_query"]),
            client.delete_artifact_lineage(values["high_control"]),
        ]
        await asyncio.gather(*calls)
        self.assertEqual({path for path, _ in transport.calls}, set(ROUTES.values()))


if __name__ == "__main__":
    unittest.main()
