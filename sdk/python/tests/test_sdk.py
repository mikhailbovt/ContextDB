from __future__ import annotations

import asyncio
import concurrent.futures
import io
import json
import unittest
import urllib.error
from collections.abc import Mapping
from email.message import Message
from pathlib import Path
from typing import Any

from contextdb import (
    AccessPolicy,
    AgentSession,
    AsyncAgentSession,
    AsyncContextDbClient,
    Consent,
    ContextDbClient,
    ContextDbError,
    ExplainRecallRequest,
    ExportRequest,
    HttpTransport,
    ImportRequest,
    ObserveRequest,
    ProtocolError,
    RecallRequest,
    RequestContext,
    Sensitivity,
    VerifyRequest,
)
from contextdb.client import (
    EXPLAIN_RECALL_PATH,
    EXPORT_PATH,
    IMPORT_PATH,
    OBSERVE_PATH,
    RECALL_PATH,
    ROUTES,
    VERIFY_PATH,
)
from contextdb.errors import _ERROR_STATUS


def context(request_id: str = "request-1") -> RequestContext:
    return RequestContext(
        request_id=request_id,
        workspace_id="workspace-1",
        subject_id="subject-1",
        audiences=frozenset({"team", "subject:subject-1"}),
        scopes=frozenset({"project", "session:session-1"}),
        purpose="assistant",
        clearance=Sensitivity.PRIVATE,
    )


def access() -> AccessPolicy:
    return AccessPolicy(
        workspace_id="workspace-1",
        scopes=frozenset({"project", "session:session-1"}),
        owners=frozenset({"subject-1"}),
        audience=frozenset({"team"}),
        audience_purpose_grants={"team": frozenset({"assistant"})},
        purposes=frozenset(),
        sensitivity=Sensitivity.PRIVATE,
        consent=Consent.GRANTED,
        retrievable=True,
    )


def watermarks(value: int = 3) -> dict[str, int]:
    return {
        "journal": value,
        "semantic": value,
        "lexical": value,
        "vector": value,
        "graph": value,
    }


def trace() -> dict[str, Any]:
    return {
        "trace_id": "trace-1",
        "snapshot_seq": 3,
        "operation": "lexical",
        "authorized_candidates": 1,
        "selected_ids": ["memory-1"],
        "watermarks": watermarks(),
    }


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_observe = False

    def post(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append((path, dict(body)))
        if path == OBSERVE_PATH:
            if self.fail_observe:
                raise RuntimeError("injected failure")
            return {
                "commit_seq": 3,
                "replayed": False,
                "request_digest": "digest-1",
                "watermarks": watermarks(),
            }
        if path == RECALL_PATH:
            return {
                "hits": [{"id": "memory-1", "score": 0.75}],
                "trace": trace(),
                "continuation": "continuation-1",
            }
        if path == EXPLAIN_RECALL_PATH:
            return trace()
        if path == EXPORT_PATH:
            return {
                "format": "contextdb-logical-v1",
                "bytes": [0, 127, 255],
                "digest": "archive-digest",
                "commit_seq": 3,
            }
        if path == IMPORT_PATH:
            return {"commit_seq": 3, "watermarks": watermarks()}
        if path == VERIFY_PATH:
            return {"valid": True, "commit_seq": 3, "archive_digest": None}
        raise AssertionError(f"unexpected path: {path}")


class FakeResponse:
    def __init__(
        self,
        value: dict[str, Any],
        *,
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        self.status = status
        self.headers = {"Content-Type": content_type}
        self._body = io.BytesIO(json.dumps(value, separators=(",", ":")).encode())

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class ClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeTransport()
        self.client = ContextDbClient(self.transport)

    def test_all_canonical_routes_and_models(self) -> None:
        observe = self.client.observe(
            ObserveRequest(
                context=context(),
                idempotency_key="key-1",
                observation_id="observation-1",
                metadata={"source": "test"},
                content={"text": "hello"},
                access=access(),
            )
        )
        recall = self.client.recall(
            RecallRequest(context(), "hello", 20, at_commit=None, continuation=None)
        )
        explained = self.client.explain_recall(ExplainRecallRequest(context(), recall.trace))
        exported = self.client.export_archive(ExportRequest(context()))
        imported = self.client.import_archive(
            ImportRequest(context(), exported.format, exported.bytes, exported.digest)
        )
        verified = self.client.verify(VerifyRequest(context(), deep=True))

        self.assertEqual(observe.commit_seq, 3)
        self.assertEqual(recall.hits[0].id, "memory-1")
        self.assertEqual(explained.trace_id, "trace-1")
        self.assertEqual(exported.bytes, b"\x00\x7f\xff")
        self.assertEqual(imported.watermarks.graph, 3)
        self.assertTrue(verified.valid)
        self.assertEqual(
            [path for path, _ in self.transport.calls],
            [
                OBSERVE_PATH,
                RECALL_PATH,
                EXPLAIN_RECALL_PATH,
                EXPORT_PATH,
                IMPORT_PATH,
                VERIFY_PATH,
            ],
        )
        _, import_body = self.transport.calls[4]
        self.assertEqual(import_body["bytes"], [0, 127, 255])
        _, recall_body = self.transport.calls[1]
        self.assertIn("at_commit", recall_body)
        self.assertIsNone(recall_body["at_commit"])

    def test_unknown_response_field_fails_closed(self) -> None:
        value = {"valid": True, "commit_seq": 1, "archive_digest": None, "extra": 1}
        with self.assertRaises(ProtocolError):
            from contextdb import VerifyResponse

            VerifyResponse.from_wire(value)

    def test_non_finite_score_and_invalid_byte_rejected(self) -> None:
        from contextdb import ExportResponse, RecallHit, VerifyResponse

        with self.assertRaises(ProtocolError):
            RecallHit.from_wire({"id": "x", "score": float("nan")})
        with self.assertRaises(ProtocolError):
            RecallHit.from_wire({"id": "x", "score": 1e100})
        with self.assertRaises(ProtocolError):
            ExportResponse.from_wire(
                {"format": "x", "bytes": [256], "digest": "d", "commit_seq": 1}
            )
        with self.assertRaises(ProtocolError):
            VerifyResponse.from_wire({"valid": True, "commit_seq": 1 << 64, "archive_digest": None})
        self.assertEqual(
            VerifyResponse.from_wire(
                {"valid": True, "commit_seq": (1 << 64) - 1, "archive_digest": None}
            ).commit_seq,
            (1 << 64) - 1,
        )

    def test_shared_contract_fixture(self) -> None:
        fixture_path = Path(__file__).parents[2] / "fixtures" / "http_v1_contract.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(fixture["max_wire_bytes"], 16 * 1024 * 1024)
        self.assertEqual(fixture["routes"], ROUTES)
        self.assertEqual(fixture["error_statuses"], _ERROR_STATUS)


class HttpTransportTests(unittest.TestCase):
    def test_exact_json_headers_and_optional_bearer(self) -> None:
        captured: dict[str, Any] = {}

        def open_request(request: Any, timeout: float) -> FakeResponse:
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["body"] = json.loads(request.data)
            captured["timeout"] = timeout
            return FakeResponse({"valid": True, "commit_seq": 0, "archive_digest": None})

        transport = HttpTransport(
            "https://contextdb.invalid/root/",
            timeout=2.5,
            bearer_token="future-token",
            headers={"X-Tenant": "tenant-1"},
            opener=open_request,
        )
        value = transport.post(VERIFY_PATH, VerifyRequest(context(), False).to_wire())

        self.assertTrue(value["valid"])
        self.assertEqual(captured["url"], "https://contextdb.invalid/root/v1/verify")
        self.assertEqual(captured["headers"]["Content-type"], "application/json")
        self.assertEqual(captured["headers"]["Accept"], "application/json")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer future-token")
        self.assertEqual(captured["headers"]["X-tenant"], "tenant-1")
        self.assertEqual(captured["timeout"], 2.5)

    def test_canonical_error_preserves_optional_context(self) -> None:
        body = {
            "code": "permission_denied",
            "message": "denied",
            "retryable": False,
            "partial_result_refs": ["receipt-1"],
            "violated_policy": "policy-1",
            "safe_next_action": "request a narrower scope",
            "trace_id": "trace-error-1",
        }
        headers = Message()
        headers["Content-Type"] = "application/json"

        def fail(_: Any, __: float) -> Any:
            raise urllib.error.HTTPError(
                "https://contextdb.invalid/v1/recall",
                403,
                "Forbidden",
                headers,
                io.BytesIO(json.dumps(body).encode()),
            )

        transport = HttpTransport("https://contextdb.invalid", opener=fail)
        with self.assertRaises(ContextDbError) as caught:
            transport.post(RECALL_PATH, {})
        error = caught.exception
        self.assertEqual(error.partial_result_refs, ("receipt-1",))
        self.assertEqual(error.violated_policy, "policy-1")
        self.assertEqual(error.safe_next_action, "request a narrower scope")
        self.assertEqual(error.trace_id, "trace-error-1")

    def test_error_status_mismatch_and_unknown_field_fail_closed(self) -> None:
        with self.assertRaises(ProtocolError):
            ContextDbError.from_wire(
                {"code": "permission_denied", "message": "x", "retryable": False},
                409,
            )
        with self.assertRaises(ProtocolError):
            ContextDbError.from_wire(
                {
                    "code": "permission_denied",
                    "message": "x",
                    "retryable": False,
                    "secret": "must not leak through",
                },
                403,
            )

    def test_wire_limit_and_content_type_enforced(self) -> None:
        transport = HttpTransport(
            "https://contextdb.invalid",
            max_wire_bytes=2,
            opener=lambda *_: FakeResponse({}),
        )
        with self.assertRaises(ProtocolError):
            transport.post(VERIFY_PATH, {"too": "large"})

        transport = HttpTransport(
            "https://contextdb.invalid",
            opener=lambda *_: FakeResponse({}, content_type="text/plain"),
        )
        with self.assertRaises(ProtocolError):
            transport.post(VERIFY_PATH, {})

        response_limited = HttpTransport(
            "https://contextdb.invalid",
            max_wire_bytes=2,
            opener=lambda *_: FakeResponse({"x": 1}),
        )
        with self.assertRaises(ProtocolError):
            response_limited.post(VERIFY_PATH, {})

        invalid_request = HttpTransport(
            "https://contextdb.invalid",
            opener=lambda *_: FakeResponse({}),
        )
        with self.assertRaises(ProtocolError):
            invalid_request.post(VERIFY_PATH, {"score": float("nan")})

    def test_non_standard_json_constants_and_framing_headers_fail_closed(self) -> None:
        with self.assertRaises(ProtocolError):
            HttpTransport._decode(b'{"valid":NaN}', status=200)
        with self.assertRaises(ValueError):
            HttpTransport("https://contextdb.invalid", headers={"Content-Length": "1"})
        with self.assertRaises(ValueError):
            HttpTransport(
                "https://contextdb.invalid",
                headers={"x-contextdb-gateway-attestation": "must-not-be-retained"},
            )
        transport = HttpTransport(
            "https://contextdb.invalid",
            header_provider=lambda *_: {"Transfer-Encoding": "chunked"},
            opener=lambda *_: FakeResponse({}),
        )
        with self.assertRaises(ProtocolError):
            transport.post(VERIFY_PATH, {})


class AgentSessionTests(unittest.TestCase):
    def test_before_after_turn_retains_trace_and_stable_retry_key(self) -> None:
        transport = FakeTransport()
        session = AgentSession(
            ContextDbClient(transport),
            context=context(),
            access=access(),
            agent_id="agent-1",
            session_id="session-1",
        )
        recall = session.before_turn("what did we decide?")
        observed = session.after_turn("hello", "hi", metadata={"channel": "chat"})

        self.assertEqual(recall.trace, session.last_trace)
        self.assertEqual(session.last_continuation, "continuation-1")
        self.assertEqual(observed.commit_seq, 3)
        _, observe_body = transport.calls[-1]
        key = observe_body["idempotency_key"]
        self.assertEqual(
            key,
            "agent-session:session-1:0:"
            "2f3e39c1c1a84fd927469d194dea24eab10aeddb80263fa288ce8dc25767f818",
        )
        self.assertEqual(observe_body["context"]["request_id"], "session:session-1:after:0")
        self.assertEqual(observe_body["metadata"]["channel"], "chat")

        second_transport = FakeTransport()
        second = AgentSession(
            ContextDbClient(second_transport),
            context=context(),
            access=access(),
            agent_id="agent-1",
            session_id="session-1",
        )
        second.after_turn("hello", "hi", metadata={"different": True})
        self.assertEqual(second_transport.calls[-1][1]["idempotency_key"], key)

    def test_failed_observe_does_not_advance_sequence(self) -> None:
        transport = FakeTransport()
        transport.fail_observe = True
        session = AgentSession(
            ContextDbClient(transport),
            context=context(),
            access=access(),
            agent_id="agent-1",
            session_id="session-1",
        )
        with self.assertRaises(RuntimeError):
            session.after_turn("hello", "hi")
        self.assertEqual(session.sequence, 0)
        first_key = transport.calls[-1][1]["idempotency_key"]
        transport.fail_observe = False
        session.after_turn("hello", "hi")
        self.assertEqual(transport.calls[-1][1]["idempotency_key"], first_key)
        self.assertEqual(session.sequence, 1)

    def test_context_is_explicit_capability_not_authentication(self) -> None:
        transport = FakeTransport()
        session = AgentSession(
            ContextDbClient(transport),
            context=context(),
            access=access(),
            agent_id="agent-1",
            session_id="session-1",
        )
        session.before_turn("hello")
        _, body = transport.calls[-1]
        self.assertEqual(body["context"]["workspace_id"], "workspace-1")
        self.assertNotIn("authorization", body["context"])

    def test_concurrent_turns_are_serialized_and_policy_is_snapshotted(self) -> None:
        transport = FakeTransport()
        policy = access()
        session = AgentSession(
            ContextDbClient(transport),
            context=context(),
            access=policy,
            agent_id="agent-1",
            session_id="session-1",
        )
        grants = policy.audience_purpose_grants
        if not isinstance(grants, dict):
            self.fail("test access fixture must retain its mutable source mapping")
        grants["team"] = frozenset({"mutated"})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(session.after_turn, "one", "first"),
                executor.submit(session.after_turn, "two", "second"),
            ]
            for future in futures:
                future.result(timeout=1)
        observations = [body for path, body in transport.calls if path == OBSERVE_PATH]
        self.assertEqual([body["content"]["sequence"] for body in observations], [0, 1])
        self.assertEqual(
            observations[0]["access"]["audience_purpose_grants"]["team"],
            ["assistant"],
        )


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_client_and_session(self) -> None:
        transport = FakeTransport()
        client = AsyncContextDbClient(ContextDbClient(transport))
        async with AsyncAgentSession(
            client,
            context=context(),
            access=access(),
            agent_id="agent-1",
            session_id="session-1",
        ) as session:
            result = await session.before_turn("hello")
            await session.after_turn("hello", "hi")
        self.assertEqual(result.trace.trace_id, "trace-1")
        self.assertEqual(session.last_continuation, "continuation-1")

    async def test_async_requests_are_real_awaitables(self) -> None:
        transport = FakeTransport()
        client = AsyncContextDbClient(ContextDbClient(transport))
        result = await asyncio.wait_for(
            client.verify(VerifyRequest(context(), deep=False)), timeout=1
        )
        self.assertTrue(result.valid)

    async def test_async_session_serializes_concurrent_turns(self) -> None:
        transport = FakeTransport()
        session = AsyncAgentSession(
            AsyncContextDbClient(ContextDbClient(transport)),
            context=context(),
            access=access(),
            agent_id="agent-1",
            session_id="session-1",
        )
        await asyncio.gather(
            session.after_turn("one", "first"),
            session.after_turn("two", "second"),
        )
        observations = [body for path, body in transport.calls if path == OBSERVE_PATH]
        self.assertEqual([body["content"]["sequence"] for body in observations], [0, 1])


if __name__ == "__main__":
    unittest.main()
