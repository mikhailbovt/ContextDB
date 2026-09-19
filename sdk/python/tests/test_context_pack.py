from __future__ import annotations

import asyncio
import copy
import io
import json
import unittest
import urllib.request
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from contextdb import (
    AsyncContextDbClient,
    AuthenticatedChannel,
    AuthenticatedRequestContext,
    Capability,
    CompileContextPlan,
    CompileContextRequest,
    ContextBudgets,
    ContextDbClient,
    HeaderProviderRequest,
    InstructionHierarchy,
    ModelProfile,
    PackPurpose,
    PositionProfile,
    ProtocolError,
    RecallIntent,
    RecallLimits,
    RecallMode,
    RendererKind,
    RequestContext,
    Sensitivity,
    StructuredFormat,
)
from contextdb.client import CONTEXT_PACK_PATH

FIXTURE = Path(__file__).parents[2] / "fixtures" / "context_pack_v1.json"


class FixtureTransport:
    def __init__(self, response: Mapping[str, Any]) -> None:
        self.response = response
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def post(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append((path, body))
        return copy.deepcopy(self.response)


class JsonResponse:
    def __init__(self, value: Mapping[str, Any]) -> None:
        self.status = 200
        self.headers = {"Content-Type": "application/json"}
        self._body = io.BytesIO(json.dumps(value, separators=(",", ":")).encode())

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> JsonResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def request() -> CompileContextRequest:
    context = AuthenticatedRequestContext(
        request=RequestContext(
            request_id="request-context-pack-1",
            workspace_id="workspace-1",
            subject_id="subject-1",
            audiences=frozenset({"team"}),
            scopes=frozenset({"project"}),
            purpose="conversation",
            clearance=Sensitivity.PRIVATE,
        ),
        actor_id="actor-1",
        agent_id="agent-1",
        session_id="session-1",
        capability_grants=frozenset({Capability.RECALL}),
        authentication=AuthenticatedChannel(
            channel_id="channel-1",
            peer_identity="actor-1",
            binding_digest="a" * 64,
        ),
    )
    return CompileContextRequest(
        context=context,
        plan=CompileContextPlan(
            pack_id="018f47b8-3158-7ad8-9227-63fc6f711e5f",
            query="What should the assistant remember?",
            mode=RecallMode.REQUIRED,
            intent=RecallIntent.CURRENT_TRUTH,
            purpose=PackPurpose.CONVERSATION,
            at_commit=None,
            now_micros=0,
            required_facets=(),
            recall_limits=RecallLimits(
                max_nodes_examined=128,
                max_seed_candidates=64,
                max_graph_hops=2,
                max_frontier_per_hop=64,
                max_evidence_units=32,
                max_context_tokens=2048,
                deadline_micros=5_000_000,
            ),
            context_budgets=ContextBudgets(
                hard_tokens=2048,
                soft_tokens=1024,
                max_blocks=32,
                max_evidence_blocks=32,
                max_raw_evidence_tokens=512,
                max_history_tokens=512,
                max_conflict_tokens=512,
                max_serialized_bytes=262144,
                max_selection_evaluations=128,
            ),
            model_profile=ModelProfile(
                id="model:local-test",
                family="reference",
                tokenizer_id="contextdb.reference-tokenizer.v1",
                renderer=RendererKind.COMPACT,
                max_context_tokens=4096,
                reserved_output_tokens=1024,
                preferred_structured_format=StructuredFormat.COMPACT_TEXT,
                supports_tool_results=False,
                supports_native_citations=False,
                supports_prompt_caching=False,
                position_profile=PositionProfile.SMALL_MODEL_EXPLICIT,
                instruction_hierarchy=InstructionHierarchy.SINGLE_PROMPT_DELIMITED,
                max_schema_complexity=32,
                external_processing=False,
            ),
            explicit_memory_request=True,
            require_primary_evidence=False,
            include_evidence_quotes=False,
            permit_derived_only=True,
            max_projection_lag_commits=0,
            allow_stale=False,
            query_vector=None,
            continuation=None,
        ),
    )


class ContextPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = cast(
            dict[str, dict[str, Any]],
            json.loads(FIXTURE.read_text(encoding="utf-8")),
        )

    def test_raw_original_contract_retains_utf8_bytes_and_rejects_forgery(self) -> None:
        original = json.loads(
            (FIXTURE.parent / "original_evidence_v1.json").read_text(encoding="utf-8")
        )
        wire = copy.deepcopy(self.fixture["response"])
        wire["context_pack"]["sections"]["raw_observations"] = [original["block"]]
        wire["context_pack"]["evidence"] = [original["evidence"]]
        response = ContextDbClient(FixtureTransport(wire)).compile_context(request())
        self.assertEqual(len(response.context_pack.sections.raw_observations), 1)
        self.assertEqual(response.context_pack.evidence[0].excerpt, original["evidence"]["excerpt"])
        for field, value in [("end", 1), ("span_digest", "0" * 64), ("unexpected", True)]:
            bad = copy.deepcopy(wire)
            bad["context_pack"]["evidence"][0]["original_span"][field] = value
            with self.assertRaises(ProtocolError):
                ContextDbClient(FixtureTransport(bad)).compile_context(request())
        wire["context_pack"]["sections"]["raw_observations"][0]["claim_ids"] = ["invented-fact"]
        with self.assertRaises(ProtocolError):
            ContextDbClient(FixtureTransport(wire)).compile_context(request())

    def test_typed_request_matches_fixture_and_response_keeps_channels_separate(self) -> None:
        transport = FixtureTransport(self.fixture["response"])
        response = ContextDbClient(transport).compile_context(request())

        self.assertEqual(transport.calls, [(CONTEXT_PACK_PATH, self.fixture["request"])])
        self.assertEqual(response.context_pack.status.value, "no_memory")
        self.assertNotEqual(response.rendered.trusted_control, "")
        self.assertEqual(response.rendered.untrusted_data, "")
        self.assertEqual(response.context_pack.snapshot, response.trace.snapshot)
        response.verify_canonical_digest()

        corrupted_bytes = replace(
            response,
            canonical_bytes=bytes([response.canonical_bytes[0] ^ 1]) + response.canonical_bytes[1:],
        )
        with self.assertRaises(ProtocolError):
            corrupted_bytes.verify_canonical_digest()
        corrupted_digest = replace(
            response,
            canonical_digest=("0" if response.canonical_digest[0] != "0" else "1")
            + response.canonical_digest[1:],
        )
        with self.assertRaises(ProtocolError):
            corrupted_digest.verify_canonical_digest()

    def test_async_client_exposes_same_typed_operation(self) -> None:
        transport = FixtureTransport(self.fixture["response"])

        async def run() -> None:
            response = await AsyncContextDbClient(ContextDbClient(transport)).compile_context(
                request()
            )
            response.verify_canonical_digest()

        asyncio.run(run())
        self.assertEqual(transport.calls[0][0], CONTEXT_PACK_PATH)

    def test_http_attestation_provider_receives_exact_context_pack_body(self) -> None:
        provider_calls: list[HeaderProviderRequest] = []
        requests: list[urllib.request.Request] = []

        def provider(value: HeaderProviderRequest) -> Mapping[str, str]:
            provider_calls.append(value)
            return {"x-contextdb-gateway-attestation": "ephemeral-context-pack"}

        def opener(value: urllib.request.Request, _timeout: float) -> JsonResponse:
            requests.append(value)
            return JsonResponse(self.fixture["response"])

        client = ContextDbClient.http(
            "https://contextdb.invalid",
            header_provider=provider,
            opener=opener,
        )
        client.compile_context(request())
        provider_request = provider_calls[0]
        wire_request = requests[0]
        self.assertEqual(provider_request.path, CONTEXT_PACK_PATH)
        self.assertEqual(json.loads(provider_request.body), self.fixture["request"])
        self.assertEqual(
            wire_request.get_header("X-contextdb-gateway-attestation"),
            "ephemeral-context-pack",
        )

    def test_unknown_nested_response_field_is_rejected(self) -> None:
        malformed = copy.deepcopy(self.fixture["response"])
        malformed["context_pack"]["sections"]["future_secret_channel"] = []
        with self.assertRaises(ProtocolError):
            ContextDbClient(FixtureTransport(malformed)).compile_context(request())

    def test_trusted_and_untrusted_fields_are_both_mandatory(self) -> None:
        malformed = copy.deepcopy(self.fixture["response"])
        del malformed["rendered"]["trusted_control"]
        with self.assertRaises(ProtocolError):
            ContextDbClient(FixtureTransport(malformed)).compile_context(request())

    def test_unknown_canonical_encoding_is_not_auto_trusted(self) -> None:
        malformed = copy.deepcopy(self.fixture["response"])
        malformed["canonical_encoding"] = "contextdb.context_pack.protobuf.v2"
        with self.assertRaises(ProtocolError):
            ContextDbClient(FixtureTransport(malformed)).compile_context(request())


if __name__ == "__main__":
    unittest.main()
