# ContextDB Python SDK

The Python SDK is a synchronous/async HTTP client for the
canonical ContextDB v1 JSON service. It supports Python 3.11 and later.
Its only runtime package is the pinned official-Rust-backed `blake3` binding,
used to verify canonical ContextPack bytes.

```python
from contextdb import ContextDbClient

client = ContextDbClient.http("http://127.0.0.1:8080")
```

The client covers all 59 protected `POST /v1` routes, including typed
policy-first ContextPack compilation, authenticated ingest/correction/forget/subscription, memory reads/traversal,
runtime lifecycle, maintenance, status, backup/restore, migration, and all 29
high-level conversation/memory/subject/artifact routes.
`StatusResponse.capability_manifest` is a strict schema-v1 DTO whose states are
the `RuntimeCapabilityState` enum; unknown versions, fields, or state strings
raise `ProtocolError` rather than being treated as support.
`CANDIDATE_RUNTIME_CAPABILITY_IDS_V1` exposes the four stable quarantined
candidate-only keys without closing the manifest map to future extensions.
`AsyncContextDbClient` provides matching awaitable methods. `AgentSession` and
`AsyncAgentSession` intentionally remain provider-neutral legacy
before/after-turn orchestration, deterministic retry keys, and retention of the
last recall trace and continuation.

`compile_context` returns nested strict DTOs. Its
`rendered.trusted_control` and `rendered.untrusted_data` fields stay separate;
the SDK never grants recalled content instruction capability. Call
`response.verify_canonical_digest()` before consuming a pack when the transport
boundary requires independent integrity verification. The helper hashes the
exact returned `contextdb.context_pack.protobuf.v1` bytes and rejects changed
bytes, digest text, algorithms, or unknown encodings.

`RequestContext` is a resolved capability input, not an authentication token.
`AuthenticatedRequestContext` and `AuthenticationEvidence` are also explicit
application DTOs, never gateway credentials. Pass `bearer_token=` or static
`headers=` for deployment configuration. The official server requires gateway
attestation on all protected routes. The router's unauthenticated,
content-free `GET /health/live` and `GET /health/ready` operational probes are
not SDK operations and do not establish RFC 31.15 or `server-v1`. Use
`header_provider(request)` for per-request
`x-contextdb-gateway-id`/attestation values; `request.path` and the exact
serialized JSON `request.body` bytes are the canonical v2 signing material
defined in [`GATEWAY_ATTESTATION_V2.md`](../GATEWAY_ATTESTATION_V2.md). The callback is invoked fresh for every call,
and returned headers are used once and are not retained or logged by the SDK.
Static attestation headers are rejected. Omitting the provider remains possible
only for source compatibility with deliberately non-strict fakes or adapters,
not as a supported way to call the official server.

Install the pinned package dependency and run the tests:

```powershell
$env:PYTHONPATH = "src"
python -m pip install -e .
python -m unittest discover -s tests -v
```

See [`examples/agent_session.py`](examples/agent_session.py) for an agent-loop
integration. The middleware does not silently invoke runtime lifecycle routes;
applications can call the typed runtime methods explicitly when appropriate.
