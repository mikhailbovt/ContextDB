# ContextDB TypeScript SDK

This dependency-light package uses native `fetch`, Web Crypto, and strict
TypeScript types for all 59 protected `POST /v1` routes in the ContextDB
HTTP/JSON router. That includes the policy-first `POST /v1/context-pack`
surface with complete nested request/response DTOs and a fail-closed response
parser.

`StatusResponse.capability_manifest` exposes the selected schema-v1 runtime
profile and a strict record of `available`, `compiled_only`, or `unsupported`
states. Unknown nested fields, versions, and state strings fail closed.
`CandidateRuntimeCapabilityIdsV1` exports the four stable quarantined
candidate-only keys while the manifest record remains additive.

```ts
import { ContextDbClient } from "@contextdb/sdk";

const client = new ContextDbClient("http://127.0.0.1:8080");
const result = await client.recall(request);
const compiled = await client.compileContext(contextPackRequest);
```

`compiled.rendered.trusted_control` and `compiled.rendered.untrusted_data`
remain separate channels. The parser rejects unknown fields, unsafe integer
rounding, inconsistent snapshot/status bindings, and any recalled block that
claims trusted instruction capability.
Call `verifyCanonicalContextDigest(compiled)` before consuming a pack when
independent transport-boundary verification is required. The helper uses the
pinned, audited `@noble/hashes` BLAKE3 implementation over the exact returned
`contextdb.context_pack.protobuf.v1` bytes and rejects changed bytes, digest
text, algorithms, or unknown encodings.

`AgentSession` adds provider-neutral before/after-turn orchestration,
deterministic SHA-256 retry keys, serialized concurrent turns, and retention of
the last recall trace/continuation. See
[`examples/agent-session.mjs`](examples/agent-session.mjs).

`RequestContext`, `AuthenticatedRequestContext`, and
`AuthenticationEvidence` are application DTOs, not gateway credentials.
Optional deployment-owned bearer/static headers are client options. An async
`headerProvider` receives the exact route path and serialized JSON body string
on every call and can return per-request gateway ID/attestation headers without
retaining them in the client. The official server requires this deployment
attestation for all protected routes; see
[`GATEWAY_ATTESTATION_V2.md`](../GATEWAY_ATTESTATION_V2.md) for the exact
transcript, freshness, and replay contract. The router's unauthenticated,
content-free `GET /health/live` and `GET /health/ready` operational probes are
not SDK operations and do not establish RFC 31.15 or `server-v1`. Static
attestation headers are rejected. Omitting
the provider remains source-compatible for deliberately non-strict fakes or
adapters, but cannot authenticate to the official server.

Build and test:

```powershell
npm ci
npm test
npm pack --dry-run
```

JavaScript cannot exactly represent every Rust `u64`. The SDK rejects request
or response integers above `Number.MAX_SAFE_INTEGER` instead of silently
corrupting commit/snapshot sequences. The current v1 JSON transport needs a
future lossless-integer encoding before values above that boundary can be used.
The same safe-integer rule applies to Rust i128 domain-time values. The agent
middleware remains an honest observe/recall helper; typed runtime/checkpoint
methods are explicit client calls rather than hidden lifecycle behavior.
