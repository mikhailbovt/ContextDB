# ContextDB Go SDK

The Go SDK exposes all 59 protected
`POST /v1` HTTP/JSON routes through `Client`, including the typed policy-first
`CompileContext` operation. Every operation accepts a `context.Context`. Its
only direct runtime dependency is the pinned `github.com/zeebo/blake3`
implementation used for canonical-wire verification.

`StatusResponse.CapabilityManifest` exposes the selected schema-v1 runtime
profile and typed `available`, `compiled_only`, or `unsupported` states. The
client rejects unknown nested fields, versions, and state strings.
`CandidateRuntimeCapabilityIDsV1()` returns the four stable quarantined
candidate-only keys; it does not imply adjudication or canonical publication.

```go
client, err := contextdb.NewClient("http://127.0.0.1:8080", nil)
response, err := client.Recall(ctx, request)
pack, err := client.CompileContext(ctx, compileRequest)
```

`CompileContextResponse.Rendered.TrustedControl` and `UntrustedData` are
deliberately separate fields. The SDK never concatenates recalled data into a
trusted instruction channel.
Call `CompileContextResponse.VerifyCanonicalDigest()` before consuming a pack
when independent transport-boundary verification is required. It hashes the
exact returned `contextdb.context_pack.protobuf.v1` bytes and rejects changed
bytes, digest text, algorithms, or unknown encodings.

`AgentSession` provides provider-neutral before/after-turn orchestration,
deterministic retry keys, serialized sequence allocation, and retention of the
last recall trace/continuation. See [`examples/agent_session`](examples/agent_session).

`RequestContext`, `AuthenticatedRequestContext`, and
`AuthenticationEvidence` are application DTOs, not gateway credentials.
Optional deployment-owned bearer/static headers live in `ClientOptions`.
The official server requires gateway attestation on all protected routes.
The router's unauthenticated, content-free `GET /health/live` and `GET
/health/ready` operational probes are not SDK operations and do not establish
RFC 31.15 or `server-v1`.
`HeaderProvider` receives a fresh `HeaderProviderRequest` containing the exact
route path and serialized JSON body bytes and can return per-request gateway
ID/attestation headers; its result is applied once and not retained by `Client`.
The exact token transcript, freshness, and replay contract is specified in
[`GATEWAY_ATTESTATION_V2.md`](../GATEWAY_ATTESTATION_V2.md).
Static attestation headers are rejected. A client without a provider remains
source-compatible for deliberately non-strict fakes or adapters, but cannot
authenticate to the official server.

Run:

```powershell
go test -race ./...
go vet ./...
```

The agent middleware remains a narrow observe/recall helper. Runtime lifecycle
methods, including checkpoint, are explicit client calls rather than hidden
middleware side effects. `Int128` preserves signed domain-time values exactly.
Arbitrary JSON response payloads retain integer tokens as `json.Number`; typed
commit/snapshot fields remain `uint64`.
