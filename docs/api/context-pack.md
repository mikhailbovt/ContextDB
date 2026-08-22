# Policy-first ContextPack API

`compile_context` is the first-class RecallEngine to ContextCompiler operation.
It returns a canonical, minimal `ContextPack`; callers must not emulate it by
materializing legacy recall IDs and concatenating their payloads.

## Surfaces

- embedded Rust: `CognitiveMemoryService::compile_context`;
- reusable provider composition:
  `contextdb_service::compile_provider_context(provider, continuation_key, request)`;
- HTTP: `POST /v1/context-pack`;
- Python SDK: `compile_context` / async `compile_context`;
- Go SDK: `CompileContext`;
- TypeScript SDK: `compileContext`;
- gRPC: `contextdb.v1.RecallService/CompileContext`;
- CLI grouped API:
  `contextdb api <path> compile-context --request <request.json>`;
- MCP: `contextdb_context`.

HTTP, CLI and MCP use the typed JSON `CompileContextRequest`. gRPC keeps the
authenticated `RequestContext` in its own field and carries the canonical JSON
`CompileContextPlan` as `plan_json`, so transport and capability authorization
complete before query, vector, or model-profile content is decoded. The gRPC
response carries canonical ContextPack JSON plus typed rendering, budget and
privacy-safe trace fields. Every JSON and gRPC response also carries the exact
canonical Protobuf bytes, the public
`contextdb.v1.CanonicalContextPackV1` encoding identifier, and the BLAKE3-256
algorithm identifier. Clients can therefore verify `canonical_digest` over the
returned bytes without reserializing JSON or trusting server-local code.

## Binding and authorization

One request resolves exactly one provider snapshot before corpus access. The
provider guard rejects a corpus request for any other snapshot. Recall and
compilation share the same keyed policy/filter digest; the compiler rejects a
different digest or snapshot rather than silently recompiling against newer
state.

The service checks `recall` before content materialization. It additionally
requires `model_processing` when the model profile declares external
processing, and `raw_evidence` before evidence excerpts may leave the service.
The authenticated purpose must match the ContextPack purpose. Provider records
are authorized before their content is copied into the compiler provider, and
compiler disclosure policy is applied again before materialization.

## Bounds, freshness and continuation

The service rejects requests above 1 MiB and responses above 8 MiB. The larger
response envelope accounts for the canonical pack's JSON view plus its exact
binary bytes (represented as an octet array in JSON). Query text,
facets, supplied vectors, recall work, token budgets, block counts, evidence
counts and selection evaluations all have explicit ceilings. Caller budgets may
be lower than those ceilings.

The trace reports the exact snapshot, keyed filter digest, bounded usage,
selected/evidence counts, maximum projection lag and content-free freshness
codes. It never reports query text, rejected candidate IDs, storage keys, vector
space names or memory content. Projection lag above
`max_projection_lag_commits` returns `index_too_stale`; `allow_stale` changes
that failure into explicit trace warnings without changing the pinned snapshot.

The opaque continuation wraps recall and compiler pagination together. It is
authenticated and bound to the authority, complete plan, snapshot and filter.
Changing the query or policy, crossing a snapshot, or modifying the token
returns `invalid_continuation`. A fresh request ID may resume when all authority
and plan bindings remain identical.

## Rendering contract

`rendered.trusted_control` is compiler-generated control with no recalled
payload. `rendered.untrusted_data` contains authorized memory with zero
instruction capability. Adapters must preserve those channels. The canonical
ContextPack remains the source of truth; rendering is a model-profile-specific
placement of the same pack.

The reference service delegates to the reusable provider pipeline. A durable
production profile is supported only after its `ProductionService` supplies a
policy-first `RecallProvider` over a coherent durable snapshot and delegates to
that same helper with a stable continuation key. Until that delegation exists,
the trait returns the typed `unsupported` result; falling back to the legacy
ID-only recall API is not an equivalent implementation.
