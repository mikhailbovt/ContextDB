# HTTP SDK contract and acceptance

The Python, Go, and TypeScript packages are handwritten adapters over the same
`contextdb-service` HTTP/JSON contract. They expose the declared 59-route SDK
surface, including the fully typed `POST /v1/context-pack` composition, and do
not know or expose physical storage.

| Family | Stable HTTP operations |
| --- | --- |
| Legacy observation/recall | `observe`, `recall`, `explain_recall` |
| Authenticated context compilation | `compile_context` |
| Authenticated mutation/stream page | `ingest_frame`, `correct`, `forget`, `subscribe` |
| Authenticated memory | `get_node`, `traverse`, `get_timeline`, `get_evidence`, `get_conflict` |
| Authenticated runtime | `bootstrap`, `preflight`, `postflight`, `checkpoint`, `resume`, `handoff` |
| Authenticated maintenance | `consolidate`, `reflect`, `reindex`, `compact` |
| Authenticated administration | `get_status`, `create_backup`, `restore_backup`, `migrate_format` |
| Legacy archive/integrity | `export_archive`, `import_archive`, `verify` |
| High-level conversation | 7 operations from `begin_session` through `bootstrap_subject` |
| High-level memory control | 9 operations from `remember` through subject import/export |
| High-level subject/relationship | 7 subject, role, runtime-migration, and sharing operations |
| High-level artifacts | 6 ingest, attach, derivation, selector, metadata, and deletion operations |

The exact 59-operation path and capability matrix is machine-readable in
`fixtures/http_v1_contract.json` and is asserted by all three package suites.
The authoritative 29-route high-level partition is mirrored from
`crates/contextdb-conformance/tests/fixtures/high_level_v1_surface.json`.
All 59 SDK routes require a deployment gateway attestation on the official
server. Every assertion uses the exact-request v2 protocol described
in [`GATEWAY_ATTESTATION_V2.md`](GATEWAY_ATTESTATION_V2.md): it binds the
transport, exact operation, exact serialized HTTP body, bounded freshness
window, and one-shot nonce. The six legacy routes retain their source-compatible
`RequestContext` DTO and therefore do not perform the newer capability-grant
check. The other 53 routes carry `AuthenticatedRequestContext` and enforce their
capability grants after exact-request verification.
Conditional requirements (hard delete, evidence/raw evidence, and
kind-sensitive timeline) are recorded separately so the matrix does not lie by
flattening conjunctions.
High-level durable-write and bounded-query routes have reference semantics.
Governed controls, subject transfer, artifact ingest/derivation, and hard
deletion are still profile-dependent and may return canonical `unsupported`
after authentication and capability checks; an SDK method is a wire-contract
claim, not a false claim that the reference executor implements the operation.
The router still registers runtime, maintenance, and administration routes when
the selected service profile has no executor. The current reference profile
executes only the pure continuity `preflight` operation from the runtime family;
its report always has `grants_authority=false`. It returns canonical
`unsupported` for bootstrap, postflight, checkpoint, resume, handoff, all four
maintenance operations, and format migration. The production CLI backend adds
durable bootstrap/postflight/checkpoint/resume/handoff. Postflight is a
content-free caller assertion, not proof of host/tool execution or an HTTP
reference-profile support claim. The production backend also implements exact
bounded `production_policy_graph_v1` Reindex, scheduler-owned physical compact
observation, and restart-safe runtime-ledger GC. This is not reference HTTP
support, offline repair, a lexical/vector/HNSW rebuild, or an SLO. Consolidate,
Reflect, live Restore, and format rewrite remain unsupported, so full
`MaintenanceAdmin` remains a gap. A restart-bound external lifecycle transcript
also remains required. SDK availability is a wire-contract claim, not a claim
that every server profile implements a route.

Authenticated status and migration responses include a strict schema-v1
`capability_manifest`. Every SDK parses the profile, the independent
`server_v1_release_ready` flag, and the map of `available`, `compiled_only`, or
`unsupported` states. Unknown nested fields, schema versions, and states fail
closed. The manifest reports executable runtime composition; it does not turn
an SDK route or a compiled dependency into an available backend capability.
The shared fixture additionally fixes the four candidate-only schema-v1 keys:
`quarantined_memory_proposals`, `policy_first_candidate_recall`,
`candidate_hierarchy_dag`, and `policy_first_candidate_traversal`. SDK maps stay
open to future keys, while these names consistently describe quarantined
proposal storage/lookup/DAG traversal—not adjudication, extraction,
consolidation, reflection, or release readiness.

The same router registers two operational host probes outside the SDK contract:
unauthenticated, content-free `GET /health/live` and `GET /health/ready`.
They belong only to the bounded `current-server` slice. The SDKs deliberately
do not wrap them, and their presence is not RFC 31.15 completion or a
`server-v1` profile claim. The shared fixture records this separate partition
without adding the probes to its 59-operation `routes` map.

## Exact HTTP v1 capability and support matrix

Every row is a protected `POST /v1` operation, requires deployment gateway attestation, and is exposed by
the synchronous Python, asynchronous Python, Go, and TypeScript clients.
`Request` means the compatibility `RequestContext`; `Authenticated` means
`AuthenticatedRequestContext`. `None` in the capability column means the legacy
DTO has no `capability_grants` field, not that the transport is unauthenticated.

| Operation | Path | Context | Capability grant | Reference profile |
| --- | --- | --- | --- | --- |
| `observe` | `/v1/observations` | Request | None | Supported |
| `ingest_frame` | `/v1/observations/ingest-frame` | Authenticated | `stream_ingest` | Supported |
| `correct` | `/v1/observations/correct` | Authenticated | `correct` | Supported |
| `forget` | `/v1/observations/forget` | Authenticated | `forget`; `hard_delete` additionally for hard delete | Reference logical mutation supported; production hard delete unsupported |
| `recall` | `/v1/recall` | Request | None | Supported |
| `compile_context` | `/v1/context-pack` | Authenticated | `recall`; `model_processing` for external processing; `raw_evidence` for excerpts | Supported by ReferenceService and delegated RecallProvider profiles |
| `explain_recall` | `/v1/recall/explain` | Request | None | Supported |
| `subscribe` | `/v1/subscriptions/page` | Authenticated | `subscribe` | Supported |
| `get_node` | `/v1/memory/node` | Authenticated | `read_memory` | Supported |
| `traverse` | `/v1/memory/traverse` | Authenticated | `traverse` | Supported |
| `get_timeline` | `/v1/memory/timeline` | Authenticated | Kind-sensitive: memory `read_memory`; evidence `read_evidence` + `raw_evidence`; conflict `read_conflict` | Supported |
| `get_evidence` | `/v1/memory/evidence` | Authenticated | `read_evidence` + `raw_evidence` | Supported |
| `get_conflict` | `/v1/memory/conflict` | Authenticated | `read_conflict` | Supported |
| `bootstrap` | `/v1/runtime/bootstrap` | Authenticated | `runtime` | `unsupported` (501) |
| `preflight` | `/v1/runtime/preflight` | Authenticated | `runtime` | Supported (pure; never grants authority) |
| `postflight` | `/v1/runtime/postflight` | Authenticated | `runtime` | `unsupported` (501) |
| `checkpoint` | `/v1/runtime/checkpoint` | Authenticated | `runtime` | `unsupported` (501) |
| `resume` | `/v1/runtime/resume` | Authenticated | `runtime` | `unsupported` (501) |
| `handoff` | `/v1/runtime/handoff` | Authenticated | `runtime` | `unsupported` (501) |
| `consolidate` | `/v1/maintenance/consolidate` | Authenticated | `maintenance` | `unsupported` (501) |
| `reflect` | `/v1/maintenance/reflect` | Authenticated | `maintenance` | `unsupported` (501) |
| `reindex` | `/v1/maintenance/reindex` | Authenticated | `maintenance` | `unsupported` (501); production CLI/Fjall-only executor is not this reference HTTP profile |
| `compact` | `/v1/maintenance/compact` | Authenticated | `maintenance` | `unsupported` (501) |
| `get_status` | `/v1/admin/status` | Authenticated | `admin` | Supported |
| `create_backup` | `/v1/admin/backup` | Authenticated | `admin` | Supported |
| `restore_backup` | `/v1/admin/restore` | Authenticated | `admin` | Supported |
| `migrate_format` | `/v1/admin/migrate` | Authenticated | `admin` | `unsupported` (501) |
| `export_archive` | `/v1/archive/export` | Request | None | Supported |
| `import_archive` | `/v1/archive/import` | Request | None | Supported |
| `verify` | `/v1/verify` | Request | None | Supported |

Every client:

- sends exact JSON with `Content-Type: application/json` and requests JSON;
- bounds requests and responses to 16 MiB by default;
- requires HTTP 200 for success and validates every response field and nested
  shape, rejecting unknown fields;
- exposes the canonical ContextPack, rendering, continuation, and privacy-safe
  trace as nested typed DTOs; compiler-owned `trusted_control` and recalled
  `untrusted_data` remain separate fields and are never concatenated by an SDK;
- exposes exact `contextdb.context_pack.protobuf.v1` bytes plus the
  `blake3-256` algorithm identifier and an explicit verification helper. The
  parser validates the byte shape and version binding, while digest verification
  remains a deliberate caller action and rejects changed bytes or digest text;
- decodes the full canonical error taxonomy and checks error code/status
  agreement;
- preserves optional `partial_result_refs`, `violated_policy`,
  `safe_next_action`, and `trace_id` remediation fields;
- preserves Rust `Vec<u8>` values as JSON integer arrays;
- represents `AuthenticatedRequestContext` as an explicit application DTO. It
  never derives transport authentication or gateway attestation from that DTO;
- accepts deployment-owned static headers and a per-request header-provider
  seam. On every call the provider receives the exact route path plus the exact
  serialized JSON body (bytes in Python and Go, string in TypeScript), which is
  the canonical material required by exact-request v2. It can produce
  `x-contextdb-gateway-id` and
  `x-contextdb-gateway-attestation` without the client retaining the returned
  credential;
- rejects a static `x-contextdb-gateway-attestation`: the keyed attestation is
  exact-body, operation, freshness, and nonce-bound and must come from the
  per-request provider. A static
  gateway ID remains valid configuration;
- preserves u64 exactly in Python and Go. TypeScript rejects values above
  `Number.MAX_SAFE_INTEGER` instead of rounding them;
- accepts the additive optional `IngestAck.lease_expires_at_ms` absolute Unix
  epoch millisecond deadline while preserving legacy acknowledgements that omit
  it; Python and Go preserve its full u64 range and TypeScript applies its safe
  integer boundary;
- exposes recall trace and continuation state through agent-session middleware,
  which remains an honest legacy recall/observe helper;
- derives the same SHA-256 turn idempotency key from a domain-separated,
  length-framed UTF-8 tuple.

The original six public calls keep their source-compatible names and request
types: Python `observe`/`recall`/`explain_recall`/`export_archive`/
`import_archive`/`verify`, Go `Observe`/`Recall`/`ExplainRecall`/
`ExportArchive`/`ImportArchive`/`Verify`, and the corresponding TypeScript
camel-case methods. Their original call patterns remain covered by compatibility
tests.

For source compatibility a client may still be constructed without a header
provider, which is useful with deliberately non-strict local fakes or custom
adapters. Such requests are rejected by the official fail-closed server; this
constructor compatibility is not an unauthenticated-server capability claim.

## Explicit boundaries

- `observe_batch` is an embedded Rust trait convenience and has no HTTP route.
- HTTP exposes finite `ingest_frame` and `subscriptions/page` operations. gRPC
  client/server streams are separate transport contracts and are not fabricated
  by these HTTP clients.
- gRPC-only `ObserveStream`, `IngestSnapshot`, `Subscribe`, `RecallStream`, and
  `ContinueRecall` streaming/distinct-RPC semantics remain in the gRPC adapter.
  The HTTP equivalents are single observe, repeated ingest frames/pages, and a
  continuation field on ordinary recall.
- The `contextdb_*` MCP JSON-RPC tools remain in the MCP adapter; their
  corresponding HTTP operations are present, but these SDKs do not fabricate
  MCP transport calls.
- The generic runtime `payload` is exposed exactly as HTTP does. ContextPack is
  a distinct typed route and is never reconstructed from legacy recall IDs.
- TypeScript also rejects domain-time i128 values outside its safe integer
  range; Python preserves the full signed i128 range and Go uses `Int128`.
- Package suites use deterministic local fakes/servers. A separately versioned
  live multi-language compatibility runner remains required for publication.
- `AuthenticationEvidence` is application data verified by the trusted server
  boundary. It is not a substitute for the deployment-owned gateway headers.

## Package checks

```powershell
$env:PYTHONPATH = "sdk/python/src"
python -m unittest discover -s sdk/python/tests -v
python -m compileall -q sdk/python/src sdk/python/examples

Push-Location sdk/python
python -m build
ruff check src tests examples
mypy --strict src tests
Pop-Location

Push-Location sdk/go
go test -race ./...
go vet ./...
Pop-Location

Push-Location sdk/typescript
npm ci
npm test
npm pack --dry-run
Pop-Location
```
