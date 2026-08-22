# Public API

## Canonical execution contract

`CanonicalOperation` and `CanonicalResponse` cover the legacy common transcript:
observe, recall, explain, export, import, and verify. `CanonicalError` mirrors
the complete stable service error envelope. Transport/setup failures remain
separate `ConformanceError` values.

`ConformanceAdapter` exposes `interface()`, a complete capability `manifest()`,
and asynchronous `invoke()`. Concrete adapters are `EmbeddedAdapter`,
`HttpAdapter`, `GrpcAdapter`, `CliProcessAdapter`, and `McpAdapter`.

## Authenticated v1 boundary

New chapter-21 methods use `AuthenticatedRequestContext`. It nests legacy
resolved `RequestContext` and adds distinct actor and agent IDs, optional
session, explicit `Capability` grants, and authenticated-channel or
request-signature evidence. Protected transports additionally require a
keyed-BLAKE3 gateway attestation bound to the complete canonical context.
gRPC verifies it before converting method content. HTTP reads at most 16 MiB,
decodes only a borrowed raw `context` envelope, verifies the attestation, and
only then deserializes the operation DTO. Both call the service only after that
proof, and the service independently validates authentication before capability
checks and payload validation. Establishing the original trusted channel or
cryptographically verifying Ed25519 signatures remains the deployment gateway's
responsibility; an unconfigured adapter rejects protected methods.

`ReferenceService` executes resumable source ingestion, subscriptions,
Correct/Forget, node/timeline/evidence/conflict reads, graph traversal, status,
logical backup/restore, and pure continuity Preflight. Preflight can block but
its report never grants host/tool authority. Stateful bootstrap, postflight,
checkpoint, resume, and handoff, Consolidate, Reflect, Reindex, Compact, and
format migration are typed but return canonical `Unsupported` after
authentication/capability validation because the reference profile has no such
executor. The embedded adapter and the HTTP and gRPC adapters in this harness
all use that reference profile. Source completion validates every item
against a private imported reference snapshot and publishes the completed state
through one coherent handle replacement; any staged failure publishes nothing.
Reference Forget can exercise a logical `Delete` mutation; it is not evidence
of production physical or cryptographic erasure.
Power-loss atomicity remains a durable-backend obligation. Because the structured
v1 frame has no compressed-byte field, identity executes while gzip/zstd
negotiate fail-closed with typed remediation. The reference profile also caps
items at 16 MiB, buffered snapshots at 64 MiB, incomplete streams at eight, and
retained stream replay states at 64.

`IngestAck.lease_expires_at_ms` is an additive optional contract for durable
profiles that reclaim incomplete staging. When present, it is an absolute Unix
epoch millisecond deadline. Exact retries preserve the deadline carried by the
original durable acknowledgement; accepting a new frame may atomically renew
it. Completion always omits it. After expiry, an authenticated retry returns
the existing typed `SnapshotExpired` outcome with
`violated_policy=stream_lease_expired`; a durable tombstone must keep that
stream identity from being reopened or aliased to an old cursor. The field is
Protobuf wire-compatible with the frozen v1 schema. JSON clients that reject
unknown response fields require a version-aware rollout because JSON has no
equivalent unknown-field preservation guarantee.
Durable migration from a legacy staging record with no stored deadline treats
that record as expired at the reclaim transaction's host `now_ms`; the rooted
tombstone stores that non-zero normalized instant. It must never reinterpret a
missing legacy deadline as a fresh lease.

## Reports and capabilities

`run_conformance_suite` returns `ConformanceReport`. Every check has a stable ID,
explicit status, content-free detail, and evidence digest. `semantic_digest`
covers ordered checks; `report_digest` also binds interface and manifest.

Every `Capability::ALL` member must be classified as `Exercised`,
`ExternalProofRequired`, `NotApplicable`, or `ProfileGap`. The vocabulary covers
resumable ingestion, compression, completion, subscriptions, authenticated v1,
memory control/read/traverse, pure no-authority runtime preflight, the stateful
runtime lifecycle, maintenance/admin, and the versioned runtime capability
manifest returned by status. Preflight is classified
independently so its executable evaluator cannot turn bootstrap/checkpoint/
resume/handoff or profile-specific postflight gaps into a synthetic pass. A
typed method with no executable backend remains a gap.

Operational probe semantics remain outside the application operation vocabulary. The
HTTP router exposes two unauthenticated, content-free `current-server` host
probes in addition to 59 protected SDK routes. Both probes carry the same
closed schema-v1 capability vocabulary used by authenticated status, while
their fixed profile labels and states remain content-free. Liveness
proves only process/router response; readiness covers the currently published
Fjall state and external-head reconciliation. The SDKs and common semantic
transcript do not expose these probes, and this slice is neither full RFC 31.15
structured health nor a `server-v1` profile claim.

The production CLI profile implements durable bootstrap/postflight/checkpoint/
resume/handoff. Postflight stores commitments and a receipt identifier, not
protected request/response content, and reports `grants_authority=false`; it is
not host/tool-execution proof. The source and unit tests cover the executor,
while the conformance profile remains `ExternalProofRequired` until its external
subprocess transcript proves restart-bound lifecycle continuity. Embedded and
reference-backed HTTP/gRPC/MCP profiles retain their explicit executor gaps.

The official production CLI/Fjall profile separately implements one Reindex
projection contract. The operation ID is non-blank, 1-1024 bytes, with no NUL.
The payload is at most 4 KiB/depth 16, rejects unknown fields, and must contain
exactly `{"schema_version":1,"projection":"production_policy_graph_v1"}`. It
synchronously rebuilds and publishes the current healthy singleton policy
graph under the publication lock. Its successful response shape is:

```json
{
  "schema_version": 1,
  "projection": "production_policy_graph_v1",
  "status": "rebuilt_and_published",
  "receipt_id": "<64 lowercase hex>",
  "replayed": false,
  "semantic_mutations": 0,
  "primary_state_mutations": 0,
  "active_generation_changed": false,
  "external_state_head_anchored": true
}
```

`replayed` is the only value that changes on exact replay, which returns the
same durable receipt. The receipt contains commitments rather than protected
request/response content. The response intentionally exposes no durable
generation, graph watermark, or record/node count.
`external_state_head_anchored=true` is reported only after an exact authority
re-read and is not persisted as an authority claim. This path does not recover
a corrupt graph and is not an offline repair, lexical, vector, or HNSW reindex.
It establishes no latency/throughput SLO. Because
Consolidate, Reflect, Compact, live Restore, and MigrateFormat remain absent,
`MaintenanceAdmin` stays `ProfileGap` even for the production CLI profile.

## Protocol probes

- `prove_http_protocol_errors` drives malformed/schema-incompatible/oversized
  bodies through the production router.
- `prove_grpc_network_streaming` starts the production server on loopback and
  proves legacy stream/recall order, manifest-first source ingestion, gzip
  fail-closed negotiation followed by identity execution, cursor-bound partial
  acks, exact retry, publication
  only after `SnapshotComplete`, stable subscription event IDs, resume/dedup,
  filters, policy omission, and transport-auth rejection.
- `McpAdapter::prove_r19` proves strict pre-initialize stateless metadata,
  standard MCP initialization, and the 2026-07-28 discovery/result profile.
- `CliProcessAdapter::prove_external_surface` proves actual subprocess JSON,
  Protobuf, errors, archive bytes, authenticated `contextdb api` status, a
  typed runtime gap, and real `contextdb mcp` discovery/call behavior when an
  executable is supplied. Every
  subprocess receives child-only token-key configuration plus a per-adapter
  external state-head authority. Windows uses an exact HKCU selector; Unix
  uses an owner-only directory outside the archive and scratch paths. Debug
  output redacts custody values, and adapter drop removes the exact authority.
- CLI archive import is clone-only: the destination must not exist and the
  adapter never sends `--force`. `run_archive_round_trip` therefore uses a
  fresh target rather than a pre-initialized live database.

## Schema compatibility

`parse_proto_schema` builds a deterministic manifest of enum values, permanent
field numbers/signatures, and RPC streaming signatures.
`compare_schema_compatibility` permits additive items and rejects removals,
renames, renumbers, retypes, and stream-shape changes. The released v1 schema is
checked in at `tests/fixtures/contextdb_v1_released.proto`.

The current schema intentionally extends that frozen fixture with RFC
§21.22-§21.25 high-level services. Compatibility tests compare the old fixture
to the current schema directionally and require a non-zero additive item count;
the fixture is not rewritten, so accidental breakage cannot be disguised as a
new baseline. These DTOs contain semantic intent, authenticated context, policy,
and bounds—not raw graph nodes or edges.
The exact four-service/method inventory and all 29 HTTP route/request/response/
capability/reference-semantics mappings are independently frozen in
`tests/fixtures/high_level_v1_surface.json` and checked against the generated
schema manifest.

`HighLevelMutationResponse.semantic_status = pending` is a hard semantic
boundary. For example, `CreateMemorySubject`, `CreateRelationshipSpace`,
`BeginSession`, and artifact attachment prove policy-authorized durable capture;
they do not claim that a canonical graph object was synchronously created.
Profiles lacking an atomic policy, runtime, subject-archive, blob/hash, or
lineage-erasure executor return `unsupported` after gateway and capability
authorization and never manufacture a successful mutation receipt.
The isolated `contextdb-secure-store` P0-P3 work defines bounded hard-delete and
production-boundary contracts only. It is not wired into these APIs, has no
production KMS/repository/provider adapter, and does not enable hard delete.
