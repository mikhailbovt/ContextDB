# ContextDB v1 API compatibility contract

Status: pre-release candidate
Applies to: embedded Rust, Protobuf/gRPC, HTTP/JSON, CLI, MCP, Python, Go,
TypeScript, streaming, subscriptions, and portable logical archives.

ContextDB has one semantic service boundary and several transports. A transport
may expose only a declared subset, but it must not reinterpret requests,
authorization, idempotency, errors, snapshots, or archive bytes. Capability
absence is a typed `unsupported`/profile-gap result, never a synthetic success.

## Version domains

These domains advance independently and are recorded in version manifests:

| Domain | Current identifier | Compatibility boundary |
| --- | --- | --- |
| service and HTTP JSON | `contextdb.service/v1` and `/v1/*` | request/response/error schemas |
| Protobuf/gRPC | package `contextdb.v1` | field numbers, enum values, RPC names and stream shapes |
| logical archive | `contextdb.logical.v1` | canonical bytes and deterministic import/export |
| semantic schema | `1` | durable meaning of canonical memory records |
| storage format | `1` | physical reader/writer range and migration plan |
| ContextPack | `1` | canonical context serialization and renderer contract |
| MCP | `2025-03-26`, `2025-06-18`, `2025-11-25`; stateless profile `2026-07-28` | standard initialize/notification/list/call flow plus strict stateless metadata, discovery, result, and cache semantics |
| SDK packages | package SemVer | typed projection of the service/HTTP contract |

A reader must reject an unknown required format feature. Optional rebuildable
projection features may be ignored only when primary logical state remains
readable and the resulting freshness/capability gap is explicit.

## Additive and breaking changes

Within a stable major version, a change is additive only when all existing
valid requests retain their meaning and every existing response remains
decodable:

- adding an optional JSON field with a documented default;
- adding a Protobuf field with a never-reused field number;
- adding a new RPC, HTTP path, MCP tool, capability, or enum value when old
  clients already fail closed on unknown values;
- widening an implementation profile without changing existing semantics;
- adding a rebuildable derived format feature recorded in the version manifest.

The following are breaking and require a new major contract or an explicit
migration/read-compatibility window:

- removing, renaming, renumbering, or retyping a field;
- reusing a retired Protobuf number or changing unary/streaming shape;
- changing authorization, purpose, idempotency, snapshot, continuation, or
  error semantics for an existing operation;
- changing canonical archive bytes without a declared reader/migrator;
- making an optional feature necessary to read primary state;
- converting a typed failure into partial success, or vice versa;
- broadening a model/provider adapter into durable core authority.

The checked-in released Proto fixture is compared structurally. The conformance
suite accepts additive mutations and rejects removals, renames, renumbers,
retypes, enum drift, and streaming-shape changes.

## Stable behavioral rules

All exposed interfaces preserve these rules:

1. authorization and purpose checks occur before candidate or payload
   materialization;
2. raw evidence has an independent capability check;
3. idempotency is scoped to the authenticated workspace, actor and operation;
   an exact replay returns the original receipt and a changed digest conflicts;
4. continuations and stream cursors are opaque and bind the principal,
   snapshot, filters and request semantics;
5. the complete 21-code error taxonomy and optional remediation fields retain
   their meaning across transports;
6. archive import verifies format, exact digest and canonical structure before
   publication, and a failed import publishes no partial state;
7. authenticated v1 methods use `AuthenticatedRequestContext`; legacy
   `RequestContext` is semantic request data and is not network authentication;
8. generated or handwritten SDK DTOs reject unknown/malformed fields and
   preserve `Vec<u8>` as JSON integer arrays without lossy integer conversion.

## Deprecation and release policy

Pre-release APIs may change, but every incompatible change must update the
released schema fixture, version manifest contract, changelog, conformance
goldens, all affected SDKs, and migration/rollback notes in the same change.
After v1.0, a stable operation is deprecated for at least one minor release
before removal and remains covered by compatibility tests during that window.
Durable-format readers remain available for the published compatibility range;
risky migrations are side-by-side and never in-place.

Official SDK artifacts are produced from one pinned source revision. Python,
Go and TypeScript package tests, examples, strict type checks, and package-file
inventories must pass from a clean checkout. A source-level package test is not
publication or supported-platform installation evidence.

The separately packaged Windows local MCP developer preview is bound to the exact
core version and artifact SHA-256 rather than a broad SemVer range. Its machine-readable
compatibility boundary is `release/local-mcp-profile.json`; the corresponding package
tool rejects server/listener feature drift and incompatible MCP protocol constants.
That receipt remains local developer-preview evidence and never satisfies M18 Alpha.

## Current profile and evidence

Executable semantics, schema checks, streaming/subscription probes, archive
round trips, and interface capability manifests live in
[`crates/contextdb-conformance`](../../crates/contextdb-conformance/README.md).
The exact HTTP SDK contract is documented in [`sdk/CONTRACT.md`](../../sdk/CONTRACT.md).

The current pre-release profile classifies pure continuity Preflight separately
as executable and no-authority (`grants_authority=false`). The production CLI
backend implements durable bootstrap/postflight/checkpoint/resume/handoff;
postflight remains a content-free caller assertion rather than verified
host/tool execution. Embedded and reference-backed HTTP/gRPC/MCP lifecycle
operations remain profile gaps, while the CLI lifecycle remains external-proof
required until a restart-bound conformance transcript exists. Production also
implements exact bounded `production_policy_graph_v1` Reindex, scheduler-owned
physical compact observation, and restart-safe runtime-ledger GC. It does not
claim corrupt-state recovery, offline repair, lexical/vector/HNSW reindex, or
an SLO. Consolidate, Reflect, live Restore, and format rewrite remain
unsupported, so aggregate `MaintenanceAdmin` is still a profile gap. Richer
conversation/subject/artifact operations, CLI/MCP authenticated-domain parity,
archive encryption/migrators, and deployment-owned gateway trust establishment
are not claimed as stable successes. The isolated secure-store P0-P3 contract
foundation supplies no production KMS, repository, provider adapter, or live
hard-delete capability. Those gaps keep strict full-chapter conformance false;
they do not permit an existing implemented method to drift silently.

`StatusResponse` additively carries `capability_manifest`. The nested schema is
version 1 and uses a map of stable capability IDs to `available`,
`compiled_only`, or `unsupported`; `server_v1_release_ready=false` remains an
independent release claim. The field is represented directly in JSON and as
field 5 plus `CapabilityManifestV1`/`RuntimeCapabilityState` in Protobuf.
The candidate-only contract has four stable schema-v1 IDs:
`quarantined_memory_proposals`, `policy_first_candidate_recall`,
`candidate_hierarchy_dag`, and `policy_first_candidate_traversal`. Native and
Codex hybrid profiles may advertise those four as `available`; reference,
transport-only, and production-lifecycle profiles leave them `unsupported`.
They do not imply `background_semantic_adjudication`,
`observation_semantic_extraction`, `consolidate`, `reflect`, or
`native_graph_store`, and never make `server_v1_release_ready` true.
