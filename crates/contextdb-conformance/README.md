# contextdb-conformance

`contextdb-conformance` is the M15 compatibility oracle for ContextDB v1. It
drives one typed operation/transcript through the embedded service, HTTP/JSON,
gRPC/Protobuf, the CLI process, and MCP 2026-07-28, then emits deterministic,
machine-readable proof reports.

The harness deliberately contains no storage, authorization, recall, or archive
business logic. Each adapter traverses the production boundary it claims to
test:

- embedded calls `CognitiveMemoryService` directly;
- HTTP traverses the Axum router, body limit, JSON extractor, status mapping,
  and typed error body;
- gRPC traverses generated service traits and Protobuf conversions, while the
  streaming probe uses a real loopback HTTP/2 server and generated client;
- CLI starts an explicitly supplied executable without a shell and validates
  JSON, Protobuf, typed stderr, archive files, the authenticated grouped API,
  and a real `contextdb mcp` child over stdin/stdout;
- MCP sends stateless JSON-RPC calls with mandatory per-request R19 metadata,
  strict authenticated runtime/correction DTOs, and typed business errors.

The generic SDK contract contains exactly 58 protected `POST /v1` routes. The
typed ContextPack surface adds one separately documented protected
`POST /v1/context-pack` route, for 59 server routes in total.
The same `current-server` router separately registers unauthenticated,
content-free `GET /health/live` and `GET /health/ready` host probes. They are not
SDK operations or part of the common semantic transcript. Their bounded
process/publication reconciliation checks do not complete RFC 31.15 and do not
materialize the `server-v1` distribution profile.

## Proof surface

The common scenario covers ordered commits, exact idempotent replay, changed
digest conflict, policy omission, authorized recall, forbidden-candidate
non-influence, unknown results, continuation snapshot/filter/principal binding,
forgery rejection, authenticated traces, canonical archive digest/deep replay,
and stable error normalization. Separate probes cover all 21 public error codes,
extended error context, raw HTTP extractor failures, gRPC stream ordering and
partial acknowledgement, archive corruption/atomic rejection, additive schema
compatibility, MCP discovery/cache metadata, and CLI output modes. A second
authenticated transcript proves exact node/traverse/correct/timeline/forget/
status/backup parity across embedded Rust, HTTP/JSON, and gRPC/Protobuf.

RFC §21.22-§21.25 are exposed additively on embedded, HTTP, and gRPC through
high-level conversation, memory-control, subject/relationship, and artifact
DTOs. The manifest classifies the safe Observe/Recall subset separately from
operations that require missing policy, runtime, blob, or physical-erasure
executors; those gaps never count as conformance success.

`ConformanceFixture::standard()` expects the canonical three-record semantic
seed at commit 1. This is intentional: the observation gateway durably captures
raw observations but does not synchronously publish semantic records. A test
backend must install the fixture through its normal semantic/import path before
running the suite.

The CLI exposes all 59 bounded domain, ContextPack, stream, runtime, maintenance/admin, and
high-level operation names through `contextdb api`. Its 29 high-level mappings
are checked directly against the canonical `high_level_v1_surface.json`
fixture. MCP exposes the RFC §21.11 preflight/postflight/checkpoint/resume/
handoff/correct subset without depending on core or durable-format internals.
Capability manifests classify the pure continuity Preflight evaluator as
exercised; preflight can block but never grants host/tool authority. The
production CLI implements durable bootstrap/postflight/checkpoint/resume/
handoff and exposes a versioned runtime capability manifest, but the external
conformance transcript has not yet exercised a restart-bound lifecycle
sequence, so `RuntimeLifecycle` is `ExternalProofRequired` rather than a
synthetic pass. Embedded/reference HTTP/gRPC and the reference-backed MCP
harness retain their exact lifecycle gaps.

The reference and production profiles execute four high-level semantic
controls: Suppress, ChangeAudience, PublishToSharedMemory, and
RevokeSharedMemory. They accept exact bounded v1 parameter DTOs only after
authentication/capability/subject binding, authorize the current record before
content materialization, and publish one canonical bitemporal policy/lifecycle
revision. Suppression and current access policy overlay retained semantic
snapshots. The production profile commits the same revision through its Fjall
event/projection transaction and external state-head reconciliation. Pin,
ChangeRetention, ExportSubject, and ImportSubject remain explicit gaps because
the generic logical archive cannot losslessly encode pin/retention policy or
prove filtered subject closure and collision-free isolation.

Reindex has the same deliberately narrow accounting. Embedded and the HTTP and
gRPC adapters in this harness run over `ReferenceService`; their Reindex method
returns canonical `Unsupported` after authentication and the Maintenance
capability check. The official production CLI/Fjall profile implements only a
synchronous rebuild-and-publish of an already healthy singleton
`production_policy_graph_v1`. Its durable receipt is content-free, the response
reports `semantic_mutations=0`, `primary_state_mutations=0`, and
`active_generation_changed=false`, and exact replay returns the same receipt.
This is not offline repair, a lexical/vector/HNSW rebuild, or an SLO claim.
Consolidate, Reflect, Compact, live Restore, and MigrateFormat remain gaps, so
the aggregate `MaintenanceAdmin` capability remains `ProfileGap` for every
manifest.

The extended chapter-21 probe drives the production resumable source-snapshot
state machine (`manifest -> observations -> SnapshotComplete`), authenticated
per-frame cursors and partial acknowledgements, fail-closed compression
negotiation, all-or-nothing reference completion, at-least-once subscriptions
with stable event IDs, and keyed trusted-gateway attestations. HTTP proves its
two-phase context-before-content decoder. Capability manifests deliberately
remain non-strict while bootstrap/checkpoint/resume/handoff, verified postflight
execution, the reference physical-maintenance executors, and the rest of the
production maintenance/admin family are absent. The CLI/MCP-specific transcripts
also do not yet exercise every exposed authenticated operation.

## Commands

```powershell
cargo test -p contextdb-conformance
cargo clippy -p contextdb-conformance --all-targets -- -D warnings
cargo fmt -p contextdb-conformance -- --check
```

The default test run records a missing CLI executable as external proof required,
never as a pass. Exercise the actual process explicitly:

```powershell
cargo build -p contextdb-cli
$env:CONTEXTDB_CONFORMANCE_CLI = (Resolve-Path target/debug/contextdb.exe).Path
cargo test -p contextdb-conformance cli_binary_absence_is_explicit_and_never_a_synthetic_pass
```

The subprocess adapter injects one deterministic non-secret
`CONTEXTDB_TOKEN_KEY_HEX` fixture into each child and removes
`CONTEXTDB_TOKEN_KEY_FILE`; it never creates a sidecar key and does not mutate
the parent environment. Each adapter also owns a distinct external state-head
authority: an exact HKCU selector on Windows or an owner-only temporary
directory outside the archive/scratch tree on Unix. The selector, token, and
authority path are redacted from debug output; the exact authority and lock are
removed when the last adapter clone is dropped.

Portable archive import is exercised only as a clone into a fresh,
non-existent destination. The harness neither passes `--force` nor claims that
the CLI can replace a live anchored database. A failed corrupt clone leaves the
destination unmaterialized, which is proven by subsequently initializing that
same destination normally.

See [docs/API.md](docs/API.md) for the public API. Executable conformance
coverage and remaining boundaries live in this crate's tests and shared
contract fixtures.
