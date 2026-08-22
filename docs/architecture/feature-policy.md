# Feature and distribution policy

Status: Public architecture and distribution policy. Changes require an explicit reviewed design record when they affect durable formats, release capabilities, security boundaries, or dependency direction. A named target is not a Cargo feature, tested build profile, or release claim unless this document explicitly records the implemented mapping and evidence.

## Principles

1. Cargo features select implementation capabilities; they MUST NOT change the meaning of an already valid durable record.
2. Features are additive. Two enabled features cannot silently select incompatible schemas or competing backends without an explicit runtime/configuration choice.
3. `contextdb-core` remains independent of storage, network, model providers, generated wire types, CLI, telemetry exporters, and domain packs.
4. Primary logical state is readable without ANN, lexical, telemetry, MCP, Python, or any model provider.
5. A disabled derived projection produces an explicit unavailable/degraded capability report, never false freshness.
6. Provider-specific features cannot receive a raw `StorageEngine` handle.
7. Feature combinations used in release artifacts are recorded in the version manifest and tested as named profiles.

## Implemented P0 compile boundaries

These boundaries exist in Cargo today. They preserve the previous default APIs while allowing smaller, explicit component builds.

| Package | Invocation or feature | Compiled boundary |
|---|---|---|
| `contextdb-proto` | `--no-default-features` | Protobuf messages and descriptor set; no normal/runtime Tonic dependency |
| `contextdb-proto` | default or `grpc` | Messages, descriptor set, and generated gRPC client/server stubs |
| `contextdb-server` | `--no-default-features` | Shared gateway-authentication primitives only |
| `contextdb-server` | `wire` | Generated-message/application-service conversion without gRPC stubs |
| `contextdb-server` | `server` | `wire` plus the Tonic gRPC application edge |
| `contextdb-server` | `http` | Axum HTTP/JSON edge without a `contextdb-proto` or Tonic dependency |
| `contextdb-runtime` | default / `storage-fjall` | Reusable Fjall owner with native journal, graph, durable format manifest and embedded builder |
| `contextdb-runtime` | `server-v1` | Aggregate compile boundary for Fjall, HTTP, gRPC, Tantivy, ANN and zstd; the manifest reports unwired components as `compiled_only` |
| `contextdb-cli` | `current-server` | Current Fjall-backed HTTP and gRPC daemon command |
| `contextdb-cli` | `server-v1` | `current-server` plus the `contextdb-runtime/server-v1` aggregate foundation |
| `contextdb-cli` | `mcp` | External MCP stdio command |
| `contextdb-cli` | default | `current-server` and `mcp`, preserving the existing CLI surface |

The Dockerfile still builds `contextdb-cli --no-default-features --features current-server`; MCP is packaged separately. `cargo check -p contextdb-cli --no-default-features --features server-v1` now names and compiles the aggregate dependency boundary, but it does not silently replace the current CLI executor. The reusable runtime manifest calls the profile `server-v1-foundation`, sets `server_v1_release_ready=false`, and records HTTP, gRPC, Tantivy, ANN and zstd as `compiled_only` until the native service executor wires them. Durable lexical/HNSW integration, bounded zstd classes, full network health semantics, OTLP, and release evidence remain separate gates.

## Named build profiles

The following names are distribution targets. `server-v1` now has a Cargo aggregate used for compile testing, but it is not yet a proven release profile or a claim that every dependency is wired at runtime.

| Profile | Required capabilities | Forbidden implicit dependencies | Release role |
|---|---|---|---|
| `embedded-minimal` | universal core, reference/exact recall, one explicitly selected storage backend | server, HTTP, MCP, Python, OTLP exporter, hosted providers, HNSW, Tantivy | Small local/embedded correctness build |
| `server-v1` | Aggregate compiles Fjall, server, HTTP, gRPC, Tantivy lexical, HNSW and zstd; reusable owner currently exposes only Fjall, journal, graph, manifest and restart verification | provider credentials or remote model calls by default | Bounded foundation is materialized; native service/index wiring and release proof remain open |
| `conformance` | memory, Fjall, redb, exact, Tantivy, HNSW, all stable interfaces, mocks | live provider/network dependencies in normal tests | CI and release conformance |
| `research` | explicitly selected experimental capabilities | mutation of stable formats without a reviewed design record and migration | Benchmarks and ContextDB Lab only |

`server-v1` may change its provisional storage default after M2 evidence. The aggregate feature name remains stable. Until the complete executor is wired, the runtime-visible profile includes the `-foundation` suffix and the versioned manifest records the selected backend plus exact `available`, `compiled_only`, and `unsupported` capability states. The same schema-v1 `CapabilityManifestV1` DTO is now returned by authenticated service status and by the closed HTTP health profile. Service profiles classify the complete stable vocabulary, including unsupported hard delete, live restore, persistent lexical/ANN recall projections, semantic extraction/adjudication, artifact blobs, and model migration; absence can no longer hide in the human-readable profile string.

## Canonical feature names

| Feature | Default profile(s) | Contract |
|---|---|---|
| `storage-fjall` | `server-v1`, `conformance` | Provisional production substrate after M2 evidence |
| `storage-redb` | `conformance` | Maintained storage conformance target |
| `server` | `server-v1`, `conformance` | gRPC application service edge |
| `http` | `server-v1`, `conformance` | HTTP/JSON adapter over canonical services |
| `mcp` | `conformance`; packaged separately for v1 | External agent adapter only; never a core dependency |
| `python` | `conformance`; packaged separately for v1 | PyO3/binding package, no provider semantics in core |
| `telemetry-otlp` | `server-v1` | Optional exporter; telemetry never enters correctness path |
| `compression-zstd` | `server-v1`, `conformance` | Compression for approved segment classes only |
| `lexical-tantivy` | `server-v1`, `conformance` | Rebuildable lexical projection; exact lexical fallback remains testable |
| `ann-hnsw` | `server-v1`, `conformance` | Rebuildable ANN accelerator; exact full-precision oracle remains mandatory |
| `multimodal-metadata` | optional | Artifact metadata/selectors/lineage, not full multimodal understanding |
| `code-domain` | coding plugin | Domain pack outside universal core |
| `local-models` | optional | Provider adapter; no durable-format dependency |

## Compatibility rules

- A writer records every format-relevant feature in the version manifest.
- A reader fails closed on an unknown required feature and may ignore a declared optional feature only when its records are rebuildable projections.
- Removing a feature never makes primary data unreadable. If a feature introduced primary records, its reader remains available until an explicit format migration retires it.
- Exactly one writable storage backend is selected for a database instance. Additional backend features may be compiled for import/export or conformance but do not open the same directory concurrently.
- Feature-gated public APIs return a typed `capability_unavailable` result when disabled.

## CI policy

- A named profile MUST compile in CI before any artifact is described with that profile name. The bounded `server-v1` aggregate is checked with `cargo test -p contextdb-runtime --features server-v1` and `cargo check -p contextdb-cli --no-default-features --features server-v1`; artifacts MUST retain the `server-v1-foundation` qualification while the manifest reports any required capability below `available`.
- Workspace tests run with all stable features. Targeted checks cover `contextdb-proto` message-only/gRPC, `contextdb-server` no-default/wire/server/http/default, `contextdb-runtime` default/server-v1, and `contextdb-cli` no-default/current-server/server-v1/mcp/default combinations.
- Feature changes include a dependency diff, binary-size delta for affected profiles, compatibility test, and benchmark delta when a hot path changes.
- Normal tests use recorded or mock provider responses and do not require network access.
