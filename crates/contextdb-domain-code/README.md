# ContextDB coding domain pack

`contextdb-domain-code` is the strict M14 reference extension. Compiler, Git,
CI, repository, file, symbol, test, and decision types remain here; none are
added to `contextdb-core`.

## Trust boundary

The Go helper under `tools/contextdb-go-indexer` uses the standard-library
`go/ast` and `go/types` packages. It emits strict provider-neutral JSON.
`GoCompilerIndex::from_json` rejects unknown fields, invalid paths, duplicate
keys, unsupported relation kinds, and malformed fingerprints before
`GoSnapshotAdapter` constructs a snapshot. A semantic fingerprint may preserve
a stable symbol identity only when exactly one direct-parent symbol matches.
Ambiguity creates a new identity rather than guessing.

The domain store itself has no authorization authority. A host evaluates
policy before exposing source bytes, then maps verified `CodeDomainRecord`
values to `NodeType::Domain { pack: "contextdb-domain-code", ... }` with a
core `SemanticEnvelope`. The projection has no mutation or publication method.

## M14 acceptance matrix

| Requirement | Implementation and evidence |
| --- | --- |
| code domain pack outside universal core | `CodeDomainProjection`; dependency direction is domain → core only |
| Git adapter | strict `GitCommitDescriptor::from_name_status_z`, rename/copy scores, path validation, message digest |
| Go compiler adapter | executable `tools/contextdb-go-indexer` using `go/ast` + `go/types`; strict Rust ingestion contract |
| stable symbol identity | direct-parent, unique semantic-fingerprint continuity; rename/move tests; ambiguous matches never auto-merge |
| incremental snapshots | immutable parent-linked `RepositorySnapshot`, stale-parent CAS check, current and historical query |
| call/import/type/test relations | typed `CodeRelation`, referential validation, bounded impact traversal |
| repository hierarchy | `CodeMemory::hierarchy` returns exact snapshot-bound file/symbol containment |
| decision links | evidence-required `DecisionRecord`; absent rationale is explicit `RationaleResult::Unknown` |
| CI ingest | evidence-required `CiRun`; test identities validated against the exact snapshot |
| coding preflight | `CodeMemory::preflight` separates compiler impact from actually retained CI execution evidence |
| impact analysis | deterministic reverse call/import/type plus test traversal with a hard edge budget |
| exact evidence | UTF-8 declaration range revalidated against exact file bytes; source and file digests retained |
| archive | canonical self-verifying payload; every snapshot manifest replayed on restore |
| BENCH-F | `examples/bench_f.rs`, `proof/M14/BENCH-F.json`, six monthly snapshots and five frozen executable baselines |

## Deliberate boundaries

- The Go helper indexes one package per invocation. A workspace driver may run
  it for every `go list` package and merge package-scoped results.
- Rust and TypeScript compiler-native helpers are domain extensions, not M14 v1
  requirements; the schema admits their language records without changing core.
- The correctness benchmark is deterministic and local. M17 owns official
  server-scale latency, concurrency, and resource certification.
- Git commit messages are content-minimized to a digest by default. A policy-
  authorized evidence adapter may retain exact ADR/issue/conversation spans.
