# ContextDB documentation

ContextDB is easiest to understand in three passes: what memory means, how the engine enforces
it, and how to operate the current alpha safely.

## Learn the model

1. [Memory concepts](memory-concepts.md) — episodes, semantic revisions, evidence, and recall.
2. [Data model](data-model.md) — identity, bitemporality, perspective, ownership, and lineage.
3. [Architecture overview](architecture/v1-overview.md) — component boundaries and end-to-end
   flow.
4. [ContextPack API](api/context-pack.md) — the compact, traceable output consumed by a model.

## Build an integration

- [Formats](formats.md) — portable and wire-level representation.
- [API compatibility](api/compatibility.md) — versioning and compatibility rules.
- [Conversation integration](integrations/conversation.md) — durable conversation semantics.
- [Domain pack authoring](domains/authoring.md) — extend ContextDB without weakening the core.
- [Local MCP broker](operations/local-mcp-broker.md) — Windows single-owner concurrency and
  local IPC.
- [SDK overview](../sdk/README.md) — Go, TypeScript, and Python surfaces.

## Operate it

- [Local run and health](operations/local-run-and-health.md)
- [Backup and restore](operations/backup-restore.md)
- [Disaster recovery](operations/disaster-recovery.md)
- [Upgrade and migration](operations/upgrade-migration.md)
- [Resource degradation](operations/resource-degradation.md)
- [Runtime-ledger maintenance](operations/runtime-ledger-maintenance.md)

## Trust and release boundaries

- [Privacy](privacy.md)
- [Security threat model](security/threat-model.md)
- [Current limitations](limitations.md)
- [Local MCP developer-preview profile](release/local-mcp-developer-preview.md)
- [Package support](release/package-support.md)
- [Signing and provenance](release/signing-and-provenance.md)
- [Third-party dependencies](release/third-party-dependencies.md)
- [Release documentation](release/README.md)

## Performance

- [Performance report](benchmarks/v1-performance-report.md)
- [Benchmark result format](benchmarks/result-format.md)

Benchmark artifacts are evidence for the exact recorded machine, build, dataset, and command.
They are not a blanket performance promise for another deployment.
