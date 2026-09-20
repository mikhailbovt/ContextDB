# Current limitations and support boundary

ContextDB is an active pre-v1 implementation. The roadmap ledger, proof files
and release verifier—not the presence of an API name—determine completion.

## Implemented source slices

- universal typed/bitemporal memory semantics and deterministic reference oracle;
- ordered journal, graph, recall, hierarchy, ANN/index and ContextPack contracts;
- provider-neutral model gateway and deterministic proposal adjudication;
- persistent conversation, knowledge and coding reference verticals;
- continuity/checkpoint/handoff contracts;
- HTTP, gRPC, CLI, MCP, Python, Go and TypeScript interfaces;
- security primitives, conformance, benchmark and release-verification tooling.

## Deliberate or unresolved limits

- Hosted model/provider SDKs are not part of core; live provider acceptance and
  quality remain external evidence.
- Runtime lifecycle and several maintenance/migration methods have typed API
  contracts but no general production executor.
- The standalone production host does not claim hard deletion until physical
  content erasure and closure receipts are wired through the selected backend.
- Logical export is not automatically an encrypted, signed physical backup.
- Native continuous capture enforces inherited source restrictions through bounded
  custody propagation. Legacy continuous stores require explicit custody migration
  and index rebuild; interrupted revocation keeps disclosure closed. Bound native
  restore checks an independently retained current suppression ledger before reads;
  unbound archives containing captures require explicit migration. The optional
  encrypted Rust profile seals native values and backups using an independently
  retained key inventory and master key. It does not hide record addresses or
  detect rollback of all authorities. CLI/MCP key provisioning, plaintext
  migration, key reclamation, remote authority custody and physical deletion
  remain open. Explicit source/assertion/chunk pruning supports interrupted
  cleanup and restore, retaining independent assertions and shared blocks.
  Version 3 authorities retain administrator-declared generic-record origins
  across restore, enforcing current source policies before body reads. Empty record
  workspaces can activate origin requirements before their first record. Explicit
  publication, candidate supersession, correction and retraction support atomic
  source-aware groups and resumable origin transfer. Rewired hierarchy edges
  retain their copied sources. The owned runtime automatically discovers and
  repairs accepted groups under a shared budget. Recovery progress is process-local;
  restart rescans history, and a missing-completion check may rescan its suffix.
  Durable progress, measured backlog limits and origin aggregation beyond the
  current 64-source profile remain unfinished.
  Unclassified records remain unavailable. New mutations bind compact body-free
  controls; older-mutation preparation, generic-record cleanup and
  verified deletion completion that reopens disclosure remain unfinished.
  See [the native profile](architecture/continuous-context.md).
- M17's 10M run measured storage records, not the RFC semantic graph/vector
  certification shape; E01/E02/E03 remain open.
- Native Linux x86_64 and Windows x86_64 local-MCP developer previews have distinct
  target-bound packages; this does not imply signed production release certification.
- The Linux x86_64 preview is tested from Ubuntu 22.04 LTS / glibc 2.35 upward; its GNU-target
  compatibility claim does not cover musl-based distributions.
- Linux arm64 and macOS arm64 package installation remain unproven and unsupported.
- Docker files have static checks only; no Docker build/run is claimed without
  explicit authorization.
- Human social-calibration/naturalness review and real-model BENCH-D/E evidence
  remain external gates.
- Registry publication, production signing custody and public immutable dataset
  hosting are not fabricated by local tooling.

## Evidence vocabulary

`source-present` means code or documentation exists. `package-conformance`
means a scoped automated suite passed. `native_measured_development` is a real
local measurement but not automatically release-qualified. `passed` for a
milestone requires every exit, dependency and required proof to be explicitly
bound and passed.

Formal release milestones remain open until those conditions are met. See
`docs/release/README.md`, `docs/release/package-support.md`, and
`release/documentation-matrix.json` for the public release boundary.
