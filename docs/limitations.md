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
- M17's 10M run measured storage records, not the RFC semantic graph/vector
  certification shape; E01/E02/E03 remain open.
- Linux arm64 and macOS arm64 release installation have not been proven in this
  Windows development environment. WSL x86-64 checks are development evidence.
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
