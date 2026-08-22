# Changelog

All notable changes to ContextDB are documented here. The project follows semantic versioning once
the public API reaches v1.0.

## [Unreleased]

No changes yet.

## [0.1.0-alpha.1] - 2026-08-22

### Added

- M0 repository, engineering policy, version manifest, architecture documentation, and CI
  baseline.
- Initial deterministic in-memory database shell and `contextdb version` command.
- A separately versioned Windows x86_64 local MCP developer-preview profile, including an
  exact compatibility manifest, listener-free Cargo feature check, deterministic ZIP staging,
  binary surface smoke test, checksums, and a non-release receipt.
- A reproducible local-MCP dependency bundle with exact-graph third-party notices, CycloneDX
  SBOM, generator receipts, and Rust standard-library license files.
- A public documentation map, visual project identity, and GitHub Sponsors/Ko-fi funding metadata.
- A polished product README and temporal-memory graph hero that explain the write, recall, trust,
  and Codex integration paths without hiding the developer-preview boundary.
- A tag-driven Windows release workflow that verifies the listener-free profile and publishes the
  standalone executable, deterministic ZIP, SHA-256 sidecars, notices, and SBOM as a prerelease.

### Changed

- `contextdb version` now identifies a correctly resolved `local-mcp` build and reports whether
  network listeners are disabled, allowing consumers to reject an accidentally mixed build.
- Repository and Go module metadata now point to the canonical `mikhailbovt/ContextDB` source.
- Legacy M16 proof-shaped files and per-package development SBOM snapshots are no longer
  presented as current release evidence; historical M16 inputs are explicitly quarantined.
- Internal RFC, architecture-decision, roadmap, scan, and acceptance drafts are kept outside the
  distributable repository; public docs now describe the implemented product directly.

### Security

- The local MCP packager fails closed if default features, HTTP/gRPC server features, listener
  runtime dependencies, or the `probe`/`serve` commands enter the packaged profile.
- `contextdb-server/wire` no longer compiles gateway-authentication or health-endpoint modules;
  those modules now require the HTTP or gRPC server surface.
- The locked `h2` dependency is updated to 0.4.16, and the checked-in local-MCP supply-chain
  artifacts are verified against the current lockfile and exact listener-free graph.
