# Changelog

All notable changes to ContextDB are documented here. The project follows semantic versioning once
the public API reaches v1.0.

## [Unreleased]

No changes yet.

## [0.2.0-alpha.3] - 2026-08-26

### Fixed

- `mcp-broker-stop` now securely reclaims an owner-only stale Unix-domain
  socket left behind when the broker is terminated before its cleanup guard can
  run. Cleanup rechecks socket type, owner, mode, link count, device, inode, and
  live connectivity before unlinking the exact endpoint.
- Linux maintenance operations no longer wait for the broker startup timeout
  after an abrupt broker death; they still prove that the durable state-head
  authority is quiescent before continuing.

### Security

- Regression coverage now SIGKILLs a real Unix broker, proves the stale inode
  survives the crash, and requires authenticated stop to reclaim it without
  weakening live, foreign, symbolic, insecure, hard-linked, or raced endpoint
  handling.
- Linux release packaging now inspects the native ELF version requirements and
  rejects imports newer than `GLIBC_2.35`, continuously preserving the declared
  Ubuntu 22.04 LTS compatibility floor.

## [0.2.0-alpha.2] - 2026-08-25

### Fixed

- Unix MCP brokers now use a bounded owner-only per-user runtime directory instead of
  placing their socket beside the durable state-head authority. A validated
  `XDG_RUNTIME_DIR` is preferred; a root-owned sticky `/tmp` provides the protected
  per-user fallback when it is absent, unsafe, or too long.
- Normal Linux home directories, long XDG/custody paths, and macOS temporary paths no
  longer exceed the platform AF_UNIX pathname limit.

### Security

- Runtime roots, broker directories, socket ownership, permissions, symbolic links,
  sticky fallback custody, and archive/runtime separation are checked before use.
- Regression coverage now includes long authority/runtime paths, insecure or symbolic
  XDG roots, symbolic broker directories, concurrent autostart, and authenticated cleanup.

## [0.2.0-alpha.1] - 2026-08-25

### Added

- A native Linux x86_64 listener-free local MCP developer-preview profile with an
  independently resolved Linux Cargo graph, exact CycloneDX SBOM, third-party notices,
  Rust runtime custody evidence, deterministic ZIP staging, and executable-bit preservation.
- An authenticated Unix-domain-socket single-owner MCP broker, mutual handshake, bounded
  request serialization, automatic proxy startup, persistence, restart, and operator shutdown.
- Native Linux and Windows release jobs that independently build, smoke-test, and verify four
  target-bound assets before one atomic GitHub prerelease publication.
- Cross-platform profile, host-selection, executable-permission, package-verification, and
  concurrent-broker regression coverage.

### Changed

- All workspace crates, Python bindings/SDK, and TypeScript SDK advance together to
  `0.2.0-alpha.1` (`0.2.0a1` for Python package metadata).
- Local MCP packaging now binds an exact platform, Rust target, executable identity, profile,
  dependency graph, archive digest, and unsigned developer-preview support boundary.
- Existing Windows x86_64 named-pipe broker, custody, package identity, and release assets
  remain independently supported rather than being weakened by the Linux integration.

### Security

- Linux token-key and state-head authorities remain external to the database archive and
  require owner-only Unix custody; no remote listener or public MCP endpoint is introduced.
- Cross-target package/SBOM substitution and archives without executable permissions fail
  closed during package verification.

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
