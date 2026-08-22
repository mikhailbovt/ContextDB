# Local MCP developer-preview profile

Status: locally packageable developer preview; not ContextDB M18 Alpha.

The `contextdb-local-mcp-windows-x86_64` profile is the narrow core artifact used by a
trusted, single-user Codex integration on Windows. It keeps the MCP stdio adapter and the
Windows local named-pipe broker, but does not compile the CLI's HTTP/JSON or gRPC listener
features. Offline lifecycle, verification, backup, and recovery commands remain available
because they operate on the same local database and external custody authorities.

The machine-readable contract is
[`release/local-mcp-profile.json`](../../release/local-mcp-profile.json). The package tool
validates that contract against the workspace version, the MCP protocol constants, the Cargo
feature graph, and the resulting binary before it writes an archive.

## Supported surface

| Boundary | Developer-preview contract |
| --- | --- |
| Host | Windows x86_64 |
| Core | exact `0.1.0-alpha.1` binary and SHA-256 |
| Rust for source builds | pinned toolchain from `rust-toolchain.toml` |
| MCP | standard `2025-03-26`, `2025-06-18`, `2025-11-25`; stateless `2026-07-28` |
| Local transports | stdio and a Windows local named pipe |
| Network listeners | none; `probe` and `serve` are absent |
| Storage | local logical archive plus external token-key and state-head authorities |

This table is a compatibility statement, not a promise that all consumers compatible with a
SemVer range will work. A consumer must pin the exact core version and packaged binary hash,
then pass its own clean-install and end-to-end checks.

## Verify and package

From the repository root:

```console
python tools/local-mcp-preview/local_mcp_preview.py verify
python tools/local-mcp-preview/local_mcp_preview.py package
python tools/local-mcp-preview/local_mcp_preview.py verify-package path/to/package.zip
```

The effective build command is deliberately fixed:

```console
cargo build --locked --release -p contextdb-cli --bin contextdb \
  --no-default-features --features local-mcp
```

`verify` fails if the resolved graph enables `current-server`, `server-v1`,
`contextdb-server/http`, or `contextdb-server/server`, or includes the Axum/Tonic listener
runtime. `package` repeats that check, builds in an isolated target directory, and requires the
binary to report `build_profile local-mcp` and `network_listeners disabled`. It also rejects a
help surface containing `probe` or `serve`.

By default packaging refuses a dirty checkout and will not overwrite an existing archive.
`--allow-dirty` exists only for local tool development; its receipt records the dirty state and
must not be distributed. The ZIP constructor is deterministic for identical staged bytes, but
that alone is not proof that Rust compilation is reproducible across hosts.

The output contains the binary, license, security policy, changelog, compatibility/profile
documents, an internal content receipt, `SHA256SUMS`, and an archive hash sidecar. It also
contains the exact-graph `THIRD_PARTY_NOTICES.txt`, CycloneDX SBOM, supply-chain manifest, and
the Rust standard-library copyright/Apache/MIT files described in
[`third-party-dependencies.md`](third-party-dependencies.md). The packager checks their graph
coverage and hashes before staging them. The archive is neither signed nor published and cannot
satisfy the formal release verifier.

## Custody and security boundary

The binary never accepts a network listen address in this profile. The named pipe is local IPC,
not a TCP transport. Authority is still external to the archive: the token key and state-head
custody must not be copied into the package or database directory.

This preview is intended for a trusted single-user workstation. It makes no production claim
for hostile local users, multi-tenant service, remote gateways, production KMS, guaranteed hard
delete, signed updates, disaster recovery, or cross-platform installation. Use synthetic or
non-critical data until those gates and a current-revision security validation are complete.

## Relationship to formal release evidence

This profile is intentionally outside `release/package-matrix.json` and the M18/M19 evidence
ledger. Source presence, a passing local package smoke test, or the `alpha` Cargo prerelease
suffix does not turn it into ContextDB Alpha. Formal release readiness remains owned by the
existing release verifier and its complete platform, signature, package, runtime, security, and
publication evidence.
