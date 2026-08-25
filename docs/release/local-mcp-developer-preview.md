# Local MCP developer-preview profiles

Status: independently packageable native Linux and Windows developer previews; neither is the
formal ContextDB M18 Alpha release.

ContextDB ships the same narrow, listener-free local-memory surface as two separately verified
native artifacts. Each package includes its own immutable target-bound dependency evidence,
native executable, authenticated single-owner broker, and integrity receipt.

| Boundary | Linux x86_64 | Windows x86_64 |
| --- | --- | --- |
| Rust target | `x86_64-unknown-linux-gnu` | `x86_64-pc-windows-msvc` |
| Profile | `contextdb-local-mcp-linux-x86_64` | `contextdb-local-mcp-windows-x86_64` |
| Native executable | `contextdb` | `contextdb.exe` |
| Shared MCP transport | Standard input/output | Standard input/output |
| Authenticated broker | Owner-only Unix-domain socket | Local Windows named pipe |
| Token-key authority | External owner-only `CONTEXTDB_TOKEN_KEY_FILE` | Existing Windows external custody |
| State-head authority | External owner-only `CONTEXTDB_STATE_HEAD_FILE` | Existing Windows external custody |
| Package identity | `contextdb-local-mcp-0.2.0-alpha.1-linux-x86_64.zip` | `contextdb-local-mcp-0.2.0-alpha.1-windows-x86_64.zip` |
| Listener commands | `serve` and `probe` absent | `serve` and `probe` absent |

Both targets expose standard MCP `2025-03-26`, `2025-06-18`, and `2025-11-25`, plus the
stateless `2026-07-28` adapter. Both require exact core version `0.2.0-alpha.1` and an exact
binary SHA-256. A SemVer-compatible range, file name, or source build is not a substitute for
target-specific package verification.

The machine-readable Windows contract is
[`release/local-mcp-profile.json`](../../release/local-mcp-profile.json); the Linux contract is
[`release/platforms/linux-x86_64/local-mcp-profile.json`](../../release/platforms/linux-x86_64/local-mcp-profile.json).
Both retain `release_ready=false`, `m18_alpha=false`, and unsigned release claims.

## Verify the current native host

Use Python 3.11 or newer and the pinned Rust toolchain from `rust-toolchain.toml`:

```console
python tools/local-mcp-preview/local_mcp_preview.py verify
python tools/local-mcp-preview/generate_supply_chain.py verify
python -m unittest discover -s tools/local-mcp-preview/tests -v
```

The host selects its corresponding target automatically. Select a profile explicitly when
auditing its source contract:

```console
python tools/local-mcp-preview/local_mcp_preview.py --platform linux-x86_64 verify
python tools/local-mcp-preview/local_mcp_preview.py --platform windows-x86_64 verify
```

`package` never cross-builds or trusts a foreign-host smoke result. Run it on the actual target:

```console
python tools/local-mcp-preview/local_mcp_preview.py package --output-dir dist
python tools/local-mcp-preview/local_mcp_preview.py verify-package \
  dist/contextdb-local-mcp-0.2.0-alpha.1-linux-x86_64.zip
```

Replace the Linux archive name with the Windows archive when running on Windows. Packaging
requires a clean checkout, refuses output overwrite, compiles the fixed command below, executes
the real binary, and re-verifies the completed archive:

```console
cargo build --locked --release -p contextdb-cli --bin contextdb \
  --no-default-features --features local-mcp
```

`--allow-dirty` is reserved for local tool development. Its receipt records dirty source and
permanently marks the resulting package non-distributable.

## Native broker and custody

`contextdb mcp` starts or connects to the target's authenticated local single-owner broker. The
broker is the only process that opens the durable state-head and Fjall storage authorities;
independent MCP clients send bounded mutually authenticated requests through local IPC. This
preserves concurrent task continuity without adding a TCP listener.

On Linux, the socket, token key, and state-head authority remain owner-only and outside the
database archive. On Windows, the existing authenticated local named-pipe and native custody
contracts remain in force. `contextdb mcp-broker-stop <archive>` authenticates and quiesces the
broker before operator work, backup, restore, replacement, or upgrade on either platform.

See [Local MCP broker operations](../operations/local-mcp-broker.md) for lifecycle and
shutdown details. The database archive never contains the external token key or state-head.

## Package and evidence boundary

Every ZIP contains its native executable, project license, security policy, changelog,
compatibility documents, target profile, exact-graph `THIRD_PARTY_NOTICES.txt`, CycloneDX SBOM,
target supply-chain manifest, pinned Rust runtime notices, internal content receipt, and
`SHA256SUMS`. An external SHA-256 sidecar binds the complete archive. Unix executable permission
is preserved and checked independently.

Windows evidence is stored in the main `release/` directory. Linux evidence is stored in
`release/platforms/linux-x86_64/`, then mapped to the same canonical `release/` paths inside its
own archive. These are different native dependency graphs: a Windows target receipt is never
relabelled as Linux or accepted as Linux provenance.

Neither package is signed or independently attested. Neither claims hostile-local-user isolation,
hosted multi-tenancy, production KMS, guaranteed physical hard deletion, disaster-recovery
certification, automatic updates, Linux arm64, or macOS support. Use synthetic or non-critical
data until those separate gates close.

Both profiles remain intentionally outside `release/package-matrix.json` and the M18/M19
release ledger. Source availability, native runtime validation, and GitHub prerelease
publication do not satisfy the formal signed production-release verifier.
