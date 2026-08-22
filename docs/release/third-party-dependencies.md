# Local-MCP third-party dependency bundle

The Windows x86_64 local-MCP developer preview ships a reviewable dependency
bundle next to `contextdb.exe`:

- `release/THIRD_PARTY_NOTICES.txt` indexes every external Cargo package in the
  exact listener-free graph and includes the license texts selected by
  `cargo-about`;
- `release/contextdb-local-mcp.cdx.json` is a deterministic CycloneDX 1.5 JSON
  SBOM for that same graph;
- `release/contextdb-local-mcp-supply-chain.json` binds the graph, `Cargo.lock`,
  generator versions, artifact hashes, and release-status limitations;
- `release/rust-runtime/` contains the standard-library copyright inventory and
  Apache-2.0/MIT texts copied byte-for-byte from the pinned Rust toolchain.

This bundle is release engineering evidence, not legal advice or a statement
that the developer preview is signed, published, formally release-ready, or
free of vulnerabilities.

## Exact dependency boundary

The source of truth is the locked normal-plus-build dependency graph for:

```console
cargo tree --locked --offline -p contextdb-cli \
  --no-default-features --features local-mcp \
  --target x86_64-pc-windows-msvc -e normal,build
```

Developer and test-only dependencies are excluded. Build dependencies are
included because they can affect the executable bytes. ContextDB workspace
crates appear in the SBOM but not in `THIRD_PARTY_NOTICES.txt`; they are covered
by the repository `LICENSE`.

`cargo-cyclonedx 0.5.9` evaluates every member of a virtual Cargo workspace.
The checked-in generator therefore uses its output as the component metadata
source, then fails unless it can prune that workspace union to the exact graph
above. It also removes machine-local paths, reconstructs exact dependency
edges, and records the pruning in SBOM properties. The upstream command emits
transient files for every workspace member; the generator retains only the
exact release SBOM and removes those transient per-member outputs. Historical
M16 SBOM receipts remain historical evidence, not current dependency metadata.

## Pinned generators

Install the reviewed versions:

```console
cargo install --locked --features cli --version 0.9.2 cargo-about
cargo install --locked --version 0.5.9 cargo-cyclonedx
```

The `cargo-about` policy is `supply-chain/about.toml`. It accepts only the
permissive SPDX licenses currently required by the locked graph and runs with
`--frozen --fail`; an unresolved or unaccepted package stops generation.
`SOURCE_DATE_EPOCH=0` and offline Cargo metadata make the CycloneDX timestamp
and dependency resolution reproducible.

Generate, verify without rewriting, or perform a full byte-for-byte freshness
check from the repository root:

```console
python tools/local-mcp-preview/generate_supply_chain.py generate
python tools/local-mcp-preview/generate_supply_chain.py verify
python tools/local-mcp-preview/generate_supply_chain.py check
```

`generate` and `check` require the pinned Windows x86_64 Rust 1.97.1 toolchain,
including `rust-src`, because the Rust runtime notice files are copied from and
verified against that sysroot. `verify` is also intentionally strict on the
release host. The preview packager invokes this strict verification before it
accepts a binary.

## Verification performed by packages

The core and Codex plugin packagers fail closed unless:

- the manifest's `Cargo.lock` digest and canonical dependency-graph digest
  match the current source;
- every third-party graph component has one or more selected notice licenses;
- the notice index, CycloneDX component set, and graph counts agree;
- every notice, SBOM, and Rust runtime file matches its recorded byte length and
  SHA-256;
- the Rust notices match Rust 1.97.1 commit
  `8bab26f4f68e0e26f0bb7960be334d5b520ea452` for
  `x86_64-pc-windows-msvc`;
- the manifest continues to state that the preview is listener-free, unsigned,
  unpublished, and not formally release-ready.

The outer ZIP receipt and checksum then bind the supply-chain bundle and the
exact `contextdb.exe` bytes. This is integrity and provenance evidence for a
local developer preview; it is not code signing or an independent attestation.
