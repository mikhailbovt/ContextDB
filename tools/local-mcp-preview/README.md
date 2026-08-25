# Local MCP developer-preview packager

This standard-library-only Python tool verifies and packages independently pinned Linux and
Windows x86_64 listener-free local MCP core profiles documented in
`docs/release/local-mcp-developer-preview.md`. Packaging always runs on the native target.

```console
python tools/local-mcp-preview/local_mcp_preview.py verify
python tools/local-mcp-preview/local_mcp_preview.py package
python tools/local-mcp-preview/local_mcp_preview.py verify-package path/to/package.zip
python tools/local-mcp-preview/generate_supply_chain.py verify
python tools/local-mcp-preview/generate_supply_chain.py check
python -m unittest discover -s tools/local-mcp-preview/tests -v
```

Select a target explicitly with `local_mcp_preview.py --platform linux-x86_64 verify` or
`generate_supply_chain.py verify --platform windows-x86_64`. The default is the current native
x86_64 host. Linux source evidence is stored under `release/platforms/linux-x86_64/`; archive
members retain canonical `release/` paths on both platforms.

It is deliberately separate from `tools/contextdb-release`: a passing preview receipt never
weakens or satisfies the formal M18/M19 verifier.

The supply-chain commands require pinned `cargo-about 0.9.2`,
`cargo-cyclonedx 0.5.9`, and the repository's pinned Rust 1.97.1 native toolchain. The
packager independently verifies the checked-in notice/SBOM/Rust-runtime bundle
before accepting it.
