# Local MCP developer-preview packager

This standard-library-only Python tool verifies and packages the narrow Windows local MCP core
profile documented in `docs/release/local-mcp-developer-preview.md`.

```console
python tools/local-mcp-preview/local_mcp_preview.py verify
python tools/local-mcp-preview/local_mcp_preview.py package
python tools/local-mcp-preview/local_mcp_preview.py verify-package path/to/package.zip
python tools/local-mcp-preview/generate_supply_chain.py verify
python tools/local-mcp-preview/generate_supply_chain.py check
python -m unittest discover -s tools/local-mcp-preview/tests -v
```

It is deliberately separate from `tools/contextdb-release`: a passing preview receipt never
weakens or satisfies the formal M18/M19 verifier.

The supply-chain commands require pinned `cargo-about 0.9.2`,
`cargo-cyclonedx 0.5.9`, and the repository Rust 1.97.1 Windows toolchain. The
packager independently verifies the checked-in notice/SBOM/Rust-runtime bundle
before accepting it.
