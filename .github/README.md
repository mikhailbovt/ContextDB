# GitHub repository governance

`workflows/ci.yml` defines M0 checks without changing GitHub remote state:

- required native gates: Linux x86_64, Linux arm64, and macOS arm64;
- reported best-effort gate: Windows x86_64;
- formatting, Clippy, workspace tests, rustdoc warnings, Python/Go/TypeScript SDK parity and packaging checks, cargo-audit, cargo-deny, governance/schema validation, and fuzz smoke;
- pinned action commits and pinned validator/tool versions.

`.github/labels.yml` is a declarative issue-label manifest only. This repository does not automatically create, update, or delete remote labels. A future synchronization workflow requires explicit maintainer approval and a separate least-privilege token policy.

The fuzz job intentionally fails when no fuzz target is registered. A silent green “fuzz smoke” that fuzzes fuck-all is not evidence.
