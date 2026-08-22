# Proof receipt conventions

Backfilled JSON receipts record the exact local command, exit status, Rust toolchain, and SHA-256 digests of the source or fixture that was exercised. A package-level test pass is not promoted into a milestone or release pass when the roadmap asks for a larger empirical, cross-platform, hosted-provider, or human-reviewed gate.

Benchmark receipts use `contextdb.benchmark-result/v1`. When no benchmark runner exists for the required scale, their status is `observation_only`; the measured values are limited to the package suite invocation and are not performance or quality certification. `contextdb.version_manifest_sha256` is the SHA-256 of the embedded version-manifest object serialized as UTF-8 JSON with keys sorted and compact separators. Artifact hashes are SHA-256 over the referenced file bytes.
