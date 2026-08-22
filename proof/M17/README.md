# M17 native 10M development evidence

This directory preserves the canonical result of the bounded Windows x86_64
BENCH-H run executed on 2026-08-12. It is deliberately classified as
`observation_only` / `native_measured_development`: the run used a dirty source
tree, recorded `m16_deep_scan_passed=false`, and does not substitute for the
required Linux/macOS, full semantic graph/vector/model, cold-cache, or
cross-release baseline evidence.

The same PID completed 10,000,000 synthetic storage records and 40,000
synchronized commits without restart. They are not semantic nodes:
`certification_node_count=0` and the tier is
`development-10m-storage-records`. The report emitted 48 metric records; all
16 threshold-bearing metrics and all nine selected report-level
correctness/privacy/resource gates passed. The streaming oracle matched the
native logical digest; a bounded 4,096-record full-MVCC differential
independently checked the scalable oracle mode. Its expected/actual digest
fields were reconstructed by rerunning only that deterministic 4,096-record
probe; no 10M timing was rerun.

Artifacts:

- `BENCH-H.json`: the required M17 BENCH-H path, containing the strict
  benchmark-result v1 report for this Windows development run,
  SHA-256 `3544dd20f0ab851f515f05d39d98b25554ad44f134f01fba0a76f852c4f9a5b1`.
- `BENCH-H-10M-windows-development.raw.json`: native phase and differential
  details, SHA-256
  `4f94c45382fe3986e969d8c1209bd3012f7b0e7a1a20efd0832a140b2fa769d3`.
- `quality-privacy-regression.json`: optimization-specific cross-proof
  correctness/privacy receipt. It is `partial_pass`, not a qualifying
  cross-release verdict, because no prior clean release baseline was supplied;
  SHA-256
  `ebd88df79cbb1c0852f966b7d05b637870ca0e629c37e53f2053f5446b3374c7`.

The interpreted measurements and release blockers are published at
[`docs/benchmarks/v1-performance-report.md`](../../docs/benchmarks/v1-performance-report.md).

The report validates against
`assets/schemas/benchmark-result.schema.json`. Its embedded version-manifest
SHA-256 is
`70a946b2c8f4cfee9b693fcee42cd680edef84fa5533b3c2a40c736d7da2aa8e`.
The original multi-gigabyte redb working directory remains under `target/` and
is not a portable proof artifact.

Subsequent source work closed the locally testable durable ANN source gap:
`PersistentAnnVectorSourceV2<RedbStorage>` now imports immutable bounded pages,
resumes byte-identical interrupted imports, recomputes vector/route/registry
roots, and verifies them again on reopen. The runtime subsequently added paged
ANN-local authorization universes, delta/current-use tombstone overlays, atomic
generation rotation, and lease-safe retention/recovery. These code changes do
not alter or retroactively promote the frozen 2026-08-12 artifacts above. The
authoritative persistent policy-universe/server composition and a new
reference-hardware 1M-vector receipt remain separate unclaimed work.
