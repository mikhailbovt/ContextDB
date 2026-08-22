# ContextDB v1 performance report

This document is the required M17 performance-report path. It records the
largest native run completed so far and, just as importantly, the claims that
the run cannot support. **M17 is not release-certified by this report.**

## Evidence classification

The canonical result is
[`proof/M17/BENCH-H.json`](../../proof/M17/BENCH-H.json), SHA-256
`3544dd20f0ab851f515f05d39d98b25554ad44f134f01fba0a76f852c4f9a5b1`.
It is `observation_only` / `native_measured_development`: Windows x86_64,
Rust release profile, redb, dirty source tree, and no operating-system cache
eviction. The raw phase record is
[`proof/M17/BENCH-H-10M-windows-development.raw.json`](../../proof/M17/BENCH-H-10M-windows-development.raw.json),
SHA-256
`4f94c45382fe3986e969d8c1209bd3012f7b0e7a1a20efd0832a140b2fa769d3`.

The same process completed 10,000,000 synthetic storage records in 40,000
synchronized commits. These records are not counted as semantic nodes: the
canonical report now records `certification_node_count=0` and tier
`development-10m-storage-records`.
The harness used a streaming expected digest and independently compared a
4,096-record slice against the full clone-on-write MVCC oracle. This avoids the
quadratic retained-copy shape that would require tens of tebibytes at 10M while
retaining an executable differential check.

## Native measurements

| Scenario | p50 | p95 | p99 | Notes |
| --- | ---: | ---: | ---: | --- |
| Sync commit latency, 40,000 batches | 3.930 ms | 5.572 ms | 6.824 ms | 51,412 records/s; 13.16 MB/s |
| First exact reads after redb reopen, 2,000 queries | 13.9 us | 40.8 us | 83.7 us | OS page cache was not evicted; not a true cold-disk claim |
| Warm exact reads, 2,000 queries | 1.9 us | 2.3 us | 2.4 us | Storage-shaped exact key recall |
| Filtered subject scans, 64 queries | 140.8 ms | 152.2 ms | 157.2 ms | Exact scan, not hybrid ANN/model recall |
| Mixed read under background compaction | 14.2 us | 25.1 us | 34.1 us | Seeded 80/20 workload |
| Mixed write under background compaction | 0.517 ms | 0.677 ms | 0.803 ms | One 257.9 ms maximum outlier |

Other observed phase times were 188.3 s for derived rebuild, 205.2 s for
foreground compaction, 162.5 s for background compaction, 11.25 ms for reopen,
5.44 ms for the bounded journal backup, and 17.46 ms for its empty-target
restore. Total harness time was 857.8 s.

Phase-boundary RSS reached 1,592,954,880 bytes under the declared 2 GiB limit.
Phase sampling is not continuous allocation telemetry and no content-addressed
external peak trace exists, so no external peak is used as evidence. This
storage-run observation does not prove the M17-E02 pressure/degraded/no-OOM
class.

## Correctness, durability, and privacy

All nine selected report-level quality gates passed: full-dataset logical
digest, snapshot consistency, initial primary count, compaction preservation,
derived rebuild equality, journal restore plus reopen, final physical count,
the 64 MiB working-buffer admission rule, and telemetry no-payload privacy.
Separately, all 16 emitted threshold-bearing metrics passed, including the
explicit `bounded_mvcc_differential_verified=true` digest check, persistent
reopen, synchronized acknowledgements at 10,000 basis points (100%), and the
phase-boundary RSS threshold. These are development checks, not M17 exits.

The cross-proof regression receipt is
[`proof/M17/quality-privacy-regression.json`](../../proof/M17/quality-privacy-regression.json).
It binds the BENCH-H harness change to BENCH-G's zero-touch privacy cases,
BENCH-A's conversation/social-calibration gates, the M7 ANN exact-overlap
floor, and BENCH-F's coding quality/tool-use floor. It is deliberately marked
`partial_pass`: these checks passed, but no qualifying prior release baseline
or full 10M semantic/model workload exists. The expected and actual bounded
MVCC digests were reconstructed by rerunning only the deterministic
4,096-record probe configuration; none of the frozen 10M timings were rerun.

## Provisional targets and interpretation

The BENCH-H configuration recorded the RFC provisional p95 targets before the
run: 120 ms hot conversation, 150 ms exact/graph, 400 ms hybrid, and 200 ms
bootstrap. The native exact-storage paths are below the numerical exact target,
but they are not substitutes for the full graph/ContextPack/model scenarios.
The filtered exact scan p95 is 152.2 ms and therefore is not relabelled as a
passing exact/graph SLO. No hybrid, bootstrap, or real modality-model latency
was measured in this run.

## Release blockers

- M16 was not complete when the run executed; the report records
  `m16_deep_scan_passed=false`.
- Linux arm64 and macOS arm64 release-platform runs do not exist; Windows is
  best-effort in the RFC platform order.
- The source tree was dirty and the version manifest is not a signed release
  manifest.
- True cold-cache I/O, continuous peak memory, full semantic graph/edge/vector
  shape, full ContextPack/model paths, and real multimodal decoders are
  unmeasured.
- No qualifying prior release baseline was supplied to the implemented
  regression comparator.
- BENCH-C and BENCH-D still require real-provider Beta evidence.

Consequently, the report satisfies proof-path presence and provides useful
10M native engineering evidence. It does **not** pass M17, Beta, M18, M19, or
v1.0 release gates by itself.

## M17 exit decision

| Exit | Status | Why it remains open |
| --- | --- | --- |
| M17-E01 | OPEN | Provisional p95 values are recorded as parameters, not evaluated full-stack thresholds; semantic/graph/vector scenarios, index freshness, and qualifying recovery coverage are absent. |
| M17-E02 | OPEN | Only phase-boundary RSS and a structural harness buffer admission were measured; pressure-induced degraded behavior and uncontrolled-OOM resistance were not exercised. |
| M17-E03 | OPEN | Selected semantic/privacy/social/ANN checks pass, but there is no qualifying clean prior-release baseline and no full-stack post-optimization regression run. |

The code-side release predicate is now fail-closed on an explicit BENCH-H
coverage manifest: at least 10M semantic nodes, 100M graph edges, 1M vectors,
all RFC BENCH-H scenarios, and every E01/E02/E03 class must be asserted and
bound. Changing evidence strings, counts, build profile, or channel cannot
promote this storage-shaped report.
