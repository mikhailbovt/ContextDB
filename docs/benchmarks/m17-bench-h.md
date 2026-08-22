# M17 BENCH-H: native 10M development run

ContextDB completed 10,000,000 synthetic storage records on the Windows x86_64
redb development path. These records are not semantic nodes or claims and do
not exercise the RFC/ERRATA v1 certification floor. This is useful native scale
evidence, but it is not an official v1 release certification or the provisional
Fjall-default reference-hardware result.

## Result

| Measure | Observed |
| --- | ---: |
| Primary records | 10,000,000 |
| Synchronized commits | 40,000 |
| Ingest rate | 51,412 ops/s |
| Commit p50 / p95 / p99 | 3.930 / 5.572 / 6.824 ms |
| Cold exact recall p95 | 40.8 us |
| Warm exact recall p95 | 2.3 us |
| Filtered recall p95 | 152.194 ms |
| Mixed read p99 | 34.1 us |
| Mixed write p99 | 0.803 ms |
| Full 10M derived rebuild and verify | 202.586 s |
| Full digest-preserving compaction | 242.991 s |
| Reopen and full 10M digest | 17.304 s |
| Phase-sampled maximum RSS | 1,592,954,880 B |
| Declared RSS limit | 2,147,483,648 B |

The same process completed every phase without restart. The streaming expected
digest and native logical digest were both
`c25358de9b280f47aaf4d5172b4d2dead030b1afb8af648010f0f248257289e1`.
A separate 4,096-record full-MVCC differential passed before the bounded
streaming oracle was admitted for 10M. Snapshot, rebuild, compaction, reopen,
portable backup, restore, durability, telemetry, and privacy gates all passed.

Canonical artifacts are in [`proof/M17`](../../proof/M17/README.md).

## Classification and limitations

The report status is `observation_only` and its evidence kind is
`native_measured_development`. It cannot be promoted retroactively because the
recorded source was dirty and the run explicitly bound `m16_deep_scan_passed`
to `false`.

This run also does not claim:

- required Linux x86_64, Linux arm64, or macOS arm64 platform evidence;
- a true cold-cache run with operating-system page-cache eviction;
- a full semantic graph edge/vector/ANN/hybrid/model workload at 10M;
- continuous RSS/allocation tracing (the canonical result samples phase
  boundaries and no content-addressed external peak trace was retained);
- real multimodal decoder/model execution; or
- a cross-release regression verdict without a qualifying prior baseline.

Those are release gates, not footnotes to be wished away.

The in-crate HNSW oracle no longer performs an all-pairs rebuild: it inserts
records deterministically with a fixed per-level construction-visit ceiling,
limits each node to 64 neighbours, validates imported graph topology, and keeps
exact full-precision reranking authoritative. The existing deterministic M7
fixture still exceeds its ANN/exact-overlap floor. This removes one quadratic
source algorithm. The executable semantic runner now keeps full-precision
vectors, targets, vector-space definitions, policy routes, and portable ANN
generations in separately verified redb stores; only the exact differential
oracle remains materialized in memory. Authorization now produces a paged
storage-backed route universe and a snapshot-safe generation lease instead of
retaining the entire route set in memory. The official production server still
does not compose and publish this index. This therefore does not establish the
1M-vector M17 floor or a `server-v1` capability.

## Derived semantic runner contract

The crate now has a bounded semantic measurement intake, but no full semantic
run is claimed here. Its raw `contextdb.bench-h-semantic-outcome/v1` contract
requires exactly these rows:

- `small`, `medium`, and `certification_v1` tiers, with scale floors fixed to
  RFC BENCH-H and ERRATA E-009 (100k/1m, 5m/50m, and at least
  10m semantic nodes plus 100m graph edges and 1m vectors respectively);
- all ten RFC BENCH-H scenarios in every tier;
- bounded raw latency, recovery, freshness, and RSS samples, plus numeric
  throughput and pressure outcomes;
- all four frozen semantic/privacy/social/ANN regression classes as numeric
  baseline/candidate comparisons; and
- raw artifacts whose SHA-256 digests and roles match every measured row,
  including the reference-hardware profile and predeclared target matrix.

The evaluator derives coverage and E01/E02/E03 flags from those rows. Inputs
contain no `completed`, `passed`, M16, or `release_candidate` switches. Even a
complete synthetic contract fixture stays `development` and
`observation_only`; it cannot become release evidence by flipping metadata.
Real scale, actual semantic-stack execution, published reference hardware, and
frozen Beta targets still need externally witnessed artifacts. Until then M17
is open, because turning caller booleans green would be benchmark necromancy.

## Executable semantic workload

`contextdb-bench` now owns a real full-stack development runner in addition to
the semantic measurement intake. It deterministically commits semantic node and
edge identities through the persistent graph, compacts and traverses paged
graph-v2 adjacency, builds a redb-backed persistent ANN-v2 generation, compares
its results with the exact full-precision oracle, reopens and exhaustively hashes
state, verifies an offline graph backup, forces bounded pressure/degraded
responses, continuously samples RSS, and kills a child process after a
synchronized Fjall marker to measure restart recovery. All ten BENCH-H scenario
names are emitted from executed calls.

The ANN-v2 evidence flag is derived, not supplied. It remains false until the
runner has synchronously published and completely verified a generation,
recorded non-regressing physical storage sequences, closed and reopened both
redb stores, recomputed the full-precision vector/route/registry roots,
recovered and re-verified the same ANN manifest, authorized through
the runtime's persistent route partitions without rescanning source routes or
reading any vector/target, searched without touching the private
representation, released the durable universe lease, and matched exact IDs and
score bits. The receipt is a content-addressed artifact of the final outcome.
This is live persistent graph/source/runtime-universe evidence rather than a
production/server-v1 claim.

The runner does not make the existing 10M storage result semantic. It supports
small configurable smoke/development runs and requires a digest-bound admission
artifact before any execution. The current 64-GiB-class Windows development
host is suitable for smoke and staged engineering measurements; that fact is
not certification approval.

Certification preflight is deliberately blocked before allocation. The graph
format now admits the required 200M directional records, but that is only an
admission boundary; it is not a measured scale result. The remaining blockers
are:

1. ANN-v2 now has a live persistent builder/publication/reopen/query path, a
   durable paged full-precision/routing source, persistent ANN-local
   authorization universes, a mutable delta/current-use tombstone overlay, and
   leased generation rotation/retention. The production service still does not
   compose this with the authoritative persistent policy universe, and no
   reference-hardware construction/recall/latency receipt exists at the
   required 1M-vector floor.
2. The final local preflight estimated 770,688,000,000 bytes of output-volume
   capacity for state, transients, and offline backup. It observed
   728,813,432,832 bytes free and admitted only the 80%-safe
   583,050,746,265-byte envelope.

That preflight recorded a planning ETA of 7,950--159,000 seconds (about 2h12m
to 44h10m). These are conservative model bounds, not measured throughput and
not authorization to begin the run.

Therefore no 10M-node/100M-edge/1M-vector result has been manufactured or
started. Measuring ANN-v2 on the reference hardware, implementing the
authoritative persistent policy-universe/server composition, and provisioning
enough dedicated output capacity remain prerequisites to requesting that long
run.
Publishing a generation above the old 100M-record ceiling also establishes the
downgrade boundary documented by ADR-0007.
