# M11 BENCH-A: Lifetime Conversation Memory

Status: **passed** on the deterministic M11 reference correctness and hot-path tier.

The canonical 2026-08-12 run executed the complete RFC 28.7 minimum shape: five
virtual years, 1,000 sessions, 50,000 Sync-durable turns, 50 people, 200 topics,
120 each of shared references, preference changes, corrections, open loops, and
labelled sensitive memories, four runtime epochs, and 100 queries in each of ten
query classes.

The executable stack was not the package smoke oracle. It used `ChatStore` and
`contextdb-journal` over redb with `Durability::Sync`, reopened the database,
deep-verified durable records, restored an exported `contextdb-reference`
semantic projection, ran `contextdb-recall::RecallEngine`, compiled and validated
canonical ContextPacks, and exercised both provider-neutral runtime adapters.

## Result

All published M11 floors passed. Precision, recall, referent resolution, current
truth, historical truth, correction retention, shared-reference accuracy,
implicit continuity, unknown precision, continuity preference, restart
consistency, and cross-runtime consistency were 100%. Temporal leakage,
wrong-person selection, sensitive-memory leakage, and unsolicited mention were
zero. All 300 policy-first probes excluded every labelled sensitive record before
planner visibility (36,000 record/query exclusions). Context token p95 was 891
tokens against a 4,096-token ceiling. Full recall/compile/runtime p95 was 11.149 ms
against a 500 ms ceiling.

These numeric floors are project release policy because RFC-0001 names the
metrics but intentionally freezes final performance targets later. The exact
threshold set is serialized in both the raw result and benchmark result.

## Evidence and hashes

| Artifact | SHA-256 |
|---|---|
| `proof/M11/BENCH-A.json` | `be2290e9db0eb7854714809d814a72205e63b4d2d026547608a5934df01a1233` |
| `proof/M11/two-runtimes.json` | `a53badc79dff43fe0ae491f923a19a3527400a24b55c114234bf445b6e371aec` |
| `proof/M11/lifetime-conversation.log` | `1b57c17332032af58089855d44d14d6064ed82f73942bb98d9f2e5a16eff207b` |
| `docs/benchmarks/results/m11-bench-a-windows-2026-08-12.raw.json` | `4b91e39de0abbba6ad30ba76dbd52516b75e9c9c0b76a32a9ac8c0e80f1b1be5` |
| `docs/benchmarks/results/m11-bench-a-windows-2026-08-12.version.json` | `b0607f6f521c765637b344a811c8ec80fecf607270ac158494178a5bd0d3741e` |
| `crates/contextdb-chat/examples/bench_a_full.rs` | `a8750eac5e91a411e166e19cec562a9f9bfa1b75941ba44839cb8863bdf88400` |
| `crates/contextdb-chat/src/benchmark.rs` | `a142384513d8aeafd072b845597a2501db195a0dae5b3fe0667934c78e77fc64` |

## Scope boundary

This result establishes deterministic synthetic correctness, labelled privacy
and social-calibration behavior, restart durability, hot-path performance on the
published host, and runtime-format portability. It does not claim that synthetic
scores generalize to unlabelled real users. The runtime adapters make no external
model calls, so response naturalness and creepiness remain human-review gates.
M17 owns concurrent-server, bounded-memory, and hardware-normalized performance
certification.
