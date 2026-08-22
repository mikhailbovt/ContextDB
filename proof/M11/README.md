# M11 release evidence

The canonical full BENCH-A run completed with exit code 0 and passed every
published M11 gate. `BENCH-A.json` is the schema-validated benchmark result,
`two-runtimes.json` is the provider-independence conformance report, and
`lifetime-conversation.log` preserves the commands, versions, interrupted
non-evidence attempt, canonical invocation, and aggregate results.

## SHA-256 manifest

| Artifact | SHA-256 |
|---|---|
| `proof/M11/BENCH-A.json` | `be2290e9db0eb7854714809d814a72205e63b4d2d026547608a5934df01a1233` |
| `proof/M11/two-runtimes.json` | `a53badc79dff43fe0ae491f923a19a3527400a24b55c114234bf445b6e371aec` |
| `proof/M11/lifetime-conversation.log` | `1b57c17332032af58089855d44d14d6064ed82f73942bb98d9f2e5a16eff207b` |
| `docs/benchmarks/results/m11-bench-a-windows-2026-08-12.raw.json` | `4b91e39de0abbba6ad30ba76dbd52516b75e9c9c0b76a32a9ac8c0e80f1b1be5` |
| `docs/benchmarks/results/m11-bench-a-windows-2026-08-12.version.json` | `b0607f6f521c765637b344a811c8ec80fecf607270ac158494178a5bd0d3741e` |
| `crates/contextdb-chat/examples/bench_a_full.rs` | `a8750eac5e91a411e166e19cec562a9f9bfa1b75941ba44839cb8863bdf88400` |
| `crates/contextdb-chat/src/benchmark.rs` | `a142384513d8aeafd072b845597a2501db195a0dae5b3fe0667934c78e77fc64` |

The manifest deliberately does not include its own hash. Recalculate with
`Get-FileHash -Algorithm SHA256` and compare the seven immutable entries above.

## Acceptance

- M11-E01: passed all referent, temporal, correction, privacy, continuity,
  latency, token-cost, unknown, and social-calibration floors.
- M11-E02: unsolicited mention, labelled sensitive-memory leakage, and
  wrong-person selection were zero; 300 policy-first probes excluded 36,000
  labelled sensitive record/query executions before planner visibility.
- M11-E03: recall/compile/runtime p95 was 11.149 ms and normalized semantic
  output was identical across both provider-neutral runtime paths.

Human naturalness/creepiness review and M17 concurrent-server performance remain
outside this deterministic reference-run claim, as recorded in `BENCH-A.json`.
