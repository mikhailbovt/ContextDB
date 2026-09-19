# Continuous context comparisons

The shared generator lives in `contextdb-bench`; conformance imports the same
history. Emit a reproducible corpus with:

```console
cargo run --locked -p contextdb-bench --example continuous_history -- 1000
```

`events` contains original query-time inputs. `evaluation` is a separate target
partition and must never be sent to the reader or used as router features.
Every baseline uses the same generator version, distractor count, reader,
budgets and query cutoff. Required comparisons are rolling, good summary,
summary with archive/hybrid retrieval, raw hybrid retrieval and ContextDB R0.
Model outcomes are unmeasured until the corresponding runtime is executed.

`baseline.json` records the original engine's test run and environment. It is
not a new-runtime benchmark. The finite conformance oracle is independently
checked with:

```console
cargo test --locked -p contextdb-conformance --test continuous_context
```

Those abstract checks are distinct from native restart/race tests and model
quality measurements. See the [delivery ledger](../../docs/roadmap/continuous-context.md).
