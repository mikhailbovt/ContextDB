# Contributing to ContextDB

ContextDB is built through executable, benchmarked vertical slices. A change is not complete
because it adds an abstraction; it must preserve the documented public contracts and demonstrate
why the mechanism is useful.

## Before proposing a change

1. Identify the public contract, architecture boundary, and machine gate affected.
2. Check whether an existing architecture, security, or release document owns the decision.
3. Keep universal core semantics independent of conversation, coding, provider, network, and
   storage-adapter types.
4. Add deterministic tests and, for an optimization, a reference-engine differential test.
5. Add or update a reproducible benchmark or ablation when the mechanism changes recall quality,
   latency, storage, or disclosure.

## Local checks

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
```

Normal tests do not use the network or a live model provider. Provider behavior is exercised with
recorded, local, or mock capability implementations.

## Safety and data rules

- Do not commit credentials, private conversations, customer data, or unredacted debug bundles.
- Model output is untrusted and cannot directly mutate primary state.
- New derived data must preserve lineage, scope, sensitivity, and ownership.
- `unsafe` is forbidden by default. An exception requires a dedicated design review, benchmark evidence,
  documented safety invariants, Miri/fuzz/property tests, and mandatory review.
- Do not loosen an ownership, audience, purpose, or consent rule in a derived object.

## Architecture decisions

Record design-changing decisions in the issue or pull request and update the affected stable
architecture contract in the same change. Include context, invariants, consequences, rejected
alternatives, migration impact, tests, and benchmark evidence.

## Commit and review scope

Keep changes reviewable and milestone-oriented. Generated code is produced reproducibly from a
versioned source schema and must have a clean regeneration diff.
