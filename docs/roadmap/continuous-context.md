# Continuous context delivery

Implementation of the [accepted design](../architecture/continuous-context.md).
Numbers retain the supplied v3 backlog. A phase is complete only when its
executable path and stated evidence exist; contract fixtures alone are not
native or model acceptance.

| Phase | Deliverable | Status |
| --- | --- | --- |
| 00 | Native ownership contract, shared histories, finite Rust oracle, baseline | Merged in #2; CI passed on all four native targets |
| 01 | Native conversation capture, receipts, streams and recovery | Merged in #3; CI passed on all four native targets |
| 02 | Tool/artifact capture, request provenance and reconciliation | Implemented; local checks passed, CI pending |
| 03 | Original ID/source/range/lexical recall without promotion | Planned |
| 04 | Persistent authorized indexed provider and exhaustive paging | Planned |
| 05 | Temporal assertions, resolution, negative overlay and coverage | Planned |
| 06 | Evidence compiler, whole-request manifest, R0 and budgets | Planned |
| 07 | Owned conversation runtime, rolling, checkpoint and resume | Planned |
| 08 | Atomic lease admission, invalidation and action fences | Planned |
| 09 | Cache/cost controller and paired runtime evaluation | Planned |
| 10 | Restore/revocation, retention, custody and bounded publication | Planned |
| 11 | Migration, integrations, demo and release evidence | Planned |
| 12 | Router replay corpus, contracts and training lineage | Planned |
| 13 | Measured R1 scorer and optional bounded R2 cascade | Planned |
| 14 | Downstream utility training and held-out evaluation | Planned |
| 15 | Disabled-by-default learning, shadow/canary and rollback | Planned |
| 16 | Open-reader differentiable gates | Optional research; not a product gate |

The first connected proof is capture → raw retrieval → current state → bounded
R0 assembly → lease admission → owned conversation resume. Tools and learned
models extend it. The public alpha support claims remain governed by the
[release support matrix](../release/package-support.md).

## Baseline

`3b38f24d30703a6a32e31b6d45b3205d6cea0cff` on Windows x86-64, Rust 1.97.1:
`cargo test --workspace --all-features --locked` passed 711 tests, zero failures
and zero ignored tests on 19 September 2026. The compact environment and command
receipt is in [baseline.json](../../benchmarks/continuous-context/baseline.json).
It describes the original engine, not the new continuous runtime.

The supplied design's four schemas, eight positive examples, 36 negative checks
and 23 finite Python tests also pass. Its 80 engine/model scenarios remain
requirements until corresponding implementation evidence is recorded here.
No provider calls, trained-router benefit, latency SLO or savings are claimed.

Phase 00 adds 24 Rust conformance checks (the 23 finite specification cases plus
shared-corpus isolation) and two benchmark contract checks. Targeted Clippy with
warnings denied and repository governance/schema validation pass. The finite
oracle includes 12,960 overlay comparisons and 64 hot-visibility combinations;
these counts do not describe native storage or real concurrent execution.

Phase 01 passes 113 tests across core, service, native service and chat, plus
Clippy with warnings denied. Capture checks use the real Fjall owner: exact
Unicode/raw bytes, restart, eight concurrent retries, lost response, edits,
producer-gap backpressure, aborted chunks, authority binding and backup restore.
Three abrupt subprocess exits exercise staged payload, pre-commit and post-sync
recovery. Deep verification detects missing outbox data. These checks establish
the initial inline profile; phase 02 extends its payload and adapter boundaries.

Phase 02 passes all 42 native-service tests, plus targeted all-feature Clippy.
The new capture adapters preserve large originals, task-linked tool/artifact
events and ordered request wire bytes. A subprocess exits after a real file
effect; recovery reconciles the target without executing again. Another check
retains a full output through a failed capture and retries only persistence.
Chunked backup/restore, missing-source detection, source ACL checks before
request materialization and rejection of independent echo roots also pass.
External target guarantees remain explicit adapter contracts; the strict
runtime and model-quality acceptance gates remain in later phases.
