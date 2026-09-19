# Continuous context delivery

Implementation of the [accepted design](../architecture/continuous-context.md).
Numbers retain the supplied v3 backlog. A phase is complete only when its
executable path and stated evidence exist; contract fixtures alone are not
native or model acceptance.

| Phase | Deliverable | Status |
| --- | --- | --- |
| 00 | Native ownership contract, shared histories, finite Rust oracle, baseline | Merged in #2; CI passed on all four native targets |
| 01 | Native conversation capture, receipts, streams and recovery | Merged in #3; CI passed on all four native targets |
| 02 | Tool/artifact capture, request provenance and reconciliation | Merged in #4; CI passed on all four native targets |
| 03 | Original ID/source/range/lexical recall without promotion | Merged in #5; CI passed on all four native targets |
| 04 | Persistent authorized indexed provider and exhaustive paging | Merged in #6; CI passed on all four native targets |
| 05 | Temporal assertions, resolution, negative overlay and coverage | Merged in #7; CI passed on all four native targets |
| 06 | Evidence compiler, whole-request manifest, R0 and budgets | Merged in #8; all eight CI jobs passed |
| 07 | Owned conversation runtime, rolling, checkpoint and resume | Merged in #9; all eight CI jobs passed; reader/cache acceptance remains open |
| 08 | Atomic lease admission, invalidation and action fences | Embedded owner checks implemented; strict transport handoff remains open |
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

Phase 03 adds native raw ID/source/session/time/lexical recall, exact source-span
materialization and a shared Unicode analyzer. Native checks cover old quotes
after restart and physical snapshot expiry, distinct repeated text, omissions,
partial capture, chunk boundaries, encrypted cursor binding and current ACL
checks before a corrupted forbidden body. Exhaustion is explicit and resumable.
The raw oracle retains bounded scanning for conformance; it does not establish
indexed performance, extraction coverage or a real reader's answer quality.

Phase 04 passes 130 tests across index, recall and native service, followed by
the final seven indexed-provider scenarios after refinement. Persistent routes
match raw-oracle fixtures across restart. Selective posting work stays constant
between one and 201 sources; this is a bounded-work fixture, not a million-event
latency result. Checks include forbidden-domain insertion, corrupted forbidden
content, current-policy revocation, staged rebuild/cutover, backup restore,
bounded fresh tail, explicit overflow, generation-aware enumeration, large-source
fallback, causal history, cancellation, writer contention and missing-index
reconstruction. The existing materialized semantic corpus provider stays available
as an oracle.

Phase 05 passes 120 tests across core, service and native service, including eight
new native scenarios. They exercise source authority, proposal isolation,
explicit supersession/retraction, future and retroactive applicability, rollback,
branch isolation, conflict, pending interpretation, producer gaps, atomic scope
comparison, concurrent retry, current evidence ACLs, restart and backup restore.
The resolver reuses canonical claims and bitemporal ranges; it does not infer
natural-language truth. Accepted assertion batches and new writes through the
existing native record/edge API retain replayable payloads and atomic scope
epochs. Deep verification reconstructs their derived rows. Host interpretation
remains an explicit pipeline claim; a capture/index watermark cannot certify it.
Full CI passed on all four native targets. Composite backups preserve native v2;
broker shutdown removes its socket before releasing durable writer authority.

Phase 06 connects native state/raw discovery to complete request assembly. The
187 affected Rust tests pass, including seven compiler and six native preparation
scenarios. They cover mandatory STOP, support alternatives, shared/complementary
closure cost, source ACLs, post-eviction coverage, UTF-8 spans, protocol groups,
pending interpretation, concurrent scope changes, catalog loss, restart and
rotated backup restore. Python (31) and TypeScript (25) SDK tests, Go tests/vet,
all-workspace Clippy and governance checks pass. The reference encoder measures
its full declared request; no actual reader quality, cache savings or vendor
token accounting is inferred. Owned rolling and lease admission remain next.

Phase 07 connects native checkpoints, automatic preparation, chunked rolling,
exact request capture, registered tools and bounded memory expansion. A
14-call scripted-reader scenario crosses multiple resident windows, reopens the
database and automatically includes an old incidental original in the next wire.
Other checks cover reader-profile switching, terminal obligation unpinning,
lost output acknowledgement without repeated dispatch, concurrent checkpoint
publication, uncheckpointed tail recovery and revoked hot sources. Tool recovery
preserves a real file effect across restart without executing twice. An expansion
proposal causes the next encoded request to contain the selected original.
Interrupted protocol bytes survive a lost receipt and restart without becoming
executable tool calls. The final affected run passes 108 tests (8 agent runtime,
25 continuity, 75 native service). These are engine/lifecycle checks; the guard
and reader are explicit test fixtures. Real reader quality and measured
prefill/cache behavior remain open; native admission is covered below.

Phase 08 adds owner-sealed preparation, atomic lease registration, coalesced scope
subscriptions and fresh model/tool admission. Native checks cover registration
races, new negative state, wire/source-list tampering, current authorization,
owner restart and real temporal expiry without a write. The owned flow admits a
real file effect with unchanged dependencies, blocks it after new source input or
an obligation change, and bounds repeated invalidation before any model send.
Built-in expansion works with the native guard and interpretation left pending.
The affected 157 Rust tests, all-workspace Clippy and governance checks pass.
Strict transport handoff/cancellation, real provider measurements and later
retention/custody hardening remain separate gates.
