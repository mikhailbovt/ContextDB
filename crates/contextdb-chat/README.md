# contextdb-chat

`contextdb-chat` is the M11 persistent conversational vertical. It composes the
existing storage, journal, cognition, recall, context-compiler, and model-neutral
contracts; it does not create a second graph, a second policy engine, or a model
SDK inside the database core.

## Durable lifecycle

The synchronous path is:

1. validate the authenticated session, memory space, participant, and active scopes;
2. synchronize protected content plus an exact prepared capture record;
3. accept a separate immutable observation frame in `contextdb-journal`;
4. synchronize the interaction index, bounded `SituationFrame`, and semantic job;
5. run policy-first recall and validate the canonical `ContextPack` before it can
   reach either runtime adapter;
6. capture assistant speech as a second evidence unit linked by interaction ID.

The caller receives no capture receipt until steps 2–4 have completed with the
configured durability (`Sync` by default). If a process stops between steps, the
prepared record contains the exact observation/content identities and a digest-only
idempotency binding. Reopen or caller retry resumes the saga. An orphaned prepared
content record is not acknowledged and cannot enter recall through this crate.

Post-turn work is asynchronous. A durable job feeds the public M10 deterministic
extractor, stores a proposal batch with no write authority, and accepts only M10's
`AdjudicationOutput`. Semantic mutation plus derived-work outbox publication remains
atomic in `contextdb-journal`. Empty and shadow results are recorded explicitly.

Checkpoints persist working state and task state; resume refreshes the frame TTL but
does not promote it to truth. User controls are typed and durable. Correction,
retraction, forgetting, privacy, and sharing require explicit confirmation, and a
job is marked applied only after a host policy/mutation executor supplies a receipt
digest.

## Runtime and recall boundaries

`ConversationRecall` is provider-neutral and returns a fully compiled context. The
middleware verifies workspace, subject, active-scope subset, snapshot ceiling,
purpose, target model profile, canonical JSON, canonical Protobuf, and digest. It
also caps automatic natural mentions. Provider failure, an invalid pack, and a late
pack degrade to no memory without undoing the user observation.

Enable `service-adapter` to use `CognitiveServiceConversationRecall`, the direct
embedded adapter to `CognitiveMemoryService::compile_context`. Construction requires
an exact `ModelProfile`, bounded compiler/freshness policy, and a
`ConversationServiceAuthority`. The authority sees a content-free identity/scope/
capability binding and must return a fully authenticated service context; the adapter
rejects broadened scopes, changed identities, missing grants, or a different purpose.

The durable user observation ID is reused as the caller-stable ContextPack ID. The
adapter deterministically maps every `ConversationMemoryIntent`, pins compilation to
the acknowledged journal snapshot, and clamps compiler work to both chat and adapter
budgets. Before returning memory it reserializes the canonical JSON/Protobuf, verifies
the digest and privacy-safe trace, and independently rerenders the pack for the bound
model profile. `PackStatus::NoMemory` becomes `Ok(None)`; payload-free service errors
become a sanitized recall error, which `ConversationMiddleware` reports as
`RecallDisposition::Degraded` without rolling back capture.

Two network-free runtime adapters demonstrate portability:

- `SeparatedChannelsAdapter` preserves trusted control, untrusted memory data, and
  current user input as distinct fields;
- `SinglePromptJsonAdapter` uses a JSON envelope so adversarial memory/user text
  cannot escape its data field by imitating delimiters.

Neither adapter invokes a provider, possesses credentials, extracts semantics, or
mutates memory.

## BENCH-A release contract

`BenchADataset::generate(BenchAScale::Full)` deterministically creates the RFC 28.7
minimum workload: 5 virtual years, 1,000 sessions, 50,000 turns, 50 people, 200
topics, at least 100 shared references, preference changes, corrections, open loops,
and labelled sensitive memories, plus four runtime epochs. All ten required query
classes are represented by 100 queries each. Dataset drift is protected by a
domain-separated digest.

`BenchAHarness` executes ingestion, primary-runtime queries, a process-equivalent
restart, and secondary-runtime queries. Reports contain only IDs, normalized answer
digests, integer rates, and latency; no response prose.

The published M11 default gates are:

| Gate | Threshold |
|---|---:|
| memory precision | at least 90.00% |
| memory recall | at least 85.00% |
| referent resolution | at least 95.00% |
| current truth | at least 95.00% |
| historical truth | at least 95.00% |
| temporal leakage | at most 10,000 ppm (1.0%) |
| wrong-person selection | at most 10,000 ppm (1.0%) |
| correction survival | at least 99.00% |
| shared-reference accuracy | at least 95.00% |
| implicit continuity | at least 90.00% |
| unknown precision | at least 99.00% |
| continuity preference | at least 90.00% |
| private-memory disclosure | exactly 0 ppm |
| unsolicited mention on silence queries | at most 5,000 ppm (0.5%) |
| restart semantic consistency | 100.00% |
| cross-runtime semantic consistency | 100.00% |
| rendered context p95 | at most 4,096 tokens |
| hot recall p95 | at most 500,000 microseconds |

These thresholds are project policy: the RFC names the metrics and M11 exit but
does not assign numeric values. `BenchAReport::failures` returns every failed gate.
The smoke test proves generator/evaluator behavior against a perfect deterministic
oracle. Release evidence comes from the independent `bench_a_full` executable and
the assembled reference stack, not that oracle.

The canonical 2026-08-12 full run passed every published gate over 1,000 sessions,
50,000 Sync-durable turns, 1,000 labelled queries, a process-equivalent reopen,
deep store verification, and both runtime paths. The machine-readable result is
`proof/M11/BENCH-A.json`; raw output, version manifest, command log, hashes, and
scope limitations are indexed in `docs/benchmarks/m11-bench-a.md`.

## Acceptance matrix

| M11 requirement | Package artifact | Automated evidence |
|---|---|---|
| middleware and before/after hooks | `ConversationMiddleware` | capture/timeout and paired-evidence tests |
| service-backed recall composition | `CognitiveServiceConversationRecall` (`service-adapter`) | exact plan mapping, no-memory, degraded capture, trace/render tamper tests |
| session bootstrap/restart | `bootstrap_session`, checkpoints, recoverable store | redb reopen and checkpoint tests |
| referents, implicit/explicit/historical/reflective intent | `SituationPatch`, `ConversationMemoryIntent`, deterministic `RecallRequest` mapping | request validation and middleware tests |
| shared/private boundary | principal + memory-space + active-scope authorization before content/recall | adversarial tenant/scope test |
| changing preferences, boundaries, current state | durable M10 job and `AdjudicationOutput` publication seam | deterministic extraction/no-op lifecycle test |
| user controls | durable confirmation/executor-receipt queue | forget confirmation test |
| social calibration | canonical use directives + automatic mention cap | pack validator and BENCH-A unsolicited/leak gates |
| relationship/shared-history summaries | canonical context sections supplied by the context compiler | enforced through `ConversationRecall`; end-to-end quality is a BENCH-A gate |
| BENCH-A | full/smoke generator, executable harness, report, thresholds | full-shape/digest and evaluator tests |
| two runtimes/no provider lock-in | separated-channel and single-prompt JSON adapters | exact text and adversarial delimiter test |
| corruption detection | checksummed records plus journal/cross-reference verification | deliberate content-frame corruption test |

## Honest boundaries

- A synchronous Rust trait cannot forcibly preempt a non-cooperative recall adapter.
  The deadline is supplied to the recall request and any result returned after it is
  discarded deterministically. Deployments needing hard cancellation must implement
  it in their async/process adapter.
- Recall retrieval and context compilation are injected because M4/M5/M7 own those
  mechanisms. This crate validates their output and never bypasses their policy seam.
- The optional service adapter composes recall only. `ChatStore` capture and the
  injected service currently retain independent commit authorities, so a chat
  journal sequence must not be treated as a service snapshot sequence. A complete
  production composition still requires one shared snapshot/commit authority (or
  an explicit, verified cross-authority snapshot token).
- Control execution, content encryption/crypto-erasure, and semantic graph projection
  are host-owned boundaries. This crate durably coordinates them but does not claim
  completion before their receipts/publications exist.
- The committed full BENCH-A result is deterministic synthetic reference-stack
  evidence. It does not replace the RFC human acceptability set for naturalness,
  creepiness, or generalization to unlabelled real-user histories.
- There are no network SDKs, API keys, or provider calls in this crate.
