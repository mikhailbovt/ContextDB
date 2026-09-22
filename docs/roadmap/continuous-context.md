# Continuous context delivery

Implementation of the [accepted design](../architecture/continuous-context.md).
Phases 00–16 retain the supplied v3 backlog; phase 17 is the user-requested
final benchmark stage. A phase is complete only when its
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
| 08 | Atomic lease admission, invalidation and action fences | Merged in #10; all eight CI jobs passed; strict transport handoff remains open |
| 09 | Cache/cost controller and paired runtime evaluation | Merged in #11; all eight CI jobs passed; R0 quality and total monetary benefit remain open |
| 10 | Restore/revocation, retention, custody and bounded publication | Custody, suppression, encrypted backups and lineage implemented; local source/assertion/generic/chunk cleanup verified on Windows; complete copy/key/external closure and completion admission remain open |
| 11 | Migration, integrations, demo and release evidence | Planned |
| 12 | Router replay corpus, contracts and training lineage | Planned |
| 13 | Measured R1 scorer and optional bounded R2 cascade | Planned |
| 14 | Downstream utility training and held-out evaluation | Planned |
| 15 | Disabled-by-default learning, shadow/canary and rollback | Planned |
| 16 | Open-reader differentiable gates | Optional research; not a product gate |
| 17 | Final paired model benchmarks: MemGym/MemoryGym, LongMemEval and LoCoMo | Planned; required final acceptance; no final benchmark runs yet |

Phase 17 evaluates the integrated result of phases 00–15; optional phase 16 does
not block it. Its primary comparison uses the same model and agent without and
with ContextDB, alongside summary and raw-hybrid baselines. The
[final benchmark protocol](../benchmarks/continuous-context-final.md) defines the
required suites, held-out evaluation, complete cost accounting and acceptance
artifacts. Phase 09 development results do not satisfy this final gate.

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
The bounded phase 09 local reader run is described below. Trained-router benefit,
production latency SLOs and total-cost savings remain unverified.

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

Phase 09 adds measured disjoint reader usage, explicit tariffs, optional cache
residency hysteresis and bounded process-local tracing. It fixes additional-memory
accounting to use the actual provider protocol and keeps raw recall available
when interpretation exceeds its bounded window, without establishing current
state or allowing external effects. The 162 affected Rust tests, three Python
accounting checks, Clippy and governance validation pass. Windows/Linux supply
receipts retain the same 148-component dependency graphs.

The [release-build reader comparison](../../benchmarks/continuous-context/README.md#measured-development-result)
executes all five treatments with pinned Qwen reader/embedding weights, verified
query-time partitions, exact captured native requests and actual cache/prefill
counters. R0 answers 24/32 correctly versus raw hybrid's 32/32; only 20 R0 answers
also receive all required originals. These failures stay open for retrieval,
rendering and downstream evaluation. The report includes failed-task cost,
summary-generation/embedding overhead and an illustrative losing token-price
case. Real monetary/energy cost, adaptive-controller benefit, multimodal/streaming
quality and multi-step task acceptance are not established by this text replay.

Phase 10 propagates access restrictions through model responses, tool results
and checkpoints, with bounded publication admission and obsolete-index cleanup.
Current native restore consults an independently retained suppression authority.
The encrypted profile seals values and v3 archives under separate key custody;
a durable issued-backup registry survives native restore and lost responses.
These foundations passed cross-platform CI before their respective merges.

Removal requests retain complete captured-source lineage, including shared owners
and independently owned novel blocks that must survive. Cleanup prepares source
controls, rebuilds and reclaims raw indexes, removes source-supported assertions
from mixed batches and affected generic revisions, then prunes primary bodies
and staged chunks. Independent
semantic mutations remain byte-exact. Control metadata preserves replay and
negative relationships without retaining removed values or envelopes. Old full,
partially pruned and cleaned archives verify their actual remaining logical rows
and restore behind current suppression.

Native tests pass on Windows. Fixtures
cover actual partial restart, overlapping removal requests, shared blocks, mixed
semantic batches, supersession/retraction targets, original receipt retries,
missing controls, resurrected content and concurrent publication. This is local
logical-copy cleanup, not physical or key erasure. Complete copy inventory,
legacy migration, old-replica reconciliation, verified local completion,
key disablement and external-copy dispositions remain open. Disclosure stays
closed after a removal request until a verified completion executor exists.

Retained record origins now prevent an old native archive from losing later
source-policy bindings. Tests include encrypted old/partial/current restore,
records absent from an early archive, denial before decoding damaged bodies,
independent recall, actual process exit after external Sync, interrupted catch-up,
registry loss and genuine version 2 compatibility. Empty record workspaces can
activate retained origin requirements before their first record, with exact retry,
old-archive catch-up and a publication fence against concurrent legacy writes.
Source-aware explicit publication, quarantined proposal/supersession, correction
and retraction atomically accept complete mutation groups and their origin intents. Copied
revisions retain predecessor origins; an interrupted transfer keeps the whole group
closed. Tests cover actual process exit after partial transfer, concurrent retries,
encrypted pending restore, hidden edges and exact copied-origin closure. Correction
retains each rewired edge's sources separately from the fully supplied successor;
tests reject swapped copy witnesses and oversized unions without partial acceptance.
Bounded discovery and repair now follow accepted workspace commits. Cursors bind
authority and history; missing completion locators cannot mint duplicate
completions. The owned runtime repairs on start, resume and before interaction,
retaining completed page progress in a bounded process-local cache. Tests cover
changing frontiers, interleaved workspaces, older encrypted restore, corrupt or
missing controls, budget interruption, and actual runtime start/reopen/resume.
Host classification remains trusted. Durable recovery progress, measured backlog
limits, larger origin ancestry and migration remain open.

Generic births and closures bind compact controls; older full mutation groups
prepare them through separate acceptance. Classified revisions retain removal
witnesses in the independent authority before their primary and journal bodies
are erased atomically. Complete source-aware groups are verified before their
first removal and bound to independent validation commitments. Graph, provenance
and history remain verifiable through partial cleanup and restore; original
receipts and independent records survive. Primary source cleanup now requires
every affected generic revision to be pruned and rejects unknown origins.
Tests cover copied correction edges, candidate graphs, historical revisions,
full/partial/cleaned archives, actual reopen, lost acknowledgement, CAS and
missing, forged or resurrected data. Unpruned bodies remain mandatory.
Non-retrievable legacy revisions can be classified and prepared administratively
without changing their stored read policy. Encrypted archives from before
classification/removal and after cleanup preserve independent data through
actual reopen/restore. Hash-only migration remains open.

Version 3 and 4 key authorities allocate immutable keys per changed value address
and native transaction, with an authenticated complete allocation journal. Old
snapshots and encrypted restore retain exact historical key IDs; an independent
rewrite uses a new key. Tests cover actual key-authority reopen, multiple owners,
authenticated ciphertext import and missing/replayed/changed allocation metadata.
Budgeted catalog pages bind the complete allocation chain and retain authenticated
continuations across reopen. Administrative primary-key inventory joins retained
source lineage to historical allocations after pruning or older restore, including
descendants absent from that archive, and excludes independent source addresses.
Selected block keys remain identifiable from retained metadata after chunk cleanup
or restore of an archive predating staging; independent shared blocks are excluded.
Record inventory identifies all historical primary, birth and closure keys from
independent revision witnesses after pruning, reopen and encrypted restore, with
stored access labels still enforced. Allocated keys do not prove native use or
physical absence.
New version 4 authorities also retain exact native-use transitions and outcomes.
A sealed native marker is committed with the data; independent acknowledgement
and restart recovery distinguish committed, aborted and still-pending attempts.
Fresh restore instances preserve imported ciphertext IDs. Bounded journal and
change pages expose this evidence; full open verification replays instance history.
Actual process-crash and uncertain-Sync recovery preserve native sequences and
data, while missing or replayed controls fail. Source-selected key reports join
their ownership addresses to fully verified native-use transitions and per-instance
acknowledged values, including raw ciphertext/value checks. Shared-version
dispositions, legacy history, safe disablement and physical-copy closure remain open.
Mixed assertion ownership is retained independently without source values or full
envelopes. Its key inventory distinguishes shared batch versions from selected
mutation bodies and labels through sequential cleanup, actual authority/native
reopen and encrypted restore, including archives predating the batch. Tests cover
independent data, retractions, policy, lost acknowledgement, publication races,
missing witnesses and rehashed false selection. Shared and cleaned replacement
keys remain available after pruning; retirement requires the separate checks below.
V4 pruning now retains custody-authenticated before/after value compositions.
The key report classifies exact versions relative to each request, preserving
independent mutations, host policies and cleaned replay controls. Sequential
removal, interrupted publication and older restore retain these distinctions;
unclassified historical versions still require evidence or explicit migration.
Raw generation reclamation now retains source/address and observed ciphertext
evidence before each page is deleted. Native verification binds that evidence to
the accepted GC history; shared metadata stays distinct from source-owned rows.
Tests cover pruning, actual authority/native reopen, empty/full/partial encrypted
archives, lost acknowledgement, concurrent publication and damaged page chains.
Older untracked prefixes and unobserved historical versions remain open;
observation does not establish erasure or key retirement.
Request-bound discovery now walks the retained observation journal with
authenticated continuations, preserving source/control identity across older
native restore. Historical raw-key inventory separates allocated keys from
observed ciphertexts and retains unresolved shared/unknown obligations. Tests
cover descendant selection, independent originals, cursor replay and rotation,
authority growth, pruning/restore and forged source or key claims. It covers
observed reclamation history; older gaps remain open.
Request-bound inspection now independently retains present rows across active,
building, retained and partly reclaimed generations. Encrypted continuations bind
the native snapshot; exact retries recover accepted pages without native writes.
The selected key report verifies the entire page chain after pruning or older
restore. Tests cover exact physical observations, restart, token rotation, native
races, lost acknowledgement, unknown rows and damaged or rehashed page chains.
Expected projection coverage, complete native-use history and unobserved copies
remain separate gates; a finished inspection does not authorize key retirement.
Encrypted projection now accepts the full 16,384-term document limit and splits
larger batches between originals, reserving capacity for native control rows.
Coverage advances only past complete documents and resumes after restart.
Primary, payload-chunk and generic-revision key decisions survive both authority
restarts and older native restore. Independent Sync is fenced against custody
publication; readback verifies
exact historical allocation/use frontiers and distinguishes pending, acknowledged
and retained-copy work. These witnesses do not disable keys or complete deletion.
Partial chunk cleanup and closed revisions retain exact earlier decisions; shared
blocks and independent records remain outside the selected body families.
Raw/index decisions use the same engine with an explicit frozen GC-observation
prefix or complete inspection receipt. Retained pages independently establish
source/address/version coverage. Exact retries, later observations, pruning and
older encrypted restore preserve historical decisions; incomplete or damaged
coverage rejects the report. Shared/unknown and untracked obligations remain open.
V4 backup issuance now retains complete ciphertext membership in the same Sync,
with immutable paged receipts surviving older restore and custody reopen. Admin
backfill verifies supplied archive bytes against their original issuance; missing
older coverage stays unknown. Interrupted registration/page writes leave no partial
acceptance. Request-owned primary, payload, revision and observed raw keys now join
every issued archive under one budget and current custody frontiers. Complete
membership distinguishes no matches from unknown older coverage; concurrent
issuance, backfill or replacement acceptance rejects stale reports.
Mixed assertion inventories also classify exact archived values, keeping independent
mutations and replay controls separate from selected data and unknown compositions.
Both archive reports now derive authorized preservation paths to clean targets
and distinguish verified complete bytes from partial or absent artifacts. Tests
cover multi-step cleanup, legacy membership backfill, reversed issuance order,
different requests, both-authority restart and older native restore. Reports are
limited to their selected family and current frontiers; they grant no key retirement
or deletion-completion authority.
Successive requests can share a path only after each exact request is independently
verified within the same workspace and removal authority.
Routing now skips complete targets with retired keys and can follow later readable
replacements. Reports bind the current refusal frontier, so retirement alone also
invalidates an in-flight archive inventory.
Request-bound replacements now preserve the original journal prefix, receipts,
payload manifests and independent bodies under full native replay. Actual target
bytes, membership and independent provenance are issued with one custody Sync.
Tests cover mixed assertions, generic revisions, partial chunks, both-authority
reopen, full/cleaned restore, divergent histories, other removal requests, missing
or rehashed metadata and actual process exits before/after Sync. Replacement bytes
can now be retained independently in resumable portions of at most 4 MiB. Immutable
prefix receipts, exact retries and full-digest verification distinguish partial
from complete availability. Tests cover interleaved archives, old native restore,
cold authority reopen, false rehashed prefixes, missing/extra chunks, request-first
access and actual process exits before/after artifact Sync. Archive frontiers also
fence byte publication. A native coordinator now advances cleanup in separate
owners restored from exact issued archives. It verifies ancestry before work,
recovers existing maintenance journals and rechecks the storage sequence before
publishing a complete retained replacement. Independent branch history, originals,
mixed assertions and generic revisions remain preserved. Fresh local inventory
also covers archives before a selected root: earlier retained co-owners and staged
blocks are cleaned, globally shared novel bytes remain, and verified empty
histories require no pruning. Orphan rows cannot count as absence. Unknown origins
and unretained descendants require explicit reconciliation; discovery still
rescans within a shared budget.
Cleanup can continue through exact accepted replacement paths after original or
intermediate keys have been refused. Every earlier request is verified separately;
only complete readable terminal bytes become the next coordinator baseline.
Restart tests preserve the separate edges, independent data and exact retries;
invalid paths, divergent owners and incomplete artifacts cannot start cleanup.
Issued originals now use the same bounded artifact retention as replacements.
Recovery automatically finds readable inputs for every issued archive, preserving
unknown membership, unavailable keys and incomplete bytes as distinct outcomes.
Shared DAG routing keeps recovery-input availability separate from clean-copy
preservation. Actual input reads verify replay and the current custody frontier.
Durable jobs now bind an exact request, input and registered pristine worker before
import. Cold restart and uncertain responses resume that same worker; subsequent
requests continue its prior result. Only actual terminal cleanup enters the sealed
job journal. Unfinished jobs prevent refusal of required input keys. Checks cover
partial-cleanup inputs, empty archives, successive requests, lost finish responses,
wrong owners and missing or rehashed controls. An owned controller now selects and
advances archive jobs automatically, reopens deterministic workers and defers their
successor aliases to the same owner across requests. Cold tests cover two archives,
successive removals, registration-only interruption, missing storage before job
admission and swapped worker directories. Missing inputs stay explicit and create
no worker. Embedded hosts can now start a background maintenance service with fresh
workspace-bound host authentication, verified request discovery and bounded steps.
It resumes after restart, discovers later requests and reports revoked access or
missing inputs while capture continues. Shutdown cancels work and joins the thread.
Completed archive workers can be permanently sealed; later requests reserve a
fresh instance from the exact seal and prior clean input. Bootstrap and import
uncertainty recover that same generation while preserving old jobs and copy
obligations. Worker disposal, cross-workspace reassignment and CLI/MCP encrypted
profile provisioning remain open.
Owned and mixed assertion keys can now be retired after fresh native-use and
complete archive-preservation verification. Mixed selections require classified
replacement batches in every affected native instance, preserving controls,
host policies and independently needed mutations. Other authorized removals are
verified against exact retained ownership; pending replacement publications block
acceptance. The independent classification frontier is fenced through Sync.
Current refusal applies to old snapshots and
staged imports, survives cold custody reopen and native restore, and fences native
transactions through Sync. Tests cover competing imports, sequential removals,
partial archive bytes, lost responses, ambiguous Sync, journal corruption and real
process exits around publication. Mixed-key tests also cover two native instances,
independent deletions in both orders, missing preservation, unknown composition
and classification races. Wrapped keys remain; this is not destruction.
Remaining replacement execution, version 1/2 key migration,
physical/external-copy closure and verified deletion completion/admission remain open.
