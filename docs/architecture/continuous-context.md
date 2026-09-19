# Continuous context

Accepted implementation direction, 19 September 2026. The source design is
Continuous Context v3 (17 September), archive SHA-256
`d885fc4b7f9772eb56b8ce5d7caf0082b4e2bb5d22709e9bbb255f09ae9c91d5`,
reviewed against `3b38f24d30703a6a32e31b6d45b3205d6cea0cff`.
The [delivery ledger](../roadmap/continuous-context.md) distinguishes contracts,
native execution, model evaluation and release evidence.

## Decision

Keep the Rust logical core and incremental native storage. Preserve accepted
originals independently of extraction or learned importance. Separate four
representations: immutable observations, attributed assertions, resolved
temporal state, and scoped task obligations. Model proposals cannot grant
permissions or silently replace an accepted decision.

An owned agent runtime assembles finite requests from host control, mandatory
state, original evidence and completed recent interaction groups. Continuation
uses durable originals and operational checkpoints; it requires no lossy
summary of the accumulated history. Summaries remain optional search aids or
requested outputs. This extends the engine through adapters without placing
provider, conversation or coding types in the universal semantic core.

The deterministic R0 router is the initial implementation and fallback. Learned
utility estimates may choose optional context, but never truth, authorization,
retention or mandatory obligations. Training defaults to off. Trained scoring
must improve a measured quality/cost frontier before default enablement.

## Publication ownership

| Existing owner | Physical keyspaces | Logical sequence / receipt | Use |
| --- | --- | --- | --- |
| `NativeService` | `contextdb_native_*` | Global native commit, workspace commit map, native idempotency response | Sole publication owner for continuous capture and preparation |
| `ChatStore<E>` | `chat_*` plus journal spaces | Chat receipt points to its `JournalCoordinator` observation | Legacy/reference saga; explicit import mapping required |
| `JournalCoordinator<E>` | Journal observation, mutation, event and outbox spaces | Typed `CommitSeq` and observation/publication receipts | Foundation/reference composition; not a second native writer |
| `FjallStorage` | Backend keyspaces and internal metadata | Physical commit sequence and short read handle | Storage transaction only; never a portable history cursor |

The native writer publishes the event, exact payload or durable blob reference,
receipt, outbox, affected scope epochs and logical commit in one synchronized
transaction. External blobs become durable before publishing their references.
Projection work does not hold the writer during inference or index construction.
Retry repeats read/validate/write with the same idempotency key and a bounded
budget. Lost responses are resolved by that key, not assumed to be failed writes.

Receipts bind database identity, sequence domain, event identity and durability.
Equal integers from chat, native and physical domains do not establish a fence.
Legacy import retains original identities and receipts with an explicit mapping.
Native audit hashes are not a replay log: reconstruction needs the accepted
mutation bytes and source history as well.

The first native capture implementation exposes `CapturePort` and the
`NativeConversationCapture` host adapter (`contextdb-chat/service-adapter`).
It preserves UTF-8 or binary originals, explicit omissions, immutable edits,
producer gaps and ordered response chunks. Each capture journal entry references
its accepted original and digest; the durable outbox carries the same reference.
Raw reads require current `ReadEvidence` and `RawEvidence` authorization.

The initial profile uses strict pause: retain the input and retry the same key
until a synchronized receipt arrives. It admits at most 256 KiB per inline
payload and 128 disjoint producer gaps. Overflow is an explicit
`ResourceExhausted`, with no partial publication. No disk spool is claimed.

First capture atomically enables the `continuous-capture-v1` format feature.
Older binaries reject this extended manifest. New code still reads legacy
databases and v1 backups; backups containing capture use the explicit v2 format.
Restore verifies original/receipt/outbox/producer/scope/stream closure before
writing a pristine target. A restored receipt remains usable after host-key
rotation, with fresh authorization and exact stored-receipt equality.

`contextdb-capture` adds host adapters for tools, complete artifact versions and
model requests. `PayloadPort` stages up to 64 MiB in synchronized 256 KiB chunks
before event publication. Each reference binds both the full original digest
and the ordered chunk manifest; a span read verifies just its intersecting
chunks. Staging has its own receipt and does not claim event capture. The
`continuous-sources-v1` feature fences older readers of these representations.

Request occurrences retain ordered source spans and novel bytes. Native capture
checks source permissions, exact byte ranges and the final wire digest, with
at most 512 parts. Request echoes cannot be used as independent source roots.
Reads check each dependency's current policy before loading the request body.

Tool intent is durable before dispatch. Recovery first asks the target about
that exact call/action digest. Automatic retry requires target idempotency or
an atomic version comparison; an unresolved duplicate does not take another
dispatcher's outcome slot. A failed result capture returns its full pending
observation for a persistence-only retry. Later resolution uses a fresh outcome
slot for the same invocation. Artifact deletion observes the source's absence;
it does not erase previously captured versions or claim retention deletion.

## Retrieval and current state

Interactive retrieval queries persistent indexes within an authorized domain;
it does not materialize the archive or rebuild a lexical index on each query.
The existing exact corpus provider remains a reference oracle. ID, source,
time/range and lexical routes work with extraction and embeddings disabled.
Analyzer versions, index coverage, outbox progress and query work are explicit.

`RawRecallPort` exposes persistent native routes and original-span materialization;
`recall_originals_oracle` remains the bounded conformance oracle. Both find accepted
events by ID, source, session, recorded time,
all lexical terms or an exact UTF-8 phrase without semantic publication. Results
carry role, source version, omission/partial status and immutable payload/span
digests. Equal text in separate events stays separate. Model-request occurrences
require explicit audit selection and retain their dependent-source label.

The analyzer lowercases Unicode alphanumeric/underscore terms while retaining
original byte offsets; exact phrases preserve case, punctuation, whitespace and
Unicode normalization form. Binary originals remain addressable without invented
text. Encrypted cursors bind the database, query, current principal and logical
knowledge position. Every resumed page rechecks current source permissions.
Work/byte exhaustion returns an explicit partial status and continuation; it is
not a negative answer. Direct IDs do not depend on index readiness. The oracle
scans bounded outbox pages on other routes; interactive selection uses persisted
postings, source/session/time routes and addressed causal neighbors.

`project_originals` builds from the native outbox outside the writer lock and
publishes a generation manifest after comparing its predecessor and authorization
epoch. Rebuilds switch separately constructed generations after catch-up. Reads
use short Fjall snapshots; neither index construction nor archive-wide corpus
materialization runs inside a query. Empty projection polls do not create writes.

Scope eligibility precedes domain labels and content search. Each domain includes
the original's policy and every source dependency's policy. Ranking uses match
spread, source length and stable ID, with no cross-domain document-frequency
statistics. Native source revocation atomically advances authorization/scope
epochs and journals the accepted transition. Old indexed routes are disabled
until rebuild, and historical reads still enforce revocation. Semantic retirement
and current-head overlays are integrated by the temporal-state phase.

The initial index profile admits 1,024 eligible domains, 128 pending raw events,
64 concurrent read views (30-second lifetime), three retained generations and
15-minute encrypted cursors. Source lexical projections cover up to 1 MiB and
16,384 unique terms; larger sources remain on an explicit unindexed route.
Exact phrases use a safe interior-word anchor when available, otherwise bounded
metadata/range traversal. Exhaustive pages freeze generation coverage and tail;
top-k reports incomplete work separately. Shared work/byte/deadline/cancellation
checks cover the query and projection publication lock. These finite bounds do
not establish the million-event latency target or eliminate hardware timing
channels. Generation reclamation and broader custody controls follow in hardening.

Reconcile an index generation with a bounded revision overlay that includes
updates, retractions, supersession, deletion and permission changes. Mask old
heads and refill candidate pages within the remaining work budget. An exhausted
overlay reports unavailable freshness instead of returning stale current state.
Historical content always uses current permissions, including permissions of
every evidence source independently of the containing claim.

`known_at` selects retained logical history; `valid_at` selects applicability.
Physical snapshots are short lived (the baseline Fjall adapter retains 64).
Future valid-time boundaries can invalidate a lease without a new write. Raw
pending interpretation is a separate coverage state: capture does not prove that
all natural-language constraints were understood.

Selective retrieval returns bounded evidence and gaps. Exhaustive retrieval
uses snapshot-bound enumeration or aggregation with explicit scan coverage.
Current-state reads return resolution, conflict or unknown with provenance.
STOP, top-k and a missing hit do not certify an exhaustive negative answer.

## Compilation and dispatch

1. Select and freeze the prospective hot layout **after planned eviction**.
   Only completed, durably captured protocol groups can be evicted.
2. Build mandatory constraints and evidence closure. Scoped obligations release
   their pins when completed or cancelled; their originals remain addressable.
3. Route optional units against that final visible span inventory. Choose
   support alternatives, account for shared evidence and consider bounded
   complementary bundles. STOP retains exactly the mandatory closure.
4. Render the complete ordered request. Count control, schemas, protocol,
   multimodal inputs, hot groups, current turn, evidence and output/headroom
   reserves. If the hot layout changes, recalculate visibility and selection.
5. Validate every source-derived zone, including hot history, notes and provider
   continuation items. Matching a digest does not grant source authority.
6. On the publication owner, atomically compare relevant scope/policy epochs and
   temporal expiry, then register the lease. Recheck before disclosure/effect.
   Notifications supplement epoch checks; they never replace them.

Mandatory overflow produces a typed budget failure, not a silently dropped
restriction. Scoring has bounded cancellation and fallback within the same
overall deadline. Unknown IDs, non-finite scores and stale bindings are rejected.
Provider profiles declare exact or conservative token accounting and support for
clean requests. Opaque remote history cannot claim selective context replacement.

External effects require the receiver's version/ETag/idempotency support where
available. The gap between a database check and an external effect is not an
atomic transaction. A request without a durable outcome becomes outcome unknown;
resume reconciles it before retrying. Shadow routers cannot execute effects.

## Provenance, migration and evaluation

Capture each model request as an occurrence plus an ordered source manifest and
novel bytes. Repeated exposure is auditable but does not create independent
corroboration. Exact wire replay requires retained bytes and the renderer version.
Missing, restricted or upstream-truncated originals are explicitly identified.

Migration preserves UUIDs, source links, policy and bitemporal history, with a
dry run, shadow comparison, one writer fence and a supported rollback export.
Legacy summaries without raw sources are never presented as original quotations.
Restore must apply current deletion/revocation suppression before reads. Logical
tombstones and backup controls are not claims of physical deletion everywhere.

Evaluate the same histories, reader, budget and resettable world against rolling,
good summary, summary plus archive/hybrid retrieval, raw hybrid and R0. Separate
archive, candidate, ranking, packing, state and reader errors. Training features
use only query-time evidence; targets and future outcomes are separate. Changed
counterfactual tool actions require a fresh sandbox outcome, not a reused result.

Reports include attempted-task cost, success rate, cost per success, actual
cache/input/output usage, processing/retry costs, latency and losing cases.
Unknown usage stays unknown. A model score, finite oracle, passing build or
smaller prompt is not proof of product benefit or production certification.
Open-reader differentiable gates and online RL are optional research profiles.
