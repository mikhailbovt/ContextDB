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

## Retrieval and current state

Interactive retrieval queries persistent indexes within an authorized domain;
it does not materialize the archive or rebuild a lexical index on each query.
The existing exact corpus provider remains a reference oracle. ID, source,
time/range and lexical routes work with extraction and embeddings disabled.
Analyzer versions, index coverage, outbox progress and query work are explicit.

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
