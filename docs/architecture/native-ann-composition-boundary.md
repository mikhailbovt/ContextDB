# Native service to persistent ANN-v2 composition boundary

- Status: design blocker recorded; no server/native ANN acceleration claim
- Applies to: `contextdb-native-service`, `contextdb-recall`, and
  `contextdb-index` with `ann-hnsw`
- Correctness authority: the native Fjall revision store and its policy labels
- Accelerator: `PersistentAnnV2`, always rebuildable and never authoritative

## Decision

The current APIs do not admit a truthful, observable-equivalent ANN fast path
for native `CompileContext`. `PersistentAnnV2` remains a real persistent engine
and benchmark component, but it is not wired into the native recall result path.

Two tempting implementations are explicitly rejected:

1. returning only ANN hits from `RecallProvider::authorized_corpus`; this drops
   candidates required by the lexical, structural, temporal, relationship,
   evidence, and conflict routes and therefore changes ContextPack results; and
2. executing ANN and then returning the same fully materialized exact corpus;
   this exercises the index in shadow mode but performs no acceleration and
   must not be reported as server composition.

The native service continues to use the exact, policy-first provider until the
additive contracts below exist. This is a safe correctness fallback, not a
waiver of the production ANN requirement.

## What is implemented today

The ANN-v2 implementation is not a stub. With `ann-hnsw`, `contextdb-index`
provides all of the following independently testable components:

- an immutable, paged, full-precision `PersistentAnnVectorSourceV2` with
  authenticated vector, route, target, and vector-space roots;
- inactive-generation construction, verification, atomic publication, reopen,
  interrupted-build recovery, generation leases, and bounded pruning;
- a storage-backed authorization universe containing route identities rather
  than vector bytes;
- exact-policy partitions, bounded HNSW traversal, exact full-precision
  reranking, and an exact fallback for partial partitions;
- immutable post-generation deltas and irreversible current-use tombstones;
  and
- fail-closed validation of route, overlay, universe, manifest, and graph
  corruption.

The runtime tests exercise exact-oracle differential search, policy-before-
vector reads, delta and tombstone behavior, persistent universe paging, Redb
reopen, process-kill recovery, lease-aware retention, and corruption failures.
The semantic BENCH-H development runner also builds, verifies, queries, and
reopens that engine. Those facts prove a live engine boundary; they do not prove
that the native service uses it for recall.

The native service separately implements the required authority boundary:
workspace-partitioned policy rows are scanned and authorized before revision
content is loaded. Its `CompileContext` adapter returns a complete authorized
corpus to the deterministic RecallEngine and currently labels caller-supplied
vectors as `native-exact-scan-v1`.

## Why direct composition is currently unsafe

### 1. Recall has no candidate-route boundary

`RecallProvider` exposes only two operations: pin a snapshot and return a fully
materialized `AuthorizedCorpus`. `AuthorizedCorpus::authorize` validates and
sorts complete documents. The RecallEngine then computes every route,
including the supplied-vector cosine route, from those documents.

The `ProviderRequest` passed to `authorized_corpus` contains only the pinned
snapshot, principal, and filter digest; it does not contain the supplied query
vector. The provider therefore cannot even select a vector-space-specific ANN
route under the present trait without smuggling query state outside the
request binding.

There is no contract for an authorized provider to return a vector ranking,
lazy document handles, route-specific candidates, or an exact materializer for
a bounded union of candidate IDs. Consequently an ANN subset is observably
incorrect, while ANN plus a full exact scan is observably equivalent but not a
fast path.

### 2. Native vectors have no immutable space identity

`MemoryDocument.vector` is only `Option<Vec<f32>>`. It does not bind values to
the immutable compatibility metadata required by `VectorSpace`: ID,
dimensions, metric, model family, model revision, preprocessing revision, and
modality. `CompileContextPlan.query_vector` carries a caller-supplied string
space and values, while the native provider currently assigns every stored
vector the hard-coded `native-exact-scan-v1` label.

Inventing a model, preprocessing contract, metric, embedding, or UUID from the
values would silently merge incompatible spaces. Deriving a space only from
dimension count is also invalid: equal-length vectors from different models
are not comparable. Legacy untyped vectors must therefore remain exact-only.

### 3. ANN-local policy is not the native policy authority

Native `AccessPolicy` supports exact audience-to-purpose grants, consent, and
the service's authenticated audience semantics. `IndexPolicy` is a routing
projection with Cartesian purpose/owner fields. Translating exact grants into
that smaller shape can broaden access. Calling the existing ANN
`authorize(IndexPrincipal, ...)` as an independent authority would create two
policy decisions and violate the single-authority design.

The future composition must pass an opaque set or cursor of representation IDs
already admitted by the native policy scan into the ANN runtime. The index may
verify membership and visibility, but it must not reinterpret a lossy policy
projection.

### 4. Projection publication is not part of semantic atomicity

Native semantic mutations commit policy, content, history, idempotency, and the
event chain in one Fjall transaction. ANN generation and overlay operations
commit separately. Calling `publish_delta` after a semantic commit without a
durable projection intent leaves an unobservable crash window and permits a
false vector watermark.

A rebuildable index may lag, but the lag and the work needed to repair it must
be durable and explicit. Correction and retraction also require immediate
current-use suppression even when a historical ANN generation remains leased.

## Required additive contracts

### Typed vector projection input

Add a versioned typed vector projection alongside the legacy `vector` field.
At minimum it must bind values to a registered immutable vector-space ID. The
registry entry must contain dimensions, metric, model family/revision,
preprocessing revision, and modality. Existing untyped vectors deserialize as
legacy and continue through the exact route only.

The service, not a caller or model, derives each immutable representation ID
from a domain-separated digest of database identity, workspace identity,
logical record identity, revision, and vector-space identity. A correction
gets a new representation; an ID can never be rebound to different bytes.

Publication also needs either a typed vector on `PublishMemoryRequest` or a
separate authenticated projection operation. Today an initial explicit memory
publication cannot supply one; only a complete correction document can.

### Two-phase authorized recall provider

Introduce an additive provider contract rather than changing the existing
fallback. The exact names may change, but the boundaries must remain:

```text
pin_snapshot(at_commit)
  -> ProviderSnapshot

authorize_routes(snapshot, principal, temporal/policy filters)
  -> opaque AuthorizedRouteUniverse

rank_route(universe, SuppliedVector, exact result ceiling, work budget)
  -> exact-reranked authorized IDs + route scores + projection trace

materialize_authorized(universe, union of route IDs and required closure IDs)
  -> labelled documents, relations, and evidence
```

The RecallEngine must merge the returned supplied-vector ranking with lexical,
structural, temporal, relationship, and other route rankings before requesting
content. It must then materialize the bounded union plus graph/evidence closure.
The existing full-corpus method remains the exact fallback.

The ANN runtime needs a narrow authorization entry point that accepts IDs from
the authoritative native universe. It may persist an opaque universe and lease
exactly as today. It must not expose unauthorized cardinality or route content
beyond the existing ANN contract, and vector/target point reads remain
forbidden until the native authority admitted the corresponding ID.

## Durable projection protocol

The recommended projection shares the native Fjall database through distinct
keyspaces; the semantic store remains authoritative and all ANN state remains
rebuildable. A separate physical sidecar is acceptable only with an
authoritative custody manifest and the same recovery behavior.

1. The semantic mutation transaction writes a content-free projection intent:
   operation, representation ID, vector-space ID, revision pointer, policy
   digest, and workspace commit. Values are not copied into routing rows.
2. A bounded worker reads policy/intent first, then materializes the exact
   revision vector through an internal authorized point read.
3. If an active source generation covers the space, a new representation is
   published as an immutable delta. New or incompatible spaces request a
   generation rebuild from a pinned native snapshot.
4. Correction writes a tombstone intent for the old representation and an add
   intent for the successor in the same semantic transaction. Retraction writes
   the tombstone intent in that transaction. Tombstone application precedes
   publication of a vector watermark for the commit.
5. Completion records are idempotent and bound to the exact intent digest.
   Reopen drains incomplete intents. Corrupt or divergent projection state
   fails closed to exact recall and marks the accelerator degraded; it never
   changes semantic records.
6. `Watermarks.vector` advances only through the greatest contiguous workspace
   commit whose vector intents are complete. Provider vector-space watermarks
   report the actual active generation coverage, never the journal head by
   construction.
7. Rotation retains the matching immutable full-precision source for every
   leased historical generation. Pruning a generation and its source is one
   custody operation after all leases are released.

No full semantic transaction waits for HNSW construction. A synchronous
tombstone/suppression route must still prevent a retracted representation from
current-use recall before the mutation is acknowledged or the exact fallback
must be forced until suppression catches up.

## Fast-path eligibility and fallback

ANN may participate only when all of these are true:

- the stored representation and query name the same registered typed space;
- dimensions, metric, model revision, and preprocessing revision match;
- the native authority produced the universe for the exact pinned snapshot;
- the active generation and overlay are verified and their watermark satisfies
  the request's staleness contract;
- current-use tombstones cover the pinned semantic head; and
- route work budgets can produce the exact result ceiling required by the
  deterministic planner.

Legacy vectors, unknown spaces, historical source gaps, unsupported policy
forms, stale or absent generations, corruption, exhausted exact fallback, and
incomplete projection intents all select the existing exact path. A fallback
must be recorded in a privacy-safe trace without names or counts derived from
rejected records.

## Acceptance tests for future wiring

The native/server capability remains unavailable until all of the following
tests pass against the composed service, not just `contextdb-index`:

1. typed-space base generation: exact and ANN supplied-vector route IDs, order,
   and score representation match at the planner's result ceiling;
2. combined-route equivalence: complete ContextPack bytes and trace semantics
   match the exact provider for lexical plus vector, temporal plus vector, and
   relationship/evidence cases;
3. same-workspace denied canary: changing denied content, vector values, or
   target bytes cannot change authorized results, authorized counts, trace
   fields, or vector/target point-read audit records;
4. exact audience-purpose grants: supported grants match the native decision;
   unsupported/complex grants force exact fallback without broadening;
5. correction: the successor has a distinct immutable representation, the old
   representation is tombstoned, and both current and retained-snapshot
   semantics match the exact oracle;
6. retraction: an already-created universe cannot return the tombstoned ID and
   ContextPack cannot contain its canary;
7. delta and generation reopen: source seal, active manifest, overlay,
   watermarks, and exact differential results survive process restart;
8. crash matrix: process termination after semantic commit, after intent
   claim, after delta/tombstone commit, and before completion converges by
   idempotent recovery without a false watermark;
9. corruption: route/source/overlay/outbox divergence disables acceleration or
   fails the request according to the declared availability policy, never
   silently returning a partial ANN subset; and
10. generation rotation: old leased universes retain their matching source,
    current queries use the new generation, and bounded pruning reclaims both
    only after lease release.

Performance evidence starts only after these differential tests are green.
The existing ANN benchmarks remain component evidence and cannot be relabelled
as native/server acceleration measurements.

## Capability statement

Until this design is implemented, manifests and documentation must say:

- native semantic storage and exact policy-first ContextPack: available;
- persistent ANN-v2 engine and standalone differential benchmark path:
  available as a development component; and
- native/server ANN acceleration: not wired.

This boundary is independent of the deferred hard-delete/security work. It is
a correctness and API-composition blocker, not a security-scan finding.
