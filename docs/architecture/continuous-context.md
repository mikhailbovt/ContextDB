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

This applies to ordinary conversation, jokes, incidental details, rejected ideas,
documents, images and action results as well as project work. Retention does not
require predicted importance. A retained detail that is not retrieved when needed
still counts as forgetting; automatic preparation and measured reader continuity
are product gates, not consequences of having an archive.

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
The legacy native prefix contains audit hashes. New record writes retain the
actual accepted record/edge revisions behind digest-bound journal references,
including negative closures; assertion publications retain their complete typed
batch. Reconstruction uses these bytes and source history. Activation is explicit
(`continuous-record-mutations-v1` / `continuous-assertions-v1`); neither retrofit
claims to recreate an old payload that the legacy journal never retained.

New record births and closures also bind a compact control in the same Sync
(`continuous-record-controls-v1`). It retains host access policy, lifecycle and
time, with hashes for record/link identifiers, values, text, vectors and
attributes. Scope reconstruction can use these accepted controls. Their complete
family and exact match to full bodies are verified across reopen and restore;
missing controls cannot fall back to legacy behavior. Old references keep their
encoding and receipts. Unpruned bodies remain required. Controls have a separate
16 MiB bound per mutation group; overflow rejects the complete publication.

`prepare_record_controls` adds verified controls for one older full mutation group
through a separate accepted publication (`continuous-record-control-preparation-v1`).
It requires Admin and each revision's access policy, uses bounded analysis and a
workspace CAS, and preserves original events and receipts. Retries validate the
accepted history; a missing locator cannot create another preparation. Prepared
controls support scope reconstruction; deletion also requires an independent
removal witness and an accepted pruning publication.
Hash-only history and unknown source provenance still require explicit migration.
Origin classification and control preparation can inspect non-retrievable legacy
revisions for cleanup; scope, audience, purpose, consent and clearance still apply.
Neither operation changes the stored disclosure policy.

`prepare_record_removal` verifies one classified revision's accepted birth and
optional closure, then retains their controls in the independent v3 removal
journal. The witness binds an exact removal request and captured source, plus
typed candidate roles and hashed graph/provenance facts. Record bodies, endpoint
names and proposal actor/request strings are excluded. Old journal entries keep
their encoding; new witnesses use a `record_witness` operation. Admin, revision
policy, bounded analysis and a workspace CAS precede external Sync. Retries
check accepted history even when a locator is missing. The witness survives
native restore; it neither erases bodies nor completes removal. Older full
mutations require explicit control preparation first.

`prune_record_revision` removes a classified revision's primary projection and
every accepted birth/closure body in one native Sync. Its retained witness, current
policy and workspace CAS bind the operation. Before the first member of a
source-aware group disappears, the complete group's validation is independently
committed against its exact event and origin intent. Deep verification then uses
the retained controls and typed graph facts, checks all remaining bodies and
rejects missing metadata or resurrected copies. Original receipts and hashed
identity reservations survive partial cleanup, reopen and native restore.

The first native capture implementation exposes `CapturePort` and the
`NativeConversationCapture` host adapter (`contextdb-chat/service-adapter`).
It preserves UTF-8 or binary originals, explicit omissions, immutable edits,
producer gaps and ordered response chunks. Each capture journal entry references
its accepted original and digest; the durable outbox carries the same reference.
Raw reads require current `ReadEvidence` and `RawEvidence` authorization.

New captures also bind compact recovery metadata into both the journal and outbox
(`continuous-capture-recovery-v1`). It retains typed identities, dependency handles,
coverage and checkpoint control transitions, with digests for arbitrary strings
and payloads. Verification compares it to the complete original before replaying
producer, stream, scope and run heads. Activation preserves the legacy prefix;
subsequent missing metadata fails verification. An explicitly pruned original also
requires independently retained control commitments and accepted native removal
publications. Recovery metadata alone never permits a missing body or changes
the original's immutable receipt.

`inspect_original_deletion` computes captured descendants from the accepted
journal, including revisions, model/tool/checkpoint inputs and shared staged
originals. A shared original reaches earlier owners and their descendants;
unrelated novel blocks still used by an independent capture are retained.
Equal text, equal ACLs and causal-only links do not establish dependency.
The administrative scan checks the global event chain and complete workspace
mapping in bounded pages, then rechecks the workspace commit before returning
only identities, receipts and digests. Its work grows with retained history;
budget exhaustion returns no partial inventory. The report covers source/payload
lineage only, with at most 65,536 targets; semantic records, keys and external
copies require further inventory. It does not suppress or remove anything.

The initial profile uses strict pause: retain the input and retry the same key
until a synchronized receipt arrives. It admits at most 256 KiB per inline
payload and 128 disjoint producer gaps. Overflow is an explicit
`ResourceExhausted`, with no partial publication. No disk spool is claimed.

First capture atomically enables the `continuous-capture-v1` format feature.
Older binaries reject this extended manifest. New code still reads legacy
databases and v1 backups; backups containing continuous capture or accepted
semantic payloads use the explicit v2 format.
Restore verifies original/receipt/outbox/producer/scope/stream closure before
writing a pristine target. A restored receipt remains usable after host-key
rotation, with fresh authorization and exact stored-receipt equality.

Continuous restore requires a bound native opener and the same
independently retained `NativeSuppressionLedger` identity. Create that authority
in a separate directory tree, retain its ID in host recovery configuration, and
reopen it with `NativeSuppressionLedger::open`; a missing or different authority
fails closed. Native backups never copy or replace the external ledger. Unbound
archives containing captures remain verifiable archival data and require explicit migration
before restore; supplying a newly created empty ledger cannot establish freshness.

Original revocations synchronize the external denial before native publication.
An epoch mismatch closes workspace disclosure across reads, indexed views,
checkpoints and runtime fences, including after a process crash or old-backup
restore. `maintain_suppression` imports at most 256 entries per budgeted call;
then `maintain_custody` propagates inherited restrictions and raw indexes rebuild.
Restore completion acknowledges archive installation; reads stay closed until
these gates pass. New denials after restore close them again. Independent capture
can continue, but an externally denied source ID cannot be recaptured. Competing
native owners compare the external head under its publication owner before append.

Explicit removal has a separate durable request. `request_original_removal`
retains the complete inspected source inventory and every known descendant-ID
denial in one external Sync. Version 2 and later authorities require permanent
workspace registration and request history; legacy authorities require migration.
Request-bound pages prove exact source and block membership. Shared novel blocks
with an independent captured owner are excluded from removal targets.

Version 3 authorities additionally retain immutable captured origins for ordinary
record revisions. `bind_record_sources` accepts an authenticated administrator's
complete declaration of 1..64 earlier captures and binds their controls to the
original accepted record bytes. Empty evidence links or similar text never prove
independence. The external declaration survives native restore and closes
disclosure until `maintain_record_sources` verifies and applies its prefix. Each
page contains at most 256 entries and 384 KiB; native application compares the
workspace before one Sync. Applied progress is journal-bound and advances the
declared record scopes. Whole registry loss is an error, including at reopen.

`initialize_record_sources` activates these requirements before the first generic
record. It checks accepted workspace history and policy projections within a
budget, then compares the workspace before external Sync. Captured history may
already exist; existing generic records require explicit migration. Registration
is a separate journal control and preserves existing v3 record-binding bytes.

Once a workspace is activated, unclassified record revisions are
unavailable. Get, timeline, candidate/ordinary recall, traversal and ContextPack
reads apply current original and inherited custody policies before loading record
bodies. Independent records remain available after ordinary source revocation.
`publish_memory_from_sources` accepts explicit memory and complete captured-input
controls in one native Sync, then transfers its actual birth commitments to the
retained authority. Reads wait for a separate journal-bound completion, including
after manual provenance catch-up or an older restore. An interrupted response
includes the accepted workspace commit; exact retry or `resume_record_source_write`
finishes that same operation without its original request body. Current source
revocation still denies disclosure. Restored archives cannot reuse retained record
identities, and administrative repair cannot replace accepted input declarations.
`propose_memory_from_sources` and `retract_from_sources` extend this handoff to
complete candidate/link and retraction groups. Copied revisions retain predecessor
origins plus new captured inputs; independent new candidates retain their own
inputs. Closed revisions keep their original birth bindings. New and historical
reads wait for the entire group to complete, even if some origins have transferred.
Candidates remain quarantined. Structural writes reject an unavailable edge in
the affected access domain instead of silently omitting it; source authorization
precedes body decoding. Groups retain at most 1,024 mutations / 16 MiB, with 1..64
origins per new revision; an unrepresentable union rejects the whole publication.
`correct_memory_from_sources` binds the exact target closure and each rewired
hierarchy edge to its predecessor. Its fully supplied successor uses new captured
inputs; each copied edge also retains its own predecessor's origins. Verification
reconstructs copied metadata and rejects missing or swapped copy witnesses before
transfer. The correction format is explicitly versioned; older groups keep their
original encoding. Completion retries up to two snapshot conflicts within the
shared budget, rechecking accepted history without accepting another mutation.
`pending_record_source_writes` discovers interrupted groups from accepted workspace
commits in pages of 1..256. `repair_record_source_writes` returns continuation only
after a complete page has been repaired. Cursors bind the caller, database,
operation and fixed journal frontier; restore revalidates their history anchors.
Missing mappings, intents, receipts or completion proofs fail closed. Before
creating a missing completion, recovery checks later accepted events to reject a
lost locator for an already completed group. Control reads share the operation's
work, byte, time and cancellation budget, with bytes charged before decoding.

The owned runtime invokes recovery on start, resume and before each interaction.
It requires the host's Runtime and Admin grants in a source-aware workspace;
model output cannot grant them. A bounded process-local cache retains completed
64-commit pages between attempts. Reopen rechecks accepted history; durable
checkpoints and measured recovery/backlog limits remain open. Proving a completion
absent may rescan the later journal after budget exhaustion. Origin aggregation
for longer revision chains also remains unfinished.
Legacy workspaces retain their existing behavior. Version 1/2 authorities require
explicit migration before accepting origins; this API does not perform migration
or establish that a host's declaration is semantically complete.

The current local maintenance sequence is:

1. `prepare_original_removal_sources` validates complete originals and their
   dependencies, revokes access and retains immutable control commitments.
2. `maintain_custody`, `project_originals` and `reclaim_raw_generations` propagate
   restrictions, build a generation omitting prepared sources and discard old copies.
3. `prune_source_assertions` removes affected assertions and retractions from one
   accepted batch, preserving independent mutations and the original receipt.
   Journal-bound controls retain IDs, evidence offsets/hashes and negative
   relationships without values or envelopes. Explicit host authority policies
   remain schema configuration. Pruned labels permanently report unavailable
   support, so an erased negative transition cannot revive an old current value.
4. `prepare_record_removal` and `prune_record_revision` remove affected generic
   revisions, including copied edges and historical bodies. Primary removal
   checks the complete revision inventory; unknown origins or unaccepted copies
   block cleanup, while independently sourced records remain intact.
5. `prune_original_sources` removes up to 256 primary body rows per Sync, retaining
   exact policy/control commitments and journal-bound tombstones.
6. `prune_original_payload` removes up to 32 staged chunks (8 MiB) per Sync after
   all affected primary bodies are pruned. Starting a block checks fresh ownership
   and its full original, at most 64 MiB; continuation verifies the accepted progress
   chain and the next batch. The immutable staging header remains available.

Analysis precedes publication; a changed workspace rejects the attempt without
partial removal. Restart and pristine restore resume the exact accepted progress.
Missing tombstones, unexplained chunk holes, resurrected data and changed controls
fail verification. A backup made during cleanup hashes the actual remaining rows
with the existing deep-digest algorithm; old full archives remain verifiable under
the retained keys and restore behind current suppression.

This executor is incomplete: primary pruning rejects affected assertions or
generic revisions whose body copies remain, and records with unknown origins.
No local completion/admission publication exists, so removal requests continue to
close disclosure. Complete copy inventory, legacy migration, key disablement and
physical/provider/export/backup dispositions remain open. These Rust APIs do not
claim completed hard deletion or expose a model-facing deletion tool.

`NativeService::open_with_suppression` retains plaintext native values.
`NativeService::open_encrypted` additionally requires `NativeCustodyKeys` and seals
every native value, including original bodies, chunks, index documents, accepted
semantic batches and captured checkpoints. New version 3 key authorities allocate
a random data key per changed value address per native transaction. Historical
ciphertext retains its exact key identity; rewriting a mixed-content row uses a
different key. Version 1 and 2 authorities retain their original address-key reuse
and require explicit migration to this profile. XChaCha20-Poly1305 binds ciphertext
to the database, authority, keyspace, record address and key identity.

New keys and an authenticated allocation journal synchronize in one bounded batch
before native publication, with at most 16,384 changed addresses. An interrupted
publication may leave unused keys, never an acknowledged original without its
durable key. Ordinary reads fetch one exact key descriptor. Opening the authority
verifies the complete allocation journal and key inventory, rejecting missing,
changed or orphaned versions. Historical keys remain available; allocation does
not disable keys or establish deletion completion.

`key_catalog_page` enumerates at most 256 accepted descriptors with a shared
work/byte/time budget and an authenticated continuation. Pages bind the authority,
allocation revision and exact batch chain; new allocations invalidate a pending
enumeration, while backup registration alone does not. Continuations survive
authority reopen. New journal records contain at most 256 descriptors, all sharing
the transaction's key-store Sync; older larger batches remain readable and budgeted.
Descriptors expose address/key identities and commitments,
without wrapped or raw keys; the complete chain must reach its retained terminal.
This is allocation evidence, including potentially unused keys after interruption.

Admin `read_original_key_inventory` joins that catalog to the selected request's
retained roots and descendants, including historical primary keys after pruning
or old-native restore. `read_payload_key_inventory` identifies each selected
block's chunk keys from retained ownership and length, even if an older archive
predates staging. Independent source addresses and retained shared blocks are
excluded. `read_record_key_inventory` uses an independent revision witness to
identify its historical primary, accepted birth and optional closure keys; Admin
and all other stored access labels remain required for non-retrievable revisions.
Each complete scan admits at most 65,536 selected allocations and 32 MiB of output.
These reports do not prove native use or physical absence, cover all copy classes,
retire keys or reopen disclosure.

Create the key inventory in its own directory and independently retain its ID and
host-provisioned `CustodyMasterKey`. Reopen with `NativeCustodyKeys::open`; never
derive that master key from the rotatable token key. Encrypted backups use
`contextdb.native-fjall.encrypted-backup.v3`, preserve ciphertext and require the
same current key and suppression authorities. Neither authority nor the master key
is included. Restore checks logical closure and authenticates each exact address
and key before importing the original ciphertext, preserving historical key IDs
without allocating a fresh key batch for the archive.
Wrong/missing keys and plaintext/encrypted format mismatches fail without fallback.
Existing plaintext stores require a separate explicit migration.

Version 2 and later key authorities retain an authenticated issued-backup registry.
Archive digest, logical verification digest, commit, size and predecessor are
synchronized before encrypted backup bytes are returned. Exact retries reuse the
registration, including after a crash before the response. `backup_registration`
provides a point lookup; `backup_catalog_page` returns at most 256 entries and
requires the same registry revision across pages. New key allocations alone do
not invalidate that enumeration. Native restore never imports or rewinds the registry.
Version 1 authorities still open existing values, but creating new backups requires
explicit registry migration; a missing required registry is corruption, never an empty
replacement. Registrations count distinct issued archives, not physical copies.
They contain no source payload and prove neither external-copy erasure nor absence.

These are local Rust APIs; the CLI and MCP do not yet provision this encrypted
profile. Record addresses, sizes, lexical hashes and archive metadata remain
visible. Values are limited to 16 MiB before encryption; each envelope adds 64
bytes, counted against scan and backup limits. Inventory growth is incremental;
key reclamation, key rotation and deletion closure remain open. This profile
requires retention of the current independent directories and does not detect
rollback of all authorities, provide a remote monotonic anchor or prove physical
erasure. Native receipts and external denials contain source identities/digests.

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
channels. Encryption and physical deletion remain separate hardening gates.

Admin `reclaim_raw_generations(context, max_rows, budget)` removes obsolete
generation rows in batches of at most 1,024 rows / 8 MiB. The three-generation
limit applies to retained generations; identities continue increasing after
reclamation. Active and current building generations are protected. A build with
obsolete authorization or format may be abandoned, allowing a fresh rebuild
after revocation. Empty maintenance polls do not publish journal entries.

The `continuous-raw-generation-gc-v1` feature retains unfinished cleanup across
restart and backup/restore. Verification reconstructs every usable generation;
rows in the explicitly unreachable generation being discarded are opaque garbage
until cleanup completes. Existing short-lived physical read views can retain
their earlier bytes. This API reclaims logical index rows and does not certify
physical erasure, blob deletion or backup suppression.

### Inherited disclosure restrictions

`continuous-derived-custody-v1` materializes the intersection of input policies
at capture. Model outputs inherit their exact request; tool results inherit their
intent and the intent's captured proposal. Checkpoints inherit hot/required
sources, pending attempts/proposals and their last model output. Declared revisions
inherit their predecessor; full replacement bytes alone cannot declassify them.
Ordinary causal links between independent observations do not declare derivation.
Repeated policies are deduplicated; read-time authorization does not traverse the
conversation. The initial profile allows 128 distinct policies and 1 MiB of custody
metadata per capture, with explicit backpressure at either limit.

`revoke_original` atomically closes workspace disclosure and advances its policy
epoch. Admin `maintain_custody(context, max_events, budget)` propagates restrictions
in capture order, at most 256 records per call. Query admission remains closed
until `caught_up`; derived captures wait, while independent originals can still
be saved. Analysis runs outside publication authority, with deadline/work/byte
checks. Publication compares the analyzed state and epoch and checks newly arrived
captures before reopening the gate. Restart and logical backup/restore preserve
unfinished work. Historical reads and checkpoint recovery use these current
restrictions, including restrictions inherited through model/tool responses.

Legacy continuous stores require the same explicit bounded custody migration
before disclosure. Afterwards, rebuild any existing raw generation with
`project_originals(..., true, ...)`, then continue with `rebuild=false` until
`caught_up`. Legacy index labels cannot become trusted merely because migration
finished. Deep verification reconstructs the checked prefix from immutable
originals; pending rows remain inaccessible until rebuilt. These Rust admin APIs
do not imply automatic background maintenance or an exposed MCP/SDK endpoint.

Capture and maintenance share a FIFO publication queue with 64 slots including
the active writer. Full admission returns retryable backpressure before opening
a transaction. Waits honor the caller's budget and have a 30-second ceiling;
cancelled waiters release their slot without overtaking other publishers.

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

`AssertionPort` adds a trusted host interpreter boundary over existing `Claim`,
`ClaimRevision`, `BitemporalRange` and evidence identities. A versioned authority
policy grants exact adapter/actor/role combinations for a predicate and scope.
Assistant proposals and model inferences remain attributed assertions without
resolution authority. Observed configuration and desired policy use different
predicate identities. Incompatible authorized values produce an explicit
conflict; correction requires supported supersession, and retraction is an
explicit negative transition. Removing a replacement's permission cannot revive
its predecessor as current. Evidence source identities and spans are verified
against capture, independently of the containing assertion's narrower envelope.

Publication compares the affected scope epoch and atomically writes accepted
semantics, interpreter/version, coverage and a new epoch. A pending original,
partial observation or producer gap blocks an unqualified current value. Raw
overlay overflow returns `IndexTooStale`. An unchanged fully interpreted scope
skips unrelated raw backlog. The bounded profile admits 128 outbox entries per
interpretation window, 128 unresolved sources, 64 changes / 4 MiB per assertion
batch, 64 authority revisions and 512 changes per queried slot. Existing native
record mutations are capped at 1,024 writes / 16 MiB per commit. Maintenance and
larger supported profiles remain explicit work; no archive-size latency SLO is
inferred from these bounds. Returned state has an opaque principal/epoch binding
and the next valid-time boundary; it is not an action lease. Historical reads
retain current source permissions, and consent uses current wall time.

Selective retrieval returns bounded evidence and gaps. Exhaustive retrieval
uses snapshot-bound enumeration or aggregation with explicit scan coverage.
Current-state reads return resolution, conflict or unknown with provenance.
STOP, top-k and a missing hit do not certify an exhaustive negative answer.

## Compilation and dispatch

`PrepareContextPort` connects the native owner to `ContextCompiler::compile_assembly`.
It discovers applicable authority keys from a scoped catalog, resolves mandatory
state, and combines it with a bounded indexed raw frontier. Administrative
`initialize_state_catalog` builds existing keys explicitly; later policy writes
maintain the directory in the same synchronized publication. Queries never rebuild
it. Activation uses `continuous-state-catalog-v1`; restore and deep verification
check the directory against accepted authority history.

`RawObservation` carries historical originals without inventing claim IDs.
`PackEvidence.original_span` binds the event, payload version, byte range and
BLAKE3 digest. Small text originals are included whole; larger lexical hits add
bounded surrounding context. Binary, unavailable or oversized unqualified sources
produce explicit mandatory unknown markers and source addresses. They are not
represented as exact quotations. Existing canonical packs keep their byte format
when these additive fields are absent; Rust, Python, Go and TypeScript share an
original-evidence fixture.

The assembly manifest binds the layout, model profile, canonical pack, ordered
occurrences, full request wire, exact source read-set and opaque scope/policy view.
The compiler verifies hot/current sources before deduplication, includes hard
dependencies and sufficient support alternatives before admission, and measures
each optional singleton or bounded complementary pair against the complete
rendered request. Shared source ranges count once. R0 can stop without removing
mandatory state; it cannot confer authority. Preparation rechecks scope/policy
epochs and temporal expiry after rendering; registration remains a separate step.

The initial embedded profile supports 32 scopes, 256 mandatory slots, eight raw
routes, 512 candidates, 2,048 supports, 64 complementary pairs and a caller-bounded
selection work limit. The reference JSON encoder uses its declared reference
tokenizer; it is not a vendor model protocol or model tokenization claim. Actual
provider integration and transport adapters remain separate delivery gates.

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

## Owned conversation lifecycle

`contextdb-agent-runtime` owns bounded conversational residency independently of
the database foundation runtime. Its buffered text/protocol path captures input, selects
post-eviction hot groups, derives bounded lexical discovery routes, prepares and
captures the whole request, calls a required dispatch guard, then captures the
visible response. A bounded `drive` loop executes registered tools and source-bound
memory expansion between model calls. A missing interpreter retains explicit
unknown state; it does not certify arbitrary text as understood. The owner dispatch
adapter checks native leases. A bounded local text reader is measured separately
in the [comparison harness](../../benchmarks/continuous-context/README.md).

`OwnedRunPort` publishes each source-addressed checkpoint and run head in the
same native synchronized capture transaction. Revisions use compare-and-publish;
an old idempotent acknowledgement cannot reset the head. Deep verification
reconstructs heads from accepted checkpoint originals. Recovery reads at most 64
ordered events beyond the checkpoint, including input captured immediately before
a crash. Missing producer positions and larger tails stop with explicit errors.
The format is fenced by `continuous-owned-runtime-v1`.

Completed captured groups alone may be evicted. Active obligations occupy an
attributed working-data zone and unpin on completion/cancellation. Checkpoints
hold at most 64 groups, 256 messages, 32 active obligations and 8 MiB of referenced
active text. Terminal runs cannot advance; source permissions are rechecked on
publication and rehydration. The initial text adapter accepts bounded 1 MiB
messages; larger current groups need an explicit range/media adapter.

A planned model call reserves its request identity before preparation. Its exact
request is captured before handoff. After a crash, a captured request with no
result requires provider reconciliation, while an uncaptured planned request
cannot have been sent through this runtime. Persistence retries retain the same
bytes/identity and never repeat the provider call.

Model-output provenance binds the exact request and fully observed action IDs.
Structured proposals are explicitly protocol JSON; model text does not grant
execution authority. The host registry resolves operation names, and a required
tool guard runs after intent capture and immediately before dispatch. Intent and
outcome positions remain reserved across restart. Unknown outcomes reconcile
through the target; lost outcome receipts retry capture alone. A successful
`contextdb.memory.expand` schedules bounded original queries for the next
preparation; its acknowledgement does not claim retrieval has already succeeded.
Terminal runs release resident source pins. Cancellation can discard unexecuted
proposals from residency without inventing outcomes; their originals and earlier
checkpoints remain auditable. Unknown dispatched outcomes must first reconcile.

Interrupted buffered output is preserved as opaque partial bytes with no
executable actions. Recovery cannot claim the request was never accepted after
output was observed. Malformed or unsupported proposals are also retained without
dispatch. An historical capture gap remains explicit until a supported coverage
repair proves closure; a later answer alone cannot erase it. Live streaming and
oversized/non-text protocol groups require explicit adapter profiles. The initial
hot-message profile is 1 MiB per source and 32 messages per interaction group;
captured overflow remains durable and returns a typed error. The
`continuous-model-protocol-v1` feature fences these new provenance contracts.

Request JSON escaping is represented by verified `JsonStringSource` transforms,
not new original quotations. Large novel protocol bytes are staged durably.
Explicit host `ModelRequest` provenance binds disclosure-only scope behavior to
the immutable event; legacy observations retain their original scope impact.
`continuous-request-transforms-v1` and `continuous-capture-impact-v1` prevent older
readers from silently accepting these rules.

## Native context leases

`ContextLeasePort` compares an owner-sealed assembly and registers its source and
scope dependencies under the native publication lock. Scope epochs cover absent
constraints as well as selected records. Polling gives coalesced invalidations;
dispatch always rechecks epochs, source permissions, capability grants and the
current run head. A modified wire/read-set cannot reuse a preparation seal.

`OwnerDispatchFence` registers and checks before model handoff. Tool admission
also binds the exact action, originating model request, resident decision context
and obligations. A bounded journal check distinguishes that model's own proposal
and operational checkpoints from new input, semantics or tool results requiring
replanning. External effects require established current interpretation; the
host-selected built-in memory expansion can read originals while interpretation
is still explicitly incomplete. Operation text cannot choose the effect class.

The initial profile retains at most 64 leases / 16 MiB of dependency metadata,
checks at most 64 intervening commits, and caps validity at 30 seconds or the next
known temporal/consent boundary. Both elapsed and wall time apply. Leases retain no
physical snapshot and expire on release or owner restart. Expiry requires fresh
preparation; slow-reader lifetime tuning remains part of runtime evaluation.
Invalidation refresh shares the bounded drive allowance and stops on exhaustion.

This is checked local admission. The writer is released before model/target I/O;
it does not make a remote handoff atomic with a concurrent native write. Strict
nonblocking handoff and in-flight cancellation require a tested transport profile.
External version comparison/idempotency and operation authorization remain target
contracts. A current lease proves dependency freshness, not natural-language
understanding or permission to execute arbitrary model-proposed code.

## Measured residency and cost

The optional `CacheResidencyController` adjusts only the soft high watermark from
the last two to four measured calls, with separate enter/leave thresholds. It
keeps complete-group eviction, mandatory state and hard request limits intact.
Unknown or invalid usage resets adaptation. This is a cache-reuse heuristic;
configured prices and measured end-to-end outcomes determine economic benefit.
The content scorer never sets lifecycle policy or grants authority.

`ReaderUsage` keeps uncached input, cache creation, cache reads and billed output
disjoint. Reasoning is a subset of output. Missing counters stay unknown, including
after failed dispatch. `ReaderTariff` requires an explicit currency and all billed
categories; it cannot infer a provider price or treat local computation as free.
Additional memory is priced in the actual outgoing protocol. Only exact input
counts may be subtracted; two conservative upper bounds cannot justify a discount.

`drain_measurements` exports a bounded 64-step process-local window, including
failed preparation, retries, reader time, scorer time, source echo/novel bytes and
logical work allowances. Overwritten records and work before process resume are
explicit. Hosts must join exported windows, tool/helper charges and persistence
work for a complete run ledger. Prefix-byte similarity is a diagnostic lower
bound, never a measured cache hit; logical bytes are not physical disk traffic.

More than 128 unprocessed originals yields `PendingWindowExceeded`, rather than
blocking authorized raw recall. Pending IDs describe only the inspected subset.
Current state remains incomplete, and native external-effect admission still
fails. The host may restrict automatic discovery with `automatic_recall_filter`
for a replay cutoff; mandatory state and current authorization remain unchanged.
Explicit expansion routes retain their own validated filters.

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
