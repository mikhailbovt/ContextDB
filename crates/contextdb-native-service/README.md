# ContextDB native service

`contextdb-native-service` is the incremental Fjall-backed implementation of
the canonical `CognitiveMemoryService` surface. It removes the legacy
standalone host's whole-archive write amplification from the working-memory
path.

Each mutation updates bounded records in one synchronized Fjall transaction:

- non-content policy labels and current heads;
- immutable revision content and bitemporal history;
- workspace-local to global commit mappings;
- content-free event-chain and idempotency receipts.
- digest-bound accepted record/edge mutation payloads and affected scope epochs.

Recall scans policy labels first and applies the requested record-family filter
before it builds or caps the authorized universe. Only then is content
materialized. Thus quarantined candidates cannot consume or alter ordinary
recall/traversal counts, and canonical records cannot consume candidate-only
budgets. Continuations and explain traces are authenticated and bound to the
caller, request, and logical snapshot. Raw observations remain durable evidence
and are not silently promoted into semantic recall.

`CompileContext` uses the same policy-first revision store through an exact,
snapshot-pinned `RecallProvider`. The shared deterministic RecallEngine and
ContextCompiler produce the canonical model-neutral ContextPack without a
second memory authority or whole-archive rewrite. Candidate records and
candidate links are filtered before provider selection, counts, documents, and
relations, so they cannot enter an ordinary ContextPack. The exact-scan path is
the correctness fallback; accelerated ANN projection is a separate bounded
index. Its additive composition boundary is documented in
[`native-ann-composition-boundary.md`](../../docs/architecture/native-ann-composition-boundary.md).

For the local MCP/Codex profile, structured model memory is candidate-only. The
native service is the durable executor behind candidate proposal, content-free
candidate recall, separately authorized candidate materialization, and
candidate-only traversal. The same profile also supplies raw observation,
read-only canonical recall and ContextPack compilation, explanation,
verification, status, physical compaction, and authenticated operator backup;
none of those read or operator paths gives model output canonical mutation
authority.

Structured model memory is proposal-only. `ProposeMemory` atomically persists a
typed `Candidate` node plus zero to sixteen candidate-link `Candidate` records.
Links use `contextdb.candidate_hierarchy.parent`, deterministic IDs in a distinct
candidate domain, one exact host-derived policy (including exact sensitivity),
and a pre-write DAG check. Unknown, unauthorized, cross-policy, self, cyclic,
or reused parent/link identities fail before any record is written. Both node
and derived links retain quarantine state and fixed-session provenance. The
write advances the journal but not canonical semantic, lexical, or graph
watermarks.

Candidate recall is lexical, typed, policy-first, and content-free: each hit is
only a candidate ID, semantic kind, and score. Candidate traversal materializes
one coherent snapshot, constructs candidate-only outgoing/incoming adjacency in
one pass, and returns node IDs from deterministic bounded BFS (with
ordered-map/set logarithmic factors, rather than repeated edge rescans). An
explicit `GetCandidate` is the only payload materialization step. It returns a
full `MemoryRecord` only for a candidate node with the `memory_proposal` role:
the candidate document plus revision and transaction-time metadata. Its value,
search projection, and proposal attributes remain untrusted; candidate-link
records are not returned as candidate memories.

Typed supersession closes active predecessors and their incident candidate
links atomically. It does not promote the successor. Candidate retraction closes
its incident candidate links and does not advance canonical semantic
watermarks. Promotion/adjudication into canonical truth is not implemented by
this crate, and no candidate receipt, lookup, or traversal result implies that
promotion occurred. Deep verification checks candidate endpoints, exact policy
equality, record roles, quarantine/provenance attributes, deterministic edge
IDs, and acyclicity before returning its database digest.

The `contextdb.native-fjall.logical-backup.v2` format includes continuous capture
and accepted semantic payloads; legacy v1 backups remain readable. Both include
their admitted native keyspaces under strict entry/byte caps, database identity, deep
verification receipt, and nested/outer BLAKE3 integrity. Restore validates the
complete archive before mutation and is restricted to a pristine native target;
replacement is one synchronized transaction and is deep-verified before its
receipt. This is a database-global operator primitive, not subject export or a
live replacement API.

`CapturePort` retains originals independently of extraction; persistent raw
recall is available through `RawRecallPort`. The host-only `AssertionPort`
publishes exact-source claims and explicit transitions under a typed authority
policy. It distinguishes knowledge time, valid time and unresolved interpretation;
assistant proposals do not become decisions. All new native record writes,
including existing candidate/correction/edge paths, journal their accepted bytes.
The [continuous-context contract](../../docs/architecture/continuous-context.md)
documents format activation, current-source ACLs and supported bounds. These
embedded ports do not give model-facing candidate tools publication authority.

Subject-safe export/import, accelerated vector search, lifecycle state, live
restore, hard deletion, and candidate promotion remain separate executors. An
unsupported method returns the canonical typed error. Exact-scan traversal is
not the separate persistent graph-v2 acceleration path.

Tests cover restart, concurrent retry, snapshot history, tenant-local
sequencing, authorization before corrupt-content materialization, continuation
rebinding, ContextPack compilation across restart, multi-parent candidate DAG
durability and traversal, pre-write rejection, deterministic idempotent replay,
canonical isolation, exact Restricted sensitivity, typed supersession,
candidate retraction, injected multi-node cycle detection, canonical
backup/reopen, tamper/database-identity rejection, pristine-only restore, and
fixed-record growth without a `contextdb.logical.v1` archive blob per write.
