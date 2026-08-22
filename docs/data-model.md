# Public data model and compatibility

This guide summarizes the stable semantic vocabulary implemented by
`contextdb-core`. Storage keys, dense graph IDs and index layouts are private
implementation details.

## Identity families

- `WorkspaceId` is the administrative isolation boundary.
- `MemorySpaceId` groups policy and lifecycle within a workspace.
- `MemorySubjectId` identifies the person, organization, agent or other entity
  whose memory is represented.
- `NodeId`, `ClaimId`, `EdgeId`, `EvidenceId`, `ConflictSetId` and typed-memory
  IDs are globally typed public identities. Cross-type UUID reuse is invalid.
- `ObservationId` identifies immutable captured experience. It is not a claim
  that the observation's content is true.

IDs survive revision, compaction, rebuild, export/import and runtime migration.
A derived index may assign private dense integers, but APIs and canonical
archives use public IDs.

## Semantic envelope

Every durable semantic value carries the context needed to interpret it:

- workspace, memory space and subject;
- perspective and epistemic basis;
- owners, audience, scopes, purpose and sensitivity;
- provenance and evidence lineage;
- valid-time and transaction-time information;
- lifecycle/revision relationships.

Derived values may preserve or narrow policy. They may not broaden access,
erase provenance or create a lineage cycle.

## Nodes, claims, edges and evidence

`Node` represents a durable entity or typed memory object. `Claim` expresses a
versioned proposition about a subject. `Edge` is a typed, temporal relationship
between public identities. `Evidence` binds a claim or decision to exact
observation/artifact material and provenance.

Evidence is immutable. A correction publishes new semantic state and explicit
lineage; it does not rewrite old evidence. Content is referenced through an
erasable indirection so a hard-delete tombstone can remain without retaining
the erased payload.

## Revisions and bitemporality

Revisions are append-only. A current head may supersede an earlier revision,
while historical reads remain available when policy and retention permit.
Current suppression, revocation and deletion are live-use overlays: transaction
time selects historical semantic state, but never bypasses the current policy
that determines whether any payload may be materialized or influence a route.

- Transaction time answers: "What did ContextDB know at commit N?"
- Valid time answers: "What was represented as true at domain time T?"

A valid-time transition closes the earlier interval and creates a successor.
Overlapping incompatible claims create a revisioned conflict set. Absence of
support is represented as unknown, not silently converted to false.

## Typed memory

Core typed memory includes preferences, boundaries, relationships, goals,
commitments, corrections, summaries, reflections and episode views. These are
not free-form labels: each kind has its own authority, evidence and lifecycle
rules. Reflections remain hypotheses until stronger evidence and an authorized
workflow promote a different semantic object.

Domain-specific concepts such as repository symbols or document sections live
in external domain packs and use `NodeType::Domain`. They do not extend the
universal core enum for each application.

## Mutation contracts

`SemanticMutationSet` is the only core publication unit for semantic writes.
It binds its base snapshot, exact accepted observations, revisions, conflicts,
lineage, policy propagation and derived-work declarations. Validation is
atomic: one invalid member rejects the whole set.

Model-provider output is a proposal input to validation, never a mutation set
with storage authority. Maintenance publications use separate typed contracts
so rebuilding an index cannot masquerade as a semantic change.

## Compatibility

Compatibility is versioned independently across wire, semantic, storage,
ContextPack and MCP contracts. The current values are declared in
`version.toml` and the version-manifest schema.

Compatible changes may add optional fields, new endpoints or explicitly
negotiated capabilities. They may not reuse a field number, change an existing
field's meaning, weaken a validation rule, or make an old unknown value execute
with authority. Destructive semantic/storage changes require a new format
version and a tested migration path.

See [API compatibility](api/compatibility.md) and
[format compatibility](formats.md) for transport and archive rules.
