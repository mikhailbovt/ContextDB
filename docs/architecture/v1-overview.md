# ContextDB v1 architecture

This document is the public implementation-oriented architecture map. It
explains where each responsibility lives and which boundaries must not be
collapsed; executable schemas, compatibility documents, and tests own the
machine-checked details.

## Product boundary

ContextDB is a headless, single-node memory engine. It persists observations,
versioned semantic state, evidence and derived indexes, then compiles the
smallest policy-authorized context that is sufficient for a caller's purpose.
It is not a chat UI, an agent framework, a model provider, or a vector database
with a memory-shaped wrapper.

Four boundaries define the architecture:

1. `contextdb-core` owns model-independent meaning and validation. It has no
   storage, network, model-provider or domain-pack dependency.
2. The ordered journal and primary logical graph are authoritative. Lexical,
   vector, hierarchy and summary structures are rebuildable projections.
3. Models and deterministic extractors may propose changes. Only deterministic
   host validation and one atomic publication path can mutate durable meaning.
4. Policy is evaluated before candidate identity, payload, graph traversal or
   ranking can influence a result.

## Write path

```text
authenticated input
  -> immutable observation acceptance
  -> proposal/extraction boundary
  -> evidence, policy and temporal validation
  -> semantic mutation set
  -> atomic journal publication + derived-work outbox
  -> graph and index projection
```

Observation acceptance and semantic publication are deliberately separate.
Raw experience can be durably captured even when model processing is delayed,
degraded or unavailable. A model response never owns a commit handle.

Every acknowledged durable write must be either fully visible or absent after
reopen. Idempotent replay returns the original typed receipt; reuse of the same
key with different canonical input is a conflict. Semantic revisions preserve
history rather than overwriting earlier meaning.

## Read path

```text
authenticated request
  -> policy-only authorized universe
  -> bounded exact/lexical/vector/graph/hierarchy routes
  -> deterministic fusion and sufficiency
  -> evidence and conflict materialization
  -> budgeted ContextPack
  -> provider-specific rendering with trusted and untrusted channels separated
```

Authorization precedes content access and candidate generation. Adding a
forbidden record must not change authorized candidates, ordering, trace shape,
continuations or watermarks. Vector similarity is an entry-point heuristic; it
does not establish identity, truth, chronology or permission.

The canonical output is a model-neutral `ContextPack`. Renderers adapt the pack
to a runtime profile without changing its semantic IDs, evidence bindings,
unknown/conflict state, snapshot, filter or policy decisions.

## Component ownership

| Area | Owning package | Durable authority |
| --- | --- | --- |
| logical types and invariants | `contextdb-core` | canonical type/version contract |
| correctness oracle | `contextdb-reference` | test/reference logical state |
| ordered publication | `contextdb-journal` | observation and semantic frames |
| primary temporal graph | `contextdb-graph` | canonical identities and revisions |
| exact/lexical/vector recall | `contextdb-recall`, `contextdb-index` | rebuildable from primary state |
| hierarchy | `contextdb-hierarchy` | versioned rebuildable generations |
| context compilation | `contextdb-context` | pure snapshot-bound result |
| model boundary | `contextdb-model`, `contextdb-cognition` | proposals only |
| conversation | `contextdb-chat` | vertical-specific durable workflow |
| continuity/migration | `contextdb-continuity` | explicit checkpoint and compatibility records |
| knowledge and coding packs | `contextdb-knowledge`, `contextdb-domain-code` | external domain adapters |
| service and transports | `contextdb-service`, `contextdb-server`, `contextdb-proto` | API boundary, not new semantics |
| CLI/MCP/SDKs | `contextdb-cli`, `contextdb-mcp`, `sdk` | external adapters |
| security controls | `contextdb-security` | policy, encryption, deletion and audit contracts |

## Identity and time

Public UUID identities are stable across compaction, index rebuild and runtime
migration. Dense graph IDs are private physical accelerators and may never leak
into a public archive or API contract.

ContextDB distinguishes transaction time (when the database learned or changed
something) from valid time (when it was true in the represented domain). Reads
bind an exact snapshot and policy/filter context. A continuation is valid only
for that complete binding.

## Failure and degradation

- Capture does not depend on successful recall or model processing.
- Missing or stale optional indexes either use an exact/delta path or return an
  explicit freshness error; they never silently pretend to be current.
- Unsupported runtime, maintenance or migration executors return typed
  `Unsupported` outcomes.
- Malformed archives, cursors, model output, policy state and evidence fail
  closed before mutation or content disclosure.
- A source-level implementation, a passing package test and a release-qualified
  platform proof are different evidence classes.

## Current implementation profile

The accepted [continuous-context extension](continuous-context.md) adds native
raw capture and indexed retrieval, current-state leases and an owned rolling
agent adapter. Its [delivery ledger](../roadmap/continuous-context.md) records
implementation and evidence separately from the existing alpha release.

The repository contains executable reference slices through M17, including the
conversation, knowledge and coding verticals, three HTTP SDKs, MCP, conformance,
security and benchmark harnesses. The standalone persistent composition is
being bound to the selected Fjall substrate while retaining an explicit
reference-only development mode.

This is not itself a v1 release declaration. M18/M19 additionally require
frozen public artifacts, signatures, supported-platform installation receipts,
external benchmark and security closure, and every dependency gate to pass.
The machine-readable roadmap and release verifier are authoritative for that
distinction.
