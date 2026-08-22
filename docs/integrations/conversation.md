# Conversation integration contract

This guide applies to applications integrating `contextdb-chat`, the HTTP SDKs
or an equivalent embedded adapter.

## Turn lifecycle

1. Resolve workspace, subject, actor, agent, session, scopes and purpose.
2. Persist the user message as immutable observation evidence before recall.
3. Call `compile_context` (HTTP `/v1/context-pack`, gRPC `CompileContext`, CLI
   `compile-context`, or MCP `contextdb_context`) to run bounded policy-first
   recall against one pinned snapshot/filter binding.
4. Validate the returned canonical `ContextPack` and its exact model profile;
   resume only with the opaque unified pipeline continuation.
5. Render trusted control separately from untrusted memory/user data.
6. Invoke the runtime. Capture the assistant response as separate evidence.
7. Queue post-turn extraction. Treat model output as proposals only.
8. Publish only a validated adjudication result through the journal.

Capture-before-recall ensures that a recall timeout or provider outage cannot
lose the current user turn. User and assistant text remain separate evidence
units linked by an interaction ID.

## Automatic significant memory for Codex

The local Codex integration performs selective proposal in the host agent, where
the current task and user intent are available. The database does not pretend
that a deterministic storage process can infer psychological importance from
arbitrary text. The installed skill classifies only durable decisions,
constraints, preferences, goals, open loops, corrections and verified
milestones; transient chat, raw logs, source dumps and secrets are excluded.
It evaluates significance automatically at natural task checkpoints: after an
accepted durable decision or correction, after a verified milestone, when a
persistent constraint, preference or actionable open loop is established, and
once before final handoff. A separate user request is not required.

For each qualifying item the model-facing adapter calls
`contextdb_ensure_candidate` with a stable logical identity key, bounded
proposed kind and zero to sixteen existing candidate parents. The trusted
adapter, not model output, normalizes that key with the versioned NFKC,
lowercase and whitespace contract and derives the candidate ID and retry key
from the fixed policy partition. A fresh process therefore reuses the same
logical identity without overwriting its stored value; it must materialize the
existing candidate before choosing a distinct successor. Successor creation
uses a new logical identity key plus `supersedes_candidate_ids` through the same
ensure route; raw `propose_memory` is a trusted service method and is not a
model-facing MCP tool. The native executor atomically commits a quarantined
Candidate plus typed
`contextdb.candidate_hierarchy.parent` candidate-link records, or commits
nothing. Parents must be active candidate-memory records in the exact same
policy partition. Self-parenting, unknown or unauthorized parents,
deterministic link collisions and cycles fail closed. Multiple parents remain
a DAG rather than being collapsed into an arbitrary tree.

Ordinary `recall`, `get_memory` and ContextPack compilation exclude both the
candidate nodes and their links. The separate `contextdb_recall_candidates`,
`contextdb_get_candidate` and `contextdb_traverse_candidates` tools return them
as explicitly untrusted continuity proposals. A successor may atomically close
active predecessor candidates and their links, but supersession never promotes
the result. Raw observations remain a separate path and are never silently
promoted. Direct semantic publish/correct methods remain host APIs and are not
exposed by the model-facing MCP adapter.

This is automatic while the ContextDB Codex skill is active in a task. It is
not an independent background daemon that can observe conversations after the
host exits. General post-turn extraction, proposal adjudication, consolidation
and reflection remain separate host/runtime responsibilities and must not be
claimed merely because quarantined Codex proposal capture is available.

The sibling Codex plugin reinforces the skill with two local lifecycle hooks.
`SessionStart` injects the candidate-memory contract for new, resumed and
compacted processes. A loop-safe `Stop` hook gives the active model one final
checkpoint to propose any significant state it has not yet captured; the second
stop is allowed through unconditionally. Hooks provide scheduling and the model
provides task-aware classification. Neither hook reads a hidden stable
transcript format, performs background model inference, or writes canonical
memory directly. Codex requires a one-time trust review for this non-managed
local hook definition.

## Failure semantics

- Recall error, timeout or invalid pack: continue with no memory and retain the
  captured turn.
- Provider/model error: record a payload-free failure; do not commit proposed
  semantics.
- Late result: discard it after the bound deadline.
- Idempotent retry: reuse the exact observation ID and key; a changed canonical
  request must fail with `IdempotencyConflict`.
- Restart: recover prepared captures and durable post-turn jobs before accepting
  a conflicting ordinal.
- Stale continuation: restart recall from an explicit snapshot rather than
  weakening its binding.

## Trust channels

Memory content, evidence quotes, tool output and the current user message are
untrusted data. They must not be concatenated into a trusted instruction
channel. `contextdb-context` renderers provide separated-channel and structured
single-prompt forms; adapters must preserve that distinction.
For `compile_context`, these are returned explicitly as
`rendered.trusted_control` and `rendered.untrusted_data`.

The database does not possess provider credentials. Runtime adapters receive a
deadline, minimized context and an immutable model profile. They may not mutate
memory directly.

## Embedded `contextdb-chat` service adapter

Build `contextdb-chat` with the `service-adapter` feature to connect
`ConversationMiddleware` directly to a `CognitiveMemoryService` without introducing
a reverse dependency from the service layer back into chat. Configure
`CognitiveServiceConversationRecall` with one exact `ModelProfile`, a
`ConversationServicePolicy`, and a host implementation of
`ConversationServiceAuthority`.

The authority callback receives no query or memory content. It receives only the
durable pack/request identity, workspace, subject, actor, agent, session, exact
scopes, purpose, and required capability set. It must authenticate that binding and
return `AuthenticatedRequestContext`; the adapter rejects any identity, purpose, or
scope drift before calling `compile_context`.

The adapter treats the service response as untrusted at the composition boundary:
it verifies the canonical pack bytes/digest and trace bindings, rerenders the pack
for the configured profile, and requires byte-for-byte equality with the returned
trusted-control and untrusted-data channels. An explicit no-memory pack remains the
middleware's `NoMemory` outcome. A sanitized service failure remains `Degraded`, and
neither case can undo the already durable user capture.

This is a recall adapter, not yet a unified storage composition. The current
`ChatStore` journal and an injected memory service can have different commit
sequences; callers must not pass a chat commit as `at_commit` for another
authority. A production host must obtain the snapshot from the memory service or
bind both authorities with an explicit verified snapshot token.

## Privacy and social calibration

Automatic recall is limited to the active subject, scope and purpose. A caller
must not probe forbidden candidate identity, content or route scores. Memory use
directives control whether an item may be mentioned naturally, only on explicit
request, or only after consent.

Sensitive silence is a behavior to prove, not a missing-output heuristic. The
BENCH-A harness contains explicit policy probes showing that restricted records
were excluded before planning.

## Checkpoint and migration

Situation frames and checkpoints are working state, not semantic truth.
Checkpoint export binds the runtime/model profile, snapshot, policy, required
memory, open loops and tool capabilities. Migration compares compatibility,
performs any required re-embedding as a separate immutable job, compiles a new
bootstrap pack and records pre/postflight results.

Exact wording or a claim of continuous consciousness is never a migration
guarantee. Stable IDs, policy, evidence, required memories and open loops are.

## Minimal adapter obligations

An adapter must implement bounded cancellation, strict JSON/wire decoding,
response-size limits, payload-safe logging and transport authentication. For
protected HTTP routes it supplies a fresh gateway attestation over the complete
`AuthenticatedRequestContext`; a bare `RequestContext` is not authentication.

See `crates/contextdb-chat/README.md`, `sdk/CONTRACT.md` and
`docs/api/compatibility.md` for executable contracts. The complete ContextPack
surface and binding semantics are documented in `docs/api/context-pack.md`.
