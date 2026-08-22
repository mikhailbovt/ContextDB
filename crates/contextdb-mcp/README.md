# contextdb-mcp

MCP adapter over `CognitiveMemoryService` with two compatible entry paths.
Standard clients such as Codex use metadata-free `initialize`, an id-less
`notifications/initialized`, and ordinary MCP list/call requests after protocol
negotiation. Hosts that deliberately skip initialization retain the stateless
`2026-07-28` profile: every request then requires protocol/client-capability
metadata. Both paths keep the same fixed host authority, while discovery and
tool results carry R19 completion, cache, and server identity metadata.

The model-callable v1 inventory is deliberately narrow:

- `contextdb_session` returns a content-free fixed request-context template,
  granted capability names, and (when the fixed purpose maps safely) a bounded
  host-owned ContextPack plan template;
- `contextdb_observe`, `contextdb_recall`, `contextdb_context`,
  `contextdb_get_memory`, `contextdb_explain`, and `contextdb_verify` expose
  evidence capture and read-only canonical-memory operations;
- `contextdb_ensure_candidate`, `contextdb_recall_candidates`,
  `contextdb_get_candidate`, and `contextdb_traverse_candidates` are the only
  model-facing structured-memory operations;
- `contextdb_preflight`, `contextdb_postflight`, `contextdb_checkpoint`,
  `contextdb_resume`, and `contextdb_handoff` expose bounded runtime continuity
  when the selected service profile implements it.

The MCP surface has no model-facing route for publishing or correcting
canonical semantic memory. Canonical mutation authority is not granted to
model output, and the model cannot supply candidate IDs or retry keys. Global
archive export, import, backup, and restore are also absent from MCP.

Automatic capture should use `contextdb_ensure_candidate`. The adapter applies
the versioned `contextdb.candidate_identity.nfkc_lower_whitespace.v1` contract:
NFKC compatibility normalization, Unicode lowercase, Unicode-whitespace
collapse, and strict byte/control limits. It hashes the normalized logical key
together with trusted workspace, subject, audience, scope, purpose, clearance,
actor, agent, and semantic kind. Raw identity text is not embedded in the ID.
The model supplies neither `candidate_id` nor `idempotency_key`. A matching
active candidate is returned without overwrite (`input_applied: false`), even
from a fresh MCP session; callers must materialize it before deciding whether a
distinct explicit successor is required.

The host accepts only these delimiter-stable Candidate identity v1 shapes:

- `project|repo=<canonical-lowercase-forward-slash-absolute-repo-root>` with
  zero parents;
- `topic|project=<project-candidate-id>|key=<lowercase-ascii-kebab>` with
  exactly that active project candidate as its parent;
- `memory|kind=<semantic-kind>|parents=<ordinal-sorted-comma-separated-parent-ids>|subject=<lowercase-ascii-kebab>|revision=<eight-decimal-digits>`
  for every other kind, starting at revision `00000001`.

The last form must name exactly the unique, ordinal-sorted
`parent_candidate_ids` array and must have at least one direct active `project`
or `topic` navigation parent. Additional active candidates of any structured
kind may be parents, so the structure remains a DAG rather than collapsing to a
tree. The adapter materializes only the supplied authorized parent IDs to
validate lifecycle and role; missing, inaccessible, inactive, and wrong-role
parents all return the same content-free `invalid_argument` response. The
native atomic mutation still independently enforces parent limits, policy
equality, cycle rejection, and cross-policy isolation.

The trusted service operation behind `contextdb_ensure_candidate` atomically
stores one typed, untrusted, quarantined
`Candidate` and zero to sixteen true candidate-only hierarchy-link `Candidate`
records. Links use the fixed `contextdb.candidate_hierarchy.parent` predicate
and deterministic IDs; parent IDs are not decorative JSON. The bounded taxonomy
is `project`, `topic`, `decision`, `constraint`, `goal`, `open_loop`,
`milestone`, `preference`, `fact`, and `evidence_summary`. Node and derived-link
records retain fixed-session actor, agent, session, request, schema, and input
digest provenance. Exact host-derived sensitivity is preserved. A successful
receipt explicitly says `proposal_state: quarantined` and `canonical: false`.
The raw `contextdb_propose_memory` service method is intentionally not an MCP
tool, so model output cannot choose candidate IDs or retry keys. Explicit
successors use a new logical identity key plus `supersedes_candidate_ids`
through the same ensure route. `supersedes_candidate_ids` is optional: omit it
or send an empty array for a new logical memory, and supply it only for an
explicit successor revision.

Candidate supersession is explicit and bounded: a new proposal may name active
candidate predecessors, which become `superseded` in the same transaction and
have incident candidate links closed. Supersession is lifecycle management, not
promotion. Promotion into canonical truth would require a separate deterministic
adjudication executor; that executor is not implemented or implied by this
adapter. Ordinary `contextdb_recall`, `contextdb_context`, and
`contextdb_get_memory` exclude every `Candidate` and candidate link before
canonical result counts and budgets.

Candidate discovery is deliberately content-free. `contextdb_recall_candidates`
returns bounded hits containing only `candidate_id`, `semantic_kind`, and
`score`; `contextdb_traverse_candidates` returns authorized candidate node IDs
in deterministic BFS order. `contextdb_get_candidate` is the only candidate
payload materializer. It returns one serialized `MemoryRecord` whose
`document.kind` is `candidate` and whose candidate role is `memory_proposal`,
together with revision and transaction-time metadata. The document's `value`,
`search_text`, and model-derived attributes remain untrusted data. Candidate-link
records are traversal infrastructure and are not materialized through this tool.

For a fixed host session, call `contextdb_session` once and copy its
`context_template`, changing only `request_id` for subsequent
channel-authenticated calls. For `contextdb_context`, copy the returned plan and
replace `pack_id`, `query`, and `now_micros`. The Codex-oriented template uses
Coding/Markdown with separated instruction channels and truthfully declares
external model processing, so the host must grant `model_processing`. Purposes
without an exact safe mapping return a null plan template. The legacy local
Codex authority purpose `assist` is preserved for policy compatibility and maps
only the host-owned ContextPack plan to the narrower `conversation` purpose.

Tool arguments carry only a semantic `RequestContext`. Authentication evidence,
actor/agent attribution, and capability grants are never accepted from the
model. Every call is authorized by a host-owned `McpSessionAuthorizer` before
the remaining payload is decoded; the adapter injects the trusted authenticated
context. `McpServer::new` is deny-by-default, while authenticated hosts opt in
with `McpServer::with_session_authorizer` or fixed-session authority.

`contextdb_context` compiles one snapshot/filter-bound minimal ContextPack with
separate `trusted_control` and `untrusted_data` rendering channels. Pipeline
continuations are opaque, authenticated, and bound to the same authority, plan,
snapshot, and filter. Raw `contextdb_observe` remains immutable evidence and is
not silently promoted into semantic recall. Preflight never grants host/tool
authority, and unavailable runtime executors return typed `unsupported` results.

Recall traces are the only MCP resources. They are bounded to the current
process, reauthorized on read, private/non-cacheable, and contain neither raw
evidence nor storage internals.
