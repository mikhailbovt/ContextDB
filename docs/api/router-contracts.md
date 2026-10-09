# Router contracts

`contextdb_context::router` exposes an opt-in record of the continuous compiler's
authorized inventory, scorer evaluations and final selection. The archive still
retains permitted originals independently of their routing score. These records
are observations and proposals; a digest or deserialized request grants no access.

## Compiler entry points

- `compile_assembly_with_router` runs the existing assembly pipeline and records
  actual scorer calls. It returns the assembly, request, plan, manifest and actual
  prepared candidate/evidence material, including unselected alternatives.
- `compile_router_plan` rebuilds the current authorized inventory and validates a
  proposed score/selection path through the same closure, support selection,
  complete protocol encoding and publication-owner read-set check. It does not
  call the scorer; its manifest labels the scores `untrusted_proposal`.
- `compile_router_plan_or_r0` lets a host explicitly choose one fresh R0 attempt
  after a malformed or stale proposal. Authorization, provider failures and
  exhausted shared budgets propagate as errors.

All entry points receive the host's provider, tokenizer, outgoing encoder and
`QueryBudget`. The existing `compile_assembly` path remains available.

## Records

| Type | Contents |
| --- | --- |
| `AuthorizedRouterRequest` | Query-time context, working state, prospective hot window, current turn, authorized units and mandatory closure. |
| `RoutingDescriptor` | Authorized compact features, explicit missing-feature mask and separate confidence and prior utility. |
| `MemoryUnit` | Existing block identity, scope, temporal and epistemic roles, source references, dependencies and representations. |
| `SupportAlternative` | One verified sufficient support bundle, original spans and material/representation commitments. |
| `RouterScore` | Actual selected-base and trial commitments, exact marginal protocol cost, utility and fit result. |
| `RouterSelectionPlan` | Proposed seeds, complete selected closure, support choices, score path and reported final wire/counts. |
| `RouterManifest` | Accepted assembly and record commitments, score provenance, measured compilation work and timing. |

Bindings cover the opaque owner snapshot, current authorization and scope state;
the complete compile request; working/hot/current/control material; reader,
tokenizer, encoder and scorer revisions; feature schemas; budgets; and candidate
and mandatory inventories. Applying a plan rebuilds these commitments from the
provider. Current source permission remains required even when an earlier plan
was valid.

Candidate data retains its interpretation role. Proposed or historical material
cannot become current state through a score, and original text cannot become host
control. Unknown coverage and STOP do not establish that an event never occurred.

## Selection and limits

STOP has no discretionary seeds and preserves the entire mandatory closure,
including required unknown/conflict state. Optional units must pay for their hard
dependencies and a sufficient support alternative. Shared source ranges and
support are accounted for by the existing union renderer; actual complete
protocol encoding determines token/byte fit.

The router profile allows at most 512 units, 4096 evaluations, 32 scopes and a
2 MiB combined request/plan/manifest/material envelope. Identity lists are ordered and
unique, support choices are explicit, and hard dependency cycles or unavailable
members are rejected. This stricter opt-in graph validation can reject malformed
optional graphs that the legacy entry point leaves unselected.

Scorer work is charged to the shared allowance. Its aggregate cooperative
latency limit defaults to one second and may be configured up to ten seconds;
the complete router preparation has a shared 30-second ceiling across fallback
attempts. A scorer must cooperate with the budget: this synchronous port cannot
preempt an arbitrary blocking implementation. Invalid finite scores or a scorer
subdeadline may trigger one fresh R0 attempt using the remaining allowance.
Global exhaustion or an impossible mandatory assembly cannot start another loop.

R0 utility remains an exact `u64`; it is not confidence or a probability.
`FiniteScoreAdapter` provides an explicit finite floating-point utility scale
for other backends and preserves their revision. R0 behavior propensity remains
absent, so these deterministic records do not support propensity-based estimates.

Manifest `compilation_*` fields measure compilation before the final envelope
integrity check. That check also consumes the same budget. Caller-replayed scores
have zero observed scorer timing; observed R0 fallback is marked separately.
Nullable training/model fields remain empty in this profile.

## Current boundary

The compiler records use versioned canonical JSON commitments. Their
`from_json` methods bound and charge input bytes before strict deserialization and
structural validation. A host must invoke compiler validation before use.
Structural validation alone is not authorization or a durable custody receipt.

The [owned host](../../tools/owned-conversation/README.md) can require protected
native traces. Canonical pages live inside the encrypted model-request occurrence,
outside the reader wire. Native seals, the pending owned call and atomic capture
bind them; current source, generic-record and state controls restrict both the
trace and its outputs/checkpoints. Recovery retains headers and controls after
authorized body pruning. Legacy omitted traces remain unavailable.

The service's optional generic query uses the existing resolver and recall engine.
Its initial complete inspection profile permits at most 100 authorized records;
larger frontiers refuse before the next candidate record body is read. Inherited
source controls can require earlier authorized reads. This is a bounded native
integration, not a scalable indexed route or automatic generic cue in the host.
The embedded `AcceptedRouterTracePort` reads the exact accepted material under
current capabilities, purpose and whole-custody controls in one latest snapshot.
It uses the caller's shared allowance and performs no model call or write. Its
result grants neither export nor training permission; ordinary transports do not
acquire the port implicitly.

Compiler validation separately reports support material, unit semantics and the
complete candidate commitment. The explicit `compile_assembly_with_router_policy`
entry retains versioned prepared actions/reasons for the last column; the default
entry and native v1 traces omit it. Native v1 refuses this extension. Historical
selection replay still lacks prepared selector state. Current source-wire replay
is also a separate operation. The [synthetic corpus](../../learning/context-router/README.md)
keeps query-time features, R0 behavior, labels and lineage distinct. Scoring
remains R0; real export, replay completion and Kev training remain later work.
