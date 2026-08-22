# contextdb-context

`contextdb-context` is the pure M8 ContextPack compiler for ContextDB. It turns
already-recalled, policy-labelled memory into one deterministic, model-neutral
pack and renders that pack for a target model/runtime without changing its
semantic identities.

The crate contains no storage, network, model-provider, or Codex integration.
Those systems implement `ContextProvider` and `TokenCounter` at their trust
boundary.

## Security and semantic contract

The compiler is deliberately two phase:

1. read non-content `CandidatePolicyLabel` values;
2. authorize scope, ownership/audience/purpose/consent, influence, mention, and
   external-model use;
3. materialize only authorized candidate payloads;
4. repeat independent authorization before materializing evidence;
5. compile, rank, budget, trace, serialize, and render only the resulting
   authorized set.

Consequently, an unauthorized payload cannot affect selected IDs, scores,
omissions, budget counters, provenance, output bytes, or renderer output.
Secret-like payloads fail closed before rendering. Memory is always emitted as
untrusted data with `instruction_capability = none`; compiler-created use
directives live in the separate trusted-control channel.

Every non-empty pack is bound to one provider snapshot, one filter digest, one
purpose, explicit scopes, and an explicit temporal view. Factual blocks carry a
`Perspective`, stable claim IDs, epistemic state, and evidence unless their
basis is explicitly an actor assertion or hypothesis. Conflict alternatives
and unknowns remain first-class records; the sufficiency report never converts
either into a guessed fact.

## Public entry points

- `ContextCompiler::compile` compiles any `ContextProvider`.
- `ContextCompiler::compile_recall` restricts compilation to the exact
  snapshot-bound subgraph selected by `contextdb-recall`.
- `ContextRenderer::render` renders an existing canonical pack under another
  compatible `ModelProfile` without mutating its semantics.
- `CanonicalSerializer` validates and round-trips canonical JSON and v1
  Protobuf, and computes a BLAKE3 digest over canonical Protobuf bytes.
- `InMemoryContextProvider` is a deterministic reference/test provider.
- `TokenCounter` is the exact tokenizer boundary. `ReferenceTokenizer` is a
  deterministic reference profile, not a claim to emulate a vendor BPE.

See [docs/API.md](docs/API.md) for the call protocol and validation guarantees.

## Determinism and budgets

Selection order is stable under provider reordering. Required and mandatory
content is admitted first, conflict closure is atomic, missing required facets
become explicit unknown blocks, and optional blocks use deterministic marginal
utility density with stable tie-breaking. The compiler never truncates inside a
semantic block.

Hard limits cover total rendered tokens, blocks, evidence blocks, raw evidence,
history, conflicts, serialized bytes, and selection evaluations. A model
profile also reserves output tokens before memory input capacity is calculated.
The compilation report records the final counters and every safe omission.

Progressive continuation tokens are opaque, keyed, and bound to snapshot,
policy filter, purpose, scopes, temporal view, required facets, budgets, model
profile, evidence mode, and compiler version. Tokens contain no memory payload.

## ContextPack contract coverage

| Requirement | Contract surface | Status and proof |
|---|---|---|
| Canonical model-neutral product and sections | Canonical structure | Implemented: 17 separate canonical sections, one situation for non-empty packs, stable IDs, graph/scope/freshness/provenance manifests. |
| Model profile | Runtime compatibility | Implemented: family, tokenizer identity, context/output limits, format and runtime capabilities, position and instruction-hierarchy profiles, schema complexity, external-processing boundary. |
| Exact hard budgets | Budget enforcement | Implemented and validated against actual `TokenCounter` output; no mid-block truncation. |
| Utility-aware selection | Selection | Implemented deterministic marginal utility/density, required-facet admission, stable ties, and an evaluation budget. |
| Multi-level structural compression | Compression | Implemented L0 orientation through L4 raw, protected facets, omission declarations, and exact fragments that survive compression. |
| Evidence placement | Evidence authorization | Implemented minimal independently-authorized evidence; text renderers place it immediately after the supported block. Canonical JSON keeps stable handles and a canonical evidence pool. |
| Instruction/data boundary | Trust separation | Implemented separate trusted/untrusted channels, zero instruction capability, taint/source classification, and disclosure filtering before materialization. |
| Unknown/conflict/confidence semantics | Semantic state | Implemented as orthogonal, validated fields; unresolved conflicts and required unknowns block rule-based sufficiency. |
| Purpose-oriented packs | Pack profiles | Implemented for conversation, continuity, autobiographical, knowledge, historical, reflective, action, handoff, and bootstrap. Acceptance tests explicitly cover conversation, knowledge, historical, reflective, and action. |
| Progressive packs and stable references | Continuation | Implemented authenticated continuation with deterministic offset and chain state, bound to snapshot/filter/profile/budget; stable block/claim/evidence/memory references are preserved. |
| Canonical serialization and report | Wire contract | Implemented canonical JSON plus versioned Protobuf, strict canonical ordering/round-trip validation, digest, omissions, sufficiency, provenance, and exact budget counters. |
| ContextPack invariants and cross-model rendering | Rendering | Implemented five deterministic renderers. A golden test renders one canonical pack as small-local, hosted, chat, coding, and canonical JSON without semantic drift. |
| No-memory result | Empty-result contract | Implemented explicit reason, missing facets, and searched-authorized-count; status/payload consistency is validated. |
| Package verification | Test suite | Covered by unit/property/golden tests and package-scoped fmt/clippy/test/doc checks. |

## Deliberate boundaries and remaining gaps

- Vendor tokenizer adapters and empirically calibrated model-profile registries
  belong to the model runtime. This crate rejects a tokenizer/profile ID
  mismatch and never substitutes a heuristic silently.
- Prompt-cache storage and lifecycle are outside this pure compiler; the model
  profile exposes cache capability and canonical digests provide cache keys.
- JSONL and YAML are not first-class renderers in v1. Canonical JSON, compact
  text, hosted structured, chat, and coding renderers cover the M8 demo/exit.
- `mention_only_when_explicit`, silent use, non-disclosure, constraint-only, and
  style-only are enforced. A stateful interactive `ask_before_using` approval
  exchange requires a caller-side consent workflow and is not fabricated here.
- The Protobuf envelope is fully versioned and deterministic; independently
  versioned domain records are canonical JSON strings inside it. A future wire
  revision may promote those records to typed nested messages without reusing
  field numbers.
- Runtime latency and real vendor token fidelity require integration benchmarks;
  package tests prove deterministic source behavior, not external deployment.

## Verification

From the workspace root:

```powershell
cargo fmt -p contextdb-context -- --check
cargo clippy -p contextdb-context --all-targets -- -D warnings
cargo test -p contextdb-context
$env:RUSTDOCFLAGS='-D warnings'
cargo doc -p contextdb-context --no-deps
```

Golden fixtures live in `tests/fixtures/`. They cover the implicit Japan-bar
question and cross-model renderer outputs/digests.
