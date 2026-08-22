# ContextPack API contract

## Compile flow

1. Construct a `CompileRequest` with a fixed `ProviderSnapshot`,
   `RecallPrincipal`, filter digest, purpose, explicit scopes,
   `TemporalConstraint`, required facets, hard budgets, and `ModelProfile`.
2. Supply a `ContextProvider`. Its label methods expose policy metadata only;
   payload methods must return the exact requested identity from the same
   immutable snapshot.
3. Supply a `TokenCounter` whose `id()` exactly equals the profile's
   `tokenizer_id`.
4. Call `ContextCompiler::compile`, or `compile_recall` with a
   `RecallContextBinding` when the inputs came from `contextdb-recall`.
5. Persist or transmit `CompiledContext::canonical_protobuf` under the public
   `contextdb.context_pack.protobuf.v1` encoding identifier and its
   `blake3-256` `canonical_digest`; pass `rendered.trusted_control` and
   `rendered.untrusted_data` to distinct runtime channels whenever the target
   supports them.

The compiler returns an error instead of weakening policy, changing snapshot,
guessing a missing facet, emitting unsupported factual content, truncating a
block, using a mismatched tokenizer, or exceeding a hard limit.

## Provider protocol

`ContextProvider` is intentionally split into label and materialization calls:

```text
snapshot
  -> candidate_labels
      -> authorize each label
          -> materialize_candidate(authorized_id only)
              -> evidence_labels(referenced_ids only)
                  -> authorize each evidence label independently
                      -> materialize_evidence(authorized_id only)
```

An implementation must serve all calls from one immutable snapshot. The
compiler sorts labels and verifies returned identities, so provider iteration
order cannot affect canonical output. Providers must not place payload snippets
inside labels; doing so would destroy the non-interference boundary.

## Canonical pack

`ContextPack` contains:

- schema/id/status/snapshot/purpose;
- `ScopeManifest`, including the exact filter digest and temporal view;
- separate canonical `PackSections`;
- independently authorized `PackEvidence`;
- out-of-band `UseDirective` values;
- `GraphManifest`, `FreshnessManifest`, and `ProvenanceManifest`;
- optional authenticated continuation;
- `CompilationReport` and optional `NoMemoryResult`.

`ContextPack::validate` rechecks section layout/order, one-snapshot visibility,
scope containment, perspective, evidence-to-claim linkage, conflict closure,
graph identity, directive/provenance completeness, exact counters, sufficiency,
and no-memory consistency. Deserializers always call this validation.

## Rendering

`ContextRenderer::render` is pure. It accepts an already canonical pack and a
compatible model profile. The renderer may change placement, delimiters, and
format, but not block IDs, claim IDs, evidence handles, conflict sets,
perspectives, or epistemic state.

Supported views are:

| `RendererKind` | Intended target |
|---|---|
| `Compact` | small/local model with explicit critical-first placement |
| `HostedStructured` | hosted tool-result runtime with native citation support |
| `Chat` | separated chat instruction/data channels |
| `Coding` | coding runtime with procedures/decisions/facts first |
| `CanonicalJson` | machine-readable complete data envelope |

All views return `RenderedContext` with separate control/data strings and exact
token counts. Text views place materialized evidence immediately after the
block it supports. Canonical JSON retains stable evidence handles plus the
canonical evidence pool.

## Progressive compilation

If optional material remains after the soft budget boundary, the pack includes
an opaque `ContextContinuationToken`. Re-submit the same request with that token
to continue deterministic optional selection. Authentication binds the token to
the complete snapshot (including watermarks), filter digest, model profile,
purpose, scopes, temporal view, facets, budgets, evidence requirements, and
compiler version. Any mutation or tampering fails closed.

Continuation state contains only counters, digests, and an offset. It does not
contain candidate text, evidence, principals, or secrets.

## Serialization

`CanonicalSerializer` exposes:

- `to_json` / `from_json`;
- `to_json_pretty`;
- `to_protobuf` / `from_protobuf`;
- `digest`, a lowercase BLAKE3 digest of canonical Protobuf bytes.

Repeated values must be in strict canonical order. Protobuf field 11 in the
block-kind enum is a rejected legacy goal/open-loop value and is never reused;
v1 uses distinct goal, constraint, and open-loop values.

## Error surface

`ContextError` separates invalid requests, authorization failures, provider
contract violations, tokenizer failures, hard-budget failures, serialization
failures, and invalid continuations. Callers should treat authorization,
provider identity/snapshot, and continuation errors as fail-closed events, not
as reasons to retry with weaker filters.
