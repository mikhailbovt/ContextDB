# M12 API and integration contract

## 1. Runtime and lineage

`RuntimeDescriptor` combines the M11 `ModelProfile` with a typed provider ID, the M8
renderer, routed capabilities, installed tool contracts, immutable embedding spaces,
prompt-cache namespace, and processing locality. `validate_as_active_lineage` binds it to
the active entry of a core `ContinuityProfile`.

Use `RuntimeDescriptor::lineage_ref(first_used_at)` to create the target lineage entry and
`append_model_lineage` to create the next immutable `ContinuityProfile` revision. The
function preserves profile/agent/subject/migration/identity policy, requires the exact next
revision, closes the old active runtime in the new lineage view, rejects malformed lineage,
and applies `SemanticEnvelope::validate_derived_from` so policy cannot broaden.

## 2. Portable checkpoint

Create an artifact with:

```rust,ignore
let checkpoint = PortableCheckpoint::new(
    core_checkpoint,
    &continuity_profile,
    &source_runtime,
    portable_policy,
)?;
let bytes = checkpoint.to_json()?;
```

`PortableCheckpoint` binds:

- stable workspace, agent, and memory subject;
- core checkpoint and open loops;
- exact continuity-profile ID, revision, content digest, and required facets;
- exact source profile and runtime digest;
- a policy envelope proven no broader than the source semantic policy;
- `OperationalContinuity` as the only identity kind.

After loading authoritative state, call `validate_against(profile, runtime)`. `from_json`
enforces compact canonical JSON and all self-contained digest/invariant checks, but an
unkeyed digest is not a signature.

## 3. Compatibility analysis

Call `CompatibilityAnalyzer::analyze` with stable migration/workspace/agent/subject IDs,
source and target descriptors, explicit `MigrationRequirements`, re-embedding scopes, and
one fixed semantic snapshot.

The output is a canonically sorted, digest-bound `MigrationCompatibilityReport`. Blocking
findings prevent bootstrap. The analyzer reports:

- absolute and relative context/schema limits;
- tokenizer and structured-output changes;
- missing or changed tools and capabilities;
- citation, cache, renderer, instruction hierarchy, position, language, modality, and
  external-processing differences;
- incompatible vector-space ID reuse, missing target spaces, and immutable rebuild jobs;
- explicit style/behavior continuity warnings.

The same source and target profile is valid for process restart. Cross-model migrations
use distinct descriptors and receive adaptation warnings.

## 4. Re-embedding

Each `ReembeddingJobSpec` is content-derived from migration ID, workspace, snapshot,
scopes, and exact source/target space descriptors. It rejects same-ID rebuilds,
cross-modality conversion, compatible no-op rebuilds, repeated scopes, and digest drift.

`ReembeddingJob` permits only:

```text
queued -> running -> succeeded
                  -> failed(retryable) -> running
queued/failed -> cancelled
```

Success includes an output manifest digest and item count. Actual vector reads, model
execution, atomic publication, and old-space compaction belong to storage/worker crates.
`MigrationLifecycle::finish_reembedding` accepts only the complete, unique set of exact
jobs from the compatibility report.

## 5. Bootstrap and lifecycle

`BootstrapRequest` carries the authoritative profile, exact source runtime, portable
checkpoint, compatibility report, exact target M8 profile, coherent snapshot/filter,
principal/scopes, strict `ContextBudgets`, and explicit conditional approvals.

`BootstrapCompiler::compile` validates every identity/runtime/policy binding before the
`ContextProvider` is touched. It then compiles a `PackPurpose::Bootstrap` M8 pack with the
RFC bootstrap facets. Deep history is not loaded. `BootstrapResult` reports stable subject,
checkpoint open loops, preservation result, warnings, and a trace digest.

`MigrationLifecycle` has validated phases:

```text
planned
  -> checkpoint_sealed
  -> compatibility_analyzed
  -> reembedding? -> ready_for_bootstrap
  -> bootstrapped
  -> completed
```

Any nonterminal phase may enter `failed`. Every transition is monotonic, append-only,
payload-free, and artifact-digest bound. `record_bootstrap` requires M8 status
`sufficient` and complete open-loop preservation. Lifecycle JSON round-trips through
strict canonical parsing.

## 6. Action profile

`PreflightEvaluator` consumes an already policy-safe action-purpose `ContextPack`. It
extracts constraints, previous decisions, procedures, preferences, and unresolved blocks.
`MemoryGuardDecision` may allow by memory policy, deny, or require review. The report's
`grants_authority` invariant is always false; `HostAuthorizationStatus` remains an
independent input.

`PostflightRecord` links the exact preflight, plan digest, untrusted tool-result digests,
actual outcome, separate verification state, produced artifacts, and follow-up
commitments. A successful external action is invalid without independently granted host
authorization. Preflight and postflight reports support strict canonical JSON.

## 7. Handoff

`HandoffRequest` requires export purpose, recipient principal, explicit non-private sharing
scope, publishable block and memory source sets, accepted commitments, issue/expiry,
revocation handle, and recipient compartments/approvals.

`HandoffCompiler` executes this order:

1. validate checkpoint, recipient, scopes, expiry, and effective export policy;
2. expose only declared candidate labels to M8;
3. let M8 authorize labels before payload materialization;
4. enforce candidate provenance inside the declared memory source set;
5. independently authorize every raw evidence handle;
6. rebuild a handoff-purpose ContextPack from the recipient-visible set;
7. allow only goal/state/decision/constraint/open-loop/evidence/unknown categories;
8. verify explicitly accepted commitments are represented;
9. seal a payload-free `HandoffManifest`.

The manifest binds sender, recipient, workspace, sharing topology, checkpoint/policy,
snapshot/filter, target profile, selected blocks, memory/evidence sources, commitments,
pack digest, issue/expiry, and revocation handle. Call `validate_use(now, revoked)` before
every consumption. The `revoked` value must come from a live host registry.

## 8. Canonical artifacts

Strict compact canonical JSON (`to_json` / `from_json`) is available for:

- `PortableCheckpoint`;
- `MigrationCompatibilityReport`;
- `MigrationLifecycle`;
- `PreflightReport`;
- `PostflightRecord`;
- `HandoffManifest`.

Alternate whitespace/key layouts are rejected on import. IDs use stable typed wrappers,
sets/maps use ordered collections, and artifact digests exclude only their own digest
field. M8 remains the authority for canonical ContextPack JSON/Protobuf and rendering.

## 9. Host responsibilities

The host must provide durable storage/MVCC, trusted current profile/runtime records, exact
tokenizers, model/tool workers, atomic vector publication, authorization decisions,
encryption/signatures, audit persistence, revocation lookup, and real BENCH-D observations.
None of those responsibilities is silently simulated by this crate.
