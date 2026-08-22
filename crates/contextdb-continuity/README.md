# contextdb-continuity

`contextdb-continuity` is the deterministic M12 orchestration layer for process restart,
cross-model migration, bounded bootstrap, optional action lifecycle, and privacy-safe
handoff. It preserves an operational `MemorySubjectId`; it does not claim that two model
runtimes are psychologically or metaphysically identical.

The crate is pure Rust and performs no storage, networking, model calls, tool execution,
embedding, encryption, or Codex integration. Hosts provide already-labelled M8 context
sources, exact token counters, timestamps, authorizations, and durable execution.

## Flow

```text
ContinuityProfile + exact source RuntimeDescriptor
    -> PortableCheckpoint (profile/runtime/policy digests)
    -> CompatibilityAnalyzer (exact target descriptor + requirements)
    -> immutable ReembeddingJobSpec(s), when needed
    -> BootstrapCompiler (policy first, bounded M8 ContextPack)
    -> MigrationLifecycle (append-only validated transition trace)
    -> host verification
```

The same checkpoint/bootstrap path supports a process restart with an unchanged runtime.
A model switch additionally adapts tokenizer, renderer, context budget, structured output,
tools, capabilities, citations, prompt cache, instruction hierarchy, position behavior,
language/modality coverage, processing locality, and embedding spaces.

## Invariants

- `AgentId`, `MemorySubjectId`, workspace, checkpoint, profile revision, and exact runtime
  digests are bound before a provider can be read.
- The only identity kind is `OperationalContinuity`; model replacement never implies
  ontological identity or identical wording/behavior.
- Portable policy must be no broader than the source `SemanticEnvelope`. Consent,
  ownership, purpose, use, compartment, and external-processing gates fail closed.
- Bootstrap uses a small, hard-budgeted M8 `ContextPack`; it never sends the complete
  checkpoint or archive to the model and cannot complete lifecycle unless every required
  facet is sufficient and every checkpoint open loop is represented.
- An incompatible vector encoder never reuses a `VectorSpaceId`. Re-embedding reads one
  immutable snapshot and publishes only a new target space.
- Preflight can block or request review but cannot grant host/tool authority. Tool results
  remain explicitly untrusted in postflight.
- Handoff is an explicit publication operation. Agent-private scope is rejected,
  recipient policy runs before provider access, summaries are rebuilt from the declared
  source set, raw evidence is authorized independently, and the manifest binds expiry,
  revocation handle, snapshot, filter, policy, source set, and ContextPack digest.

## Public surfaces

- Runtime/profile: `RuntimeDescriptor`, `ToolDescriptor`,
  `EmbeddingSpaceDescriptor`, `append_model_lineage`.
- Checkpoint/policy: `PortableCheckpoint`, `ContinuityPolicyEnvelope`,
  `ConditionalApprovals`.
- Compatibility: `MigrationRequirements`, `CompatibilityAnalyzer`,
  `MigrationCompatibilityReport`.
- Representation rebuild: `ReembeddingJobSpec`, `ReembeddingJob`.
- Resume: `BootstrapRequest`, `BootstrapCompiler`, `BootstrapResult`.
- Lifecycle: `MigrationLifecycle`, `MigrationPhase`, `MigrationEvent`.
- Action profile: `PreflightEvaluator`, `PreflightReport`, `PostflightRecord`.
- Multi-agent transfer: `HandoffCompiler`, `HandoffManifest`,
  `MemorySharingScope`.
- Evaluation: `BenchD`, `BenchDThresholds`, `BenchDObservation`, `BenchDReport`.

See [docs/API.md](docs/API.md) for integration order and serialization
contracts. Executable acceptance coverage and remaining external boundaries
are recorded by this crate's tests and verification commands.

## Verification

```powershell
cargo fmt -p contextdb-continuity -- --check
cargo clippy -p contextdb-continuity --all-targets -- -D warnings
cargo test -p contextdb-continuity
$env:RUSTDOCFLAGS='-D warnings'; cargo doc -p contextdb-continuity --no-deps
```

The deterministic Model A to Model B oracle is locked by
`tests/fixtures/model_a_to_b_golden.json`. It proves stable identities, expected warnings,
new-space re-embedding, target rendering, and open-loop bootstrap output.

## Security boundary

BLAKE3 bindings and strict canonical parsing provide deterministic integrity checks, not
transport authenticity. A host exporting checkpoint JSON must encrypt it, authenticate or
sign it, enforce export capability, persist an audit receipt, and support redacted subsets.
`HandoffManifest::validate_use` accepts the host's live revocation decision; this crate does
not pretend that a serialized boolean is a revocation registry.
