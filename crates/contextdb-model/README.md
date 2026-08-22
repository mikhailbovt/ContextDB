# contextdb-model

`contextdb-model` is the M9 provider-neutral compute boundary for ContextDB.
It treats every model response as untrusted proposal data. The crate has no
storage/journal dependency, no provider SDK, no credentials, and no API that
can publish a semantic mutation.

The implementation follows RFC 0001 sections 17.4, 20.3-20.23, 26.13,
26.15, 26.18, 26.21, 26.23, 27.11, and the M9 roadmap gate.

## Non-negotiable invariants

- A provider receives only an immutable prompt/schema reference, a separate
  instruction channel, and the policy-selected input representation.
- Hosted execution is denied unless consent, allowlist, residency, retention,
  training, classification, and explicit redaction requirements all pass.
- `Secret` input never reaches a model route or deterministic fallback.
- Raw provider bytes cannot become a `ValidatedModelProposal` without exact
  structural and semantic schema validation. Unknown and duplicate JSON fields
  fail closed.
- `ValidatedModelProposal` is still only a proposal. Model adapters have no
  core mutation, storage, journal, ACL, evidence-deletion, or publication API.
- A provider call cannot start unless its payload-free start audit record is
  accepted. Audit and `Debug` surfaces contain digests, sizes, lineage, route
  decisions, status, timing, and usage—not input/output content.
- Shadow results expose only status, digests, validity, route, and usage. They
  never enter production cache or circuit state.
- Retry, deadline, repair, queue, batch, schema, prompt, identifier, token,
  latency, and cost operations are explicitly bounded.

## M9 acceptance matrix

| RFC / requested capability | Implementation artifact | Executable proof | Status |
|---|---|---|---|
| Capability registry and `ModelProfile` | `registry.rs`, `types.rs` | `capability_registry_profiles_and_prompt_assets_are_immutable` | Complete |
| Provider-neutral gateway and isolated provider boundary | `gateway.rs`, `provider.rs` | `recorded_local_adapter_is_a_second_network_free_model_path` | Complete |
| Deterministic mock and local adapters, without network calls | `mock.rs`, `RecordedLocalProvider` | recorded-local, retry, deadline, and shadow tests | Complete |
| Strict structured output before proposal escape | `schema.rs`, private fields on `ValidatedModelProposal` | `strict_schema_rejects_malformed_unknown_duplicate_and_unbounded_outputs_before_mutation`; `semantic_validation_runs_after_structure_and_before_proposal_escape`; unknown-field property test | Complete |
| Proposal-only model authority | crate dependency boundary and opaque validated result | compile-time API boundary plus schema tests | Complete for M9; authorization/publication remains a downstream core responsibility |
| Bounded retry, stable provider idempotency key, retry lineage, deadline abstraction | `RetryPolicy`, `RuntimeTimer`, gateway attempt loop | `retries_are_bounded_idempotent_and_audited_with_fake_time`; `late_provider_output_is_timeout_not_success_and_retry_can_recover_without_sleep`; repair-phase and retry-bound tests | Complete |
| Circuit breaker and rate-limit watermark | `CircuitBreaker`, `AvailabilityRegistry` | `circuit_breaker_opens_and_allows_only_one_fake_clock_probe` | Complete |
| Cost, quality, capability, language, modality, locality, and privacy routing | `policy.rs` | `cost_and_currency_budgets_filter_routes_before_provider_execution`; `privacy_router_blocks_unredacted_hosted_data_and_sends_only_minimized_payload` | Complete |
| Payload-free model call audit | `audit.rs`, gateway fail-closed audit calls | `validated_cache_deduplicates_calls_and_audit_never_contains_sensitive_payload`; `external_call_is_aborted_when_pre_call_audit_fails` | Complete |
| Immutable prompt version and hash, golden/adversarial metadata | `prompt.rs` | `capability_registry_profiles_and_prompt_assets_are_immutable` | Complete |
| Isolated shadow evaluation | `ModelGateway::evaluate_shadow` | `shadow_evaluation_is_digest_only_and_cannot_warm_production_cache` | Complete |
| No-model correctness/degraded path | `fallback.rs`, explicit `DegradedModelOutcome` | `provider_outage_uses_schema_validated_no_model_fallback_or_explicit_degraded_mode` | Complete |
| Batch scheduling, exact-envelope deduplication, safe coalescing, compatibility partitions, urgency | `batch.rs`, provider `invoke_batch` contract | `batch_scheduler_deduplicates_exact_envelopes_but_not_lineage_and_coalesces_safely` | Complete |
| M9 exit: no provider type in core semantics | all provider types live only in this crate; `contextdb-core` is read-only dependency | package build and dependency inspection | Complete |
| M9 exit: malformed output cannot mutate memory | no mutation/storage API plus opaque validated proposal | strict and semantic schema tests | Complete |
| M9 exit: privacy routing tested | hosted raw denial, explicit minimization, selected-classification, `Secret` denial | privacy adversarial test | Complete |
| M9 exit: deterministic mode works | schema-validated recorded fallback | outage/fallback test | Complete |

## Deliberate integration boundaries

- `ModelProvider` is synchronous and carries an absolute deadline. The gateway
  rejects a response returned at or after that deadline, but Rust cannot safely
  preempt a non-cooperative blocking adapter. A real local or hosted adapter
  must enforce the deadline in its inference/transport runtime.
- The scheduler forms bounded compatible batches and the provider trait exposes
  `invoke_batch`; production-native bulk transport is an adapter optimization,
  not part of this network-free crate.
- Cost budgets are immutable snapshots evaluated before routing. Atomic durable
  reservation/debit belongs to the host budget authority; this crate does not
  claim concurrency-safe financial accounting.
- Prompt assets bind evaluation thresholds and immutable golden/adversarial
  case digests. Running an organization-specific evaluation corpus and signing
  its report is a release/evaluation concern outside this crate.
- No real hosted SDK, local inference engine, credential store, or network call
  is included. Those adapters must remain outside core semantics and pass the
  same provider conformance boundary.
