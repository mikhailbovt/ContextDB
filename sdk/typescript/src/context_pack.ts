import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { ProtocolError } from "./errors.js";
import type { AuthenticatedRequestContext } from "./domain.js";

export const CONTEXT_PACK_CANONICAL_ENCODING = "contextdb.context_pack.protobuf.v1" as const;
export const CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM = "blake3-256" as const;

export type RecallMode =
  | "never" | "optional" | "auto" | "required" | "implicit_continuity"
  | "explicit" | "associative" | "relational" | "historical" | "forensic";
export type RecallIntent =
  | "continuity" | "current_truth" | "historical_truth" | "associative" | "relational"
  | "procedural" | "reflective" | "forensic" | "bootstrap" | "preflight";
export type PackPurpose =
  | "conversation" | "continuity" | "autobiographical" | "knowledge" | "historical"
  | "reflective" | "action" | "handoff" | "bootstrap";
export type RendererKind = "compact" | "hosted_structured" | "chat" | "coding" | "canonical_json";
export type StructuredFormat = "compact_text" | "json" | "markdown" | "tool_result";
export type PositionProfile = "balanced" | "critical_first" | "evidence_adjacent" | "small_model_explicit";
export type InstructionHierarchy = "separated_channels" | "single_prompt_delimited";
export type PackStatus = "sufficient" | "partial" | "no_memory";
export type RecallStatus = "skipped" | "complete" | "partial" | "unknown";
export type StopReason =
  | "gate_skipped" | "sufficient" | "node_budget" | "graph_budget" | "hop_budget"
  | "token_budget" | "deadline" | "no_useful_candidates" | "unknown_or_conflicted"
  | "continuation_boundary";
export type PackBlockKind =
  | "situation" | "self_context" | "participant" | "shared_history" | "episode"
  | "fact" | "relationship" | "preference" | "boundary" | "goal" | "decision"
  | "timeline" | "procedure" | "constraint" | "open_loop" | "conflict" | "unknown" | "raw_observation";
export type CompressionLevel = "l0_orientation" | "l1_summary" | "l2_structured" | "l3_evidence" | "l4_raw";
export type ContentTrust = "trusted_source" | "mixed" | "untrusted" | "unknown";
export type InstructionCapability = "none" | "host_trusted";
export type InterpretationRule =
  | "factual_data" | "historical_data" | "constraint_data" | "style_signal"
  | "hypothesis_only" | "unknown_marker" | "conflict_alternatives";
export type UseAction = "mention_naturally" | "use_silently" | "constraint_only" | "style_only";
export type DirectiveReason =
  | "policy_allows_mention" | "mention_denied" | "explicit_request_required"
  | "constraint_semantics" | "style_semantics";
export type OmissionReason =
  | "outside_requested_scope" | "future_transaction" | "epistemically_inactive"
  | "secret_redacted" | "unsupported_under_evidence_policy"
  | "unresolved_conflict_without_manifest" | "redundant" | "block_budget" | "token_budget"
  | "evidence_budget" | "history_budget" | "conflict_budget" | "serialization_budget"
  | "selection_evaluation_budget" | "continuation_boundary";
export type NoMemoryReason =
  | "no_authorized_candidates" | "no_relevant_candidates"
  | "budget_could_not_admit_optional_memory";

export interface OtherVariant { readonly other: string }
export type RecallIntentValue = RecallIntent | OtherVariant;
export type StringOrOther = string | OtherVariant;

export interface PackFacetRequirement {
  readonly name: string;
  readonly minimum_confidence_micros: number;
  readonly require_evidence: boolean;
}

export interface RecallLimits {
  readonly max_nodes_examined: number;
  readonly max_seed_candidates: number;
  readonly max_graph_hops: number;
  readonly max_frontier_per_hop: number;
  readonly max_evidence_units: number;
  readonly max_context_tokens: number;
  readonly deadline_micros: number;
}

export interface ContextBudgets {
  readonly hard_tokens: number;
  readonly soft_tokens: number;
  readonly max_blocks: number;
  readonly max_evidence_blocks: number;
  readonly max_raw_evidence_tokens: number;
  readonly max_history_tokens: number;
  readonly max_conflict_tokens: number;
  readonly max_serialized_bytes: number;
  readonly max_selection_evaluations: number;
}

export interface ModelProfile {
  readonly id: string;
  readonly family: string;
  readonly tokenizer_id: string;
  readonly renderer: RendererKind;
  readonly max_context_tokens: number;
  readonly reserved_output_tokens: number;
  readonly preferred_structured_format: StructuredFormat;
  readonly supports_tool_results: boolean;
  readonly supports_native_citations: boolean;
  readonly supports_prompt_caching: boolean;
  readonly position_profile: PositionProfile;
  readonly instruction_hierarchy: InstructionHierarchy;
  readonly max_schema_complexity: number;
  readonly external_processing: boolean;
}

export interface SuppliedVector {
  readonly space: string;
  readonly values: readonly number[];
}

export interface CompileContextPlan {
  readonly pack_id: string;
  readonly query: string;
  readonly mode: RecallMode;
  readonly intent: RecallIntentValue;
  readonly purpose: PackPurpose;
  readonly at_commit: number | null;
  readonly now_micros: number;
  readonly required_facets: readonly PackFacetRequirement[];
  readonly recall_limits: RecallLimits;
  readonly context_budgets: ContextBudgets;
  readonly model_profile: ModelProfile;
  readonly explicit_memory_request: boolean;
  readonly require_primary_evidence: boolean;
  readonly include_evidence_quotes: boolean;
  readonly permit_derived_only: boolean;
  readonly max_projection_lag_commits: number;
  readonly allow_stale: boolean;
  readonly query_vector: SuppliedVector | null;
  readonly continuation: string | null;
}

export interface CompileContextRequest {
  readonly context: AuthenticatedRequestContext;
  readonly plan: CompileContextPlan;
}

export interface RecallWatermarks {
  readonly journal: number;
  readonly semantic: number;
  readonly lexical: number;
  readonly vector: Readonly<Record<string, number>>;
  readonly graph: number;
  readonly hierarchy: Readonly<Record<string, number>>;
}

export interface ProviderSnapshot {
  readonly database_id: string;
  readonly commit_seq: number;
  readonly watermarks: RecallWatermarks;
}

export interface TimeRange { readonly start: number; readonly end: number | null }
export type TemporalConstraint =
  | { readonly kind: "current" }
  | { readonly kind: "valid_during"; readonly range: TimeRange }
  | { readonly kind: "known_at"; readonly commit_seq: number }
  | { readonly kind: "bitemporal"; readonly valid_during: TimeRange; readonly known_at: number };

export interface BlockRepresentation {
  readonly level: CompressionLevel;
  readonly summary: string;
  readonly fields: Readonly<Record<string, string>>;
  readonly omitted_facets: readonly string[];
}

export interface ExactFragment { readonly label: string; readonly value: string }
export type MemoryRefKind =
  | "observation" | "episode_view" | "artifact" | "evidence" | "node" | "claim"
  | "edge" | "conflict_set";
export interface MemoryRef { readonly kind: MemoryRefKind; readonly id: string }

export type EpistemicRole =
  | "experiencer" | "witness" | "asserter" | "interpreter" | "verifier"
  | "external_reporter" | "fictional_narrator" | OtherVariant;
export interface Perspective {
  readonly knower: string;
  readonly experiencer: string | null;
  readonly narrator: string;
  readonly role: EpistemicRole;
}

export type ConflictState =
  | { readonly state: "none" | "disputed" }
  | { readonly state: "in_conflict" | "resolved"; readonly set_id: string };
export type EpistemicBasis =
  | "observation" | "actor_assertion" | "model_inference" | "deterministic_derivation"
  | "human_adjudication" | "hypothesis";
export type AcceptanceState = "proposed" | "validated" | "accepted" | "consolidated" | "rejected";
export type PackLifecycle = "active" | "historical" | "superseded" | "retracted" | "suppressed" | "deleted";
export interface EpistemicState {
  readonly basis: EpistemicBasis;
  readonly acceptance: AcceptanceState;
  readonly conflict: ConflictState;
  readonly lifecycle: PackLifecycle;
}
export type SupportState =
  | { readonly state: "supported" }
  | { readonly state: "unsupported"; readonly reason: string };
export type ConflictResolution =
  | { readonly state: "unresolved" }
  | { readonly state: "resolved"; readonly winner: string; readonly rationale: string };
export interface ConflictDescriptor {
  readonly set_id: string;
  readonly alternatives: readonly string[];
  readonly resolution: ConflictResolution;
  readonly blocking: boolean;
}
export interface UnknownDescriptor { readonly question: string; readonly reason: string; readonly blocking: boolean }

export type SourceClass =
  | "user_statement" | "shared_conversation" | "repository" | "tool_output"
  | "external_document" | "sensor" | "deterministic_derivation" | "model_generated"
  | "imported" | OtherVariant;
export type ContentTaint =
  | "untrusted_instructions" | "external_content" | "user_controlled" | "generated"
  | "secret_like" | "personally_sensitive" | OtherVariant;

export interface ContextBlock {
  readonly id: string;
  readonly kind: PackBlockKind;
  readonly representation: BlockRepresentation;
  readonly exact_fragments: readonly ExactFragment[];
  readonly memory_refs: readonly MemoryRef[];
  readonly claim_ids: readonly string[];
  readonly evidence_handles: readonly string[];
  readonly facets: readonly string[];
  readonly scopes: readonly string[];
  readonly valid_time: TimeRange | null;
  readonly known_at_commit: number;
  readonly perspective: Perspective | null;
  readonly epistemic: EpistemicState;
  readonly confidence_micros: number;
  readonly trust: ContentTrust;
  readonly instruction_capability: "none";
  readonly source_class: SourceClass;
  readonly taints: readonly ContentTaint[];
  readonly interpretation: InterpretationRule;
  readonly support: SupportState;
  readonly conflict: ConflictDescriptor | null;
  readonly unknown: UnknownDescriptor | null;
}

export interface PackSections {
  readonly situation: readonly ContextBlock[];
  readonly self_context: readonly ContextBlock[];
  readonly participants: readonly ContextBlock[];
  readonly shared_history: readonly ContextBlock[];
  readonly episodes: readonly ContextBlock[];
  readonly facts: readonly ContextBlock[];
  readonly relationships: readonly ContextBlock[];
  readonly preferences: readonly ContextBlock[];
  readonly boundaries: readonly ContextBlock[];
  readonly goals: readonly ContextBlock[];
  readonly decisions: readonly ContextBlock[];
  readonly timeline: readonly ContextBlock[];
  readonly procedures: readonly ContextBlock[];
  readonly constraints: readonly ContextBlock[];
  readonly open_loops: readonly ContextBlock[];
  readonly conflicts: readonly ContextBlock[];
  readonly unknowns: readonly ContextBlock[];
  readonly raw_observations?: readonly ContextBlock[];
}

export type EvidenceSelector =
  | { readonly kind: "text_bytes" | "lines" | "time_micros"; readonly start: number; readonly end: number }
  | { readonly kind: "json_pointer"; readonly pointer: string }
  | { readonly kind: "whole" };
export interface OriginalSourceSpan {
  readonly event_id: string;
  readonly payload_digest: string;
  readonly start: number;
  readonly end: number;
  readonly span_digest: string;
}
export interface PackEvidence {
  readonly id: string;
  readonly source: string;
  readonly selector: EvidenceSelector;
  readonly excerpt: string | null;
  readonly claim_ids: readonly string[];
  readonly provenance_family: string;
  readonly primary: boolean;
  readonly trust_micros: number;
  readonly source_class: SourceClass;
  readonly taints: readonly ContentTaint[];
  readonly lineage: readonly string[];
  readonly original_span?: OriginalSourceSpan;
}
export interface UseDirective { readonly block_id: string; readonly action: UseAction; readonly reason_code: DirectiveReason }
export interface ScopeManifest {
  readonly workspace: string;
  readonly subject: string;
  readonly scopes: readonly string[];
  readonly purpose: PackPurpose;
  readonly temporal_view: TemporalConstraint;
  readonly filter_digest: string;
}
export interface GraphManifest {
  readonly memory_refs: readonly MemoryRef[];
  readonly claim_ids: readonly string[];
  readonly conflict_sets: readonly string[];
}
export interface BlockProvenance {
  readonly block_id: string;
  readonly memory_refs: readonly MemoryRef[];
  readonly evidence_handles: readonly string[];
  readonly source_classes: readonly SourceClass[];
}
export interface ProvenanceManifest {
  readonly compiler_version: string;
  readonly policy_filter_digest: string;
  readonly blocks: readonly BlockProvenance[];
  readonly evidence_sources: Readonly<Record<string, string>>;
}
export interface FreshnessManifest { readonly snapshot: ProviderSnapshot; readonly warnings: readonly string[] }
export interface ContextBudgetUsage {
  readonly rendered_tokens: number;
  readonly control_tokens: number;
  readonly data_tokens: number;
  readonly blocks: number;
  readonly evidence_blocks: number;
  readonly raw_evidence_tokens: number;
  readonly history_tokens: number;
  readonly conflict_tokens: number;
  readonly serialized_bytes: number;
  readonly selection_evaluations: number;
}
export interface Omission { readonly block_id: string; readonly reason: OmissionReason }
export interface PackSufficiencyReport {
  readonly sufficient: boolean;
  readonly covered_facets: readonly string[];
  readonly missing_facets: readonly string[];
  readonly unresolved_conflicts: readonly string[];
  readonly blocking_unknowns: readonly string[];
  readonly unsupported_blocks: readonly string[];
}
export interface CompilationReport {
  readonly compiler_version: string;
  readonly schema_version: string;
  readonly model_profile: string;
  readonly tokenizer: string;
  readonly renderer: RendererKind;
  readonly budget: ContextBudgets;
  readonly usage: ContextBudgetUsage;
  readonly soft_budget_exceeded: boolean;
  readonly selected_blocks: readonly string[];
  readonly omissions: readonly Omission[];
  readonly sufficiency: PackSufficiencyReport;
}
export interface NoMemoryResult { readonly reason: NoMemoryReason; readonly missing_facets: readonly string[] }
export interface ContextPackContinuation { readonly opaque: string }
export interface ContextPack {
  readonly schema_version: string;
  readonly id: string;
  readonly status: PackStatus;
  readonly snapshot: ProviderSnapshot;
  readonly purpose: PackPurpose;
  readonly scope_manifest: ScopeManifest;
  readonly sections: PackSections;
  readonly evidence: readonly PackEvidence[];
  readonly use_directives: readonly UseDirective[];
  readonly graph_manifest: GraphManifest;
  readonly freshness: FreshnessManifest;
  readonly provenance: ProvenanceManifest;
  readonly continuation: ContextPackContinuation | null;
  readonly compilation: CompilationReport;
  readonly no_memory: NoMemoryResult | null;
}
export interface RenderedContextPayload {
  readonly profile_id: string;
  readonly renderer: RendererKind;
  readonly trusted_control: string;
  readonly untrusted_data: string;
  readonly control_tokens: number;
  readonly data_tokens: number;
  readonly total_tokens: number;
}
export interface RecallBudgetUsage {
  readonly nodes_examined: number;
  readonly graph_edges_examined: number;
  readonly max_hop_reached: number;
  readonly evidence_units: number;
  readonly context_tokens: number;
}
export interface ContextPackTrace {
  readonly trace_id: string;
  readonly snapshot: ProviderSnapshot;
  readonly filter_digest: string;
  readonly recall_status: RecallStatus;
  readonly stop_reason: StopReason;
  readonly recall_usage: RecallBudgetUsage;
  readonly pack_status: PackStatus;
  readonly pack_usage: ContextBudgetUsage;
  readonly selected_blocks: number;
  readonly evidence_blocks: number;
  readonly max_projection_lag_commits: number;
  readonly stale: boolean;
  readonly freshness_warnings: readonly string[];
}
export interface CompileContextResponse {
  readonly context_pack: ContextPack;
  readonly canonical_encoding: typeof CONTEXT_PACK_CANONICAL_ENCODING;
  readonly canonical_bytes: Uint8Array;
  readonly canonical_digest_algorithm: typeof CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM;
  readonly canonical_digest: string;
  readonly rendered: RenderedContextPayload;
  readonly continuation: string | null;
  readonly trace: ContextPackTrace;
}

type ObjectValue = Record<string, unknown>;

function object(value: unknown, name: string): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolError(`${name} must be an object`);
  }
  return value as ObjectValue;
}

function exact(value: ObjectValue, keys: readonly string[], name: string): void {
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    throw new ProtocolError(`${name} has missing or unknown fields`);
  }
}

function text(value: unknown, name: string): string {
  if (typeof value !== "string") throw new ProtocolError(`${name} must be a string`);
  return value;
}

function bool(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") throw new ProtocolError(`${name} must be a boolean`);
  return value;
}

function uint(value: unknown, name: string, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new ProtocolError(`${name} exceeds the safe unsigned integer range`);
  }
  return value;
}

function octets(value: unknown, name: string): Uint8Array {
  if (!Array.isArray(value) || value.some((item) => (
    typeof item !== "number" || !Number.isInteger(item) || item < 0 || item > 255
  ))) {
    throw new ProtocolError(`${name} must be an octet array`);
  }
  return Uint8Array.from(value as number[]);
}

function digest(value: unknown, name: string): string {
  const result = text(value, name);
  if (!/^[0-9a-f]{64}$/u.test(result)) throw new ProtocolError(`${name} must be lowercase BLAKE3-256 hex`);
  return result;
}

function int64(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new ProtocolError(`${name} exceeds the safe signed integer range`);
  }
  return value;
}

function nullableText(value: unknown, name: string): string | null {
  return value === null ? null : text(value, name);
}

function strings(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new ProtocolError(`${name} must be a string array`);
  }
  return value as string[];
}

function array<T>(value: unknown, name: string, parser: (item: unknown) => T): readonly T[] {
  if (!Array.isArray(value)) throw new ProtocolError(`${name} must be an array`);
  return value.map(parser);
}

function enumValue<T extends string>(value: unknown, name: string, choices: readonly T[]): T {
  const parsed = text(value, name);
  if (!(choices as readonly string[]).includes(parsed)) throw new ProtocolError(`${name} is invalid`);
  return parsed as T;
}

function stringRecord(value: unknown, name: string): Readonly<Record<string, string>> {
  const parsed = object(value, name);
  if (Object.values(parsed).some((item) => typeof item !== "string")) {
    throw new ProtocolError(`${name} values must be strings`);
  }
  return parsed as Record<string, string>;
}

function uintRecord(value: unknown, name: string): Readonly<Record<string, number>> {
  const parsed = object(value, name);
  const result: Record<string, number> = {};
  for (const [key, item] of Object.entries(parsed)) result[key] = uint(item, `${name}.${key}`);
  return result;
}

const recallModes = ["never", "optional", "auto", "required", "implicit_continuity", "explicit", "associative", "relational", "historical", "forensic"] as const;
const recallIntents = ["continuity", "current_truth", "historical_truth", "associative", "relational", "procedural", "reflective", "forensic", "bootstrap", "preflight"] as const;
const packPurposes = ["conversation", "continuity", "autobiographical", "knowledge", "historical", "reflective", "action", "handoff", "bootstrap"] as const;
const renderers = ["compact", "hosted_structured", "chat", "coding", "canonical_json"] as const;
const structuredFormats = ["compact_text", "json", "markdown", "tool_result"] as const;
const positionProfiles = ["balanced", "critical_first", "evidence_adjacent", "small_model_explicit"] as const;
const instructionHierarchies = ["separated_channels", "single_prompt_delimited"] as const;
const packStatuses = ["sufficient", "partial", "no_memory"] as const;
const recallStatuses = ["skipped", "complete", "partial", "unknown"] as const;
const stopReasons = ["gate_skipped", "sufficient", "node_budget", "graph_budget", "hop_budget", "token_budget", "deadline", "no_useful_candidates", "unknown_or_conflicted", "continuation_boundary"] as const;
const blockKinds = ["situation", "self_context", "participant", "shared_history", "episode", "fact", "relationship", "preference", "boundary", "goal", "decision", "timeline", "procedure", "constraint", "open_loop", "conflict", "unknown", "raw_observation"] as const;
const compressionLevels = ["l0_orientation", "l1_summary", "l2_structured", "l3_evidence", "l4_raw"] as const;
const contentTrust = ["trusted_source", "mixed", "untrusted", "unknown"] as const;
const interpretations = ["factual_data", "historical_data", "constraint_data", "style_signal", "hypothesis_only", "unknown_marker", "conflict_alternatives"] as const;
const useActions = ["mention_naturally", "use_silently", "constraint_only", "style_only"] as const;
const directiveReasons = ["policy_allows_mention", "mention_denied", "explicit_request_required", "constraint_semantics", "style_semantics"] as const;
const omissionReasons = ["outside_requested_scope", "future_transaction", "epistemically_inactive", "secret_redacted", "unsupported_under_evidence_policy", "unresolved_conflict_without_manifest", "redundant", "block_budget", "token_budget", "evidence_budget", "history_budget", "conflict_budget", "serialization_budget", "selection_evaluation_budget", "continuation_boundary"] as const;
const noMemoryReasons = ["no_authorized_candidates", "no_relevant_candidates", "budget_could_not_admit_optional_memory"] as const;
const memoryRefKinds = ["observation", "episode_view", "artifact", "evidence", "node", "claim", "edge", "conflict_set"] as const;
const sourceClasses = ["user_statement", "shared_conversation", "repository", "tool_output", "external_document", "sensor", "deterministic_derivation", "model_generated", "imported"] as const;
const taintKinds = ["untrusted_instructions", "external_content", "user_controlled", "generated", "secret_like", "personally_sensitive"] as const;

function other(value: unknown, name: string, choices: readonly string[]): StringOrOther {
  if (typeof value === "string") {
    if (!choices.includes(value)) throw new ProtocolError(`${name} is invalid`);
    return value;
  }
  const parsed = object(value, name);
  exact(parsed, ["other"], name);
  return { other: text(parsed.other, `${name}.other`) };
}

function parseRecallWatermarks(value: unknown): RecallWatermarks {
  const parsed = object(value, "recall watermarks");
  exact(parsed, ["journal", "semantic", "lexical", "vector", "graph", "hierarchy"], "recall watermarks");
  return {
    journal: uint(parsed.journal, "watermarks.journal"),
    semantic: uint(parsed.semantic, "watermarks.semantic"),
    lexical: uint(parsed.lexical, "watermarks.lexical"),
    vector: uintRecord(parsed.vector, "watermarks.vector"),
    graph: uint(parsed.graph, "watermarks.graph"),
    hierarchy: uintRecord(parsed.hierarchy, "watermarks.hierarchy"),
  };
}

function parseSnapshot(value: unknown): ProviderSnapshot {
  const parsed = object(value, "provider snapshot");
  exact(parsed, ["database_id", "commit_seq", "watermarks"], "provider snapshot");
  return {
    database_id: text(parsed.database_id, "snapshot.database_id"),
    commit_seq: uint(parsed.commit_seq, "snapshot.commit_seq"),
    watermarks: parseRecallWatermarks(parsed.watermarks),
  };
}

function parseTimeRange(value: unknown): TimeRange {
  const parsed = object(value, "time range");
  exact(parsed, ["start", "end"], "time range");
  return { start: int64(parsed.start, "time_range.start"), end: parsed.end === null ? null : int64(parsed.end, "time_range.end") };
}

function parseTemporal(value: unknown): TemporalConstraint {
  const parsed = object(value, "temporal constraint");
  const kind = text(parsed.kind, "temporal constraint kind");
  if (kind === "current") {
    exact(parsed, ["kind"], "temporal constraint");
    return { kind };
  }
  if (kind === "valid_during") {
    exact(parsed, ["kind", "range"], "temporal constraint");
    return { kind, range: parseTimeRange(parsed.range) };
  }
  if (kind === "known_at") {
    exact(parsed, ["kind", "commit_seq"], "temporal constraint");
    return { kind, commit_seq: uint(parsed.commit_seq, "temporal commit") };
  }
  if (kind === "bitemporal") {
    exact(parsed, ["kind", "valid_during", "known_at"], "temporal constraint");
    return { kind, valid_during: parseTimeRange(parsed.valid_during), known_at: uint(parsed.known_at, "temporal known_at") };
  }
  throw new ProtocolError("temporal constraint kind is invalid");
}

function parseMemoryRef(value: unknown): MemoryRef {
  const parsed = object(value, "memory ref");
  exact(parsed, ["kind", "id"], "memory ref");
  return { kind: enumValue(parsed.kind, "memory ref kind", memoryRefKinds), id: text(parsed.id, "memory ref id") };
}

function parseRepresentation(value: unknown): BlockRepresentation {
  const parsed = object(value, "block representation");
  exact(parsed, ["level", "summary", "fields", "omitted_facets"], "block representation");
  return {
    level: enumValue(parsed.level, "compression level", compressionLevels),
    summary: text(parsed.summary, "representation summary"),
    fields: stringRecord(parsed.fields, "representation fields"),
    omitted_facets: strings(parsed.omitted_facets, "omitted facets"),
  };
}

function parseExactFragment(value: unknown): ExactFragment {
  const parsed = object(value, "exact fragment");
  exact(parsed, ["label", "value"], "exact fragment");
  return { label: text(parsed.label, "fragment label"), value: text(parsed.value, "fragment value") };
}

function parsePerspective(value: unknown): Perspective {
  const parsed = object(value, "perspective");
  exact(parsed, ["knower", "experiencer", "narrator", "role"], "perspective");
  return {
    knower: text(parsed.knower, "perspective knower"),
    experiencer: nullableText(parsed.experiencer, "perspective experiencer"),
    narrator: text(parsed.narrator, "perspective narrator"),
    role: other(parsed.role, "epistemic role", ["experiencer", "witness", "asserter", "interpreter", "verifier", "external_reporter", "fictional_narrator"]) as EpistemicRole,
  };
}

function parseConflictState(value: unknown): ConflictState {
  const parsed = object(value, "conflict state");
  const state = text(parsed.state, "conflict state");
  if (state === "none" || state === "disputed") {
    exact(parsed, ["state"], "conflict state");
    return { state };
  }
  if (state === "in_conflict" || state === "resolved") {
    exact(parsed, ["state", "set_id"], "conflict state");
    return { state, set_id: text(parsed.set_id, "conflict set") };
  }
  throw new ProtocolError("conflict state is invalid");
}

function parseEpistemic(value: unknown): EpistemicState {
  const parsed = object(value, "epistemic state");
  exact(parsed, ["basis", "acceptance", "conflict", "lifecycle"], "epistemic state");
  return {
    basis: enumValue(parsed.basis, "epistemic basis", ["observation", "actor_assertion", "model_inference", "deterministic_derivation", "human_adjudication", "hypothesis"]),
    acceptance: enumValue(parsed.acceptance, "acceptance", ["proposed", "validated", "accepted", "consolidated", "rejected"]),
    conflict: parseConflictState(parsed.conflict),
    lifecycle: enumValue(parsed.lifecycle, "lifecycle", ["active", "historical", "superseded", "retracted", "suppressed", "deleted"]),
  };
}

function parseSupport(value: unknown): SupportState {
  const parsed = object(value, "support state");
  const state = text(parsed.state, "support state");
  if (state === "supported") {
    exact(parsed, ["state"], "support state");
    return { state };
  }
  if (state === "unsupported") {
    exact(parsed, ["state", "reason"], "support state");
    return { state, reason: text(parsed.reason, "support reason") };
  }
  throw new ProtocolError("support state is invalid");
}

function parseConflictResolution(value: unknown): ConflictResolution {
  const parsed = object(value, "conflict resolution");
  const state = text(parsed.state, "conflict resolution");
  if (state === "unresolved") {
    exact(parsed, ["state"], "conflict resolution");
    return { state };
  }
  if (state === "resolved") {
    exact(parsed, ["state", "winner", "rationale"], "conflict resolution");
    return { state, winner: text(parsed.winner, "conflict winner"), rationale: text(parsed.rationale, "conflict rationale") };
  }
  throw new ProtocolError("conflict resolution is invalid");
}

function parseConflictDescriptor(value: unknown): ConflictDescriptor {
  const parsed = object(value, "conflict descriptor");
  exact(parsed, ["set_id", "alternatives", "resolution", "blocking"], "conflict descriptor");
  return {
    set_id: text(parsed.set_id, "conflict set"),
    alternatives: strings(parsed.alternatives, "conflict alternatives"),
    resolution: parseConflictResolution(parsed.resolution),
    blocking: bool(parsed.blocking, "conflict blocking"),
  };
}

function parseUnknown(value: unknown): UnknownDescriptor {
  const parsed = object(value, "unknown descriptor");
  exact(parsed, ["question", "reason", "blocking"], "unknown descriptor");
  return {
    question: text(parsed.question, "unknown question"),
    reason: text(parsed.reason, "unknown reason"),
    blocking: bool(parsed.blocking, "unknown blocking"),
  };
}

function parseContextBlock(value: unknown): ContextBlock {
  const parsed = object(value, "context block");
  exact(parsed, ["id", "kind", "representation", "exact_fragments", "memory_refs", "claim_ids", "evidence_handles", "facets", "scopes", "valid_time", "known_at_commit", "perspective", "epistemic", "confidence_micros", "trust", "instruction_capability", "source_class", "taints", "interpretation", "support", "conflict", "unknown"], "context block");
  const capability = enumValue(parsed.instruction_capability, "instruction capability", ["none", "host_trusted"]);
  if (capability !== "none") throw new ProtocolError("recalled ContextPack data gained instruction capability");
  if (parsed.kind === "raw_observation" && (strings(parsed.claim_ids, "claim ids").length !== 0 ||
    strings(parsed.evidence_handles, "evidence handles").length === 0 || parsed.interpretation !== "historical_data" ||
    parseSupport(parsed.support).state !== "supported")) {
    throw new ProtocolError("raw observation must retain evidence without asserting current claims");
  }
  return {
    id: text(parsed.id, "block id"),
    kind: enumValue(parsed.kind, "block kind", blockKinds),
    representation: parseRepresentation(parsed.representation),
    exact_fragments: array(parsed.exact_fragments, "exact fragments", parseExactFragment),
    memory_refs: array(parsed.memory_refs, "memory refs", parseMemoryRef),
    claim_ids: strings(parsed.claim_ids, "claim ids"),
    evidence_handles: strings(parsed.evidence_handles, "evidence handles"),
    facets: strings(parsed.facets, "facets"),
    scopes: strings(parsed.scopes, "scopes"),
    valid_time: parsed.valid_time === null ? null : parseTimeRange(parsed.valid_time),
    known_at_commit: uint(parsed.known_at_commit, "known_at_commit"),
    perspective: parsed.perspective === null ? null : parsePerspective(parsed.perspective),
    epistemic: parseEpistemic(parsed.epistemic),
    confidence_micros: uint(parsed.confidence_micros, "confidence_micros", 0xffff_ffff),
    trust: enumValue(parsed.trust, "content trust", contentTrust),
    instruction_capability: capability,
    source_class: other(parsed.source_class, "source class", sourceClasses) as SourceClass,
    taints: array(parsed.taints, "taints", (item) => other(item, "content taint", taintKinds) as ContentTaint),
    interpretation: enumValue(parsed.interpretation, "interpretation", interpretations),
    support: parseSupport(parsed.support),
    conflict: parsed.conflict === null ? null : parseConflictDescriptor(parsed.conflict),
    unknown: parsed.unknown === null ? null : parseUnknown(parsed.unknown),
  };
}

const sectionKeys = ["situation", "self_context", "participants", "shared_history", "episodes", "facts", "relationships", "preferences", "boundaries", "goals", "decisions", "timeline", "procedures", "constraints", "open_loops", "conflicts", "unknowns"] as const;

function parseSections(value: unknown): PackSections {
  const parsed = object(value, "ContextPack sections");
  exact(parsed, "raw_observations" in parsed ? [...sectionKeys, "raw_observations"] : sectionKeys, "ContextPack sections");
  const result = {} as Record<(typeof sectionKeys)[number], readonly ContextBlock[]>;
  for (const key of sectionKeys) result[key] = array(parsed[key], `sections.${key}`, parseContextBlock);
  return "raw_observations" in parsed ? { ...result, raw_observations: array(parsed.raw_observations, "sections.raw_observations", parseContextBlock) } : result;
}

function parseEvidenceSelector(value: unknown): EvidenceSelector {
  const parsed = object(value, "evidence selector");
  const kind = text(parsed.kind, "evidence selector kind");
  if (kind === "text_bytes" || kind === "lines" || kind === "time_micros") {
    exact(parsed, ["kind", "start", "end"], "evidence selector");
    return { kind, start: uint(parsed.start, "selector start"), end: uint(parsed.end, "selector end") };
  }
  if (kind === "json_pointer") {
    exact(parsed, ["kind", "pointer"], "evidence selector");
    return { kind, pointer: text(parsed.pointer, "selector pointer") };
  }
  if (kind === "whole") {
    exact(parsed, ["kind"], "evidence selector");
    return { kind };
  }
  throw new ProtocolError("evidence selector kind is invalid");
}

function parsePackEvidence(value: unknown): PackEvidence {
  const parsed = object(value, "pack evidence");
  const keys = ["id", "source", "selector", "excerpt", "claim_ids", "provenance_family", "primary", "trust_micros", "source_class", "taints", "lineage"];
  if ("original_span" in parsed) keys.push("original_span");
  exact(parsed, keys, "pack evidence");
  const selector = parseEvidenceSelector(parsed.selector);
  const excerpt = nullableText(parsed.excerpt, "evidence excerpt");
  const span = "original_span" in parsed ? parseOriginalSpan(parsed.original_span) : undefined;
  if (span !== undefined) {
    const bytes = new TextEncoder().encode(excerpt ?? "");
    if (excerpt === null || bytes.length !== span.end - span.start || bytesToHex(blake3(bytes)) !== span.span_digest ||
      (selector.kind !== "text_bytes" || selector.start !== span.start || selector.end !== span.end)) {
      throw new ProtocolError("original span differs from exact evidence bytes/selector");
    }
  }
  return {
    id: text(parsed.id, "evidence id"),
    source: text(parsed.source, "evidence source"),
    selector,
    excerpt,
    claim_ids: strings(parsed.claim_ids, "evidence claim ids"),
    provenance_family: text(parsed.provenance_family, "provenance family"),
    primary: bool(parsed.primary, "primary"),
    trust_micros: uint(parsed.trust_micros, "trust_micros", 0xffff_ffff),
    source_class: other(parsed.source_class, "source class", sourceClasses) as SourceClass,
    taints: array(parsed.taints, "evidence taints", (item) => other(item, "content taint", taintKinds) as ContentTaint),
    lineage: strings(parsed.lineage, "evidence lineage"),
    ...(span === undefined ? {} : { original_span: span }),
  };
}

function parseOriginalSpan(value: unknown): OriginalSourceSpan {
  const parsed = object(value, "original span");
  exact(parsed, ["event_id", "payload_digest", "start", "end", "span_digest"], "original span");
  const span = { event_id: text(parsed.event_id, "event id"), payload_digest: text(parsed.payload_digest, "payload digest"),
    start: uint(parsed.start, "span start"), end: uint(parsed.end, "span end"), span_digest: text(parsed.span_digest, "span digest") };
  if (span.end <= span.start || !/^[0-9a-f]{64}$/.test(span.payload_digest) || !/^[0-9a-f]{64}$/.test(span.span_digest)) {
    throw new ProtocolError("invalid exact original span");
  }
  return span;
}

function parseUseDirective(value: unknown): UseDirective {
  const parsed = object(value, "use directive");
  exact(parsed, ["block_id", "action", "reason_code"], "use directive");
  return {
    block_id: text(parsed.block_id, "directive block"),
    action: enumValue(parsed.action, "use action", useActions),
    reason_code: enumValue(parsed.reason_code, "directive reason", directiveReasons),
  };
}

function parseScopeManifest(value: unknown): ScopeManifest {
  const parsed = object(value, "scope manifest");
  exact(parsed, ["workspace", "subject", "scopes", "purpose", "temporal_view", "filter_digest"], "scope manifest");
  return {
    workspace: text(parsed.workspace, "scope workspace"),
    subject: text(parsed.subject, "scope subject"),
    scopes: strings(parsed.scopes, "scope list"),
    purpose: enumValue(parsed.purpose, "pack purpose", packPurposes),
    temporal_view: parseTemporal(parsed.temporal_view),
    filter_digest: text(parsed.filter_digest, "filter digest"),
  };
}

function parseGraphManifest(value: unknown): GraphManifest {
  const parsed = object(value, "graph manifest");
  exact(parsed, ["memory_refs", "claim_ids", "conflict_sets"], "graph manifest");
  return {
    memory_refs: array(parsed.memory_refs, "graph memory refs", parseMemoryRef),
    claim_ids: strings(parsed.claim_ids, "graph claims"),
    conflict_sets: strings(parsed.conflict_sets, "graph conflicts"),
  };
}

function parseBlockProvenance(value: unknown): BlockProvenance {
  const parsed = object(value, "block provenance");
  exact(parsed, ["block_id", "memory_refs", "evidence_handles", "source_classes"], "block provenance");
  return {
    block_id: text(parsed.block_id, "provenance block"),
    memory_refs: array(parsed.memory_refs, "provenance refs", parseMemoryRef),
    evidence_handles: strings(parsed.evidence_handles, "provenance evidence"),
    source_classes: array(parsed.source_classes, "source classes", (item) => other(item, "source class", sourceClasses) as SourceClass),
  };
}

function parseProvenance(value: unknown): ProvenanceManifest {
  const parsed = object(value, "provenance");
  exact(parsed, ["compiler_version", "policy_filter_digest", "blocks", "evidence_sources"], "provenance");
  return {
    compiler_version: text(parsed.compiler_version, "compiler version"),
    policy_filter_digest: text(parsed.policy_filter_digest, "policy filter digest"),
    blocks: array(parsed.blocks, "provenance blocks", parseBlockProvenance),
    evidence_sources: stringRecord(parsed.evidence_sources, "evidence sources"),
  };
}

function parseFreshness(value: unknown): FreshnessManifest {
  const parsed = object(value, "freshness");
  exact(parsed, ["snapshot", "warnings"], "freshness");
  return { snapshot: parseSnapshot(parsed.snapshot), warnings: strings(parsed.warnings, "freshness warnings") };
}

function parseContextBudgets(value: unknown): ContextBudgets {
  const parsed = object(value, "ContextPack budgets");
  const keys = ["hard_tokens", "soft_tokens", "max_blocks", "max_evidence_blocks", "max_raw_evidence_tokens", "max_history_tokens", "max_conflict_tokens", "max_serialized_bytes", "max_selection_evaluations"] as const;
  exact(parsed, keys, "ContextPack budgets");
  const result = {} as Record<(typeof keys)[number], number>;
  for (const key of keys) result[key] = uint(parsed[key], `context_budgets.${key}`, 0xffff_ffff);
  return result;
}

function parseContextUsage(value: unknown): ContextBudgetUsage {
  const parsed = object(value, "ContextPack usage");
  const keys = ["rendered_tokens", "control_tokens", "data_tokens", "blocks", "evidence_blocks", "raw_evidence_tokens", "history_tokens", "conflict_tokens", "serialized_bytes", "selection_evaluations"] as const;
  exact(parsed, keys, "ContextPack usage");
  const result = {} as Record<(typeof keys)[number], number>;
  for (const key of keys) result[key] = uint(parsed[key], `pack_usage.${key}`, 0xffff_ffff);
  return result;
}

function parseOmission(value: unknown): Omission {
  const parsed = object(value, "omission");
  exact(parsed, ["block_id", "reason"], "omission");
  return { block_id: text(parsed.block_id, "omitted block"), reason: enumValue(parsed.reason, "omission reason", omissionReasons) };
}

function parseSufficiency(value: unknown): PackSufficiencyReport {
  const parsed = object(value, "sufficiency");
  exact(parsed, ["sufficient", "covered_facets", "missing_facets", "unresolved_conflicts", "blocking_unknowns", "unsupported_blocks"], "sufficiency");
  return {
    sufficient: bool(parsed.sufficient, "sufficient"),
    covered_facets: strings(parsed.covered_facets, "covered facets"),
    missing_facets: strings(parsed.missing_facets, "missing facets"),
    unresolved_conflicts: strings(parsed.unresolved_conflicts, "unresolved conflicts"),
    blocking_unknowns: strings(parsed.blocking_unknowns, "blocking unknowns"),
    unsupported_blocks: strings(parsed.unsupported_blocks, "unsupported blocks"),
  };
}

function parseCompilation(value: unknown): CompilationReport {
  const parsed = object(value, "compilation");
  exact(parsed, ["compiler_version", "schema_version", "model_profile", "tokenizer", "renderer", "budget", "usage", "soft_budget_exceeded", "selected_blocks", "omissions", "sufficiency"], "compilation");
  return {
    compiler_version: text(parsed.compiler_version, "compiler version"),
    schema_version: text(parsed.schema_version, "schema version"),
    model_profile: text(parsed.model_profile, "model profile"),
    tokenizer: text(parsed.tokenizer, "tokenizer"),
    renderer: enumValue(parsed.renderer, "renderer", renderers),
    budget: parseContextBudgets(parsed.budget),
    usage: parseContextUsage(parsed.usage),
    soft_budget_exceeded: bool(parsed.soft_budget_exceeded, "soft budget"),
    selected_blocks: strings(parsed.selected_blocks, "selected blocks"),
    omissions: array(parsed.omissions, "omissions", parseOmission),
    sufficiency: parseSufficiency(parsed.sufficiency),
  };
}

function parseNoMemory(value: unknown): NoMemoryResult {
  const parsed = object(value, "no memory");
  exact(parsed, ["reason", "missing_facets"], "no memory");
  return { reason: enumValue(parsed.reason, "no-memory reason", noMemoryReasons), missing_facets: strings(parsed.missing_facets, "missing facets") };
}

function parseContextPack(value: unknown): ContextPack {
  const parsed = object(value, "ContextPack");
  exact(parsed, ["schema_version", "id", "status", "snapshot", "purpose", "scope_manifest", "sections", "evidence", "use_directives", "graph_manifest", "freshness", "provenance", "continuation", "compilation", "no_memory"], "ContextPack");
  const status = enumValue(parsed.status, "pack status", packStatuses);
  let continuation: ContextPackContinuation | null = null;
  if (parsed.continuation !== null) {
    const raw = object(parsed.continuation, "pack continuation");
    exact(raw, ["opaque"], "pack continuation");
    continuation = { opaque: text(raw.opaque, "pack continuation") };
  }
  const noMemory = parsed.no_memory === null ? null : parseNoMemory(parsed.no_memory);
  if ((status === "no_memory") !== (noMemory !== null)) {
    throw new ProtocolError("ContextPack no-memory result does not match its status");
  }
  return {
    schema_version: text(parsed.schema_version, "pack schema"),
    id: text(parsed.id, "pack id"),
    status,
    snapshot: parseSnapshot(parsed.snapshot),
    purpose: enumValue(parsed.purpose, "pack purpose", packPurposes),
    scope_manifest: parseScopeManifest(parsed.scope_manifest),
    sections: parseSections(parsed.sections),
    evidence: array(parsed.evidence, "pack evidence", parsePackEvidence),
    use_directives: array(parsed.use_directives, "use directives", parseUseDirective),
    graph_manifest: parseGraphManifest(parsed.graph_manifest),
    freshness: parseFreshness(parsed.freshness),
    provenance: parseProvenance(parsed.provenance),
    continuation,
    compilation: parseCompilation(parsed.compilation),
    no_memory: noMemory,
  };
}

function parseRendered(value: unknown): RenderedContextPayload {
  const parsed = object(value, "rendered ContextPack");
  exact(parsed, ["profile_id", "renderer", "trusted_control", "untrusted_data", "control_tokens", "data_tokens", "total_tokens"], "rendered ContextPack");
  const controlTokens = uint(parsed.control_tokens, "control tokens", 0xffff_ffff);
  const dataTokens = uint(parsed.data_tokens, "data tokens", 0xffff_ffff);
  const totalTokens = uint(parsed.total_tokens, "total tokens", 0xffff_ffff);
  if (controlTokens + dataTokens !== totalTokens) throw new ProtocolError("rendered ContextPack token totals are inconsistent");
  return {
    profile_id: text(parsed.profile_id, "render profile"),
    renderer: enumValue(parsed.renderer, "renderer", renderers),
    trusted_control: text(parsed.trusted_control, "trusted control"),
    untrusted_data: text(parsed.untrusted_data, "untrusted data"),
    control_tokens: controlTokens,
    data_tokens: dataTokens,
    total_tokens: totalTokens,
  };
}

function parseRecallUsage(value: unknown): RecallBudgetUsage {
  const parsed = object(value, "recall usage");
  exact(parsed, ["nodes_examined", "graph_edges_examined", "max_hop_reached", "evidence_units", "context_tokens"], "recall usage");
  return {
    nodes_examined: uint(parsed.nodes_examined, "nodes examined", 0xffff_ffff),
    graph_edges_examined: uint(parsed.graph_edges_examined, "edges examined", 0xffff_ffff),
    max_hop_reached: uint(parsed.max_hop_reached, "max hop", 0xff),
    evidence_units: uint(parsed.evidence_units, "evidence units", 0xffff_ffff),
    context_tokens: uint(parsed.context_tokens, "context tokens", 0xffff_ffff),
  };
}

function parseTrace(value: unknown): ContextPackTrace {
  const parsed = object(value, "ContextPack trace");
  exact(parsed, ["trace_id", "snapshot", "filter_digest", "recall_status", "stop_reason", "recall_usage", "pack_status", "pack_usage", "selected_blocks", "evidence_blocks", "max_projection_lag_commits", "stale", "freshness_warnings"], "ContextPack trace");
  return {
    trace_id: text(parsed.trace_id, "trace id"),
    snapshot: parseSnapshot(parsed.snapshot),
    filter_digest: text(parsed.filter_digest, "filter digest"),
    recall_status: enumValue(parsed.recall_status, "recall status", recallStatuses),
    stop_reason: enumValue(parsed.stop_reason, "stop reason", stopReasons),
    recall_usage: parseRecallUsage(parsed.recall_usage),
    pack_status: enumValue(parsed.pack_status, "pack status", packStatuses),
    pack_usage: parseContextUsage(parsed.pack_usage),
    selected_blocks: uint(parsed.selected_blocks, "selected blocks", 0xffff_ffff),
    evidence_blocks: uint(parsed.evidence_blocks, "evidence blocks", 0xffff_ffff),
    max_projection_lag_commits: uint(parsed.max_projection_lag_commits, "projection lag"),
    stale: bool(parsed.stale, "stale"),
    freshness_warnings: strings(parsed.freshness_warnings, "freshness warnings"),
  };
}

function sameSnapshot(left: ProviderSnapshot, right: ProviderSnapshot): boolean {
  const sameRecord = (
    first: Readonly<Record<string, number>>,
    second: Readonly<Record<string, number>>,
  ): boolean => {
    const keys = Object.keys(first);
    return keys.length === Object.keys(second).length
      && keys.every((key) => Object.hasOwn(second, key) && first[key] === second[key]);
  };
  return left.database_id === right.database_id
    && left.commit_seq === right.commit_seq
    && left.watermarks.journal === right.watermarks.journal
    && left.watermarks.semantic === right.watermarks.semantic
    && left.watermarks.lexical === right.watermarks.lexical
    && left.watermarks.graph === right.watermarks.graph
    && sameRecord(left.watermarks.vector, right.watermarks.vector)
    && sameRecord(left.watermarks.hierarchy, right.watermarks.hierarchy);
}

/** Parses the full canonical response and rejects unknown fields and unsafe u64 values. */
export function parseCompileContextResponse(value: unknown): CompileContextResponse {
  const parsed = object(value, "compile-context response");
  exact(parsed, ["context_pack", "canonical_encoding", "canonical_bytes", "canonical_digest_algorithm", "canonical_digest", "rendered", "continuation", "trace"], "compile-context response");
  const contextPack = parseContextPack(parsed.context_pack);
  const trace = parseTrace(parsed.trace);
  if (!sameSnapshot(contextPack.snapshot, trace.snapshot)) {
    throw new ProtocolError("ContextPack trace snapshot differs from the canonical pack");
  }
  if (contextPack.status !== trace.pack_status) {
    throw new ProtocolError("ContextPack trace status differs from the canonical pack");
  }
  if (parsed.canonical_encoding !== CONTEXT_PACK_CANONICAL_ENCODING) {
    throw new ProtocolError("unsupported ContextPack canonical encoding");
  }
  if (parsed.canonical_digest_algorithm !== CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM) {
    throw new ProtocolError("unsupported ContextPack canonical digest algorithm");
  }
  const canonicalBytes = octets(parsed.canonical_bytes, "canonical bytes");
  if (canonicalBytes.byteLength !== contextPack.compilation.usage.serialized_bytes) {
    throw new ProtocolError("canonical bytes differ from the ContextPack serialized size");
  }
  return {
    context_pack: contextPack,
    canonical_encoding: CONTEXT_PACK_CANONICAL_ENCODING,
    canonical_bytes: canonicalBytes,
    canonical_digest_algorithm: CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM,
    canonical_digest: digest(parsed.canonical_digest, "canonical digest"),
    rendered: parseRendered(parsed.rendered),
    continuation: nullableText(parsed.continuation, "ContextPack continuation"),
    trace,
  };
}

/** Fails unless the exact returned canonical bytes match the advertised digest. */
export function verifyCanonicalContextDigest(response: CompileContextResponse): void {
  if (response.canonical_encoding !== CONTEXT_PACK_CANONICAL_ENCODING) {
    throw new ProtocolError("unsupported ContextPack canonical encoding");
  }
  if (response.canonical_digest_algorithm !== CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM) {
    throw new ProtocolError("unsupported ContextPack canonical digest algorithm");
  }
  const computed = bytesToHex(blake3(response.canonical_bytes));
  if (computed !== response.canonical_digest) {
    throw new ProtocolError("ContextPack canonical digest mismatch");
  }
}

// Keep the request-side enum sets reachable by compile-time dead-code analysis;
// the client validates the complete request as finite, safe JSON before sending.
void recallModes;
void recallIntents;
void structuredFormats;
void positionProfiles;
void instructionHierarchies;
