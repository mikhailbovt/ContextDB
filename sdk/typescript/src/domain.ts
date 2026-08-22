import { ProtocolError } from "./errors.js";
import type { AccessPolicy, JsonValue, ObserveResponse, RequestContext, Watermarks } from "./types.js";

export type Capability =
  | "observe" | "stream_ingest" | "recall" | "correct" | "forget" | "hard_delete"
  | "read_memory" | "traverse" | "read_evidence" | "read_conflict" | "subscribe"
  | "runtime" | "maintenance" | "admin" | "raw_evidence" | "model_processing";

export type AuthenticationEvidence =
  | {
      readonly kind: "authenticated_channel";
      readonly channel_id: string;
      readonly peer_identity: string;
      readonly binding_digest: string;
    }
  | {
      readonly kind: "request_signature";
      readonly algorithm: string;
      readonly key_id: string;
      readonly signature: string;
      readonly signed_context_digest: string;
    };

/** Application DTO only; it is never converted into gateway headers. */
export interface AuthenticatedRequestContext {
  readonly request: RequestContext;
  readonly actor_id: string;
  readonly agent_id: string;
  readonly session_id: string | null;
  readonly capability_grants: readonly Capability[];
  readonly authentication: AuthenticationEvidence;
}

export type Compression = "identity" | "gzip" | "zstd";

export interface SourceRevisionManifest {
  readonly source_id: string;
  readonly revision_id: string;
  readonly snapshot_id: string;
  readonly expected_items: number;
  readonly ordered_items_digest: string;
  readonly compression: Compression;
  readonly attributes: Readonly<Record<string, string>>;
}

export interface StreamObservation {
  readonly idempotency_key: string;
  readonly observation_id: string;
  readonly metadata: Readonly<Record<string, JsonValue>>;
  readonly content: JsonValue;
  readonly access: AccessPolicy;
}

export interface SnapshotComplete {
  readonly snapshot_id: string;
  readonly item_count: number;
  readonly ordered_items_digest: string;
}

export type IngestFrameValue =
  | { readonly kind: "manifest"; readonly value: SourceRevisionManifest }
  | { readonly kind: "observation"; readonly value: StreamObservation }
  | { readonly kind: "snapshot_complete"; readonly value: SnapshotComplete };

export interface IngestFrame {
  readonly context: AuthenticatedRequestContext;
  readonly stream_id: string;
  readonly position: number;
  readonly resume_cursor: string | null;
  readonly value: IngestFrameValue;
}

export type IngestDisposition = "accepted" | "replayed" | "snapshot_committed";

export interface IngestAck {
  readonly stream_id: string;
  readonly position: number;
  readonly disposition: IngestDisposition;
  readonly frame_digest: string;
  readonly resume_cursor: string;
  readonly commit_seq: number | null;
  readonly partial_result_refs: readonly string[];
  readonly lease_expires_at_ms?: number;
}

export type MemoryEventKind =
  | "node_changed" | "claim_changed" | "open_loop_triggered" | "index_watermark_advanced"
  | "conflict_resolved" | "source_invalidated" | "operation_progress" | "security_event"
  | "observation_accepted" | "record_changed";

export interface SubscribeRequest {
  readonly context: AuthenticatedRequestContext;
  readonly filters: readonly MemoryEventKind[];
  readonly resume_cursor: string | null;
  readonly max_events: number;
}

export interface MemoryEvent {
  readonly event_id: string;
  readonly commit_seq: number;
  readonly ordinal: number;
  readonly kind: MemoryEventKind;
  readonly object_refs: readonly string[];
  readonly attributes: Readonly<Record<string, string>>;
}

export interface SubscriptionPage {
  readonly events: readonly MemoryEvent[];
  readonly resume_cursor: string;
  readonly caught_up: boolean;
}

export type MemoryRecordKind =
  | "node" | "claim" | "edge" | "conflict" | "evidence" | "candidate"
  | "semantic_object" | "runtime_state" | "domain_extension";
export type MemoryLifecycle = "active" | "superseded" | "retracted" | "suppressed";

/** TypeScript intentionally restricts the Rust i128 wire field to safe integers. */
export interface DomainTimeRange {
  readonly from: number | null;
  readonly to: number | null;
}

export interface MemoryLinks {
  readonly subject: string | null;
  readonly source: string | null;
  readonly target: string | null;
  readonly predicate: string | null;
  readonly conflict_set: string | null;
  readonly supersedes: readonly string[];
  readonly evidence: readonly string[];
  readonly conflict_members: readonly string[];
  readonly single_valued: boolean;
}

export interface MemoryDocument {
  readonly id: string;
  readonly kind: MemoryRecordKind;
  readonly access: AccessPolicy;
  readonly valid_time: DomainTimeRange;
  readonly lifecycle: MemoryLifecycle;
  readonly links: MemoryLinks;
  readonly value: JsonValue;
  readonly search_text: string | null;
  readonly vector: readonly number[] | null;
  readonly attributes: Readonly<Record<string, JsonValue>>;
}

export interface MemoryRecord {
  readonly document: MemoryDocument;
  readonly revision: number;
  readonly transaction_from: number;
  readonly transaction_to: number | null;
}

export interface MutationResponse {
  readonly commit_seq: number;
  readonly replayed: boolean;
  readonly request_digest: string;
  readonly watermarks: Watermarks;
}

export interface HighLevelWriteRequest {
  readonly context: AuthenticatedRequestContext;
  readonly idempotency_key: string;
  readonly target_subject_id: string;
  readonly session_id: string | null;
  readonly logical_id: string;
  readonly access: AccessPolicy;
  readonly payload: JsonValue;
  readonly references: readonly string[];
}

export interface HighLevelQueryRequest {
  readonly context: AuthenticatedRequestContext;
  readonly target_subject_id: string;
  readonly cue: string;
  readonly page_size: number;
  readonly at_commit: number | null;
  readonly continuation: string | null;
}

export interface HighLevelControlRequest {
  readonly context: AuthenticatedRequestContext;
  readonly idempotency_key: string;
  readonly target_subject_id: string;
  readonly target_id: string;
  readonly parameters: JsonValue;
}

export interface HighLevelTransferRequest {
  readonly context: AuthenticatedRequestContext;
  readonly idempotency_key: string;
  readonly target_subject_id: string;
  readonly format: string;
  readonly bytes: Uint8Array;
  readonly digest: string;
}

export interface HighLevelMutationResponse {
  readonly operation: string;
  readonly logical_id: string;
  readonly policy_result: "accepted";
  readonly semantic_status: "pending";
  readonly receipt: ObserveResponse;
}

export interface CorrectRequest {
  readonly context: AuthenticatedRequestContext;
  readonly idempotency_key: string;
  readonly target_id: string;
  readonly replacement: MemoryDocument;
}

export type ForgetMode = "retract" | "hard_delete";

export interface ForgetRequest {
  readonly context: AuthenticatedRequestContext;
  readonly idempotency_key: string;
  readonly target_id: string;
  readonly mode: ForgetMode;
  readonly reason: string;
}

export interface GetMemoryRequest {
  readonly context: AuthenticatedRequestContext;
  readonly record_id: string;
  readonly at_commit: number | null;
}

export interface GetTimelineRequest {
  readonly context: AuthenticatedRequestContext;
  readonly record_id: string;
  readonly expected_kind: MemoryRecordKind;
  readonly at_commit: number | null;
  readonly max_revisions: number;
}

export interface TimelineResponse {
  readonly revisions: readonly MemoryRecord[];
  readonly snapshot_seq: number;
  readonly watermarks: Watermarks;
}

export type TraverseDirection = "outgoing" | "incoming" | "both";

export interface TraverseRequest {
  readonly context: AuthenticatedRequestContext;
  readonly start_ids: readonly string[];
  readonly direction: TraverseDirection;
  readonly predicate_ids: readonly string[];
  readonly max_hops: number;
  readonly max_nodes: number;
  readonly at_commit: number | null;
}

export interface TraverseResponse {
  readonly node_ids: readonly string[];
  readonly snapshot_seq: number;
  readonly authorized_candidates: number;
  readonly watermarks: Watermarks;
}

export interface RuntimeRequest {
  readonly context: AuthenticatedRequestContext;
  readonly operation_id: string;
  readonly payload: JsonValue;
}

export interface RuntimeResponse {
  readonly operation_id: string;
  readonly payload: JsonValue;
}

export interface MaintenanceRequest {
  readonly context: AuthenticatedRequestContext;
  readonly operation_id: string;
  readonly payload: JsonValue;
}

export interface MaintenanceResponse {
  readonly operation_id: string;
  readonly payload: JsonValue;
}

export interface GetStatusRequest { readonly context: AuthenticatedRequestContext }
export interface CreateBackupRequest { readonly context: AuthenticatedRequestContext }

export type RuntimeCapabilityState = "available" | "compiled_only" | "unsupported";

/** Stable candidate-only schema-v1 keys; the manifest map remains additive. */
export const CandidateRuntimeCapabilityIdsV1 = [
  "candidate_hierarchy_dag",
  "policy_first_candidate_recall",
  "policy_first_candidate_traversal",
  "quarantined_memory_proposals",
] as const;

export interface CapabilityManifestV1 {
  readonly schema_version: 1;
  readonly profile: string;
  readonly server_v1_release_ready: boolean;
  readonly capabilities: Readonly<Record<string, RuntimeCapabilityState>>;
}

export interface StatusResponse {
  readonly schema_version: number;
  readonly profile: string;
  readonly commit_seq: number;
  readonly watermarks: Watermarks;
  readonly capability_manifest: CapabilityManifestV1;
}

export interface BackupResponse {
  readonly format: string;
  readonly bytes: Uint8Array;
  readonly digest: string;
  readonly commit_seq: number;
}

export interface RestoreBackupRequest {
  readonly context: AuthenticatedRequestContext;
  readonly format: string;
  readonly bytes: Uint8Array;
  readonly digest: string;
}

export interface RestoreBackupResponse {
  readonly commit_seq: number;
  readonly watermarks: Watermarks;
}

export interface MigrateFormatRequest {
  readonly context: AuthenticatedRequestContext;
  readonly target_format: string;
  readonly operation_id: string;
}

type ObjectValue = Record<string, unknown>;

function object(value: unknown, name: string): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolError(`${name} must be an object`);
  }
  return value as ObjectValue;
}

function exact(value: ObjectValue, keys: readonly string[]): void {
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) {
    throw new ProtocolError("response object has missing or unknown fields");
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

function int(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new ProtocolError(`${name} exceeds the safe integer range`);
  }
  return value;
}

function nullableText(value: unknown, name: string): string | null {
  return value === null ? null : text(value, name);
}

function nullableUint(value: unknown, name: string): number | null {
  return value === null ? null : uint(value, name);
}

function strings(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new ProtocolError(`${name} must be a string array`);
  }
  return value as string[];
}

function stringRecord(value: unknown, name: string): Readonly<Record<string, string>> {
  const result = object(value, name);
  if (Object.values(result).some((item) => typeof item !== "string")) {
    throw new ProtocolError(`${name} values must be strings`);
  }
  return result as Record<string, string>;
}

function enumValue<T extends string>(value: unknown, name: string, allowed: readonly T[]): T {
  const result = text(value, name);
  if (!(allowed as readonly string[]).includes(result)) throw new ProtocolError(`${name} is invalid`);
  return result as T;
}

function jsonValue(value: unknown): JsonValue {
  validateJsonValue(value, new Set<object>());
  return value as JsonValue;
}

function validateJsonValue(value: unknown, seen: Set<object>): void {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new ProtocolError("response contains a non-finite or unsafe integer");
    }
    return;
  }
  if (typeof value !== "object" || seen.has(value)) {
    throw new ProtocolError("response contains a non-JSON value");
  }
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) validateJsonValue(item, seen);
  } else {
    for (const item of Object.values(value as ObjectValue)) validateJsonValue(item, seen);
  }
  seen.delete(value);
}

function watermarks(value: unknown): Watermarks {
  const result = object(value, "watermarks");
  exact(result, ["journal", "semantic", "lexical", "vector", "graph"]);
  return {
    journal: uint(result.journal, "watermarks.journal"),
    semantic: uint(result.semantic, "watermarks.semantic"),
    lexical: uint(result.lexical, "watermarks.lexical"),
    vector: uint(result.vector, "watermarks.vector"),
    graph: uint(result.graph, "watermarks.graph"),
  };
}

const memoryKinds = ["node", "claim", "edge", "conflict", "evidence", "candidate", "semantic_object", "runtime_state", "domain_extension"] as const;
const lifecycles = ["active", "superseded", "retracted", "suppressed"] as const;
const eventKinds = ["node_changed", "claim_changed", "open_loop_triggered", "index_watermark_advanced", "conflict_resolved", "source_invalidated", "operation_progress", "security_event", "observation_accepted", "record_changed"] as const;

function accessPolicy(value: unknown): AccessPolicy {
  const result = object(value, "access policy");
  exact(result, ["workspace_id", "scopes", "owners", "audience", "audience_purpose_grants", "purposes", "sensitivity", "consent", "retrievable"]);
  const grantsObject = object(result.audience_purpose_grants, "audience_purpose_grants");
  const grants: Record<string, readonly string[]> = {};
  for (const [key, item] of Object.entries(grantsObject)) grants[key] = strings(item, `audience_purpose_grants.${key}`);
  return {
    workspace_id: text(result.workspace_id, "workspace_id"),
    scopes: strings(result.scopes, "scopes"),
    owners: strings(result.owners, "owners"),
    audience: strings(result.audience, "audience"),
    audience_purpose_grants: grants,
    purposes: strings(result.purposes, "purposes"),
    sensitivity: enumValue(result.sensitivity, "sensitivity", ["public", "internal", "private", "restricted"]),
    consent: enumValue(result.consent, "consent", ["granted", "unknown", "denied"]),
    retrievable: bool(result.retrievable, "retrievable"),
  };
}

function links(value: unknown): MemoryLinks {
  const result = object(value, "memory links");
  exact(result, ["subject", "source", "target", "predicate", "conflict_set", "supersedes", "evidence", "conflict_members", "single_valued"]);
  return {
    subject: nullableText(result.subject, "links.subject"),
    source: nullableText(result.source, "links.source"),
    target: nullableText(result.target, "links.target"),
    predicate: nullableText(result.predicate, "links.predicate"),
    conflict_set: nullableText(result.conflict_set, "links.conflict_set"),
    supersedes: strings(result.supersedes, "links.supersedes"),
    evidence: strings(result.evidence, "links.evidence"),
    conflict_members: strings(result.conflict_members, "links.conflict_members"),
    single_valued: bool(result.single_valued, "links.single_valued"),
  };
}

function document(value: unknown): MemoryDocument {
  const result = object(value, "memory document");
  exact(result, ["id", "kind", "access", "valid_time", "lifecycle", "links", "value", "search_text", "vector", "attributes"]);
  const time = object(result.valid_time, "valid_time");
  exact(time, ["from", "to"]);
  const vector = result.vector;
  let parsedVector: readonly number[] | null = null;
  if (vector !== null) {
    if (!Array.isArray(vector) || vector.some((item) => typeof item !== "number" || !Number.isFinite(item) || Math.abs(item) > 3.4028235e38)) {
      throw new ProtocolError("vector must contain finite f32 values");
    }
    parsedVector = vector as number[];
  }
  return {
    id: text(result.id, "memory id"),
    kind: enumValue(result.kind, "memory kind", memoryKinds),
    access: accessPolicy(result.access),
    valid_time: { from: time.from === null ? null : int(time.from, "valid_time.from"), to: time.to === null ? null : int(time.to, "valid_time.to") },
    lifecycle: enumValue(result.lifecycle, "memory lifecycle", lifecycles),
    links: links(result.links),
    value: jsonValue(result.value),
    search_text: nullableText(result.search_text, "search_text"),
    vector: parsedVector,
    attributes: jsonValue(object(result.attributes, "attributes")) as Readonly<Record<string, JsonValue>>,
  };
}

export function parseMemoryRecord(value: unknown): MemoryRecord {
  const result = object(value, "memory record");
  exact(result, ["document", "revision", "transaction_from", "transaction_to"]);
  return {
    document: document(result.document),
    revision: uint(result.revision, "revision", 0xffff_ffff),
    transaction_from: uint(result.transaction_from, "transaction_from"),
    transaction_to: nullableUint(result.transaction_to, "transaction_to"),
  };
}

export function parseMutationResponse(value: unknown): MutationResponse {
  const result = object(value, "mutation response");
  exact(result, ["commit_seq", "replayed", "request_digest", "watermarks"]);
  return { commit_seq: uint(result.commit_seq, "commit_seq"), replayed: bool(result.replayed, "replayed"), request_digest: text(result.request_digest, "request_digest"), watermarks: watermarks(result.watermarks) };
}

export function parseHighLevelMutationResponse(value: unknown): HighLevelMutationResponse {
  const result = object(value, "high-level mutation response");
  exact(result, ["operation", "logical_id", "policy_result", "semantic_status", "receipt"]);
  if (result.policy_result !== "accepted" || result.semantic_status !== "pending") {
    throw new ProtocolError("invalid high-level mutation state");
  }
  const receipt = object(result.receipt, "high-level mutation receipt");
  exact(receipt, ["commit_seq", "replayed", "request_digest", "watermarks"]);
  return {
    operation: text(result.operation, "operation"),
    logical_id: text(result.logical_id, "logical_id"),
    policy_result: "accepted",
    semantic_status: "pending",
    receipt: {
      commit_seq: uint(receipt.commit_seq, "commit_seq"),
      replayed: bool(receipt.replayed, "replayed"),
      request_digest: text(receipt.request_digest, "request_digest"),
      watermarks: watermarks(receipt.watermarks),
    },
  };
}

export function parseIngestAck(value: unknown): IngestAck {
  const result = object(value, "ingest acknowledgement");
  const required = ["stream_id", "position", "disposition", "frame_digest", "resume_cursor", "commit_seq", "partial_result_refs"];
  const allowed = new Set([...required, "lease_expires_at_ms"]);
  if (required.some((key) => !Object.hasOwn(result, key)) || Object.keys(result).some((key) => !allowed.has(key))) {
    throw new ProtocolError("response object has missing or unknown fields");
  }
  const acknowledgement: IngestAck = {
    stream_id: text(result.stream_id, "stream_id"), position: uint(result.position, "position"),
    disposition: enumValue(result.disposition, "disposition", ["accepted", "replayed", "snapshot_committed"]),
    frame_digest: text(result.frame_digest, "frame_digest"), resume_cursor: text(result.resume_cursor, "resume_cursor"),
    commit_seq: nullableUint(result.commit_seq, "commit_seq"), partial_result_refs: strings(result.partial_result_refs, "partial_result_refs"),
  };
  return Object.hasOwn(result, "lease_expires_at_ms")
    ? { ...acknowledgement, lease_expires_at_ms: uint(result.lease_expires_at_ms, "lease_expires_at_ms") }
    : acknowledgement;
}

export function parseSubscriptionPage(value: unknown): SubscriptionPage {
  const result = object(value, "subscription page");
  exact(result, ["events", "resume_cursor", "caught_up"]);
  if (!Array.isArray(result.events)) throw new ProtocolError("events must be an array");
  return {
    events: result.events.map((item): MemoryEvent => {
      const event = object(item, "memory event");
      exact(event, ["event_id", "commit_seq", "ordinal", "kind", "object_refs", "attributes"]);
      return { event_id: text(event.event_id, "event_id"), commit_seq: uint(event.commit_seq, "commit_seq"), ordinal: uint(event.ordinal, "ordinal", 0xffff_ffff), kind: enumValue(event.kind, "event kind", eventKinds), object_refs: strings(event.object_refs, "object_refs"), attributes: stringRecord(event.attributes, "event attributes") };
    }),
    resume_cursor: text(result.resume_cursor, "resume_cursor"), caught_up: bool(result.caught_up, "caught_up"),
  };
}

export function parseTraverseResponse(value: unknown): TraverseResponse {
  const result = object(value, "traverse response");
  exact(result, ["node_ids", "snapshot_seq", "authorized_candidates", "watermarks"]);
  return { node_ids: strings(result.node_ids, "node_ids"), snapshot_seq: uint(result.snapshot_seq, "snapshot_seq"), authorized_candidates: uint(result.authorized_candidates, "authorized_candidates"), watermarks: watermarks(result.watermarks) };
}

export function parseTimelineResponse(value: unknown): TimelineResponse {
  const result = object(value, "timeline response");
  exact(result, ["revisions", "snapshot_seq", "watermarks"]);
  if (!Array.isArray(result.revisions)) throw new ProtocolError("revisions must be an array");
  return { revisions: result.revisions.map(parseMemoryRecord), snapshot_seq: uint(result.snapshot_seq, "snapshot_seq"), watermarks: watermarks(result.watermarks) };
}

export function parseRuntimeResponse(value: unknown): RuntimeResponse {
  const result = object(value, "runtime response");
  exact(result, ["operation_id", "payload"]);
  return { operation_id: text(result.operation_id, "operation_id"), payload: jsonValue(result.payload) };
}

export function parseMaintenanceResponse(value: unknown): MaintenanceResponse {
  const result = parseRuntimeResponse(value);
  return result;
}

export function parseStatusResponse(value: unknown): StatusResponse {
  const result = object(value, "status response");
  exact(result, ["schema_version", "profile", "commit_seq", "watermarks", "capability_manifest"]);
  const profile = text(result.profile, "profile");
  const manifest = capabilityManifest(result.capability_manifest);
  if (manifest.profile !== profile) throw new ProtocolError("status profile does not match capability manifest profile");
  return { schema_version: uint(result.schema_version, "schema_version", 0xffff), profile, commit_seq: uint(result.commit_seq, "commit_seq"), watermarks: watermarks(result.watermarks), capability_manifest: manifest };
}

function capabilityManifest(value: unknown): CapabilityManifestV1 {
  const result = object(value, "capability manifest");
  exact(result, ["schema_version", "profile", "server_v1_release_ready", "capabilities"]);
  const schemaVersion = uint(result.schema_version, "capability manifest schema_version", 0xffff);
  if (schemaVersion !== 1) throw new ProtocolError("unsupported capability manifest schema_version");
  const rawCapabilities = object(result.capabilities, "capability manifest capabilities");
  const capabilities: Record<string, RuntimeCapabilityState> = {};
  for (const [capability, state] of Object.entries(rawCapabilities)) {
    capabilities[capability] = enumValue(state, `capability state for ${capability}`, ["available", "compiled_only", "unsupported"]);
  }
  return {
    schema_version: 1,
    profile: text(result.profile, "capability manifest profile"),
    server_v1_release_ready: bool(result.server_v1_release_ready, "server_v1_release_ready"),
    capabilities,
  };
}

function octets(value: unknown): Uint8Array {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "number" || !Number.isInteger(item) || item < 0 || item > 255)) {
    throw new ProtocolError("archive bytes must be an octet array");
  }
  return Uint8Array.from(value as number[]);
}

export function parseBackupResponse(value: unknown): BackupResponse {
  const result = object(value, "backup response");
  exact(result, ["format", "bytes", "digest", "commit_seq"]);
  return { format: text(result.format, "backup format"), bytes: octets(result.bytes), digest: text(result.digest, "backup digest"), commit_seq: uint(result.commit_seq, "commit_seq") };
}

export function parseRestoreBackupResponse(value: unknown): RestoreBackupResponse {
  const result = object(value, "restore response");
  exact(result, ["commit_seq", "watermarks"]);
  return { commit_seq: uint(result.commit_seq, "commit_seq"), watermarks: watermarks(result.watermarks) };
}
