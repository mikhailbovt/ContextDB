import { ContextDbError, ErrorCodes, ProtocolError, TransportError, type ErrorCode } from "./errors.js";
import {
  parseCompileContextResponse,
  type CompileContextRequest,
  type CompileContextResponse,
} from "./context_pack.js";
import {
  parseBackupResponse,
  parseIngestAck,
  parseHighLevelMutationResponse,
  parseMaintenanceResponse,
  parseMemoryRecord,
  parseMutationResponse,
  parseRestoreBackupResponse,
  parseRuntimeResponse,
  parseStatusResponse,
  parseSubscriptionPage,
  parseTimelineResponse,
  parseTraverseResponse,
  type BackupResponse,
  type CorrectRequest,
  type CreateBackupRequest,
  type ForgetRequest,
  type GetMemoryRequest,
  type GetStatusRequest,
  type GetTimelineRequest,
  type HighLevelControlRequest,
  type HighLevelMutationResponse,
  type HighLevelQueryRequest,
  type HighLevelTransferRequest,
  type HighLevelWriteRequest,
  type IngestAck,
  type IngestFrame,
  type MaintenanceRequest,
  type MaintenanceResponse,
  type MemoryRecord,
  type MigrateFormatRequest,
  type MutationResponse,
  type RestoreBackupRequest,
  type RestoreBackupResponse,
  type RuntimeRequest,
  type RuntimeResponse,
  type StatusResponse,
  type SubscribeRequest,
  type SubscriptionPage,
  type TimelineResponse,
  type TraverseRequest,
  type TraverseResponse,
} from "./domain.js";
import type {
  ExplainRecallRequest,
  ExportRequest,
  ExportResponse,
  ImportRequest,
  ImportResponse,
  ObserveRequest,
  ObserveResponse,
  RecallHit,
  RecallRequest,
  RecallResponse,
  RecallTrace,
  RequestOptions,
  VerifyRequest,
  VerifyResponse,
  Watermarks,
} from "./types.js";

export const MAX_WIRE_BYTES = 16 * 1024 * 1024;
export const Routes = {
  observe: "/v1/observations",
  ingestFrame: "/v1/observations/ingest-frame",
  correct: "/v1/observations/correct",
  forget: "/v1/observations/forget",
  recall: "/v1/recall",
  compileContext: "/v1/context-pack",
  explainRecall: "/v1/recall/explain",
  subscribe: "/v1/subscriptions/page",
  getNode: "/v1/memory/node",
  traverse: "/v1/memory/traverse",
  getTimeline: "/v1/memory/timeline",
  getEvidence: "/v1/memory/evidence",
  getConflict: "/v1/memory/conflict",
  bootstrap: "/v1/runtime/bootstrap",
  preflight: "/v1/runtime/preflight",
  postflight: "/v1/runtime/postflight",
  checkpoint: "/v1/runtime/checkpoint",
  resume: "/v1/runtime/resume",
  handoff: "/v1/runtime/handoff",
  consolidate: "/v1/maintenance/consolidate",
  reflect: "/v1/maintenance/reflect",
  reindex: "/v1/maintenance/reindex",
  compact: "/v1/maintenance/compact",
  getStatus: "/v1/admin/status",
  createBackup: "/v1/admin/backup",
  restoreBackup: "/v1/admin/restore",
  migrateFormat: "/v1/admin/migrate",
  exportArchive: "/v1/archive/export",
  importArchive: "/v1/archive/import",
  verify: "/v1/verify",
  beginSession: "/v1/conversation/begin-session",
  beforeTurn: "/v1/conversation/before-turn",
  afterTurn: "/v1/conversation/after-turn",
  resolveReferent: "/v1/conversation/resolve-referent",
  recallSharedHistory: "/v1/conversation/recall-shared-history",
  endSession: "/v1/conversation/end-session",
  bootstrapSubject: "/v1/conversation/bootstrap-subject",
  remember: "/v1/memory/remember",
  pin: "/v1/memory/pin",
  suppress: "/v1/memory/suppress",
  changeAudience: "/v1/memory/change-audience",
  changeRetention: "/v1/memory/change-retention",
  explainMemory: "/v1/memory/explain",
  listSubjectMemories: "/v1/memory/list-subject",
  exportSubject: "/v1/memory/export-subject",
  importSubject: "/v1/memory/import-subject",
  createMemorySubject: "/v1/subjects/create",
  createRelationshipSpace: "/v1/relationship-spaces/create",
  getContinuityProfile: "/v1/subjects/continuity-profile",
  updateConfiguredRole: "/v1/subjects/configured-role/update",
  migrateAgentRuntime: "/v1/subjects/agent-runtime/migrate",
  publishToSharedMemory: "/v1/shared-memory/publish",
  revokeSharedMemory: "/v1/shared-memory/revoke",
  ingestArtifact: "/v1/artifacts/ingest",
  attachArtifactToEpisode: "/v1/artifacts/attach-to-episode",
  addDerivedRepresentation: "/v1/artifacts/derived-representations",
  addEvidenceSelector: "/v1/artifacts/evidence-selectors",
  getArtifactMetadata: "/v1/artifacts/metadata",
  deleteArtifactLineage: "/v1/artifacts/delete-lineage",
} as const;

export interface HeaderProviderRequest {
  readonly path: string;
  readonly body: string;
  readonly signal?: AbortSignal;
}

/** Per-request deployment seam for ephemeral gateway ID/attestation headers. */
export type HeaderProvider = (
  request: HeaderProviderRequest,
) => HeadersInit | Promise<HeadersInit>;

export interface ClientOptions {
  readonly fetch?: typeof globalThis.fetch;
  readonly headers?: HeadersInit;
  readonly bearerToken?: string;
  readonly maxWireBytes?: number;
  readonly headerProvider?: HeaderProvider;
}

type RecordValue = Record<string, unknown>;
type Parser<T> = (value: unknown) => T;

export const ErrorStatusByCode: Readonly<Record<ErrorCode, number>> = {
  [ErrorCodes.InvalidScope]: 400,
  [ErrorCodes.Unauthorized]: 403,
  [ErrorCodes.AmbiguousIdentity]: 400,
  [ErrorCodes.SnapshotExpired]: 410,
  [ErrorCodes.IndexTooStale]: 409,
  [ErrorCodes.EvidenceRequired]: 400,
  [ErrorCodes.ConflictUnresolved]: 409,
  [ErrorCodes.BudgetExhausted]: 413,
  [ErrorCodes.ContinuationExpired]: 410,
  [ErrorCodes.FormatIncompatible]: 422,
  [ErrorCodes.ProviderUnavailable]: 503,
  [ErrorCodes.DegradedMode]: 206,
  [ErrorCodes.InvalidArgument]: 400,
  [ErrorCodes.PermissionDenied]: 403,
  [ErrorCodes.NotFound]: 404,
  [ErrorCodes.IdempotencyConflict]: 409,
  [ErrorCodes.InvalidContinuation]: 400,
  [ErrorCodes.IntegrityFailure]: 422,
  [ErrorCodes.Unavailable]: 503,
  [ErrorCodes.ResourceExhausted]: 413,
  [ErrorCodes.Unsupported]: 501,
};

const errorCodes = new Set<string>(Object.values(ErrorCodes));

function record(value: unknown, name: string): RecordValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolError(`${name} must be an object`);
  }
  return value as RecordValue;
}

function exactKeys(value: RecordValue, required: readonly string[], optional: readonly string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.hasOwn(value, key)) {
      throw new ProtocolError("response object has missing or unknown fields");
    }
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new ProtocolError("response object has missing or unknown fields");
    }
  }
}

function stringValue(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new ProtocolError(`${name} must be a string`);
  }
  return value;
}

function booleanValue(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") {
    throw new ProtocolError(`${name} must be a boolean`);
  }
  return value;
}

function safeUint(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ProtocolError(`${name} exceeds JavaScript's safe unsigned integer range`);
  }
  return value;
}

function finiteNumber(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || Math.abs(value) > 3.4028235e38) {
    throw new ProtocolError(`${name} must be a finite f32 value`);
  }
  return value;
}

function stringArray(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new ProtocolError(`${name} must be a string array`);
  }
  return value as string[];
}

function nullableString(value: unknown, name: string): string | null {
  if (value !== null && typeof value !== "string") {
    throw new ProtocolError(`${name} must be a string or null`);
  }
  return value as string | null;
}

function parseWatermarks(value: unknown): Watermarks {
  const object = record(value, "watermarks");
  exactKeys(object, ["journal", "semantic", "lexical", "vector", "graph"]);
  return {
    journal: safeUint(object.journal, "watermarks.journal"),
    semantic: safeUint(object.semantic, "watermarks.semantic"),
    lexical: safeUint(object.lexical, "watermarks.lexical"),
    vector: safeUint(object.vector, "watermarks.vector"),
    graph: safeUint(object.graph, "watermarks.graph"),
  };
}

function parseObserveResponse(value: unknown): ObserveResponse {
  const object = record(value, "observe response");
  exactKeys(object, ["commit_seq", "replayed", "request_digest", "watermarks"]);
  return {
    commit_seq: safeUint(object.commit_seq, "commit_seq"),
    replayed: booleanValue(object.replayed, "replayed"),
    request_digest: stringValue(object.request_digest, "request_digest"),
    watermarks: parseWatermarks(object.watermarks),
  };
}

function parseRecallHit(value: unknown): RecallHit {
  const object = record(value, "recall hit");
  exactKeys(object, ["id", "score"]);
  return {
    id: stringValue(object.id, "recall hit id"),
    score: finiteNumber(object.score, "recall hit score"),
  };
}

function parseRecallTrace(value: unknown): RecallTrace {
  const object = record(value, "recall trace");
  exactKeys(object, [
    "trace_id",
    "snapshot_seq",
    "operation",
    "authorized_candidates",
    "selected_ids",
    "watermarks",
  ]);
  return {
    trace_id: stringValue(object.trace_id, "trace_id"),
    snapshot_seq: safeUint(object.snapshot_seq, "snapshot_seq"),
    operation: stringValue(object.operation, "operation"),
    authorized_candidates: safeUint(object.authorized_candidates, "authorized_candidates"),
    selected_ids: stringArray(object.selected_ids, "selected_ids"),
    watermarks: parseWatermarks(object.watermarks),
  };
}

function parseRecallResponse(value: unknown): RecallResponse {
  const object = record(value, "recall response");
  exactKeys(object, ["hits", "trace", "continuation"]);
  if (!Array.isArray(object.hits)) {
    throw new ProtocolError("hits must be an array");
  }
  return {
    hits: object.hits.map(parseRecallHit),
    trace: parseRecallTrace(object.trace),
    continuation: nullableString(object.continuation, "continuation"),
  };
}

function parseExportResponse(value: unknown): ExportResponse {
  const object = record(value, "export response");
  exactKeys(object, ["format", "bytes", "digest", "commit_seq"]);
  if (
    !Array.isArray(object.bytes) ||
    object.bytes.some(
      (item) => typeof item !== "number" || !Number.isInteger(item) || item < 0 || item > 255,
    )
  ) {
    throw new ProtocolError("archive bytes must be an octet array");
  }
  return {
    format: stringValue(object.format, "archive format"),
    bytes: Uint8Array.from(object.bytes as number[]),
    digest: stringValue(object.digest, "archive digest"),
    commit_seq: safeUint(object.commit_seq, "commit_seq"),
  };
}

function parseImportResponse(value: unknown): ImportResponse {
  const object = record(value, "import response");
  exactKeys(object, ["commit_seq", "watermarks"]);
  return {
    commit_seq: safeUint(object.commit_seq, "commit_seq"),
    watermarks: parseWatermarks(object.watermarks),
  };
}

function parseVerifyResponse(value: unknown): VerifyResponse {
  const object = record(value, "verify response");
  exactKeys(object, ["valid", "commit_seq", "archive_digest"]);
  return {
    valid: booleanValue(object.valid, "valid"),
    commit_seq: safeUint(object.commit_seq, "commit_seq"),
    archive_digest: nullableString(object.archive_digest, "archive_digest"),
  };
}

function parseServiceError(value: unknown, status: number): ContextDbError {
  const object = record(value, "ContextDB error envelope");
  exactKeys(
    object,
    ["code", "message", "retryable"],
    ["partial_result_refs", "violated_policy", "safe_next_action", "trace_id"],
  );
  const code = stringValue(object.code, "error code");
  if (!errorCodes.has(code) || ErrorStatusByCode[code as ErrorCode] !== status) {
    throw new ProtocolError("error code and HTTP status disagree", status);
  }
  const refs = Object.hasOwn(object, "partial_result_refs")
    ? stringArray(object.partial_result_refs, "partial_result_refs")
    : [];
  const optionalString = (key: string): string | null =>
    Object.hasOwn(object, key) ? nullableString(object[key], key) : null;
  return new ContextDbError({
    code: code as ErrorCode,
    message: stringValue(object.message, "error message"),
    retryable: booleanValue(object.retryable, "retryable"),
    status,
    partialResultRefs: refs,
    violatedPolicy: optionalString("violated_policy"),
    safeNextAction: optionalString("safe_next_action"),
    traceId: optionalString("trace_id"),
  });
}

function assertSafeJson(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new ProtocolError("request contains a non-finite or unsafe integer");
    }
    return;
  }
  if (typeof value !== "object") {
    throw new ProtocolError("request contains a non-JSON value");
  }
  if (seen.has(value)) throw new ProtocolError("request contains a cycle");
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) assertSafeJson(item, seen);
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new ProtocolError("request contains a non-JSON object");
    }
    for (const item of Object.values(value as RecordValue)) assertSafeJson(item, seen);
  }
  seen.delete(value);
}

async function readBounded(response: Response, maxWireBytes: number): Promise<unknown> {
  const contentLength = response.headers.get("Content-Length");
  if (contentLength !== null) {
    const length = Number(contentLength);
    if (Number.isFinite(length) && length > maxWireBytes) {
      throw new ProtocolError("response exceeds the configured wire limit", response.status);
    }
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (response.body !== null) {
    const reader = response.body.getReader();
    try {
      while (true) {
        const result = await reader.read();
        if (result.done) break;
        total += result.value.byteLength;
        if (total > maxWireBytes) {
          await reader.cancel().catch(() => undefined);
          throw new ProtocolError("response exceeds the configured wire limit", response.status);
        }
        chunks.push(result.value);
      }
    } finally {
      reader.releaseLock();
    }
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new ProtocolError(`response is not valid UTF-8: ${String(error)}`, response.status);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new ProtocolError(`response is not valid JSON: ${String(error)}`, response.status);
  }
}

// ContextDbClient is a dependency-light, native-fetch v1 HTTP client.
export class ContextDbClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly headers: Headers;
  private readonly maxWireBytes: number;
  private readonly headerProvider: HeaderProvider | undefined;

  constructor(baseUrl: string, options: ClientOptions = {}) {
    let parsed: URL;
    try {
      parsed = new URL(baseUrl);
    } catch {
      throw new TypeError("baseUrl must be an absolute http(s) URL");
    }
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.search !== "" ||
      parsed.hash !== ""
    ) {
      throw new TypeError("baseUrl must be http(s) without credentials, query, or fragment");
    }
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new TypeError("a native-compatible fetch implementation is required");
    }
    const maxWireBytes = options.maxWireBytes ?? MAX_WIRE_BYTES;
    if (!Number.isSafeInteger(maxWireBytes) || maxWireBytes <= 0) {
      throw new TypeError("maxWireBytes must be a positive safe integer");
    }
    if (options.bearerToken?.includes("\r") || options.bearerToken?.includes("\n")) {
      throw new TypeError("bearerToken contains a newline");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.fetchImpl = fetchImpl;
    this.headers = new Headers(options.headers);
    for (const forbidden of ["host", "content-length", "transfer-encoding"]) {
      if (this.headers.has(forbidden)) {
        throw new TypeError(`deployment headers must not set ${forbidden}`);
      }
    }
    if (this.headers.has("x-contextdb-gateway-attestation")) {
      throw new TypeError("gateway attestation must be supplied by headerProvider");
    }
    if (options.bearerToken !== undefined && options.bearerToken !== "") {
      this.headers.set("Authorization", `Bearer ${options.bearerToken}`);
    }
    this.headers.set("Accept", "application/json");
    this.headers.set("Content-Type", "application/json");
    this.maxWireBytes = maxWireBytes;
    this.headerProvider = options.headerProvider;
  }

  observe(request: ObserveRequest, options: RequestOptions = {}): Promise<ObserveResponse> {
    return this.post(Routes.observe, request, parseObserveResponse, options);
  }

  ingestFrame(request: IngestFrame, options: RequestOptions = {}): Promise<IngestAck> {
    return this.post(Routes.ingestFrame, request, parseIngestAck, options);
  }

  correct(request: CorrectRequest, options: RequestOptions = {}): Promise<MutationResponse> {
    return this.post(Routes.correct, request, parseMutationResponse, options);
  }

  forget(request: ForgetRequest, options: RequestOptions = {}): Promise<MutationResponse> {
    return this.post(Routes.forget, request, parseMutationResponse, options);
  }

  recall(request: RecallRequest, options: RequestOptions = {}): Promise<RecallResponse> {
    return this.post(Routes.recall, request, parseRecallResponse, options);
  }

  compileContext(request: CompileContextRequest, options: RequestOptions = {}): Promise<CompileContextResponse> {
    return this.post(Routes.compileContext, request, parseCompileContextResponse, options);
  }

  explainRecall(request: ExplainRecallRequest, options: RequestOptions = {}): Promise<RecallTrace> {
    return this.post(Routes.explainRecall, request, parseRecallTrace, options);
  }

  subscribe(request: SubscribeRequest, options: RequestOptions = {}): Promise<SubscriptionPage> {
    return this.post(Routes.subscribe, request, parseSubscriptionPage, options);
  }

  getNode(request: GetMemoryRequest, options: RequestOptions = {}): Promise<MemoryRecord> {
    return this.post(Routes.getNode, request, parseMemoryRecord, options);
  }

  traverse(request: TraverseRequest, options: RequestOptions = {}): Promise<TraverseResponse> {
    return this.post(Routes.traverse, request, parseTraverseResponse, options);
  }

  getTimeline(request: GetTimelineRequest, options: RequestOptions = {}): Promise<TimelineResponse> {
    return this.post(Routes.getTimeline, request, parseTimelineResponse, options);
  }

  getEvidence(request: GetMemoryRequest, options: RequestOptions = {}): Promise<MemoryRecord> {
    return this.post(Routes.getEvidence, request, parseMemoryRecord, options);
  }

  getConflict(request: GetMemoryRequest, options: RequestOptions = {}): Promise<MemoryRecord> {
    return this.post(Routes.getConflict, request, parseMemoryRecord, options);
  }

  bootstrap(request: RuntimeRequest, options: RequestOptions = {}): Promise<RuntimeResponse> {
    return this.post(Routes.bootstrap, request, parseRuntimeResponse, options);
  }

  preflight(request: RuntimeRequest, options: RequestOptions = {}): Promise<RuntimeResponse> {
    return this.post(Routes.preflight, request, parseRuntimeResponse, options);
  }

  postflight(request: RuntimeRequest, options: RequestOptions = {}): Promise<RuntimeResponse> {
    return this.post(Routes.postflight, request, parseRuntimeResponse, options);
  }

  checkpoint(request: RuntimeRequest, options: RequestOptions = {}): Promise<RuntimeResponse> {
    return this.post(Routes.checkpoint, request, parseRuntimeResponse, options);
  }

  resume(request: RuntimeRequest, options: RequestOptions = {}): Promise<RuntimeResponse> {
    return this.post(Routes.resume, request, parseRuntimeResponse, options);
  }

  handoff(request: RuntimeRequest, options: RequestOptions = {}): Promise<RuntimeResponse> {
    return this.post(Routes.handoff, request, parseRuntimeResponse, options);
  }

  consolidate(request: MaintenanceRequest, options: RequestOptions = {}): Promise<MaintenanceResponse> {
    return this.post(Routes.consolidate, request, parseMaintenanceResponse, options);
  }

  reflect(request: MaintenanceRequest, options: RequestOptions = {}): Promise<MaintenanceResponse> {
    return this.post(Routes.reflect, request, parseMaintenanceResponse, options);
  }

  reindex(request: MaintenanceRequest, options: RequestOptions = {}): Promise<MaintenanceResponse> {
    return this.post(Routes.reindex, request, parseMaintenanceResponse, options);
  }

  compact(request: MaintenanceRequest, options: RequestOptions = {}): Promise<MaintenanceResponse> {
    return this.post(Routes.compact, request, parseMaintenanceResponse, options);
  }

  getStatus(request: GetStatusRequest, options: RequestOptions = {}): Promise<StatusResponse> {
    return this.post(Routes.getStatus, request, parseStatusResponse, options);
  }

  createBackup(request: CreateBackupRequest, options: RequestOptions = {}): Promise<BackupResponse> {
    return this.post(Routes.createBackup, request, parseBackupResponse, options);
  }

  restoreBackup(request: RestoreBackupRequest, options: RequestOptions = {}): Promise<RestoreBackupResponse> {
    const wire = { ...request, bytes: Array.from(request.bytes) };
    return this.post(Routes.restoreBackup, wire, parseRestoreBackupResponse, options);
  }

  migrateFormat(request: MigrateFormatRequest, options: RequestOptions = {}): Promise<StatusResponse> {
    return this.post(Routes.migrateFormat, request, parseStatusResponse, options);
  }

  exportArchive(request: ExportRequest, options: RequestOptions = {}): Promise<ExportResponse> {
    return this.post(Routes.exportArchive, request, parseExportResponse, options);
  }

  importArchive(request: ImportRequest, options: RequestOptions = {}): Promise<ImportResponse> {
    const wire = { ...request, bytes: Array.from(request.bytes) };
    return this.post(Routes.importArchive, wire, parseImportResponse, options);
  }

  verify(request: VerifyRequest, options: RequestOptions = {}): Promise<VerifyResponse> {
    return this.post(Routes.verify, request, parseVerifyResponse, options);
  }

  private highLevelWrite(path: string, request: HighLevelWriteRequest, options: RequestOptions): Promise<HighLevelMutationResponse> {
    return this.post(path, request, parseHighLevelMutationResponse, options);
  }

  private highLevelQuery(path: string, request: HighLevelQueryRequest, options: RequestOptions): Promise<RecallResponse> {
    return this.post(path, request, parseRecallResponse, options);
  }

  private highLevelControl(path: string, request: HighLevelControlRequest, options: RequestOptions): Promise<MutationResponse> {
    return this.post(path, request, parseMutationResponse, options);
  }

  beginSession(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.beginSession, request, options); }
  beforeTurn(request: HighLevelQueryRequest, options: RequestOptions = {}): Promise<RecallResponse> { return this.highLevelQuery(Routes.beforeTurn, request, options); }
  afterTurn(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.afterTurn, request, options); }
  resolveReferent(request: HighLevelQueryRequest, options: RequestOptions = {}): Promise<RecallResponse> { return this.highLevelQuery(Routes.resolveReferent, request, options); }
  recallSharedHistory(request: HighLevelQueryRequest, options: RequestOptions = {}): Promise<RecallResponse> { return this.highLevelQuery(Routes.recallSharedHistory, request, options); }
  endSession(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.endSession, request, options); }
  bootstrapSubject(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.bootstrapSubject, request, options); }
  remember(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.remember, request, options); }
  pin(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.pin, request, options); }
  suppress(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.suppress, request, options); }
  changeAudience(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.changeAudience, request, options); }
  changeRetention(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.changeRetention, request, options); }
  explainMemory(request: HighLevelQueryRequest, options: RequestOptions = {}): Promise<RecallResponse> { return this.highLevelQuery(Routes.explainMemory, request, options); }
  listSubjectMemories(request: HighLevelQueryRequest, options: RequestOptions = {}): Promise<RecallResponse> { return this.highLevelQuery(Routes.listSubjectMemories, request, options); }
  createMemorySubject(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.createMemorySubject, request, options); }
  createRelationshipSpace(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.createRelationshipSpace, request, options); }
  getContinuityProfile(request: HighLevelQueryRequest, options: RequestOptions = {}): Promise<RecallResponse> { return this.highLevelQuery(Routes.getContinuityProfile, request, options); }
  updateConfiguredRole(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.updateConfiguredRole, request, options); }
  migrateAgentRuntime(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.migrateAgentRuntime, request, options); }
  publishToSharedMemory(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.publishToSharedMemory, request, options); }
  revokeSharedMemory(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.revokeSharedMemory, request, options); }
  ingestArtifact(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.ingestArtifact, request, options); }
  attachArtifactToEpisode(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.attachArtifactToEpisode, request, options); }
  addDerivedRepresentation(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.addDerivedRepresentation, request, options); }
  addEvidenceSelector(request: HighLevelWriteRequest, options: RequestOptions = {}): Promise<HighLevelMutationResponse> { return this.highLevelWrite(Routes.addEvidenceSelector, request, options); }
  getArtifactMetadata(request: HighLevelQueryRequest, options: RequestOptions = {}): Promise<RecallResponse> { return this.highLevelQuery(Routes.getArtifactMetadata, request, options); }
  deleteArtifactLineage(request: HighLevelControlRequest, options: RequestOptions = {}): Promise<MutationResponse> { return this.highLevelControl(Routes.deleteArtifactLineage, request, options); }

  exportSubject(request: HighLevelTransferRequest, options: RequestOptions = {}): Promise<ExportResponse> {
    return this.post(Routes.exportSubject, { ...request, bytes: Array.from(request.bytes) }, parseExportResponse, options);
  }

  importSubject(request: HighLevelTransferRequest, options: RequestOptions = {}): Promise<ImportResponse> {
    return this.post(Routes.importSubject, { ...request, bytes: Array.from(request.bytes) }, parseImportResponse, options);
  }

  private async post<T>(path: string, request: unknown, parser: Parser<T>, options: RequestOptions): Promise<T> {
    assertSafeJson(request);
    const body = JSON.stringify(request);
    if (new TextEncoder().encode(body).byteLength > this.maxWireBytes) {
      throw new ProtocolError("request exceeds the configured wire limit");
    }
    const headers = new Headers(this.headers);
    if (this.headerProvider !== undefined) {
      const providerRequest: HeaderProviderRequest = options.signal === undefined
        ? { path, body }
        : { path, body, signal: options.signal };
      let provided: Headers;
      try {
        provided = new Headers(await this.headerProvider(providerRequest));
      } catch (error) {
        throw new TransportError(error);
      }
      for (const [key, value] of provided) {
        if (["host", "content-length", "transfer-encoding"].includes(key.toLowerCase())) {
          throw new ProtocolError("header provider returned a forbidden framing header");
        }
        headers.set(key, value);
      }
    }
    headers.set("Accept", "application/json");
    headers.set("Content-Type", "application/json");
    const init: RequestInit = {
      method: "POST",
      headers,
      body,
      redirect: "error",
    };
    if (options.signal !== undefined) init.signal = options.signal;
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    } catch (error) {
      throw new TransportError(error);
    }
    const contentType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json") {
      throw new ProtocolError("response Content-Type is not application/json", response.status);
    }
    let value: unknown;
    try {
      value = await readBounded(response, this.maxWireBytes);
    } catch (error) {
      if (error instanceof ProtocolError) throw error;
      throw new TransportError(error);
    }
    if (response.status !== 200) throw parseServiceError(value, response.status);
    return parser(value);
  }
}
