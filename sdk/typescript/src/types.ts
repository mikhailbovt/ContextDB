export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export type Sensitivity = "public" | "internal" | "private" | "restricted";
export type Consent = "granted" | "unknown" | "denied";

export interface RequestContext {
  readonly request_id: string;
  readonly workspace_id: string;
  readonly subject_id: string;
  readonly audiences: readonly string[];
  readonly scopes: readonly string[];
  readonly purpose: string;
  readonly clearance: Sensitivity;
}

export interface AccessPolicy {
  readonly workspace_id: string;
  readonly scopes: readonly string[];
  readonly owners: readonly string[];
  readonly audience: readonly string[];
  readonly audience_purpose_grants: Readonly<Record<string, readonly string[]>>;
  readonly purposes: readonly string[];
  readonly sensitivity: Sensitivity;
  readonly consent: Consent;
  readonly retrievable: boolean;
}

export interface Watermarks {
  readonly journal: number;
  readonly semantic: number;
  readonly lexical: number;
  readonly vector: number;
  readonly graph: number;
}

export interface ObserveRequest {
  readonly context: RequestContext;
  readonly idempotency_key: string;
  readonly observation_id: string;
  readonly metadata: Readonly<Record<string, JsonValue>>;
  readonly content: JsonValue;
  readonly access: AccessPolicy;
}

export interface ObserveResponse {
  readonly commit_seq: number;
  readonly replayed: boolean;
  readonly request_digest: string;
  readonly watermarks: Watermarks;
}

export interface RecallRequest {
  readonly context: RequestContext;
  readonly query: string;
  readonly page_size: number;
  readonly at_commit: number | null;
  readonly continuation: string | null;
}

export interface RecallHit {
  readonly id: string;
  readonly score: number;
}

export interface RecallTrace {
  readonly trace_id: string;
  readonly snapshot_seq: number;
  readonly operation: string;
  readonly authorized_candidates: number;
  readonly selected_ids: readonly string[];
  readonly watermarks: Watermarks;
}

export interface RecallResponse {
  readonly hits: readonly RecallHit[];
  readonly trace: RecallTrace;
  readonly continuation: string | null;
}

export interface ExplainRecallRequest {
  readonly context: RequestContext;
  readonly trace: RecallTrace;
}

export interface ExportRequest {
  readonly context: RequestContext;
}

export interface ExportResponse {
  readonly format: string;
  readonly bytes: Uint8Array;
  readonly digest: string;
  readonly commit_seq: number;
}

export interface ImportRequest {
  readonly context: RequestContext;
  readonly format: string;
  readonly bytes: Uint8Array;
  readonly digest: string;
}

export interface ImportResponse {
  readonly commit_seq: number;
  readonly watermarks: Watermarks;
}

export interface VerifyRequest {
  readonly context: RequestContext;
  readonly deep: boolean;
}

export interface VerifyResponse {
  readonly valid: boolean;
  readonly commit_seq: number;
  readonly archive_digest: string | null;
}

export interface RequestOptions {
  readonly signal?: AbortSignal;
}
