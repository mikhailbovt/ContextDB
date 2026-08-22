export const ErrorCodes = {
  InvalidScope: "invalid_scope",
  Unauthorized: "unauthorized",
  AmbiguousIdentity: "ambiguous_identity",
  SnapshotExpired: "snapshot_expired",
  IndexTooStale: "index_too_stale",
  EvidenceRequired: "evidence_required",
  ConflictUnresolved: "conflict_unresolved",
  BudgetExhausted: "budget_exhausted",
  ContinuationExpired: "continuation_expired",
  FormatIncompatible: "format_incompatible",
  ProviderUnavailable: "provider_unavailable",
  DegradedMode: "degraded_mode",
  InvalidArgument: "invalid_argument",
  PermissionDenied: "permission_denied",
  NotFound: "not_found",
  IdempotencyConflict: "idempotency_conflict",
  InvalidContinuation: "invalid_continuation",
  IntegrityFailure: "integrity_failure",
  Unavailable: "unavailable",
  ResourceExhausted: "resource_exhausted",
  Unsupported: "unsupported",
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

export class ContextDbError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly status: number;
  readonly partial_result_refs: readonly string[];
  readonly violated_policy: string | null;
  readonly safe_next_action: string | null;
  readonly trace_id: string | null;

  constructor(options: {
    code: ErrorCode;
    message: string;
    retryable: boolean;
    status: number;
    partialResultRefs?: readonly string[];
    violatedPolicy?: string | null;
    safeNextAction?: string | null;
    traceId?: string | null;
  }) {
    super(options.message);
    this.name = "ContextDbError";
    this.code = options.code;
    this.retryable = options.retryable;
    this.status = options.status;
    this.partial_result_refs = options.partialResultRefs ?? [];
    this.violated_policy = options.violatedPolicy ?? null;
    this.safe_next_action = options.safeNextAction ?? null;
    this.trace_id = options.traceId ?? null;
  }

  get partialResultRefs(): readonly string[] {
    return this.partial_result_refs;
  }

  get violatedPolicy(): string | null {
    return this.violated_policy;
  }

  get safeNextAction(): string | null {
    return this.safe_next_action;
  }

  get traceId(): string | null {
    return this.trace_id;
  }
}

export class ProtocolError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "ProtocolError";
    this.status = status;
  }
}

export class TransportError extends Error {
  override readonly cause: unknown;

  constructor(cause: unknown) {
    super("ContextDB request failed");
    this.name = "TransportError";
    this.cause = cause;
  }
}
