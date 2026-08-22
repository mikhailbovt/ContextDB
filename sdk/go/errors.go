package contextdb

import "fmt"

// ErrorCode is the stable service error taxonomy.
type ErrorCode string

const (
	ErrorInvalidScope        ErrorCode = "invalid_scope"
	ErrorUnauthorized        ErrorCode = "unauthorized"
	ErrorAmbiguousIdentity   ErrorCode = "ambiguous_identity"
	ErrorSnapshotExpired     ErrorCode = "snapshot_expired"
	ErrorIndexTooStale       ErrorCode = "index_too_stale"
	ErrorEvidenceRequired    ErrorCode = "evidence_required"
	ErrorConflictUnresolved  ErrorCode = "conflict_unresolved"
	ErrorBudgetExhausted     ErrorCode = "budget_exhausted"
	ErrorContinuationExpired ErrorCode = "continuation_expired"
	ErrorFormatIncompatible  ErrorCode = "format_incompatible"
	ErrorProviderUnavailable ErrorCode = "provider_unavailable"
	ErrorDegradedMode        ErrorCode = "degraded_mode"
	ErrorInvalidArgument     ErrorCode = "invalid_argument"
	ErrorPermissionDenied    ErrorCode = "permission_denied"
	ErrorNotFound            ErrorCode = "not_found"
	ErrorIdempotencyConflict ErrorCode = "idempotency_conflict"
	ErrorInvalidContinuation ErrorCode = "invalid_continuation"
	ErrorIntegrityFailure    ErrorCode = "integrity_failure"
	ErrorUnavailable         ErrorCode = "unavailable"
	ErrorResourceExhausted   ErrorCode = "resource_exhausted"
	ErrorUnsupported         ErrorCode = "unsupported"
)

// ServiceError is a canonical error returned by a conforming ContextDB peer.
type ServiceError struct {
	Code              ErrorCode `json:"code"`
	Message           string    `json:"message"`
	Retryable         bool      `json:"retryable"`
	Status            int       `json:"-"`
	PartialResultRefs []string  `json:"partial_result_refs,omitempty"`
	ViolatedPolicy    *string   `json:"violated_policy,omitempty"`
	SafeNextAction    *string   `json:"safe_next_action,omitempty"`
	TraceID           *string   `json:"trace_id,omitempty"`
}

func (failure *ServiceError) Error() string {
	return fmt.Sprintf("%s: %s", failure.Code, failure.Message)
}

// ProtocolError means an HTTP peer violated the canonical v1 contract.
type ProtocolError struct {
	Message string
	Status  int
}

func (failure *ProtocolError) Error() string { return failure.Message }

// TransportError means the request could not reach a conforming HTTP peer.
type TransportError struct {
	Cause error
}

func (failure *TransportError) Error() string { return "ContextDB request failed" }
func (failure *TransportError) Unwrap() error { return failure.Cause }

var errorStatuses = map[ErrorCode]int{
	ErrorInvalidScope:        400,
	ErrorUnauthorized:        403,
	ErrorAmbiguousIdentity:   400,
	ErrorSnapshotExpired:     410,
	ErrorIndexTooStale:       409,
	ErrorEvidenceRequired:    400,
	ErrorConflictUnresolved:  409,
	ErrorBudgetExhausted:     413,
	ErrorContinuationExpired: 410,
	ErrorFormatIncompatible:  422,
	ErrorProviderUnavailable: 503,
	ErrorDegradedMode:        206,
	ErrorInvalidArgument:     400,
	ErrorPermissionDenied:    403,
	ErrorNotFound:            404,
	ErrorIdempotencyConflict: 409,
	ErrorInvalidContinuation: 400,
	ErrorIntegrityFailure:    422,
	ErrorUnavailable:         503,
	ErrorResourceExhausted:   413,
	ErrorUnsupported:         501,
}
