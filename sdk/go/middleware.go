package contextdb

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// MemoryClient is the narrow seam required by agent-session middleware.
type MemoryClient interface {
	Observe(context.Context, ObserveRequest) (ObserveResponse, error)
	Recall(context.Context, RecallRequest) (RecallResponse, error)
}

type BeforeTurnOptions struct {
	PageSize     uint32
	AtCommit     *uint64
	Continuation *string
}

type AfterTurnOptions struct {
	Metadata       map[string]any
	IdempotencyKey string
}

// AgentSession serializes turn numbering so retries retain the same
// observation identity and idempotency key.
type AgentSession struct {
	client    MemoryClient
	context   RequestContext
	access    AccessPolicy
	agentID   string
	sessionID string

	mu               sync.Mutex
	sequence         uint64
	recallSequence   uint64
	lastTrace        *RecallTrace
	lastContinuation *string
}

func NewAgentSession(
	client MemoryClient,
	requestContext RequestContext,
	access AccessPolicy,
	agentID string,
	sessionID string,
) (*AgentSession, error) {
	if client == nil {
		return nil, errors.New("client is required")
	}
	if agentID == "" || sessionID == "" {
		return nil, errors.New("agent ID and session ID must be non-empty")
	}
	if requestContext.WorkspaceID != access.WorkspaceID {
		return nil, errors.New("access policy and request context workspace differ")
	}
	return &AgentSession{
		client:    client,
		context:   cloneRequestContext(requestContext),
		access:    cloneAccessPolicy(access),
		agentID:   agentID,
		sessionID: sessionID,
	}, nil
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

func cloneRequestContext(value RequestContext) RequestContext {
	value.Audiences = cloneStrings(value.Audiences)
	value.Scopes = cloneStrings(value.Scopes)
	return value
}

func cloneAccessPolicy(value AccessPolicy) AccessPolicy {
	value.Scopes = cloneStrings(value.Scopes)
	value.Owners = cloneStrings(value.Owners)
	value.Audience = cloneStrings(value.Audience)
	value.Purposes = cloneStrings(value.Purposes)
	grants := make(map[string][]string, len(value.AudiencePurposeGrants))
	for audience, purposes := range value.AudiencePurposeGrants {
		grants[audience] = cloneStrings(purposes)
	}
	value.AudiencePurposeGrants = grants
	return value
}

func (session *AgentSession) BeforeTurn(
	ctx context.Context,
	message string,
	options BeforeTurnOptions,
) (RecallResponse, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	pageSize := options.PageSize
	if pageSize == 0 {
		pageSize = 20
	}
	requestContext := session.context
	requestContext.RequestID = fmt.Sprintf(
		"session:%s:before:%d",
		session.sessionID,
		session.recallSequence,
	)
	response, err := session.client.Recall(ctx, RecallRequest{
		Context:      requestContext,
		Query:        message,
		PageSize:     pageSize,
		AtCommit:     options.AtCommit,
		Continuation: options.Continuation,
	})
	if err != nil {
		return RecallResponse{}, err
	}
	session.recallSequence++
	trace := response.Trace
	session.lastTrace = &trace
	if response.Continuation == nil {
		session.lastContinuation = nil
	} else {
		continuation := *response.Continuation
		session.lastContinuation = &continuation
	}
	return response, nil
}

func (session *AgentSession) AfterTurn(
	ctx context.Context,
	userMessage string,
	assistantResponse string,
	options AfterTurnOptions,
) (ObserveResponse, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	content := map[string]any{
		"kind":               "chat_turn",
		"session_id":         session.sessionID,
		"agent_id":           session.agentID,
		"sequence":           session.sequence,
		"user_message":       userMessage,
		"assistant_response": assistantResponse,
	}
	metadata := make(map[string]any, len(options.Metadata)+4)
	for key, value := range options.Metadata {
		metadata[key] = value
	}
	metadata["kind"] = "agent_session_turn"
	metadata["session_id"] = session.sessionID
	metadata["agent_id"] = session.agentID
	metadata["sequence"] = session.sequence
	idempotencyKey := options.IdempotencyKey
	if idempotencyKey == "" {
		digest := turnDigest(
			session.sessionID,
			session.agentID,
			session.sequence,
			userMessage,
			assistantResponse,
		)
		idempotencyKey = fmt.Sprintf(
			"agent-session:%s:%d:%s",
			session.sessionID,
			session.sequence,
			hex.EncodeToString(digest[:]),
		)
	}
	requestContext := session.context
	requestContext.RequestID = fmt.Sprintf(
		"session:%s:after:%d",
		session.sessionID,
		session.sequence,
	)
	response, err := session.client.Observe(ctx, ObserveRequest{
		Context:        requestContext,
		IdempotencyKey: idempotencyKey,
		ObservationID: fmt.Sprintf(
			"session:%s:turn:%d",
			session.sessionID,
			session.sequence,
		),
		Metadata: metadata,
		Content:  content,
		Access:   session.access,
	})
	if err != nil {
		return ObserveResponse{}, err
	}
	session.sequence++
	return response, nil
}

func turnDigest(
	sessionID string,
	agentID string,
	sequence uint64,
	userMessage string,
	assistantResponse string,
) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("contextdb-agent-turn-v1\x00"))
	writeText := func(value string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len([]byte(value))))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	writeText(sessionID)
	writeText(agentID)
	var encodedSequence [8]byte
	binary.BigEndian.PutUint64(encodedSequence[:], sequence)
	_, _ = hash.Write(encodedSequence[:])
	writeText(userMessage)
	writeText(assistantResponse)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (session *AgentSession) LastTrace() (RecallTrace, bool) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.lastTrace == nil {
		return RecallTrace{}, false
	}
	return *session.lastTrace, true
}

func (session *AgentSession) LastContinuation() (string, bool) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.lastContinuation == nil {
		return "", false
	}
	return *session.lastContinuation, true
}

func (session *AgentSession) Sequence() uint64 {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.sequence
}
