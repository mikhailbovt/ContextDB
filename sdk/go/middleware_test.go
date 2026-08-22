package contextdb

import (
	"context"
	"errors"
	"testing"
)

type fakeMemoryClient struct {
	observations []ObserveRequest
	recalls      []RecallRequest
	failObserve  bool
}

func (client *fakeMemoryClient) Observe(_ context.Context, request ObserveRequest) (ObserveResponse, error) {
	client.observations = append(client.observations, request)
	if client.failObserve {
		return ObserveResponse{}, errors.New("injected failure")
	}
	return ObserveResponse{CommitSeq: 3, RequestDigest: "digest", Watermarks: testWatermarks()}, nil
}

func (client *fakeMemoryClient) Recall(_ context.Context, request RecallRequest) (RecallResponse, error) {
	client.recalls = append(client.recalls, request)
	continuation := "continuation-1"
	return RecallResponse{
		Hits:  []RecallHit{{ID: "memory-1", Score: 1}},
		Trace: testTrace(), Continuation: &continuation,
	}, nil
}

func TestAgentSessionBeforeAfterAndStableRetry(t *testing.T) {
	t.Parallel()
	fake := &fakeMemoryClient{}
	session, err := NewAgentSession(fake, testContext(), testAccess(), "agent-1", "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.BeforeTurn(context.Background(), "what did we decide?", BeforeTurnOptions{}); err != nil {
		t.Fatal(err)
	}
	trace, ok := session.LastTrace()
	if !ok || trace.TraceID != "trace-1" {
		t.Fatalf("last trace = %#v, %v", trace, ok)
	}
	continuation, ok := session.LastContinuation()
	if !ok || continuation != "continuation-1" {
		t.Fatalf("continuation = %q, %v", continuation, ok)
	}
	if _, err := session.AfterTurn(context.Background(), "hello", "hi", AfterTurnOptions{
		Metadata: map[string]any{"channel": "chat"},
	}); err != nil {
		t.Fatal(err)
	}
	observed := fake.observations[0]
	if observed.IdempotencyKey != "agent-session:session-1:0:2f3e39c1c1a84fd927469d194dea24eab10aeddb80263fa288ce8dc25767f818" {
		t.Fatalf("idempotency key = %s", observed.IdempotencyKey)
	}
	if observed.Context.RequestID != "session:session-1:after:0" || observed.Metadata["channel"] != "chat" {
		t.Fatalf("observation = %#v", observed)
	}
	if session.Sequence() != 1 {
		t.Fatalf("sequence = %d", session.Sequence())
	}

	secondFake := &fakeMemoryClient{}
	second, err := NewAgentSession(secondFake, testContext(), testAccess(), "agent-1", "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.AfterTurn(context.Background(), "hello", "hi", AfterTurnOptions{
		Metadata: map[string]any{"different": true},
	}); err != nil {
		t.Fatal(err)
	}
	if secondFake.observations[0].IdempotencyKey != observed.IdempotencyKey {
		t.Fatal("metadata changed the stable exact-turn retry key")
	}
}

func TestAgentSessionFailureDoesNotAdvance(t *testing.T) {
	t.Parallel()
	fake := &fakeMemoryClient{failObserve: true}
	session, err := NewAgentSession(fake, testContext(), testAccess(), "agent-1", "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.AfterTurn(context.Background(), "hello", "hi", AfterTurnOptions{}); err == nil {
		t.Fatal("injected failure succeeded")
	}
	firstKey := fake.observations[0].IdempotencyKey
	if session.Sequence() != 0 {
		t.Fatal("failed write advanced sequence")
	}
	fake.failObserve = false
	if _, err := session.AfterTurn(context.Background(), "hello", "hi", AfterTurnOptions{}); err != nil {
		t.Fatal(err)
	}
	if fake.observations[1].IdempotencyKey != firstKey || session.Sequence() != 1 {
		t.Fatal("retry identity changed")
	}
}

func TestAgentSessionRejectsWorkspaceConfusion(t *testing.T) {
	t.Parallel()
	policy := testAccess()
	policy.WorkspaceID = "other-workspace"
	if _, err := NewAgentSession(&fakeMemoryClient{}, testContext(), policy, "agent-1", "session-1"); err == nil {
		t.Fatal("cross-workspace policy accepted")
	}
}

func TestAgentSessionSnapshotsCapabilityInputs(t *testing.T) {
	t.Parallel()
	fake := &fakeMemoryClient{}
	requestContext := testContext()
	policy := testAccess()
	session, err := NewAgentSession(fake, requestContext, policy, "agent-1", "session-1")
	if err != nil {
		t.Fatal(err)
	}
	requestContext.Scopes[0] = "mutated"
	policy.AudiencePurposeGrants["team"][0] = "mutated"
	if _, err := session.AfterTurn(context.Background(), "hello", "hi", AfterTurnOptions{}); err != nil {
		t.Fatal(err)
	}
	observed := fake.observations[0]
	if observed.Context.Scopes[0] != "project" || observed.Access.AudiencePurposeGrants["team"][0] != "assistant" {
		t.Fatalf("session inputs were mutated: %#v", observed)
	}
}
