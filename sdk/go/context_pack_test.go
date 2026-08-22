package contextdb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

type contextPackFixture struct {
	Request  json.RawMessage `json:"request"`
	Response json.RawMessage `json:"response"`
}

func loadContextPackFixture(t *testing.T) contextPackFixture {
	t.Helper()
	data, err := os.ReadFile("../fixtures/context_pack_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture contextPackFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func testCompileContextRequest() CompileContextRequest {
	session := "session-1"
	auth := AuthenticatedRequestContext{
		Request: RequestContext{
			RequestID: "request-context-pack-1", WorkspaceID: "workspace-1", SubjectID: "subject-1",
			Audiences: []string{"team"}, Scopes: []string{"project"}, Purpose: "conversation",
			Clearance: SensitivityPrivate,
		},
		ActorID: "actor-1", AgentID: "agent-1", SessionID: &session,
		CapabilityGrants: []Capability{CapabilityRecall},
		Authentication: AuthenticationEvidence{
			Kind: AuthenticationAuthenticatedChannel, ChannelID: "channel-1", PeerIdentity: "actor-1",
			BindingDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	return CompileContextRequest{
		Context: auth,
		Plan: CompileContextPlan{
			PackID: "018f47b8-3158-7ad8-9227-63fc6f711e5f", Query: "What should the assistant remember?",
			Mode: RecallRequired, Intent: StandardRecallIntent(RecallIntentCurrentTruth),
			Purpose: PackPurposeConversation, RequiredFacets: []PackFacetRequirement{},
			RecallLimits: RecallLimits{
				MaxNodesExamined: 128, MaxSeedCandidates: 64, MaxGraphHops: 2,
				MaxFrontierPerHop: 64, MaxEvidenceUnits: 32, MaxContextTokens: 2048,
				DeadlineMicros: 5_000_000,
			},
			ContextBudgets: ContextBudgets{
				HardTokens: 2048, SoftTokens: 1024, MaxBlocks: 32, MaxEvidenceBlocks: 32,
				MaxRawEvidenceTokens: 512, MaxHistoryTokens: 512, MaxConflictTokens: 512,
				MaxSerializedBytes: 262144, MaxSelectionEvaluations: 128,
			},
			ModelProfile: ModelProfile{
				ID: "model:local-test", Family: "reference",
				TokenizerID: "contextdb.reference-tokenizer.v1", Renderer: RendererCompact,
				MaxContextTokens: 4096, ReservedOutputTokens: 1024,
				PreferredStructuredFormat: StructuredCompactText,
				PositionProfile:           PositionSmallModelExplicit,
				InstructionHierarchy:      InstructionSinglePromptDelimited,
				MaxSchemaComplexity:       32,
			},
			ExplicitMemoryRequest: true, PermitDerivedOnly: true,
		},
	}
}

func TestCompileContextTypedRouteAndSeparatedRendering(t *testing.T) {
	t.Parallel()
	fixture := loadContextPackFixture(t)
	var providerBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != ContextPackPath || request.Method != http.MethodPost {
			t.Errorf("unexpected operation %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("x-contextdb-gateway-attestation") != "ephemeral-context-pack" {
			t.Errorf("missing exact-request gateway attestation")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(fixture.Response)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, &ClientOptions{HeaderProvider: func(_ context.Context, request HeaderProviderRequest) (http.Header, error) {
		if request.Path != ContextPackPath {
			t.Fatalf("provider path = %s", request.Path)
		}
		providerBody = append([]byte(nil), request.Body...)
		return http.Header{"x-contextdb-gateway-attestation": {"ephemeral-context-pack"}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.CompileContext(context.Background(), testCompileContextRequest())
	if err != nil {
		t.Fatal(err)
	}
	if response.ContextPack.Status != PackNoMemory || response.Trace.PackStatus != PackNoMemory {
		t.Fatalf("unexpected pack status: %#v", response)
	}
	if response.Rendered.TrustedControl == "" || response.Rendered.UntrustedData != "" {
		t.Fatalf("trusted/untrusted channels were not preserved: %#v", response.Rendered)
	}
	if err := response.VerifyCanonicalDigest(); err != nil {
		t.Fatalf("canonical digest verification failed: %v", err)
	}
	corruptedBytes := response
	corruptedBytes.CanonicalBytes = append(ByteArray(nil), response.CanonicalBytes...)
	corruptedBytes.CanonicalBytes[0] ^= 1
	if err := corruptedBytes.VerifyCanonicalDigest(); err == nil {
		t.Fatal("corrupted canonical bytes passed digest verification")
	}
	corruptedDigest := response
	corruptedDigest.CanonicalDigest = "0" + response.CanonicalDigest[1:]
	if corruptedDigest.CanonicalDigest == response.CanonicalDigest {
		corruptedDigest.CanonicalDigest = "1" + response.CanonicalDigest[1:]
	}
	if err := corruptedDigest.VerifyCanonicalDigest(); err == nil {
		t.Fatal("corrupted canonical digest passed verification")
	}
	var sent map[string]any
	if err := json.Unmarshal(providerBody, &sent); err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if err := json.Unmarshal(fixture.Request, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sent, expected) {
		t.Fatalf("typed request differs from shared fixture\n got: %#v\nwant: %#v", sent, expected)
	}
}

func TestCompileContextRejectsUnknownNestedFields(t *testing.T) {
	t.Parallel()
	fixture := loadContextPackFixture(t)
	var response map[string]any
	if err := json.Unmarshal(fixture.Response, &response); err != nil {
		t.Fatal(err)
	}
	pack := response["context_pack"].(map[string]any)
	sections := pack["sections"].(map[string]any)
	sections["future_secret_channel"] = []any{}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, http.StatusOK, response)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CompileContext(context.Background(), testCompileContextRequest())
	var protocol *ProtocolError
	if !errors.As(err, &protocol) {
		t.Fatalf("expected strict nested ProtocolError, got %T %v", err, err)
	}
}

func TestCompileContextRejectsUnknownCanonicalEncoding(t *testing.T) {
	t.Parallel()
	fixture := loadContextPackFixture(t)
	var response map[string]any
	if err := json.Unmarshal(fixture.Response, &response); err != nil {
		t.Fatal(err)
	}
	response["canonical_encoding"] = "contextdb.context_pack.protobuf.v2"

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, http.StatusOK, response)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CompileContext(context.Background(), testCompileContextRequest())
	var protocol *ProtocolError
	if !errors.As(err, &protocol) {
		t.Fatalf("expected unknown-encoding ProtocolError, got %T %v", err, err)
	}
}

func TestCompileContextPreservesCanonicalServiceErrors(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, http.StatusForbidden, map[string]any{
			"code": "permission_denied", "message": "recall capability is required", "retryable": false,
		})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CompileContext(context.Background(), testCompileContextRequest())
	var serviceError *ServiceError
	if !errors.As(err, &serviceError) || serviceError.Code != ErrorPermissionDenied {
		t.Fatalf("canonical service error was not preserved: %T %v", err, err)
	}
}
