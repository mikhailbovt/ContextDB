package contextdb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestHighLevelSurfaceFixtureMatchesSDK(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.FromSlash("../../crates/contextdb-conformance/tests/fixtures/high_level_v1_surface.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Routes map[string]struct {
			Capabilities []Capability `json:"capabilities"`
		} `json:"http_routes"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	want := map[string][]Capability{
		BeginSessionPath: {CapabilityObserve}, BeforeTurnPath: {CapabilityRecall}, AfterTurnPath: {CapabilityObserve},
		ResolveReferentPath: {CapabilityRecall}, RecallSharedHistoryPath: {CapabilityRecall}, EndSessionPath: {CapabilityObserve},
		BootstrapSubjectPath: {CapabilityObserve}, RememberPath: {CapabilityObserve}, PinPath: {CapabilityCorrect},
		SuppressPath: {CapabilityCorrect}, ChangeAudiencePath: {CapabilityCorrect}, ChangeRetentionPath: {CapabilityCorrect},
		ExplainMemoryPath: {CapabilityRecall}, ListSubjectMemoriesPath: {CapabilityRecall}, ExportSubjectPath: {CapabilityReadMemory},
		ImportSubjectPath: {CapabilityObserve, CapabilityAdmin}, CreateMemorySubjectPath: {CapabilityObserve},
		CreateRelationshipSpacePath: {CapabilityObserve}, GetContinuityProfilePath: {CapabilityRecall},
		UpdateConfiguredRolePath: {CapabilityRuntime}, MigrateAgentRuntimePath: {CapabilityRuntime},
		PublishToSharedMemoryPath: {CapabilityCorrect}, RevokeSharedMemoryPath: {CapabilityCorrect},
		IngestArtifactPath: {CapabilityObserve}, AttachArtifactToEpisodePath: {CapabilityObserve},
		AddDerivedRepresentationPath: {CapabilityObserve}, AddEvidenceSelectorPath: {CapabilityObserve},
		GetArtifactMetadataPath: {CapabilityRecall}, DeleteArtifactLineagePath: {CapabilityForget, CapabilityHardDelete},
	}
	if len(fixture.Routes) != 29 || !reflect.DeepEqual(func() map[string][]Capability {
		result := make(map[string][]Capability, len(fixture.Routes))
		for path, route := range fixture.Routes {
			result[path] = route.Capabilities
		}
		return result
	}(), want) {
		t.Fatalf("high-level route/capability fixture does not match SDK: %#v", fixture.Routes)
	}
}

func TestHighLevelHTTPV1AllRoutesUseFreshExactAttestation(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var paths []string
	var providerBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		index := len(paths)
		paths = append(paths, request.URL.Path)
		provided := append([]byte(nil), providerBodies[index]...)
		mu.Unlock()
		var decoded map[string]any
		if err := json.Unmarshal(provided, &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(body, decoded) {
			t.Errorf("provider body differs for %s", request.URL.Path)
		}
		switch request.URL.Path {
		case BeforeTurnPath, ResolveReferentPath, RecallSharedHistoryPath, ExplainMemoryPath, ListSubjectMemoriesPath, GetContinuityProfilePath, GetArtifactMetadataPath:
			writeJSON(t, writer, 200, RecallResponse{Hits: []RecallHit{}, Trace: RecallTrace{TraceID: "trace", Operation: "lexical", SelectedIDs: []string{}, Watermarks: testWatermarks()}})
		case PinPath, SuppressPath, ChangeAudiencePath, ChangeRetentionPath, UpdateConfiguredRolePath, MigrateAgentRuntimePath, PublishToSharedMemoryPath, RevokeSharedMemoryPath, DeleteArtifactLineagePath:
			writeJSON(t, writer, 200, MutationResponse{CommitSeq: 7, RequestDigest: "digest", Watermarks: testWatermarks()})
		case ExportSubjectPath:
			writeJSON(t, writer, 200, ExportResponse{Format: "contextdb-subject-v1", Bytes: ByteArray{}, Digest: "digest", CommitSeq: 7})
		case ImportSubjectPath:
			writeJSON(t, writer, 200, ImportResponse{CommitSeq: 7, Watermarks: testWatermarks()})
		default:
			writeJSON(t, writer, 200, HighLevelMutationResponse{Operation: "Operation", LogicalID: "logical-1", PolicyResult: "accepted", SemanticStatus: "pending", Receipt: ObserveResponse{CommitSeq: 7, RequestDigest: "digest", Watermarks: testWatermarks()}})
		}
	}))
	defer server.Close()
	providerCalls := 0
	client, err := NewClient(server.URL, &ClientOptions{HeaderProvider: func(_ context.Context, request HeaderProviderRequest) (http.Header, error) {
		mu.Lock()
		defer mu.Unlock()
		providerCalls++
		providerBodies = append(providerBodies, append([]byte(nil), request.Body...))
		return http.Header{"x-contextdb-gateway-id": {"gateway-1"}, "x-contextdb-gateway-attestation": {fmt.Sprintf("fresh-%d", providerCalls)}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	auth := testAuthenticatedContext()
	write := HighLevelWriteRequest{Context: auth, IdempotencyKey: "key", TargetSubjectID: "subject-1", SessionID: auth.SessionID, LogicalID: "logical-1", Access: testAccess(), Payload: map[string]any{}, References: []string{}}
	query := HighLevelQueryRequest{Context: auth, TargetSubjectID: "subject-1", Cue: "cue", PageSize: 20}
	control := HighLevelControlRequest{Context: auth, IdempotencyKey: "key", TargetSubjectID: "subject-1", TargetID: "target-1", Parameters: map[string]any{}}
	transfer := HighLevelTransferRequest{Context: auth, IdempotencyKey: "key", TargetSubjectID: "subject-1", Format: "contextdb-subject-v1", Bytes: ByteArray{}}
	calls := []func() error{
		func() error { _, e := client.BeginSession(ctx, write); return e }, func() error { _, e := client.BeforeTurn(ctx, query); return e },
		func() error { _, e := client.AfterTurn(ctx, write); return e }, func() error { _, e := client.ResolveReferent(ctx, query); return e },
		func() error { _, e := client.RecallSharedHistory(ctx, query); return e }, func() error { _, e := client.EndSession(ctx, write); return e },
		func() error { _, e := client.BootstrapSubject(ctx, write); return e }, func() error { _, e := client.Remember(ctx, write); return e },
		func() error { _, e := client.Pin(ctx, control); return e }, func() error { _, e := client.Suppress(ctx, control); return e },
		func() error { _, e := client.ChangeAudience(ctx, control); return e }, func() error { _, e := client.ChangeRetention(ctx, control); return e },
		func() error { _, e := client.ExplainMemory(ctx, query); return e }, func() error { _, e := client.ListSubjectMemories(ctx, query); return e },
		func() error { _, e := client.ExportSubject(ctx, transfer); return e }, func() error { _, e := client.ImportSubject(ctx, transfer); return e },
		func() error { _, e := client.CreateMemorySubject(ctx, write); return e }, func() error { _, e := client.CreateRelationshipSpace(ctx, write); return e },
		func() error { _, e := client.GetContinuityProfile(ctx, query); return e }, func() error { _, e := client.UpdateConfiguredRole(ctx, control); return e },
		func() error { _, e := client.MigrateAgentRuntime(ctx, control); return e }, func() error { _, e := client.PublishToSharedMemory(ctx, control); return e },
		func() error { _, e := client.RevokeSharedMemory(ctx, control); return e }, func() error { _, e := client.IngestArtifact(ctx, write); return e },
		func() error { _, e := client.AttachArtifactToEpisode(ctx, write); return e }, func() error { _, e := client.AddDerivedRepresentation(ctx, write); return e },
		func() error { _, e := client.AddEvidenceSelector(ctx, write); return e }, func() error { _, e := client.GetArtifactMetadata(ctx, query); return e },
		func() error { _, e := client.DeleteArtifactLineage(ctx, control); return e },
	}
	for index, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("call %d: %v", index, err)
		}
	}
	if providerCalls != 29 || len(paths) != 29 {
		t.Fatalf("provider=%d paths=%d", providerCalls, len(paths))
	}
}
