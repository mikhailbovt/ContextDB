package contextdb

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func testContext() RequestContext {
	return RequestContext{
		RequestID:   "request-1",
		WorkspaceID: "workspace-1",
		SubjectID:   "subject-1",
		Audiences:   []string{"subject:subject-1", "team"},
		Scopes:      []string{"project", "session:session-1"},
		Purpose:     "assistant",
		Clearance:   SensitivityPrivate,
	}
}

func testAccess() AccessPolicy {
	return AccessPolicy{
		WorkspaceID:           "workspace-1",
		Scopes:                []string{"project", "session:session-1"},
		Owners:                []string{"subject-1"},
		Audience:              []string{"team"},
		AudiencePurposeGrants: map[string][]string{"team": {"assistant"}},
		Purposes:              []string{},
		Sensitivity:           SensitivityPrivate,
		Consent:               ConsentGranted,
		Retrievable:           true,
	}
}

func testWatermarks() Watermarks {
	return Watermarks{Journal: 3, Semantic: 3, Lexical: 3, Vector: 3, Graph: 3}
}

func testTrace() RecallTrace {
	return RecallTrace{
		TraceID:              "trace-1",
		SnapshotSeq:          3,
		Operation:            "lexical",
		AuthorizedCandidates: 1,
		SelectedIDs:          []string{"memory-1"},
		Watermarks:           testWatermarks(),
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func TestClientCanonicalRoutesTypesAndHeaders(t *testing.T) {
	t.Parallel()
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		if request.Method != http.MethodPost {
			t.Errorf("method = %s", request.Method)
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("canonical JSON headers missing: %v", request.Header)
		}
		if request.Header.Get("Authorization") != "Bearer future-token" || request.Header.Get("X-Tenant") != "tenant-1" {
			t.Errorf("optional deployment headers missing: %v", request.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		switch strings.TrimPrefix(request.URL.Path, "/root") {
		case ObservePath:
			writeJSON(t, writer, 200, ObserveResponse{3, false, "digest-1", testWatermarks()})
		case RecallPath:
			if value, ok := body["at_commit"]; !ok || value != nil {
				t.Errorf("at_commit must be explicit null: %#v", body)
			}
			continuation := "continuation-1"
			writeJSON(t, writer, 200, RecallResponse{
				Hits:  []RecallHit{{ID: "memory-1", Score: 0.75}},
				Trace: testTrace(), Continuation: &continuation,
			})
		case ExplainRecallPath:
			writeJSON(t, writer, 200, testTrace())
		case ExportPath:
			writeJSON(t, writer, 200, ExportResponse{
				Format: "contextdb-logical-v1", Bytes: ByteArray{0, 127, 255},
				Digest: "archive-digest", CommitSeq: 3,
			})
		case ImportPath:
			archive, ok := body["bytes"].([]any)
			if !ok || !reflect.DeepEqual(archive, []any{float64(0), float64(127), float64(255)}) {
				t.Errorf("archive bytes are not integer array: %#v", body["bytes"])
			}
			writeJSON(t, writer, 200, ImportResponse{CommitSeq: 3, Watermarks: testWatermarks()})
		case VerifyPath:
			writeJSON(t, writer, 200, VerifyResponse{Valid: true, CommitSeq: 3})
		default:
			t.Errorf("unexpected route %s", request.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL+"/root/", &ClientOptions{
		Headers: http.Header{"X-Tenant": {"tenant-1"}}, BearerToken: "future-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Observe(ctx, ObserveRequest{
		Context: testContext(), IdempotencyKey: "key-1", ObservationID: "observation-1",
		Metadata: map[string]any{"source": "test"}, Content: map[string]any{"text": "hello"}, Access: testAccess(),
	}); err != nil {
		t.Fatal(err)
	}
	recalled, err := client.Recall(ctx, RecallRequest{Context: testContext(), Query: "hello", PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExplainRecall(ctx, ExplainRecallRequest{Context: testContext(), Trace: recalled.Trace}); err != nil {
		t.Fatal(err)
	}
	exported, err := client.ExportArchive(ctx, ExportRequest{Context: testContext()})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(exported.Bytes, ByteArray{0, 127, 255}) {
		t.Fatalf("export bytes = %v", exported.Bytes)
	}
	if _, err := client.ImportArchive(ctx, ImportRequest{
		Context: testContext(), Format: exported.Format, Bytes: exported.Bytes, Digest: exported.Digest,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Verify(ctx, VerifyRequest{Context: testContext(), Deep: true}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/root" + ObservePath, "/root" + RecallPath, "/root" + ExplainRecallPath,
		"/root" + ExportPath, "/root" + ImportPath, "/root" + VerifyPath,
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestSharedContractFixture(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../fixtures/http_v1_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		MaxWireBytes                int64             `json:"max_wire_bytes"`
		CandidateCapabilityIDs      []string          `json:"candidate_runtime_capability_ids_v1"`
		Routes                      map[string]string `json:"routes"`
		Statuses                    map[ErrorCode]int `json:"error_statuses"`
		LegacyRoutes                []string          `json:"legacy_request_context_routes"`
		AuthenticatedContextRoutes  []string          `json:"authenticated_context_routes"`
		GatewayAttestationRoutes    []string          `json:"gateway_attestation_routes"`
		GatewayAttestationBinding   map[string]string `json:"gateway_attestation_binding"`
		UnauthenticatedNonSDKRoutes map[string]struct {
			Method  string `json:"method"`
			Path    string `json:"path"`
			Profile string `json:"profile"`
			Claim   string `json:"claim"`
		} `json:"unauthenticated_non_sdk_routes"`
		HealthBoundary struct {
			SDKExposed                 bool `json:"sdk_exposed"`
			GatewayAttestationRequired bool `json:"gateway_attestation_required"`
			ContentFree                bool `json:"content_free"`
			RFC3115Complete            bool `json:"rfc_31_15_complete"`
			ServerV1ProfileProven      bool `json:"server_v1_profile_proven"`
		} `json:"health_boundary"`
		SignatureEvidence json.RawMessage `json:"request_signature_evidence"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.MaxWireBytes != MaxWireBytes {
		t.Fatalf("max wire bytes = %d", fixture.MaxWireBytes)
	}
	wantCandidateCapabilities := CandidateRuntimeCapabilityIDsV1()
	if !reflect.DeepEqual(fixture.CandidateCapabilityIDs, wantCandidateCapabilities[:]) {
		t.Fatalf("candidate capability IDs = %#v", fixture.CandidateCapabilityIDs)
	}
	if fixture.GatewayAttestationBinding["protocol"] != "v2 exact request; no legacy fallback" ||
		fixture.GatewayAttestationBinding["body"] != "exact serialized JSON bytes" ||
		fixture.GatewayAttestationBinding["replay"] != "unique 128-bit nonce consumed atomically" {
		t.Fatalf("gateway attestation binding = %#v", fixture.GatewayAttestationBinding)
	}
	wantRoutes := map[string]string{
		"observe": ObservePath, "ingest_frame": IngestFramePath, "correct": CorrectPath,
		"forget": ForgetPath, "recall": RecallPath, "compile_context": ContextPackPath,
		"explain_recall": ExplainRecallPath,
		"subscribe":      SubscribePath, "get_node": GetNodePath, "traverse": TraversePath,
		"get_timeline": GetTimelinePath, "get_evidence": GetEvidencePath,
		"get_conflict": GetConflictPath, "bootstrap": BootstrapPath, "preflight": PreflightPath,
		"postflight": PostflightPath, "checkpoint": CheckpointPath, "resume": ResumePath,
		"handoff": HandoffPath, "consolidate": ConsolidatePath, "reflect": ReflectPath,
		"reindex": ReindexPath, "compact": CompactPath, "get_status": GetStatusPath,
		"create_backup": CreateBackupPath, "restore_backup": RestoreBackupPath,
		"migrate_format": MigrateFormatPath, "export_archive": ExportPath,
		"import_archive": ImportPath, "verify": VerifyPath,
		"begin_session": BeginSessionPath, "before_turn": BeforeTurnPath,
		"after_turn": AfterTurnPath, "resolve_referent": ResolveReferentPath,
		"recall_shared_history": RecallSharedHistoryPath, "end_session": EndSessionPath,
		"bootstrap_subject": BootstrapSubjectPath, "remember": RememberPath,
		"pin": PinPath, "suppress": SuppressPath, "change_audience": ChangeAudiencePath,
		"change_retention": ChangeRetentionPath, "explain_memory": ExplainMemoryPath,
		"list_subject_memories": ListSubjectMemoriesPath, "export_subject": ExportSubjectPath,
		"import_subject": ImportSubjectPath, "create_memory_subject": CreateMemorySubjectPath,
		"create_relationship_space": CreateRelationshipSpacePath,
		"get_continuity_profile":    GetContinuityProfilePath,
		"update_configured_role":    UpdateConfiguredRolePath,
		"migrate_agent_runtime":     MigrateAgentRuntimePath,
		"publish_to_shared_memory":  PublishToSharedMemoryPath,
		"revoke_shared_memory":      RevokeSharedMemoryPath, "ingest_artifact": IngestArtifactPath,
		"attach_artifact_to_episode": AttachArtifactToEpisodePath,
		"add_derived_representation": AddDerivedRepresentationPath,
		"add_evidence_selector":      AddEvidenceSelectorPath,
		"get_artifact_metadata":      GetArtifactMetadataPath,
		"delete_artifact_lineage":    DeleteArtifactLineagePath,
	}
	if !reflect.DeepEqual(fixture.Routes, wantRoutes) {
		t.Fatalf("routes = %#v", fixture.Routes)
	}
	attested := make(map[string]bool, len(fixture.GatewayAttestationRoutes))
	for _, operation := range fixture.GatewayAttestationRoutes {
		attested[operation] = true
	}
	if len(attested) != len(wantRoutes) {
		t.Fatalf("attested routes = %#v", fixture.GatewayAttestationRoutes)
	}
	for operation := range wantRoutes {
		if !attested[operation] {
			t.Fatalf("route %s is not attested", operation)
		}
	}
	if len(fixture.LegacyRoutes) != 6 || len(fixture.AuthenticatedContextRoutes) != 53 {
		t.Fatalf("route auth partition = %d legacy + %d authenticated", len(fixture.LegacyRoutes), len(fixture.AuthenticatedContextRoutes))
	}
	if !reflect.DeepEqual(fixture.UnauthenticatedNonSDKRoutes, map[string]struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Profile string `json:"profile"`
		Claim   string `json:"claim"`
	}{
		"liveness": {
			Method: "GET", Path: "/health/live", Profile: "current-server",
			Claim: "process_router_responsive",
		},
		"readiness": {
			Method: "GET", Path: "/health/ready", Profile: "current-server",
			Claim: "bounded_fjall_publication_and_external_head_reconciliation",
		},
	}) {
		t.Fatalf("non-SDK health routes = %#v", fixture.UnauthenticatedNonSDKRoutes)
	}
	if fixture.HealthBoundary.SDKExposed || fixture.HealthBoundary.GatewayAttestationRequired ||
		!fixture.HealthBoundary.ContentFree || fixture.HealthBoundary.RFC3115Complete ||
		fixture.HealthBoundary.ServerV1ProfileProven {
		t.Fatalf("health boundary overclaims: %#v", fixture.HealthBoundary)
	}
	partition := make(map[string]string, len(wantRoutes))
	for _, operation := range fixture.LegacyRoutes {
		partition[operation] = "legacy"
	}
	for _, operation := range fixture.AuthenticatedContextRoutes {
		if partition[operation] != "" {
			t.Fatalf("route %s appears in both context partitions", operation)
		}
		partition[operation] = "authenticated"
	}
	if len(partition) != len(wantRoutes) {
		t.Fatalf("context route partition = %#v", partition)
	}
	if !reflect.DeepEqual(fixture.Statuses, errorStatuses) {
		t.Fatalf("error statuses = %#v", fixture.Statuses)
	}
	evidence, err := json.Marshal(AuthenticationEvidence{
		Kind: AuthenticationRequestSignature, Algorithm: "ed25519", KeyID: "key-1",
		Signature: strings.Repeat("b", 128), SignedContextDigest: strings.Repeat("c", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(evidence, fixture.SignatureEvidence) {
		t.Fatalf("signature evidence = %s", evidence)
	}
}

func jsonEqual(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil && json.Unmarshal(right, &rightValue) == nil && reflect.DeepEqual(leftValue, rightValue)
}

func TestCanonicalErrorPreservesOptionalContext(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, 403, map[string]any{
			"code": "permission_denied", "message": "denied", "retryable": false,
			"partial_result_refs": []string{"receipt-1"}, "violated_policy": "policy-1",
			"safe_next_action": "request a narrower scope", "trace_id": "trace-error-1",
		})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Recall(context.Background(), RecallRequest{})
	var failure *ServiceError
	if !errors.As(err, &failure) {
		t.Fatalf("error = %T %v", err, err)
	}
	if failure.Status != 403 || failure.Code != ErrorPermissionDenied || failure.ViolatedPolicy == nil || *failure.ViolatedPolicy != "policy-1" {
		t.Fatalf("service error = %#v", failure)
	}
	if !reflect.DeepEqual(failure.PartialResultRefs, []string{"receipt-1"}) || failure.TraceID == nil {
		t.Fatalf("optional context lost: %#v", failure)
	}
}

func TestResponseAndErrorShapesFailClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"unknown success field", 200, `{"valid":true,"commit_seq":1,"archive_digest":null,"extra":1}`},
		{"missing nested watermark", 200, `{"valid":true,"commit_seq":1}`},
		{"null boolean", 200, `{"valid":null,"commit_seq":1,"archive_digest":null}`},
		{"null integer", 200, `{"valid":true,"commit_seq":null,"archive_digest":null}`},
		{"invalid nullable string", 200, `{"valid":true,"commit_seq":1,"archive_digest":false}`},
		{"status mismatch", 409, `{"code":"permission_denied","message":"x","retryable":false}`},
		{"unknown error field", 403, `{"code":"permission_denied","message":"x","retryable":false,"secret":"x"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Verify(context.Background(), VerifyRequest{})
			var protocol *ProtocolError
			if !errors.As(err, &protocol) {
				t.Fatalf("error = %T %v", err, err)
			}
		})
	}
}

func TestNilCollectionsEncodeAsCanonicalEmpty(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		requestContext := body["context"].(map[string]any)
		if !reflect.DeepEqual(requestContext["audiences"], []any{}) || !reflect.DeepEqual(requestContext["scopes"], []any{}) {
			t.Errorf("nil context sets did not become arrays: %#v", requestContext)
		}
		policy := body["access"].(map[string]any)
		if !reflect.DeepEqual(policy["scopes"], []any{}) || !reflect.DeepEqual(policy["audience_purpose_grants"], map[string]any{}) {
			t.Errorf("nil policy collections did not become canonical empties: %#v", policy)
		}
		if !reflect.DeepEqual(body["metadata"], map[string]any{}) {
			t.Errorf("nil metadata did not become object: %#v", body["metadata"])
		}
		writeJSON(t, writer, 200, ObserveResponse{
			CommitSeq: 1, RequestDigest: "digest", Watermarks: testWatermarks(),
		})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Observe(context.Background(), ObserveRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestWireLimitsAndContentType(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "{}")
	}))
	defer server.Close()
	client, err := NewClient(server.URL, &ClientOptions{MaxWireBytes: 2})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Verify(context.Background(), VerifyRequest{Context: testContext()})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || !strings.Contains(protocol.Message, "request exceeds") {
		t.Fatalf("error = %T %v", err, err)
	}

	client, err = NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Verify(context.Background(), VerifyRequest{})
	if !errors.As(err, &protocol) || !strings.Contains(protocol.Message, "Content-Type") {
		t.Fatalf("error = %T %v", err, err)
	}

	largeServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(make([]byte, 1001))
	}))
	defer largeServer.Close()
	client, err = NewClient(largeServer.URL, &ClientOptions{MaxWireBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Verify(context.Background(), VerifyRequest{})
	if !errors.As(err, &protocol) || !strings.Contains(protocol.Message, "response exceeds") {
		t.Fatalf("error = %T %v", err, err)
	}
}

func TestByteArrayRejectsNonOctetsAndBase64(t *testing.T) {
	t.Parallel()
	for _, value := range []string{`[256]`, `[-1]`, `[1.5]`, `"AA=="`, `null`} {
		var bytes ByteArray
		if err := json.Unmarshal([]byte(value), &bytes); err == nil {
			t.Errorf("accepted invalid byte array %s", value)
		}
	}
}

func TestNullRecallScalarFailsClosed(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, 200, map[string]any{
			"hits":  []any{map[string]any{"id": "memory-1", "score": nil}},
			"trace": testTrace(), "continuation": nil,
		})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Recall(context.Background(), RecallRequest{})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) {
		t.Fatalf("error = %T %v", err, err)
	}
}
