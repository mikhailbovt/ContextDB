package contextdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func testAuthenticatedContext() AuthenticatedRequestContext {
	session := "session-1"
	return AuthenticatedRequestContext{
		Request:   testContext(),
		ActorID:   "actor-1",
		AgentID:   "agent-1",
		SessionID: &session,
		CapabilityGrants: []Capability{
			CapabilityAdmin, CapabilityCorrect, CapabilityForget, CapabilityHardDelete,
			CapabilityMaintenance, CapabilityModelProcessing, CapabilityObserve,
			CapabilityRawEvidence, CapabilityReadConflict, CapabilityReadEvidence,
			CapabilityReadMemory, CapabilityRecall, CapabilityRuntime,
			CapabilityStreamIngest, CapabilitySubscribe, CapabilityTraverse,
		},
		Authentication: AuthenticationEvidence{
			Kind: AuthenticationAuthenticatedChannel, ChannelID: "channel-1",
			PeerIdentity: "actor-1", BindingDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
}

func testMemoryDocument(t *testing.T) MemoryDocument {
	t.Helper()
	from, err := NewInt128("-1")
	if err != nil {
		t.Fatal(err)
	}
	search := "hello"
	return MemoryDocument{
		ID: "memory-1", Kind: MemoryRecordNode, Access: testAccess(),
		ValidTime: DomainTimeRange{From: &from}, Lifecycle: MemoryActive,
		Links: MemoryLinks{Supersedes: []string{}, Evidence: []string{}, ConflictMembers: []string{}},
		Value: map[string]any{"text": "hello"}, SearchText: &search,
		Vector: []float32{0.25, 0.5}, Attributes: map[string]any{"source": "test"},
	}
}

func testMemoryRecord(t *testing.T) MemoryRecord {
	t.Helper()
	return MemoryRecord{Document: testMemoryDocument(t), Revision: 1, TransactionFrom: 7}
}

func TestAuthenticatedHTTPV1RoutesBodiesResponsesAndHeaderProvider(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var paths []string
	attestations := map[string]bool{}
	providerCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		paths = append(paths, request.URL.Path)
		attestations[request.Header.Get("x-contextdb-gateway-attestation")] = true
		mu.Unlock()
		if request.Header.Get("x-contextdb-gateway-id") != "gateway-1" || !strings.HasPrefix(request.Header.Get("x-contextdb-gateway-attestation"), "ephemeral-") {
			t.Errorf("gateway headers are missing or stale")
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		contextObject, _ := body["context"].(map[string]any)
		if contextObject != nil {
			authentication, _ := contextObject["authentication"].(map[string]any)
			if authentication["kind"] != "authenticated_channel" {
				t.Errorf("authentication DTO missing: %#v", body)
			}
		}
		switch request.URL.Path {
		case IngestFramePath:
			writeJSON(t, writer, 200, IngestAck{StreamID: "stream-1", Disposition: IngestAccepted, FrameDigest: "frame", ResumeCursor: "cursor", PartialResultRefs: []string{}})
		case CorrectPath, ForgetPath:
			writeJSON(t, writer, 200, MutationResponse{CommitSeq: 7, RequestDigest: "digest", Watermarks: testWatermarks()})
		case SubscribePath:
			writeJSON(t, writer, 200, SubscriptionPage{Events: []MemoryEvent{{EventID: "event-1", CommitSeq: 7, Kind: MemoryEventRecordChanged, ObjectRefs: []string{"memory-1"}, Attributes: map[string]string{}}}, ResumeCursor: "cursor", CaughtUp: true})
		case GetNodePath, GetEvidencePath, GetConflictPath:
			writeJSON(t, writer, 200, testMemoryRecord(t))
		case TraversePath:
			writeJSON(t, writer, 200, TraverseResponse{NodeIDs: []string{"memory-1"}, SnapshotSeq: 7, AuthorizedCandidates: 1, Watermarks: testWatermarks()})
		case GetTimelinePath:
			writeJSON(t, writer, 200, TimelineResponse{Revisions: []MemoryRecord{testMemoryRecord(t)}, SnapshotSeq: 7, Watermarks: testWatermarks()})
		case BootstrapPath, PreflightPath, PostflightPath, CheckpointPath, ResumePath, HandoffPath:
			writeJSON(t, writer, 200, RuntimeResponse{OperationID: "operation-1", Payload: map[string]any{"ok": true}})
		case ConsolidatePath, ReflectPath, ReindexPath, CompactPath:
			writeJSON(t, writer, 200, MaintenanceResponse{OperationID: "operation-1", Payload: map[string]any{"ok": true}})
		case GetStatusPath, MigrateFormatPath:
			writeJSON(t, writer, 200, StatusResponse{
				SchemaVersion: 1,
				Profile:       "reference",
				CommitSeq:     7,
				Watermarks:    testWatermarks(),
				CapabilityManifest: CapabilityManifestV1{
					SchemaVersion:        1,
					Profile:              "reference",
					ServerV1ReleaseReady: false,
					Capabilities: map[string]RuntimeCapabilityState{
						"background_semantic_adjudication":      RuntimeCapabilityUnsupported,
						CandidateCapabilityHierarchyDAG:         RuntimeCapabilityUnsupported,
						CandidateCapabilityPolicyFirstRecall:    RuntimeCapabilityUnsupported,
						CandidateCapabilityPolicyFirstTraversal: RuntimeCapabilityUnsupported,
						CandidateCapabilityQuarantinedProposals: RuntimeCapabilityUnsupported,
						"consolidate":                           RuntimeCapabilityUnsupported,
						"hard_delete":                           RuntimeCapabilityUnsupported,
						"native_graph_store":                    RuntimeCapabilityUnsupported,
						"observation_semantic_extraction":       RuntimeCapabilityUnsupported,
						"reflect":                               RuntimeCapabilityUnsupported,
						"status":                                RuntimeCapabilityAvailable,
					},
				},
			})
		case CreateBackupPath:
			writeJSON(t, writer, 200, BackupResponse{Format: "contextdb-logical-v1", Bytes: ByteArray{0, 127, 255}, Digest: "archive", CommitSeq: 7})
		case RestoreBackupPath:
			if !reflect.DeepEqual(body["bytes"], []any{float64(0), float64(127), float64(255)}) {
				t.Errorf("restore bytes = %#v", body["bytes"])
			}
			writeJSON(t, writer, 200, RestoreBackupResponse{CommitSeq: 7, Watermarks: testWatermarks()})
		default:
			t.Errorf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, &ClientOptions{HeaderProvider: func(_ context.Context, request HeaderProviderRequest) (http.Header, error) {
		providerCalls++
		if request.Path == "" || len(request.Body) == 0 {
			t.Errorf("provider did not receive exact request")
		}
		return http.Header{"x-contextdb-gateway-id": {"gateway-1"}, "x-contextdb-gateway-attestation": {fmt.Sprintf("ephemeral-%d", providerCalls)}, "Content-Type": {"text/plain"}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	auth := testAuthenticatedContext()
	document := testMemoryDocument(t)
	manifest := SourceRevisionManifest{SourceID: "source-1", RevisionID: "revision-1", SnapshotID: "snapshot-1", OrderedItemsDigest: "digest", Compression: CompressionIdentity}
	if _, err := client.IngestFrame(ctx, IngestFrame{Context: auth, StreamID: "stream-1", Value: IngestFrameValue{Kind: IngestFrameManifest, Value: manifest}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Correct(ctx, CorrectRequest{Context: auth, IdempotencyKey: "key", TargetID: "memory-0", Replacement: document}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Forget(ctx, ForgetRequest{Context: auth, IdempotencyKey: "key", TargetID: "memory-1", Mode: ForgetRetract, Reason: "requested"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Subscribe(ctx, SubscribeRequest{Context: auth, Filters: []MemoryEventKind{MemoryEventRecordChanged}, MaxEvents: 20}); err != nil {
		t.Fatal(err)
	}
	get := GetMemoryRequest{Context: auth, RecordID: "memory-1"}
	if _, err := client.GetNode(ctx, get); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Traverse(ctx, TraverseRequest{Context: auth, StartIDs: []string{"memory-1"}, Direction: TraverseBoth, MaxHops: 2, MaxNodes: 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTimeline(ctx, GetTimelineRequest{Context: auth, RecordID: "memory-1", ExpectedKind: MemoryRecordNode, MaxRevisions: 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetEvidence(ctx, get); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetConflict(ctx, get); err != nil {
		t.Fatal(err)
	}
	runtimeRequest := RuntimeRequest{Context: auth, OperationID: "operation-1", Payload: map[string]any{"input": true}}
	for name, call := range map[string]func() error{
		"bootstrap":  func() error { _, err := client.Bootstrap(ctx, runtimeRequest); return err },
		"preflight":  func() error { _, err := client.Preflight(ctx, runtimeRequest); return err },
		"postflight": func() error { _, err := client.Postflight(ctx, runtimeRequest); return err },
		"checkpoint": func() error { _, err := client.Checkpoint(ctx, runtimeRequest); return err },
		"resume":     func() error { _, err := client.Resume(ctx, runtimeRequest); return err },
		"handoff":    func() error { _, err := client.Handoff(ctx, runtimeRequest); return err },
	} {
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	maintenance := MaintenanceRequest{Context: auth, OperationID: "operation-1", Payload: map[string]any{"input": true}}
	for name, call := range map[string]func() error{
		"consolidate": func() error { _, err := client.Consolidate(ctx, maintenance); return err },
		"reflect":     func() error { _, err := client.Reflect(ctx, maintenance); return err },
		"reindex":     func() error { _, err := client.Reindex(ctx, maintenance); return err },
		"compact":     func() error { _, err := client.Compact(ctx, maintenance); return err },
	} {
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := client.GetStatus(ctx, GetStatusRequest{Context: auth}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateBackup(ctx, CreateBackupRequest{Context: auth}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RestoreBackup(ctx, RestoreBackupRequest{Context: auth, Format: "contextdb-logical-v1", Bytes: ByteArray{0, 127, 255}, Digest: "archive"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.MigrateFormat(ctx, MigrateFormatRequest{Context: auth, TargetFormat: "contextdb-logical-v1", OperationID: "operation-1"}); err != nil {
		t.Fatal(err)
	}
	if providerCalls != 23 || len(paths) != 23 || len(attestations) != 23 {
		t.Fatalf("provider calls=%d paths=%d fresh attestations=%d", providerCalls, len(paths), len(attestations))
	}
}

func TestAuthenticatedNestedResponseAndInt128FailClosed(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"170141183460469231731687303715884105727",
		"-170141183460469231731687303715884105728",
	} {
		parsed, err := NewInt128(value)
		if err != nil || string(parsed) != value {
			t.Fatalf("Int128 %s: %v", value, err)
		}
	}
	for _, value := range []string{"01", "-0", "170141183460469231731687303715884105728"} {
		if _, err := NewInt128(value); err == nil {
			t.Fatalf("accepted invalid i128 %s", value)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		record := testMemoryRecord(t)
		data, _ := json.Marshal(record)
		var value map[string]any
		_ = json.Unmarshal(data, &value)
		document := value["document"].(map[string]any)
		document["secret"] = "must fail"
		writeJSON(t, writer, 200, value)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetNode(context.Background(), GetMemoryRequest{Context: testAuthenticatedContext()})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) {
		t.Fatalf("error = %T %v", err, err)
	}
}

func TestU64ResponseBoundaryIsExact(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"valid":true,"commit_seq":18446744073709551615,"archive_digest":null}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Verify(context.Background(), VerifyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.CommitSeq != ^uint64(0) {
		t.Fatalf("commit sequence = %d", response.CommitSeq)
	}
}

func TestIngestAckLeaseDeadlineIsAdditiveAndU64Exact(t *testing.T) {
	t.Parallel()
	parse := func(raw string) (IngestAck, error) {
		object, err := decodeObject([]byte(raw), http.StatusOK)
		if err != nil {
			return IngestAck{}, err
		}
		if err := validateIngestAck(object); err != nil {
			return IngestAck{}, err
		}
		var acknowledgement IngestAck
		if err := strictDecode([]byte(raw), &acknowledgement); err != nil {
			return IngestAck{}, err
		}
		return acknowledgement, nil
	}

	legacyWire := `{"stream_id":"stream-1","position":0,"disposition":"accepted","frame_digest":"frame","resume_cursor":"cursor","commit_seq":null,"partial_result_refs":[]}`
	legacy, err := parse(legacyWire)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.LeaseExpiresAtMS != nil {
		t.Fatalf("legacy deadline = %v", *legacy.LeaseExpiresAtMS)
	}
	serializedLegacy, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serializedLegacy), "lease_expires_at_ms") {
		t.Fatalf("legacy acknowledgement serialized a deadline: %s", serializedLegacy)
	}

	leasedWire := `{"stream_id":"stream-1","position":0,"disposition":"accepted","frame_digest":"frame","resume_cursor":"cursor","commit_seq":null,"partial_result_refs":[],"lease_expires_at_ms":18446744073709551615}`
	leased, err := parse(leasedWire)
	if err != nil {
		t.Fatal(err)
	}
	if leased.LeaseExpiresAtMS == nil || *leased.LeaseExpiresAtMS != ^uint64(0) {
		t.Fatalf("leased deadline = %v", leased.LeaseExpiresAtMS)
	}
	serializedLeased, err := json.Marshal(leased)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(serializedLeased), `"lease_expires_at_ms":18446744073709551615`) {
		t.Fatalf("leased acknowledgement lost exact deadline: %s", serializedLeased)
	}

	for _, invalid := range []string{
		`{"stream_id":"stream-1","position":0,"disposition":"accepted","frame_digest":"frame","resume_cursor":"cursor","commit_seq":null,"partial_result_refs":[],"lease_expires_at_ms":-1}`,
		`{"stream_id":"stream-1","position":0,"disposition":"accepted","frame_digest":"frame","resume_cursor":"cursor","commit_seq":null,"partial_result_refs":[],"lease_expires_at_ms":18446744073709551616}`,
		`{"stream_id":"stream-1","position":0,"disposition":"accepted","frame_digest":"frame","resume_cursor":"cursor","commit_seq":null,"partial_result_refs":[],"lease_expires_at_ms":null}`,
		`{"stream_id":"stream-1","position":0,"disposition":"accepted","frame_digest":"frame","resume_cursor":"cursor","commit_seq":null,"partial_result_refs":[],"unexpected":1}`,
	} {
		if _, err := parse(invalid); err == nil {
			t.Fatalf("accepted invalid acknowledgement: %s", invalid)
		}
	}
}

func TestStatusCapabilityManifestFailsClosed(t *testing.T) {
	t.Parallel()
	validate := func(raw string) error {
		object, err := decodeObject([]byte(raw), http.StatusOK)
		if err != nil {
			return err
		}
		return validateStatusResponse(object)
	}
	const prefix = `{"schema_version":1,"profile":"reference","commit_seq":1,"watermarks":{"journal":1,"semantic":1,"lexical":1,"vector":1,"graph":1},"capability_manifest":`
	if err := validate(prefix + `{"schema_version":1,"profile":"different","server_v1_release_ready":false,"capabilities":{"status":"available"}}}`); err == nil {
		t.Fatal("mismatched profile accepted")
	}
	if err := validate(prefix + `{"schema_version":1,"profile":"reference","server_v1_release_ready":false,"capabilities":{"status":"maybe"}}}`); err == nil {
		t.Fatal("unknown capability state accepted")
	}
	if err := validate(prefix + `{"schema_version":2,"profile":"reference","server_v1_release_ready":false,"capabilities":{"status":"available"}}}`); err == nil {
		t.Fatal("unknown capability schema accepted")
	}
}

func TestDeploymentHeadersCannotOverrideHTTPFraming(t *testing.T) {
	t.Parallel()
	if _, err := NewClient("https://contextdb.invalid", &ClientOptions{
		Headers: http.Header{"Content-Length": {"1"}},
	}); err == nil {
		t.Fatal("accepted static Content-Length")
	}
	if _, err := NewClient("https://contextdb.invalid", &ClientOptions{
		Headers: http.Header{"x-contextdb-gateway-attestation": {"must-not-be-retained"}},
	}); err == nil {
		t.Fatal("accepted static gateway attestation")
	}
	client, err := NewClient("https://contextdb.invalid", &ClientOptions{
		HeaderProvider: func(context.Context, HeaderProviderRequest) (http.Header, error) {
			return http.Header{"Transfer-Encoding": {"chunked"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Verify(context.Background(), VerifyRequest{})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) {
		t.Fatalf("error = %T %v", err, err)
	}
}

func TestAuthenticatedDTOCannotDeriveGatewayHeadersAndProviderFailureStopsSend(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("x-contextdb-gateway-id") != "" || request.Header.Get("x-contextdb-gateway-attestation") != "" {
			t.Errorf("SDK derived gateway headers from application DTO")
		}
		writeJSON(t, writer, 200, IngestAck{
			StreamID: "stream-1", Disposition: IngestAccepted, FrameDigest: "frame",
			ResumeCursor: "cursor", PartialResultRefs: []string{},
		})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.IngestFrame(context.Background(), IngestFrame{
		Context: testAuthenticatedContext(), StreamID: "stream-1",
		Value: IngestFrameValue{Kind: IngestFrameManifest, Value: SourceRevisionManifest{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d", requests)
	}

	failedClient, err := NewClient(server.URL, &ClientOptions{
		HeaderProvider: func(context.Context, HeaderProviderRequest) (http.Header, error) {
			return nil, errors.New("no attestation")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = failedClient.IngestFrame(context.Background(), IngestFrame{
		Context: testAuthenticatedContext(), StreamID: "stream-1",
		Value: IngestFrameValue{Kind: IngestFrameManifest, Value: SourceRevisionManifest{}},
	})
	var transport *TransportError
	if !errors.As(err, &transport) || requests != 1 {
		t.Fatalf("provider failure error=%v requests=%d", err, requests)
	}
}

func TestLegacyRouteUsesFreshOperationAwareHeaderProvider(t *testing.T) {
	t.Parallel()
	providerCalls := 0
	providerBodies := make([]string, 0, 2)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != VerifyPath {
			t.Errorf("path = %s", request.URL.Path)
		}
		if request.Header.Get("x-contextdb-gateway-id") != "gateway-1" || request.Header.Get("x-contextdb-gateway-attestation") != fmt.Sprintf("ephemeral-%d", requests) {
			t.Errorf("gateway headers do not match request %d", requests)
		}
		wireBody, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		} else if string(wireBody) != providerBodies[requests-1] {
			t.Errorf("provider body differs from outgoing body")
		}
		writeJSON(t, writer, 200, VerifyResponse{Valid: true})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, &ClientOptions{
		HeaderProvider: func(_ context.Context, request HeaderProviderRequest) (http.Header, error) {
			providerCalls++
			providerBodies = append(providerBodies, string(request.Body))
			if request.Path != VerifyPath {
				t.Errorf("provider path = %s", request.Path)
			}
			var body VerifyRequest
			if err := json.Unmarshal(request.Body, &body); err != nil {
				t.Errorf("provider body: %v", err)
			}
			if body.Context.WorkspaceID != testContext().WorkspaceID {
				t.Errorf("provider did not receive the exact legacy context")
			}
			return http.Header{
				"x-contextdb-gateway-id":          {"gateway-1"},
				"x-contextdb-gateway-attestation": {fmt.Sprintf("ephemeral-%d", providerCalls)},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.Verify(context.Background(), VerifyRequest{Context: testContext(), Deep: true}); err != nil {
			t.Fatal(err)
		}
	}
	if providerCalls != 2 || requests != 2 {
		t.Fatalf("provider calls=%d requests=%d", providerCalls, requests)
	}
}
