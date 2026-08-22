package contextdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	MaxWireBytes                 int64 = 16 * 1024 * 1024
	ObservePath                        = "/v1/observations"
	IngestFramePath                    = "/v1/observations/ingest-frame"
	CorrectPath                        = "/v1/observations/correct"
	ForgetPath                         = "/v1/observations/forget"
	RecallPath                         = "/v1/recall"
	ExplainRecallPath                  = "/v1/recall/explain"
	SubscribePath                      = "/v1/subscriptions/page"
	GetNodePath                        = "/v1/memory/node"
	TraversePath                       = "/v1/memory/traverse"
	GetTimelinePath                    = "/v1/memory/timeline"
	GetEvidencePath                    = "/v1/memory/evidence"
	GetConflictPath                    = "/v1/memory/conflict"
	BootstrapPath                      = "/v1/runtime/bootstrap"
	PreflightPath                      = "/v1/runtime/preflight"
	PostflightPath                     = "/v1/runtime/postflight"
	CheckpointPath                     = "/v1/runtime/checkpoint"
	ResumePath                         = "/v1/runtime/resume"
	HandoffPath                        = "/v1/runtime/handoff"
	ConsolidatePath                    = "/v1/maintenance/consolidate"
	ReflectPath                        = "/v1/maintenance/reflect"
	ReindexPath                        = "/v1/maintenance/reindex"
	CompactPath                        = "/v1/maintenance/compact"
	GetStatusPath                      = "/v1/admin/status"
	CreateBackupPath                   = "/v1/admin/backup"
	RestoreBackupPath                  = "/v1/admin/restore"
	MigrateFormatPath                  = "/v1/admin/migrate"
	ExportPath                         = "/v1/archive/export"
	ImportPath                         = "/v1/archive/import"
	VerifyPath                         = "/v1/verify"
	BeginSessionPath                   = "/v1/conversation/begin-session"
	BeforeTurnPath                     = "/v1/conversation/before-turn"
	AfterTurnPath                      = "/v1/conversation/after-turn"
	ResolveReferentPath                = "/v1/conversation/resolve-referent"
	RecallSharedHistoryPath            = "/v1/conversation/recall-shared-history"
	EndSessionPath                     = "/v1/conversation/end-session"
	BootstrapSubjectPath               = "/v1/conversation/bootstrap-subject"
	RememberPath                       = "/v1/memory/remember"
	PinPath                            = "/v1/memory/pin"
	SuppressPath                       = "/v1/memory/suppress"
	ChangeAudiencePath                 = "/v1/memory/change-audience"
	ChangeRetentionPath                = "/v1/memory/change-retention"
	ExplainMemoryPath                  = "/v1/memory/explain"
	ListSubjectMemoriesPath            = "/v1/memory/list-subject"
	ExportSubjectPath                  = "/v1/memory/export-subject"
	ImportSubjectPath                  = "/v1/memory/import-subject"
	CreateMemorySubjectPath            = "/v1/subjects/create"
	CreateRelationshipSpacePath        = "/v1/relationship-spaces/create"
	GetContinuityProfilePath           = "/v1/subjects/continuity-profile"
	UpdateConfiguredRolePath           = "/v1/subjects/configured-role/update"
	MigrateAgentRuntimePath            = "/v1/subjects/agent-runtime/migrate"
	PublishToSharedMemoryPath          = "/v1/shared-memory/publish"
	RevokeSharedMemoryPath             = "/v1/shared-memory/revoke"
	IngestArtifactPath                 = "/v1/artifacts/ingest"
	AttachArtifactToEpisodePath        = "/v1/artifacts/attach-to-episode"
	AddDerivedRepresentationPath       = "/v1/artifacts/derived-representations"
	AddEvidenceSelectorPath            = "/v1/artifacts/evidence-selectors"
	GetArtifactMetadataPath            = "/v1/artifacts/metadata"
	DeleteArtifactLineagePath          = "/v1/artifacts/delete-lineage"
)

// HTTPDoer makes the transport replaceable in tests and custom deployments.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// HeaderProviderRequest contains exact canonical HTTP material for one
// deployment-attestation decision. Body is a private copy so a provider cannot
// mutate the outgoing request body.
type HeaderProviderRequest struct {
	Path string
	Body []byte
}

// HeaderProvider returns ephemeral deployment headers for one exact request.
// It can produce gateway ID/attestation values without retaining them in Client.
// AuthenticatedRequestContext is never used implicitly by this SDK as proof.
type HeaderProvider func(context.Context, HeaderProviderRequest) (http.Header, error)

// ClientOptions configures only transport concerns. Authentication remains
// deployment-owned and optional.
type ClientOptions struct {
	HTTPClient     HTTPDoer
	Headers        http.Header
	BearerToken    string
	MaxWireBytes   int64
	HeaderProvider HeaderProvider
}

// Client is the canonical v1 HTTP/JSON client.
type Client struct {
	baseURL        string
	httpClient     HTTPDoer
	headers        http.Header
	maxWireBytes   int64
	headerProvider HeaderProvider
}

func NewClient(baseURL string, options *ClientOptions) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("base URL must be an absolute http(s) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("base URL must not contain credentials, query, or fragment")
	}
	configured := ClientOptions{}
	if options != nil {
		configured = *options
	}
	if configured.MaxWireBytes == 0 {
		configured.MaxWireBytes = MaxWireBytes
	}
	if configured.MaxWireBytes < 1 {
		return nil, errors.New("max wire bytes must be positive")
	}
	if strings.ContainsAny(configured.BearerToken, "\r\n") {
		return nil, errors.New("bearer token contains a newline")
	}
	headers := make(http.Header, len(configured.Headers)+1)
	for key, values := range configured.Headers {
		if key == "" || strings.ContainsAny(key, "\r\n") {
			return nil, errors.New("invalid HTTP header name")
		}
		if forbiddenFramingHeader(key) {
			return nil, errors.New("deployment headers must not set HTTP framing headers")
		}
		if strings.EqualFold(key, "x-contextdb-gateway-attestation") {
			return nil, errors.New("gateway attestation must be supplied by HeaderProvider")
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return nil, errors.New("invalid HTTP header value")
			}
		}
		headers[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}
	if configured.BearerToken != "" {
		headers.Set("Authorization", "Bearer "+configured.BearerToken)
	}
	client := configured.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Client{
		baseURL:        strings.TrimRight(baseURL, "/"),
		httpClient:     client,
		headers:        headers,
		maxWireBytes:   configured.MaxWireBytes,
		headerProvider: configured.HeaderProvider,
	}, nil
}

func (client *Client) Observe(ctx context.Context, request ObserveRequest) (ObserveResponse, error) {
	request.Context = normalizeRequestContext(request.Context)
	request.Access = normalizeAccessPolicy(request.Access)
	request.Access = sortAccessPolicy(request.Access)
	if request.Metadata == nil {
		request.Metadata = map[string]any{}
	}
	var response ObserveResponse
	err := client.post(ctx, ObservePath, request, &response, validateObserveResponse)
	return response, err
}

func (client *Client) Recall(ctx context.Context, request RecallRequest) (RecallResponse, error) {
	request.Context = normalizeRequestContext(request.Context)
	var response RecallResponse
	err := client.post(ctx, RecallPath, request, &response, validateRecallResponse)
	return response, err
}

func (client *Client) ExplainRecall(ctx context.Context, request ExplainRecallRequest) (RecallTrace, error) {
	request.Context = normalizeRequestContext(request.Context)
	if request.Trace.SelectedIDs == nil {
		request.Trace.SelectedIDs = []string{}
	}
	var response RecallTrace
	err := client.post(ctx, ExplainRecallPath, request, &response, validateRecallTrace)
	return response, err
}

func (client *Client) ExportArchive(ctx context.Context, request ExportRequest) (ExportResponse, error) {
	request.Context = normalizeRequestContext(request.Context)
	var response ExportResponse
	err := client.post(ctx, ExportPath, request, &response, validateExportResponse)
	return response, err
}

func (client *Client) ImportArchive(ctx context.Context, request ImportRequest) (ImportResponse, error) {
	request.Context = normalizeRequestContext(request.Context)
	var response ImportResponse
	err := client.post(ctx, ImportPath, request, &response, validateImportResponse)
	return response, err
}

func (client *Client) Verify(ctx context.Context, request VerifyRequest) (VerifyResponse, error) {
	request.Context = normalizeRequestContext(request.Context)
	var response VerifyResponse
	err := client.post(ctx, VerifyPath, request, &response, validateVerifyResponse)
	return response, err
}

func normalizeRequestContext(value RequestContext) RequestContext {
	if value.Audiences == nil {
		value.Audiences = []string{}
	} else {
		value.Audiences = append([]string(nil), value.Audiences...)
	}
	if value.Scopes == nil {
		value.Scopes = []string{}
	} else {
		value.Scopes = append([]string(nil), value.Scopes...)
	}
	sort.Strings(value.Audiences)
	sort.Strings(value.Scopes)
	return value
}

func normalizeAccessPolicy(value AccessPolicy) AccessPolicy {
	if value.Scopes == nil {
		value.Scopes = []string{}
	} else {
		value.Scopes = append([]string(nil), value.Scopes...)
	}
	if value.Owners == nil {
		value.Owners = []string{}
	} else {
		value.Owners = append([]string(nil), value.Owners...)
	}
	if value.Audience == nil {
		value.Audience = []string{}
	} else {
		value.Audience = append([]string(nil), value.Audience...)
	}
	if value.Purposes == nil {
		value.Purposes = []string{}
	} else {
		value.Purposes = append([]string(nil), value.Purposes...)
	}
	if value.AudiencePurposeGrants == nil {
		value.AudiencePurposeGrants = map[string][]string{}
	} else {
		grants := make(map[string][]string, len(value.AudiencePurposeGrants))
		for audience, purposes := range value.AudiencePurposeGrants {
			if purposes == nil {
				grants[audience] = []string{}
			} else {
				grants[audience] = append([]string(nil), purposes...)
			}
		}
		value.AudiencePurposeGrants = grants
	}
	return sortAccessPolicy(value)
}

type shapeValidator func(map[string]any) error

func (client *Client) post(
	ctx context.Context,
	path string,
	requestValue any,
	responseValue any,
	validate shapeValidator,
) error {
	body, err := json.Marshal(requestValue)
	if err != nil {
		return fmt.Errorf("encode ContextDB request: %w", err)
	}
	if int64(len(body)) > client.maxWireBytes {
		return &ProtocolError{Message: "request exceeds the configured wire limit"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create ContextDB request: %w", err)
	}
	request.Header = client.headers.Clone()
	if client.headerProvider != nil {
		dynamic, providerErr := client.headerProvider(ctx, HeaderProviderRequest{
			Path: path,
			Body: append([]byte(nil), body...),
		})
		if providerErr != nil {
			return &TransportError{Cause: providerErr}
		}
		for key, values := range dynamic {
			if key == "" || strings.ContainsAny(key, "\r\n") {
				return &ProtocolError{Message: "header provider returned an invalid HTTP header"}
			}
			if forbiddenFramingHeader(key) {
				return &ProtocolError{Message: "header provider returned a forbidden framing header"}
			}
			for _, value := range values {
				if strings.ContainsAny(value, "\r\n") {
					return &ProtocolError{Message: "header provider returned an invalid HTTP header"}
				}
			}
			request.Header[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
		}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return &TransportError{Cause: err}
	}
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return &ProtocolError{Message: "response Content-Type is not application/json", Status: response.StatusCode}
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, client.maxWireBytes+1))
	if err != nil {
		return &TransportError{Cause: err}
	}
	if int64(len(responseBody)) > client.maxWireBytes {
		return &ProtocolError{Message: "response exceeds the configured wire limit", Status: response.StatusCode}
	}
	if response.StatusCode != http.StatusOK {
		return decodeServiceError(responseBody, response.StatusCode)
	}
	object, err := decodeObject(responseBody, response.StatusCode)
	if err != nil {
		return err
	}
	if err := validate(object); err != nil {
		return &ProtocolError{Message: err.Error(), Status: response.StatusCode}
	}
	if err := strictDecode(responseBody, responseValue); err != nil {
		return &ProtocolError{Message: "invalid ContextDB response: " + err.Error(), Status: response.StatusCode}
	}
	return nil
}

func forbiddenFramingHeader(key string) bool {
	switch strings.ToLower(key) {
	case "host", "content-length", "transfer-encoding":
		return true
	default:
		return false
	}
}

func strictDecode(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	// Preserve arbitrary payload integers as json.Number instead of silently
	// rounding them through float64. Typed u64 fields still decode to uint64.
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeObject(data []byte, status int) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, &ProtocolError{Message: "response is not valid JSON", Status: status}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, &ProtocolError{Message: "response has multiple JSON values", Status: status}
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, &ProtocolError{Message: "response JSON must be an object", Status: status}
	}
	return object, nil
}

func requireKeys(object map[string]any, required ...string) error {
	if len(object) != len(required) {
		return errors.New("response object has missing or unknown fields")
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return errors.New("response object has missing or unknown fields")
		}
	}
	return nil
}

func nestedObject(value any, name string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return object, nil
}

func validateWatermarks(value any) error {
	object, err := nestedObject(value, "watermarks")
	if err != nil {
		return err
	}
	if err := requireKeys(object, "journal", "semantic", "lexical", "vector", "graph"); err != nil {
		return err
	}
	for _, key := range []string{"journal", "semantic", "lexical", "vector", "graph"} {
		if err := requireUint(object[key], "watermarks."+key); err != nil {
			return err
		}
	}
	return nil
}

func validateObserveResponse(object map[string]any) error {
	if err := requireKeys(object, "commit_seq", "replayed", "request_digest", "watermarks"); err != nil {
		return err
	}
	if err := requireUint(object["commit_seq"], "commit_seq"); err != nil {
		return err
	}
	if _, ok := object["replayed"].(bool); !ok {
		return errors.New("replayed must be a boolean")
	}
	if _, ok := object["request_digest"].(string); !ok {
		return errors.New("request_digest must be a string")
	}
	return validateWatermarks(object["watermarks"])
}

func validateRecallTrace(object map[string]any) error {
	if err := requireKeys(object, "trace_id", "snapshot_seq", "operation", "authorized_candidates", "selected_ids", "watermarks"); err != nil {
		return err
	}
	for _, key := range []string{"trace_id", "operation"} {
		if _, ok := object[key].(string); !ok {
			return fmt.Errorf("%s must be a string", key)
		}
	}
	for _, key := range []string{"snapshot_seq", "authorized_candidates"} {
		if err := requireUint(object[key], key); err != nil {
			return err
		}
	}
	if err := requireStringArray(object["selected_ids"], "selected_ids"); err != nil {
		return err
	}
	return validateWatermarks(object["watermarks"])
}

func validateRecallResponse(object map[string]any) error {
	if err := requireKeys(object, "hits", "trace", "continuation"); err != nil {
		return err
	}
	hits, ok := object["hits"].([]any)
	if !ok {
		return errors.New("hits must be an array")
	}
	for _, value := range hits {
		hit, err := nestedObject(value, "recall hit")
		if err != nil {
			return err
		}
		if err := requireKeys(hit, "id", "score"); err != nil {
			return err
		}
		if _, ok := hit["id"].(string); !ok {
			return errors.New("recall hit id must be a string")
		}
		if err := requireFiniteF32(hit["score"], "recall hit score"); err != nil {
			return err
		}
	}
	if continuation := object["continuation"]; continuation != nil {
		if _, ok := continuation.(string); !ok {
			return errors.New("continuation must be a string or null")
		}
	}
	trace, err := nestedObject(object["trace"], "trace")
	if err != nil {
		return err
	}
	return validateRecallTrace(trace)
}

func validateExportResponse(object map[string]any) error {
	if err := requireKeys(object, "format", "bytes", "digest", "commit_seq"); err != nil {
		return err
	}
	for _, key := range []string{"format", "digest"} {
		if _, ok := object[key].(string); !ok {
			return fmt.Errorf("%s must be a string", key)
		}
	}
	if err := requireUint(object["commit_seq"], "commit_seq"); err != nil {
		return err
	}
	items, ok := object["bytes"].([]any)
	if !ok {
		return errors.New("archive bytes must be an array")
	}
	for _, item := range items {
		number, ok := item.(json.Number)
		if !ok {
			return errors.New("archive byte must be an integer")
		}
		if _, err := strconv.ParseUint(number.String(), 10, 8); err != nil {
			return errors.New("archive byte must be between 0 and 255")
		}
	}
	return nil
}

func validateImportResponse(object map[string]any) error {
	if err := requireKeys(object, "commit_seq", "watermarks"); err != nil {
		return err
	}
	if err := requireUint(object["commit_seq"], "commit_seq"); err != nil {
		return err
	}
	return validateWatermarks(object["watermarks"])
}

func validateVerifyResponse(object map[string]any) error {
	if err := requireKeys(object, "valid", "commit_seq", "archive_digest"); err != nil {
		return err
	}
	if _, ok := object["valid"].(bool); !ok {
		return errors.New("valid must be a boolean")
	}
	if err := requireUint(object["commit_seq"], "commit_seq"); err != nil {
		return err
	}
	if digest := object["archive_digest"]; digest != nil {
		if _, ok := digest.(string); !ok {
			return errors.New("archive_digest must be a string or null")
		}
	}
	return nil
}

func requireUint(value any, name string) error {
	number, ok := value.(json.Number)
	if !ok {
		return fmt.Errorf("%s must be an unsigned integer", name)
	}
	if _, err := strconv.ParseUint(number.String(), 10, 64); err != nil {
		return fmt.Errorf("%s must be an unsigned integer", name)
	}
	return nil
}

func requireFiniteF32(value any, name string) error {
	number, ok := value.(json.Number)
	if !ok {
		return fmt.Errorf("%s must be a finite number", name)
	}
	if _, err := strconv.ParseFloat(number.String(), 32); err != nil {
		return fmt.Errorf("%s must be a finite f32 number", name)
	}
	return nil
}

func requireStringArray(value any, name string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s must be a string array", name)
	}
	for _, item := range items {
		if _, ok := item.(string); !ok {
			return fmt.Errorf("%s must be a string array", name)
		}
	}
	return nil
}

func decodeServiceError(data []byte, status int) error {
	object, err := decodeObject(data, status)
	if err != nil {
		return err
	}
	required := map[string]bool{"code": true, "message": true, "retryable": true}
	optional := map[string]bool{
		"partial_result_refs": true,
		"violated_policy":     true,
		"safe_next_action":    true,
		"trace_id":            true,
	}
	for key := range required {
		if _, ok := object[key]; !ok {
			return &ProtocolError{Message: "invalid ContextDB error envelope", Status: status}
		}
	}
	for key := range object {
		if !required[key] && !optional[key] {
			return &ProtocolError{Message: "invalid ContextDB error envelope", Status: status}
		}
	}
	if _, ok := object["code"].(string); !ok {
		return &ProtocolError{Message: "invalid error code", Status: status}
	}
	if _, ok := object["message"].(string); !ok {
		return &ProtocolError{Message: "invalid error message", Status: status}
	}
	if _, ok := object["retryable"].(bool); !ok {
		return &ProtocolError{Message: "invalid retryable flag", Status: status}
	}
	if refs, present := object["partial_result_refs"]; present {
		items, ok := refs.([]any)
		if !ok {
			return &ProtocolError{Message: "invalid partial_result_refs", Status: status}
		}
		for _, item := range items {
			if _, ok := item.(string); !ok {
				return &ProtocolError{Message: "invalid partial_result_refs", Status: status}
			}
		}
	}
	var failure ServiceError
	if err := strictDecode(data, &failure); err != nil {
		return &ProtocolError{Message: "invalid ContextDB error envelope: " + err.Error(), Status: status}
	}
	if failure.PartialResultRefs == nil {
		failure.PartialResultRefs = []string{}
	}
	expected, known := errorStatuses[failure.Code]
	if !known || expected != status {
		return &ProtocolError{Message: "error code and HTTP status disagree", Status: status}
	}
	failure.Status = status
	return &failure
}
