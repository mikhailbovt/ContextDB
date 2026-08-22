package contextdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Sensitivity is the canonical ordered disclosure label.
type Sensitivity string

const (
	SensitivityPublic     Sensitivity = "public"
	SensitivityInternal   Sensitivity = "internal"
	SensitivityPrivate    Sensitivity = "private"
	SensitivityRestricted Sensitivity = "restricted"
)

// Consent is the canonical observation consent state.
type Consent string

const (
	ConsentGranted Consent = "granted"
	ConsentUnknown Consent = "unknown"
	ConsentDenied  Consent = "denied"
)

// RequestContext is a deployment-resolved capability input. It is not an
// authentication credential.
type RequestContext struct {
	RequestID   string      `json:"request_id"`
	WorkspaceID string      `json:"workspace_id"`
	SubjectID   string      `json:"subject_id"`
	Audiences   []string    `json:"audiences"`
	Scopes      []string    `json:"scopes"`
	Purpose     string      `json:"purpose"`
	Clearance   Sensitivity `json:"clearance"`
}

// AccessPolicy is stored separately from erasable observation content.
type AccessPolicy struct {
	WorkspaceID           string              `json:"workspace_id"`
	Scopes                []string            `json:"scopes"`
	Owners                []string            `json:"owners"`
	Audience              []string            `json:"audience"`
	AudiencePurposeGrants map[string][]string `json:"audience_purpose_grants"`
	Purposes              []string            `json:"purposes"`
	Sensitivity           Sensitivity         `json:"sensitivity"`
	Consent               Consent             `json:"consent"`
	Retrievable           bool                `json:"retrievable"`
}

// Watermarks report coherent journal and projection progress.
type Watermarks struct {
	Journal  uint64 `json:"journal"`
	Semantic uint64 `json:"semantic"`
	Lexical  uint64 `json:"lexical"`
	Vector   uint64 `json:"vector"`
	Graph    uint64 `json:"graph"`
}

type ObserveRequest struct {
	Context        RequestContext `json:"context"`
	IdempotencyKey string         `json:"idempotency_key"`
	ObservationID  string         `json:"observation_id"`
	Metadata       map[string]any `json:"metadata"`
	Content        any            `json:"content"`
	Access         AccessPolicy   `json:"access"`
}

type ObserveResponse struct {
	CommitSeq     uint64     `json:"commit_seq"`
	Replayed      bool       `json:"replayed"`
	RequestDigest string     `json:"request_digest"`
	Watermarks    Watermarks `json:"watermarks"`
}

type RecallRequest struct {
	Context      RequestContext `json:"context"`
	Query        string         `json:"query"`
	PageSize     uint32         `json:"page_size"`
	AtCommit     *uint64        `json:"at_commit"`
	Continuation *string        `json:"continuation"`
}

type RecallHit struct {
	ID    string  `json:"id"`
	Score float32 `json:"score"`
}

type RecallTrace struct {
	TraceID              string     `json:"trace_id"`
	SnapshotSeq          uint64     `json:"snapshot_seq"`
	Operation            string     `json:"operation"`
	AuthorizedCandidates uint64     `json:"authorized_candidates"`
	SelectedIDs          []string   `json:"selected_ids"`
	Watermarks           Watermarks `json:"watermarks"`
}

type RecallResponse struct {
	Hits         []RecallHit `json:"hits"`
	Trace        RecallTrace `json:"trace"`
	Continuation *string     `json:"continuation"`
}

type ExplainRecallRequest struct {
	Context RequestContext `json:"context"`
	Trace   RecallTrace    `json:"trace"`
}

type ExportRequest struct {
	Context RequestContext `json:"context"`
}

// ByteArray preserves Rust Vec<u8>'s canonical JSON representation (an array
// of integers). Plain Go []byte would silently encode as a base64 string.
type ByteArray []byte

func (value ByteArray) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Grow(len(value)*4 + 2)
	buffer.WriteByte('[')
	for index, item := range value {
		if index > 0 {
			buffer.WriteByte(',')
		}
		buffer.WriteString(strconv.FormatUint(uint64(item), 10))
	}
	buffer.WriteByte(']')
	return buffer.Bytes(), nil
}

func (value *ByteArray) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("archive bytes must be an array")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("archive bytes must be an array: %w", err)
	}
	decoded := make([]byte, len(items))
	for index, item := range items {
		number, err := strconv.ParseUint(string(item), 10, 8)
		if err != nil {
			return fmt.Errorf("archive byte %d is invalid: %w", index, err)
		}
		decoded[index] = byte(number)
	}
	*value = decoded
	return nil
}

type ExportResponse struct {
	Format    string    `json:"format"`
	Bytes     ByteArray `json:"bytes"`
	Digest    string    `json:"digest"`
	CommitSeq uint64    `json:"commit_seq"`
}

type ImportRequest struct {
	Context RequestContext `json:"context"`
	Format  string         `json:"format"`
	Bytes   ByteArray      `json:"bytes"`
	Digest  string         `json:"digest"`
}

type ImportResponse struct {
	CommitSeq  uint64     `json:"commit_seq"`
	Watermarks Watermarks `json:"watermarks"`
}

type VerifyRequest struct {
	Context RequestContext `json:"context"`
	Deep    bool           `json:"deep"`
}

type VerifyResponse struct {
	Valid         bool    `json:"valid"`
	CommitSeq     uint64  `json:"commit_seq"`
	ArchiveDigest *string `json:"archive_digest"`
}
