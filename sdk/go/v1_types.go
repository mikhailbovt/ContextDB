package contextdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
)

// Capability is an application authorization grant, not a transport credential.
type Capability string

const (
	CapabilityObserve         Capability = "observe"
	CapabilityStreamIngest    Capability = "stream_ingest"
	CapabilityRecall          Capability = "recall"
	CapabilityCorrect         Capability = "correct"
	CapabilityForget          Capability = "forget"
	CapabilityHardDelete      Capability = "hard_delete"
	CapabilityReadMemory      Capability = "read_memory"
	CapabilityTraverse        Capability = "traverse"
	CapabilityReadEvidence    Capability = "read_evidence"
	CapabilityReadConflict    Capability = "read_conflict"
	CapabilitySubscribe       Capability = "subscribe"
	CapabilityRuntime         Capability = "runtime"
	CapabilityMaintenance     Capability = "maintenance"
	CapabilityAdmin           Capability = "admin"
	CapabilityRawEvidence     Capability = "raw_evidence"
	CapabilityModelProcessing Capability = "model_processing"
)

type AuthenticationEvidenceKind string

const (
	AuthenticationAuthenticatedChannel AuthenticationEvidenceKind = "authenticated_channel"
	AuthenticationRequestSignature     AuthenticationEvidenceKind = "request_signature"
)

// AuthenticationEvidence is explicit application data verified by the server.
// It is never converted into deployment gateway headers by this SDK.
type AuthenticationEvidence struct {
	Kind                AuthenticationEvidenceKind
	ChannelID           string
	PeerIdentity        string
	BindingDigest       string
	Algorithm           string
	KeyID               string
	Signature           string
	SignedContextDigest string
}

func (value AuthenticationEvidence) MarshalJSON() ([]byte, error) {
	switch value.Kind {
	case AuthenticationAuthenticatedChannel:
		return json.Marshal(struct {
			Kind          AuthenticationEvidenceKind `json:"kind"`
			ChannelID     string                     `json:"channel_id"`
			PeerIdentity  string                     `json:"peer_identity"`
			BindingDigest string                     `json:"binding_digest"`
		}{value.Kind, value.ChannelID, value.PeerIdentity, value.BindingDigest})
	case AuthenticationRequestSignature:
		return json.Marshal(struct {
			Kind                AuthenticationEvidenceKind `json:"kind"`
			Algorithm           string                     `json:"algorithm"`
			KeyID               string                     `json:"key_id"`
			Signature           string                     `json:"signature"`
			SignedContextDigest string                     `json:"signed_context_digest"`
		}{value.Kind, value.Algorithm, value.KeyID, value.Signature, value.SignedContextDigest})
	default:
		return nil, errors.New("unknown authentication evidence kind")
	}
}

type AuthenticatedRequestContext struct {
	Request          RequestContext         `json:"request"`
	ActorID          string                 `json:"actor_id"`
	AgentID          string                 `json:"agent_id"`
	SessionID        *string                `json:"session_id"`
	CapabilityGrants []Capability           `json:"capability_grants"`
	Authentication   AuthenticationEvidence `json:"authentication"`
}

type Compression string

const (
	CompressionIdentity Compression = "identity"
	CompressionGzip     Compression = "gzip"
	CompressionZstd     Compression = "zstd"
)

type SourceRevisionManifest struct {
	SourceID           string            `json:"source_id"`
	RevisionID         string            `json:"revision_id"`
	SnapshotID         string            `json:"snapshot_id"`
	ExpectedItems      uint64            `json:"expected_items"`
	OrderedItemsDigest string            `json:"ordered_items_digest"`
	Compression        Compression       `json:"compression"`
	Attributes         map[string]string `json:"attributes"`
}

type StreamObservation struct {
	IdempotencyKey string         `json:"idempotency_key"`
	ObservationID  string         `json:"observation_id"`
	Metadata       map[string]any `json:"metadata"`
	Content        any            `json:"content"`
	Access         AccessPolicy   `json:"access"`
}

type SnapshotComplete struct {
	SnapshotID         string `json:"snapshot_id"`
	ItemCount          uint64 `json:"item_count"`
	OrderedItemsDigest string `json:"ordered_items_digest"`
}

type IngestFrameKind string

const (
	IngestFrameManifest         IngestFrameKind = "manifest"
	IngestFrameObservation      IngestFrameKind = "observation"
	IngestFrameSnapshotComplete IngestFrameKind = "snapshot_complete"
)

type IngestFrameValue struct {
	Kind  IngestFrameKind `json:"kind"`
	Value any             `json:"value"`
}

type IngestFrame struct {
	Context      AuthenticatedRequestContext `json:"context"`
	StreamID     string                      `json:"stream_id"`
	Position     uint64                      `json:"position"`
	ResumeCursor *string                     `json:"resume_cursor"`
	Value        IngestFrameValue            `json:"value"`
}

type IngestDisposition string

const (
	IngestAccepted          IngestDisposition = "accepted"
	IngestReplayed          IngestDisposition = "replayed"
	IngestSnapshotCommitted IngestDisposition = "snapshot_committed"
)

type IngestAck struct {
	StreamID          string            `json:"stream_id"`
	Position          uint64            `json:"position"`
	Disposition       IngestDisposition `json:"disposition"`
	FrameDigest       string            `json:"frame_digest"`
	ResumeCursor      string            `json:"resume_cursor"`
	CommitSeq         *uint64           `json:"commit_seq"`
	PartialResultRefs []string          `json:"partial_result_refs"`
	LeaseExpiresAtMS  *uint64           `json:"lease_expires_at_ms,omitempty"`
}

type MemoryEventKind string

const (
	MemoryEventNodeChanged            MemoryEventKind = "node_changed"
	MemoryEventClaimChanged           MemoryEventKind = "claim_changed"
	MemoryEventOpenLoopTriggered      MemoryEventKind = "open_loop_triggered"
	MemoryEventIndexWatermarkAdvanced MemoryEventKind = "index_watermark_advanced"
	MemoryEventConflictResolved       MemoryEventKind = "conflict_resolved"
	MemoryEventSourceInvalidated      MemoryEventKind = "source_invalidated"
	MemoryEventOperationProgress      MemoryEventKind = "operation_progress"
	MemoryEventSecurityEvent          MemoryEventKind = "security_event"
	MemoryEventObservationAccepted    MemoryEventKind = "observation_accepted"
	MemoryEventRecordChanged          MemoryEventKind = "record_changed"
)

type SubscribeRequest struct {
	Context      AuthenticatedRequestContext `json:"context"`
	Filters      []MemoryEventKind           `json:"filters"`
	ResumeCursor *string                     `json:"resume_cursor"`
	MaxEvents    uint32                      `json:"max_events"`
}

type MemoryEvent struct {
	EventID    string            `json:"event_id"`
	CommitSeq  uint64            `json:"commit_seq"`
	Ordinal    uint32            `json:"ordinal"`
	Kind       MemoryEventKind   `json:"kind"`
	ObjectRefs []string          `json:"object_refs"`
	Attributes map[string]string `json:"attributes"`
}

type SubscriptionPage struct {
	Events       []MemoryEvent `json:"events"`
	ResumeCursor string        `json:"resume_cursor"`
	CaughtUp     bool          `json:"caught_up"`
}

type MemoryRecordKind string

const (
	MemoryRecordNode            MemoryRecordKind = "node"
	MemoryRecordClaim           MemoryRecordKind = "claim"
	MemoryRecordEdge            MemoryRecordKind = "edge"
	MemoryRecordConflict        MemoryRecordKind = "conflict"
	MemoryRecordEvidence        MemoryRecordKind = "evidence"
	MemoryRecordCandidate       MemoryRecordKind = "candidate"
	MemoryRecordSemanticObject  MemoryRecordKind = "semantic_object"
	MemoryRecordRuntimeState    MemoryRecordKind = "runtime_state"
	MemoryRecordDomainExtension MemoryRecordKind = "domain_extension"
)

type MemoryLifecycle string

const (
	MemoryActive     MemoryLifecycle = "active"
	MemorySuperseded MemoryLifecycle = "superseded"
	MemoryRetracted  MemoryLifecycle = "retracted"
	MemorySuppressed MemoryLifecycle = "suppressed"
)

// Int128 preserves Rust i128 JSON integers as their exact canonical decimal.
type Int128 string

var canonicalInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
var minInt128 = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
var maxInt128 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))

func NewInt128(value string) (Int128, error) {
	if !canonicalInteger.MatchString(value) || value == "-0" {
		return "", errors.New("i128 must be canonical decimal")
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || parsed.Cmp(minInt128) < 0 || parsed.Cmp(maxInt128) > 0 {
		return "", errors.New("i128 is out of range")
	}
	return Int128(value), nil
}

func (value Int128) MarshalJSON() ([]byte, error) {
	validated, err := NewInt128(string(value))
	if err != nil {
		return nil, err
	}
	return []byte(validated), nil
}

func (value *Int128) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("i128 must be an integer")
	}
	validated, err := NewInt128(string(data))
	if err != nil {
		return err
	}
	*value = validated
	return nil
}

type DomainTimeRange struct {
	From *Int128 `json:"from"`
	To   *Int128 `json:"to"`
}

type MemoryLinks struct {
	Subject         *string  `json:"subject"`
	Source          *string  `json:"source"`
	Target          *string  `json:"target"`
	Predicate       *string  `json:"predicate"`
	ConflictSet     *string  `json:"conflict_set"`
	Supersedes      []string `json:"supersedes"`
	Evidence        []string `json:"evidence"`
	ConflictMembers []string `json:"conflict_members"`
	SingleValued    bool     `json:"single_valued"`
}

type MemoryDocument struct {
	ID         string           `json:"id"`
	Kind       MemoryRecordKind `json:"kind"`
	Access     AccessPolicy     `json:"access"`
	ValidTime  DomainTimeRange  `json:"valid_time"`
	Lifecycle  MemoryLifecycle  `json:"lifecycle"`
	Links      MemoryLinks      `json:"links"`
	Value      any              `json:"value"`
	SearchText *string          `json:"search_text"`
	Vector     []float32        `json:"vector"`
	Attributes map[string]any   `json:"attributes"`
}

type MemoryRecord struct {
	Document        MemoryDocument `json:"document"`
	Revision        uint32         `json:"revision"`
	TransactionFrom uint64         `json:"transaction_from"`
	TransactionTo   *uint64        `json:"transaction_to"`
}

type MutationResponse struct {
	CommitSeq     uint64     `json:"commit_seq"`
	Replayed      bool       `json:"replayed"`
	RequestDigest string     `json:"request_digest"`
	Watermarks    Watermarks `json:"watermarks"`
}

type HighLevelWriteRequest struct {
	Context         AuthenticatedRequestContext `json:"context"`
	IdempotencyKey  string                      `json:"idempotency_key"`
	TargetSubjectID string                      `json:"target_subject_id"`
	SessionID       *string                     `json:"session_id"`
	LogicalID       string                      `json:"logical_id"`
	Access          AccessPolicy                `json:"access"`
	Payload         any                         `json:"payload"`
	References      []string                    `json:"references"`
}

type HighLevelQueryRequest struct {
	Context         AuthenticatedRequestContext `json:"context"`
	TargetSubjectID string                      `json:"target_subject_id"`
	Cue             string                      `json:"cue"`
	PageSize        uint32                      `json:"page_size"`
	AtCommit        *uint64                     `json:"at_commit"`
	Continuation    *string                     `json:"continuation"`
}

type HighLevelControlRequest struct {
	Context         AuthenticatedRequestContext `json:"context"`
	IdempotencyKey  string                      `json:"idempotency_key"`
	TargetSubjectID string                      `json:"target_subject_id"`
	TargetID        string                      `json:"target_id"`
	Parameters      any                         `json:"parameters"`
}

type HighLevelTransferRequest struct {
	Context         AuthenticatedRequestContext `json:"context"`
	IdempotencyKey  string                      `json:"idempotency_key"`
	TargetSubjectID string                      `json:"target_subject_id"`
	Format          string                      `json:"format"`
	Bytes           ByteArray                   `json:"bytes"`
	Digest          string                      `json:"digest"`
}

type HighLevelMutationResponse struct {
	Operation      string          `json:"operation"`
	LogicalID      string          `json:"logical_id"`
	PolicyResult   string          `json:"policy_result"`
	SemanticStatus string          `json:"semantic_status"`
	Receipt        ObserveResponse `json:"receipt"`
}

type CorrectRequest struct {
	Context        AuthenticatedRequestContext `json:"context"`
	IdempotencyKey string                      `json:"idempotency_key"`
	TargetID       string                      `json:"target_id"`
	Replacement    MemoryDocument              `json:"replacement"`
}

type ForgetMode string

const (
	ForgetRetract    ForgetMode = "retract"
	ForgetHardDelete ForgetMode = "hard_delete"
)

type ForgetRequest struct {
	Context        AuthenticatedRequestContext `json:"context"`
	IdempotencyKey string                      `json:"idempotency_key"`
	TargetID       string                      `json:"target_id"`
	Mode           ForgetMode                  `json:"mode"`
	Reason         string                      `json:"reason"`
}

type GetMemoryRequest struct {
	Context  AuthenticatedRequestContext `json:"context"`
	RecordID string                      `json:"record_id"`
	AtCommit *uint64                     `json:"at_commit"`
}

type GetTimelineRequest struct {
	Context      AuthenticatedRequestContext `json:"context"`
	RecordID     string                      `json:"record_id"`
	ExpectedKind MemoryRecordKind            `json:"expected_kind"`
	AtCommit     *uint64                     `json:"at_commit"`
	MaxRevisions uint32                      `json:"max_revisions"`
}

type TimelineResponse struct {
	Revisions   []MemoryRecord `json:"revisions"`
	SnapshotSeq uint64         `json:"snapshot_seq"`
	Watermarks  Watermarks     `json:"watermarks"`
}

type TraverseDirection string

const (
	TraverseOutgoing TraverseDirection = "outgoing"
	TraverseIncoming TraverseDirection = "incoming"
	TraverseBoth     TraverseDirection = "both"
)

type TraverseRequest struct {
	Context      AuthenticatedRequestContext `json:"context"`
	StartIDs     []string                    `json:"start_ids"`
	Direction    TraverseDirection           `json:"direction"`
	PredicateIDs []string                    `json:"predicate_ids"`
	MaxHops      uint8                       `json:"max_hops"`
	MaxNodes     uint32                      `json:"max_nodes"`
	AtCommit     *uint64                     `json:"at_commit"`
}

type TraverseResponse struct {
	NodeIDs              []string   `json:"node_ids"`
	SnapshotSeq          uint64     `json:"snapshot_seq"`
	AuthorizedCandidates uint64     `json:"authorized_candidates"`
	Watermarks           Watermarks `json:"watermarks"`
}

type RuntimeRequest struct {
	Context     AuthenticatedRequestContext `json:"context"`
	OperationID string                      `json:"operation_id"`
	Payload     any                         `json:"payload"`
}

type RuntimeResponse struct {
	OperationID string `json:"operation_id"`
	Payload     any    `json:"payload"`
}

type MaintenanceRequest struct {
	Context     AuthenticatedRequestContext `json:"context"`
	OperationID string                      `json:"operation_id"`
	Payload     any                         `json:"payload"`
}

type MaintenanceResponse struct {
	OperationID string `json:"operation_id"`
	Payload     any    `json:"payload"`
}

type GetStatusRequest struct {
	Context AuthenticatedRequestContext `json:"context"`
}

type RuntimeCapabilityState string

const (
	RuntimeCapabilityAvailable    RuntimeCapabilityState = "available"
	RuntimeCapabilityCompiledOnly RuntimeCapabilityState = "compiled_only"
	RuntimeCapabilityUnsupported  RuntimeCapabilityState = "unsupported"
)

const (
	CandidateCapabilityHierarchyDAG         = "candidate_hierarchy_dag"
	CandidateCapabilityPolicyFirstRecall    = "policy_first_candidate_recall"
	CandidateCapabilityPolicyFirstTraversal = "policy_first_candidate_traversal"
	CandidateCapabilityQuarantinedProposals = "quarantined_memory_proposals"
)

// CandidateRuntimeCapabilityIDsV1 returns the stable candidate-only schema-v1
// keys while CapabilityManifestV1 remains an open map for additive extensions.
func CandidateRuntimeCapabilityIDsV1() [4]string {
	return [...]string{
		CandidateCapabilityHierarchyDAG,
		CandidateCapabilityPolicyFirstRecall,
		CandidateCapabilityPolicyFirstTraversal,
		CandidateCapabilityQuarantinedProposals,
	}
}

type CapabilityManifestV1 struct {
	SchemaVersion        uint16                            `json:"schema_version"`
	Profile              string                            `json:"profile"`
	ServerV1ReleaseReady bool                              `json:"server_v1_release_ready"`
	Capabilities         map[string]RuntimeCapabilityState `json:"capabilities"`
}

type StatusResponse struct {
	SchemaVersion      uint16               `json:"schema_version"`
	Profile            string               `json:"profile"`
	CommitSeq          uint64               `json:"commit_seq"`
	Watermarks         Watermarks           `json:"watermarks"`
	CapabilityManifest CapabilityManifestV1 `json:"capability_manifest"`
}

type CreateBackupRequest struct {
	Context AuthenticatedRequestContext `json:"context"`
}

type BackupResponse struct {
	Format    string    `json:"format"`
	Bytes     ByteArray `json:"bytes"`
	Digest    string    `json:"digest"`
	CommitSeq uint64    `json:"commit_seq"`
}

type RestoreBackupRequest struct {
	Context AuthenticatedRequestContext `json:"context"`
	Format  string                      `json:"format"`
	Bytes   ByteArray                   `json:"bytes"`
	Digest  string                      `json:"digest"`
}

type RestoreBackupResponse struct {
	CommitSeq  uint64     `json:"commit_seq"`
	Watermarks Watermarks `json:"watermarks"`
}

type MigrateFormatRequest struct {
	Context      AuthenticatedRequestContext `json:"context"`
	TargetFormat string                      `json:"target_format"`
	OperationID  string                      `json:"operation_id"`
}
