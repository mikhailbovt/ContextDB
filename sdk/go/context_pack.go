package contextdb

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/zeebo/blake3"
)

// ContextPackPath is the policy-first RecallEngine-to-ContextCompiler route.
const ContextPackPath = "/v1/context-pack"

const (
	// ContextPackCanonicalEncoding identifies the normative public Protobuf schema.
	ContextPackCanonicalEncoding = "contextdb.context_pack.protobuf.v1"
	// ContextPackCanonicalDigestAlgorithm identifies the digest over canonical bytes.
	ContextPackCanonicalDigestAlgorithm = "blake3-256"
)

type RecallMode string

const (
	RecallNever              RecallMode = "never"
	RecallOptional           RecallMode = "optional"
	RecallAuto               RecallMode = "auto"
	RecallRequired           RecallMode = "required"
	RecallImplicitContinuity RecallMode = "implicit_continuity"
	RecallExplicit           RecallMode = "explicit"
	RecallAssociative        RecallMode = "associative"
	RecallRelational         RecallMode = "relational"
	RecallHistorical         RecallMode = "historical"
	RecallForensic           RecallMode = "forensic"
)

type RecallIntentKind string

const (
	RecallIntentContinuity      RecallIntentKind = "continuity"
	RecallIntentCurrentTruth    RecallIntentKind = "current_truth"
	RecallIntentHistoricalTruth RecallIntentKind = "historical_truth"
	RecallIntentAssociative     RecallIntentKind = "associative"
	RecallIntentRelational      RecallIntentKind = "relational"
	RecallIntentProcedural      RecallIntentKind = "procedural"
	RecallIntentReflective      RecallIntentKind = "reflective"
	RecallIntentForensic        RecallIntentKind = "forensic"
	RecallIntentBootstrap       RecallIntentKind = "bootstrap"
	RecallIntentPreflight       RecallIntentKind = "preflight"
)

// RecallIntent preserves the Rust string-or-{other: label} enum without using any.
type RecallIntent struct {
	Kind  RecallIntentKind
	Other string
}

func StandardRecallIntent(kind RecallIntentKind) RecallIntent { return RecallIntent{Kind: kind} }
func OtherRecallIntent(label string) RecallIntent             { return RecallIntent{Other: label} }

func (value RecallIntent) MarshalJSON() ([]byte, error) {
	if value.Other != "" && value.Kind == "" {
		return json.Marshal(map[string]string{"other": value.Other})
	}
	if value.Kind != "" && value.Other == "" {
		return json.Marshal(value.Kind)
	}
	return nil, errors.New("recall intent must contain exactly one standard or other value")
}

func (value *RecallIntent) UnmarshalJSON(data []byte) error {
	var raw any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	switch typed := raw.(type) {
	case string:
		value.Kind = RecallIntentKind(typed)
		value.Other = ""
		return nil
	case map[string]any:
		if len(typed) != 1 {
			return errors.New("invalid other recall intent")
		}
		label, ok := typed["other"].(string)
		if !ok {
			return errors.New("invalid other recall intent")
		}
		value.Kind = ""
		value.Other = label
		return nil
	default:
		return errors.New("invalid recall intent")
	}
}

type PackPurpose string

const (
	PackPurposeConversation     PackPurpose = "conversation"
	PackPurposeContinuity       PackPurpose = "continuity"
	PackPurposeAutobiographical PackPurpose = "autobiographical"
	PackPurposeKnowledge        PackPurpose = "knowledge"
	PackPurposeHistorical       PackPurpose = "historical"
	PackPurposeReflective       PackPurpose = "reflective"
	PackPurposeAction           PackPurpose = "action"
	PackPurposeHandoff          PackPurpose = "handoff"
	PackPurposeBootstrap        PackPurpose = "bootstrap"
)

type RendererKind string

const (
	RendererCompact          RendererKind = "compact"
	RendererHostedStructured RendererKind = "hosted_structured"
	RendererChat             RendererKind = "chat"
	RendererCoding           RendererKind = "coding"
	RendererCanonicalJSON    RendererKind = "canonical_json"
)

type StructuredFormat string

const (
	StructuredCompactText StructuredFormat = "compact_text"
	StructuredJSON        StructuredFormat = "json"
	StructuredMarkdown    StructuredFormat = "markdown"
	StructuredToolResult  StructuredFormat = "tool_result"
)

type PositionProfile string

const (
	PositionBalanced           PositionProfile = "balanced"
	PositionCriticalFirst      PositionProfile = "critical_first"
	PositionEvidenceAdjacent   PositionProfile = "evidence_adjacent"
	PositionSmallModelExplicit PositionProfile = "small_model_explicit"
)

type InstructionHierarchy string

const (
	InstructionSeparatedChannels     InstructionHierarchy = "separated_channels"
	InstructionSinglePromptDelimited InstructionHierarchy = "single_prompt_delimited"
)

type PackFacetRequirement struct {
	Name                    string `json:"name"`
	MinimumConfidenceMicros uint32 `json:"minimum_confidence_micros"`
	RequireEvidence         bool   `json:"require_evidence"`
}

type RecallLimits struct {
	MaxNodesExamined  uint32 `json:"max_nodes_examined"`
	MaxSeedCandidates uint32 `json:"max_seed_candidates"`
	MaxGraphHops      uint8  `json:"max_graph_hops"`
	MaxFrontierPerHop uint32 `json:"max_frontier_per_hop"`
	MaxEvidenceUnits  uint32 `json:"max_evidence_units"`
	MaxContextTokens  uint32 `json:"max_context_tokens"`
	DeadlineMicros    uint64 `json:"deadline_micros"`
}

type ContextBudgets struct {
	HardTokens              uint32 `json:"hard_tokens"`
	SoftTokens              uint32 `json:"soft_tokens"`
	MaxBlocks               uint32 `json:"max_blocks"`
	MaxEvidenceBlocks       uint32 `json:"max_evidence_blocks"`
	MaxRawEvidenceTokens    uint32 `json:"max_raw_evidence_tokens"`
	MaxHistoryTokens        uint32 `json:"max_history_tokens"`
	MaxConflictTokens       uint32 `json:"max_conflict_tokens"`
	MaxSerializedBytes      uint32 `json:"max_serialized_bytes"`
	MaxSelectionEvaluations uint32 `json:"max_selection_evaluations"`
}

type ModelProfile struct {
	ID                        string               `json:"id"`
	Family                    string               `json:"family"`
	TokenizerID               string               `json:"tokenizer_id"`
	Renderer                  RendererKind         `json:"renderer"`
	MaxContextTokens          uint32               `json:"max_context_tokens"`
	ReservedOutputTokens      uint32               `json:"reserved_output_tokens"`
	PreferredStructuredFormat StructuredFormat     `json:"preferred_structured_format"`
	SupportsToolResults       bool                 `json:"supports_tool_results"`
	SupportsNativeCitations   bool                 `json:"supports_native_citations"`
	SupportsPromptCaching     bool                 `json:"supports_prompt_caching"`
	PositionProfile           PositionProfile      `json:"position_profile"`
	InstructionHierarchy      InstructionHierarchy `json:"instruction_hierarchy"`
	MaxSchemaComplexity       uint32               `json:"max_schema_complexity"`
	ExternalProcessing        bool                 `json:"external_processing"`
}

type SuppliedVector struct {
	Space  string    `json:"space"`
	Values []float32 `json:"values"`
}

type CompileContextPlan struct {
	PackID                  string                 `json:"pack_id"`
	Query                   string                 `json:"query"`
	Mode                    RecallMode             `json:"mode"`
	Intent                  RecallIntent           `json:"intent"`
	Purpose                 PackPurpose            `json:"purpose"`
	AtCommit                *uint64                `json:"at_commit"`
	NowMicros               int64                  `json:"now_micros"`
	RequiredFacets          []PackFacetRequirement `json:"required_facets"`
	RecallLimits            RecallLimits           `json:"recall_limits"`
	ContextBudgets          ContextBudgets         `json:"context_budgets"`
	ModelProfile            ModelProfile           `json:"model_profile"`
	ExplicitMemoryRequest   bool                   `json:"explicit_memory_request"`
	RequirePrimaryEvidence  bool                   `json:"require_primary_evidence"`
	IncludeEvidenceQuotes   bool                   `json:"include_evidence_quotes"`
	PermitDerivedOnly       bool                   `json:"permit_derived_only"`
	MaxProjectionLagCommits uint64                 `json:"max_projection_lag_commits"`
	AllowStale              bool                   `json:"allow_stale"`
	QueryVector             *SuppliedVector        `json:"query_vector"`
	Continuation            *string                `json:"continuation"`
}

type CompileContextRequest struct {
	Context AuthenticatedRequestContext `json:"context"`
	Plan    CompileContextPlan          `json:"plan"`
}

type RecallWatermarks struct {
	Journal   uint64            `json:"journal"`
	Semantic  uint64            `json:"semantic"`
	Lexical   uint64            `json:"lexical"`
	Vector    map[string]uint64 `json:"vector"`
	Graph     uint64            `json:"graph"`
	Hierarchy map[string]uint64 `json:"hierarchy"`
}

type ProviderSnapshot struct {
	DatabaseID string           `json:"database_id"`
	CommitSeq  uint64           `json:"commit_seq"`
	Watermarks RecallWatermarks `json:"watermarks"`
}

type PackStatus string
type RecallStatus string
type ContextStopReason string
type PackBlockKind string
type CompressionLevel string
type ContentTrust string
type InstructionCapability string
type InterpretationRule string
type UseAction string
type DirectiveReason string
type OmissionReason string
type NoMemoryReason string

const (
	PackSufficient PackStatus = "sufficient"
	PackPartial    PackStatus = "partial"
	PackNoMemory   PackStatus = "no_memory"

	RecallStatusSkipped  RecallStatus = "skipped"
	RecallStatusComplete RecallStatus = "complete"
	RecallStatusPartial  RecallStatus = "partial"
	RecallStatusUnknown  RecallStatus = "unknown"

	StopGateSkipped          ContextStopReason = "gate_skipped"
	StopSufficient           ContextStopReason = "sufficient"
	StopNodeBudget           ContextStopReason = "node_budget"
	StopGraphBudget          ContextStopReason = "graph_budget"
	StopHopBudget            ContextStopReason = "hop_budget"
	StopTokenBudget          ContextStopReason = "token_budget"
	StopDeadline             ContextStopReason = "deadline"
	StopNoUsefulCandidates   ContextStopReason = "no_useful_candidates"
	StopUnknownOrConflicted  ContextStopReason = "unknown_or_conflicted"
	StopContinuationBoundary ContextStopReason = "continuation_boundary"

	BlockSituation     PackBlockKind = "situation"
	BlockSelfContext   PackBlockKind = "self_context"
	BlockParticipant   PackBlockKind = "participant"
	BlockSharedHistory PackBlockKind = "shared_history"
	BlockEpisode       PackBlockKind = "episode"
	BlockFact          PackBlockKind = "fact"
	BlockRelationship  PackBlockKind = "relationship"
	BlockPreference    PackBlockKind = "preference"
	BlockBoundary      PackBlockKind = "boundary"
	BlockGoal          PackBlockKind = "goal"
	BlockDecision      PackBlockKind = "decision"
	BlockTimeline      PackBlockKind = "timeline"
	BlockProcedure     PackBlockKind = "procedure"
	BlockConstraint    PackBlockKind = "constraint"
	BlockOpenLoop      PackBlockKind = "open_loop"
	BlockConflict      PackBlockKind = "conflict"
	BlockUnknown       PackBlockKind = "unknown"

	CompressionL0Orientation CompressionLevel = "l0_orientation"
	CompressionL1Summary     CompressionLevel = "l1_summary"
	CompressionL2Structured  CompressionLevel = "l2_structured"
	CompressionL3Evidence    CompressionLevel = "l3_evidence"
	CompressionL4Raw         CompressionLevel = "l4_raw"

	ContentTrustedSource ContentTrust = "trusted_source"
	ContentMixed         ContentTrust = "mixed"
	ContentUntrusted     ContentTrust = "untrusted"
	ContentUnknown       ContentTrust = "unknown"

	InstructionCapabilityNone        InstructionCapability = "none"
	InstructionCapabilityHostTrusted InstructionCapability = "host_trusted"

	InterpretationFactualData          InterpretationRule = "factual_data"
	InterpretationHistoricalData       InterpretationRule = "historical_data"
	InterpretationConstraintData       InterpretationRule = "constraint_data"
	InterpretationStyleSignal          InterpretationRule = "style_signal"
	InterpretationHypothesisOnly       InterpretationRule = "hypothesis_only"
	InterpretationUnknownMarker        InterpretationRule = "unknown_marker"
	InterpretationConflictAlternatives InterpretationRule = "conflict_alternatives"

	UseMentionNaturally UseAction = "mention_naturally"
	UseSilently         UseAction = "use_silently"
	UseConstraintOnly   UseAction = "constraint_only"
	UseStyleOnly        UseAction = "style_only"

	DirectivePolicyAllowsMention     DirectiveReason = "policy_allows_mention"
	DirectiveMentionDenied           DirectiveReason = "mention_denied"
	DirectiveExplicitRequestRequired DirectiveReason = "explicit_request_required"
	DirectiveConstraintSemantics     DirectiveReason = "constraint_semantics"
	DirectiveStyleSemantics          DirectiveReason = "style_semantics"

	NoMemoryNoAuthorizedCandidates            NoMemoryReason = "no_authorized_candidates"
	NoMemoryNoRelevantCandidates              NoMemoryReason = "no_relevant_candidates"
	NoMemoryBudgetCouldNotAdmitOptionalMemory NoMemoryReason = "budget_could_not_admit_optional_memory"
)

// StringOrOther preserves extensible Rust enums such as SourceClass and ContentTaint.
type StringOrOther struct {
	Value string
	Other string
}

func StandardStringOrOther(value string) StringOrOther { return StringOrOther{Value: value} }
func OtherStringOrOther(value string) StringOrOther    { return StringOrOther{Other: value} }

func (value StringOrOther) MarshalJSON() ([]byte, error) {
	if value.Other != "" && value.Value == "" {
		return json.Marshal(map[string]string{"other": value.Other})
	}
	if value.Value != "" && value.Other == "" {
		return json.Marshal(value.Value)
	}
	return nil, errors.New("extensible enum must contain exactly one standard or other value")
}

func (value *StringOrOther) UnmarshalJSON(data []byte) error {
	var standard string
	if err := json.Unmarshal(data, &standard); err == nil {
		value.Value, value.Other = standard, ""
		return nil
	}
	var other map[string]string
	if err := json.Unmarshal(data, &other); err != nil || len(other) != 1 || other["other"] == "" {
		return errors.New("invalid extensible enum")
	}
	value.Value, value.Other = "", other["other"]
	return nil
}

type TimeRange struct {
	Start int64  `json:"start"`
	End   *int64 `json:"end"`
}

type TemporalConstraint struct {
	Kind        string     `json:"kind"`
	Range       *TimeRange `json:"range,omitempty"`
	CommitSeq   *uint64    `json:"commit_seq,omitempty"`
	ValidDuring *TimeRange `json:"valid_during,omitempty"`
	KnownAt     *uint64    `json:"known_at,omitempty"`
}

type BlockRepresentation struct {
	Level         CompressionLevel  `json:"level"`
	Summary       string            `json:"summary"`
	Fields        map[string]string `json:"fields"`
	OmittedFacets []string          `json:"omitted_facets"`
}

type ExactFragment struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type MemoryRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type Perspective struct {
	Knower      string        `json:"knower"`
	Experiencer *string       `json:"experiencer"`
	Narrator    string        `json:"narrator"`
	Role        StringOrOther `json:"role"`
}

type ConflictState struct {
	State string  `json:"state"`
	SetID *string `json:"set_id,omitempty"`
}

type EpistemicState struct {
	Basis      string        `json:"basis"`
	Acceptance string        `json:"acceptance"`
	Conflict   ConflictState `json:"conflict"`
	Lifecycle  string        `json:"lifecycle"`
}

type SupportState struct {
	State  string  `json:"state"`
	Reason *string `json:"reason,omitempty"`
}

type ConflictResolution struct {
	State     string  `json:"state"`
	Winner    *string `json:"winner,omitempty"`
	Rationale *string `json:"rationale,omitempty"`
}

type ConflictDescriptor struct {
	SetID        string             `json:"set_id"`
	Alternatives []string           `json:"alternatives"`
	Resolution   ConflictResolution `json:"resolution"`
	Blocking     bool               `json:"blocking"`
}

type UnknownDescriptor struct {
	Question string `json:"question"`
	Reason   string `json:"reason"`
	Blocking bool   `json:"blocking"`
}

type ContextBlock struct {
	ID                    string                `json:"id"`
	Kind                  PackBlockKind         `json:"kind"`
	Representation        BlockRepresentation   `json:"representation"`
	ExactFragments        []ExactFragment       `json:"exact_fragments"`
	MemoryRefs            []MemoryRef           `json:"memory_refs"`
	ClaimIDs              []string              `json:"claim_ids"`
	EvidenceHandles       []string              `json:"evidence_handles"`
	Facets                []string              `json:"facets"`
	Scopes                []string              `json:"scopes"`
	ValidTime             *TimeRange            `json:"valid_time"`
	KnownAtCommit         uint64                `json:"known_at_commit"`
	Perspective           *Perspective          `json:"perspective"`
	Epistemic             EpistemicState        `json:"epistemic"`
	ConfidenceMicros      uint32                `json:"confidence_micros"`
	Trust                 ContentTrust          `json:"trust"`
	InstructionCapability InstructionCapability `json:"instruction_capability"`
	SourceClass           StringOrOther         `json:"source_class"`
	Taints                []StringOrOther       `json:"taints"`
	Interpretation        InterpretationRule    `json:"interpretation"`
	Support               SupportState          `json:"support"`
	Conflict              *ConflictDescriptor   `json:"conflict"`
	Unknown               *UnknownDescriptor    `json:"unknown"`
}

type PackSections struct {
	Situation     []ContextBlock `json:"situation"`
	SelfContext   []ContextBlock `json:"self_context"`
	Participants  []ContextBlock `json:"participants"`
	SharedHistory []ContextBlock `json:"shared_history"`
	Episodes      []ContextBlock `json:"episodes"`
	Facts         []ContextBlock `json:"facts"`
	Relationships []ContextBlock `json:"relationships"`
	Preferences   []ContextBlock `json:"preferences"`
	Boundaries    []ContextBlock `json:"boundaries"`
	Goals         []ContextBlock `json:"goals"`
	Decisions     []ContextBlock `json:"decisions"`
	Timeline      []ContextBlock `json:"timeline"`
	Procedures    []ContextBlock `json:"procedures"`
	Constraints   []ContextBlock `json:"constraints"`
	OpenLoops     []ContextBlock `json:"open_loops"`
	Conflicts     []ContextBlock `json:"conflicts"`
	Unknowns      []ContextBlock `json:"unknowns"`
}

type EvidenceSelector struct {
	Kind    string  `json:"kind"`
	Start   *uint64 `json:"start,omitempty"`
	End     *uint64 `json:"end,omitempty"`
	Pointer *string `json:"pointer,omitempty"`
}

type PackEvidence struct {
	ID               string           `json:"id"`
	Source           string           `json:"source"`
	Selector         EvidenceSelector `json:"selector"`
	Excerpt          *string          `json:"excerpt"`
	ClaimIDs         []string         `json:"claim_ids"`
	ProvenanceFamily string           `json:"provenance_family"`
	Primary          bool             `json:"primary"`
	TrustMicros      uint32           `json:"trust_micros"`
	SourceClass      StringOrOther    `json:"source_class"`
	Taints           []StringOrOther  `json:"taints"`
	Lineage          []string         `json:"lineage"`
}

type UseDirective struct {
	BlockID    string          `json:"block_id"`
	Action     UseAction       `json:"action"`
	ReasonCode DirectiveReason `json:"reason_code"`
}

type ScopeManifest struct {
	Workspace    string             `json:"workspace"`
	Subject      string             `json:"subject"`
	Scopes       []string           `json:"scopes"`
	Purpose      PackPurpose        `json:"purpose"`
	TemporalView TemporalConstraint `json:"temporal_view"`
	FilterDigest string             `json:"filter_digest"`
}

type GraphManifest struct {
	MemoryRefs   []MemoryRef `json:"memory_refs"`
	ClaimIDs     []string    `json:"claim_ids"`
	ConflictSets []string    `json:"conflict_sets"`
}

type BlockProvenance struct {
	BlockID         string          `json:"block_id"`
	MemoryRefs      []MemoryRef     `json:"memory_refs"`
	EvidenceHandles []string        `json:"evidence_handles"`
	SourceClasses   []StringOrOther `json:"source_classes"`
}

type ProvenanceManifest struct {
	CompilerVersion    string            `json:"compiler_version"`
	PolicyFilterDigest string            `json:"policy_filter_digest"`
	Blocks             []BlockProvenance `json:"blocks"`
	EvidenceSources    map[string]string `json:"evidence_sources"`
}

type FreshnessManifest struct {
	Snapshot ProviderSnapshot `json:"snapshot"`
	Warnings []string         `json:"warnings"`
}

type ContextBudgetUsage struct {
	RenderedTokens       uint32 `json:"rendered_tokens"`
	ControlTokens        uint32 `json:"control_tokens"`
	DataTokens           uint32 `json:"data_tokens"`
	Blocks               uint32 `json:"blocks"`
	EvidenceBlocks       uint32 `json:"evidence_blocks"`
	RawEvidenceTokens    uint32 `json:"raw_evidence_tokens"`
	HistoryTokens        uint32 `json:"history_tokens"`
	ConflictTokens       uint32 `json:"conflict_tokens"`
	SerializedBytes      uint32 `json:"serialized_bytes"`
	SelectionEvaluations uint32 `json:"selection_evaluations"`
}

type Omission struct {
	BlockID string         `json:"block_id"`
	Reason  OmissionReason `json:"reason"`
}

type PackSufficiencyReport struct {
	Sufficient          bool     `json:"sufficient"`
	CoveredFacets       []string `json:"covered_facets"`
	MissingFacets       []string `json:"missing_facets"`
	UnresolvedConflicts []string `json:"unresolved_conflicts"`
	BlockingUnknowns    []string `json:"blocking_unknowns"`
	UnsupportedBlocks   []string `json:"unsupported_blocks"`
}

type CompilationReport struct {
	CompilerVersion    string                `json:"compiler_version"`
	SchemaVersion      string                `json:"schema_version"`
	ModelProfile       string                `json:"model_profile"`
	Tokenizer          string                `json:"tokenizer"`
	Renderer           RendererKind          `json:"renderer"`
	Budget             ContextBudgets        `json:"budget"`
	Usage              ContextBudgetUsage    `json:"usage"`
	SoftBudgetExceeded bool                  `json:"soft_budget_exceeded"`
	SelectedBlocks     []string              `json:"selected_blocks"`
	Omissions          []Omission            `json:"omissions"`
	Sufficiency        PackSufficiencyReport `json:"sufficiency"`
}

type NoMemoryResult struct {
	Reason        NoMemoryReason `json:"reason"`
	MissingFacets []string       `json:"missing_facets"`
}

type ContextContinuationToken struct {
	Opaque string `json:"opaque"`
}

type ContextPack struct {
	SchemaVersion string                    `json:"schema_version"`
	ID            string                    `json:"id"`
	Status        PackStatus                `json:"status"`
	Snapshot      ProviderSnapshot          `json:"snapshot"`
	Purpose       PackPurpose               `json:"purpose"`
	ScopeManifest ScopeManifest             `json:"scope_manifest"`
	Sections      PackSections              `json:"sections"`
	Evidence      []PackEvidence            `json:"evidence"`
	UseDirectives []UseDirective            `json:"use_directives"`
	GraphManifest GraphManifest             `json:"graph_manifest"`
	Freshness     FreshnessManifest         `json:"freshness"`
	Provenance    ProvenanceManifest        `json:"provenance"`
	Continuation  *ContextContinuationToken `json:"continuation"`
	Compilation   CompilationReport         `json:"compilation"`
	NoMemory      *NoMemoryResult           `json:"no_memory"`
}

// RenderedContextPayload deliberately has no combined prompt field: trusted
// compiler control and recalled untrusted data are separate channels.
type RenderedContextPayload struct {
	ProfileID      string       `json:"profile_id"`
	Renderer       RendererKind `json:"renderer"`
	TrustedControl string       `json:"trusted_control"`
	UntrustedData  string       `json:"untrusted_data"`
	ControlTokens  uint32       `json:"control_tokens"`
	DataTokens     uint32       `json:"data_tokens"`
	TotalTokens    uint32       `json:"total_tokens"`
}

type RecallBudgetUsage struct {
	NodesExamined      uint32 `json:"nodes_examined"`
	GraphEdgesExamined uint32 `json:"graph_edges_examined"`
	MaxHopReached      uint8  `json:"max_hop_reached"`
	EvidenceUnits      uint32 `json:"evidence_units"`
	ContextTokens      uint32 `json:"context_tokens"`
}

type ContextPackTrace struct {
	TraceID                 string             `json:"trace_id"`
	Snapshot                ProviderSnapshot   `json:"snapshot"`
	FilterDigest            string             `json:"filter_digest"`
	RecallStatus            RecallStatus       `json:"recall_status"`
	StopReason              ContextStopReason  `json:"stop_reason"`
	RecallUsage             RecallBudgetUsage  `json:"recall_usage"`
	PackStatus              PackStatus         `json:"pack_status"`
	PackUsage               ContextBudgetUsage `json:"pack_usage"`
	SelectedBlocks          uint32             `json:"selected_blocks"`
	EvidenceBlocks          uint32             `json:"evidence_blocks"`
	MaxProjectionLagCommits uint64             `json:"max_projection_lag_commits"`
	Stale                   bool               `json:"stale"`
	FreshnessWarnings       []string           `json:"freshness_warnings"`
}

type CompileContextResponse struct {
	ContextPack              ContextPack            `json:"context_pack"`
	CanonicalEncoding        string                 `json:"canonical_encoding"`
	CanonicalBytes           ByteArray              `json:"canonical_bytes"`
	CanonicalDigestAlgorithm string                 `json:"canonical_digest_algorithm"`
	CanonicalDigest          string                 `json:"canonical_digest"`
	Rendered                 RenderedContextPayload `json:"rendered"`
	Continuation             *string                `json:"continuation"`
	Trace                    ContextPackTrace       `json:"trace"`
}

// VerifyCanonicalDigest fails unless the exact returned bytes have the
// advertised, supported BLAKE3-256 digest. It never decodes unknown encodings.
func (response CompileContextResponse) VerifyCanonicalDigest() error {
	if response.CanonicalEncoding != ContextPackCanonicalEncoding {
		return errors.New("unsupported ContextPack canonical encoding")
	}
	if response.CanonicalDigestAlgorithm != ContextPackCanonicalDigestAlgorithm {
		return errors.New("unsupported ContextPack canonical digest algorithm")
	}
	claimed, err := hex.DecodeString(response.CanonicalDigest)
	if err != nil || len(claimed) != 32 {
		return errors.New("invalid ContextPack canonical digest")
	}
	computed := blake3.Sum256(response.CanonicalBytes)
	if subtle.ConstantTimeCompare(computed[:], claimed) != 1 {
		return errors.New("ContextPack canonical digest mismatch")
	}
	return nil
}

// CompileContext invokes the first-class typed pipeline; it never reconstructs
// a pack from legacy recall IDs.
func (client *Client) CompileContext(ctx context.Context, request CompileContextRequest) (CompileContextResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	if request.Plan.RequiredFacets == nil {
		request.Plan.RequiredFacets = []PackFacetRequirement{}
	}
	if request.Plan.QueryVector != nil && request.Plan.QueryVector.Values == nil {
		request.Plan.QueryVector.Values = []float32{}
	}
	var response CompileContextResponse
	err := client.post(ctx, ContextPackPath, request, &response, validateCompileContextResponse)
	return response, err
}

func validateCompileContextResponse(object map[string]any) error {
	if err := validateCompileContextWire(object); err != nil {
		return err
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return err
	}
	var response CompileContextResponse
	if err := strictDecode(encoded, &response); err != nil {
		return err
	}
	if response.ContextPack.SchemaVersion == "" || response.CanonicalDigest == "" || response.Trace.TraceID == "" {
		return errors.New("ContextPack identity fields must not be empty")
	}
	if response.CanonicalEncoding != ContextPackCanonicalEncoding {
		return errors.New("unsupported ContextPack canonical encoding")
	}
	if response.CanonicalDigestAlgorithm != ContextPackCanonicalDigestAlgorithm {
		return errors.New("unsupported ContextPack canonical digest algorithm")
	}
	decodedDigest, err := hex.DecodeString(response.CanonicalDigest)
	if err != nil || len(decodedDigest) != 32 || hex.EncodeToString(decodedDigest) != response.CanonicalDigest {
		return errors.New("invalid ContextPack canonical digest")
	}
	if uint32(len(response.CanonicalBytes)) != response.ContextPack.Compilation.Usage.SerializedBytes {
		return errors.New("canonical bytes differ from the ContextPack serialized size")
	}
	if response.ContextPack.Status != response.Trace.PackStatus {
		return errors.New("ContextPack trace status differs from canonical pack")
	}
	if !reflect.DeepEqual(response.ContextPack.Snapshot, response.Trace.Snapshot) {
		return errors.New("ContextPack trace snapshot differs from canonical pack")
	}
	if response.ContextPack.Purpose != response.ContextPack.ScopeManifest.Purpose ||
		!oneOf(response.ContextPack.Purpose, PackPurposeConversation, PackPurposeContinuity, PackPurposeAutobiographical, PackPurposeKnowledge, PackPurposeHistorical, PackPurposeReflective, PackPurposeAction, PackPurposeHandoff, PackPurposeBootstrap) ||
		!reflect.DeepEqual(response.ContextPack.Snapshot, response.ContextPack.Freshness.Snapshot) ||
		response.ContextPack.ScopeManifest.FilterDigest != response.Trace.FilterDigest ||
		response.ContextPack.Provenance.PolicyFilterDigest != response.Trace.FilterDigest ||
		!reflect.DeepEqual(response.ContextPack.Compilation.Usage, response.Trace.PackUsage) {
		return errors.New("ContextPack response contains an inconsistent canonical binding")
	}
	if !oneOf(response.ContextPack.Status, PackSufficient, PackPartial, PackNoMemory) ||
		!oneOf(response.Trace.RecallStatus, RecallStatusSkipped, RecallStatusComplete, RecallStatusPartial, RecallStatusUnknown) ||
		!oneOf(response.Trace.StopReason, StopGateSkipped, StopSufficient, StopNodeBudget, StopGraphBudget, StopHopBudget, StopTokenBudget, StopDeadline, StopNoUsefulCandidates, StopUnknownOrConflicted, StopContinuationBoundary) ||
		!oneOf(response.Rendered.Renderer, RendererCompact, RendererHostedStructured, RendererChat, RendererCoding, RendererCanonicalJSON) {
		return errors.New("ContextPack response contains an unknown status or renderer")
	}
	if uint64(response.Rendered.ControlTokens)+uint64(response.Rendered.DataTokens) != uint64(response.Rendered.TotalTokens) {
		return errors.New("rendered ContextPack token channels do not add to the total")
	}
	if err := validateProviderSnapshot(response.ContextPack.Snapshot); err != nil {
		return err
	}
	for _, blocks := range contextPackSections(response.ContextPack.Sections) {
		for _, block := range blocks {
			if block.InstructionCapability != InstructionCapabilityNone {
				return errors.New("recalled ContextPack data gained instruction capability")
			}
			if !oneOf(block.Kind, BlockSituation, BlockSelfContext, BlockParticipant, BlockSharedHistory, BlockEpisode, BlockFact, BlockRelationship, BlockPreference, BlockBoundary, BlockGoal, BlockDecision, BlockTimeline, BlockProcedure, BlockConstraint, BlockOpenLoop, BlockConflict, BlockUnknown) ||
				!oneOf(block.Representation.Level, CompressionL0Orientation, CompressionL1Summary, CompressionL2Structured, CompressionL3Evidence, CompressionL4Raw) ||
				!oneOf(block.Trust, ContentTrustedSource, ContentMixed, ContentUntrusted, ContentUnknown) ||
				!oneOf(block.Interpretation, InterpretationFactualData, InterpretationHistoricalData, InterpretationConstraintData, InterpretationStyleSignal, InterpretationHypothesisOnly, InterpretationUnknownMarker, InterpretationConflictAlternatives) {
				return errors.New("ContextPack block contains an unknown typed enum")
			}
			if !validStringOrOther(block.SourceClass, "user_statement", "shared_conversation", "repository", "tool_output", "external_document", "sensor", "deterministic_derivation", "model_generated", "imported") {
				return errors.New("ContextPack block contains an unknown source class")
			}
			for _, taint := range block.Taints {
				if !validStringOrOther(taint, "untrusted_instructions", "external_content", "user_controlled", "generated", "secret_like", "personally_sensitive") {
					return errors.New("ContextPack block contains an unknown content taint")
				}
			}
		}
	}
	for _, evidence := range response.ContextPack.Evidence {
		if !validStringOrOther(evidence.SourceClass, "user_statement", "shared_conversation", "repository", "tool_output", "external_document", "sensor", "deterministic_derivation", "model_generated", "imported") {
			return errors.New("ContextPack evidence contains an unknown source class")
		}
		for _, taint := range evidence.Taints {
			if !validStringOrOther(taint, "untrusted_instructions", "external_content", "user_controlled", "generated", "secret_like", "personally_sensitive") {
				return errors.New("ContextPack evidence contains an unknown content taint")
			}
		}
	}
	for _, directive := range response.ContextPack.UseDirectives {
		if !oneOf(directive.Action, UseMentionNaturally, UseSilently, UseConstraintOnly, UseStyleOnly) ||
			!oneOf(directive.ReasonCode, DirectivePolicyAllowsMention, DirectiveMentionDenied, DirectiveExplicitRequestRequired, DirectiveConstraintSemantics, DirectiveStyleSemantics) {
			return errors.New("ContextPack directive contains an unknown typed enum")
		}
	}
	if response.ContextPack.NoMemory != nil && !oneOf(response.ContextPack.NoMemory.Reason, NoMemoryNoAuthorizedCandidates, NoMemoryNoRelevantCandidates, NoMemoryBudgetCouldNotAdmitOptionalMemory) {
		return errors.New("ContextPack no-memory result contains an unknown reason")
	}
	for _, omission := range response.ContextPack.Compilation.Omissions {
		if !oneOf(string(omission.Reason), "outside_requested_scope", "future_transaction", "epistemically_inactive", "secret_redacted", "unsupported_under_evidence_policy", "unresolved_conflict_without_manifest", "redundant", "block_budget", "token_budget", "evidence_budget", "history_budget", "conflict_budget", "serialization_budget", "selection_evaluation_budget", "continuation_boundary") {
			return errors.New("ContextPack compilation contains an unknown omission reason")
		}
	}
	return nil
}

func oneOf[T comparable](value T, allowed ...T) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validStringOrOther(value StringOrOther, standard ...string) bool {
	if value.Other != "" {
		return value.Value == ""
	}
	return value.Value != "" && oneOf(value.Value, standard...)
}

func validateProviderSnapshot(snapshot ProviderSnapshot) error {
	if snapshot.DatabaseID == "" || snapshot.Watermarks.Journal > snapshot.CommitSeq ||
		snapshot.Watermarks.Semantic > snapshot.CommitSeq || snapshot.Watermarks.Lexical > snapshot.CommitSeq ||
		snapshot.Watermarks.Graph > snapshot.CommitSeq {
		return errors.New("invalid ContextPack provider snapshot")
	}
	for _, values := range []map[string]uint64{snapshot.Watermarks.Vector, snapshot.Watermarks.Hierarchy} {
		for _, watermark := range values {
			if watermark > snapshot.CommitSeq {
				return errors.New("invalid ContextPack provider watermark")
			}
		}
	}
	return nil
}

func contextPackSections(sections PackSections) [][]ContextBlock {
	return [][]ContextBlock{
		sections.Situation, sections.SelfContext, sections.Participants, sections.SharedHistory,
		sections.Episodes, sections.Facts, sections.Relationships, sections.Preferences,
		sections.Boundaries, sections.Goals, sections.Decisions, sections.Timeline,
		sections.Procedures, sections.Constraints, sections.OpenLoops, sections.Conflicts,
		sections.Unknowns,
	}
}

func validateCompileContextWire(object map[string]any) error {
	if err := requireKeys(object, "context_pack", "canonical_encoding", "canonical_bytes", "canonical_digest_algorithm", "canonical_digest", "rendered", "continuation", "trace"); err != nil {
		return err
	}
	if err := validateByteArray(object["canonical_bytes"], "canonical bytes"); err != nil {
		return err
	}
	pack, err := requiredObject(object["context_pack"], "context_pack")
	if err != nil {
		return err
	}
	if err := requireKeys(pack, "schema_version", "id", "status", "snapshot", "purpose", "scope_manifest", "sections", "evidence", "use_directives", "graph_manifest", "freshness", "provenance", "continuation", "compilation", "no_memory"); err != nil {
		return err
	}
	if err := validateSnapshotWire(pack["snapshot"]); err != nil {
		return err
	}
	if err := validateScopeWire(pack["scope_manifest"]); err != nil {
		return err
	}
	if err := validateSectionsWire(pack["sections"]); err != nil {
		return err
	}
	if err := validateArrayItems(pack["evidence"], "evidence", validateEvidenceWire); err != nil {
		return err
	}
	if err := validateArrayItems(pack["use_directives"], "use_directives", func(value any) error {
		_, inner := exactObject(value, "use_directive", "block_id", "action", "reason_code")
		return inner
	}); err != nil {
		return err
	}
	graph, err := exactObject(pack["graph_manifest"], "graph_manifest", "memory_refs", "claim_ids", "conflict_sets")
	if err != nil {
		return err
	}
	if err := validateArrayItems(graph["memory_refs"], "graph memory_refs", validateMemoryRefWire); err != nil {
		return err
	}
	if _, err := requiredArray(graph["claim_ids"], "graph claim_ids"); err != nil {
		return err
	}
	if _, err := requiredArray(graph["conflict_sets"], "graph conflict_sets"); err != nil {
		return err
	}
	freshness, err := exactObject(pack["freshness"], "freshness", "snapshot", "warnings")
	if err != nil {
		return err
	}
	if err := validateSnapshotWire(freshness["snapshot"]); err != nil {
		return err
	}
	if _, err := requiredArray(freshness["warnings"], "freshness warnings"); err != nil {
		return err
	}
	provenance, err := exactObject(pack["provenance"], "provenance", "compiler_version", "policy_filter_digest", "blocks", "evidence_sources")
	if err != nil {
		return err
	}
	if err := validateArrayItems(provenance["blocks"], "provenance.blocks", func(value any) error {
		block, inner := exactObject(value, "block_provenance", "block_id", "memory_refs", "evidence_handles", "source_classes")
		if inner != nil {
			return inner
		}
		return validateArrayItems(block["memory_refs"], "memory_refs", validateMemoryRefWire)
	}); err != nil {
		return err
	}
	if _, err := requiredObject(provenance["evidence_sources"], "evidence sources"); err != nil {
		return err
	}
	if pack["continuation"] != nil {
		if _, err := exactObject(pack["continuation"], "pack continuation", "opaque"); err != nil {
			return err
		}
	}
	if err := validateCompilationWire(pack["compilation"]); err != nil {
		return err
	}
	if pack["no_memory"] != nil {
		noMemory, err := exactObject(pack["no_memory"], "no_memory", "reason", "missing_facets")
		if err != nil {
			return err
		}
		if _, err := requiredArray(noMemory["missing_facets"], "no_memory missing_facets"); err != nil {
			return err
		}
	}
	if _, err := exactObject(object["rendered"], "rendered", "profile_id", "renderer", "trusted_control", "untrusted_data", "control_tokens", "data_tokens", "total_tokens"); err != nil {
		return err
	}
	trace, err := exactObject(object["trace"], "trace", "trace_id", "snapshot", "filter_digest", "recall_status", "stop_reason", "recall_usage", "pack_status", "pack_usage", "selected_blocks", "evidence_blocks", "max_projection_lag_commits", "stale", "freshness_warnings")
	if err != nil {
		return err
	}
	if err := validateSnapshotWire(trace["snapshot"]); err != nil {
		return err
	}
	if _, err := exactObject(trace["recall_usage"], "recall_usage", "nodes_examined", "graph_edges_examined", "max_hop_reached", "evidence_units", "context_tokens"); err != nil {
		return err
	}
	if _, err := requiredArray(trace["freshness_warnings"], "trace freshness_warnings"); err != nil {
		return err
	}
	return validateUsageWire(trace["pack_usage"])
}

func validateByteArray(value any, name string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s must be an octet array", name)
	}
	for _, item := range items {
		number, ok := item.(json.Number)
		if !ok {
			return fmt.Errorf("%s must be an octet array", name)
		}
		if _, err := strconv.ParseUint(number.String(), 10, 8); err != nil {
			return fmt.Errorf("%s must be an octet array", name)
		}
	}
	return nil
}

func validateSnapshotWire(value any) error {
	snapshot, err := exactObject(value, "snapshot", "database_id", "commit_seq", "watermarks")
	if err != nil {
		return err
	}
	watermarks, err := exactObject(snapshot["watermarks"], "recall watermarks", "journal", "semantic", "lexical", "vector", "graph", "hierarchy")
	if err != nil {
		return err
	}
	if _, err := requiredObject(watermarks["vector"], "vector watermarks"); err != nil {
		return err
	}
	_, err = requiredObject(watermarks["hierarchy"], "hierarchy watermarks")
	return err
}

func validateScopeWire(value any) error {
	scope, err := exactObject(value, "scope manifest", "workspace", "subject", "scopes", "purpose", "temporal_view", "filter_digest")
	if err != nil {
		return err
	}
	if _, err := requiredArray(scope["scopes"], "scope list"); err != nil {
		return err
	}
	return validateTemporalWire(scope["temporal_view"])
}

func validateTemporalWire(value any) error {
	temporal, err := requiredObject(value, "temporal constraint")
	if err != nil {
		return err
	}
	kind, ok := temporal["kind"].(string)
	if !ok {
		return errors.New("invalid temporal constraint kind")
	}
	var keys []string
	switch kind {
	case "current":
		keys = []string{"kind"}
	case "valid_during":
		keys = []string{"kind", "range"}
	case "known_at":
		keys = []string{"kind", "commit_seq"}
	case "bitemporal":
		keys = []string{"kind", "valid_during", "known_at"}
	default:
		return errors.New("invalid temporal constraint kind")
	}
	return requireKeys(temporal, keys...)
}

func validateSectionsWire(value any) error {
	keys := []string{"situation", "self_context", "participants", "shared_history", "episodes", "facts", "relationships", "preferences", "boundaries", "goals", "decisions", "timeline", "procedures", "constraints", "open_loops", "conflicts", "unknowns"}
	sections, err := requiredObject(value, "sections")
	if err != nil {
		return err
	}
	if err := requireKeys(sections, keys...); err != nil {
		return err
	}
	for _, key := range keys {
		if err := validateArrayItems(sections[key], "sections."+key, validateBlockWire); err != nil {
			return err
		}
	}
	return nil
}

func validateBlockWire(value any) error {
	block, err := exactObject(value, "context block", "id", "kind", "representation", "exact_fragments", "memory_refs", "claim_ids", "evidence_handles", "facets", "scopes", "valid_time", "known_at_commit", "perspective", "epistemic", "confidence_micros", "trust", "instruction_capability", "source_class", "taints", "interpretation", "support", "conflict", "unknown")
	if err != nil {
		return err
	}
	representation, err := exactObject(block["representation"], "representation", "level", "summary", "fields", "omitted_facets")
	if err != nil {
		return err
	}
	if _, err := requiredObject(representation["fields"], "representation fields"); err != nil {
		return err
	}
	if _, err := requiredArray(representation["omitted_facets"], "omitted facets"); err != nil {
		return err
	}
	if err := validateArrayItems(block["exact_fragments"], "exact_fragments", func(item any) error { _, inner := exactObject(item, "exact fragment", "label", "value"); return inner }); err != nil {
		return err
	}
	if err := validateArrayItems(block["memory_refs"], "memory_refs", validateMemoryRefWire); err != nil {
		return err
	}
	for _, key := range []string{"claim_ids", "evidence_handles", "facets", "scopes", "taints"} {
		if _, err := requiredArray(block[key], "block "+key); err != nil {
			return err
		}
	}
	if block["valid_time"] != nil {
		if _, err := exactObject(block["valid_time"], "valid_time", "start", "end"); err != nil {
			return err
		}
	}
	if block["perspective"] != nil {
		if _, err := exactObject(block["perspective"], "perspective", "knower", "experiencer", "narrator", "role"); err != nil {
			return err
		}
	}
	epistemic, err := exactObject(block["epistemic"], "epistemic", "basis", "acceptance", "conflict", "lifecycle")
	if err != nil {
		return err
	}
	if err := validateStateVariant(epistemic["conflict"], "conflict state", map[string][]string{"none": {"state"}, "disputed": {"state"}, "in_conflict": {"state", "set_id"}, "resolved": {"state", "set_id"}}); err != nil {
		return err
	}
	if err := validateStateVariant(block["support"], "support", map[string][]string{"supported": {"state"}, "unsupported": {"state", "reason"}}); err != nil {
		return err
	}
	if block["conflict"] != nil {
		conflict, err := exactObject(block["conflict"], "conflict", "set_id", "alternatives", "resolution", "blocking")
		if err != nil {
			return err
		}
		if err := validateStateVariant(conflict["resolution"], "conflict resolution", map[string][]string{"unresolved": {"state"}, "resolved": {"state", "winner", "rationale"}}); err != nil {
			return err
		}
	}
	if block["unknown"] != nil {
		if _, err := exactObject(block["unknown"], "unknown", "question", "reason", "blocking"); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceWire(value any) error {
	evidence, err := exactObject(value, "evidence", "id", "source", "selector", "excerpt", "claim_ids", "provenance_family", "primary", "trust_micros", "source_class", "taints", "lineage")
	if err != nil {
		return err
	}
	for _, key := range []string{"claim_ids", "taints", "lineage"} {
		if _, err := requiredArray(evidence[key], "evidence "+key); err != nil {
			return err
		}
	}
	selector, err := requiredObject(evidence["selector"], "evidence selector")
	if err != nil {
		return err
	}
	kind, ok := selector["kind"].(string)
	if !ok {
		return errors.New("invalid evidence selector")
	}
	switch kind {
	case "text_bytes", "lines", "time_micros":
		return requireKeys(selector, "kind", "start", "end")
	case "json_pointer":
		return requireKeys(selector, "kind", "pointer")
	case "whole":
		return requireKeys(selector, "kind")
	default:
		return errors.New("invalid evidence selector")
	}
}

func validateMemoryRefWire(value any) error {
	_, err := exactObject(value, "memory ref", "kind", "id")
	return err
}

func validateCompilationWire(value any) error {
	compilation, err := exactObject(value, "compilation", "compiler_version", "schema_version", "model_profile", "tokenizer", "renderer", "budget", "usage", "soft_budget_exceeded", "selected_blocks", "omissions", "sufficiency")
	if err != nil {
		return err
	}
	if _, err := exactObject(compilation["budget"], "context budgets", "hard_tokens", "soft_tokens", "max_blocks", "max_evidence_blocks", "max_raw_evidence_tokens", "max_history_tokens", "max_conflict_tokens", "max_serialized_bytes", "max_selection_evaluations"); err != nil {
		return err
	}
	if err := validateUsageWire(compilation["usage"]); err != nil {
		return err
	}
	if _, err := requiredArray(compilation["selected_blocks"], "selected blocks"); err != nil {
		return err
	}
	if err := validateArrayItems(compilation["omissions"], "omissions", func(value any) error { _, inner := exactObject(value, "omission", "block_id", "reason"); return inner }); err != nil {
		return err
	}
	sufficiency, err := exactObject(compilation["sufficiency"], "sufficiency", "sufficient", "covered_facets", "missing_facets", "unresolved_conflicts", "blocking_unknowns", "unsupported_blocks")
	if err != nil {
		return err
	}
	for _, key := range []string{"covered_facets", "missing_facets", "unresolved_conflicts", "blocking_unknowns", "unsupported_blocks"} {
		if _, err := requiredArray(sufficiency[key], "sufficiency "+key); err != nil {
			return err
		}
	}
	return nil
}

func validateUsageWire(value any) error {
	_, err := exactObject(value, "context usage", "rendered_tokens", "control_tokens", "data_tokens", "blocks", "evidence_blocks", "raw_evidence_tokens", "history_tokens", "conflict_tokens", "serialized_bytes", "selection_evaluations")
	return err
}

func validateStateVariant(value any, name string, variants map[string][]string) error {
	object, err := requiredObject(value, name)
	if err != nil {
		return err
	}
	state, ok := object["state"].(string)
	if !ok {
		return fmt.Errorf("invalid %s", name)
	}
	keys, ok := variants[state]
	if !ok {
		return fmt.Errorf("invalid %s", name)
	}
	return requireKeys(object, keys...)
}

func requiredObject(value any, name string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return object, nil
}

func exactObject(value any, name string, keys ...string) (map[string]any, error) {
	object, err := requiredObject(value, name)
	if err != nil {
		return nil, err
	}
	if err := requireKeys(object, keys...); err != nil {
		return nil, err
	}
	return object, nil
}

func validateArrayItems(value any, name string, validate func(any) error) error {
	items, err := requiredArray(value, name)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := validate(item); err != nil {
			return err
		}
	}
	return nil
}

func requiredArray(value any, name string) ([]any, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", name)
	}
	return items, nil
}
