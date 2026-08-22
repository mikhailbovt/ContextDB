use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Monotonic transaction sequence in one database instance. Zero is the empty database.
pub type CommitSeq = u64;

/// Stable logical identifier used by the generic reference shell.
pub type LogicalId = String;

/// Inclusive/exclusive domain-time interval. Missing bounds mean unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidTime {
    /// Inclusive start, expressed as Unix nanoseconds in this reference layer.
    pub from: Option<i128>,
    /// Exclusive end, expressed as Unix nanoseconds in this reference layer.
    pub to: Option<i128>,
}

impl ValidTime {
    /// An interval without domain-time bounds.
    pub const UNBOUNDED: Self = Self {
        from: None,
        to: None,
    };

    /// Returns whether the interval contains a domain-time instant.
    #[must_use]
    pub fn contains(self, instant: i128) -> bool {
        self.from.is_none_or(|from| instant >= from) && self.to.is_none_or(|to| instant < to)
    }

    /// Returns whether the interval is well formed.
    #[must_use]
    pub fn is_valid(self) -> bool {
        match (self.from, self.to) {
            (Some(from), Some(to)) => from < to,
            _ => true,
        }
    }
}

/// Sensitivity ordering used by the deterministic authorization gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Safe for the configured public audience.
    #[default]
    Public,
    /// Ordinary workspace-internal information.
    Internal,
    /// Private information with an explicit audience.
    Private,
    /// High-assurance compartmented information.
    Restricted,
}

/// Current consent governing retrieval of a logical object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Consent {
    /// Retrieval is permitted subject to the other policy dimensions.
    #[default]
    Granted,
    /// No decision exists; fail closed.
    Unknown,
    /// Retrieval is explicitly denied.
    Denied,
}

/// Policy data kept outside encrypted/erasable content so authorization can run first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessLabel {
    /// Administrative isolation boundary.
    pub workspace: LogicalId,
    /// Semantic compartments. At least one must be granted unless this set is empty.
    pub scopes: BTreeSet<LogicalId>,
    /// Subjects that jointly own the memory.
    pub owners: BTreeSet<LogicalId>,
    /// Subjects allowed to retrieve it. The reserved value `*` means public audience.
    pub audience: BTreeSet<LogicalId>,
    /// Purpose grants paired to audience keys. When present, these take precedence over the
    /// legacy Cartesian `audience`/`purposes` fields and avoid accidentally widening access.
    #[serde(default)]
    pub audience_purpose_grants: BTreeMap<LogicalId, BTreeSet<String>>,
    /// Purpose strings allowed by policy. Empty means any otherwise-authorized purpose.
    pub purposes: BTreeSet<String>,
    /// Confidentiality ceiling required of a caller.
    pub sensitivity: Sensitivity,
    /// Explicit subject consent.
    pub consent: Consent,
    /// Whether ordinary retrieval is permitted. Conditional core policy is mapped to false.
    #[serde(default = "default_true")]
    pub retrievable: bool,
}

/// Authorization context resolved before candidate generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Calling memory subject.
    pub subject: LogicalId,
    /// Resolved group, memory-space, and public audience keys for the caller.
    #[serde(default)]
    pub audiences: BTreeSet<LogicalId>,
    /// Administrative workspace selected by the host.
    pub workspace: LogicalId,
    /// Scope grants already resolved by the host policy layer.
    pub scopes: BTreeSet<LogicalId>,
    /// Purpose of the current read.
    pub purpose: String,
    /// Maximum sensitivity the caller may see.
    pub clearance: Sensitivity,
}

impl Principal {
    /// Evaluates only non-content policy metadata.
    #[must_use]
    pub fn allows(&self, label: &AccessLabel) -> bool {
        if label.workspace != self.workspace
            || label.consent != Consent::Granted
            || !label.retrievable
            || label.sensitivity > self.clearance
        {
            return false;
        }
        let is_owner = label.owners.contains(&self.subject);
        let has_scope =
            label.scopes.is_empty() || label.scopes.iter().any(|scope| self.scopes.contains(scope));
        let has_audience_grant = if label.audience_purpose_grants.is_empty() {
            (label.audience.contains(&self.subject) || label.audience.contains("*"))
                && (label.purposes.is_empty() || label.purposes.contains(&self.purpose))
                || is_owner && (label.purposes.is_empty() || label.purposes.contains(&self.purpose))
        } else {
            self.audience_keys(is_owner).any(|audience| {
                label
                    .audience_purpose_grants
                    .get(audience)
                    .is_some_and(|purposes| purposes.contains(&self.purpose))
            })
        };
        has_audience_grant && has_scope
    }

    fn audience_keys(&self, is_owner: bool) -> impl Iterator<Item = &str> {
        std::iter::once(self.subject.as_str())
            .chain(std::iter::once("*"))
            .chain(is_owner.then_some("@owner"))
            .chain(self.audiences.iter().map(String::as_str))
    }
}

const fn default_true() -> bool {
    true
}

/// High-level record families understood by the correctness oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// Stable graph node identity or one of its revisions.
    Node,
    /// Bitemporal factual assertion.
    Claim,
    /// Traversable graph relation.
    Edge,
    /// Revisioned conflict set.
    Conflict,
    /// Evidence metadata and selector.
    Evidence,
    /// Quarantined proposal, explicitly outside published truth.
    Candidate,
    /// Preference, boundary, goal, commitment, relationship, or self state.
    SemanticObject,
    /// Session or situation working state.
    RuntimeState,
    /// Domain-pack-owned extension record.
    DomainExtension,
}

/// Lifecycle status independent from the epistemic basis of a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Current and eligible for ordinary reads.
    #[default]
    Active,
    /// Replaced by another revision or object.
    Superseded,
    /// Explicitly withdrawn but retained for history.
    Retracted,
    /// Suppressed from ordinary reads while retained.
    Suppressed,
}

/// Metadata needed for exact graph and cardinality validation without reading content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SemanticLinks {
    /// Claim subject, if this is a claim.
    pub subject: Option<LogicalId>,
    /// Edge source, if this is an edge.
    pub source: Option<LogicalId>,
    /// Edge target, if this is an edge.
    pub target: Option<LogicalId>,
    /// Predicate identifier for claims and edges.
    pub predicate: Option<LogicalId>,
    /// Conflict set containing this claim.
    pub conflict_set: Option<LogicalId>,
    /// Claims or revisions explicitly superseded by this record.
    pub supersedes: BTreeSet<LogicalId>,
    /// Evidence identifiers supporting this record.
    pub evidence: BTreeSet<LogicalId>,
    /// Conflict members for a conflict-set record.
    pub conflict_members: BTreeSet<LogicalId>,
    /// Whether the predicate is single-valued in one scope signature.
    pub single_valued: bool,
}

/// A caller-supplied logical object before transaction-time metadata is assigned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogicalRecord {
    /// Stable identifier never reused within a database instance.
    pub id: LogicalId,
    /// Stable record family.
    pub kind: RecordKind,
    /// Authorization metadata evaluated before content materialization.
    pub access: AccessLabel,
    /// Domain-time validity.
    pub valid_time: ValidTime,
    /// Current logical lifecycle.
    pub lifecycle: Lifecycle,
    /// Typed graph/cardinality linkage metadata.
    pub links: SemanticLinks,
    /// Canonical semantic data. The engine stores this through erasable indirection.
    pub value: Value,
    /// Optional normalized text used by the exact lexical oracle after authorization.
    pub search_text: Option<String>,
    /// Optional full-precision vector used by the exact vector oracle after authorization.
    pub vector: Option<Vec<f32>>,
    /// Extensible deterministic metadata; callers should use sorted keys.
    pub attributes: BTreeMap<String, Value>,
}

/// One committed revision in system time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredRevision {
    /// Stable record identifier.
    pub id: LogicalId,
    /// Revision ordinal starting at one.
    pub revision: u32,
    /// Commit where this revision became visible.
    pub transaction_from: CommitSeq,
    /// First commit where this revision is no longer current.
    pub transaction_to: Option<CommitSeq>,
    /// Record metadata excluding erasable content.
    pub record: LogicalRecordMetadata,
    /// Digest and indirection key for erasable content.
    pub content: ContentRef,
}

/// Non-content subset of a logical record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalRecordMetadata {
    /// Stable record family.
    pub kind: RecordKind,
    /// Authorization label.
    pub access: AccessLabel,
    /// Domain-time validity.
    pub valid_time: ValidTime,
    /// Logical lifecycle.
    pub lifecycle: Lifecycle,
    /// Graph/cardinality linkage metadata.
    pub links: SemanticLinks,
}

/// Content-addressed indirection used to make deletion effective across retained snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRef {
    /// Content identifier (BLAKE3 digest in the reference implementation).
    pub id: String,
    /// Integrity digest of the canonical content payload.
    pub digest: String,
}

/// Materialized record returned only after authorization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaterializedRecord {
    /// Committed revision metadata.
    pub revision: StoredRevision,
    /// Erasable semantic content.
    pub content: RecordContent,
}

/// Content payload behind an erasable indirection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordContent {
    /// Canonical semantic value.
    pub value: Value,
    /// Exact lexical text.
    pub search_text: Option<String>,
    /// Full-precision vector.
    pub vector: Option<Vec<f32>>,
    /// Extensible attributes.
    pub attributes: BTreeMap<String, Value>,
}

/// Typed semantic mutation set committed atomically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticTransaction {
    /// Snapshot precondition. The commit fails when head has changed.
    pub base_seq: CommitSeq,
    /// Stable caller key for retry safety.
    pub idempotency_key: String,
    /// Ordered mutations; order is preserved in the publication record.
    pub mutations: Vec<Mutation>,
}

/// Logical mutations supported by the deterministic oracle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Mutation {
    /// Create or revise a typed object.
    Put {
        /// Complete new logical value.
        record: LogicalRecord,
        /// Optional optimistic per-object revision precondition.
        expected_revision: Option<u32>,
    },
    /// Correct an existing object with a separate successor identity.
    Correct {
        /// Existing object to supersede.
        target: LogicalId,
        /// Replacement record, which must list the target in `supersedes`.
        replacement: LogicalRecord,
    },
    /// Retract an object while retaining its evidence/history.
    Retract {
        /// Stable object identifier.
        target: LogicalId,
    },
    /// Hard-delete erasable content and publish a non-content tombstone.
    Delete {
        /// Stable object identifier.
        target: LogicalId,
        /// Actor requesting deletion.
        requested_by: LogicalId,
        /// Non-sensitive deletion reason code.
        reason: String,
    },
}

/// Immutable raw observation accepted independently from semantic publication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationInput {
    /// Caller-controlled retry key.
    pub idempotency_key: String,
    /// Stable observation identifier.
    pub observation_id: LogicalId,
    /// Authorization metadata.
    pub access: AccessLabel,
    /// Source/stream-safe metadata.
    pub metadata: BTreeMap<String, Value>,
    /// Raw evidence content stored through erasable indirection.
    pub content: Value,
}

/// Snapshot handle fixed to one coherent commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Stable database namespace.
    pub database_id: String,
    /// Visible commit sequence.
    pub commit_seq: CommitSeq,
    /// Logical semantic generation.
    pub semantic_generation: u64,
    /// Physical generation; always zero for the in-memory oracle.
    pub storage_generation: u64,
}

/// Explicit freshness state returned with reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Watermarks {
    /// Last committed observation or semantic publication.
    pub journal: CommitSeq,
    /// Last semantic publication.
    pub semantic: CommitSeq,
    /// Exact lexical oracle covers this sequence.
    pub lexical: CommitSeq,
    /// Exact vector oracle covers this sequence.
    pub vector: CommitSeq,
    /// Exact graph oracle covers this sequence.
    pub graph: CommitSeq,
}

/// Outcome of an idempotent write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitReceipt {
    /// Published commit sequence.
    pub commit_seq: CommitSeq,
    /// True when this response replays an earlier successful request.
    pub replayed: bool,
    /// Digest of the exact validated request.
    pub request_digest: String,
    /// Freshness after the commit.
    pub watermarks: Watermarks,
}

/// Immutable metadata for one accepted observation. Its content remains erasable by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRecord {
    /// Stable observation identifier.
    pub observation_id: LogicalId,
    /// Commit at which capture became durable.
    pub accepted_seq: CommitSeq,
    /// Authorization label evaluated before materialization.
    pub access: AccessLabel,
    /// Canonical digest and erasable content indirection.
    pub content: ContentRef,
    /// Non-content source metadata.
    pub metadata: BTreeMap<String, Value>,
}

/// Authorized materialization of one immutable observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaterializedObservation {
    /// Immutable observation metadata.
    pub record: ObservationRecord,
    /// Raw observation content behind the erasable indirection.
    pub content: Value,
}

/// Non-content proof that a hard deletion was published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionTombstone {
    /// Target external identifier.
    pub target: LogicalId,
    /// Actor that requested deletion.
    pub requested_by: LogicalId,
    /// Non-sensitive reason code.
    pub reason: String,
    /// First commit where the target is deleted.
    pub effective_seq: CommitSeq,
    /// Content indirections erased by the reference implementation.
    pub erased_content_refs: BTreeSet<String>,
}

/// Immutable semantic-journal event. Content is referenced, never embedded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum JournalEvent {
    /// Raw observation accepted to the journal.
    ObservationAccepted {
        /// Stable observation ID.
        observation_id: LogicalId,
        /// Digest of the exact accepted request.
        request_digest: String,
        /// Erasable request content.
        request_content: ContentRef,
    },
    /// Validated semantic transaction atomically published.
    SemanticPublished {
        /// Digest of the exact validated transaction.
        request_digest: String,
        /// Erasable exact transaction bytes.
        request_content: ContentRef,
        /// Stable IDs changed by the transaction.
        affected_ids: BTreeSet<LogicalId>,
    },
}

/// One append-only semantic journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    /// Publication sequence, assigned only by atomic commit.
    pub commit_seq: CommitSeq,
    /// Previous record digest, if any.
    pub previous_digest: Option<String>,
    /// Stable digest chaining metadata and event.
    pub record_digest: String,
    /// Journal event.
    pub event: JournalEvent,
}

/// Content-free event candidate selected by the trusted workspace index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceEventCandidateKind {
    /// One immutable observation may be visible to the caller.
    ObservationAccepted {
        /// Stable observation identifier; content is not loaded by the index.
        observation_id: LogicalId,
    },
    /// One changed semantic record may be visible to the caller.
    SemanticRecordChanged {
        /// Stable record identifier; content is not loaded by the index.
        record_id: LogicalId,
    },
    /// End-of-publication marker used to derive an authorized index watermark event.
    SemanticWatermark,
}

/// One bounded candidate addressed by a tenant-local event position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEventCandidate {
    /// One-based journal sequence within the selected workspace.
    pub workspace_seq: CommitSeq,
    /// Stable candidate ordinal within the journal publication.
    pub ordinal: u32,
    /// Internal commit used only to open the candidate's historical snapshot.
    pub commit_seq: CommitSeq,
    /// Content-free digest used to derive stable event identities.
    pub record_digest: String,
    /// Minimal candidate metadata; protected payload remains untouched.
    pub kind: WorkspaceEventCandidateKind,
}

/// Strictly bounded tenant-local event-candidate page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEventPage {
    /// Candidates selected strictly after the supplied local cursor.
    pub candidates: Vec<WorkspaceEventCandidate>,
    /// Last tenant-local candidate position examined by storage.
    pub scanned_through: (CommitSeq, u32),
    /// Whether additional indexed candidates remain after this page.
    pub has_more: bool,
}

/// Public shape of a canonical logical export.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogicalExport {
    /// Export contract version.
    pub format: String,
    /// Stable database namespace.
    pub database_id: String,
    /// Current global commit sequence.
    pub head: CommitSeq,
    /// Freshness watermarks.
    pub watermarks: Watermarks,
    /// All retained system-time revisions in stable key order.
    pub histories: BTreeMap<LogicalId, Vec<StoredRevision>>,
    /// Immutable observation records in stable key order.
    pub observations: BTreeMap<LogicalId, ObservationRecord>,
    /// Hard-deletion proofs.
    pub tombstones: BTreeMap<LogicalId, DeletionTombstone>,
    /// Semantic journal in publication order.
    pub journal: Vec<JournalRecord>,
    /// Retry outcomes indexed by a digest of the caller's idempotency key.
    pub idempotency: BTreeMap<String, IdempotencyRecord>,
    /// Erasable content needed to reconstruct non-deleted logical state.
    pub contents: BTreeMap<String, Value>,
}

/// Durable retry metadata that contains no plaintext request content or key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    /// Digest of the exact request, including its operation class.
    pub request_digest: String,
    /// Original successful outcome.
    pub receipt: CommitReceipt,
}

/// Direction for exact graph traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Follow source to target.
    Outgoing,
    /// Follow target to source.
    Incoming,
    /// Follow both directions.
    Both,
}

/// Deterministic exact-search result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    /// Record identifier.
    pub id: LogicalId,
    /// Higher scores sort first.
    pub score: f32,
}

/// Privacy-safe trace for an exact operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadTrace {
    /// Snapshot used by the complete operation.
    pub snapshot_seq: CommitSeq,
    /// Operation name.
    pub operation: String,
    /// Count after authorization, never count of the global collection.
    pub authorized_candidates: usize,
    /// Returned stable identifiers.
    pub selected_ids: Vec<LogicalId>,
    /// Freshness accompanying this operation.
    pub watermarks: Watermarks,
}

/// Exact operation response with a privacy-safe trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Traced<T> {
    /// Operation result.
    pub value: T,
    /// Deterministic explain trace.
    pub trace: ReadTrace,
}

/// Deterministic transaction failpoints used for crash/replay tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Failpoint {
    /// Normal commit.
    #[default]
    None,
    /// Fail after validation but before any state is published.
    BeforePublish,
    /// Publish atomically, then simulate loss of the response.
    AfterPublish,
}
