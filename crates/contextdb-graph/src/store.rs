use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

use contextdb_core::{
    Artifact, Claim, ClaimRevision, CommitSeq, ConflictSet, ConflictSetRevision, Edge,
    EdgeRevision, LifecycleState, MemorySpace, MemorySpaceId, MemorySubject, MemorySubjectId, Node,
    NodeId, NodeRevision, TransactionRevision, Validate, Workspace, WorkspaceId,
};
use contextdb_journal::{
    JournalEvent, PublicationReceipt, ValidatedMaintenanceBytes, ValidatedMutationBytes,
};
use contextdb_storage::{
    Durability, ReadSnapshot, ScanPage, ScanPageRequest, SnapshotSelector, StorageEngine,
    WriteTransaction,
};
use serde::{Deserialize, Serialize};

use crate::codec::{decode, digest, encode, external_key, revision_key, u64_key};
use crate::keyspace::Keyspaces;
use crate::policy::{allows, audience_key, build_policy};
use crate::{
    AdjacencyPruneReport, AdjacencyRange, AdjacencySegment, AdministrativePolicyIndex,
    ArtifactMetadata, ClaimState, ConflictState, DenseId, Direction, GraphError,
    GraphProjectionReceipt, GraphPublication, GraphSnapshot, IdMapping, NodeState,
    PolicyIndexEntry, PolicyIndexQuery, ReadPrincipal, Result, SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
    SegmentEdge, SegmentManifest, TraversalResult, TraversalTrace,
};

const ACTIVE_MANIFEST: &[u8] = b"active_manifest";
const ADJACENCY_RETENTION_FLOOR: &[u8] = b"adjacency_retention_floor";
const ADJACENCY_RETENTION_BASELINE: &[u8] = b"adjacency_retention_baseline";
const ADJACENCY_MAINTENANCE_EPOCH: &[u8] = b"adjacency_maintenance_epoch";
const ADJACENCY_MAINTENANCE_FENCE: &[u8] = b"adjacency_maintenance_fence";
const NEXT_DENSE_ID: &[u8] = b"next_dense_id";
const SEMANTIC_WATERMARK: &[u8] = b"semantic_watermark";
const BASE_SEGMENT_KEY: &[u8] = b"base";
const SEGMENT_V2_FORMAT: u16 = 2;
const SEGMENT_V2_SCAN_ENTRIES: usize = 1_024;
const SEGMENT_V2_SCAN_BYTES: usize = 8 * 1024 * 1024;
const SEGMENT_V2_MAX_EDGE_VALUE_BYTES: u64 = 64 * 1024;
const SEGMENT_V2_MAX_ROW_EDGES: u64 = 65_536;
const SEGMENT_V2_MAX_ROW_BYTES: u64 = 16 * 1024 * 1024;
const SEGMENT_V2_MAX_ROWS: u64 = 20_000_000;
const SEGMENT_V2_MAX_EDGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const ADJACENCY_READ_MAX_RECORDS: u64 = SEGMENT_V2_MAX_ROW_EDGES * 4;
const ADJACENCY_READ_MAX_BYTES: u64 = SEGMENT_V2_MAX_ROW_BYTES * 4;
// Leave room for the twelve-byte `base || generation` key inside one portable 64 MiB page.
const LEGACY_SEGMENT_MAX_BYTES: usize = contextdb_storage::MAX_SCAN_PAGE_BYTES - 12;
const PRUNE_MAX_HISTORY_ENTRIES: u64 = 1_000_000;
const PRUNE_MAX_GENERATIONS: u64 = 1_000_000;
const PRUNE_FULL_V2_GENERATIONS: u64 = 2;
const SEGMENT_V2_MAX_MERKLE_RECORDS: u64 = segment_v2_merkle_record_count(SEGMENT_V2_MAX_ROWS);
const SEGMENT_V2_MAX_PHYSICAL_RECORDS_PER_GENERATION: u64 = capacity_checked_add(
    SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
    capacity_checked_add(SEGMENT_V2_MAX_ROWS, SEGMENT_V2_MAX_MERKLE_RECORDS),
);
const PRUNE_MAX_PHYSICAL_RECORDS: u64 = capacity_checked_add(
    capacity_checked_mul(
        SEGMENT_V2_MAX_PHYSICAL_RECORDS_PER_GENERATION,
        PRUNE_FULL_V2_GENERATIONS,
    ),
    PRUNE_MAX_GENERATIONS,
);
const PRUNE_MAX_PHYSICAL_BYTES: u64 = 128 * 1024 * 1024 * 1024;

const fn capacity_checked_add(left: u64, right: u64) -> u64 {
    match left.checked_add(right) {
        Some(value) => value,
        None => panic!("graph capacity addition overflow"),
    }
}

const fn capacity_checked_mul(left: u64, right: u64) -> u64 {
    match left.checked_mul(right) {
        Some(value) => value,
        None => panic!("graph capacity multiplication overflow"),
    }
}

const fn segment_v2_merkle_record_count(mut width: u64) -> u64 {
    let mut total = 0_u64;
    while width > 0 {
        total = capacity_checked_add(total, width);
        if width == 1 {
            return total;
        }
        width = capacity_checked_add(width / 2, width % 2);
    }
    total
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SegmentDirectionV2 {
    Outgoing,
    Incoming,
}

impl SegmentDirectionV2 {
    const ALL: [Self; 2] = [Self::Outgoing, Self::Incoming];

    const fn key_byte(self) -> u8 {
        match self {
            Self::Outgoing => 0,
            Self::Incoming => 1,
        }
    }

    const fn row_node(self, edge: &SegmentEdge) -> DenseId {
        match self {
            Self::Outgoing => edge.source,
            Self::Incoming => edge.target,
        }
    }

    const fn other_node(self, edge: &SegmentEdge) -> DenseId {
        match self {
            Self::Outgoing => edge.target,
            Self::Incoming => edge.source,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AdjacencyRowManifestV2 {
    format_version: u16,
    generation: u64,
    built_through_seq: u64,
    direction: SegmentDirectionV2,
    node: DenseId,
    edge_count: u64,
    edge_bytes: u64,
    edge_digest: String,
}

#[derive(Debug)]
struct ManifestHistoryEntry {
    switch_seq: u64,
    manifest: SegmentManifest,
}

#[derive(Debug)]
struct AdjacencyRetentionPlan {
    baseline_generation: u64,
    baseline_switch_seq: Option<u64>,
    baseline_manifest: SegmentManifest,
    active_generation: u64,
    referenced_generations: BTreeMap<u64, u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AdjacencyRetentionBaseline {
    format_version: u16,
    oldest_retained_storage_seq: u64,
    baseline_switch_seq: Option<u64>,
    baseline_generation: u64,
    baseline_manifest: SegmentManifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AdjacencyMaintenanceOperation {
    Compact {
        generation: u64,
        source_storage_seq: u64,
        base_generation: u64,
    },
    Prune {
        oldest_retained_storage_seq: u64,
    },
}

impl AdjacencyMaintenanceOperation {
    const fn name(self) -> &'static str {
        match self {
            Self::Compact { .. } => "compact_graph",
            Self::Prune { .. } => "prune_adjacency_generations",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AdjacencyMaintenanceFence {
    format_version: u16,
    epoch: u64,
    operation: AdjacencyMaintenanceOperation,
}

#[derive(Default)]
struct AdjacencyPrunePhysicalTotals {
    records: u64,
    bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRevision<T> {
    visible_from: u64,
    visible_to: Option<u64>,
    value: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPolicy {
    visible_from: u64,
    value: PolicyIndexEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ApplyOutcome {
    storage_seq: u64,
    replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BitemporalInstant {
    storage_seq: u64,
    semantic_seq: CommitSeq,
    valid_at: contextdb_core::TimestampMicros,
}

/// Atomic canonical graph write batch.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GraphMutation {
    /// Storage snapshot precondition.
    pub base_storage_seq: u64,
    /// Administrative workspaces introduced in this transaction.
    pub workspaces: Vec<Workspace>,
    /// Ownership/isolation spaces introduced in this transaction.
    pub memory_spaces: Vec<MemorySpace>,
    /// Stable cognitive subjects introduced in this transaction.
    pub memory_subjects: Vec<MemorySubject>,
    /// Stable identities created in this transaction.
    pub nodes: Vec<Node>,
    /// Node revisions published in this transaction.
    pub node_revisions: Vec<NodeRevision>,
    /// Stable claim identities.
    pub claims: Vec<Claim>,
    /// Claim revisions.
    pub claim_revisions: Vec<ClaimRevision>,
    /// Stable edge identities.
    pub edges: Vec<Edge>,
    /// Edge revisions.
    pub edge_revisions: Vec<EdgeRevision>,
    /// Stable revisioned conflict identities.
    pub conflicts: Vec<ConflictSet>,
    /// Conflict revisions.
    pub conflict_revisions: Vec<ConflictSetRevision>,
    /// Canonical artifact metadata without blob bytes.
    pub artifacts: Vec<Artifact>,
}

/// Persistent typed temporal graph over a backend-neutral storage engine.
pub struct GraphStore<E: StorageEngine> {
    engine: E,
    keyspaces: Keyspaces,
    write_lock: Mutex<()>,
}

impl<E: StorageEngine> std::fmt::Debug for GraphStore<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("GraphStore").finish_non_exhaustive()
    }
}

impl<E: StorageEngine> GraphStore<E> {
    /// Opens or creates the graph keyspaces in the supplied storage instance.
    pub fn new(engine: E) -> Result<Self> {
        Ok(Self {
            engine,
            keyspaces: Keyspaces::new()?,
            write_lock: Mutex::new(()),
        })
    }

    /// Returns the backend, preserving all graph bytes.
    pub fn into_engine(self) -> E {
        self.engine
    }

    /// Opens one complete graph snapshot.
    pub fn snapshot(&self, selector: SnapshotSelector) -> Result<GraphSnapshot> {
        let (snapshot, storage_seq) = match selector {
            SnapshotSelector::Latest => {
                let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
                let sequence = snapshot.sequence();
                ensure_adjacency_snapshot_retained(
                    sequence,
                    read_and_validate_adjacency_retention(&snapshot, &self.keyspaces)?,
                )?;
                (snapshot, sequence)
            }
            SnapshotSelector::At(storage_seq) => {
                (self.read_at_or_latest(storage_seq)?, storage_seq)
            }
        };
        let manifest = read_manifest_at(&snapshot, &self.keyspaces, storage_seq)?;
        validate_manifest(&manifest)?;
        if manifest.format_version == SEGMENT_V2_FORMAT && manifest.generation > 0 {
            validate_segment_v2_generation(&snapshot, &self.keyspaces, &manifest)?;
        }
        Ok(GraphSnapshot {
            storage_seq,
            semantic_seq: read_semantic_at(&snapshot, &self.keyspaces, storage_seq)?,
            segment_generation: manifest.generation,
        })
    }

    /// Opens the exact physical graph snapshot published for a semantic commit.
    pub fn snapshot_at_semantic(&self, commit_seq: CommitSeq) -> Result<GraphSnapshot> {
        let latest = self.engine.begin_read(SnapshotSelector::Latest)?;
        let storage_seq = latest
            .get(
                &self.keyspaces.semantic_snapshot,
                &u64_key(commit_seq.get()),
            )?
            .map(|bytes| decode::<u64>(&bytes))
            .transpose()?
            .ok_or_else(|| not_found("semantic snapshot", &commit_seq.to_string()))?;
        ensure_adjacency_snapshot_retained(
            storage_seq,
            read_and_validate_adjacency_retention(&latest, &self.keyspaces)?,
        )?;
        let manifest = read_manifest_at(&latest, &self.keyspaces, storage_seq)?;
        validate_manifest(&manifest)?;
        if manifest.format_version == SEGMENT_V2_FORMAT && manifest.generation > 0 {
            validate_segment_v2_generation(&latest, &self.keyspaces, &manifest)?;
        }
        let actual_semantic = read_semantic_at(&latest, &self.keyspaces, storage_seq)?;
        if actual_semantic != commit_seq {
            return Err(GraphError::Corrupt(
                "semantic snapshot mapping does not identify its own logical commit".to_owned(),
            ));
        }
        Ok(GraphSnapshot {
            storage_seq,
            semantic_seq: commit_seq,
            segment_generation: manifest.generation,
        })
    }

    /// Projects one validated journal publication into graph state exactly once.
    ///
    /// The exact bytes remain owned by the journal. The graph persists their digest and the
    /// journal identities atomically with the projection, making recovery after a lost
    /// acknowledgement replay-safe.
    pub fn project_publication(
        &self,
        validated: &ValidatedMutationBytes,
        receipt: PublicationReceipt,
    ) -> Result<GraphProjectionReceipt> {
        if validated.mutation_id() != receipt.mutation_id
            || validated.digest() != receipt.mutation_digest
        {
            return Err(GraphError::Invariant(
                "journal receipt does not identify the validated mutation bytes".to_owned(),
            ));
        }
        let mutation = validated.mutation();
        let expected_outbox = u32::try_from(mutation.derived_work.len())
            .map_err(|_| GraphError::Invariant("semantic outbox exceeds u32".to_owned()))?;
        if receipt.outbox_count != expected_outbox {
            return Err(GraphError::Invariant(
                "journal receipt outbox count disagrees with validated mutation".to_owned(),
            ));
        }
        validate_publication_time(mutation, receipt.commit_seq)?;
        let graph_mutation = GraphMutation {
            base_storage_seq: 0,
            nodes: mutation.node_creates.clone(),
            node_revisions: mutation.node_revisions.clone(),
            claims: mutation.claim_creates.clone(),
            claim_revisions: mutation.claim_revisions.clone(),
            edges: mutation.edge_creates.clone(),
            edge_revisions: mutation.edge_revisions.clone(),
            conflicts: mutation.conflict_creates.clone(),
            conflict_revisions: mutation.conflict_revisions.clone(),
            ..GraphMutation::default()
        };
        let publication = GraphPublication {
            mutation_id: receipt.mutation_id,
            publication_id: receipt.publication_id,
            commit_seq: receipt.commit_seq,
            mutation_digest: receipt.mutation_digest,
        };
        let outcome =
            self.apply_mutation(graph_mutation, receipt.durability, Some(publication), false)?;
        Ok(GraphProjectionReceipt {
            publication,
            storage_seq: outcome.storage_seq,
            replayed: outcome.replayed,
        })
    }

    /// Replays one verified logical journal event into graph state.
    ///
    /// Observations have no graph projection. Semantic publications are applied exactly once.
    /// Maintenance is decoded and authenticated, then rejected explicitly until the corresponding
    /// operation has a graph-native projector; it is never treated as a no-op.
    pub fn project_journal_event(
        &self,
        event: &JournalEvent,
        durability: Durability,
    ) -> Result<Option<GraphProjectionReceipt>> {
        match event {
            JournalEvent::ObservationAccepted { .. } => Ok(None),
            JournalEvent::SemanticPublished {
                commit_seq,
                mutation_id,
                publication_id,
                exact_mutation_bytes,
                mutation_digest,
                outbox,
            } => {
                let validated = ValidatedMutationBytes::from_json(exact_mutation_bytes.clone())
                    .map_err(|error| GraphError::Corrupt(error.to_string()))?;
                if validated.mutation().derived_work != *outbox {
                    return Err(GraphError::Corrupt(
                        "semantic event outbox disagrees with exact mutation bytes".to_owned(),
                    ));
                }
                self.project_publication(
                    &validated,
                    PublicationReceipt {
                        mutation_id: *mutation_id,
                        publication_id: *publication_id,
                        commit_seq: *commit_seq,
                        durability,
                        outbox_count: u32::try_from(outbox.len()).map_err(|_| {
                            GraphError::Corrupt("semantic outbox exceeds u32".to_owned())
                        })?,
                        replayed: false,
                        mutation_digest: *mutation_digest,
                    },
                )
                .map(Some)
            }
            JournalEvent::MaintenancePublished {
                mutation_id,
                exact_mutation_bytes,
                mutation_digest,
                outbox,
                ..
            } => {
                let validated = ValidatedMaintenanceBytes::from_json(exact_mutation_bytes.clone())
                    .map_err(|error| GraphError::Corrupt(error.to_string()))?;
                if validated.mutation_id() != *mutation_id
                    || validated.digest() != *mutation_digest
                    || validated.mutation().derived_work != *outbox
                {
                    return Err(GraphError::Corrupt(
                        "maintenance event disagrees with exact mutation bytes".to_owned(),
                    ));
                }
                Err(GraphError::UnsupportedMaintenance(maintenance_kind(
                    &validated.mutation().operation,
                )))
            }
        }
    }

    /// Atomically writes stable identities, revisions, policy indexes, and adjacency deltas.
    pub fn commit(&self, mutation: GraphMutation, durability: Durability) -> Result<u64> {
        Ok(self
            .apply_mutation(mutation, durability, None, true)?
            .storage_seq)
    }

    fn apply_mutation(
        &self,
        mutation: GraphMutation,
        durability: Durability,
        publication: Option<GraphPublication>,
        enforce_base: bool,
    ) -> Result<ApplyOutcome> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| GraphError::Invariant("graph write lock poisoned".to_owned()))?;
        let mut transaction = self.engine.begin_write()?;
        if let Some(publication) = publication
            && let Some(bytes) = transaction.get(
                &self.keyspaces.publication,
                publication.mutation_id.to_string().as_bytes(),
            )?
        {
            let existing: GraphProjectionReceipt = decode(&bytes)?;
            if existing.publication != publication {
                return Err(GraphError::Invariant(
                    "mutation ID was already projected with different publication bytes".to_owned(),
                ));
            }
            return Ok(ApplyOutcome {
                storage_seq: existing.storage_seq,
                replayed: true,
            });
        }
        if enforce_base && transaction.sequence() != mutation.base_storage_seq {
            return Err(GraphError::Invariant(format!(
                "snapshot precondition failed: expected {}, current {}",
                mutation.base_storage_seq,
                transaction.sequence()
            )));
        }
        validate_batch(&mutation)?;
        let visible_from = transaction
            .sequence()
            .checked_add(1)
            .ok_or_else(|| GraphError::Invariant("storage sequence exhausted".to_owned()))?;
        let previous_semantic = read_semantic_watermark(&transaction, &self.keyspaces)?;
        let semantic_seq = match publication {
            Some(publication) => {
                if publication.commit_seq <= previous_semantic {
                    return Err(GraphError::Invariant(format!(
                        "journal projection sequence {} does not advance graph watermark {}",
                        publication.commit_seq, previous_semantic
                    )));
                }
                publication.commit_seq
            }
            None => previous_semantic
                .checked_next()
                .ok_or_else(|| GraphError::Invariant("semantic sequence exhausted".to_owned()))?,
        };
        validate_mutation_time(&mutation, semantic_seq)?;
        let mut next_dense =
            read_u64(&transaction, &self.keyspaces.meta, NEXT_DENSE_ID)?.unwrap_or(1);
        for workspace in &mutation.workspaces {
            register_object_id(
                &mut transaction,
                &self.keyspaces,
                &workspace.id.to_string(),
                "workspace",
            )?;
            ensure_absent(
                &transaction,
                &self.keyspaces.workspace_identity,
                &workspace.id.to_string(),
            )?;
            transaction.put(
                &self.keyspaces.workspace_identity,
                external_key(workspace.id),
                encode(workspace)?,
            )?;
            transaction.put(
                &self.keyspaces.administrative_policy,
                external_key(workspace.id),
                encode(&AdministrativePolicyIndex {
                    created_seq: visible_from,
                    workspace_id: workspace.id,
                    subjects: BTreeSet::new(),
                    memory_spaces: BTreeSet::new(),
                })?,
            )?;
        }
        for space in &mutation.memory_spaces {
            register_object_id(
                &mut transaction,
                &self.keyspaces,
                &space.id.to_string(),
                "memory_space",
            )?;
            ensure_absent(
                &transaction,
                &self.keyspaces.space_identity,
                &space.id.to_string(),
            )?;
            require_identity(
                &transaction,
                &self.keyspaces.workspace_identity,
                space.workspace_id,
            )?;
            transaction.put(
                &self.keyspaces.space_identity,
                external_key(space.id),
                encode(space)?,
            )?;
            transaction.put(
                &self.keyspaces.administrative_policy,
                external_key(space.id),
                encode(&AdministrativePolicyIndex {
                    created_seq: visible_from,
                    workspace_id: space.workspace_id,
                    subjects: space.owners.iter().copied().collect(),
                    memory_spaces: BTreeSet::from([space.id]),
                })?,
            )?;
            transaction.put(
                &self.keyspaces.space_by_workspace,
                index_key(&space.workspace_id.to_string(), &space.id.to_string()),
                Vec::new(),
            )?;
            for owner in &space.owners {
                transaction.put(
                    &self.keyspaces.space_by_owner,
                    index_key(&owner.to_string(), &space.id.to_string()),
                    Vec::new(),
                )?;
            }
        }
        for subject in &mutation.memory_subjects {
            register_object_id(
                &mut transaction,
                &self.keyspaces,
                &subject.id.to_string(),
                "memory_subject",
            )?;
            ensure_absent(
                &transaction,
                &self.keyspaces.subject_identity,
                &subject.id.to_string(),
            )?;
            require_identity(
                &transaction,
                &self.keyspaces.workspace_identity,
                subject.workspace_id,
            )?;
            transaction.put(
                &self.keyspaces.subject_identity,
                external_key(subject.id),
                encode(subject)?,
            )?;
            transaction.put(
                &self.keyspaces.administrative_policy,
                external_key(subject.id),
                encode(&AdministrativePolicyIndex {
                    created_seq: visible_from,
                    workspace_id: subject.workspace_id,
                    subjects: BTreeSet::from([subject.id]),
                    memory_spaces: subject.primary_spaces.iter().copied().collect(),
                })?,
            )?;
            transaction.put(
                &self.keyspaces.subject_by_workspace,
                index_key(&subject.workspace_id.to_string(), &subject.id.to_string()),
                Vec::new(),
            )?;
            for space in &subject.primary_spaces {
                transaction.put(
                    &self.keyspaces.subject_by_space,
                    index_key(&space.to_string(), &subject.id.to_string()),
                    Vec::new(),
                )?;
            }
        }
        for node in &mutation.nodes {
            register_object_id(
                &mut transaction,
                &self.keyspaces,
                &node.id.to_string(),
                "node",
            )?;
            require_identity(
                &transaction,
                &self.keyspaces.workspace_identity,
                node.workspace_id,
            )?;
            ensure_absent(
                &transaction,
                &self.keyspaces.node_identity,
                &node.id.to_string(),
            )?;
            allocate_mapping(
                &mut transaction,
                &self.keyspaces,
                &node.id.to_string(),
                &mut next_dense,
                visible_from,
            )?;
            transaction.put(
                &self.keyspaces.node_identity,
                external_key(node.id),
                encode(node)?,
            )?;
        }
        for claim in &mutation.claims {
            register_object_id(
                &mut transaction,
                &self.keyspaces,
                &claim.id.to_string(),
                "claim",
            )?;
            require_identity(
                &transaction,
                &self.keyspaces.workspace_identity,
                claim.workspace_id,
            )?;
            require_identity(&transaction, &self.keyspaces.node_identity, claim.subject)?;
            ensure_absent(
                &transaction,
                &self.keyspaces.claim_identity,
                &claim.id.to_string(),
            )?;
            transaction.put(
                &self.keyspaces.claim_identity,
                external_key(claim.id),
                encode(claim)?,
            )?;
        }
        for edge in &mutation.edges {
            register_object_id(
                &mut transaction,
                &self.keyspaces,
                &edge.id.to_string(),
                "edge",
            )?;
            require_identity(
                &transaction,
                &self.keyspaces.workspace_identity,
                edge.workspace_id,
            )?;
            require_identity(&transaction, &self.keyspaces.node_identity, edge.source)?;
            require_identity(&transaction, &self.keyspaces.node_identity, edge.target)?;
            ensure_absent(
                &transaction,
                &self.keyspaces.edge_identity,
                &edge.id.to_string(),
            )?;
            transaction.put(
                &self.keyspaces.edge_identity,
                external_key(edge.id),
                encode(edge)?,
            )?;
        }
        for conflict in &mutation.conflicts {
            register_object_id(
                &mut transaction,
                &self.keyspaces,
                &conflict.id.to_string(),
                "conflict_set",
            )?;
            require_identity(
                &transaction,
                &self.keyspaces.workspace_identity,
                conflict.workspace_id,
            )?;
            require_identity(
                &transaction,
                &self.keyspaces.node_identity,
                conflict.subject,
            )?;
            ensure_absent(
                &transaction,
                &self.keyspaces.conflict_identity,
                &conflict.id.to_string(),
            )?;
            transaction.put(
                &self.keyspaces.conflict_identity,
                external_key(conflict.id),
                encode(conflict)?,
            )?;
        }
        validate_staged_references(&transaction, &self.keyspaces, &mutation)?;
        write_revisions(&mut transaction, &self.keyspaces, &mutation, visible_from)?;
        for artifact in &mutation.artifacts {
            let id = artifact.id.to_string();
            register_object_id(&mut transaction, &self.keyspaces, &id, "artifact")?;
            ensure_absent(&transaction, &self.keyspaces.artifact, &id)?;
            let workspace = workspace_from_envelope(&artifact.envelope)?;
            validate_envelope_references(
                &transaction,
                &self.keyspaces,
                &artifact.envelope,
                workspace,
            )?;
            let policy = build_policy(workspace, &artifact.envelope);
            transaction.put(
                &self.keyspaces.policy,
                id.as_bytes().to_vec(),
                encode(&policy)?,
            )?;
            transaction.put(
                &self.keyspaces.policy_history,
                policy_history_key(&id, visible_from),
                encode(&PersistedPolicy {
                    visible_from,
                    value: policy.clone(),
                })?,
            )?;
            write_policy_indexes(&mut transaction, &self.keyspaces, &id, &policy)?;
            transaction.put(
                &self.keyspaces.artifact,
                external_key(artifact.id),
                encode(&ArtifactMetadata {
                    artifact: artifact.clone(),
                    policy,
                    created_seq: visible_from,
                })?,
            )?;
        }
        transaction.put(
            &self.keyspaces.meta,
            NEXT_DENSE_ID.to_vec(),
            encode(&next_dense)?,
        )?;
        transaction.put(
            &self.keyspaces.meta,
            SEMANTIC_WATERMARK.to_vec(),
            encode(&semantic_seq)?,
        )?;
        transaction.put(
            &self.keyspaces.semantic_snapshot,
            u64_key(semantic_seq.get()),
            encode(&visible_from)?,
        )?;
        if let Some(publication) = publication {
            let projection = GraphProjectionReceipt {
                publication,
                storage_seq: visible_from,
                replayed: false,
            };
            transaction.put(
                &self.keyspaces.publication,
                publication.mutation_id.to_string().into_bytes(),
                encode(&projection)?,
            )?;
        }
        let receipt = transaction.commit(durability)?;
        if receipt.sequence != visible_from {
            return Err(GraphError::Invariant(
                "backend sequence diverged from prepared graph sequence".to_owned(),
            ));
        }
        Ok(ApplyOutcome {
            storage_seq: receipt.sequence,
            replayed: false,
        })
    }

    /// Returns a stable dense mapping after policy authorization.
    pub fn id_mapping(
        &self,
        id: &str,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<IdMapping> {
        let read = self.read_snapshot(snapshot)?;
        authorize(&read, &self.keyspaces, id, snapshot.storage_seq, principal)?;
        let bytes = read
            .get(&self.keyspaces.id_external, id.as_bytes())?
            .ok_or_else(|| not_found("mapping", id))?;
        let mapping: IdMapping = decode(&bytes)?;
        if mapping.created_seq > snapshot.storage_seq {
            return Err(not_found("mapping", id));
        }
        Ok(mapping)
    }

    /// Materializes an administrative workspace after checking its metadata-only boundary.
    pub fn workspace(
        &self,
        id: WorkspaceId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<Workspace> {
        let read = self.read_snapshot(snapshot)?;
        authorize_administrative(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        get_identity(&read, &self.keyspaces.workspace_identity, id, "workspace")
    }

    /// Materializes an owned memory space only after its administrative policy is accepted.
    pub fn memory_space(
        &self,
        id: MemorySpaceId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<MemorySpace> {
        let read = self.read_snapshot(snapshot)?;
        authorize_administrative(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        get_identity(&read, &self.keyspaces.space_identity, id, "memory space")
    }

    /// Materializes a stable cognitive subject only after its administrative policy is accepted.
    pub fn memory_subject(
        &self,
        id: MemorySubjectId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<MemorySubject> {
        let read = self.read_snapshot(snapshot)?;
        authorize_administrative(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        get_identity(
            &read,
            &self.keyspaces.subject_identity,
            id,
            "memory subject",
        )
    }

    /// Returns only caller-authorized subjects indexed under a memory space.
    pub fn subjects_in_space(
        &self,
        space: MemorySpaceId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<BTreeSet<MemorySubjectId>> {
        let read = self.read_snapshot(snapshot)?;
        authorize_administrative(
            &read,
            &self.keyspaces,
            &space.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        let prefix = format!("{space}/");
        let mut subjects = BTreeSet::new();
        for entry in read.scan_prefix(&self.keyspaces.subject_by_space, prefix.as_bytes())? {
            let id = indexed_id(&entry.key, &prefix)?;
            if authorize_administrative(&read, &self.keyspaces, id, snapshot.storage_seq, principal)
                .is_ok()
            {
                let subject: MemorySubject = get_identity(
                    &read,
                    &self.keyspaces.subject_identity,
                    id,
                    "memory subject",
                )?;
                subjects.insert(subject.id);
            }
        }
        Ok(subjects)
    }

    /// Returns only caller-authorized memory spaces indexed under an owner.
    pub fn spaces_owned_by(
        &self,
        owner: MemorySubjectId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<BTreeSet<MemorySpaceId>> {
        if owner != principal.subject {
            return Err(GraphError::Unauthorized);
        }
        let read = self.read_snapshot(snapshot)?;
        let prefix = format!("{owner}/");
        let mut spaces = BTreeSet::new();
        for entry in read.scan_prefix(&self.keyspaces.space_by_owner, prefix.as_bytes())? {
            let id = indexed_id(&entry.key, &prefix)?;
            if authorize_administrative(&read, &self.keyspaces, id, snapshot.storage_seq, principal)
                .is_ok()
            {
                let space: MemorySpace =
                    get_identity(&read, &self.keyspaces.space_identity, id, "memory space")?;
                spaces.insert(space.id);
            }
        }
        Ok(spaces)
    }

    /// Computes stable IDs authorized for this caller from metadata-only policy indexes.
    /// No node, claim, edge, artifact, or revision bytes are read during this phase.
    pub fn authorized_universe(
        &self,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<BTreeSet<String>> {
        self.authorized_index(
            &PolicyIndexQuery::Workspace(principal.workspace_id),
            snapshot,
            principal,
        )
    }

    /// Uses one metadata-only policy index and returns only IDs which pass the complete policy.
    /// Protected identity and revision bytes are not read by this operation.
    pub fn authorized_index(
        &self,
        query: &PolicyIndexQuery,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<BTreeSet<String>> {
        let read = self.read_snapshot(snapshot)?;
        if read.sequence() != snapshot.storage_seq {
            let mut policies = BTreeMap::<String, PersistedPolicy>::new();
            for entry in read.scan_prefix(&self.keyspaces.policy_history, b"")? {
                let id = policy_history_id(&entry.key)?.to_owned();
                let persisted: PersistedPolicy = decode(&entry.value)?;
                if persisted.visible_from <= snapshot.storage_seq {
                    policies.insert(id, persisted);
                }
            }
            return Ok(policies
                .into_iter()
                .filter(|(_, persisted)| {
                    policy_matches(&persisted.value, query) && allows(&persisted.value, principal)
                })
                .map(|(id, _)| id)
                .collect());
        }
        let (keyspace, value) = match query {
            PolicyIndexQuery::Workspace(value) => (&self.keyspaces.by_workspace, value.to_string()),
            PolicyIndexQuery::Subject(value) => (&self.keyspaces.by_subject, value.to_string()),
            PolicyIndexQuery::Scope(value) => (&self.keyspaces.by_scope, value.to_string()),
            PolicyIndexQuery::Owner(value) => (&self.keyspaces.by_owner, value.to_string()),
            PolicyIndexQuery::MemorySpace(value) => (&self.keyspaces.by_space, value.to_string()),
            PolicyIndexQuery::Audience(value) => (&self.keyspaces.by_audience, audience_key(value)),
            PolicyIndexQuery::Purpose(value) => (&self.keyspaces.by_purpose, purpose_key(value)?),
        };
        let prefix = format!("{value}/");
        let mut allowed = BTreeSet::new();
        for entry in read.scan_prefix(keyspace, prefix.as_bytes())? {
            let id = indexed_id(&entry.key, &prefix)?;
            if authorize(&read, &self.keyspaces, id, snapshot.storage_seq, principal).is_ok() {
                allowed.insert(id.to_owned());
            }
        }
        Ok(allowed)
    }

    /// Materializes an authorized node at one bitemporal snapshot.
    pub fn node(
        &self,
        id: NodeId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<NodeState> {
        let read = self.read_snapshot(snapshot)?;
        authorize(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        let node = get_identity(&read, &self.keyspaces.node_identity, id, "node")?;
        let revision = get_revision(
            &read,
            &self.keyspaces.node_revision,
            &id.to_string(),
            snapshot.storage_seq,
            snapshot.semantic_seq,
            "node revision",
        )?;
        Ok(NodeState { node, revision })
    }

    /// Looks up the most recent transaction-visible node revision valid at one domain-time instant.
    pub fn node_at_valid_time(
        &self,
        id: NodeId,
        valid_at: contextdb_core::TimestampMicros,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<NodeState> {
        let read = self.read_snapshot(snapshot)?;
        authorize(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        let node = get_identity(&read, &self.keyspaces.node_identity, id, "node")?;
        let revision = get_revision_at(
            &read,
            &self.keyspaces.node_revision,
            &id.to_string(),
            BitemporalInstant {
                storage_seq: snapshot.storage_seq,
                semantic_seq: snapshot.semantic_seq,
                valid_at,
            },
            |revision: &NodeRevision| revision.temporal.valid_time,
            "node revision",
        )?;
        Ok(NodeState { node, revision })
    }

    /// Materializes an authorized claim at one bitemporal snapshot.
    pub fn claim(
        &self,
        id: contextdb_core::ClaimId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<ClaimState> {
        let read = self.read_snapshot(snapshot)?;
        authorize(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        Ok(ClaimState {
            claim: get_identity(&read, &self.keyspaces.claim_identity, id, "claim")?,
            revision: get_revision(
                &read,
                &self.keyspaces.claim_revision,
                &id.to_string(),
                snapshot.storage_seq,
                snapshot.semantic_seq,
                "claim revision",
            )?,
        })
    }

    /// Looks up the most recent transaction-visible claim revision valid at domain time.
    pub fn claim_at_valid_time(
        &self,
        id: contextdb_core::ClaimId,
        valid_at: contextdb_core::TimestampMicros,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<ClaimState> {
        let read = self.read_snapshot(snapshot)?;
        authorize(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        Ok(ClaimState {
            claim: get_identity(&read, &self.keyspaces.claim_identity, id, "claim")?,
            revision: get_revision_at(
                &read,
                &self.keyspaces.claim_revision,
                &id.to_string(),
                BitemporalInstant {
                    storage_seq: snapshot.storage_seq,
                    semantic_seq: snapshot.semantic_seq,
                    valid_at,
                },
                |revision: &ClaimRevision| revision.temporal.valid_time,
                "claim revision",
            )?,
        })
    }

    /// Materializes an authorized edge at one bitemporal snapshot.
    pub fn edge(
        &self,
        id: contextdb_core::EdgeId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<crate::EdgeState> {
        let read = self.read_snapshot(snapshot)?;
        authorize(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        Ok(crate::EdgeState {
            edge: get_identity(&read, &self.keyspaces.edge_identity, id, "edge")?,
            revision: get_revision(
                &read,
                &self.keyspaces.edge_revision,
                &id.to_string(),
                snapshot.storage_seq,
                snapshot.semantic_seq,
                "edge revision",
            )?,
        })
    }

    /// Looks up the most recent transaction-visible edge revision valid at domain time.
    pub fn edge_at_valid_time(
        &self,
        id: contextdb_core::EdgeId,
        valid_at: contextdb_core::TimestampMicros,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<crate::EdgeState> {
        let read = self.read_snapshot(snapshot)?;
        authorize(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        Ok(crate::EdgeState {
            edge: get_identity(&read, &self.keyspaces.edge_identity, id, "edge")?,
            revision: get_revision_at(
                &read,
                &self.keyspaces.edge_revision,
                &id.to_string(),
                BitemporalInstant {
                    storage_seq: snapshot.storage_seq,
                    semantic_seq: snapshot.semantic_seq,
                    valid_at,
                },
                |revision: &EdgeRevision| revision.temporal.valid_time,
                "edge revision",
            )?,
        })
    }

    /// Materializes authorized artifact metadata without blob bytes.
    pub fn artifact(
        &self,
        id: contextdb_core::ArtifactId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<ArtifactMetadata> {
        let read = self.read_snapshot(snapshot)?;
        let id = id.to_string();
        authorize(&read, &self.keyspaces, &id, snapshot.storage_seq, principal)?;
        let bytes = read
            .get(&self.keyspaces.artifact, id.as_bytes())?
            .ok_or_else(|| not_found("artifact", &id))?;
        let metadata: ArtifactMetadata = decode(&bytes)?;
        if metadata.created_seq > snapshot.storage_seq {
            return Err(not_found("artifact", &id));
        }
        Ok(metadata)
    }

    /// Materializes an authorized revisioned conflict set.
    pub fn conflict(
        &self,
        id: contextdb_core::ConflictSetId,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<ConflictState> {
        let read = self.read_snapshot(snapshot)?;
        authorize(
            &read,
            &self.keyspaces,
            &id.to_string(),
            snapshot.storage_seq,
            principal,
        )?;
        Ok(ConflictState {
            conflict: get_identity(&read, &self.keyspaces.conflict_identity, id, "conflict set")?,
            revision: get_revision(
                &read,
                &self.keyspaces.conflict_revision,
                &id.to_string(),
                snapshot.storage_seq,
                snapshot.semantic_seq,
                "conflict revision",
            )?,
        })
    }

    /// Bounded deterministic traversal over the authorized base-plus-delta adjacency view.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the bounded typed graph traversal contract"
    )]
    pub fn traverse(
        &self,
        start: &[NodeId],
        direction: Direction,
        edge_types: &BTreeSet<contextdb_core::EdgeTypeId>,
        max_hops: u8,
        max_nodes: usize,
        snapshot: &GraphSnapshot,
        principal: &ReadPrincipal,
    ) -> Result<TraversalResult> {
        let read = self.read_snapshot(snapshot)?;
        for node in start {
            authorize(
                &read,
                &self.keyspaces,
                &node.to_string(),
                snapshot.storage_seq,
                principal,
            )?;
        }
        if max_hops == 0 || max_nodes == 0 {
            return Ok(TraversalResult {
                nodes: Vec::new(),
                trace: TraversalTrace {
                    snapshot_seq: snapshot.storage_seq,
                    segment_generation: snapshot.segment_generation,
                    authorized_edges: 0,
                    selected_nodes: Vec::new(),
                },
            });
        }
        let mut queue = VecDeque::new();
        let mut visited = start
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        for node in start {
            queue.push_back((node.to_string(), 0_u8));
        }
        let allowed_types = edge_types
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let mut result = Vec::new();
        let mut authorized_edges = 0_usize;
        while let Some((node, hops)) = queue.pop_front() {
            if hops >= max_hops {
                continue;
            }
            let dense_node = dense_for_external(&read, &self.keyspaces, &node)?;
            let edges = merged_edges_for_node(
                &read,
                &self.keyspaces,
                snapshot,
                principal,
                dense_node,
                direction,
            )?;
            let mut neighbours = BTreeSet::new();
            for edge in edges {
                if !allowed_types.is_empty() && !allowed_types.contains(&edge.edge_type) {
                    continue;
                }
                let neighbour = match (edge.directionality, direction) {
                    (contextdb_core::Directionality::Undirected, _)
                        if edge.source == dense_node =>
                    {
                        Some(&edge.target)
                    }
                    (contextdb_core::Directionality::Undirected, _)
                        if edge.target == dense_node =>
                    {
                        Some(&edge.source)
                    }
                    (contextdb_core::Directionality::Directed, Direction::Outgoing)
                        if edge.source == dense_node =>
                    {
                        Some(&edge.target)
                    }
                    (contextdb_core::Directionality::Directed, Direction::Incoming)
                        if edge.target == dense_node =>
                    {
                        Some(&edge.source)
                    }
                    (contextdb_core::Directionality::Directed, Direction::Both)
                        if edge.source == dense_node =>
                    {
                        Some(&edge.target)
                    }
                    (contextdb_core::Directionality::Directed, Direction::Both)
                        if edge.target == dense_node =>
                    {
                        Some(&edge.source)
                    }
                    (contextdb_core::Directionality::Directed, _)
                    | (contextdb_core::Directionality::Undirected, _) => None,
                };
                if let Some(neighbour) = neighbour {
                    let neighbour = external_for_dense(&read, &self.keyspaces, *neighbour)?;
                    if authorize(
                        &read,
                        &self.keyspaces,
                        &neighbour,
                        snapshot.storage_seq,
                        principal,
                    )
                    .is_ok()
                    {
                        authorized_edges = authorized_edges.saturating_add(1);
                        neighbours.insert(neighbour);
                    }
                }
            }
            for neighbour in neighbours {
                if visited.insert(neighbour.clone()) {
                    result.push(neighbour.clone());
                    queue.push_back((neighbour, hops.saturating_add(1)));
                    if result.len() >= max_nodes {
                        break;
                    }
                }
            }
            if result.len() >= max_nodes {
                break;
            }
        }
        Ok(TraversalResult {
            nodes: result.clone(),
            trace: TraversalTrace {
                snapshot_seq: snapshot.storage_seq,
                segment_generation: snapshot.segment_generation,
                authorized_edges,
                selected_nodes: result,
            },
        })
    }

    /// Rebuilds immutable adjacency from current authorized-independent primary edges and atomically
    /// switches the manifest. Stable IDs and revision history are untouched.
    pub fn compact_graph(&self, durability: Durability) -> Result<SegmentManifest> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| GraphError::Invariant("graph write lock poisoned".to_owned()))?;
        let source = self.engine.begin_read(SnapshotSelector::Latest)?;
        let built_through_seq = source.sequence();
        let semantic_seq = read_semantic_watermark(&source, &self.keyspaces)?;
        let current = read_manifest(&source, &self.keyspaces)?;
        validate_manifest(&current)?;
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphError::Invariant("segment generation exhausted".to_owned()))?;
        let fence = acquire_adjacency_compaction_fence(
            &self.engine,
            &self.keyspaces,
            built_through_seq,
            &current,
            durability,
        )?;
        let result = (|| {
            clear_segment_v2_generation(
                &self.engine,
                &self.keyspaces,
                generation,
                &current,
                &fence,
                durability,
            )?;
            let (edge_count, edge_bytes) = write_segment_v2_edges(
                &self.engine,
                &source,
                &self.keyspaces,
                generation,
                built_through_seq,
                semantic_seq,
                &current,
                &fence,
                durability,
            )?;
            let (row_count, summarized_edges, summarized_bytes) = write_segment_v2_rows(
                &self.engine,
                &source,
                &self.keyspaces,
                generation,
                built_through_seq,
                &current,
                &fence,
                durability,
            )?;
            if (edge_count, edge_bytes) != (summarized_edges, summarized_bytes) {
                return Err(GraphError::Corrupt(
                    "paged adjacency row totals disagree with written edge totals".to_owned(),
                ));
            }
            let row_merkle_root = build_segment_v2_merkle(
                &self.engine,
                &self.keyspaces,
                generation,
                row_count,
                &current,
                &fence,
                durability,
            )?;
            let segment_digest = segment_v2_manifest_root(
                generation,
                built_through_seq,
                row_count,
                edge_count,
                edge_bytes,
                row_merkle_root,
            )
            .to_hex()
            .to_string();
            let manifest = SegmentManifest {
                format_version: SEGMENT_V2_FORMAT,
                generation,
                built_through_seq,
                segment_digest,
                row_count,
                edge_count,
                edge_bytes,
            };
            validate_manifest(&manifest)?;
            let latest = self.engine.begin_read(SnapshotSelector::Latest)?;
            ensure_adjacency_maintenance_fence(&latest, &self.keyspaces, &fence)?;
            validate_segment_v2_generation(&latest, &self.keyspaces, &manifest)?;
            drop(latest);
            let mut transaction = self.engine.begin_write()?;
            ensure_adjacency_maintenance_fence(&transaction, &self.keyspaces, &fence)?;
            if read_manifest(&transaction, &self.keyspaces)? != current
                || read_semantic_watermark(&transaction, &self.keyspaces)? != semantic_seq
            {
                return Err(GraphError::Invariant(
                    "graph changed while building inactive adjacency generation".to_owned(),
                ));
            }
            let switch_seq = transaction
                .sequence()
                .checked_add(1)
                .ok_or_else(|| GraphError::Invariant("storage sequence exhausted".to_owned()))?;
            transaction.put(
                &self.keyspaces.meta,
                ACTIVE_MANIFEST.to_vec(),
                encode(&manifest)?,
            )?;
            transaction.put(
                &self.keyspaces.manifest_history,
                u64_key(switch_seq),
                encode(&manifest)?,
            )?;
            transaction.delete(&self.keyspaces.meta, ADJACENCY_MAINTENANCE_FENCE.to_vec())?;
            let receipt = transaction.commit(durability)?;
            if receipt.sequence != switch_seq {
                return Err(GraphError::Invariant(
                    "backend sequence diverged from graph manifest switch".to_owned(),
                ));
            }
            Ok(manifest)
        })();
        if result.is_err() {
            let _ = release_adjacency_maintenance_fence(
                &self.engine,
                &self.keyspaces,
                &fence,
                durability,
            );
        }
        result
    }

    /// Advances the explicit adjacency-retention floor and reclaims unreachable generations.
    ///
    /// The caller supplies the oldest physical graph sequence which must remain readable. The
    /// operation preserves the exact baseline manifest active at that sequence, every later
    /// manifest, and the active generation. It validates all retained history and physical
    /// generation keys before deleting anything. A crash can leave unreachable records behind,
    /// but can never make a retained generation unreachable; repeating the same request resumes
    /// cleanup safely.
    pub fn prune_adjacency_generations(
        &self,
        oldest_retained_storage_seq: u64,
        durability: Durability,
    ) -> Result<AdjacencyPruneReport> {
        if durability != Durability::Sync {
            return Err(GraphError::SyncDurabilityRequired {
                operation: "prune_adjacency_generations",
            });
        }
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| GraphError::Invariant("graph write lock poisoned".to_owned()))?;
        let fence = acquire_adjacency_prune_fence(
            &self.engine,
            &self.keyspaces,
            oldest_retained_storage_seq,
            durability,
        )?;
        let result = (|| {
            let preflight = self.engine.begin_read(SnapshotSelector::Latest)?;
            ensure_adjacency_maintenance_fence(&preflight, &self.keyspaces, &fence)?;
            let preflight_head = preflight.sequence();
            if oldest_retained_storage_seq > preflight_head {
                return Err(GraphError::Invariant(format!(
                    "adjacency retention floor {oldest_retained_storage_seq} exceeds graph head {preflight_head}"
                )));
            }
            let previous_floor =
                read_and_validate_adjacency_retention(&preflight, &self.keyspaces)?;
            if oldest_retained_storage_seq < previous_floor {
                return Err(GraphError::Invariant(format!(
                    "adjacency retention floor cannot move backward from {previous_floor} to {oldest_retained_storage_seq}"
                )));
            }
            let history = read_validated_manifest_history(&preflight, &self.keyspaces)?;
            let active = read_manifest(&preflight, &self.keyspaces)?;
            validate_adjacency_retention_baseline(
                &preflight,
                &self.keyspaces,
                &history,
                &active,
                previous_floor,
            )?;
            let initial_plan =
                build_adjacency_retention_plan(&history, &active, oldest_retained_storage_seq)?;
            validate_retained_adjacency_generations(
                &preflight,
                &self.keyspaces,
                &history,
                &initial_plan,
            )?;
            preflight_adjacency_generation_keys(&preflight, &self.keyspaces)?;
            drop(preflight);

            if oldest_retained_storage_seq > previous_floor {
                let mut transaction = self.engine.begin_write()?;
                ensure_adjacency_maintenance_fence(&transaction, &self.keyspaces, &fence)?;
                if transaction.sequence() != preflight_head
                    || read_and_validate_adjacency_retention(&transaction, &self.keyspaces)?
                        != previous_floor
                    || read_manifest(&transaction, &self.keyspaces)? != active
                {
                    return Err(GraphError::Invariant(
                        "graph changed after adjacency prune preflight".to_owned(),
                    ));
                }
                transaction.put(
                    &self.keyspaces.meta,
                    ADJACENCY_RETENTION_FLOOR.to_vec(),
                    encode(&oldest_retained_storage_seq)?,
                )?;
                transaction.put(
                    &self.keyspaces.meta,
                    ADJACENCY_RETENTION_BASELINE.to_vec(),
                    encode(&AdjacencyRetentionBaseline {
                        format_version: 2,
                        oldest_retained_storage_seq,
                        baseline_switch_seq: initial_plan.baseline_switch_seq,
                        baseline_generation: initial_plan.baseline_generation,
                        baseline_manifest: initial_plan.baseline_manifest.clone(),
                    })?,
                )?;
                transaction.commit(durability)?;
            }

            let history_entries_deleted = delete_manifest_history_before(
                &self.engine,
                &self.keyspaces,
                initial_plan.baseline_switch_seq,
                oldest_retained_storage_seq,
                &active,
                &fence,
                durability,
            )?;

            // Re-read after the history phase. This makes a retry after any intermediate crash use
            // the already-published floor and the remaining canonical history as its source of truth.
            let retained = self.engine.begin_read(SnapshotSelector::Latest)?;
            ensure_adjacency_maintenance_fence(&retained, &self.keyspaces, &fence)?;
            let retained_history = read_validated_manifest_history(&retained, &self.keyspaces)?;
            let retained_active = read_manifest(&retained, &self.keyspaces)?;
            validate_adjacency_retention_baseline(
                &retained,
                &self.keyspaces,
                &retained_history,
                &retained_active,
                oldest_retained_storage_seq,
            )?;
            let retained_plan = build_adjacency_retention_plan(
                &retained_history,
                &retained_active,
                oldest_retained_storage_seq,
            )?;
            if retained_plan.baseline_manifest != initial_plan.baseline_manifest {
                return Err(GraphError::Corrupt(
                    "adjacency baseline changed during prune".to_owned(),
                ));
            }
            validate_retained_adjacency_generations(
                &retained,
                &self.keyspaces,
                &retained_history,
                &retained_plan,
            )?;
            preflight_adjacency_generation_keys(&retained, &self.keyspaces)?;
            drop(retained);

            let v1_deleted = delete_unreferenced_v1_generations(
                &self.engine,
                &self.keyspaces,
                &retained_plan.referenced_generations,
                oldest_retained_storage_seq,
                &retained_active,
                &fence,
                durability,
            )?;
            let (v2_deleted, v2_records_deleted) = delete_unreferenced_v2_generations(
                &self.engine,
                &self.keyspaces,
                &retained_plan.referenced_generations,
                oldest_retained_storage_seq,
                &retained_active,
                &fence,
                durability,
            )?;

            Ok(AdjacencyPruneReport {
                previous_oldest_retained_storage_seq: previous_floor,
                oldest_retained_storage_seq,
                baseline_generation: retained_plan.baseline_generation,
                active_generation: retained_plan.active_generation,
                history_entries_deleted,
                v1_generations_deleted: u64::try_from(v1_deleted.len()).unwrap_or(u64::MAX),
                v2_generations_deleted: u64::try_from(v2_deleted.len()).unwrap_or(u64::MAX),
                v2_records_deleted,
            })
        })();
        match result {
            Ok(report) => {
                release_adjacency_maintenance_fence(
                    &self.engine,
                    &self.keyspaces,
                    &fence,
                    durability,
                )?;
                Ok(report)
            }
            Err(error) => {
                let _ = release_adjacency_maintenance_fence(
                    &self.engine,
                    &self.keyspaces,
                    &fence,
                    durability,
                );
                Err(error)
            }
        }
    }

    fn read_snapshot(&self, snapshot: &GraphSnapshot) -> Result<E::ReadSnapshot<'_>> {
        let read = self.read_at_or_latest(snapshot.storage_seq)?;
        let manifest = read_manifest_at(&read, &self.keyspaces, snapshot.storage_seq)?;
        let semantic_seq = read_semantic_at(&read, &self.keyspaces, snapshot.storage_seq)?;
        validate_manifest(&manifest)?;
        if manifest.generation != snapshot.segment_generation
            || semantic_seq != snapshot.semantic_seq
        {
            return Err(GraphError::Invariant(
                "snapshot metadata does not match its retained physical view".to_owned(),
            ));
        }
        Ok(read)
    }

    fn read_at_or_latest(&self, storage_seq: u64) -> Result<E::ReadSnapshot<'_>> {
        let latest = self.engine.begin_read(SnapshotSelector::Latest)?;
        ensure_adjacency_snapshot_retained(
            storage_seq,
            read_and_validate_adjacency_retention(&latest, &self.keyspaces)?,
        )?;
        match self.engine.begin_read(SnapshotSelector::At(storage_seq)) {
            Ok(snapshot) => Ok(snapshot),
            Err(contextdb_storage::StorageError::SnapshotUnavailable { head, .. })
                if storage_seq <= head =>
            {
                if latest.sequence() < storage_seq {
                    return Err(GraphError::Invariant(
                        "latest backend snapshot precedes requested graph snapshot".to_owned(),
                    ));
                }
                Ok(latest)
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn read_adjacency_maintenance_state<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
) -> Result<(u64, Option<AdjacencyMaintenanceFence>)> {
    let epoch = snapshot
        .get(&keyspaces.meta, ADJACENCY_MAINTENANCE_EPOCH)?
        .map(|bytes| decode::<u64>(&bytes))
        .transpose()?
        .unwrap_or(0);
    let fence = snapshot
        .get(&keyspaces.meta, ADJACENCY_MAINTENANCE_FENCE)?
        .map(|bytes| decode::<AdjacencyMaintenanceFence>(&bytes))
        .transpose()?;
    if let Some(fence) = fence {
        let operation_valid = match fence.operation {
            AdjacencyMaintenanceOperation::Compact {
                generation,
                source_storage_seq,
                base_generation,
            } => {
                generation > 0
                    && base_generation.checked_add(1) == Some(generation)
                    && source_storage_seq < snapshot.sequence()
            }
            AdjacencyMaintenanceOperation::Prune {
                oldest_retained_storage_seq,
            } => oldest_retained_storage_seq < snapshot.sequence(),
        };
        if fence.format_version != 1 || fence.epoch == 0 || fence.epoch != epoch || !operation_valid
        {
            return Err(GraphError::Corrupt(
                "adjacency maintenance fence is not canonical".to_owned(),
            ));
        }
        Ok((epoch, Some(fence)))
    } else {
        Ok((epoch, None))
    }
}

fn acquire_adjacency_compaction_fence<E: StorageEngine>(
    engine: &E,
    keyspaces: &Keyspaces,
    source_storage_seq: u64,
    current: &SegmentManifest,
    durability: Durability,
) -> Result<AdjacencyMaintenanceFence> {
    let generation = current
        .generation
        .checked_add(1)
        .ok_or_else(|| GraphError::Invariant("segment generation exhausted".to_owned()))?;
    let mut transaction = engine.begin_write()?;
    if transaction.sequence() != source_storage_seq
        || read_manifest(&transaction, keyspaces)? != *current
    {
        return Err(GraphError::Invariant(
            "graph changed before adjacency compaction fence acquisition".to_owned(),
        ));
    }
    let (epoch, existing) = read_adjacency_maintenance_state(&transaction, keyspaces)?;
    if existing
        .is_some_and(|fence| matches!(fence.operation, AdjacencyMaintenanceOperation::Prune { .. }))
    {
        return Err(GraphError::AdjacencyMaintenanceConflict {
            requested: "compact_graph",
            active: "prune_adjacency_generations",
        });
    }
    let next_epoch = epoch
        .checked_add(1)
        .ok_or_else(|| GraphError::Invariant("adjacency maintenance epoch exhausted".to_owned()))?;
    let fence = AdjacencyMaintenanceFence {
        format_version: 1,
        epoch: next_epoch,
        operation: AdjacencyMaintenanceOperation::Compact {
            generation,
            source_storage_seq,
            base_generation: current.generation,
        },
    };
    transaction.put(
        &keyspaces.meta,
        ADJACENCY_MAINTENANCE_EPOCH.to_vec(),
        encode(&next_epoch)?,
    )?;
    transaction.put(
        &keyspaces.meta,
        ADJACENCY_MAINTENANCE_FENCE.to_vec(),
        encode(&fence)?,
    )?;
    transaction.commit(durability)?;
    Ok(fence)
}

fn acquire_adjacency_prune_fence<E: StorageEngine>(
    engine: &E,
    keyspaces: &Keyspaces,
    oldest_retained_storage_seq: u64,
    durability: Durability,
) -> Result<AdjacencyMaintenanceFence> {
    let mut transaction = engine.begin_write()?;
    let head = transaction.sequence();
    if oldest_retained_storage_seq > head {
        return Err(GraphError::Invariant(format!(
            "adjacency retention floor {oldest_retained_storage_seq} exceeds graph head {head}"
        )));
    }
    let previous_floor = read_and_validate_adjacency_retention(&transaction, keyspaces)?;
    if oldest_retained_storage_seq < previous_floor {
        return Err(GraphError::Invariant(format!(
            "adjacency retention floor cannot move backward from {previous_floor} to {oldest_retained_storage_seq}"
        )));
    }
    let (epoch, existing) = read_adjacency_maintenance_state(&transaction, keyspaces)?;
    if existing.is_some_and(|fence| {
        matches!(
            fence.operation,
            AdjacencyMaintenanceOperation::Compact { .. }
        )
    }) {
        return Err(GraphError::AdjacencyMaintenanceConflict {
            requested: "prune_adjacency_generations",
            active: "compact_graph",
        });
    }
    let next_epoch = epoch
        .checked_add(1)
        .ok_or_else(|| GraphError::Invariant("adjacency maintenance epoch exhausted".to_owned()))?;
    let fence = AdjacencyMaintenanceFence {
        format_version: 1,
        epoch: next_epoch,
        operation: AdjacencyMaintenanceOperation::Prune {
            oldest_retained_storage_seq,
        },
    };
    transaction.put(
        &keyspaces.meta,
        ADJACENCY_MAINTENANCE_EPOCH.to_vec(),
        encode(&next_epoch)?,
    )?;
    transaction.put(
        &keyspaces.meta,
        ADJACENCY_MAINTENANCE_FENCE.to_vec(),
        encode(&fence)?,
    )?;
    transaction.commit(durability)?;
    Ok(fence)
}

fn ensure_adjacency_maintenance_fence<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    expected: &AdjacencyMaintenanceFence,
) -> Result<()> {
    let (_, actual) = read_adjacency_maintenance_state(snapshot, keyspaces)?;
    if actual.as_ref() == Some(expected) {
        return Ok(());
    }
    Err(GraphError::AdjacencyMaintenanceConflict {
        requested: expected.operation.name(),
        active: actual.map_or("no adjacency maintenance", |fence| fence.operation.name()),
    })
}

fn release_adjacency_maintenance_fence<E: StorageEngine>(
    engine: &E,
    keyspaces: &Keyspaces,
    expected: &AdjacencyMaintenanceFence,
    durability: Durability,
) -> Result<()> {
    let mut transaction = engine.begin_write()?;
    ensure_adjacency_maintenance_fence(&transaction, keyspaces, expected)?;
    transaction.delete(&keyspaces.meta, ADJACENCY_MAINTENANCE_FENCE.to_vec())?;
    transaction.commit(durability)?;
    Ok(())
}

fn read_adjacency_retention_floor<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
) -> Result<u64> {
    let floor = snapshot
        .get(&keyspaces.meta, ADJACENCY_RETENTION_FLOOR)?
        .map(|bytes| decode::<u64>(&bytes))
        .transpose()?
        .unwrap_or(0);
    if floor > snapshot.sequence() {
        return Err(GraphError::Corrupt(
            "adjacency retention floor exceeds the storage head".to_owned(),
        ));
    }
    Ok(floor)
}

fn read_adjacency_retention_baseline<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
) -> Result<Option<AdjacencyRetentionBaseline>> {
    snapshot
        .get(&keyspaces.meta, ADJACENCY_RETENTION_BASELINE)?
        .map(|bytes| decode::<AdjacencyRetentionBaseline>(&bytes))
        .transpose()
}

fn read_and_validate_adjacency_retention<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
) -> Result<u64> {
    let floor = read_adjacency_retention_floor(snapshot, keyspaces)?;
    let marker = read_adjacency_retention_baseline(snapshot, keyspaces)?;
    if floor == 0 {
        if marker.is_some() {
            return Err(GraphError::Corrupt(
                "zero adjacency retention floor has a baseline marker".to_owned(),
            ));
        }
        return Ok(0);
    }
    let marker = marker.ok_or_else(|| {
        GraphError::Corrupt("adjacency retention baseline marker missing".to_owned())
    })?;
    validate_manifest(&marker.baseline_manifest)?;
    if marker.format_version != 2
        || marker.oldest_retained_storage_seq != floor
        || marker.baseline_generation != marker.baseline_manifest.generation
    {
        return Err(GraphError::Corrupt(
            "adjacency retention baseline marker is not canonical".to_owned(),
        ));
    }
    match marker.baseline_switch_seq {
        Some(switch_seq) => {
            if switch_seq == 0
                || switch_seq > floor
                || marker.baseline_generation == 0
                || marker.baseline_manifest.built_through_seq >= switch_seq
            {
                return Err(GraphError::Corrupt(
                    "adjacency retention baseline identity is not canonical".to_owned(),
                ));
            }
            let bytes = snapshot
                .get(&keyspaces.manifest_history, &u64_key(switch_seq))?
                .ok_or_else(|| {
                    GraphError::Corrupt(
                        "adjacency retention baseline history entry is missing".to_owned(),
                    )
                })?;
            let history_manifest: SegmentManifest = decode(&bytes)?;
            validate_manifest(&history_manifest)?;
            if history_manifest != marker.baseline_manifest {
                return Err(GraphError::Corrupt(
                    "adjacency retention baseline history identity was tampered".to_owned(),
                ));
            }
            let baseline_key = u64_key(switch_seq);
            let page = snapshot.scan_prefix_page(
                &keyspaces.manifest_history,
                ScanPageRequest {
                    prefix: b"",
                    start_after: Some(&baseline_key),
                    max_entries: 1,
                    max_bytes: SEGMENT_V2_SCAN_BYTES,
                },
            )?;
            validate_scan_progress(&page, Some(&baseline_key))?;
            if let Some(entry) = page.entries.first()
                && decode_u64_key(&entry.key)? <= floor
            {
                return Err(GraphError::Corrupt(
                    "adjacency retention baseline is not the latest switch at the floor".to_owned(),
                ));
            }
        }
        None => {
            if marker.baseline_manifest != empty_segment_manifest() {
                return Err(GraphError::Corrupt(
                    "empty adjacency retention baseline is not canonical".to_owned(),
                ));
            }
            let page = snapshot.scan_prefix_page(
                &keyspaces.manifest_history,
                ScanPageRequest {
                    prefix: b"",
                    start_after: None,
                    max_entries: 1,
                    max_bytes: SEGMENT_V2_SCAN_BYTES,
                },
            )?;
            validate_scan_progress(&page, None)?;
            if let Some(entry) = page.entries.first()
                && decode_u64_key(&entry.key)? <= floor
            {
                return Err(GraphError::Corrupt(
                    "empty adjacency retention baseline omits retained history".to_owned(),
                ));
            }
        }
    }
    Ok(floor)
}

fn ensure_adjacency_snapshot_retained(requested: u64, oldest_retained: u64) -> Result<()> {
    if requested < oldest_retained {
        Err(GraphError::SnapshotPruned {
            requested,
            oldest_retained,
        })
    } else {
        Ok(())
    }
}

fn validate_adjacency_retention_baseline<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    history: &[ManifestHistoryEntry],
    active: &SegmentManifest,
    floor: u64,
) -> Result<()> {
    let marker = read_adjacency_retention_baseline(snapshot, keyspaces)?;
    if floor == 0 {
        if marker.is_some() {
            return Err(GraphError::Corrupt(
                "zero adjacency retention floor has a baseline marker".to_owned(),
            ));
        }
        return Ok(());
    }
    let marker = marker.ok_or_else(|| {
        GraphError::Corrupt("adjacency retention baseline marker missing".to_owned())
    })?;
    read_and_validate_adjacency_retention(snapshot, keyspaces)?;
    let plan = build_adjacency_retention_plan(history, active, floor)?;
    if marker.format_version != 2
        || marker.oldest_retained_storage_seq != floor
        || marker.baseline_switch_seq != plan.baseline_switch_seq
        || marker.baseline_generation != plan.baseline_generation
        || marker.baseline_manifest != plan.baseline_manifest
    {
        return Err(GraphError::Corrupt(
            "adjacency retention baseline marker disagrees with retained history".to_owned(),
        ));
    }
    Ok(())
}

fn read_validated_manifest_history<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
) -> Result<Vec<ManifestHistoryEntry>> {
    let mut history = Vec::new();
    let mut continuation = None;
    let mut previous_generation = None;
    let mut previous_built_through = None;
    let mut count = 0_u64;
    loop {
        let page = snapshot.scan_prefix_page(
            &keyspaces.manifest_history,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: SEGMENT_V2_SCAN_ENTRIES,
                max_bytes: SEGMENT_V2_SCAN_BYTES,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        for entry in page.entries {
            bounded_add(
                &mut count,
                1,
                "adjacency_manifest_history_entries",
                PRUNE_MAX_HISTORY_ENTRIES,
            )?;
            let switch_seq = decode_u64_key(&entry.key)?;
            let manifest: SegmentManifest = decode(&entry.value)?;
            validate_manifest(&manifest)?;
            if switch_seq > snapshot.sequence()
                || manifest.generation == 0
                || manifest.built_through_seq >= switch_seq
                || previous_generation.is_some_and(|generation: u64| {
                    generation.checked_add(1) != Some(manifest.generation)
                })
                || previous_built_through
                    .is_some_and(|built_through| built_through > manifest.built_through_seq)
            {
                return Err(GraphError::Corrupt(
                    "adjacency manifest history is not canonical".to_owned(),
                ));
            }
            previous_generation = Some(manifest.generation);
            previous_built_through = Some(manifest.built_through_seq);
            history.push(ManifestHistoryEntry {
                switch_seq,
                manifest,
            });
        }
        let Some(next) = page.continuation else {
            break;
        };
        continuation = Some(next);
    }
    let active = read_manifest(snapshot, keyspaces)?;
    validate_manifest(&active)?;
    match (active.generation, history.last()) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => {
            return Err(GraphError::Corrupt(
                "active adjacency manifest disagrees with manifest history".to_owned(),
            ));
        }
        (_, Some(last)) if last.manifest != active => {
            return Err(GraphError::Corrupt(
                "active adjacency manifest is not the latest history entry".to_owned(),
            ));
        }
        _ => {}
    }
    Ok(history)
}

fn build_adjacency_retention_plan(
    history: &[ManifestHistoryEntry],
    active: &SegmentManifest,
    oldest_retained_storage_seq: u64,
) -> Result<AdjacencyRetentionPlan> {
    validate_manifest(active)?;
    let baseline_index = history
        .iter()
        .rposition(|entry| entry.switch_seq <= oldest_retained_storage_seq);
    let (baseline_manifest, baseline_switch_seq, retained_start) =
        baseline_index.map_or((empty_segment_manifest(), None, 0), |index| {
            (
                history[index].manifest.clone(),
                Some(history[index].switch_seq),
                index,
            )
        });
    let baseline_generation = baseline_manifest.generation;
    let mut referenced_generations = BTreeMap::new();
    for entry in &history[retained_start..] {
        if entry.manifest.generation > 0 {
            referenced_generations.insert(entry.manifest.generation, entry.manifest.format_version);
        }
    }
    if active.generation > 0
        && referenced_generations
            .insert(active.generation, active.format_version)
            .is_some_and(|format_version| format_version != active.format_version)
    {
        return Err(GraphError::Corrupt(
            "one adjacency generation is referenced with multiple formats".to_owned(),
        ));
    }
    ensure_bound(
        "adjacency_retained_generations",
        u64::try_from(referenced_generations.len()).unwrap_or(u64::MAX),
        PRUNE_MAX_GENERATIONS,
    )?;
    Ok(AdjacencyRetentionPlan {
        baseline_generation,
        baseline_switch_seq,
        baseline_manifest,
        active_generation: active.generation,
        referenced_generations,
    })
}

fn validate_retained_adjacency_generations<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    history: &[ManifestHistoryEntry],
    plan: &AdjacencyRetentionPlan,
) -> Result<()> {
    for entry in history {
        let manifest = &entry.manifest;
        if plan.referenced_generations.get(&manifest.generation) != Some(&manifest.format_version) {
            continue;
        }
        match manifest.format_version {
            1 => {
                let bytes = snapshot
                    .get(&keyspaces.segment, &segment_key(manifest.generation))?
                    .ok_or_else(|| {
                        GraphError::Corrupt(
                            "retained legacy adjacency generation is missing".to_owned(),
                        )
                    })?;
                ensure_bound(
                    "legacy_segment_bytes",
                    u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    u64::try_from(LEGACY_SEGMENT_MAX_BYTES).unwrap_or(u64::MAX),
                )?;
                let segment: AdjacencySegment = decode(&bytes)?;
                validate_segment(&segment, manifest)?;
            }
            SEGMENT_V2_FORMAT => {
                validate_segment_v2_generation(snapshot, keyspaces, manifest)?;
            }
            _ => {
                return Err(GraphError::Corrupt(
                    "unsupported retained adjacency generation format".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_adjacency_prune_delete_guard<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    oldest_retained_storage_seq: u64,
    active: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
) -> Result<()> {
    ensure_adjacency_maintenance_fence(snapshot, keyspaces, fence)?;
    if read_and_validate_adjacency_retention(snapshot, keyspaces)? != oldest_retained_storage_seq
        || read_manifest(snapshot, keyspaces)? != *active
    {
        return Err(GraphError::AdjacencyMaintenanceConflict {
            requested: "prune_adjacency_generations",
            active: "changed adjacency retention or manifest state",
        });
    }
    Ok(())
}

fn validate_adjacency_compaction_guard<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    base_manifest: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
) -> Result<()> {
    ensure_adjacency_maintenance_fence(snapshot, keyspaces, fence)?;
    if read_manifest(snapshot, keyspaces)? != *base_manifest {
        return Err(GraphError::AdjacencyMaintenanceConflict {
            requested: "compact_graph",
            active: "changed active adjacency manifest",
        });
    }
    Ok(())
}

fn delete_manifest_history_before<E: StorageEngine>(
    engine: &E,
    keyspaces: &Keyspaces,
    baseline_switch_seq: Option<u64>,
    oldest_retained_storage_seq: u64,
    active: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
    durability: Durability,
) -> Result<u64> {
    let Some(baseline_switch_seq) = baseline_switch_seq else {
        return Ok(0);
    };
    let mut continuation = None;
    let mut deleted = 0_u64;
    loop {
        let mut transaction = engine.begin_write()?;
        validate_adjacency_prune_delete_guard(
            &transaction,
            keyspaces,
            oldest_retained_storage_seq,
            active,
            fence,
        )?;
        let page = transaction.scan_prefix_page(
            &keyspaces.manifest_history,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: SEGMENT_V2_SCAN_ENTRIES,
                max_bytes: SEGMENT_V2_SCAN_BYTES,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        if page.entries.is_empty() {
            transaction.rollback()?;
            return Ok(deleted);
        }
        let next = page.continuation;
        let mut page_deleted = 0_u64;
        let mut reached_baseline = false;
        for entry in page.entries {
            let switch_seq = decode_u64_key(&entry.key)?;
            if switch_seq >= baseline_switch_seq {
                reached_baseline = true;
                break;
            }
            bounded_add(
                &mut deleted,
                1,
                "adjacency_manifest_history_entries",
                PRUNE_MAX_HISTORY_ENTRIES,
            )?;
            page_deleted += 1;
            transaction.delete(&keyspaces.manifest_history, entry.key)?;
        }
        if page_deleted == 0 {
            transaction.rollback()?;
        } else {
            transaction.commit(durability)?;
        }
        if reached_baseline {
            return Ok(deleted);
        }
        let Some(next) = next else {
            return Ok(deleted);
        };
        continuation = Some(next);
    }
}

fn preflight_adjacency_generation_keys<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
) -> Result<()> {
    let mut generations = BTreeSet::new();
    let mut totals = AdjacencyPrunePhysicalTotals::default();
    preflight_generation_keyspace(
        snapshot,
        &keyspaces.segment,
        contextdb_storage::MAX_SCAN_PAGE_BYTES,
        parse_segment_v1_generation,
        &mut generations,
        &mut totals,
    )?;
    preflight_generation_keyspace(
        snapshot,
        &keyspaces.segment_v2,
        SEGMENT_V2_SCAN_BYTES,
        parse_segment_v2_generation,
        &mut generations,
        &mut totals,
    )?;
    Ok(())
}

fn preflight_generation_keyspace<S, F>(
    snapshot: &S,
    keyspace: &contextdb_storage::Keyspace,
    max_page_bytes: usize,
    parse_generation: F,
    generations: &mut BTreeSet<u64>,
    totals: &mut AdjacencyPrunePhysicalTotals,
) -> Result<()>
where
    S: ReadSnapshot,
    F: Fn(&[u8]) -> Result<u64>,
{
    let mut continuation = None;
    loop {
        let page = snapshot.scan_prefix_page(
            keyspace,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: SEGMENT_V2_SCAN_ENTRIES,
                max_bytes: max_page_bytes,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        for entry in page.entries {
            record_adjacency_prune_physical_entry(totals, &entry)?;
            generations.insert(parse_generation(&entry.key)?);
            ensure_bound(
                "adjacency_physical_generations",
                u64::try_from(generations.len()).unwrap_or(u64::MAX),
                PRUNE_MAX_GENERATIONS,
            )?;
        }
        let Some(next) = page.continuation else {
            return Ok(());
        };
        continuation = Some(next);
    }
}

fn record_adjacency_prune_physical_entry(
    totals: &mut AdjacencyPrunePhysicalTotals,
    entry: &contextdb_storage::Entry,
) -> Result<()> {
    bounded_add(
        &mut totals.records,
        1,
        "adjacency_prune_physical_records",
        PRUNE_MAX_PHYSICAL_RECORDS,
    )?;
    bounded_add(
        &mut totals.bytes,
        entry_record_bytes(entry)?,
        "adjacency_prune_physical_bytes",
        PRUNE_MAX_PHYSICAL_BYTES,
    )
}

fn delete_unreferenced_v1_generations<E: StorageEngine>(
    engine: &E,
    keyspaces: &Keyspaces,
    referenced: &BTreeMap<u64, u16>,
    oldest_retained_storage_seq: u64,
    active: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
    durability: Durability,
) -> Result<BTreeSet<u64>> {
    let mut continuation = None;
    let mut deleted_generations = BTreeSet::new();
    let mut scanned_records = 0_u64;
    let mut scanned_bytes = 0_u64;
    loop {
        let mut transaction = engine.begin_write()?;
        validate_adjacency_prune_delete_guard(
            &transaction,
            keyspaces,
            oldest_retained_storage_seq,
            active,
            fence,
        )?;
        let page = transaction.scan_prefix_page(
            &keyspaces.segment,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: SEGMENT_V2_SCAN_ENTRIES,
                max_bytes: contextdb_storage::MAX_SCAN_PAGE_BYTES,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        if page.entries.is_empty() {
            transaction.rollback()?;
            return Ok(deleted_generations);
        }
        let next = page.continuation;
        let mut page_deleted = false;
        for entry in page.entries {
            bounded_add(
                &mut scanned_records,
                1,
                "adjacency_prune_physical_records",
                PRUNE_MAX_PHYSICAL_RECORDS,
            )?;
            bounded_add(
                &mut scanned_bytes,
                entry_record_bytes(&entry)?,
                "adjacency_prune_physical_bytes",
                PRUNE_MAX_PHYSICAL_BYTES,
            )?;
            let generation = parse_segment_v1_generation(&entry.key)?;
            if referenced.get(&generation) != Some(&1) {
                transaction.delete(&keyspaces.segment, entry.key)?;
                deleted_generations.insert(generation);
                ensure_bound(
                    "adjacency_physical_generations",
                    u64::try_from(deleted_generations.len()).unwrap_or(u64::MAX),
                    PRUNE_MAX_GENERATIONS,
                )?;
                page_deleted = true;
            }
        }
        if page_deleted {
            transaction.commit(durability)?;
        } else {
            transaction.rollback()?;
        }
        let Some(next) = next else {
            return Ok(deleted_generations);
        };
        continuation = Some(next);
    }
}

fn delete_unreferenced_v2_generations<E: StorageEngine>(
    engine: &E,
    keyspaces: &Keyspaces,
    referenced: &BTreeMap<u64, u16>,
    oldest_retained_storage_seq: u64,
    active: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
    durability: Durability,
) -> Result<(BTreeSet<u64>, u64)> {
    let mut continuation = None;
    let mut deleted_generations = BTreeSet::new();
    let mut deleted_records = 0_u64;
    let mut scanned_records = 0_u64;
    let mut scanned_bytes = 0_u64;
    loop {
        let mut transaction = engine.begin_write()?;
        validate_adjacency_prune_delete_guard(
            &transaction,
            keyspaces,
            oldest_retained_storage_seq,
            active,
            fence,
        )?;
        let page = transaction.scan_prefix_page(
            &keyspaces.segment_v2,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: SEGMENT_V2_SCAN_ENTRIES,
                max_bytes: SEGMENT_V2_SCAN_BYTES,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        if page.entries.is_empty() {
            transaction.rollback()?;
            return Ok((deleted_generations, deleted_records));
        }
        let next = page.continuation;
        let mut page_deleted = false;
        for entry in page.entries {
            bounded_add(
                &mut scanned_records,
                1,
                "adjacency_prune_physical_records",
                PRUNE_MAX_PHYSICAL_RECORDS,
            )?;
            bounded_add(
                &mut scanned_bytes,
                entry_record_bytes(&entry)?,
                "adjacency_prune_physical_bytes",
                PRUNE_MAX_PHYSICAL_BYTES,
            )?;
            let generation = parse_segment_v2_generation(&entry.key)?;
            if referenced.get(&generation) != Some(&SEGMENT_V2_FORMAT) {
                transaction.delete(&keyspaces.segment_v2, entry.key)?;
                deleted_generations.insert(generation);
                bounded_add(
                    &mut deleted_records,
                    1,
                    "adjacency_prune_physical_records",
                    PRUNE_MAX_PHYSICAL_RECORDS,
                )?;
                ensure_bound(
                    "adjacency_physical_generations",
                    u64::try_from(deleted_generations.len()).unwrap_or(u64::MAX),
                    PRUNE_MAX_GENERATIONS,
                )?;
                page_deleted = true;
            }
        }
        if page_deleted {
            transaction.commit(durability)?;
        } else {
            transaction.rollback()?;
        }
        let Some(next) = next else {
            return Ok((deleted_generations, deleted_records));
        };
        continuation = Some(next);
    }
}

fn entry_record_bytes(entry: &contextdb_storage::Entry) -> Result<u64> {
    u64::try_from(entry.key.len())
        .ok()
        .and_then(|key_bytes| {
            u64::try_from(entry.value.len())
                .ok()
                .and_then(|value_bytes| key_bytes.checked_add(value_bytes))
        })
        .ok_or_else(|| GraphError::Corrupt("adjacency record length exceeds u64".to_owned()))
}

fn parse_segment_v1_generation(key: &[u8]) -> Result<u64> {
    let generation_bytes = key.strip_prefix(BASE_SEGMENT_KEY).ok_or_else(|| {
        GraphError::Corrupt("legacy adjacency segment key prefix mismatch".to_owned())
    })?;
    let generation = decode_u64_key(generation_bytes)?;
    if generation == 0 {
        return Err(GraphError::Corrupt(
            "legacy adjacency segment generation is zero".to_owned(),
        ));
    }
    Ok(generation)
}

fn parse_segment_v2_generation(key: &[u8]) -> Result<u64> {
    if key.len() < 10 || key[0] != b'g' {
        return Err(GraphError::Corrupt(
            "paged adjacency generation key prefix mismatch".to_owned(),
        ));
    }
    let generation = decode_u64_key(&key[1..9])?;
    if generation == 0 {
        return Err(GraphError::Corrupt(
            "paged adjacency generation is zero".to_owned(),
        ));
    }
    match key[9] {
        b'e' => validate_segment_v2_edge_key(key)?,
        b'r' => {
            if key.len() != 19 || key[10] > 1 || decode_u64_key(&key[11..19])? == 0 {
                return Err(GraphError::Corrupt(
                    "paged adjacency row key is malformed".to_owned(),
                ));
            }
        }
        b't' => {
            if key.len() != 20 {
                return Err(GraphError::Corrupt(
                    "paged adjacency Merkle key is malformed".to_owned(),
                ));
            }
            let _: [u8; 2] = key[10..12].try_into().map_err(|_| {
                GraphError::Corrupt("paged adjacency Merkle level is malformed".to_owned())
            })?;
            decode_u64_key(&key[12..20])?;
        }
        _ => {
            return Err(GraphError::Corrupt(
                "paged adjacency record kind is unsupported".to_owned(),
            ));
        }
    }
    Ok(generation)
}

fn validate_segment_v2_edge_key(key: &[u8]) -> Result<()> {
    if key.len() < 31
        || key[10] > 1
        || decode_u64_key(&key[11..19])? == 0
        || decode_u64_key(&key[19..27])? == 0
    {
        return Err(GraphError::Corrupt(
            "paged adjacency edge key is malformed".to_owned(),
        ));
    }
    let mut cursor = 27_usize;
    for _ in 0..2 {
        let length_bytes: [u8; 2] = key
            .get(cursor..cursor.saturating_add(2))
            .ok_or_else(|| GraphError::Corrupt("paged adjacency key length missing".to_owned()))?
            .try_into()
            .map_err(|_| GraphError::Corrupt("paged adjacency key length malformed".to_owned()))?;
        cursor = cursor.saturating_add(2);
        let length = usize::from(u16::from_be_bytes(length_bytes));
        if length == 0 {
            return Err(GraphError::Corrupt(
                "paged adjacency key component is empty".to_owned(),
            ));
        }
        let component = key
            .get(cursor..cursor.saturating_add(length))
            .ok_or_else(|| {
                GraphError::Corrupt("paged adjacency key component is truncated".to_owned())
            })?;
        std::str::from_utf8(component).map_err(|error| GraphError::Corrupt(error.to_string()))?;
        cursor = cursor.saturating_add(length);
    }
    if cursor != key.len() {
        return Err(GraphError::Corrupt(
            "paged adjacency edge key has trailing bytes".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct SegmentV2RowScan {
    edges: Vec<SegmentEdge>,
    edge_count: u64,
    edge_bytes: u64,
    edge_digest: String,
}

fn clear_segment_v2_generation<E: StorageEngine>(
    engine: &E,
    keyspaces: &Keyspaces,
    generation: u64,
    base_manifest: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
    durability: Durability,
) -> Result<()> {
    let prefix = segment_v2_generation_prefix(generation);
    let mut continuation = None;
    loop {
        let mut transaction = engine.begin_write()?;
        validate_adjacency_compaction_guard(&transaction, keyspaces, base_manifest, fence)?;
        let page = transaction.scan_prefix_page(
            &keyspaces.segment_v2,
            ScanPageRequest {
                prefix: &prefix,
                start_after: continuation.as_deref(),
                max_entries: SEGMENT_V2_SCAN_ENTRIES,
                max_bytes: SEGMENT_V2_SCAN_BYTES,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        if page.entries.is_empty() {
            transaction.rollback()?;
            return Ok(());
        }
        for entry in page.entries {
            transaction.delete(&keyspaces.segment_v2, entry.key)?;
        }
        let next = page.continuation;
        transaction.commit(durability)?;
        let Some(next) = next else {
            return Ok(());
        };
        continuation = Some(next);
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit immutable segment identity"
)]
fn write_segment_v2_edges<E, S>(
    engine: &E,
    source: &S,
    keyspaces: &Keyspaces,
    generation: u64,
    built_through_seq: u64,
    semantic_seq: CommitSeq,
    base_manifest: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
    durability: Durability,
) -> Result<(u64, u64)>
where
    E: StorageEngine,
    S: ReadSnapshot,
{
    let mut continuation = None;
    let mut total_count = 0_u64;
    let mut total_bytes = 0_u64;
    loop {
        let page = source.scan_prefix_page(
            &keyspaces.edge_identity,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: 128,
                max_bytes: 2 * 1024 * 1024,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        if page.entries.is_empty() {
            return Ok((total_count, total_bytes));
        }
        let mut transaction = engine.begin_write()?;
        validate_adjacency_compaction_guard(&transaction, keyspaces, base_manifest, fence)?;
        let expected_sequence = transaction.sequence();
        let mut batch_count = 0_u64;
        let mut batch_bytes = 0_u64;
        for entry in page.entries {
            let edge: Edge = decode(&entry.value)?;
            if entry.key != external_key(edge.id) {
                return Err(GraphError::Corrupt(
                    "edge identity key disagrees with its canonical ID".to_owned(),
                ));
            }
            let revision = current_edge_revision(
                source,
                keyspaces,
                &edge.id.to_string(),
                built_through_seq,
                semantic_seq,
            )?;
            if revision.epistemic.lifecycle != LifecycleState::Active {
                continue;
            }
            let row = SegmentEdge {
                edge_id: edge.id.to_string(),
                source: dense_for_external(source, keyspaces, &edge.source.to_string())?,
                target: dense_for_external(source, keyspaces, &edge.target.to_string())?,
                edge_type: edge.edge_type.to_string(),
                directionality: edge.directionality,
            };
            put_segment_v2_edge(
                &mut transaction,
                keyspaces,
                generation,
                SegmentDirectionV2::Outgoing,
                &row,
                &mut total_count,
                &mut total_bytes,
                &mut batch_count,
                &mut batch_bytes,
            )?;
            put_segment_v2_edge(
                &mut transaction,
                keyspaces,
                generation,
                SegmentDirectionV2::Incoming,
                &row,
                &mut total_count,
                &mut total_bytes,
                &mut batch_count,
                &mut batch_bytes,
            )?;
            if row.directionality == contextdb_core::Directionality::Undirected
                && row.source != row.target
            {
                let reverse = SegmentEdge {
                    source: row.target,
                    target: row.source,
                    ..row
                };
                put_segment_v2_edge(
                    &mut transaction,
                    keyspaces,
                    generation,
                    SegmentDirectionV2::Outgoing,
                    &reverse,
                    &mut total_count,
                    &mut total_bytes,
                    &mut batch_count,
                    &mut batch_bytes,
                )?;
                put_segment_v2_edge(
                    &mut transaction,
                    keyspaces,
                    generation,
                    SegmentDirectionV2::Incoming,
                    &reverse,
                    &mut total_count,
                    &mut total_bytes,
                    &mut batch_count,
                    &mut batch_bytes,
                )?;
            }
        }
        if batch_count == 0 {
            transaction.rollback()?;
        } else {
            let receipt = transaction.commit(durability)?;
            if receipt.sequence != expected_sequence.saturating_add(1) {
                return Err(GraphError::Invariant(
                    "backend sequence diverged while writing adjacency edges".to_owned(),
                ));
            }
        }
        let Some(next) = page.continuation else {
            return Ok((total_count, total_bytes));
        };
        continuation = Some(next);
    }
}

#[allow(clippy::too_many_arguments, reason = "bounded counters are explicit")]
fn put_segment_v2_edge<T: WriteTransaction>(
    transaction: &mut T,
    keyspaces: &Keyspaces,
    generation: u64,
    direction: SegmentDirectionV2,
    edge: &SegmentEdge,
    total_count: &mut u64,
    total_bytes: &mut u64,
    batch_count: &mut u64,
    batch_bytes: &mut u64,
) -> Result<()> {
    let value = encode(edge)?;
    let value_bytes = u64::try_from(value.len())
        .map_err(|_| GraphError::Invariant("edge value length exceeds u64".to_owned()))?;
    ensure_bound(
        "segment_v2_edge_value_bytes",
        value_bytes,
        SEGMENT_V2_MAX_EDGE_VALUE_BYTES,
    )?;
    let key = segment_v2_edge_key(generation, direction, edge)?;
    let record_bytes = u64::try_from(key.len())
        .ok()
        .and_then(|key_bytes| key_bytes.checked_add(value_bytes))
        .ok_or_else(|| GraphError::Invariant("edge record length exceeds u64".to_owned()))?;
    bounded_add(
        total_count,
        1,
        "segment_v2_edges",
        SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
    )?;
    bounded_add(
        total_bytes,
        record_bytes,
        "segment_v2_edge_bytes",
        SEGMENT_V2_MAX_EDGE_BYTES,
    )?;
    bounded_add(batch_count, 1, "segment_v2_batch_edges", 512)?;
    bounded_add(
        batch_bytes,
        record_bytes,
        "segment_v2_batch_bytes",
        32 * 1024 * 1024,
    )?;
    transaction.put(&keyspaces.segment_v2, key, value)?;
    Ok(())
}

fn current_edge_revision<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    edge_id: &str,
    storage_seq: u64,
    semantic_seq: CommitSeq,
) -> Result<EdgeRevision> {
    let head = snapshot
        .get(&keyspaces.edge_head, edge_id.as_bytes())?
        .map(|bytes| decode::<u32>(&bytes))
        .transpose()?
        .ok_or_else(|| not_found("edge revision head", edge_id))?;
    let bytes = snapshot
        .get(&keyspaces.edge_revision, &revision_key(edge_id, head))?
        .ok_or_else(|| not_found("edge revision", edge_id))?;
    let persisted: PersistedRevision<EdgeRevision> = decode(&bytes)?;
    if persisted.value.edge_id.to_string() != edge_id
        || persisted.value.revision.get() != head
        || persisted.visible_from > storage_seq
        || persisted.visible_to.is_some_and(|end| storage_seq >= end)
        || !persisted.value.transaction_time().contains(semantic_seq)
    {
        return Err(GraphError::Corrupt(
            "edge revision head is not visible at the compaction snapshot".to_owned(),
        ));
    }
    Ok(persisted.value)
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit fenced generation identity"
)]
fn write_segment_v2_rows<E, S>(
    engine: &E,
    source: &S,
    keyspaces: &Keyspaces,
    generation: u64,
    built_through_seq: u64,
    base_manifest: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
    durability: Durability,
) -> Result<(u64, u64, u64)>
where
    E: StorageEngine,
    S: ReadSnapshot,
{
    let mut continuation = None;
    let mut expected_dense = 1_u64;
    let mut row_count = 0_u64;
    let mut edge_count = 0_u64;
    let mut edge_bytes = 0_u64;
    loop {
        let page = source.scan_prefix_page(
            &keyspaces.id_dense,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: 128,
                max_bytes: 2 * 1024 * 1024,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        if page.entries.is_empty() {
            return Ok((row_count, edge_count, edge_bytes));
        }
        let mut transaction = engine.begin_write()?;
        validate_adjacency_compaction_guard(&transaction, keyspaces, base_manifest, fence)?;
        let expected_sequence = transaction.sequence();
        for entry in page.entries {
            let actual_dense = decode_u64_key(&entry.key)?;
            if actual_dense != expected_dense || entry.value.is_empty() {
                return Err(GraphError::Corrupt(
                    "dense ID index is not contiguous and canonical".to_owned(),
                ));
            }
            let node = DenseId::new(actual_dense)?;
            expected_dense = expected_dense
                .checked_add(1)
                .ok_or_else(|| GraphError::Invariant("dense ID sequence exhausted".to_owned()))?;
            for direction in SegmentDirectionV2::ALL {
                let summary = scan_segment_v2_row(
                    &transaction,
                    keyspaces,
                    generation,
                    direction,
                    node,
                    false,
                )?;
                bounded_add(&mut row_count, 1, "segment_v2_rows", SEGMENT_V2_MAX_ROWS)?;
                bounded_add(
                    &mut edge_count,
                    summary.edge_count,
                    "segment_v2_edges",
                    SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
                )?;
                bounded_add(
                    &mut edge_bytes,
                    summary.edge_bytes,
                    "segment_v2_edge_bytes",
                    SEGMENT_V2_MAX_EDGE_BYTES,
                )?;
                let row = AdjacencyRowManifestV2 {
                    format_version: SEGMENT_V2_FORMAT,
                    generation,
                    built_through_seq,
                    direction,
                    node,
                    edge_count: summary.edge_count,
                    edge_bytes: summary.edge_bytes,
                    edge_digest: summary.edge_digest,
                };
                let row_bytes = encode(&row)?;
                let leaf = segment_v2_leaf_hash(&row_bytes);
                let leaf_index = row_count - 1;
                transaction.put(
                    &keyspaces.segment_v2,
                    segment_v2_row_key(generation, direction, node),
                    row_bytes,
                )?;
                transaction.put(
                    &keyspaces.segment_v2,
                    segment_v2_tree_key(generation, 0, leaf_index),
                    leaf.as_bytes().to_vec(),
                )?;
            }
        }
        let receipt = transaction.commit(durability)?;
        if receipt.sequence != expected_sequence.saturating_add(1) {
            return Err(GraphError::Invariant(
                "backend sequence diverged while writing adjacency rows".to_owned(),
            ));
        }
        let Some(next) = page.continuation else {
            return Ok((row_count, edge_count, edge_bytes));
        };
        continuation = Some(next);
    }
}

fn build_segment_v2_merkle<E: StorageEngine>(
    engine: &E,
    keyspaces: &Keyspaces,
    generation: u64,
    row_count: u64,
    base_manifest: &SegmentManifest,
    fence: &AdjacencyMaintenanceFence,
    durability: Durability,
) -> Result<blake3::Hash> {
    if row_count == 0 {
        return Ok(segment_v2_empty_root());
    }
    let mut level = 0_u16;
    let mut width = row_count;
    while width > 1 {
        let parent_width = width.div_ceil(2);
        let mut parent_start = 0_u64;
        while parent_start < parent_width {
            let parent_end = parent_start.saturating_add(1_024).min(parent_width);
            let mut transaction = engine.begin_write()?;
            validate_adjacency_compaction_guard(&transaction, keyspaces, base_manifest, fence)?;
            for parent in parent_start..parent_end {
                let left_index = parent.checked_mul(2).ok_or_else(|| {
                    GraphError::Invariant("Merkle child index exhausted".to_owned())
                })?;
                let left =
                    read_segment_v2_hash(&transaction, keyspaces, generation, level, left_index)?;
                let right = if left_index + 1 < width {
                    read_segment_v2_hash(
                        &transaction,
                        keyspaces,
                        generation,
                        level,
                        left_index + 1,
                    )?
                } else {
                    left
                };
                transaction.put(
                    &keyspaces.segment_v2,
                    segment_v2_tree_key(generation, level + 1, parent),
                    segment_v2_parent_hash(left, right).as_bytes().to_vec(),
                )?;
            }
            transaction.commit(durability)?;
            parent_start = parent_end;
        }
        level = level
            .checked_add(1)
            .ok_or_else(|| GraphError::Invariant("Merkle level exhausted".to_owned()))?;
        width = parent_width;
    }
    let latest = engine.begin_read(SnapshotSelector::Latest)?;
    validate_adjacency_compaction_guard(&latest, keyspaces, base_manifest, fence)?;
    read_segment_v2_hash(&latest, keyspaces, generation, level, 0)
}

fn validate_segment_v2_generation<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    manifest: &SegmentManifest,
) -> Result<()> {
    let row_root = if manifest.row_count == 0 {
        segment_v2_empty_root()
    } else {
        read_segment_v2_hash(
            snapshot,
            keyspaces,
            manifest.generation,
            segment_v2_root_level(manifest.row_count)?,
            0,
        )?
    };
    let actual = segment_v2_manifest_root(
        manifest.generation,
        manifest.built_through_seq,
        manifest.row_count,
        manifest.edge_count,
        manifest.edge_bytes,
        row_root,
    );
    if actual.to_hex().as_str() != manifest.segment_digest {
        return Err(GraphError::Corrupt(
            "paged adjacency root disagrees with active manifest".to_owned(),
        ));
    }
    Ok(())
}

fn scan_segment_v2_row<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    generation: u64,
    direction: SegmentDirectionV2,
    node: DenseId,
    collect_edges: bool,
) -> Result<SegmentV2RowScan> {
    let prefix = segment_v2_edge_prefix(generation, direction, node);
    let mut continuation = None;
    let mut edge_count = 0_u64;
    let mut edge_bytes = 0_u64;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb.graph.segment.v2.row\0");
    let mut edges = Vec::new();
    loop {
        let page = snapshot.scan_prefix_page(
            &keyspaces.segment_v2,
            ScanPageRequest {
                prefix: &prefix,
                start_after: continuation.as_deref(),
                max_entries: SEGMENT_V2_SCAN_ENTRIES,
                max_bytes: SEGMENT_V2_SCAN_BYTES,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        for entry in page.entries {
            let edge: SegmentEdge = decode(&entry.value)?;
            if direction.row_node(&edge) != node
                || entry.key != segment_v2_edge_key(generation, direction, &edge)?
            {
                return Err(GraphError::Corrupt(
                    "paged adjacency edge key disagrees with its value".to_owned(),
                ));
            }
            let record_bytes = u64::try_from(entry.key.len())
                .ok()
                .and_then(|key_bytes| {
                    u64::try_from(entry.value.len())
                        .ok()
                        .and_then(|value_bytes| key_bytes.checked_add(value_bytes))
                })
                .ok_or_else(|| GraphError::Corrupt("edge record length exceeds u64".to_owned()))?;
            bounded_add(
                &mut edge_count,
                1,
                "segment_v2_row_edges",
                SEGMENT_V2_MAX_ROW_EDGES,
            )?;
            bounded_add(
                &mut edge_bytes,
                record_bytes,
                "segment_v2_row_bytes",
                SEGMENT_V2_MAX_ROW_BYTES,
            )?;
            update_segment_v2_digest(&mut hasher, &entry.key, &entry.value)?;
            if collect_edges {
                edges.push(edge);
            }
        }
        let Some(next) = page.continuation else {
            return Ok(SegmentV2RowScan {
                edges,
                edge_count,
                edge_bytes,
                edge_digest: hasher.finalize().to_hex().to_string(),
            });
        };
        continuation = Some(next);
    }
}

fn validate_scan_progress(page: &ScanPage, previous: Option<&[u8]>) -> Result<()> {
    if page.continuation.is_some() && page.entries.is_empty() {
        return Err(GraphError::Corrupt(
            "paged storage scan returned a continuation without progress".to_owned(),
        ));
    }
    if let (Some(previous), Some(next)) = (previous, page.continuation.as_deref())
        && next <= previous
    {
        return Err(GraphError::Corrupt(
            "paged storage scan continuation did not advance".to_owned(),
        ));
    }
    Ok(())
}

fn bounded_add(value: &mut u64, add: u64, resource: &'static str, limit: u64) -> Result<()> {
    let required = value.checked_add(add).unwrap_or(u64::MAX);
    ensure_bound(resource, required, limit)?;
    *value = required;
    Ok(())
}

fn ensure_bound(resource: &'static str, required: u64, limit: u64) -> Result<()> {
    if required > limit {
        Err(GraphError::ResourceExhausted {
            resource,
            limit,
            required,
        })
    } else {
        Ok(())
    }
}

fn update_segment_v2_digest(hasher: &mut blake3::Hasher, key: &[u8], value: &[u8]) -> Result<()> {
    let key_len = u64::try_from(key.len())
        .map_err(|_| GraphError::Invariant("segment key length exceeds u64".to_owned()))?;
    let value_len = u64::try_from(value.len())
        .map_err(|_| GraphError::Invariant("segment value length exceeds u64".to_owned()))?;
    hasher.update(&key_len.to_be_bytes());
    hasher.update(key);
    hasher.update(&value_len.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn segment_v2_leaf_hash(row_bytes: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb.graph.segment.v2.leaf\0");
    hasher.update(row_bytes);
    hasher.finalize()
}

fn segment_v2_parent_hash(left: blake3::Hash, right: blake3::Hash) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb.graph.segment.v2.parent\0");
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

fn segment_v2_empty_root() -> blake3::Hash {
    blake3::hash(b"contextdb.graph.segment.v2.empty\0")
}

fn segment_v2_manifest_root(
    generation: u64,
    built_through_seq: u64,
    row_count: u64,
    edge_count: u64,
    edge_bytes: u64,
    row_merkle_root: blake3::Hash,
) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb.graph.segment.v2.manifest\0");
    hasher.update(&SEGMENT_V2_FORMAT.to_be_bytes());
    hasher.update(&generation.to_be_bytes());
    hasher.update(&built_through_seq.to_be_bytes());
    hasher.update(&row_count.to_be_bytes());
    hasher.update(&edge_count.to_be_bytes());
    hasher.update(&edge_bytes.to_be_bytes());
    hasher.update(row_merkle_root.as_bytes());
    hasher.finalize()
}

fn read_segment_v2_hash<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    generation: u64,
    level: u16,
    index: u64,
) -> Result<blake3::Hash> {
    let bytes = snapshot
        .get(
            &keyspaces.segment_v2,
            &segment_v2_tree_key(generation, level, index),
        )?
        .ok_or_else(|| GraphError::Corrupt("paged adjacency Merkle node missing".to_owned()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GraphError::Corrupt("paged adjacency Merkle node is malformed".to_owned()))?;
    Ok(blake3::Hash::from_bytes(bytes))
}

fn segment_v2_root_level(mut width: u64) -> Result<u16> {
    let mut level = 0_u16;
    while width > 1 {
        width = width.div_ceil(2);
        level = level.checked_add(1).ok_or_else(|| {
            GraphError::Corrupt("paged adjacency Merkle depth exceeds u16".to_owned())
        })?;
    }
    Ok(level)
}

fn validate_batch(mutation: &GraphMutation) -> Result<()> {
    for value in &mutation.workspaces {
        value.validate()?;
    }
    for value in &mutation.memory_spaces {
        value.validate()?;
    }
    for value in &mutation.memory_subjects {
        value.validate()?;
    }
    for value in &mutation.nodes {
        value.validate()?;
    }
    for value in &mutation.node_revisions {
        value.validate()?;
    }
    for value in &mutation.claims {
        value.validate()?;
    }
    for value in &mutation.claim_revisions {
        value.validate()?;
    }
    for value in &mutation.edges {
        value.validate()?;
    }
    for value in &mutation.edge_revisions {
        value.validate()?;
    }
    for value in &mutation.conflicts {
        value.validate()?;
    }
    for value in &mutation.conflict_revisions {
        value.validate()?;
    }
    for value in &mutation.artifacts {
        value.validate()?;
    }
    Ok(())
}

fn validate_mutation_time(mutation: &GraphMutation, commit_seq: CommitSeq) -> Result<()> {
    let stable_times_match = mutation
        .nodes
        .iter()
        .all(|value| value.created_seq == commit_seq)
        && mutation
            .claims
            .iter()
            .all(|value| value.created_seq == commit_seq)
        && mutation
            .edges
            .iter()
            .all(|value| value.created_seq == commit_seq)
        && mutation
            .conflicts
            .iter()
            .all(|value| value.created_seq == commit_seq);
    let revision_times_match = mutation
        .node_revisions
        .iter()
        .all(|value| value.transaction_time().start == commit_seq)
        && mutation
            .claim_revisions
            .iter()
            .all(|value| value.transaction_time().start == commit_seq)
        && mutation
            .edge_revisions
            .iter()
            .all(|value| value.transaction_time().start == commit_seq)
        && mutation
            .conflict_revisions
            .iter()
            .all(|value| value.transaction_time().start == commit_seq);
    if stable_times_match && revision_times_match {
        Ok(())
    } else {
        Err(GraphError::Invariant(format!(
            "created/transaction times must begin at graph semantic commit {commit_seq}"
        )))
    }
}

fn validate_staged_references<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    mutation: &GraphMutation,
) -> Result<()> {
    for space in &mutation.memory_spaces {
        let mut ancestors = BTreeSet::from([space.id]);
        let mut parent_id = space.parent;
        while let Some(current_parent) = parent_id {
            if !ancestors.insert(current_parent) {
                return Err(GraphError::Invariant(
                    "memory-space parent hierarchy contains a cycle".to_owned(),
                ));
            }
            let parent: MemorySpace = get_identity(
                snapshot,
                &keyspaces.space_identity,
                current_parent,
                "parent memory space",
            )?;
            ensure_workspace(
                "memory-space parent",
                space.workspace_id,
                parent.workspace_id,
            )?;
            parent_id = parent.parent;
        }
        for owner in &space.owners {
            let subject: MemorySubject = get_identity(
                snapshot,
                &keyspaces.subject_identity,
                *owner,
                "memory-space owner",
            )?;
            ensure_workspace(
                "memory-space owner",
                space.workspace_id,
                subject.workspace_id,
            )?;
        }
    }
    for subject in &mutation.memory_subjects {
        let canonical: Node = get_identity(
            snapshot,
            &keyspaces.node_identity,
            subject.canonical_node,
            "subject canonical node",
        )?;
        ensure_workspace(
            "subject canonical node",
            subject.workspace_id,
            canonical.workspace_id,
        )?;
        for space_id in &subject.primary_spaces {
            let space: MemorySpace = get_identity(
                snapshot,
                &keyspaces.space_identity,
                *space_id,
                "subject primary space",
            )?;
            ensure_workspace(
                "subject primary space",
                subject.workspace_id,
                space.workspace_id,
            )?;
            if !space.owners.contains(&subject.id) {
                return Err(GraphError::Invariant(format!(
                    "subject {} is not an owner of primary space {}",
                    subject.id, space.id
                )));
            }
        }
    }
    for node in &mutation.nodes {
        match &node.primary_scope.kind {
            contextdb_core::ScopeKind::Workspace => {
                let workspace = WorkspaceId::from_uuid(node.primary_scope.id.as_uuid())
                    .map_err(|error| GraphError::Invariant(error.to_string()))?;
                ensure_workspace("node primary workspace", node.workspace_id, workspace)?;
            }
            contextdb_core::ScopeKind::MemorySpace => {
                let space_id = MemorySpaceId::from_uuid(node.primary_scope.id.as_uuid())
                    .map_err(|error| GraphError::Invariant(error.to_string()))?;
                let space: MemorySpace = get_identity(
                    snapshot,
                    &keyspaces.space_identity,
                    space_id,
                    "node memory space",
                )?;
                ensure_workspace("node memory space", node.workspace_id, space.workspace_id)?;
            }
            _ => {}
        }
    }
    for claim in &mutation.claims {
        let subject: Node = get_identity(
            snapshot,
            &keyspaces.node_identity,
            claim.subject,
            "claim subject",
        )?;
        ensure_workspace("claim subject", claim.workspace_id, subject.workspace_id)?;
    }
    for edge in &mutation.edges {
        let source: Node = get_identity(
            snapshot,
            &keyspaces.node_identity,
            edge.source,
            "edge source",
        )?;
        let target: Node = get_identity(
            snapshot,
            &keyspaces.node_identity,
            edge.target,
            "edge target",
        )?;
        ensure_workspace("edge source", edge.workspace_id, source.workspace_id)?;
        ensure_workspace("edge target", edge.workspace_id, target.workspace_id)?;
        if let Some(claim_id) = edge.materialized_from_claim {
            let claim: Claim = get_identity(
                snapshot,
                &keyspaces.claim_identity,
                claim_id,
                "materialized claim",
            )?;
            ensure_workspace("materialized claim", edge.workspace_id, claim.workspace_id)?;
        }
    }
    for conflict in &mutation.conflicts {
        let subject: Node = get_identity(
            snapshot,
            &keyspaces.node_identity,
            conflict.subject,
            "conflict subject",
        )?;
        ensure_workspace(
            "conflict subject",
            conflict.workspace_id,
            subject.workspace_id,
        )?;
    }
    for revision in &mutation.claim_revisions {
        let claim: Claim = get_identity(
            snapshot,
            &keyspaces.claim_identity,
            revision.claim_id,
            "claim",
        )?;
        for superseded_id in &revision.supersedes {
            let superseded: Claim = get_identity(
                snapshot,
                &keyspaces.claim_identity,
                *superseded_id,
                "superseded claim",
            )?;
            if (claim.workspace_id, claim.subject, claim.predicate)
                != (
                    superseded.workspace_id,
                    superseded.subject,
                    superseded.predicate,
                )
            {
                return Err(GraphError::Invariant(
                    "a claim may supersede only the same workspace/subject/predicate".to_owned(),
                ));
            }
        }
        if let Some(set_id) = revision.epistemic.conflict.set_id() {
            let conflict: ConflictSet = get_identity(
                snapshot,
                &keyspaces.conflict_identity,
                set_id,
                "referenced conflict set",
            )?;
            ensure_claim_conflict_signature(&claim, &conflict)?;
        }
    }
    for revision in &mutation.conflict_revisions {
        let conflict: ConflictSet = get_identity(
            snapshot,
            &keyspaces.conflict_identity,
            revision.conflict_set_id,
            "conflict set",
        )?;
        for member in &revision.members {
            let claim: Claim = get_identity(
                snapshot,
                &keyspaces.claim_identity,
                *member,
                "conflict member",
            )?;
            ensure_claim_conflict_signature(&claim, &conflict)?;
        }
    }
    Ok(())
}

fn ensure_workspace(
    relation: &'static str,
    expected: WorkspaceId,
    actual: WorkspaceId,
) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(GraphError::Invariant(format!(
            "{relation} crosses workspace boundary {expected} -> {actual}"
        )))
    }
}

fn ensure_claim_conflict_signature(claim: &Claim, conflict: &ConflictSet) -> Result<()> {
    if (claim.workspace_id, claim.subject, claim.predicate)
        == (conflict.workspace_id, conflict.subject, conflict.predicate)
    {
        Ok(())
    } else {
        Err(GraphError::Invariant(
            "conflict member does not share workspace/subject/predicate".to_owned(),
        ))
    }
}

fn write_revisions<T: WriteTransaction>(
    transaction: &mut T,
    keyspaces: &Keyspaces,
    mutation: &GraphMutation,
    visible_from: u64,
) -> Result<()> {
    for revision in &mutation.node_revisions {
        let workspace = workspace_for_node(transaction, keyspaces, revision.node_id)?;
        validate_envelope_references(transaction, keyspaces, &revision.envelope, workspace)?;
        write_revision(
            transaction,
            &keyspaces.node_identity,
            &keyspaces.node_revision,
            &keyspaces.node_head,
            keyspaces,
            &revision.node_id.to_string(),
            revision.revision.get(),
            revision,
            visible_from,
            build_policy(workspace, &revision.envelope),
        )?;
    }
    for revision in &mutation.claim_revisions {
        let workspace = workspace_for_claim(transaction, keyspaces, revision.claim_id)?;
        validate_envelope_references(transaction, keyspaces, &revision.envelope, workspace)?;
        write_revision(
            transaction,
            &keyspaces.claim_identity,
            &keyspaces.claim_revision,
            &keyspaces.claim_head,
            keyspaces,
            &revision.claim_id.to_string(),
            revision.revision.get(),
            revision,
            visible_from,
            build_policy(workspace, &revision.envelope),
        )?;
    }
    for revision in &mutation.edge_revisions {
        let edge = edge_identity(transaction, keyspaces, revision.edge_id)?;
        validate_envelope_references(
            transaction,
            keyspaces,
            &revision.envelope,
            edge.workspace_id,
        )?;
        write_revision(
            transaction,
            &keyspaces.edge_identity,
            &keyspaces.edge_revision,
            &keyspaces.edge_head,
            keyspaces,
            &revision.edge_id.to_string(),
            revision.revision.get(),
            revision,
            visible_from,
            build_policy(edge.workspace_id, &revision.envelope),
        )?;
        let source = dense_for_external(transaction, keyspaces, &edge.source.to_string())?;
        let target = dense_for_external(transaction, keyspaces, &edge.target.to_string())?;
        let delta = SegmentEdge {
            edge_id: edge.id.to_string(),
            source,
            target,
            edge_type: edge.edge_type.to_string(),
            directionality: edge.directionality,
        };
        transaction.put(
            &keyspaces.edge_out_delta,
            delta_key(source, visible_from, &edge.id.to_string()),
            encode(&delta)?,
        )?;
        transaction.put(
            &keyspaces.edge_in_delta,
            delta_key(target, visible_from, &edge.id.to_string()),
            encode(&delta)?,
        )?;
        if edge.directionality == contextdb_core::Directionality::Undirected {
            let reverse = SegmentEdge {
                source: target,
                target: source,
                ..delta
            };
            transaction.put(
                &keyspaces.edge_out_delta,
                delta_key(target, visible_from, &edge.id.to_string()),
                encode(&reverse)?,
            )?;
            transaction.put(
                &keyspaces.edge_in_delta,
                delta_key(source, visible_from, &edge.id.to_string()),
                encode(&reverse)?,
            )?;
        }
    }
    for revision in &mutation.conflict_revisions {
        let workspace = workspace_for_conflict(transaction, keyspaces, revision.conflict_set_id)?;
        validate_envelope_references(transaction, keyspaces, &revision.envelope, workspace)?;
        write_revision(
            transaction,
            &keyspaces.conflict_identity,
            &keyspaces.conflict_revision,
            &keyspaces.conflict_head,
            keyspaces,
            &revision.conflict_set_id.to_string(),
            revision.revision.get(),
            revision,
            visible_from,
            build_policy(workspace, &revision.envelope),
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "single generic revision persistence primitive"
)]
fn write_revision<T, R>(
    transaction: &mut T,
    identity_space: &contextdb_storage::Keyspace,
    revision_space: &contextdb_storage::Keyspace,
    head_space: &contextdb_storage::Keyspace,
    keyspaces: &Keyspaces,
    id: &str,
    revision: u32,
    value: &R,
    visible_from: u64,
    policy: PolicyIndexEntry,
) -> Result<()>
where
    T: WriteTransaction,
    R: Serialize,
{
    if transaction.get(identity_space, id.as_bytes())?.is_none() {
        return Err(not_found("stable identity", id));
    }
    let expected = transaction
        .get(head_space, id.as_bytes())?
        .map(|bytes| decode::<u32>(&bytes))
        .transpose()?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| GraphError::Invariant("revision sequence exhausted".to_owned()))?;
    if revision != expected {
        return Err(GraphError::Invariant(format!(
            "revision sequence for {id}: expected {expected}, received {revision}"
        )));
    }
    transaction.put(
        revision_space,
        revision_key(id, revision),
        encode(&PersistedRevision {
            visible_from,
            visible_to: None,
            value,
        })?,
    )?;
    transaction.put(head_space, id.as_bytes().to_vec(), encode(&revision)?)?;
    if let Some(previous) = transaction.get(&keyspaces.policy, id.as_bytes())? {
        remove_policy_indexes(transaction, keyspaces, id, &decode(&previous)?)?;
    }
    transaction.put(&keyspaces.policy, id.as_bytes().to_vec(), encode(&policy)?)?;
    transaction.put(
        &keyspaces.policy_history,
        policy_history_key(id, visible_from),
        encode(&PersistedPolicy {
            visible_from,
            value: policy.clone(),
        })?,
    )?;
    write_policy_indexes(transaction, keyspaces, id, &policy)?;
    Ok(())
}

fn write_policy_indexes<T: WriteTransaction>(
    transaction: &mut T,
    keyspaces: &Keyspaces,
    id: &str,
    policy: &PolicyIndexEntry,
) -> Result<()> {
    transaction.put(
        &keyspaces.by_workspace,
        index_key(&policy.workspace_id.to_string(), id),
        Vec::new(),
    )?;
    for subject in &policy.subjects {
        transaction.put(
            &keyspaces.by_subject,
            index_key(&subject.to_string(), id),
            Vec::new(),
        )?;
    }
    for scope in &policy.scopes {
        transaction.put(
            &keyspaces.by_scope,
            index_key(&scope.to_string(), id),
            Vec::new(),
        )?;
    }
    for owner in &policy.owners {
        transaction.put(
            &keyspaces.by_owner,
            index_key(&owner.to_string(), id),
            Vec::new(),
        )?;
    }
    for space in &policy.memory_spaces {
        transaction.put(
            &keyspaces.by_space,
            index_key(&space.to_string(), id),
            Vec::new(),
        )?;
    }
    for audience in policy.audience_purposes.keys() {
        transaction.put(&keyspaces.by_audience, index_key(audience, id), Vec::new())?;
    }
    for purpose in &policy.allowed_purposes {
        transaction.put(
            &keyspaces.by_purpose,
            index_key(&purpose_key(purpose)?, id),
            Vec::new(),
        )?;
    }
    Ok(())
}

fn remove_policy_indexes<T: WriteTransaction>(
    transaction: &mut T,
    keyspaces: &Keyspaces,
    id: &str,
    policy: &PolicyIndexEntry,
) -> Result<()> {
    transaction.delete(
        &keyspaces.by_workspace,
        index_key(&policy.workspace_id.to_string(), id),
    )?;
    for subject in &policy.subjects {
        transaction.delete(&keyspaces.by_subject, index_key(&subject.to_string(), id))?;
    }
    for scope in &policy.scopes {
        transaction.delete(&keyspaces.by_scope, index_key(&scope.to_string(), id))?;
    }
    for owner in &policy.owners {
        transaction.delete(&keyspaces.by_owner, index_key(&owner.to_string(), id))?;
    }
    for space in &policy.memory_spaces {
        transaction.delete(&keyspaces.by_space, index_key(&space.to_string(), id))?;
    }
    for audience in policy.audience_purposes.keys() {
        transaction.delete(&keyspaces.by_audience, index_key(audience, id))?;
    }
    for purpose in &policy.allowed_purposes {
        transaction.delete(&keyspaces.by_purpose, index_key(&purpose_key(purpose)?, id))?;
    }
    Ok(())
}

fn index_key(value: &str, id: &str) -> Vec<u8> {
    format!("{value}/{id}").into_bytes()
}

fn purpose_key(purpose: &contextdb_core::Purpose) -> Result<String> {
    serde_json::to_string(purpose).map_err(|error| GraphError::Corrupt(error.to_string()))
}

fn allocate_mapping<T: WriteTransaction>(
    transaction: &mut T,
    keyspaces: &Keyspaces,
    external_id: &str,
    next_dense: &mut u64,
    created_seq: u64,
) -> Result<()> {
    ensure_absent(transaction, &keyspaces.id_external, external_id)?;
    let dense_id = DenseId::new(*next_dense)?;
    *next_dense = next_dense
        .checked_add(1)
        .ok_or_else(|| GraphError::Invariant("dense identifier space exhausted".to_owned()))?;
    let mapping = IdMapping {
        external_id: external_id.to_owned(),
        dense_id,
        created_seq,
    };
    transaction.put(
        &keyspaces.id_external,
        external_id.as_bytes().to_vec(),
        encode(&mapping)?,
    )?;
    transaction.put(
        &keyspaces.id_dense,
        u64_key(dense_id.get()),
        external_id.as_bytes().to_vec(),
    )?;
    Ok(())
}

fn dense_for_external<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    external_id: &str,
) -> Result<DenseId> {
    snapshot
        .get(&keyspaces.id_external, external_id.as_bytes())?
        .map(|bytes| decode::<IdMapping>(&bytes))
        .transpose()?
        .map(|mapping| mapping.dense_id)
        .ok_or_else(|| not_found("dense mapping", external_id))
}

fn external_for_dense<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    dense_id: DenseId,
) -> Result<String> {
    let bytes = snapshot
        .get(&keyspaces.id_dense, &u64_key(dense_id.get()))?
        .ok_or_else(|| not_found("external mapping", &dense_id.get().to_string()))?;
    String::from_utf8(bytes).map_err(|error| GraphError::Corrupt(error.to_string()))
}

fn delta_prefix(node: DenseId) -> Vec<u8> {
    format!("{:020}/", node.get()).into_bytes()
}

fn delta_key(node: DenseId, visible_from: u64, edge_id: &str) -> Vec<u8> {
    format!("{:020}/{visible_from:020}/{edge_id}", node.get()).into_bytes()
}

fn validate_adjacency_ranges<F>(
    ranges: &[AdjacencyRange],
    edges: &[SegmentEdge],
    row_node: F,
) -> Result<()>
where
    F: Fn(&SegmentEdge) -> DenseId,
{
    let mut previous_node = None;
    let mut expected_start = 0_u64;
    for range in ranges {
        if range.start != expected_start
            || range.start >= range.end
            || previous_node.is_some_and(|previous| previous >= range.node)
        {
            return Err(GraphError::Corrupt(
                "adjacency range table is not canonical".to_owned(),
            ));
        }
        let start = usize::try_from(range.start)
            .map_err(|_| GraphError::Corrupt("adjacency offset exceeds usize".to_owned()))?;
        let end = usize::try_from(range.end)
            .map_err(|_| GraphError::Corrupt("adjacency offset exceeds usize".to_owned()))?;
        let Some(row) = edges.get(start..end) else {
            return Err(GraphError::Corrupt(
                "adjacency range exceeds edge array".to_owned(),
            ));
        };
        if row.iter().any(|edge| row_node(edge) != range.node) {
            return Err(GraphError::Corrupt(
                "adjacency row contains an edge for another node".to_owned(),
            ));
        }
        expected_start = range.end;
        previous_node = Some(range.node);
    }
    if expected_start
        != u64::try_from(edges.len())
            .map_err(|_| GraphError::Corrupt("adjacency length exceeds u64".to_owned()))?
    {
        return Err(GraphError::Corrupt(
            "adjacency range table does not cover its edge array".to_owned(),
        ));
    }
    Ok(())
}

fn register_object_id<T: WriteTransaction>(
    transaction: &mut T,
    keyspaces: &Keyspaces,
    external_id: &str,
    kind: &'static str,
) -> Result<()> {
    if let Some(bytes) = transaction.get(&keyspaces.object_kind, external_id.as_bytes())? {
        let existing: String = decode(&bytes)?;
        return Err(GraphError::Invariant(format!(
            "stable external ID {external_id} is already registered as {existing}, not {kind}"
        )));
    }
    transaction.put(
        &keyspaces.object_kind,
        external_id.as_bytes().to_vec(),
        encode(&kind)?,
    )?;
    Ok(())
}

fn policy_history_key(id: &str, visible_from: u64) -> Vec<u8> {
    format!("{id}/{visible_from:020}").into_bytes()
}

fn policy_history_id(key: &[u8]) -> Result<&str> {
    let key = std::str::from_utf8(key).map_err(|error| GraphError::Corrupt(error.to_string()))?;
    key.rsplit_once('/')
        .map(|(id, _)| id)
        .ok_or_else(|| GraphError::Corrupt("policy history key is missing a sequence".to_owned()))
}

fn policy_matches(policy: &PolicyIndexEntry, query: &PolicyIndexQuery) -> bool {
    match query {
        PolicyIndexQuery::Workspace(value) => policy.workspace_id == *value,
        PolicyIndexQuery::Subject(value) => policy.subjects.contains(value),
        PolicyIndexQuery::Scope(value) => policy.scopes.contains(value),
        PolicyIndexQuery::Owner(value) => policy.owners.contains(value),
        PolicyIndexQuery::MemorySpace(value) => policy.memory_spaces.contains(value),
        PolicyIndexQuery::Audience(value) => {
            policy.audience_purposes.contains_key(&audience_key(value))
        }
        PolicyIndexQuery::Purpose(value) => policy.allowed_purposes.contains(value),
    }
}

fn read_policy_at<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: &str,
    storage_seq: u64,
) -> Result<Option<PolicyIndexEntry>> {
    let prefix = format!("{id}/");
    let mut selected = None;
    for entry in snapshot.scan_prefix(&keyspaces.policy_history, prefix.as_bytes())? {
        let persisted: PersistedPolicy = decode(&entry.value)?;
        if persisted.visible_from <= storage_seq {
            selected = Some(persisted.value);
        }
    }
    Ok(selected)
}

fn authorize<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: &str,
    storage_seq: u64,
    principal: &ReadPrincipal,
) -> Result<()> {
    let Some(policy) = read_policy_at(snapshot, keyspaces, id, storage_seq)? else {
        return Err(GraphError::Unauthorized);
    };
    if allows(&policy, principal) {
        Ok(())
    } else {
        Err(GraphError::Unauthorized)
    }
}

fn authorize_administrative<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: &str,
    storage_seq: u64,
    principal: &ReadPrincipal,
) -> Result<()> {
    let Some(bytes) = snapshot.get(&keyspaces.administrative_policy, id.as_bytes())? else {
        return Err(GraphError::Unauthorized);
    };
    let policy: AdministrativePolicyIndex = decode(&bytes)?;
    let workspace_only = policy.subjects.is_empty() && policy.memory_spaces.is_empty();
    if policy.created_seq <= storage_seq
        && policy.workspace_id == principal.workspace_id
        && (workspace_only
            || policy.subjects.contains(&principal.subject)
            || !policy.memory_spaces.is_disjoint(&principal.memory_spaces))
    {
        Ok(())
    } else {
        Err(GraphError::Unauthorized)
    }
}

fn merged_edges_for_node<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    graph_snapshot: &GraphSnapshot,
    principal: &ReadPrincipal,
    node: DenseId,
    direction: Direction,
) -> Result<Vec<SegmentEdge>> {
    let manifest = read_manifest_at(snapshot, keyspaces, graph_snapshot.storage_seq)?;
    validate_manifest(&manifest)?;
    let mut edges = BTreeMap::<String, SegmentEdge>::new();
    if manifest.generation > 0 {
        let mut base_rows = Vec::new();
        match manifest.format_version {
            1 => {
                let bytes = snapshot
                    .get(&keyspaces.segment, &segment_key(manifest.generation))?
                    .ok_or_else(|| {
                        GraphError::Corrupt("active adjacency segment missing".to_owned())
                    })?;
                ensure_bound(
                    "legacy_segment_bytes",
                    u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    u64::try_from(LEGACY_SEGMENT_MAX_BYTES).unwrap_or(u64::MAX),
                )?;
                let segment: AdjacencySegment = decode(&bytes)?;
                validate_segment(&segment, &manifest)?;
                if matches!(direction, Direction::Outgoing | Direction::Both) {
                    base_rows.extend_from_slice(adjacency_row(
                        &segment.outgoing_ranges,
                        &segment.outgoing_edges,
                        node,
                    )?);
                }
                if matches!(direction, Direction::Incoming | Direction::Both) {
                    base_rows.extend_from_slice(adjacency_row(
                        &segment.incoming_ranges,
                        &segment.incoming_edges,
                        node,
                    )?);
                }
            }
            SEGMENT_V2_FORMAT => {
                if matches!(direction, Direction::Outgoing | Direction::Both) {
                    base_rows.extend(read_segment_v2_row(
                        snapshot,
                        keyspaces,
                        &manifest,
                        SegmentDirectionV2::Outgoing,
                        node,
                    )?);
                }
                if matches!(direction, Direction::Incoming | Direction::Both) {
                    base_rows.extend(read_segment_v2_row(
                        snapshot,
                        keyspaces,
                        &manifest,
                        SegmentDirectionV2::Incoming,
                        node,
                    )?);
                }
            }
            _ => {
                return Err(GraphError::Corrupt(
                    "unsupported adjacency segment format".to_owned(),
                ));
            }
        }
        for edge in base_rows {
            if authorize(
                snapshot,
                keyspaces,
                &edge.edge_id,
                graph_snapshot.storage_seq,
                principal,
            )
            .is_ok()
            {
                edges.insert(edge.edge_id.clone(), edge);
            }
        }
    }
    let prefix = delta_prefix(node);
    let delta_spaces = match direction {
        Direction::Outgoing => vec![&keyspaces.edge_out_delta],
        Direction::Incoming => vec![&keyspaces.edge_in_delta],
        Direction::Both => vec![&keyspaces.edge_out_delta, &keyspaces.edge_in_delta],
    };
    let mut delta_records = 0_u64;
    let mut delta_bytes = 0_u64;
    for keyspace in delta_spaces {
        let mut continuation = None;
        loop {
            let page = snapshot.scan_prefix_page(
                keyspace,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: continuation.as_deref(),
                    max_entries: SEGMENT_V2_SCAN_ENTRIES,
                    max_bytes: SEGMENT_V2_SCAN_BYTES,
                },
            )?;
            validate_scan_progress(&page, continuation.as_deref())?;
            for entry in page.entries {
                bounded_add(
                    &mut delta_records,
                    1,
                    "adjacency_read_records",
                    ADJACENCY_READ_MAX_RECORDS,
                )?;
                let record_bytes = u64::try_from(entry.key.len())
                    .ok()
                    .and_then(|key_bytes| {
                        u64::try_from(entry.value.len())
                            .ok()
                            .and_then(|value_bytes| key_bytes.checked_add(value_bytes))
                    })
                    .unwrap_or(u64::MAX);
                bounded_add(
                    &mut delta_bytes,
                    record_bytes,
                    "adjacency_read_bytes",
                    ADJACENCY_READ_MAX_BYTES,
                )?;
                let delta_seq = edge_delta_seq(&entry.key)?;
                if delta_seq <= manifest.built_through_seq || delta_seq > graph_snapshot.storage_seq
                {
                    continue;
                }
                let edge: SegmentEdge = decode(&entry.value)?;
                if authorize(
                    snapshot,
                    keyspaces,
                    &edge.edge_id,
                    graph_snapshot.storage_seq,
                    principal,
                )
                .is_ok()
                {
                    let revision: EdgeRevision = get_revision(
                        snapshot,
                        &keyspaces.edge_revision,
                        &edge.edge_id,
                        graph_snapshot.storage_seq,
                        graph_snapshot.semantic_seq,
                        "edge revision",
                    )?;
                    if revision.epistemic.lifecycle == LifecycleState::Active {
                        edges.insert(edge.edge_id.clone(), edge);
                    } else {
                        edges.remove(&edge.edge_id);
                    }
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            continuation = Some(next);
        }
    }
    ensure_bound(
        "adjacency_materialized_edges",
        u64::try_from(edges.len()).unwrap_or(u64::MAX),
        ADJACENCY_READ_MAX_RECORDS,
    )?;
    Ok(edges.into_values().collect())
}

fn adjacency_row<'a>(
    ranges: &[AdjacencyRange],
    edges: &'a [SegmentEdge],
    node: DenseId,
) -> Result<&'a [SegmentEdge]> {
    let Ok(index) = ranges.binary_search_by_key(&node, |range| range.node) else {
        return Ok(&[]);
    };
    let range = ranges[index];
    let start = usize::try_from(range.start)
        .map_err(|_| GraphError::Corrupt("adjacency range start exceeds usize".to_owned()))?;
    let end = usize::try_from(range.end)
        .map_err(|_| GraphError::Corrupt("adjacency range end exceeds usize".to_owned()))?;
    edges
        .get(start..end)
        .ok_or_else(|| GraphError::Corrupt("adjacency range exceeds edge array".to_owned()))
}

fn read_segment_v2_row<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    manifest: &SegmentManifest,
    direction: SegmentDirectionV2,
    node: DenseId,
) -> Result<Vec<SegmentEdge>> {
    validate_manifest(manifest)?;
    let leaf_index = node
        .get()
        .checked_sub(1)
        .and_then(|index| index.checked_mul(2))
        .and_then(|index| index.checked_add(u64::from(direction.key_byte())))
        .ok_or_else(|| GraphError::Corrupt("paged adjacency leaf index exhausted".to_owned()))?;
    if leaf_index >= manifest.row_count {
        // Nodes created after `built_through_seq` are represented exclusively by deltas until
        // the next compaction. Every node that existed at the cutoff still has a mandatory row.
        return Ok(Vec::new());
    }
    let row_bytes = snapshot
        .get(
            &keyspaces.segment_v2,
            &segment_v2_row_key(manifest.generation, direction, node),
        )?
        .ok_or_else(|| GraphError::Corrupt("paged adjacency row manifest missing".to_owned()))?;
    let row: AdjacencyRowManifestV2 = decode(&row_bytes)?;
    if row.format_version != SEGMENT_V2_FORMAT
        || row.generation != manifest.generation
        || row.built_through_seq != manifest.built_through_seq
        || row.direction != direction
        || row.node != node
    {
        return Err(GraphError::Corrupt(
            "paged adjacency row manifest identity mismatch".to_owned(),
        ));
    }
    ensure_bound(
        "segment_v2_row_edges",
        row.edge_count,
        SEGMENT_V2_MAX_ROW_EDGES,
    )?;
    ensure_bound(
        "segment_v2_row_bytes",
        row.edge_bytes,
        SEGMENT_V2_MAX_ROW_BYTES,
    )?;
    let scanned = scan_segment_v2_row(
        snapshot,
        keyspaces,
        manifest.generation,
        direction,
        node,
        true,
    )?;
    if (scanned.edge_count, scanned.edge_bytes, &scanned.edge_digest)
        != (row.edge_count, row.edge_bytes, &row.edge_digest)
    {
        return Err(GraphError::Corrupt(
            "paged adjacency row content disagrees with its manifest".to_owned(),
        ));
    }
    authenticate_segment_v2_row(
        snapshot,
        keyspaces,
        manifest,
        leaf_index,
        segment_v2_leaf_hash(&row_bytes),
    )?;
    Ok(scanned.edges)
}

fn authenticate_segment_v2_row<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    manifest: &SegmentManifest,
    mut index: u64,
    mut actual: blake3::Hash,
) -> Result<()> {
    let stored_leaf = read_segment_v2_hash(snapshot, keyspaces, manifest.generation, 0, index)?;
    if stored_leaf != actual {
        return Err(GraphError::Corrupt(
            "paged adjacency row digest disagrees with its Merkle leaf".to_owned(),
        ));
    }
    let mut level = 0_u16;
    let mut width = manifest.row_count;
    while width > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            index.saturating_add(1)
        } else {
            index - 1
        };
        let sibling = if sibling_index < width {
            read_segment_v2_hash(
                snapshot,
                keyspaces,
                manifest.generation,
                level,
                sibling_index,
            )?
        } else {
            actual
        };
        actual = if index.is_multiple_of(2) {
            segment_v2_parent_hash(actual, sibling)
        } else {
            segment_v2_parent_hash(sibling, actual)
        };
        index /= 2;
        width = width.div_ceil(2);
        level = level.checked_add(1).ok_or_else(|| {
            GraphError::Corrupt("paged adjacency Merkle depth exhausted".to_owned())
        })?;
        let stored_parent =
            read_segment_v2_hash(snapshot, keyspaces, manifest.generation, level, index)?;
        if stored_parent != actual {
            return Err(GraphError::Corrupt(
                "paged adjacency Merkle path is inconsistent".to_owned(),
            ));
        }
    }
    let segment_root = segment_v2_manifest_root(
        manifest.generation,
        manifest.built_through_seq,
        manifest.row_count,
        manifest.edge_count,
        manifest.edge_bytes,
        actual,
    );
    if segment_root.to_hex().as_str() != manifest.segment_digest {
        return Err(GraphError::Corrupt(
            "paged adjacency row does not authenticate to the active root".to_owned(),
        ));
    }
    Ok(())
}

fn validate_manifest(manifest: &SegmentManifest) -> Result<()> {
    if manifest.generation == 0 {
        if !matches!(manifest.format_version, 1 | SEGMENT_V2_FORMAT)
            || manifest.built_through_seq != 0
            || !manifest.segment_digest.is_empty()
            || manifest.row_count != 0
            || manifest.edge_count != 0
            || manifest.edge_bytes != 0
        {
            return Err(GraphError::Corrupt(
                "empty adjacency manifest is not canonical".to_owned(),
            ));
        }
        return Ok(());
    }
    match manifest.format_version {
        1 => {
            if manifest.segment_digest.len() != 64
                || !manifest
                    .segment_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || manifest.row_count != 0
                || manifest.edge_count != 0
                || manifest.edge_bytes != 0
            {
                return Err(GraphError::Corrupt(
                    "legacy adjacency manifest is not canonical".to_owned(),
                ));
            }
        }
        SEGMENT_V2_FORMAT => {
            ensure_bound("segment_v2_rows", manifest.row_count, SEGMENT_V2_MAX_ROWS)?;
            ensure_bound(
                "segment_v2_edges",
                manifest.edge_count,
                SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
            )?;
            ensure_bound(
                "segment_v2_edge_bytes",
                manifest.edge_bytes,
                SEGMENT_V2_MAX_EDGE_BYTES,
            )?;
            if !manifest.row_count.is_multiple_of(2)
                || manifest.segment_digest.len() != 64
                || !manifest
                    .segment_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || (manifest.row_count == 0
                    && (manifest.edge_count != 0 || manifest.edge_bytes != 0))
            {
                return Err(GraphError::Corrupt(
                    "paged adjacency manifest is not canonical".to_owned(),
                ));
            }
        }
        _ => {
            return Err(GraphError::Corrupt(
                "unsupported adjacency manifest format".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_segment(segment: &AdjacencySegment, manifest: &SegmentManifest) -> Result<()> {
    ensure_bound(
        "legacy_segment_edges",
        u64::try_from(segment.outgoing_edges.len())
            .ok()
            .and_then(|outgoing| {
                u64::try_from(segment.incoming_edges.len())
                    .ok()
                    .and_then(|incoming| outgoing.checked_add(incoming))
            })
            .unwrap_or(u64::MAX),
        ADJACENCY_READ_MAX_RECORDS,
    )?;
    #[derive(Serialize)]
    struct SegmentDigest<'a> {
        format_version: u16,
        generation: u64,
        built_through_seq: u64,
        outgoing_ranges: &'a [AdjacencyRange],
        outgoing_edges: &'a [SegmentEdge],
        incoming_ranges: &'a [AdjacencyRange],
        incoming_edges: &'a [SegmentEdge],
    }
    let actual = digest(&SegmentDigest {
        format_version: segment.format_version,
        generation: segment.generation,
        built_through_seq: segment.built_through_seq,
        outgoing_ranges: &segment.outgoing_ranges,
        outgoing_edges: &segment.outgoing_edges,
        incoming_ranges: &segment.incoming_ranges,
        incoming_edges: &segment.incoming_edges,
    })?;
    if manifest.format_version != 1
        || segment.format_version != 1
        || segment.generation != manifest.generation
        || segment.built_through_seq != manifest.built_through_seq
        || segment.digest != manifest.segment_digest
        || actual != segment.digest
    {
        return Err(GraphError::Corrupt(
            "adjacency segment/manifest integrity mismatch".to_owned(),
        ));
    }
    validate_adjacency_ranges(&segment.outgoing_ranges, &segment.outgoing_edges, |edge| {
        edge.source
    })?;
    validate_adjacency_ranges(&segment.incoming_ranges, &segment.incoming_edges, |edge| {
        edge.target
    })?;
    Ok(())
}

fn get_revision<S, T>(
    snapshot: &S,
    keyspace: &contextdb_storage::Keyspace,
    id: &str,
    storage_seq: u64,
    semantic_seq: CommitSeq,
    kind: &'static str,
) -> Result<T>
where
    S: ReadSnapshot,
    T: serde::de::DeserializeOwned + TransactionRevision,
{
    let prefix = format!("{id}/");
    let entries = snapshot.scan_prefix(keyspace, prefix.as_bytes())?;
    let mut selected = None;
    for entry in entries {
        let revision: PersistedRevision<T> = decode(&entry.value)?;
        if revision.visible_from <= storage_seq
            && revision.visible_to.is_none_or(|end| storage_seq < end)
            && revision.value.transaction_time().contains(semantic_seq)
        {
            selected = Some(revision.value);
        }
    }
    selected.ok_or_else(|| not_found(kind, id))
}

fn get_revision_at<S, T, F>(
    snapshot: &S,
    keyspace: &contextdb_storage::Keyspace,
    id: &str,
    instant: BitemporalInstant,
    valid_time: F,
    kind: &'static str,
) -> Result<T>
where
    S: ReadSnapshot,
    T: serde::de::DeserializeOwned + TransactionRevision,
    F: Fn(&T) -> contextdb_core::TimeRange,
{
    let prefix = format!("{id}/");
    let entries = snapshot.scan_prefix(keyspace, prefix.as_bytes())?;
    let mut selected = None;
    for entry in entries {
        let revision: PersistedRevision<T> = decode(&entry.value)?;
        if revision.visible_from <= instant.storage_seq
            && revision
                .visible_to
                .is_none_or(|end| instant.storage_seq < end)
            && revision
                .value
                .transaction_time()
                .contains(instant.semantic_seq)
            && valid_time(&revision.value).contains(instant.valid_at)
        {
            selected = Some(revision.value);
        }
    }
    selected.ok_or_else(|| not_found(kind, id))
}

fn get_identity<S, T, I>(
    snapshot: &S,
    keyspace: &contextdb_storage::Keyspace,
    id: I,
    kind: &'static str,
) -> Result<T>
where
    S: ReadSnapshot,
    T: serde::de::DeserializeOwned,
    I: std::fmt::Display,
{
    let id = id.to_string();
    snapshot
        .get(keyspace, id.as_bytes())?
        .map(|bytes| decode(&bytes))
        .transpose()?
        .ok_or_else(|| not_found(kind, &id))
}

fn require_identity<S: ReadSnapshot, I: std::fmt::Display>(
    snapshot: &S,
    keyspace: &contextdb_storage::Keyspace,
    id: I,
) -> Result<()> {
    let id = id.to_string();
    if snapshot.get(keyspace, id.as_bytes())?.is_some() {
        Ok(())
    } else {
        Err(not_found("stable identity", &id))
    }
}

fn ensure_absent<S: ReadSnapshot>(
    snapshot: &S,
    keyspace: &contextdb_storage::Keyspace,
    id: &str,
) -> Result<()> {
    if snapshot.get(keyspace, id.as_bytes())?.is_some() {
        Err(GraphError::Invariant(format!(
            "stable external ID {id} cannot be reused"
        )))
    } else {
        Ok(())
    }
}

fn workspace_for_node<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: NodeId,
) -> Result<WorkspaceId> {
    Ok(get_identity::<_, Node, _>(snapshot, &keyspaces.node_identity, id, "node")?.workspace_id)
}

fn workspace_for_claim<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: contextdb_core::ClaimId,
) -> Result<WorkspaceId> {
    Ok(get_identity::<_, Claim, _>(snapshot, &keyspaces.claim_identity, id, "claim")?.workspace_id)
}

fn workspace_for_conflict<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: contextdb_core::ConflictSetId,
) -> Result<WorkspaceId> {
    Ok(get_identity::<_, ConflictSet, _>(
        snapshot,
        &keyspaces.conflict_identity,
        id,
        "conflict set",
    )?
    .workspace_id)
}

fn edge_identity<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: contextdb_core::EdgeId,
) -> Result<Edge> {
    get_identity(snapshot, &keyspaces.edge_identity, id, "edge")
}

fn workspace_from_envelope(envelope: &contextdb_core::SemanticEnvelope) -> Result<WorkspaceId> {
    envelope
        .scopes
        .iter()
        .find(|scope| scope.kind == contextdb_core::ScopeKind::Workspace)
        .and_then(|scope| WorkspaceId::from_uuid(scope.id.as_uuid()).ok())
        .ok_or_else(|| {
            GraphError::Invariant("artifact envelope requires a workspace scope".to_owned())
        })
}

fn validate_envelope_references<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    envelope: &contextdb_core::SemanticEnvelope,
    expected: WorkspaceId,
) -> Result<()> {
    let actual = workspace_from_envelope(envelope)?;
    ensure_workspace("semantic envelope", expected, actual)?;
    for scope in &envelope.scopes {
        if scope.kind == contextdb_core::ScopeKind::MemorySpace {
            let space_id = MemorySpaceId::from_uuid(scope.id.as_uuid())
                .map_err(|error| GraphError::Invariant(error.to_string()))?;
            require_space_workspace(snapshot, keyspaces, space_id, expected)?;
        }
    }
    require_subject_workspace(snapshot, keyspaces, envelope.perspective.knower, expected)?;
    if let Some(experiencer) = envelope.perspective.experiencer {
        require_subject_workspace(snapshot, keyspaces, experiencer, expected)?;
    }
    for owner in &envelope.ownership.owners {
        require_subject_workspace(snapshot, keyspaces, *owner, expected)?;
    }
    for grant in &envelope.ownership.audience_grants {
        match grant.audience {
            contextdb_core::Audience::Subject { id } | contextdb_core::Audience::Group { id } => {
                require_subject_workspace(snapshot, keyspaces, id, expected)?;
            }
            contextdb_core::Audience::MemorySpace { id } => {
                require_space_workspace(snapshot, keyspaces, id, expected)?;
            }
            contextdb_core::Audience::Public | contextdb_core::Audience::Owner => {}
        }
    }
    Ok(())
}

fn require_subject_workspace<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: MemorySubjectId,
    expected: WorkspaceId,
) -> Result<()> {
    let subject: MemorySubject = get_identity(
        snapshot,
        &keyspaces.subject_identity,
        id,
        "envelope subject",
    )?;
    ensure_workspace("semantic envelope subject", expected, subject.workspace_id)
}

fn require_space_workspace<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    id: MemorySpaceId,
    expected: WorkspaceId,
) -> Result<()> {
    let space: MemorySpace = get_identity(
        snapshot,
        &keyspaces.space_identity,
        id,
        "envelope memory space",
    )?;
    ensure_workspace(
        "semantic envelope memory space",
        expected,
        space.workspace_id,
    )
}

fn read_manifest<S: ReadSnapshot>(snapshot: &S, keyspaces: &Keyspaces) -> Result<SegmentManifest> {
    snapshot
        .get(&keyspaces.meta, ACTIVE_MANIFEST)?
        .map(|bytes| decode(&bytes))
        .transpose()
        .map(|manifest| {
            manifest.unwrap_or(SegmentManifest {
                format_version: SEGMENT_V2_FORMAT,
                generation: 0,
                built_through_seq: 0,
                segment_digest: String::new(),
                row_count: 0,
                edge_count: 0,
                edge_bytes: 0,
            })
        })
}

fn read_manifest_at<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    storage_seq: u64,
) -> Result<SegmentManifest> {
    let mut selected = None;
    let mut continuation = None;
    let mut count = 0_u64;
    let mut previous_generation = None;
    loop {
        let page = snapshot.scan_prefix_page(
            &keyspaces.manifest_history,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: SEGMENT_V2_SCAN_ENTRIES,
                max_bytes: SEGMENT_V2_SCAN_BYTES,
            },
        )?;
        validate_scan_progress(&page, continuation.as_deref())?;
        for entry in page.entries {
            bounded_add(
                &mut count,
                1,
                "adjacency_manifest_history_entries",
                PRUNE_MAX_HISTORY_ENTRIES,
            )?;
            let switch_seq = decode_u64_key(&entry.key)?;
            if switch_seq > snapshot.sequence() {
                return Err(GraphError::Corrupt(
                    "adjacency manifest switch exceeds the storage head".to_owned(),
                ));
            }
            if switch_seq > storage_seq {
                return selected.map_or_else(
                    || {
                        if snapshot.sequence() == storage_seq {
                            read_manifest(snapshot, keyspaces)
                        } else {
                            Ok(empty_segment_manifest())
                        }
                    },
                    Ok,
                );
            }
            let manifest: SegmentManifest = decode(&entry.value)?;
            validate_manifest(&manifest)?;
            if manifest.generation == 0
                || manifest.built_through_seq >= switch_seq
                || previous_generation.is_some_and(|generation: u64| {
                    generation.checked_add(1) != Some(manifest.generation)
                })
            {
                return Err(GraphError::Corrupt(
                    "adjacency manifest history is not canonical".to_owned(),
                ));
            }
            previous_generation = Some(manifest.generation);
            selected = Some(manifest);
        }
        let Some(next) = page.continuation else {
            break;
        };
        continuation = Some(next);
    }
    if let Some(manifest) = selected {
        Ok(manifest)
    } else if snapshot.sequence() == storage_seq {
        read_manifest(snapshot, keyspaces)
    } else {
        Ok(empty_segment_manifest())
    }
}

fn empty_segment_manifest() -> SegmentManifest {
    SegmentManifest {
        format_version: SEGMENT_V2_FORMAT,
        generation: 0,
        built_through_seq: 0,
        segment_digest: String::new(),
        row_count: 0,
        edge_count: 0,
        edge_bytes: 0,
    }
}

fn read_semantic_at<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
    storage_seq: u64,
) -> Result<CommitSeq> {
    let mut selected = CommitSeq::GENESIS;
    for entry in snapshot.scan_prefix(&keyspaces.semantic_snapshot, b"")? {
        let semantic_seq = CommitSeq::new(decode_u64_key(&entry.key)?);
        let physical_seq: u64 = decode(&entry.value)?;
        if physical_seq <= storage_seq && semantic_seq > selected {
            selected = semantic_seq;
        }
    }
    Ok(selected)
}

fn read_u64<S: ReadSnapshot>(
    snapshot: &S,
    keyspace: &contextdb_storage::Keyspace,
    key: &[u8],
) -> Result<Option<u64>> {
    snapshot
        .get(keyspace, key)?
        .map(|bytes| decode(&bytes))
        .transpose()
}

fn read_semantic_watermark<S: ReadSnapshot>(
    snapshot: &S,
    keyspaces: &Keyspaces,
) -> Result<CommitSeq> {
    snapshot
        .get(&keyspaces.meta, SEMANTIC_WATERMARK)?
        .map(|bytes| decode(&bytes))
        .transpose()
        .map(|value| value.unwrap_or(CommitSeq::GENESIS))
}

fn validate_publication_time(
    mutation: &contextdb_core::SemanticMutationSet,
    commit_seq: CommitSeq,
) -> Result<()> {
    if mutation.base_snapshot.commit_seq.checked_next() != Some(commit_seq) {
        return Err(GraphError::Invariant(
            "publication commit must immediately follow its declared base snapshot".to_owned(),
        ));
    }
    let valid = mutation
        .node_revisions
        .iter()
        .all(|revision| revision.transaction_time().start == commit_seq)
        && mutation
            .claim_revisions
            .iter()
            .all(|revision| revision.transaction_time().start == commit_seq)
        && mutation
            .edge_revisions
            .iter()
            .all(|revision| revision.transaction_time().start == commit_seq)
        && mutation
            .conflict_revisions
            .iter()
            .all(|revision| revision.transaction_time().start == commit_seq);
    if valid {
        Ok(())
    } else {
        Err(GraphError::Invariant(
            "projected graph revisions must begin at the publication commit".to_owned(),
        ))
    }
}

const fn maintenance_kind(operation: &contextdb_core::MaintenanceOperation) -> &'static str {
    match operation {
        contextdb_core::MaintenanceOperation::PolicyRevision { .. } => "policy_revision",
        contextdb_core::MaintenanceOperation::HierarchyPublication { .. } => {
            "hierarchy_publication"
        }
        contextdb_core::MaintenanceOperation::SummaryRevision { .. } => "summary_revision",
        contextdb_core::MaintenanceOperation::MergeSplitDecision { .. } => "merge_split_decision",
        contextdb_core::MaintenanceOperation::DeletionPropagation { .. } => "deletion_propagation",
        contextdb_core::MaintenanceOperation::CompactionMetadata { .. } => "compaction_metadata",
        contextdb_core::MaintenanceOperation::IndexGenerationSwitch { .. } => {
            "index_generation_switch"
        }
    }
}

fn indexed_id<'a>(key: &'a [u8], prefix: &str) -> Result<&'a str> {
    let key = std::str::from_utf8(key).map_err(|error| GraphError::Corrupt(error.to_string()))?;
    key.strip_prefix(prefix)
        .ok_or_else(|| GraphError::Corrupt("administrative index prefix mismatch".to_owned()))
}

fn edge_delta_seq(key: &[u8]) -> Result<u64> {
    let value = std::str::from_utf8(key).map_err(|error| GraphError::Corrupt(error.to_string()))?;
    let mut parts = value.split('/');
    let _node = parts.next();
    parts
        .next()
        .ok_or_else(|| GraphError::Corrupt("edge delta sequence missing".to_owned()))?
        .parse()
        .map_err(|error| GraphError::Corrupt(format!("invalid edge delta sequence: {error}")))
}

fn segment_key(generation: u64) -> Vec<u8> {
    let mut key = BASE_SEGMENT_KEY.to_vec();
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn segment_v2_generation_prefix(generation: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(9);
    key.push(b'g');
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn segment_v2_edge_prefix(
    generation: u64,
    direction: SegmentDirectionV2,
    node: DenseId,
) -> Vec<u8> {
    let mut key = segment_v2_generation_prefix(generation);
    key.push(b'e');
    key.push(direction.key_byte());
    key.extend_from_slice(&node.get().to_be_bytes());
    key
}

fn segment_v2_edge_key(
    generation: u64,
    direction: SegmentDirectionV2,
    edge: &SegmentEdge,
) -> Result<Vec<u8>> {
    let mut key = segment_v2_edge_prefix(generation, direction, direction.row_node(edge));
    key.extend_from_slice(&direction.other_node(edge).get().to_be_bytes());
    push_segment_v2_key_component(&mut key, &edge.edge_type)?;
    push_segment_v2_key_component(&mut key, &edge.edge_id)?;
    Ok(key)
}

fn segment_v2_row_key(generation: u64, direction: SegmentDirectionV2, node: DenseId) -> Vec<u8> {
    let mut key = segment_v2_generation_prefix(generation);
    key.push(b'r');
    key.push(direction.key_byte());
    key.extend_from_slice(&node.get().to_be_bytes());
    key
}

fn segment_v2_tree_key(generation: u64, level: u16, index: u64) -> Vec<u8> {
    let mut key = segment_v2_generation_prefix(generation);
    key.push(b't');
    key.extend_from_slice(&level.to_be_bytes());
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn push_segment_v2_key_component(key: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| GraphError::ResourceExhausted {
        resource: "segment_v2_key_component_bytes",
        limit: u64::from(u16::MAX),
        required: u64::try_from(value.len()).unwrap_or(u64::MAX),
    })?;
    key.extend_from_slice(&length.to_be_bytes());
    key.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_u64_key(key: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = key
        .try_into()
        .map_err(|_| GraphError::Corrupt("expected an eight-byte integer key".to_owned()))?;
    Ok(u64::from_be_bytes(bytes))
}

fn not_found(kind: &'static str, id: &str) -> GraphError {
    GraphError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use contextdb_storage::Entry;

    use super::{
        AdjacencyPrunePhysicalTotals, PRUNE_MAX_GENERATIONS, PRUNE_MAX_PHYSICAL_BYTES,
        PRUNE_MAX_PHYSICAL_RECORDS, SEGMENT_V2_MAX_EDGE_BYTES, SEGMENT_V2_MAX_MERKLE_RECORDS,
        SEGMENT_V2_MAX_PHYSICAL_RECORDS_PER_GENERATION, SEGMENT_V2_MAX_ROWS, bounded_add,
        record_adjacency_prune_physical_entry, segment_v2_root_level, validate_manifest,
    };
    use crate::{GraphError, SEGMENT_V2_MAX_DIRECTIONAL_RECORDS, SegmentManifest};

    #[test]
    fn certification_directional_cap_is_arithmetic_only_not_scale_evidence() {
        assert_eq!(SEGMENT_V2_MAX_DIRECTIONAL_RECORDS, 200_000_000);
        assert_eq!(SEGMENT_V2_MAX_ROWS, 20_000_000);
        assert_eq!(SEGMENT_V2_MAX_EDGE_BYTES, 64 * 1024 * 1024 * 1024);
        assert_eq!(segment_v2_root_level(SEGMENT_V2_MAX_ROWS), Ok(25));

        let mut count = SEGMENT_V2_MAX_DIRECTIONAL_RECORDS - 1;
        bounded_add(
            &mut count,
            1,
            "segment_v2_edges",
            SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
        )
        .expect("certification directional floor fits the capacity contract");
        assert_eq!(count, SEGMENT_V2_MAX_DIRECTIONAL_RECORDS);

        let mut manifest = SegmentManifest {
            format_version: 2,
            generation: 1,
            built_through_seq: 1,
            segment_digest: "00".repeat(32),
            row_count: SEGMENT_V2_MAX_ROWS,
            edge_count: SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
            edge_bytes: SEGMENT_V2_MAX_EDGE_BYTES,
        };
        validate_manifest(&manifest).expect("all independent generation caps are inclusive");

        assert!(matches!(
            bounded_add(
                &mut count,
                1,
                "segment_v2_edges",
                SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
            ),
            Err(GraphError::ResourceExhausted {
                resource: "segment_v2_edges",
                limit: SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
                required,
            }) if required == SEGMENT_V2_MAX_DIRECTIONAL_RECORDS + 1
        ));
        manifest.edge_count = SEGMENT_V2_MAX_DIRECTIONAL_RECORDS + 1;
        assert!(matches!(
            validate_manifest(&manifest),
            Err(GraphError::ResourceExhausted {
                resource: "segment_v2_edges",
                limit: SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
                required,
            }) if required == SEGMENT_V2_MAX_DIRECTIONAL_RECORDS + 1
        ));
    }

    #[test]
    fn prune_record_cap_is_checked_from_two_full_v2_generations() {
        assert_eq!(SEGMENT_V2_MAX_MERKLE_RECORDS, 40_000_009);
        assert_eq!(SEGMENT_V2_MAX_PHYSICAL_RECORDS_PER_GENERATION, 260_000_009);
        assert_eq!(
            PRUNE_MAX_PHYSICAL_RECORDS,
            SEGMENT_V2_MAX_PHYSICAL_RECORDS_PER_GENERATION * 2 + PRUNE_MAX_GENERATIONS
        );
        assert_eq!(PRUNE_MAX_PHYSICAL_RECORDS, 521_000_018);
        assert_eq!(PRUNE_MAX_PHYSICAL_BYTES, 128 * 1024 * 1024 * 1024);
    }

    #[test]
    fn adjacency_prune_physical_caps_are_shared_across_keyspaces() {
        let one_byte = Entry {
            key: vec![1],
            value: Vec::new(),
        };
        let mut totals = AdjacencyPrunePhysicalTotals {
            records: PRUNE_MAX_PHYSICAL_RECORDS - 1,
            bytes: PRUNE_MAX_PHYSICAL_BYTES - 1,
        };
        record_adjacency_prune_physical_entry(&mut totals, &one_byte).expect("last aggregate slot");
        assert_eq!(totals.records, PRUNE_MAX_PHYSICAL_RECORDS);
        assert_eq!(totals.bytes, PRUNE_MAX_PHYSICAL_BYTES);
        assert!(matches!(
            record_adjacency_prune_physical_entry(&mut totals, &one_byte),
            Err(GraphError::ResourceExhausted {
                resource: "adjacency_prune_physical_records",
                limit: PRUNE_MAX_PHYSICAL_RECORDS,
                required,
            }) if required == PRUNE_MAX_PHYSICAL_RECORDS + 1
        ));
    }
}
