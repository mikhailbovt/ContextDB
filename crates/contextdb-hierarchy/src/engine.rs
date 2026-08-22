use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use contextdb_core::{
    CommitSeq, ContentDigest, HierarchyViewId, LineageNode, NodeId, SnapshotRef, Validate,
    WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::query::{
    BeamTraversalRequest, BeamTraversalResult, FreshnessRequirement, GenerationFreshness,
    HierarchyRoute, RouteMaterialization, RouteRequest, TraversalHit,
};
use crate::types::validate_text;
use crate::{
    AssignmentPolicy, AuthorizationSnapshot, BranchStatistics, Confidence, DeletionRecord,
    GenerationNumber, HierarchyEpoch, HierarchyError, HierarchyGeneration, HierarchyGenerationRef,
    HierarchyInvalidation, HierarchyItemId, HierarchyKind, HierarchyMembership, HierarchyNode,
    HierarchyProfile, HierarchyProvenance, HierarchySnapshotSelector, InvalidationReason,
    MembershipRole, PolicyPartition, Result, ValidatedHierarchyProposal,
};

/// Backend-neutral mutation and snapshot boundary for hierarchy repositories.
pub trait HierarchyRepository: Send + Sync {
    /// Immutable query snapshot returned by this repository.
    type Snapshot: HierarchyRead;

    /// Atomically publishes one validated side-by-side generation.
    fn publish(&self, proposal: &ValidatedHierarchyProposal) -> Result<HierarchyGenerationRef>;

    /// Marks a view dirty without mutating its active immutable generation.
    fn invalidate(&self, invalidation: HierarchyInvalidation) -> Result<HierarchyEpoch>;

    /// Installs an immediate deletion barrier and marks dependent views dirty.
    fn record_deletions(&self, deletion: DeletionRecord) -> Result<HierarchyEpoch>;

    /// Opens a stable hierarchy catalog snapshot.
    fn snapshot(&self, selector: HierarchySnapshotSelector) -> Result<Self::Snapshot>;
}

/// Backend-neutral immutable hierarchy query surface.
pub trait HierarchyRead: Clone + Send + Sync {
    /// Hierarchy catalog epoch represented by this snapshot.
    fn epoch(&self) -> HierarchyEpoch;

    /// Resolves one navigation item only after policy, deletion, validity, and
    /// freshness checks.
    fn resolve_node(
        &self,
        view_id: HierarchyViewId,
        item: HierarchyItemId,
        semantic_snapshot: SnapshotRef,
        domain_time: Option<contextdb_core::TimestampMicros>,
        freshness: FreshnessRequirement,
        authorization: &AuthorizationSnapshot,
    ) -> Result<(HierarchyNode, GenerationFreshness)>;

    /// Returns deterministic content-free branch statistics without exposing
    /// unauthorized generation contents or counts.
    fn branch_statistics(
        &self,
        view_id: HierarchyViewId,
        item: HierarchyItemId,
        semantic_snapshot: SnapshotRef,
        freshness: FreshnessRequirement,
        authorization: &AuthorizationSnapshot,
    ) -> Result<(BranchStatistics, GenerationFreshness)>;

    /// Materializes bounded, policy-filtered root-to-target alternatives.
    fn materialize_routes(
        &self,
        request: &RouteRequest,
        authorization: &AuthorizationSnapshot,
    ) -> Result<RouteMaterialization>;

    /// Performs deterministic policy-filtered beam traversal.
    fn beam_traverse(
        &self,
        request: &BeamTraversalRequest,
        authorization: &AuthorizationSnapshot,
    ) -> Result<BeamTraversalResult>;

    /// Rejects cached routes after generation, authorization, validity, or
    /// deletion state changes.
    fn validate_route(
        &self,
        route: &HierarchyRoute,
        authorization: &AuthorizationSnapshot,
    ) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
struct ViewState {
    active: Option<GenerationNumber>,
    generations: BTreeMap<GenerationNumber, Arc<HierarchyGeneration>>,
    navigation: BTreeMap<GenerationNumber, Arc<NavigationIndex>>,
    dirty_through: Option<CommitSeq>,
    invalidations: Vec<HierarchyInvalidation>,
}

#[derive(Clone, Debug, Default)]
struct NavigationIndex {
    children: BTreeMap<HierarchyItemId, Vec<usize>>,
}

impl NavigationIndex {
    fn build(generation: &HierarchyGeneration) -> Self {
        let mut children: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (index, membership) in generation.memberships.iter().enumerate() {
            children.entry(membership.parent).or_default().push(index);
        }
        for indexes in children.values_mut() {
            indexes.sort_by(|left, right| {
                let left = &generation.memberships[*left];
                let right = &generation.memberships[*right];
                membership_order(left, right).then_with(|| left.child.cmp(&right.child))
            });
        }
        Self { children }
    }
}

#[derive(Clone, Debug)]
struct Catalog {
    epoch: HierarchyEpoch,
    views: BTreeMap<HierarchyViewId, ViewState>,
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            epoch: HierarchyEpoch::GENESIS,
            views: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct RepositoryState {
    current: Arc<Catalog>,
    history: BTreeMap<HierarchyEpoch, Arc<Catalog>>,
}

impl Default for RepositoryState {
    fn default() -> Self {
        let catalog = Arc::new(Catalog::default());
        Self {
            current: Arc::clone(&catalog),
            history: BTreeMap::from([(HierarchyEpoch::GENESIS, catalog)]),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct DeletionRegistry {
    epoch: HierarchyEpoch,
    deleted_nodes: BTreeMap<(WorkspaceId, NodeId), CommitSeq>,
    deleted_lineage: BTreeMap<(WorkspaceId, LineageNode), CommitSeq>,
}

/// Self-verifying, backend-neutral snapshot of all retained hierarchy catalog
/// epochs and the live deletion barrier. Persistent adapters may atomically
/// store this bundle without gaining access to hierarchy semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentHierarchyBundle {
    /// Portable hierarchy-state format version.
    pub schema_version: u16,
    /// Latest hierarchy catalog epoch in the payload.
    pub current_epoch: HierarchyEpoch,
    /// BLAKE3 digest of the canonical payload bytes.
    pub payload_digest: [u8; 32],
    /// Canonical JSON payload. This contains derived hierarchy metadata, not
    /// primary semantic content outside the generation records themselves.
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HierarchyStatePayload {
    schema_version: u16,
    current_epoch: HierarchyEpoch,
    catalogs: Vec<CatalogPayload>,
    deletion_epoch: HierarchyEpoch,
    deleted_nodes: Vec<DeletedNodePayload>,
    deleted_lineage: Vec<DeletedLineagePayload>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogPayload {
    epoch: HierarchyEpoch,
    views: Vec<ViewPayload>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewPayload {
    view_id: HierarchyViewId,
    active: Option<GenerationNumber>,
    generations: Vec<GenerationPayload>,
    dirty_through: Option<CommitSeq>,
    invalidations: Vec<HierarchyInvalidation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilePayload {
    id: HierarchyViewId,
    workspace_id: WorkspaceId,
    kind: HierarchyKind,
    name: String,
    profile_revision: u64,
    partitions: Vec<PolicyPartition>,
    assignment: AssignmentPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemStatisticsPayload {
    item: HierarchyItemId,
    statistics: BranchStatistics,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationPayload {
    profile: ProfilePayload,
    generation: GenerationNumber,
    built_from: SnapshotRef,
    published_epoch: HierarchyEpoch,
    roots: Vec<HierarchyItemId>,
    nodes: Vec<HierarchyNode>,
    memberships: Vec<HierarchyMembership>,
    statistics: Vec<ItemStatisticsPayload>,
    manifest_digest: ContentDigest,
    build_provenance: HierarchyProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletedNodePayload {
    workspace_id: WorkspaceId,
    node_id: NodeId,
    effective_at: CommitSeq,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletedLineagePayload {
    workspace_id: WorkspaceId,
    dependency: LineageNode,
    effective_at: CommitSeq,
}

impl From<&HierarchyGeneration> for GenerationPayload {
    fn from(generation: &HierarchyGeneration) -> Self {
        Self {
            profile: ProfilePayload {
                id: generation.profile.id,
                workspace_id: generation.profile.workspace_id,
                kind: generation.profile.kind.clone(),
                name: generation.profile.name.clone(),
                profile_revision: generation.profile.profile_revision,
                partitions: generation.profile.partitions.values().cloned().collect(),
                assignment: generation.profile.assignment,
            },
            generation: generation.generation,
            built_from: generation.built_from,
            published_epoch: generation.published_epoch,
            roots: generation.roots.iter().copied().collect(),
            nodes: generation.nodes.values().cloned().collect(),
            memberships: generation.memberships.clone(),
            statistics: generation
                .statistics
                .iter()
                .map(|(item, statistics)| ItemStatisticsPayload {
                    item: *item,
                    statistics: *statistics,
                })
                .collect(),
            manifest_digest: generation.manifest_digest,
            build_provenance: generation.build_provenance.clone(),
        }
    }
}

impl GenerationPayload {
    fn try_into_generation(self) -> Result<HierarchyGeneration> {
        let mut partitions = BTreeMap::new();
        for partition in self.profile.partitions {
            if partitions.insert(partition.id, partition).is_some() {
                return Err(HierarchyError::ManifestMismatch);
            }
        }
        let mut nodes = BTreeMap::new();
        for node in self.nodes {
            if nodes.insert(node.id, node).is_some() {
                return Err(HierarchyError::ManifestMismatch);
            }
        }
        let mut statistics = BTreeMap::new();
        for entry in self.statistics {
            if statistics.insert(entry.item, entry.statistics).is_some() {
                return Err(HierarchyError::ManifestMismatch);
            }
        }
        Ok(HierarchyGeneration {
            profile: HierarchyProfile {
                id: self.profile.id,
                workspace_id: self.profile.workspace_id,
                kind: self.profile.kind,
                name: self.profile.name,
                profile_revision: self.profile.profile_revision,
                partitions,
                assignment: self.profile.assignment,
            },
            generation: self.generation,
            built_from: self.built_from,
            published_epoch: self.published_epoch,
            roots: self.roots.into_iter().collect(),
            nodes,
            memberships: self.memberships,
            statistics,
            manifest_digest: self.manifest_digest,
            build_provenance: self.build_provenance,
        })
    }
}

/// Exact in-memory reference implementation of the backend-neutral hierarchy
/// contracts. Persistent adapters can implement [`HierarchyRepository`] without
/// changing proposal, validation, generation, or query semantics.
pub struct InMemoryHierarchyEngine {
    state: RwLock<RepositoryState>,
    deletions: Arc<RwLock<DeletionRegistry>>,
}

impl fmt::Debug for InMemoryHierarchyEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryHierarchyEngine")
            .finish_non_exhaustive()
    }
}

impl Default for InMemoryHierarchyEngine {
    fn default() -> Self {
        Self {
            state: RwLock::new(RepositoryState::default()),
            deletions: Arc::new(RwLock::new(DeletionRegistry::default())),
        }
    }
}

impl InMemoryHierarchyEngine {
    /// Creates an empty hierarchy repository at epoch zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inherent convenience wrapper for [`HierarchyRepository::publish`].
    pub fn publish(&self, proposal: &ValidatedHierarchyProposal) -> Result<HierarchyGenerationRef> {
        <Self as HierarchyRepository>::publish(self, proposal)
    }

    /// Inherent convenience wrapper for [`HierarchyRepository::invalidate`].
    pub fn invalidate(&self, invalidation: HierarchyInvalidation) -> Result<HierarchyEpoch> {
        <Self as HierarchyRepository>::invalidate(self, invalidation)
    }

    /// Inherent convenience wrapper for deletion closure.
    pub fn record_deletions(&self, deletion: DeletionRecord) -> Result<HierarchyEpoch> {
        <Self as HierarchyRepository>::record_deletions(self, deletion)
    }

    /// Inherent convenience wrapper for opening hierarchy snapshots.
    pub fn snapshot(&self, selector: HierarchySnapshotSelector) -> Result<HierarchySnapshot> {
        <Self as HierarchyRepository>::snapshot(self, selector)
    }

    /// Exports every retained catalog epoch and the current deletion barrier as
    /// one canonical, self-verifying persistence bundle.
    pub fn export_persistent(&self) -> Result<PersistentHierarchyBundle> {
        // Preserve the engine's global lock order: deletion registry first.
        let deletions = self
            .deletions
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?;
        let state = self
            .state
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?;
        let catalogs = state
            .history
            .values()
            .map(|catalog| CatalogPayload {
                epoch: catalog.epoch,
                views: catalog
                    .views
                    .iter()
                    .map(|(view_id, view)| ViewPayload {
                        view_id: *view_id,
                        active: view.active,
                        generations: view
                            .generations
                            .values()
                            .map(|generation| GenerationPayload::from(generation.as_ref()))
                            .collect(),
                        dirty_through: view.dirty_through,
                        invalidations: view.invalidations.clone(),
                    })
                    .collect(),
            })
            .collect();
        let payload = HierarchyStatePayload {
            schema_version: crate::FORMAT_VERSION,
            current_epoch: state.current.epoch,
            catalogs,
            deletion_epoch: deletions.epoch,
            deleted_nodes: deletions
                .deleted_nodes
                .iter()
                .map(
                    |((workspace_id, node_id), effective_at)| DeletedNodePayload {
                        workspace_id: *workspace_id,
                        node_id: *node_id,
                        effective_at: *effective_at,
                    },
                )
                .collect(),
            deleted_lineage: deletions
                .deleted_lineage
                .iter()
                .map(
                    |((workspace_id, dependency), effective_at)| DeletedLineagePayload {
                        workspace_id: *workspace_id,
                        dependency: dependency.clone(),
                        effective_at: *effective_at,
                    },
                )
                .collect(),
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(PersistentHierarchyBundle {
            schema_version: crate::FORMAT_VERSION,
            current_epoch: payload.current_epoch,
            payload_digest: *blake3::hash(&bytes).as_bytes(),
            payload: bytes,
        })
    }

    /// Restores a hierarchy engine only after validating the outer digest,
    /// retained history, active pointers, generation manifests, and lineage.
    pub fn from_persistent(bundle: &PersistentHierarchyBundle) -> Result<Self> {
        if bundle.schema_version != crate::FORMAT_VERSION
            || *blake3::hash(&bundle.payload).as_bytes() != bundle.payload_digest
        {
            return Err(HierarchyError::ManifestMismatch);
        }
        let payload: HierarchyStatePayload = serde_json::from_slice(&bundle.payload)?;
        if payload.schema_version != bundle.schema_version
            || payload.current_epoch != bundle.current_epoch
        {
            return Err(HierarchyError::ManifestMismatch);
        }
        let mut history = BTreeMap::new();
        for (ordinal, catalog_payload) in payload.catalogs.into_iter().enumerate() {
            let expected_epoch = u64::try_from(ordinal)
                .map(HierarchyEpoch::new)
                .map_err(|_| HierarchyError::SequenceExhausted)?;
            if catalog_payload.epoch != expected_epoch {
                return Err(HierarchyError::ManifestMismatch);
            }
            let mut views = BTreeMap::new();
            for view_payload in catalog_payload.views {
                let mut generations = BTreeMap::new();
                let mut navigation = BTreeMap::new();
                for generation_payload in view_payload.generations {
                    let generation = generation_payload.try_into_generation()?;
                    generation.verify_manifest()?;
                    let generation_number = generation.generation;
                    let index = Arc::new(NavigationIndex::build(&generation));
                    if generation.profile.id != view_payload.view_id
                        || generation.published_epoch > catalog_payload.epoch
                        || generations
                            .insert(generation_number, Arc::new(generation))
                            .is_some()
                        || navigation.insert(generation_number, index).is_some()
                    {
                        return Err(HierarchyError::ManifestMismatch);
                    }
                }
                if view_payload
                    .active
                    .is_some_and(|active| !generations.contains_key(&active))
                    || views
                        .insert(
                            view_payload.view_id,
                            ViewState {
                                active: view_payload.active,
                                generations,
                                navigation,
                                dirty_through: view_payload.dirty_through,
                                invalidations: view_payload.invalidations,
                            },
                        )
                        .is_some()
                {
                    return Err(HierarchyError::ManifestMismatch);
                }
            }
            let epoch = catalog_payload.epoch;
            if history
                .insert(epoch, Arc::new(Catalog { epoch, views }))
                .is_some()
            {
                return Err(HierarchyError::ManifestMismatch);
            }
        }
        let current = history
            .get(&payload.current_epoch)
            .cloned()
            .ok_or(HierarchyError::ManifestMismatch)?;
        if history
            .last_key_value()
            .is_none_or(|(epoch, _)| *epoch != payload.current_epoch)
        {
            return Err(HierarchyError::ManifestMismatch);
        }
        let mut deleted_nodes = BTreeMap::new();
        for entry in payload.deleted_nodes {
            if deleted_nodes
                .insert((entry.workspace_id, entry.node_id), entry.effective_at)
                .is_some()
            {
                return Err(HierarchyError::ManifestMismatch);
            }
        }
        let mut deleted_lineage = BTreeMap::new();
        for entry in payload.deleted_lineage {
            entry
                .dependency
                .validate()
                .map_err(|error| HierarchyError::InvalidProvenance(error.to_string()))?;
            if deleted_lineage
                .insert((entry.workspace_id, entry.dependency), entry.effective_at)
                .is_some()
            {
                return Err(HierarchyError::ManifestMismatch);
            }
        }
        Ok(Self {
            state: RwLock::new(RepositoryState { current, history }),
            deletions: Arc::new(RwLock::new(DeletionRegistry {
                epoch: payload.deletion_epoch,
                deleted_nodes,
                deleted_lineage,
            })),
        })
    }
}

impl HierarchyRepository for InMemoryHierarchyEngine {
    type Snapshot = HierarchySnapshot;

    fn publish(&self, validated: &ValidatedHierarchyProposal) -> Result<HierarchyGenerationRef> {
        // Deletion lock precedes catalog lock everywhere. A deletion installed
        // concurrently either wins before this check or after publication and
        // is then applied dynamically to all snapshots.
        let deletions = self
            .deletions
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?;
        reject_deleted_dependencies(validated, &deletions)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| HierarchyError::LockPoisoned)?;
        let current_view = state.current.views.get(&validated.proposal.profile.id);
        let active = current_view.and_then(|view| view.active);
        if active != validated.proposal.expected_active {
            return Err(HierarchyError::ActiveGenerationConflict);
        }
        let expected = match active {
            Some(generation) => generation.checked_next()?,
            None => GenerationNumber::new(1)?,
        };
        if validated.proposal.generation != expected {
            return Err(HierarchyError::GenerationConflict {
                expected,
                proposed: validated.proposal.generation,
            });
        }

        let mut required = CommitSeq::GENESIS;
        if let Some(view) = current_view {
            if let Some(active_generation) =
                view.active.and_then(|number| view.generations.get(&number))
            {
                if active_generation.profile.workspace_id != validated.proposal.profile.workspace_id
                {
                    return Err(HierarchyError::WorkspaceMismatch {
                        view_id: validated.proposal.profile.id,
                        workspace_id: validated.proposal.profile.workspace_id,
                    });
                }
                if validated.proposal.profile.profile_revision
                    < active_generation.profile.profile_revision
                {
                    return Err(HierarchyError::ProfileRevisionRegression {
                        active: active_generation.profile.profile_revision,
                        proposed: validated.proposal.profile.profile_revision,
                    });
                }
                if validated.proposal.profile.profile_revision
                    == active_generation.profile.profile_revision
                    && validated.proposal.profile != active_generation.profile
                {
                    return Err(HierarchyError::ProfileRevisionReuse(
                        validated.proposal.profile.profile_revision,
                    ));
                }
                required = active_generation.built_from.commit_seq;
            }
            if let Some(dirty) = view.dirty_through {
                required = required.max(dirty);
            }
        }
        if validated.proposal.built_from.commit_seq < required {
            return Err(HierarchyError::StaleProposal {
                built_from: validated.proposal.built_from.commit_seq,
                required,
            });
        }

        let epoch = state.current.epoch.checked_next()?;
        let generation = Arc::new(HierarchyGeneration {
            profile: validated.proposal.profile.clone(),
            generation: validated.proposal.generation,
            built_from: validated.proposal.built_from,
            published_epoch: epoch,
            roots: validated.proposal.roots.clone(),
            nodes: validated.proposal.nodes.clone(),
            memberships: validated.proposal.memberships.clone(),
            statistics: validated.statistics.clone(),
            manifest_digest: validated.digest,
            build_provenance: validated.proposal.build_provenance.clone(),
        });
        let mut catalog = (*state.current).clone();
        catalog.epoch = epoch;
        let view = catalog
            .views
            .entry(validated.proposal.profile.id)
            .or_default();
        view.generations
            .insert(validated.proposal.generation, Arc::clone(&generation));
        view.navigation.insert(
            validated.proposal.generation,
            Arc::new(NavigationIndex::build(&generation)),
        );
        view.active = Some(validated.proposal.generation);
        if view
            .dirty_through
            .is_some_and(|dirty| dirty <= generation.built_from.commit_seq)
        {
            view.dirty_through = None;
        }
        let catalog = Arc::new(catalog);
        state.history.insert(epoch, Arc::clone(&catalog));
        state.current = catalog;
        Ok(generation_reference(&generation))
    }

    fn invalidate(&self, invalidation: HierarchyInvalidation) -> Result<HierarchyEpoch> {
        if let InvalidationReason::Domain(label) = &invalidation.reason {
            validate_text(label, "hierarchy_invalidation.reason")?;
        }
        let mut state = self
            .state
            .write()
            .map_err(|_| HierarchyError::LockPoisoned)?;
        let current_view = state
            .current
            .views
            .get(&invalidation.view_id)
            .ok_or(HierarchyError::ViewUnavailable)?;
        let active = current_view
            .active
            .and_then(|generation| current_view.generations.get(&generation))
            .ok_or(HierarchyError::ViewUnavailable)?;
        if active.profile.workspace_id != invalidation.workspace_id {
            return Err(HierarchyError::WorkspaceMismatch {
                view_id: invalidation.view_id,
                workspace_id: invalidation.workspace_id,
            });
        }
        let epoch = state.current.epoch.checked_next()?;
        let mut catalog = (*state.current).clone();
        catalog.epoch = epoch;
        let view = catalog
            .views
            .get_mut(&invalidation.view_id)
            .ok_or(HierarchyError::ViewUnavailable)?;
        view.dirty_through = Some(
            view.dirty_through
                .map_or(invalidation.dirty_through, |current| {
                    current.max(invalidation.dirty_through)
                }),
        );
        view.invalidations.push(invalidation);
        let catalog = Arc::new(catalog);
        state.history.insert(epoch, Arc::clone(&catalog));
        state.current = catalog;
        Ok(epoch)
    }

    fn record_deletions(&self, deletion: DeletionRecord) -> Result<HierarchyEpoch> {
        if deletion.node_ids.is_empty() && deletion.lineage_dependencies.is_empty() {
            return self
                .deletions
                .read()
                .map(|registry| registry.epoch)
                .map_err(|_| HierarchyError::LockPoisoned);
        }
        for dependency in &deletion.lineage_dependencies {
            dependency
                .validate()
                .map_err(|error| HierarchyError::InvalidProvenance(error.to_string()))?;
        }
        let mut registry = self
            .deletions
            .write()
            .map_err(|_| HierarchyError::LockPoisoned)?;
        registry.epoch = registry.epoch.checked_next()?;
        for node_id in &deletion.node_ids {
            registry
                .deleted_nodes
                .entry((deletion.workspace_id, *node_id))
                .and_modify(|current| *current = (*current).min(deletion.effective_at))
                .or_insert(deletion.effective_at);
        }
        for dependency in &deletion.lineage_dependencies {
            registry
                .deleted_lineage
                .entry((deletion.workspace_id, dependency.clone()))
                .and_modify(|current| *current = (*current).min(deletion.effective_at))
                .or_insert(deletion.effective_at);
        }
        let deletion_epoch = registry.epoch;

        let mut state = self
            .state
            .write()
            .map_err(|_| HierarchyError::LockPoisoned)?;
        let epoch = state.current.epoch.checked_next()?;
        let mut catalog = (*state.current).clone();
        catalog.epoch = epoch;
        for (view_id, view) in &mut catalog.views {
            let Some(active) = view
                .active
                .and_then(|generation| view.generations.get(&generation))
            else {
                continue;
            };
            if active.profile.workspace_id != deletion.workspace_id
                || !generation_depends_on_deletion(active, &deletion)
            {
                continue;
            }
            view.dirty_through =
                Some(view.dirty_through.map_or(deletion.effective_at, |current| {
                    current.max(deletion.effective_at)
                }));
            view.invalidations.push(HierarchyInvalidation {
                view_id: *view_id,
                workspace_id: deletion.workspace_id,
                dirty_through: deletion.effective_at,
                reason: InvalidationReason::Deletion,
                affected_items: active
                    .nodes
                    .values()
                    .filter(|node| {
                        deletion.node_ids.iter().any(|node_id| {
                            item_depends_on_node(node.id, &node.provenance, *node_id)
                        }) || deletion.lineage_dependencies.iter().any(|dependency| {
                            provenance_depends_on_lineage(&node.provenance, dependency)
                        })
                    })
                    .map(|node| node.id)
                    .collect(),
            });
        }
        let catalog = Arc::new(catalog);
        state.history.insert(epoch, Arc::clone(&catalog));
        state.current = catalog;
        drop(state);
        drop(registry);
        Ok(deletion_epoch)
    }

    fn snapshot(&self, selector: HierarchySnapshotSelector) -> Result<Self::Snapshot> {
        let state = self
            .state
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?;
        let catalog =
            match selector {
                HierarchySnapshotSelector::Latest => Arc::clone(&state.current),
                HierarchySnapshotSelector::At(epoch) => state.history.get(&epoch).cloned().ok_or(
                    HierarchyError::SnapshotUnavailable {
                        requested: epoch,
                        head: state.current.epoch,
                    },
                )?,
            };
        Ok(HierarchySnapshot {
            catalog,
            deletions: Arc::clone(&self.deletions),
        })
    }
}

/// Immutable hierarchy catalog snapshot with a live deletion barrier.
#[derive(Clone)]
pub struct HierarchySnapshot {
    catalog: Arc<Catalog>,
    deletions: Arc<RwLock<DeletionRegistry>>,
}

impl fmt::Debug for HierarchySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HierarchySnapshot")
            .field("epoch", &self.catalog.epoch)
            .finish_non_exhaustive()
    }
}

impl HierarchySnapshot {
    /// Inherent convenience wrapper for route materialization.
    pub fn materialize_routes(
        &self,
        request: &RouteRequest,
        authorization: &AuthorizationSnapshot,
    ) -> Result<RouteMaterialization> {
        <Self as HierarchyRead>::materialize_routes(self, request, authorization)
    }

    /// Inherent convenience wrapper for beam traversal.
    pub fn beam_traverse(
        &self,
        request: &BeamTraversalRequest,
        authorization: &AuthorizationSnapshot,
    ) -> Result<BeamTraversalResult> {
        <Self as HierarchyRead>::beam_traverse(self, request, authorization)
    }

    /// Inherent convenience wrapper for cached-route validation.
    pub fn validate_route(
        &self,
        route: &HierarchyRoute,
        authorization: &AuthorizationSnapshot,
    ) -> Result<()> {
        <Self as HierarchyRead>::validate_route(self, route, authorization)
    }

    /// Resolves one policy-safe hierarchy item.
    pub fn resolve_node(
        &self,
        view_id: HierarchyViewId,
        item: HierarchyItemId,
        semantic_snapshot: SnapshotRef,
        domain_time: Option<contextdb_core::TimestampMicros>,
        freshness: FreshnessRequirement,
        authorization: &AuthorizationSnapshot,
    ) -> Result<(HierarchyNode, GenerationFreshness)> {
        <Self as HierarchyRead>::resolve_node(
            self,
            view_id,
            item,
            semantic_snapshot,
            domain_time,
            freshness,
            authorization,
        )
    }

    /// Returns policy-safe deterministic statistics for one branch.
    pub fn branch_statistics(
        &self,
        view_id: HierarchyViewId,
        item: HierarchyItemId,
        semantic_snapshot: SnapshotRef,
        freshness: FreshnessRequirement,
        authorization: &AuthorizationSnapshot,
    ) -> Result<(BranchStatistics, GenerationFreshness)> {
        <Self as HierarchyRead>::branch_statistics(
            self,
            view_id,
            item,
            semantic_snapshot,
            freshness,
            authorization,
        )
    }

    /// Lists only view IDs with at least one authorized partition and a
    /// generation not newer than the requested semantic snapshot.
    pub fn available_views(
        &self,
        semantic_snapshot: SnapshotRef,
        authorization: &AuthorizationSnapshot,
    ) -> Vec<HierarchyViewId> {
        let Ok(deletions) = self.deletions.read() else {
            return Vec::new();
        };
        self.catalog
            .views
            .iter()
            .filter_map(|(view_id, view)| {
                select_generation(view, semantic_snapshot, authorization)
                    .ok()
                    .filter(|generation| {
                        generation.nodes.is_empty()
                            || generation.nodes.keys().copied().any(|item| {
                                node_visible(
                                    generation,
                                    item,
                                    semantic_snapshot,
                                    None,
                                    authorization,
                                    &deletions,
                                )
                            })
                    })
                    .map(|_| *view_id)
            })
            .collect()
    }
}

impl HierarchyRead for HierarchySnapshot {
    fn epoch(&self) -> HierarchyEpoch {
        self.catalog.epoch
    }

    fn resolve_node(
        &self,
        view_id: HierarchyViewId,
        item: HierarchyItemId,
        semantic_snapshot: SnapshotRef,
        domain_time: Option<contextdb_core::TimestampMicros>,
        freshness_requirement: FreshnessRequirement,
        authorization: &AuthorizationSnapshot,
    ) -> Result<(HierarchyNode, GenerationFreshness)> {
        let view = self
            .catalog
            .views
            .get(&view_id)
            .ok_or(HierarchyError::RouteUnavailable)?;
        let generation = select_generation(view, semantic_snapshot, authorization)?;
        let freshness = generation_freshness(view, &generation, semantic_snapshot);
        require_freshness(freshness, freshness_requirement)?;
        let deletions = self
            .deletions
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?
            .clone();
        if !node_visible(
            &generation,
            item,
            semantic_snapshot,
            domain_time,
            authorization,
            &deletions,
        ) {
            return Err(HierarchyError::RouteUnavailable);
        }
        generation
            .nodes
            .get(&item)
            .cloned()
            .map(|node| (node, freshness))
            .ok_or(HierarchyError::RouteUnavailable)
    }

    fn branch_statistics(
        &self,
        view_id: HierarchyViewId,
        item: HierarchyItemId,
        semantic_snapshot: SnapshotRef,
        freshness_requirement: FreshnessRequirement,
        authorization: &AuthorizationSnapshot,
    ) -> Result<(BranchStatistics, GenerationFreshness)> {
        let view = self
            .catalog
            .views
            .get(&view_id)
            .ok_or(HierarchyError::RouteUnavailable)?;
        let generation = select_generation(view, semantic_snapshot, authorization)?;
        let freshness = generation_freshness(view, &generation, semantic_snapshot);
        require_freshness(freshness, freshness_requirement)?;
        let deletions = self
            .deletions
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?
            .clone();
        if !node_visible(
            &generation,
            item,
            semantic_snapshot,
            None,
            authorization,
            &deletions,
        ) {
            return Err(HierarchyError::RouteUnavailable);
        }
        let adjacency = visible_adjacency(
            &generation,
            semantic_snapshot,
            None,
            authorization,
            &deletions,
        );
        let incoming = incoming_counts(&adjacency);
        let topological = crate::validation::topological_order(&adjacency, &incoming)?;
        let roots: BTreeSet<_> = adjacency
            .keys()
            .filter(|candidate| !incoming.contains_key(candidate))
            .copied()
            .collect();
        crate::validation::compute_statistics(&adjacency, &roots, &topological)
            .get(&item)
            .copied()
            .map(|statistics| (statistics, freshness))
            .ok_or(HierarchyError::RouteUnavailable)
    }

    fn materialize_routes(
        &self,
        request: &RouteRequest,
        authorization: &AuthorizationSnapshot,
    ) -> Result<RouteMaterialization> {
        validate_route_budget(request)?;
        let view = self
            .catalog
            .views
            .get(&request.view_id)
            .ok_or(HierarchyError::RouteUnavailable)?;
        let generation = select_generation(view, request.semantic_snapshot, authorization)?;
        let freshness = generation_freshness(view, &generation, request.semantic_snapshot);
        require_freshness(freshness, request.freshness)?;
        let deletions = self
            .deletions
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?
            .clone();
        if !node_visible(
            &generation,
            request.target,
            request.semantic_snapshot,
            request.domain_time,
            authorization,
            &deletions,
        ) {
            return Err(HierarchyError::RouteUnavailable);
        }

        let visible_roots: BTreeSet<_> = generation
            .roots
            .iter()
            .copied()
            .filter(|root| {
                node_visible(
                    &generation,
                    *root,
                    request.semantic_snapshot,
                    request.domain_time,
                    authorization,
                    &deletions,
                )
            })
            .collect();
        let parents = visible_parents(
            &generation,
            request.semantic_snapshot,
            request.domain_time,
            authorization,
            &deletions,
        );
        let target_confidence = generation
            .nodes
            .get(&request.target)
            .map(|node| node.confidence)
            .ok_or(HierarchyError::RouteUnavailable)?;
        let mut stack = vec![RouteState {
            current: request.target,
            reversed_items: vec![request.target],
            reversed_memberships: Vec::new(),
            confidence: target_confidence,
        }];
        let mut routes = Vec::new();
        let mut truncated = false;
        while let Some(state) = stack.pop() {
            if visible_roots.contains(&state.current) {
                let mut items = state.reversed_items;
                let mut memberships = state.reversed_memberships;
                items.reverse();
                memberships.reverse();
                let nodes = items
                    .iter()
                    .filter_map(|item| generation.nodes.get(item).cloned())
                    .collect::<Vec<_>>();
                if nodes.len() != items.len() {
                    return Err(HierarchyError::RouteUnavailable);
                }
                let mut route = HierarchyRoute {
                    generation: generation_reference(&generation),
                    hierarchy_epoch: self.catalog.epoch,
                    deletion_epoch: deletions.epoch,
                    semantic_snapshot: request.semantic_snapshot,
                    domain_time: request.domain_time,
                    items,
                    nodes,
                    memberships,
                    confidence: state.confidence,
                    freshness,
                    integrity_digest: [0; 32],
                };
                route.integrity_digest = route_digest(&route)?;
                routes.push(route);
                if routes.len() == request.max_routes {
                    truncated |= !stack.is_empty();
                    break;
                }
                continue;
            }
            if state.reversed_memberships.len() >= request.max_depth {
                truncated = true;
                continue;
            }
            let Some(parent_edges) = parents.get(&state.current) else {
                continue;
            };
            for membership in parent_edges.iter().rev() {
                if state.reversed_items.contains(&membership.parent) {
                    continue;
                }
                let Some(parent_node) = generation.nodes.get(&membership.parent) else {
                    continue;
                };
                let mut next = state.clone();
                next.current = membership.parent;
                next.reversed_items.push(membership.parent);
                next.reversed_memberships.push((*membership).clone());
                next.confidence = next
                    .confidence
                    .combine(membership.confidence)
                    .combine(parent_node.confidence);
                stack.push(next);
            }
        }
        if routes.is_empty() {
            return Err(HierarchyError::RouteUnavailable);
        }
        routes.sort_by(route_order);
        Ok(RouteMaterialization {
            routes,
            truncated,
            freshness,
        })
    }

    fn beam_traverse(
        &self,
        request: &BeamTraversalRequest,
        authorization: &AuthorizationSnapshot,
    ) -> Result<BeamTraversalResult> {
        validate_beam_budget(request)?;
        let view = self
            .catalog
            .views
            .get(&request.view_id)
            .ok_or(HierarchyError::RouteUnavailable)?;
        let generation = select_generation(view, request.semantic_snapshot, authorization)?;
        let freshness = generation_freshness(view, &generation, request.semantic_snapshot);
        require_freshness(freshness, request.freshness)?;
        let deletions = self
            .deletions
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?
            .clone();
        let requested_roots = if request.roots.is_empty() {
            generation.roots.clone()
        } else {
            request.roots.clone()
        };
        let mut frontier: Vec<_> = requested_roots
            .into_iter()
            .filter(|root| generation.roots.contains(root))
            .filter(|root| {
                node_visible(
                    &generation,
                    *root,
                    request.semantic_snapshot,
                    request.domain_time,
                    authorization,
                    &deletions,
                )
            })
            .filter_map(|root| {
                generation.nodes.get(&root).map(|node| TraversalHit {
                    item: root,
                    path: vec![root],
                    confidence: node.confidence,
                    depth: 0,
                })
            })
            .collect();
        frontier.sort_by(traversal_order);
        let root_count = frontier.len();
        frontier.truncate(request.beam_width);
        if frontier.is_empty() {
            return Err(HierarchyError::RouteUnavailable);
        }

        let navigation = view
            .navigation
            .get(&generation.generation)
            .ok_or(HierarchyError::ManifestMismatch)?;
        let mut hits = frontier.clone();
        let mut expansions = 0_usize;
        let mut truncated = root_count > request.beam_width;
        for depth in 1..=request.max_depth {
            let mut candidates = Vec::new();
            'frontier: for hit in &frontier {
                if let Some(indexes) = navigation.children.get(&hit.item) {
                    for index in indexes {
                        let membership = &generation.memberships[*index];
                        if !membership_visible(
                            &generation,
                            membership,
                            request.semantic_snapshot,
                            request.domain_time,
                            authorization,
                            &deletions,
                        ) {
                            continue;
                        }
                        if expansions == request.max_expansions {
                            truncated = true;
                            break 'frontier;
                        }
                        expansions += 1;
                        if hit.path.contains(&membership.child) {
                            continue;
                        }
                        let Some(child) = generation.nodes.get(&membership.child) else {
                            continue;
                        };
                        let mut path = hit.path.clone();
                        path.push(membership.child);
                        candidates.push(TraversalHit {
                            item: membership.child,
                            path,
                            confidence: hit
                                .confidence
                                .combine(membership.confidence)
                                .combine(child.confidence),
                            depth,
                        });
                    }
                }
            }
            candidates.sort_by(traversal_order);
            candidates.dedup_by(|left, right| left.path == right.path);
            if candidates.len() > request.beam_width {
                candidates.truncate(request.beam_width);
                truncated = true;
            }
            if candidates.is_empty() {
                break;
            }
            hits.extend(candidates.iter().cloned());
            frontier = candidates;
            if expansions == request.max_expansions {
                break;
            }
            if depth == request.max_depth
                && frontier.iter().any(|hit| {
                    navigation
                        .children
                        .get(&hit.item)
                        .is_some_and(|edges| !edges.is_empty())
                })
            {
                truncated = true;
            }
        }
        Ok(BeamTraversalResult {
            hits,
            expansions,
            truncated,
            freshness,
            generation: generation_reference(&generation),
        })
    }

    fn validate_route(
        &self,
        route: &HierarchyRoute,
        authorization: &AuthorizationSnapshot,
    ) -> Result<()> {
        if route.hierarchy_epoch != self.catalog.epoch
            || route.items.is_empty()
            || route.nodes.len() != route.items.len()
            || route.memberships.len().saturating_add(1) != route.items.len()
            || route.integrity_digest != route_digest(route)?
        {
            return Err(HierarchyError::StaleRoute);
        }
        let deletions = self
            .deletions
            .read()
            .map_err(|_| HierarchyError::LockPoisoned)?
            .clone();
        if route.deletion_epoch != deletions.epoch {
            return Err(HierarchyError::StaleRoute);
        }
        let view = self
            .catalog
            .views
            .get(&route.generation.view_id)
            .ok_or(HierarchyError::StaleRoute)?;
        let generation = view
            .generations
            .get(&route.generation.generation)
            .ok_or(HierarchyError::StaleRoute)?;
        if generation_reference(generation) != route.generation
            || generation_freshness(view, generation, route.semantic_snapshot) != route.freshness
            || !generation.roots.contains(&route.items[0])
        {
            return Err(HierarchyError::StaleRoute);
        }
        for (item, cached_node) in route.items.iter().zip(&route.nodes) {
            if !node_visible(
                generation,
                *item,
                route.semantic_snapshot,
                route.domain_time,
                authorization,
                &deletions,
            ) || generation.nodes.get(item) != Some(cached_node)
                || cached_node.id != *item
            {
                return Err(HierarchyError::StaleRoute);
            }
        }
        for (index, membership) in route.memberships.iter().enumerate() {
            if membership.parent != route.items[index]
                || membership.child != route.items[index + 1]
                || !generation.memberships.contains(membership)
                || !membership_visible(
                    generation,
                    membership,
                    route.semantic_snapshot,
                    route.domain_time,
                    authorization,
                    &deletions,
                )
            {
                return Err(HierarchyError::StaleRoute);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RouteState {
    current: HierarchyItemId,
    reversed_items: Vec<HierarchyItemId>,
    reversed_memberships: Vec<HierarchyMembership>,
    confidence: Confidence,
}

fn select_generation(
    view: &ViewState,
    semantic_snapshot: SnapshotRef,
    authorization: &AuthorizationSnapshot,
) -> Result<Arc<HierarchyGeneration>> {
    if authorization.evaluated_at() < semantic_snapshot.commit_seq {
        return Err(HierarchyError::RouteUnavailable);
    }
    let generation = view
        .generations
        .values()
        .rev()
        .find(|generation| generation.built_from.commit_seq <= semantic_snapshot.commit_seq)
        .cloned()
        .ok_or(HierarchyError::GenerationUnavailable(
            semantic_snapshot.commit_seq,
        ))?;
    if generation.profile.workspace_id != authorization.workspace_id()
        || !generation.profile.partitions.values().any(|partition| {
            partition.policy_revision <= authorization.evaluated_at()
                && authorization.allows(partition.id)
        })
    {
        return Err(HierarchyError::RouteUnavailable);
    }
    Ok(generation)
}

fn generation_freshness(
    view: &ViewState,
    generation: &HierarchyGeneration,
    semantic_snapshot: SnapshotRef,
) -> GenerationFreshness {
    let dirty_relevant = view.dirty_through.is_some_and(|dirty| {
        dirty <= semantic_snapshot.commit_seq && dirty > generation.built_from.commit_seq
    });
    GenerationFreshness {
        covered_through: generation.built_from.commit_seq,
        requested: semantic_snapshot.commit_seq,
        dirty_through: view.dirty_through,
        current: generation.built_from.commit_seq == semantic_snapshot.commit_seq
            && !dirty_relevant,
    }
}

fn require_freshness(
    freshness: GenerationFreshness,
    requirement: FreshnessRequirement,
) -> Result<()> {
    if requirement == FreshnessRequirement::RequireCurrent && !freshness.current {
        return Err(HierarchyError::StaleGeneration {
            covered: freshness.covered_through,
            requested: freshness.requested,
        });
    }
    Ok(())
}

fn node_visible(
    generation: &HierarchyGeneration,
    item: HierarchyItemId,
    semantic_snapshot: SnapshotRef,
    domain_time: Option<contextdb_core::TimestampMicros>,
    authorization: &AuthorizationSnapshot,
    deletions: &DeletionRegistry,
) -> bool {
    let Some(node) = generation.nodes.get(&item) else {
        return false;
    };
    generation.profile.workspace_id == authorization.workspace_id()
        && authorization.allows(node.partition)
        && node.validity.visible_at(semantic_snapshot, domain_time)
        && !provenance_deleted(
            generation.profile.workspace_id,
            &generation.build_provenance,
            deletions,
        )
        && !item_or_provenance_deleted(
            generation.profile.workspace_id,
            node.id,
            &node.provenance,
            deletions,
        )
}

fn membership_visible(
    generation: &HierarchyGeneration,
    membership: &HierarchyMembership,
    semantic_snapshot: SnapshotRef,
    domain_time: Option<contextdb_core::TimestampMicros>,
    authorization: &AuthorizationSnapshot,
    deletions: &DeletionRegistry,
) -> bool {
    membership
        .validity
        .visible_at(semantic_snapshot, domain_time)
        && node_visible(
            generation,
            membership.parent,
            semantic_snapshot,
            domain_time,
            authorization,
            deletions,
        )
        && node_visible(
            generation,
            membership.child,
            semantic_snapshot,
            domain_time,
            authorization,
            deletions,
        )
        && !provenance_deleted(
            generation.profile.workspace_id,
            &membership.provenance,
            deletions,
        )
}

fn visible_parents<'a>(
    generation: &'a HierarchyGeneration,
    semantic_snapshot: SnapshotRef,
    domain_time: Option<contextdb_core::TimestampMicros>,
    authorization: &AuthorizationSnapshot,
    deletions: &DeletionRegistry,
) -> BTreeMap<HierarchyItemId, Vec<&'a HierarchyMembership>> {
    let mut parents: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for membership in &generation.memberships {
        if membership_visible(
            generation,
            membership,
            semantic_snapshot,
            domain_time,
            authorization,
            deletions,
        ) {
            parents
                .entry(membership.child)
                .or_default()
                .push(membership);
        }
    }
    for edges in parents.values_mut() {
        edges.sort_by(|left, right| membership_order(left, right));
    }
    parents
}

fn visible_adjacency(
    generation: &HierarchyGeneration,
    semantic_snapshot: SnapshotRef,
    domain_time: Option<contextdb_core::TimestampMicros>,
    authorization: &AuthorizationSnapshot,
    deletions: &DeletionRegistry,
) -> BTreeMap<HierarchyItemId, Vec<HierarchyItemId>> {
    let mut adjacency: BTreeMap<_, Vec<_>> = generation
        .nodes
        .keys()
        .copied()
        .filter(|item| {
            node_visible(
                generation,
                *item,
                semantic_snapshot,
                domain_time,
                authorization,
                deletions,
            )
        })
        .map(|item| (item, Vec::new()))
        .collect();
    for membership in &generation.memberships {
        if membership_visible(
            generation,
            membership,
            semantic_snapshot,
            domain_time,
            authorization,
            deletions,
        ) && let Some(children) = adjacency.get_mut(&membership.parent)
        {
            children.push(membership.child);
        }
    }
    for children in adjacency.values_mut() {
        children.sort_unstable();
    }
    adjacency
}

fn incoming_counts(
    adjacency: &BTreeMap<HierarchyItemId, Vec<HierarchyItemId>>,
) -> BTreeMap<HierarchyItemId, usize> {
    let mut incoming = BTreeMap::new();
    for children in adjacency.values() {
        for child in children {
            *incoming.entry(*child).or_default() += 1;
        }
    }
    incoming
}

fn membership_order(left: &HierarchyMembership, right: &HierarchyMembership) -> std::cmp::Ordering {
    role_rank(left.role)
        .cmp(&role_rank(right.role))
        .then_with(|| right.confidence.cmp(&left.confidence))
        .then_with(|| left.order_key.cmp(&right.order_key))
        .then_with(|| left.parent.cmp(&right.parent))
}

const fn role_rank(role: MembershipRole) -> u8 {
    match role {
        MembershipRole::Primary => 0,
        MembershipRole::Alternative => 1,
    }
}

fn route_order(left: &HierarchyRoute, right: &HierarchyRoute) -> std::cmp::Ordering {
    let left_alternatives = left
        .memberships
        .iter()
        .filter(|membership| membership.role == MembershipRole::Alternative)
        .count();
    let right_alternatives = right
        .memberships
        .iter()
        .filter(|membership| membership.role == MembershipRole::Alternative)
        .count();
    left_alternatives
        .cmp(&right_alternatives)
        .then_with(|| right.confidence.cmp(&left.confidence))
        .then_with(|| left.items.cmp(&right.items))
}

fn traversal_order(left: &TraversalHit, right: &TraversalHit) -> std::cmp::Ordering {
    right
        .confidence
        .cmp(&left.confidence)
        .then_with(|| left.path.cmp(&right.path))
}

fn validate_route_budget(request: &RouteRequest) -> Result<()> {
    if request.max_routes == 0 {
        return Err(HierarchyError::InvalidBudget("max_routes"));
    }
    if request.max_depth == 0 {
        return Err(HierarchyError::InvalidBudget("max_depth"));
    }
    Ok(())
}

fn validate_beam_budget(request: &BeamTraversalRequest) -> Result<()> {
    if request.beam_width == 0 {
        return Err(HierarchyError::InvalidBudget("beam_width"));
    }
    if request.max_depth == 0 {
        return Err(HierarchyError::InvalidBudget("max_depth"));
    }
    if request.max_expansions == 0 {
        return Err(HierarchyError::InvalidBudget("max_expansions"));
    }
    Ok(())
}

fn generation_reference(generation: &HierarchyGeneration) -> HierarchyGenerationRef {
    HierarchyGenerationRef {
        view_id: generation.profile.id,
        generation: generation.generation,
        published_epoch: generation.published_epoch,
        built_from: generation.built_from,
        manifest_digest: generation.manifest_digest,
    }
}

fn route_digest(route: &HierarchyRoute) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-hierarchy-materialized-route-v1\0");
    hasher.update(route.generation.view_id.as_uuid().as_bytes());
    hasher.update(&route.generation.generation.get().to_be_bytes());
    hasher.update(&route.hierarchy_epoch.get().to_be_bytes());
    hasher.update(&route.deletion_epoch.get().to_be_bytes());
    hasher.update(&route.semantic_snapshot.commit_seq.get().to_be_bytes());
    hasher.update(&serde_json::to_vec(&route.domain_time)?);
    hasher.update(&serde_json::to_vec(&route.items)?);
    hasher.update(&serde_json::to_vec(&route.nodes)?);
    hasher.update(&serde_json::to_vec(&route.memberships)?);
    hasher.update(&route.confidence.basis_points().to_be_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn reject_deleted_dependencies(
    validated: &ValidatedHierarchyProposal,
    deletions: &DeletionRegistry,
) -> Result<()> {
    let workspace = validated.proposal.profile.workspace_id;
    for node_id in deletions
        .deleted_nodes
        .keys()
        .filter_map(|(candidate_workspace, node_id)| {
            (*candidate_workspace == workspace).then_some(*node_id)
        })
    {
        if proposal_depends_on_node(validated, node_id) {
            return Err(HierarchyError::DeletedDependency(node_id));
        }
    }
    for dependency in
        deletions
            .deleted_lineage
            .keys()
            .filter_map(|(candidate_workspace, dependency)| {
                (*candidate_workspace == workspace).then_some(dependency)
            })
    {
        if proposal_depends_on_lineage(validated, dependency) {
            return Err(HierarchyError::DeletedLineageDependency(dependency.clone()));
        }
    }
    Ok(())
}

fn proposal_depends_on_node(validated: &ValidatedHierarchyProposal, node_id: NodeId) -> bool {
    validated
        .proposal
        .nodes
        .values()
        .any(|node| item_depends_on_node(node.id, &node.provenance, node_id))
        || validated
            .proposal
            .memberships
            .iter()
            .any(|membership| provenance_depends_on_node(&membership.provenance, node_id))
        || provenance_depends_on_node(&validated.proposal.build_provenance, node_id)
}

fn proposal_depends_on_lineage(
    validated: &ValidatedHierarchyProposal,
    dependency: &LineageNode,
) -> bool {
    validated
        .proposal
        .nodes
        .values()
        .any(|node| provenance_depends_on_lineage(&node.provenance, dependency))
        || validated
            .proposal
            .memberships
            .iter()
            .any(|membership| provenance_depends_on_lineage(&membership.provenance, dependency))
        || provenance_depends_on_lineage(&validated.proposal.build_provenance, dependency)
}

fn generation_depends_on_deletion(
    generation: &HierarchyGeneration,
    deletion: &DeletionRecord,
) -> bool {
    deletion
        .node_ids
        .iter()
        .any(|node_id| generation_depends_on_node(generation, *node_id))
        || deletion
            .lineage_dependencies
            .iter()
            .any(|dependency| generation_depends_on_lineage(generation, dependency))
}

fn generation_depends_on_node(generation: &HierarchyGeneration, node_id: NodeId) -> bool {
    generation
        .nodes
        .values()
        .any(|node| item_depends_on_node(node.id, &node.provenance, node_id))
        || generation
            .memberships
            .iter()
            .any(|membership| provenance_depends_on_node(&membership.provenance, node_id))
        || provenance_depends_on_node(&generation.build_provenance, node_id)
}

fn generation_depends_on_lineage(
    generation: &HierarchyGeneration,
    dependency: &LineageNode,
) -> bool {
    generation
        .nodes
        .values()
        .any(|node| provenance_depends_on_lineage(&node.provenance, dependency))
        || generation
            .memberships
            .iter()
            .any(|membership| provenance_depends_on_lineage(&membership.provenance, dependency))
        || provenance_depends_on_lineage(&generation.build_provenance, dependency)
}

fn item_depends_on_node(
    item: HierarchyItemId,
    provenance: &HierarchyProvenance,
    node_id: NodeId,
) -> bool {
    item == HierarchyItemId::Semantic(node_id) || provenance_depends_on_node(provenance, node_id)
}

fn provenance_depends_on_node(provenance: &HierarchyProvenance, node_id: NodeId) -> bool {
    provenance
        .derivation
        .inputs
        .iter()
        .any(|input| matches!(input, LineageNode::NodeRevision { id, .. } if *id == node_id))
}

fn provenance_depends_on_lineage(
    provenance: &HierarchyProvenance,
    dependency: &LineageNode,
) -> bool {
    provenance.derivation.inputs.contains(dependency)
}

fn item_or_provenance_deleted(
    workspace_id: WorkspaceId,
    item: HierarchyItemId,
    provenance: &HierarchyProvenance,
    deletions: &DeletionRegistry,
) -> bool {
    if let HierarchyItemId::Semantic(node_id) = item
        && deletions
            .deleted_nodes
            .contains_key(&(workspace_id, node_id))
    {
        return true;
    }
    provenance_deleted(workspace_id, provenance, deletions)
}

fn provenance_deleted(
    workspace_id: WorkspaceId,
    provenance: &HierarchyProvenance,
    deletions: &DeletionRegistry,
) -> bool {
    provenance.derivation.inputs.iter().any(|input| {
        deletions
            .deleted_lineage
            .contains_key(&(workspace_id, input.clone()))
            || matches!(input, LineageNode::NodeRevision { id, .. }
                if deletions.deleted_nodes.contains_key(&(workspace_id, *id)))
    })
}
