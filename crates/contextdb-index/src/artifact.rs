use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    Artifact, ArtifactId, BlobLocator, CommitSeq, ContentBlock, ContentBlockId, ContentDigest,
    EvidenceSelector, LineageNode, Modality, PolicyDecision, RepresentationId, SemanticEnvelope,
    TimestampMicros, Validate, VectorSpaceId,
};
use serde::{Deserialize, Serialize};

use crate::{IndexError, IndexPolicy, IndexPrincipal, Result};

/// The semantic role of a representation derived from an original artifact.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationKind {
    Transcript,
    Caption,
    Ocr,
    Thumbnail,
    Embedding,
    RegionDescription,
    Other(String),
}

/// Explicit compatibility contract for cross-modal representations.
///
/// Absence means that the representation may only be used in its own vector
/// space. A consumer must still validate every referenced `VectorSpace`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationCompatibility {
    pub family: String,
    pub revision: String,
    pub native_vector_space: Option<VectorSpaceId>,
    pub compatible_vector_spaces: BTreeSet<VectorSpaceId>,
}

impl RepresentationCompatibility {
    fn validate(&self) -> Result<()> {
        if self.family.trim().is_empty() || self.revision.trim().is_empty() {
            return Err(IndexError::Invalid(
                "representation compatibility identifiers must not be blank",
            ));
        }
        if let Some(native) = self.native_vector_space
            && !self.compatible_vector_spaces.contains(&native)
        {
            return Err(IndexError::Invalid(
                "native vector space must be included in compatibility set",
            ));
        }
        Ok(())
    }
}

/// One immutable derived transcript, caption, OCR result, preview, or embedding.
///
/// The original artifact and selector remain canonical evidence. `content_block`
/// points at derived bytes and never replaces the source block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRepresentation {
    pub id: RepresentationId,
    pub artifact_id: ArtifactId,
    pub source_content_block_id: ContentBlockId,
    pub source_selector: EvidenceSelector,
    pub source_content_hash: ContentDigest,
    pub kind: RepresentationKind,
    pub modality: Modality,
    pub content_block: ContentBlock,
    pub confidence_millionths: u32,
    pub compatibility: Option<RepresentationCompatibility>,
    pub envelope: SemanticEnvelope,
    pub policy: IndexPolicy,
    pub projected_at: CommitSeq,
    pub tombstone_at: Option<CommitSeq>,
}

impl ArtifactRepresentation {
    fn validate(&self) -> Result<()> {
        if let RepresentationKind::Other(label) = &self.kind
            && label.trim().is_empty()
        {
            return Err(IndexError::Invalid(
                "representation kind label must not be blank",
            ));
        }
        if let Modality::Other(label) = &self.modality
            && label.trim().is_empty()
        {
            return Err(IndexError::Invalid(
                "representation modality label must not be blank",
            ));
        }
        self.source_selector
            .validate()
            .map_err(|_| IndexError::Invalid("artifact selector is invalid"))?;
        self.content_block
            .validate()
            .map_err(|_| IndexError::Invalid("derived content block is invalid"))?;
        self.envelope
            .validate()
            .map_err(|_| IndexError::Invalid("representation envelope is invalid"))?;
        if self.confidence_millionths > 1_000_000 {
            return Err(IndexError::Invalid("representation confidence exceeds one"));
        }
        if self
            .tombstone_at
            .is_some_and(|deleted| deleted < self.projected_at)
        {
            return Err(IndexError::Invalid(
                "representation tombstone precedes projection",
            ));
        }
        if !self
            .envelope
            .derivation
            .inputs
            .contains(&LineageNode::Artifact {
                id: self.artifact_id,
            })
        {
            return Err(IndexError::Invalid(
                "derived representation must retain original artifact lineage",
            ));
        }
        if self.content_block.id == self.source_content_block_id {
            return Err(IndexError::Invalid(
                "derived and original content blocks must have distinct identities",
            ));
        }
        if let Some(compatibility) = &self.compatibility {
            compatibility.validate()?;
        }
        match self.kind {
            RepresentationKind::Transcript
            | RepresentationKind::Caption
            | RepresentationKind::Ocr
            | RepresentationKind::RegionDescription
                if self.modality != Modality::Text =>
            {
                return Err(IndexError::Invalid(
                    "textual artifact representation must use text modality",
                ));
            }
            RepresentationKind::Embedding
                if self
                    .compatibility
                    .as_ref()
                    .and_then(|value| value.native_vector_space)
                    .is_none() =>
            {
                return Err(IndexError::Invalid(
                    "embedding representation requires a native vector space",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Original artifact metadata and all content-addressed blocks it owns.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProjection {
    pub artifact: Artifact,
    pub content_blocks: Vec<ContentBlock>,
    pub blob_locator_schema_version: u16,
    pub policy: IndexPolicy,
    pub projected_at: CommitSeq,
    pub tombstone_at: Option<CommitSeq>,
}

impl ArtifactProjection {
    fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        self.artifact
            .validate()
            .map_err(|_| IndexError::Invalid("artifact metadata is invalid"))?;
        let envelope = &self.artifact.envelope;
        let envelope_owners = envelope
            .ownership
            .owners
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let envelope_scopes = envelope
            .scopes
            .iter()
            .map(|scope| scope.id)
            .collect::<BTreeSet<_>>();
        if self.policy.owners != envelope_owners
            || !self
                .policy
                .purposes
                .is_subset(&envelope.ownership.allowed_purposes)
            || !envelope_scopes.is_subset(&self.policy.scopes)
            || self.policy.classification < envelope.security.classification
            || !envelope
                .security
                .labels
                .is_subset(&self.policy.security_labels)
            || !envelope
                .security
                .required_compartments
                .is_subset(&self.policy.required_compartments)
            || (self.policy.allow_external_processing
                && !envelope.security.allow_external_processing)
            || (self.policy.retrieve_allowed
                && envelope.use_policy.retrieve != PolicyDecision::Allow)
        {
            return Err(IndexError::Invalid(
                "artifact projection policy broadens or contradicts semantic envelope",
            ));
        }
        if self.blob_locator_schema_version == 0 {
            return Err(IndexError::Invalid(
                "blob locator schema version must be positive",
            ));
        }
        if self
            .tombstone_at
            .is_some_and(|deleted| deleted < self.projected_at)
        {
            return Err(IndexError::Invalid(
                "artifact tombstone precedes projection",
            ));
        }
        let declared = self
            .artifact
            .content_blocks
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if declared.len() != self.artifact.content_blocks.len() {
            return Err(IndexError::Invalid(
                "artifact contains duplicate content block IDs",
            ));
        }
        let supplied = self
            .content_blocks
            .iter()
            .map(|block| block.id)
            .collect::<BTreeSet<_>>();
        if supplied.len() != self.content_blocks.len() || supplied != declared {
            return Err(IndexError::Invalid(
                "artifact content block manifest does not match metadata",
            ));
        }
        for block in &self.content_blocks {
            block
                .validate()
                .map_err(|_| IndexError::Invalid("artifact content block is invalid"))?;
            validate_blob_locator(&block.blob_locator)?;
        }
        Ok(())
    }
}

/// Opaque policy result. Artifact metadata, hashes, selectors, and locators are
/// deliberately absent until materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedArtifactUniverse {
    snapshot: CommitSeq,
    generation: u64,
    artifact_ids: BTreeSet<ArtifactId>,
    representation_ids: BTreeSet<RepresentationId>,
}

/// Materialized original artifact after authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedArtifact {
    pub artifact: Artifact,
    pub content_blocks: Vec<ContentBlock>,
}

/// Complete deterministic deletion closure for artifact-derived projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDeletionClosure {
    pub artifact_id: ArtifactId,
    pub representation_ids: Vec<RepresentationId>,
    pub blob_locators: Vec<BlobLocator>,
}

/// Self-verifying artifact/representation generation. It contains locators and
/// hashes, never the externally stored raw blob bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentArtifactGeneration {
    pub schema_version: u16,
    pub generation: u64,
    pub watermark: CommitSeq,
    pub payload_digest: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPayload {
    schema_version: u16,
    generation: u64,
    watermark: CommitSeq,
    artifacts: BTreeMap<ArtifactId, ArtifactProjection>,
    representations: BTreeMap<RepresentationId, ArtifactRepresentation>,
}

/// Policy-first artifact metadata store with snapshot-bound generations.
#[derive(Clone, Debug, Default)]
pub struct ArtifactIndex {
    artifacts: BTreeMap<ArtifactId, ArtifactProjection>,
    representations: BTreeMap<RepresentationId, ArtifactRepresentation>,
    artifact_routes: BTreeMap<ArtifactId, IndexPolicy>,
    representation_routes: BTreeMap<RepresentationId, IndexPolicy>,
    generation_watermarks: BTreeMap<u64, CommitSeq>,
    active_generation: u64,
}

impl ArtifactIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts immutable source metadata. Raw bytes stay behind blob locators.
    pub fn insert_artifact(&mut self, projection: ArtifactProjection) -> Result<()> {
        projection.validate()?;
        let id = projection.artifact.id;
        if self.artifacts.contains_key(&id) {
            return Err(IndexError::Invalid("artifact IDs are immutable"));
        }
        self.artifact_routes.insert(id, projection.policy.clone());
        self.artifacts.insert(id, projection);
        Ok(())
    }

    /// Inserts one immutable derived representation and proves source lineage.
    pub fn insert_representation(&mut self, representation: ArtifactRepresentation) -> Result<()> {
        representation.validate()?;
        representation.policy.validate()?;
        if self.representations.contains_key(&representation.id) {
            return Err(IndexError::Invalid(
                "artifact representation IDs are immutable",
            ));
        }
        let source = self
            .artifacts
            .get(&representation.artifact_id)
            .ok_or(IndexError::UnknownArtifact(representation.artifact_id))?;
        validate_representation_source(&representation, source)?;
        let id = representation.id;
        self.representation_routes
            .insert(id, representation.policy.clone());
        self.representations.insert(id, representation);
        Ok(())
    }

    /// Publishes a logical projection generation. Source and derived records
    /// newer than the watermark remain in the delta for future snapshots.
    pub fn publish_generation(
        &mut self,
        generation: u64,
        watermark: CommitSeq,
    ) -> Result<[u8; 32]> {
        if generation <= self.active_generation
            || self
                .generation_watermarks
                .values()
                .next_back()
                .is_some_and(|previous| watermark < *previous)
        {
            return Err(IndexError::StaleGeneration);
        }
        let artifacts = self
            .artifacts
            .iter()
            .filter(|(_, record)| record.projected_at <= watermark)
            .collect::<BTreeMap<_, _>>();
        let representations = self
            .representations
            .iter()
            .filter(|(_, record)| record.projected_at <= watermark)
            .collect::<BTreeMap<_, _>>();
        let bytes = serde_json::to_vec(&(generation, watermark, artifacts, representations))?;
        let digest = *blake3::hash(&bytes).as_bytes();
        self.generation_watermarks.insert(generation, watermark);
        self.active_generation = generation;
        Ok(digest)
    }

    /// Evaluates routing metadata before materializing any artifact-derived data.
    pub fn authorize(
        &self,
        principal: &IndexPrincipal,
        snapshot: CommitSeq,
    ) -> AuthorizedArtifactUniverse {
        let generation = self.generation_for(snapshot);
        let artifact_ids = self
            .artifact_routes
            .iter()
            .filter_map(|(id, policy)| {
                self.artifacts.get(id).and_then(|record| {
                    (record.projected_at <= snapshot
                        && record.tombstone_at.is_none_or(|deleted| deleted > snapshot)
                        && policy.authorizes(principal, snapshot))
                    .then_some(*id)
                })
            })
            .collect::<BTreeSet<_>>();
        let representation_ids = self
            .representation_routes
            .iter()
            .filter_map(|(id, policy)| {
                self.representations.get(id).and_then(|record| {
                    (artifact_ids.contains(&record.artifact_id)
                        && record.projected_at <= snapshot
                        && record.tombstone_at.is_none_or(|deleted| deleted > snapshot)
                        && policy.authorizes(principal, snapshot))
                    .then_some(*id)
                })
            })
            .collect();
        AuthorizedArtifactUniverse {
            snapshot,
            generation,
            artifact_ids,
            representation_ids,
        }
    }

    /// Materializes source metadata and locators only after authorization.
    pub fn artifact(
        &self,
        universe: &AuthorizedArtifactUniverse,
        id: ArtifactId,
    ) -> Result<AuthorizedArtifact> {
        self.validate_universe(universe)?;
        if !universe.artifact_ids.contains(&id) {
            return Err(IndexError::UnknownArtifact(id));
        }
        let record = self
            .artifacts
            .get(&id)
            .ok_or(IndexError::UnknownArtifact(id))?;
        Ok(AuthorizedArtifact {
            artifact: record.artifact.clone(),
            content_blocks: record.content_blocks.clone(),
        })
    }

    /// Materializes a derived record only after both source and derived policy pass.
    pub fn representation(
        &self,
        universe: &AuthorizedArtifactUniverse,
        id: RepresentationId,
    ) -> Result<ArtifactRepresentation> {
        self.validate_universe(universe)?;
        if !universe.representation_ids.contains(&id) {
            return Err(IndexError::UnknownRepresentation(id));
        }
        self.representations
            .get(&id)
            .cloned()
            .ok_or(IndexError::UnknownRepresentation(id))
    }

    /// Tombstones the original and every representation derived from it.
    pub fn tombstone_artifact(
        &mut self,
        id: ArtifactId,
        at: CommitSeq,
    ) -> Result<ArtifactDeletionClosure> {
        let record = self
            .artifacts
            .get_mut(&id)
            .ok_or(IndexError::UnknownArtifact(id))?;
        if at < record.projected_at {
            return Err(IndexError::Invalid(
                "artifact tombstone precedes projection",
            ));
        }
        record.tombstone_at = Some(at);
        if let Some(route) = self.artifact_routes.get_mut(&id) {
            route.deleted_at = Some(at);
        }
        let mut representation_ids = Vec::new();
        let mut blob_locators = record
            .content_blocks
            .iter()
            .map(|block| block.blob_locator.clone())
            .collect::<Vec<_>>();
        for (representation_id, representation) in &mut self.representations {
            if representation.artifact_id == id {
                representation.tombstone_at = Some(at);
                if let Some(route) = self.representation_routes.get_mut(representation_id) {
                    route.deleted_at = Some(at);
                }
                representation_ids.push(*representation_id);
                blob_locators.push(representation.content_block.blob_locator.clone());
            }
        }
        representation_ids.sort_unstable();
        blob_locators.sort_unstable();
        blob_locators.dedup();
        Ok(ArtifactDeletionClosure {
            artifact_id: id,
            representation_ids,
            blob_locators,
        })
    }

    #[must_use]
    pub fn generation_watermark(&self, generation: u64) -> Option<CommitSeq> {
        self.generation_watermarks.get(&generation).copied()
    }

    /// Exports one self-verifying logical generation for staged persistence.
    pub fn export_generation(&self, generation: u64) -> Result<PersistentArtifactGeneration> {
        let watermark = self
            .generation_watermarks
            .get(&generation)
            .copied()
            .ok_or(IndexError::GenerationNotReady(generation))?;
        let payload = ArtifactPayload {
            schema_version: 1,
            generation,
            watermark,
            artifacts: self
                .artifacts
                .iter()
                .filter(|(_, record)| record.projected_at <= watermark)
                .map(|(id, record)| (*id, record.clone()))
                .collect(),
            representations: self
                .representations
                .iter()
                .filter(|(_, record)| record.projected_at <= watermark)
                .map(|(id, record)| (*id, record.clone()))
                .collect(),
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(PersistentArtifactGeneration {
            schema_version: 1,
            generation,
            watermark,
            payload_digest: *blake3::hash(&bytes).as_bytes(),
            payload: bytes,
        })
    }

    /// Restores a verified artifact generation into an empty index.
    pub fn import_generation(&mut self, bundle: PersistentArtifactGeneration) -> Result<()> {
        if !self.artifacts.is_empty()
            || !self.representations.is_empty()
            || !self.generation_watermarks.is_empty()
        {
            return Err(IndexError::Invalid(
                "artifact generation restore target must be empty",
            ));
        }
        if bundle.schema_version != 1
            || *blake3::hash(&bundle.payload).as_bytes() != bundle.payload_digest
        {
            return Err(IndexError::Invalid(
                "artifact generation schema or digest mismatch",
            ));
        }
        let payload: ArtifactPayload = serde_json::from_slice(&bundle.payload)?;
        if payload.schema_version != bundle.schema_version
            || payload.generation != bundle.generation
            || payload.watermark != bundle.watermark
        {
            return Err(IndexError::Invalid("artifact generation manifest mismatch"));
        }
        for projection in payload.artifacts.values() {
            projection.validate()?;
            if projection.projected_at > payload.watermark {
                return Err(IndexError::FutureWatermark {
                    watermark: projection.projected_at,
                    snapshot: payload.watermark,
                });
            }
        }
        for representation in payload.representations.values() {
            representation.validate()?;
            let source = payload
                .artifacts
                .get(&representation.artifact_id)
                .ok_or(IndexError::UnknownArtifact(representation.artifact_id))?;
            validate_representation_source(representation, source)?;
            if representation.projected_at > payload.watermark {
                return Err(IndexError::FutureWatermark {
                    watermark: representation.projected_at,
                    snapshot: payload.watermark,
                });
            }
        }
        self.artifact_routes = payload
            .artifacts
            .iter()
            .map(|(id, record)| (*id, record.policy.clone()))
            .collect();
        self.representation_routes = payload
            .representations
            .iter()
            .map(|(id, record)| (*id, record.policy.clone()))
            .collect();
        self.artifacts = payload.artifacts;
        self.representations = payload.representations;
        self.generation_watermarks
            .insert(payload.generation, payload.watermark);
        self.active_generation = payload.generation;
        Ok(())
    }

    fn generation_for(&self, snapshot: CommitSeq) -> u64 {
        self.generation_watermarks
            .iter()
            .rev()
            .find_map(|(generation, watermark)| (*watermark <= snapshot).then_some(*generation))
            .unwrap_or(0)
    }

    fn validate_universe(&self, universe: &AuthorizedArtifactUniverse) -> Result<()> {
        if self.generation_for(universe.snapshot) != universe.generation {
            return Err(IndexError::StaleAuthorization);
        }
        Ok(())
    }
}

fn validate_blob_locator(locator: &BlobLocator) -> Result<()> {
    let Some((scheme, remainder)) = locator.0.split_once(':') else {
        return Err(IndexError::Invalid(
            "blob locator must contain an explicit versioned scheme",
        ));
    };
    if scheme.trim().is_empty() || remainder.trim().is_empty() {
        return Err(IndexError::Invalid(
            "blob locator scheme or target is blank",
        ));
    }
    Ok(())
}

fn policy_matches_envelope(policy: &IndexPolicy, envelope: &SemanticEnvelope) -> bool {
    let envelope_owners = envelope
        .ownership
        .owners
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let envelope_scopes = envelope
        .scopes
        .iter()
        .map(|scope| scope.id)
        .collect::<BTreeSet<_>>();
    policy.owners == envelope_owners
        && policy
            .purposes
            .is_subset(&envelope.ownership.allowed_purposes)
        && envelope_scopes.is_subset(&policy.scopes)
        && policy.classification >= envelope.security.classification
        && envelope.security.labels.is_subset(&policy.security_labels)
        && envelope
            .security
            .required_compartments
            .is_subset(&policy.required_compartments)
        && (!policy.allow_external_processing || envelope.security.allow_external_processing)
        && (!policy.retrieve_allowed || envelope.use_policy.retrieve == PolicyDecision::Allow)
}

fn validate_representation_source(
    representation: &ArtifactRepresentation,
    source: &ArtifactProjection,
) -> Result<()> {
    let source_block = source
        .content_blocks
        .iter()
        .find(|block| block.id == representation.source_content_block_id)
        .ok_or(IndexError::Invalid(
            "representation source content block is absent",
        ))?;
    if source_block.content_hash != representation.source_content_hash {
        return Err(IndexError::Invalid(
            "representation source hash does not match original content block",
        ));
    }
    representation
        .envelope
        .validate_derived_from(&source.artifact.envelope)
        .map_err(|_| {
            IndexError::Invalid("derived representation semantic envelope broadens original policy")
        })?;
    if !policy_matches_envelope(&representation.policy, &representation.envelope) {
        return Err(IndexError::Invalid(
            "representation projection policy contradicts semantic envelope",
        ));
    }
    if !representation.policy.is_restriction_of(&source.policy) {
        return Err(IndexError::Invalid(
            "derived representation policy broadens original artifact policy",
        ));
    }
    Ok(())
}

impl IndexPolicy {
    fn is_restriction_of(&self, source: &Self) -> bool {
        self.workspace_id == source.workspace_id
            && self.memory_spaces.is_subset(&source.memory_spaces)
            && (source.subjects.is_empty()
                || (!self.subjects.is_empty() && self.subjects.is_subset(&source.subjects)))
            && self.owners == source.owners
            && source.scopes.is_subset(&self.scopes)
            && self.purposes.is_subset(&source.purposes)
            && self.classification >= source.classification
            && source.security_labels.is_subset(&self.security_labels)
            && source
                .required_compartments
                .is_subset(&self.required_compartments)
            && (!self.allow_external_processing || source.allow_external_processing)
            && (!self.retrieve_allowed || source.retrieve_allowed)
            && match (self.deleted_at, source.deleted_at) {
                (_, None) => true,
                (Some(derived), Some(original)) => derived <= original,
                (None, Some(_)) => false,
            }
    }
}

/// Metadata surfaced when an external locator cannot currently be resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissingArtifactWarning {
    pub artifact_id: ArtifactId,
    pub content_block_id: ContentBlockId,
    pub observed_at: TimestampMicros,
}
