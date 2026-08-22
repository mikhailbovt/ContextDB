//! Lossless, validated adapters from the canonical `contextdb-core` model into the generic
//! reference store. The generic shell exists only to keep the oracle inspectable; public semantic
//! writes should enter through these adapters rather than inventing a second domain model.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    AccessCapability, Audience, ClaimRecord, ConflictSetRecord, ConsentStatus, EdgeRecord,
    LifecycleState, NodeRecord, ObservationUnit, PolicyDecision, Purpose, SecurityClassification,
    SemanticEnvelope, SemanticMutationSet, TypedMemoryMutation, Validate,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::error::{ReferenceError, Result};
use crate::model::{
    AccessLabel, Consent, Lifecycle, LogicalRecord, ObservationInput, RecordKind, SemanticLinks,
    Sensitivity, ValidTime,
};

/// Converts a validated canonical node record and one selected revision into an oracle record.
pub fn node_revision(record: &NodeRecord, revision_index: usize) -> Result<LogicalRecord> {
    record.validate()?;
    let revision = record
        .revisions
        .get(revision_index)
        .ok_or_else(|| missing_revision("node", revision_index))?;
    Ok(LogicalRecord {
        id: record.node.id.to_string(),
        kind: RecordKind::Node,
        access: access_label(&record.node.workspace_id.to_string(), &revision.envelope),
        valid_time: valid_time(revision.temporal.valid_time),
        lifecycle: lifecycle(revision.epistemic.lifecycle),
        links: SemanticLinks {
            evidence: strings(revision.evidence.iter()),
            ..SemanticLinks::default()
        },
        value: to_value(record)?,
        search_text: Some(revision.canonical_name.clone()),
        vector: None,
        attributes: revision.attributes.clone(),
    })
}

/// Converts a validated canonical claim record and one selected revision into an oracle record.
pub fn claim_revision(
    record: &ClaimRecord,
    revision_index: usize,
    single_valued: bool,
) -> Result<LogicalRecord> {
    record.validate()?;
    let revision = record
        .revisions
        .get(revision_index)
        .ok_or_else(|| missing_revision("claim", revision_index))?;
    Ok(LogicalRecord {
        id: record.claim.id.to_string(),
        kind: RecordKind::Claim,
        access: access_label(&record.claim.workspace_id.to_string(), &revision.envelope),
        valid_time: valid_time(revision.temporal.valid_time),
        lifecycle: lifecycle(revision.epistemic.lifecycle),
        links: SemanticLinks {
            subject: Some(record.claim.subject.to_string()),
            predicate: Some(record.claim.predicate.to_string()),
            conflict_set: revision
                .epistemic
                .conflict
                .set_id()
                .map(|id| id.to_string()),
            supersedes: strings(revision.supersedes.iter()),
            evidence: strings(revision.evidence.iter()),
            single_valued,
            ..SemanticLinks::default()
        },
        value: to_value(record)?,
        search_text: lexical_projection(&revision.object),
        vector: None,
        attributes: BTreeMap::new(),
    })
}

/// Converts a validated canonical edge record and one selected revision into an oracle record.
pub fn edge_revision(record: &EdgeRecord, revision_index: usize) -> Result<LogicalRecord> {
    record.validate()?;
    let revision = record
        .revisions
        .get(revision_index)
        .ok_or_else(|| missing_revision("edge", revision_index))?;
    Ok(LogicalRecord {
        id: record.edge.id.to_string(),
        kind: RecordKind::Edge,
        access: access_label(&record.edge.workspace_id.to_string(), &revision.envelope),
        valid_time: valid_time(revision.temporal.valid_time),
        lifecycle: lifecycle(revision.epistemic.lifecycle),
        links: SemanticLinks {
            source: Some(record.edge.source.to_string()),
            target: Some(record.edge.target.to_string()),
            predicate: Some(record.edge.edge_type.to_string()),
            evidence: strings(revision.evidence.iter()),
            ..SemanticLinks::default()
        },
        value: to_value(record)?,
        search_text: None,
        vector: None,
        attributes: revision.attributes.clone(),
    })
}

/// Converts a validated canonical conflict set and one selected revision into an oracle record.
pub fn conflict_revision(
    record: &ConflictSetRecord,
    revision_index: usize,
) -> Result<LogicalRecord> {
    record.validate()?;
    let revision = record
        .revisions
        .get(revision_index)
        .ok_or_else(|| missing_revision("conflict set", revision_index))?;
    Ok(LogicalRecord {
        id: record.conflict.id.to_string(),
        kind: RecordKind::Conflict,
        access: access_label(
            &record.conflict.workspace_id.to_string(),
            &revision.envelope,
        ),
        valid_time: ValidTime::UNBOUNDED,
        lifecycle: Lifecycle::Active,
        links: SemanticLinks {
            subject: Some(record.conflict.subject.to_string()),
            predicate: Some(record.conflict.predicate.to_string()),
            evidence: strings(revision.evidence.iter()),
            conflict_members: strings(revision.members.iter()),
            ..SemanticLinks::default()
        },
        value: to_value(record)?,
        search_text: None,
        vector: None,
        attributes: BTreeMap::new(),
    })
}

/// Converts an immutable canonical observation into the reference observation gateway contract.
///
/// `idempotency_key` is host transport metadata and intentionally is not part of
/// `contextdb-core::ObservationUnit`.
pub fn observation(
    observation: &ObservationUnit,
    idempotency_key: impl Into<String>,
) -> Result<ObservationInput> {
    observation.validate()?;
    Ok(ObservationInput {
        idempotency_key: idempotency_key.into(),
        observation_id: observation.id.to_string(),
        access: access_label(&observation.workspace_id.to_string(), &observation.envelope),
        metadata: BTreeMap::from([
            ("source_id".to_owned(), json!(observation.source_id)),
            ("memory_spaces".to_owned(), json!(observation.memory_spaces)),
            ("participants".to_owned(), json!(observation.participants)),
            ("occurred_at".to_owned(), json!(observation.occurred_at)),
            ("observed_at".to_owned(), json!(observation.observed_at)),
            ("recorded_at".to_owned(), json!(observation.recorded_at)),
        ]),
        content: to_value(observation)?,
    })
}

/// Converts one validated canonical mutation set into ordered generic oracle writes.
/// Stable identities and mutable revisions are paired by ID; typed memory values retain their
/// canonical JSON shape and common policy envelope.
pub fn mutation_records(
    mutation: &SemanticMutationSet,
    existing_records: &BTreeMap<String, (RecordKind, Value)>,
) -> Result<Vec<LogicalRecord>> {
    mutation.validate()?;
    let mut records = Vec::new();
    for revision in &mutation.node_revisions {
        let owned_node = mutation
            .node_creates
            .iter()
            .find(|node| node.id == revision.node_id)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| {
                existing_identity(
                    existing_records,
                    revision.node_id,
                    RecordKind::Node,
                    "identity",
                )
            })?;
        let node = &owned_node;
        records.push(LogicalRecord {
            id: node.id.to_string(),
            kind: RecordKind::Node,
            access: access_label(&node.workspace_id.to_string(), &revision.envelope),
            valid_time: valid_time(revision.temporal.valid_time),
            lifecycle: lifecycle(revision.epistemic.lifecycle),
            links: SemanticLinks {
                evidence: strings(revision.evidence.iter()),
                ..SemanticLinks::default()
            },
            value: json!({"identity": node, "revision": revision}),
            search_text: Some(revision.canonical_name.clone()),
            vector: None,
            attributes: revision.attributes.clone(),
        });
    }
    for revision in &mutation.claim_revisions {
        let owned_claim = mutation
            .claim_creates
            .iter()
            .find(|claim| claim.id == revision.claim_id)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| {
                existing_identity(
                    existing_records,
                    revision.claim_id,
                    RecordKind::Claim,
                    "identity",
                )
            })?;
        let claim = &owned_claim;
        records.push(LogicalRecord {
            id: claim.id.to_string(),
            kind: RecordKind::Claim,
            access: access_label(&claim.workspace_id.to_string(), &revision.envelope),
            valid_time: valid_time(revision.temporal.valid_time),
            lifecycle: lifecycle(revision.epistemic.lifecycle),
            links: SemanticLinks {
                subject: Some(claim.subject.to_string()),
                predicate: Some(claim.predicate.to_string()),
                conflict_set: revision
                    .epistemic
                    .conflict
                    .set_id()
                    .map(|id| id.to_string()),
                supersedes: strings(revision.supersedes.iter()),
                evidence: strings(revision.evidence.iter()),
                single_valued: false,
                ..SemanticLinks::default()
            },
            value: json!({"identity": claim, "revision": revision}),
            search_text: lexical_projection(&revision.object),
            vector: None,
            attributes: BTreeMap::new(),
        });
    }
    for revision in &mutation.edge_revisions {
        let owned_edge = mutation
            .edge_creates
            .iter()
            .find(|edge| edge.id == revision.edge_id)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| {
                existing_identity(
                    existing_records,
                    revision.edge_id,
                    RecordKind::Edge,
                    "identity",
                )
            })?;
        let edge = &owned_edge;
        records.push(LogicalRecord {
            id: edge.id.to_string(),
            kind: RecordKind::Edge,
            access: access_label(&edge.workspace_id.to_string(), &revision.envelope),
            valid_time: valid_time(revision.temporal.valid_time),
            lifecycle: lifecycle(revision.epistemic.lifecycle),
            links: SemanticLinks {
                source: Some(edge.source.to_string()),
                target: Some(edge.target.to_string()),
                predicate: Some(edge.edge_type.to_string()),
                evidence: strings(revision.evidence.iter()),
                ..SemanticLinks::default()
            },
            value: json!({"identity": edge, "revision": revision}),
            search_text: None,
            vector: None,
            attributes: revision.attributes.clone(),
        });
    }
    for revision in &mutation.conflict_revisions {
        let owned_conflict = mutation
            .conflict_creates
            .iter()
            .find(|conflict| conflict.id == revision.conflict_set_id)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| {
                existing_identity(
                    existing_records,
                    revision.conflict_set_id,
                    RecordKind::Conflict,
                    "identity",
                )
            })?;
        let conflict = &owned_conflict;
        records.push(LogicalRecord {
            id: conflict.id.to_string(),
            kind: RecordKind::Conflict,
            access: access_label(&conflict.workspace_id.to_string(), &revision.envelope),
            valid_time: ValidTime::UNBOUNDED,
            lifecycle: Lifecycle::Active,
            links: SemanticLinks {
                subject: Some(conflict.subject.to_string()),
                predicate: Some(conflict.predicate.to_string()),
                evidence: strings(revision.evidence.iter()),
                conflict_members: strings(revision.members.iter()),
                ..SemanticLinks::default()
            },
            value: json!({"identity": conflict, "revision": revision}),
            search_text: None,
            vector: None,
            attributes: BTreeMap::new(),
        });
    }
    for typed in &mutation.typed_memory_writes {
        records.push(typed_memory(typed)?);
    }
    for candidate in &mutation.candidate_writes {
        records.push(LogicalRecord {
            id: candidate.id.to_string(),
            kind: RecordKind::Candidate,
            access: access_label(&workspace_scope(&candidate.envelope), &candidate.envelope),
            valid_time: ValidTime::UNBOUNDED,
            lifecycle: Lifecycle::Active,
            links: SemanticLinks {
                evidence: strings(candidate.evidence_spans.iter()),
                ..SemanticLinks::default()
            },
            value: to_value(candidate)?,
            search_text: None,
            vector: None,
            attributes: BTreeMap::new(),
        });
    }
    for episode in &mutation.episode_view_writes {
        records.push(LogicalRecord {
            id: episode.id.to_string(),
            kind: RecordKind::SemanticObject,
            access: access_label(&episode.workspace_id.to_string(), &episode.envelope),
            valid_time: valid_time(episode.occurred_at),
            lifecycle: Lifecycle::Active,
            links: SemanticLinks::default(),
            value: to_value(episode)?,
            search_text: None,
            vector: None,
            attributes: BTreeMap::new(),
        });
    }
    Ok(records)
}

fn existing_identity<T>(
    existing_records: &BTreeMap<String, (RecordKind, Value)>,
    id: impl ToString,
    expected_kind: RecordKind,
    field: &str,
) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let id = id.to_string();
    let (kind, value) = existing_records
        .get(&id)
        .ok_or_else(|| ReferenceError::Invariant(format!("missing stable identity {id}")))?;
    if *kind != expected_kind {
        return Err(ReferenceError::Invariant(format!(
            "stable identity {id} has the wrong record kind"
        )));
    }
    serde_json::from_value(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| ReferenceError::Invariant(format!("record {id} lacks {field}")))?,
    )
    .map_err(|error| ReferenceError::Serialization(error.to_string()))
}

fn typed_memory(value: &TypedMemoryMutation) -> Result<LogicalRecord> {
    let (node_id, workspace, envelope, lifecycle_state, valid, evidence) = match value {
        TypedMemoryMutation::Preference(item) => header_parts(&item.header),
        TypedMemoryMutation::Boundary(item) => header_parts(&item.header),
        TypedMemoryMutation::Goal(item) => header_parts(&item.header),
        TypedMemoryMutation::Commitment(item) => header_parts(&item.header),
        TypedMemoryMutation::Procedure(item) => header_parts(&item.header),
        TypedMemoryMutation::Relationship(item) => header_parts(&item.header),
        TypedMemoryMutation::SharedReference(item) => header_parts(&item.header),
        TypedMemoryMutation::SelfModel(item) => header_parts(&item.header),
        TypedMemoryMutation::InteractionSignal(item) => header_parts(&item.header),
        TypedMemoryMutation::ContinuityProfile(item) => {
            return Ok(LogicalRecord {
                id: item.id.to_string(),
                kind: RecordKind::SemanticObject,
                access: access_label(&item.workspace_id.to_string(), &item.envelope),
                valid_time: ValidTime::UNBOUNDED,
                lifecycle: Lifecycle::Active,
                links: SemanticLinks::default(),
                value: to_value(value)?,
                search_text: None,
                vector: None,
                attributes: BTreeMap::new(),
            });
        }
    };
    Ok(LogicalRecord {
        id: node_id,
        kind: RecordKind::SemanticObject,
        access: access_label(&workspace, envelope),
        valid_time: valid,
        lifecycle: lifecycle(lifecycle_state),
        links: SemanticLinks {
            evidence,
            ..SemanticLinks::default()
        },
        value: to_value(value)?,
        search_text: None,
        vector: None,
        attributes: BTreeMap::new(),
    })
}

fn header_parts(
    header: &contextdb_core::MemoryRevisionHeader,
) -> (
    String,
    String,
    &SemanticEnvelope,
    LifecycleState,
    ValidTime,
    BTreeSet<String>,
) {
    (
        header.node_id.to_string(),
        workspace_scope(&header.envelope),
        &header.envelope,
        header.epistemic.lifecycle,
        valid_time(header.temporal.valid_time),
        strings(header.evidence.iter()),
    )
}

fn workspace_scope(envelope: &SemanticEnvelope) -> String {
    envelope
        .scopes
        .iter()
        .find(|scope| scope.kind == contextdb_core::ScopeKind::Workspace)
        .map_or_else(
            || "core-unspecified-workspace".to_owned(),
            |scope| scope.id.to_string(),
        )
}

fn access_label(workspace: &str, envelope: &SemanticEnvelope) -> AccessLabel {
    let owners = strings(envelope.ownership.owners.iter());
    let mut audience = BTreeSet::new();
    let mut audience_purpose_grants = BTreeMap::<String, BTreeSet<String>>::new();
    for grant in &envelope.ownership.audience_grants {
        if !grant.capabilities.contains(&AccessCapability::Retrieve) {
            continue;
        }
        let key = audience_key(&grant.audience);
        audience.insert(key.clone());
        audience_purpose_grants
            .entry(key)
            .or_default()
            .extend(grant.purposes.iter().map(purpose));
    }
    AccessLabel {
        workspace: workspace.to_owned(),
        scopes: envelope
            .scopes
            .iter()
            .map(|scope| scope.id.to_string())
            .collect(),
        owners,
        audience,
        audience_purpose_grants,
        purposes: envelope
            .ownership
            .allowed_purposes
            .iter()
            .map(purpose)
            .collect(),
        sensitivity: match envelope.security.classification {
            SecurityClassification::Public => Sensitivity::Public,
            SecurityClassification::Internal => Sensitivity::Internal,
            SecurityClassification::Confidential => Sensitivity::Private,
            SecurityClassification::Restricted => Sensitivity::Restricted,
        },
        consent: consent(envelope),
        retrievable: envelope.use_policy.retrieve == PolicyDecision::Allow,
    }
}

fn consent(envelope: &SemanticEnvelope) -> Consent {
    if !envelope.consent.required {
        return Consent::Granted;
    }
    if envelope
        .consent
        .decisions
        .iter()
        .any(|decision| decision.status == ConsentStatus::Denied)
    {
        Consent::Denied
    } else if !envelope.consent.decisions.is_empty()
        && envelope
            .consent
            .decisions
            .iter()
            .all(|decision| decision.status == ConsentStatus::Granted)
    {
        Consent::Granted
    } else {
        Consent::Unknown
    }
}

fn lifecycle(value: LifecycleState) -> Lifecycle {
    match value {
        LifecycleState::Active => Lifecycle::Active,
        LifecycleState::Historical | LifecycleState::Superseded => Lifecycle::Superseded,
        LifecycleState::Retracted => Lifecycle::Retracted,
        LifecycleState::Suppressed | LifecycleState::Deleted => Lifecycle::Suppressed,
    }
}

fn valid_time(value: contextdb_core::TimeRange) -> ValidTime {
    ValidTime {
        from: Some(i128::from(value.start.0)),
        to: value.end.map(|end| i128::from(end.0)),
    }
}

fn audience_key(audience: &Audience) -> String {
    match audience {
        Audience::Public => "*".to_owned(),
        Audience::Owner => "@owner".to_owned(),
        Audience::Subject { id } => id.to_string(),
        Audience::Group { id } => format!("group:{id}"),
        Audience::MemorySpace { id } => format!("space:{id}"),
    }
}

fn purpose(value: &Purpose) -> String {
    match value {
        Purpose::Conversation => "conversation".to_owned(),
        Purpose::Personalisation => "personalisation".to_owned(),
        Purpose::TaskExecution => "task_execution".to_owned(),
        Purpose::KnowledgeRecall => "knowledge_recall".to_owned(),
        Purpose::Safety => "safety".to_owned(),
        Purpose::Audit => "audit".to_owned(),
        Purpose::Export => "export".to_owned(),
        Purpose::Migration => "migration".to_owned(),
        Purpose::UserSpecified(label) => format!("user:{label}"),
    }
}

fn lexical_projection(object: &contextdb_core::ClaimObject) -> Option<String> {
    match object {
        contextdb_core::ClaimObject::String(value) | contextdb_core::ClaimObject::Uri(value) => {
            Some(value.clone())
        }
        contextdb_core::ClaimObject::Quantity { value, unit } => Some(format!("{value} {unit}")),
        contextdb_core::ClaimObject::Integer(value) => Some(value.to_string()),
        contextdb_core::ClaimObject::Float(value) => Some(value.to_string()),
        contextdb_core::ClaimObject::Boolean(value) => Some(value.to_string()),
        contextdb_core::ClaimObject::Node(value) => Some(value.to_string()),
        contextdb_core::ClaimObject::Timestamp(value) => Some(value.0.to_string()),
        contextdb_core::ClaimObject::TimeRange(_)
        | contextdb_core::ClaimObject::CodeLocation { .. }
        | contextdb_core::ClaimObject::Structured(_) => None,
    }
}

fn strings<'a, T>(values: impl Iterator<Item = &'a T>) -> BTreeSet<String>
where
    T: ToString + 'a,
{
    values.map(ToString::to_string).collect()
}

fn to_value<T: Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| ReferenceError::Serialization(error.to_string()))
}

fn missing_revision(kind: &'static str, index: usize) -> ReferenceError {
    ReferenceError::Invariant(format!("{kind} revision index {index} is out of range"))
}
