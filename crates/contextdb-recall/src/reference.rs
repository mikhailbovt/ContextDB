use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{CommitRange, CommitSeq, PolicyDecision};
use contextdb_reference::{
    Consent, ContextDb, MaterializedRecord, Principal, RecordKind, Sensitivity, Snapshot,
};
use serde_json::Value;

use crate::{
    AccessConsent, AccessRule, AuthorizedCorpus, DocumentId, DocumentPerspective,
    DocumentTemporalState, DocumentUseProfile, ProviderDocument, ProviderEvidence,
    ProviderRelation, ProviderRequest, ProviderSnapshot, RecallConflictState, RecallDocument,
    RecallDocumentKind, RecallError, RecallProvider, RecallRelation, RecallRelationKind,
    RecallSensitivity, RecallWatermarks, Result, SuppliedVector, bounded_time,
};

/// Adapter over the policy-first in-memory correctness oracle.
#[derive(Debug)]
pub struct ReferenceProvider<'a> {
    pub database: &'a ContextDb,
}

impl RecallProvider for ReferenceProvider<'_> {
    fn snapshot(&self, at_commit: Option<u64>) -> Result<ProviderSnapshot> {
        let snapshot = match at_commit {
            Some(commit) => self.database.snapshot_at(commit),
            None => self.database.snapshot(),
        }
        .map_err(reference_error)?;
        let watermarks = self.database.watermarks().map_err(reference_error)?;
        provider_snapshot(&snapshot, &watermarks)
    }

    fn authorized_corpus(&self, request: &ProviderRequest) -> Result<AuthorizedCorpus> {
        let snapshot = self
            .database
            .snapshot_at(request.snapshot.commit_seq)
            .map_err(reference_error)?;
        if snapshot.database_id != request.snapshot.database_id {
            return Err(RecallError::Provider(
                "reference snapshot database differs from provider request".to_owned(),
            ));
        }
        let principal = reference_principal(&request.principal);
        let mut documents = Vec::new();
        let mut relations = Vec::new();
        // Each scan performs reference authorization before materialization. We
        // then retain the label and run the crate's sealed-corpus gate again.
        for kind in [
            RecordKind::Node,
            RecordKind::Claim,
            RecordKind::Edge,
            RecordKind::Conflict,
            RecordKind::Evidence,
            // Candidate is an audit/quarantine family, never an ordinary
            // recall family. Authorized promotion materializes a separate
            // typed Claim/Node/SemanticObject; generic attributes or a forged
            // candidate payload therefore cannot opt model output into use.
            RecordKind::SemanticObject,
            RecordKind::RuntimeState,
            RecordKind::DomainExtension,
        ] {
            let records = self
                .database
                .scan_kind(kind, &snapshot, &principal)
                .map_err(reference_error)?;
            for record in records.value {
                if record.revision.record.kind == RecordKind::Edge
                    && let Some(relation) = reference_relation(&record)?
                {
                    relations.push(relation);
                }
                documents.push(reference_document(record)?);
            }
        }
        AuthorizedCorpus::authorize(request, documents, relations)
    }
}

fn provider_snapshot(
    snapshot: &Snapshot,
    watermarks: &contextdb_reference::Watermarks,
) -> Result<ProviderSnapshot> {
    let snapshot = ProviderSnapshot {
        database_id: snapshot.database_id.clone(),
        commit_seq: snapshot.commit_seq,
        watermarks: RecallWatermarks {
            journal: watermarks.journal.min(snapshot.commit_seq),
            semantic: watermarks.semantic.min(snapshot.commit_seq),
            lexical: watermarks.lexical.min(snapshot.commit_seq),
            vector: BTreeMap::from([(
                "reference-full-precision".to_owned(),
                watermarks.vector.min(snapshot.commit_seq),
            )]),
            graph: watermarks.graph.min(snapshot.commit_seq),
            hierarchy: BTreeMap::new(),
        },
    };
    snapshot.validate()?;
    Ok(snapshot)
}

fn reference_principal(principal: &crate::RecallPrincipal) -> Principal {
    Principal {
        subject: principal.subject.clone(),
        audiences: principal.audiences.clone(),
        workspace: principal.workspace.clone(),
        scopes: principal.scopes.clone(),
        purpose: principal.purpose.clone(),
        clearance: match principal.clearance {
            RecallSensitivity::Public => Sensitivity::Public,
            RecallSensitivity::Internal => Sensitivity::Internal,
            RecallSensitivity::Confidential => Sensitivity::Private,
            RecallSensitivity::Restricted => Sensitivity::Restricted,
        },
    }
}

fn reference_document(record: MaterializedRecord) -> Result<ProviderDocument> {
    let revision = &record.revision;
    let metadata = &revision.record;
    let text = record
        .content
        .search_text
        .clone()
        .unwrap_or_else(|| compact_json(&record.content.value));
    let facets = string_set(record.content.attributes.get("facets"));
    let subjects = metadata
        .links
        .subject
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let participants = string_set(record.content.attributes.get("participants"));
    let aliases = string_vec(record.content.attributes.get("aliases"));
    let canonical_name = record
        .content
        .attributes
        .get("canonical_name")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| record.content.search_text.clone());
    let record_access = access_rule(&metadata.access);
    let evidence = metadata
        .links
        .evidence
        .iter()
        .map(|id| ProviderEvidence {
            access: record_access.clone(),
            evidence: crate::RecallEvidence {
                id: id.clone(),
                source_observation: None,
                excerpt: None,
                primary: true,
                trust: 1.0,
                estimated_tokens: 1,
            },
        })
        .collect::<Vec<_>>();
    let conflict =
        metadata
            .links
            .conflict_set
            .as_ref()
            .map_or(RecallConflictState::None, |set_id| {
                RecallConflictState::Unresolved {
                    set_id: set_id.clone(),
                }
            });
    let valid_time = bounded_time(metadata.valid_time.from, metadata.valid_time.to)?;
    let transaction_time = CommitRange::new(
        CommitSeq::new(revision.transaction_from),
        revision.transaction_to.map(CommitSeq::new),
    )
    .map_err(|error| RecallError::Provider(error.to_string()))?;
    let estimated_tokens =
        u32::try_from(text.chars().count().div_ceil(4).max(1)).unwrap_or(u32::MAX);
    let vector = record.content.vector.map(|values| SuppliedVector {
        space: "reference-full-precision".to_owned(),
        values,
    });
    let document = RecallDocument {
        id: DocumentId::new(revision.id.clone())?,
        kind: document_kind(metadata.kind),
        canonical_name,
        aliases,
        text,
        facets,
        subjects,
        participants,
        active_keys: metadata
            .links
            .source
            .iter()
            .chain(metadata.links.target.iter())
            .cloned()
            .collect(),
        temporal: DocumentTemporalState {
            valid_time,
            transaction_time,
        },
        perspective: DocumentPerspective {
            knower: None,
            narrator: None,
            role: "reference_materialized".to_owned(),
        },
        conflict,
        evidence: Vec::new(),
        vector,
        source_trust: 1.0,
        importance: 0.5,
        estimated_tokens,
        use_profile: DocumentUseProfile {
            influence: PolicyDecision::Allow,
            mention: PolicyDecision::Conditional,
            external_model_use: PolicyDecision::Conditional,
            shared_with_principal: true,
            personal_detail: false,
            constraint_only: false,
            style_only: false,
        },
    };
    document.validate()?;
    Ok(ProviderDocument {
        access: record_access,
        document,
        evidence,
    })
}

fn reference_relation(record: &MaterializedRecord) -> Result<Option<ProviderRelation>> {
    let links = &record.revision.record.links;
    let (Some(source), Some(target)) = (&links.source, &links.target) else {
        return Ok(None);
    };
    let valid_time = bounded_time(
        record.revision.record.valid_time.from,
        record.revision.record.valid_time.to,
    )?;
    Ok(Some(ProviderRelation {
        access: access_rule(&record.revision.record.access),
        relation: RecallRelation {
            id: record.revision.id.clone(),
            source: DocumentId::new(source.clone())?,
            target: DocumentId::new(target.clone())?,
            kind: links
                .predicate
                .as_ref()
                .map_or(RecallRelationKind::RelatedTo, |predicate| {
                    RecallRelationKind::Domain(predicate.clone())
                }),
            weight: 1.0,
            valid_time,
            trust: 1.0,
        },
    }))
}

fn access_rule(label: &contextdb_reference::AccessLabel) -> AccessRule {
    let mut grants = label.audience_purpose_grants.clone();
    if grants.is_empty() {
        let purposes = if label.purposes.is_empty() {
            BTreeSet::from(["*".to_owned()])
        } else {
            label.purposes.clone()
        };
        for audience in label.audience.iter().chain(label.owners.iter()) {
            grants.insert(audience.clone(), purposes.clone());
        }
        if !label.owners.is_empty() {
            grants.insert("@owner".to_owned(), purposes);
        }
    }
    AccessRule {
        workspace: label.workspace.clone(),
        scopes: label.scopes.clone(),
        owners: label.owners.clone(),
        audience_purpose_grants: grants,
        sensitivity: match label.sensitivity {
            Sensitivity::Public => RecallSensitivity::Public,
            Sensitivity::Internal => RecallSensitivity::Internal,
            Sensitivity::Private => RecallSensitivity::Confidential,
            Sensitivity::Restricted => RecallSensitivity::Restricted,
        },
        required_compartments: BTreeSet::new(),
        consent: match label.consent {
            Consent::Granted => AccessConsent::Granted,
            Consent::Unknown => AccessConsent::Unknown,
            Consent::Denied => AccessConsent::Denied,
        },
        retrievable: label.retrievable,
    }
}

fn document_kind(kind: RecordKind) -> RecallDocumentKind {
    match kind {
        RecordKind::Node => RecallDocumentKind::Entity,
        RecordKind::Claim => RecallDocumentKind::Claim,
        RecordKind::Edge => RecallDocumentKind::Relationship,
        RecordKind::Conflict => RecallDocumentKind::Conflict,
        RecordKind::Evidence => RecallDocumentKind::Observation,
        RecordKind::Candidate => RecallDocumentKind::Unknown,
        RecordKind::SemanticObject => RecallDocumentKind::Knowledge,
        RecordKind::RuntimeState => RecallDocumentKind::Episode,
        RecordKind::DomainExtension => RecallDocumentKind::Domain,
    }
}

fn string_set(value: Option<&Value>) -> BTreeSet<String> {
    string_vec(value).into_iter().collect()
}

fn string_vec(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .filter(|value| !value.trim().is_empty())
        .collect()
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned())
}

fn reference_error(error: contextdb_reference::ReferenceError) -> RecallError {
    RecallError::Provider(error.to_string())
}
