use std::collections::BTreeSet;

use crate::{
    ProviderDocument, ProviderRelation, ProviderRequest, ProviderSnapshot, RecallDocument,
    RecallError, RecallRelation, Result,
};

/// Corpus already filtered by authorization before any content-based routing.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedCorpus {
    snapshot: ProviderSnapshot,
    filter_digest: String,
    documents: Vec<RecallDocument>,
    relations: Vec<RecallRelation>,
}

impl AuthorizedCorpus {
    /// Performs the only supported transition from labelled provider records to
    /// planner-visible content. Policy metadata is evaluated before any semantic
    /// field of a rejected record is inspected.
    pub fn authorize(
        request: &ProviderRequest,
        documents: Vec<ProviderDocument>,
        relations: Vec<ProviderRelation>,
    ) -> Result<Self> {
        let snapshot = request.snapshot.clone();
        let filter_digest = request.filter_digest.clone();
        let principal = &request.principal;
        snapshot.validate()?;
        principal.validate()?;
        if filter_digest.trim().is_empty() {
            return Err(RecallError::Provider(
                "authorized corpus requires a filter digest".to_owned(),
            ));
        }

        // Deliberately keep the policy check as the first operation in each
        // iteration. Rejected content must not participate in validation,
        // deduplication, endpoint checks, sorting, counts, or diagnostics.
        let mut authorized_documents = Vec::new();
        for record in documents {
            if !principal.allows(&record.access) {
                continue;
            }
            record.access.validate()?;
            let ProviderDocument {
                access: _,
                mut document,
                evidence,
            } = record;
            if !document.evidence.is_empty() {
                return Err(RecallError::Provider(
                    "provider documents must submit evidence through labelled evidence records"
                        .to_owned(),
                ));
            }
            for labelled_evidence in evidence {
                if !principal.allows(&labelled_evidence.access) {
                    continue;
                }
                labelled_evidence.access.validate()?;
                labelled_evidence.evidence.validate()?;
                document.evidence.push(labelled_evidence.evidence);
            }
            document
                .evidence
                .sort_by(|left, right| left.id.cmp(&right.id));
            if document
                .evidence
                .windows(2)
                .any(|pair| pair[0].id == pair[1].id)
            {
                return Err(RecallError::Provider(
                    "authorized document contains duplicate evidence IDs".to_owned(),
                ));
            }
            document.validate()?;
            authorized_documents.push(document);
        }
        authorized_documents.sort_by(|left, right| left.id.cmp(&right.id));
        if authorized_documents
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id)
        {
            return Err(RecallError::Provider(
                "authorized corpus contains duplicate document IDs".to_owned(),
            ));
        }
        let endpoints = authorized_documents
            .iter()
            .map(|document| document.id.clone())
            .collect::<BTreeSet<_>>();

        let mut authorized_relations = Vec::new();
        for record in relations {
            if !principal.allows(&record.access) {
                continue;
            }
            record.access.validate()?;
            record.relation.validate()?;
            if endpoints.contains(&record.relation.source)
                && endpoints.contains(&record.relation.target)
            {
                authorized_relations.push(record.relation);
            }
        }
        authorized_relations.sort_by(|left, right| left.id.cmp(&right.id));
        if authorized_relations
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id)
        {
            return Err(RecallError::Provider(
                "authorized corpus contains duplicate relation IDs".to_owned(),
            ));
        }

        Ok(Self {
            snapshot,
            filter_digest,
            documents: authorized_documents,
            relations: authorized_relations,
        })
    }

    /// Snapshot to which every returned record is bound.
    #[must_use]
    pub fn snapshot(&self) -> &ProviderSnapshot {
        &self.snapshot
    }

    /// Digest of every non-content filter applied before materialization.
    #[must_use]
    pub fn filter_digest(&self) -> &str {
        &self.filter_digest
    }

    /// Planner-visible authorized documents in stable identifier order.
    #[must_use]
    pub fn documents(&self) -> &[RecallDocument] {
        &self.documents
    }

    /// Planner-visible authorized relations in stable identifier order.
    #[must_use]
    pub fn relations(&self) -> &[RecallRelation] {
        &self.relations
    }

    /// Fails closed if a provider returned data for another snapshot or filter.
    pub fn verify_binding(&self, request: &ProviderRequest) -> Result<()> {
        if self.snapshot != request.snapshot || self.filter_digest != request.filter_digest {
            return Err(RecallError::Provider(
                "authorized corpus is not bound to the requested snapshot and filters".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Storage-neutral read boundary for deterministic recall.
pub trait RecallProvider {
    /// Returns a coherent current or retained snapshot.
    fn snapshot(&self, at_commit: Option<u64>) -> Result<ProviderSnapshot>;

    /// Authorizes first, then returns a sealed corpus. Implementations must not
    /// perform content-based candidate generation before this boundary.
    fn authorized_corpus(&self, request: &ProviderRequest) -> Result<AuthorizedCorpus>;
}
