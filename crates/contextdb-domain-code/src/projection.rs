use contextdb_core::{ContentDigest, NodeType};
use serde::{Deserialize, Serialize};

use crate::{CodeDomainError, RepositorySnapshot, Result, SnapshotId};

const PACK_NAME: &str = "contextdb-domain-code";

/// One canonical external domain record ready for a policy-aware host to map
/// into universal nodes/evidence. It deliberately carries no mutation power.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeDomainRecord {
    /// Domain record type, versioned by this pack.
    pub record_type: String,
    /// Stable external identity in the coding domain.
    pub stable_identity: String,
    /// Canonical JSON payload.
    pub payload: serde_json::Value,
    /// Digest over record type, identity, and payload.
    pub payload_digest: ContentDigest,
}

impl CodeDomainRecord {
    /// Returns the universal extension node type without adding a code-specific
    /// variant to `contextdb-core`.
    #[must_use]
    pub fn universal_node_type(&self) -> NodeType {
        NodeType::Domain {
            pack: PACK_NAME.to_owned(),
            name: self.record_type.clone(),
        }
    }

    /// Revalidates a record received from a portable adapter.
    pub fn verify(&self) -> Result<()> {
        let expected = record_digest(&self.record_type, &self.stable_identity, &self.payload)?;
        if expected != self.payload_digest {
            return Err(CodeDomainError::PortableIntegrity);
        }
        Ok(())
    }
}

/// Deterministic code-domain record set for one immutable repository snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeDomainProjection {
    /// Source snapshot.
    pub snapshot: SnapshotId,
    /// Canonically ordered external records.
    pub records: Vec<CodeDomainRecord>,
}

impl CodeDomainProjection {
    /// Projects files, symbols, and relations without depending on graph,
    /// storage, model, or provider types. The host must attach authorization and
    /// evidence envelopes before proposing universal mutations.
    pub fn from_snapshot(snapshot: &RepositorySnapshot) -> Result<Self> {
        let mut records = Vec::new();
        for file in &snapshot.files {
            records.push(make_record(
                "file_revision",
                &file.identity.to_string(),
                serde_json::to_value(file)?,
            )?);
        }
        for symbol in &snapshot.symbols {
            records.push(make_record(
                "symbol_revision",
                &symbol.identity.to_string(),
                serde_json::to_value(symbol)?,
            )?);
        }
        for relation in &snapshot.relations {
            let stable_identity = format!(
                "{}:{:?}:{}",
                relation.source, relation.kind, relation.target
            );
            records.push(make_record(
                "code_relation",
                &stable_identity,
                serde_json::to_value(relation)?,
            )?);
        }
        records.sort_by(|left, right| {
            left.record_type
                .cmp(&right.record_type)
                .then_with(|| left.stable_identity.cmp(&right.stable_identity))
        });
        Ok(Self {
            snapshot: snapshot.id,
            records,
        })
    }

    /// Verifies ordering, uniqueness, and every nested record digest.
    pub fn verify(&self) -> Result<()> {
        let mut previous: Option<(&str, &str)> = None;
        for record in &self.records {
            record.verify()?;
            let current = (record.record_type.as_str(), record.stable_identity.as_str());
            if previous.is_some_and(|value| value >= current) {
                return Err(CodeDomainError::PortableIntegrity);
            }
            previous = Some(current);
        }
        Ok(())
    }
}

fn make_record(
    record_type: &str,
    stable_identity: &str,
    payload: serde_json::Value,
) -> Result<CodeDomainRecord> {
    Ok(CodeDomainRecord {
        record_type: record_type.to_owned(),
        stable_identity: stable_identity.to_owned(),
        payload_digest: record_digest(record_type, stable_identity, &payload)?,
        payload,
    })
}

fn record_digest(
    record_type: &str,
    stable_identity: &str,
    payload: &serde_json::Value,
) -> Result<ContentDigest> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-code-domain-record-v1\0");
    hasher.update(record_type.as_bytes());
    hasher.update(&[0]);
    hasher.update(stable_identity.as_bytes());
    hasher.update(&[0]);
    hasher.update(&serde_json::to_vec(payload)?);
    Ok(ContentDigest::from_bytes(*hasher.finalize().as_bytes()))
}
