//! Versioned deterministic JSON and Protobuf serialization.

use std::str::FromStr;

use contextdb_core::ContextPackId;
use prost::Message;

use crate::{
    CONTEXT_PACK_SCHEMA_VERSION, ContextBlock, ContextError, ContextPack, PackBlockKind,
    PackPurpose, PackStatus, Result,
};

/// Canonical serializer. All repeated values enter it in domain-canonical order;
/// the wire schema deliberately contains no Protobuf maps.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    /// Stable compact JSON representation.
    pub fn to_json(pack: &ContextPack) -> Result<Vec<u8>> {
        pack.validate()?;
        Self::validate_recorded_size(pack)?;
        serde_json::to_vec(pack).map_err(|error| ContextError::Serialization(error.to_string()))
    }

    /// Human-readable JSON view. Compact JSON remains the digest input.
    pub fn to_json_pretty(pack: &ContextPack) -> Result<Vec<u8>> {
        pack.validate()?;
        Self::validate_recorded_size(pack)?;
        serde_json::to_vec_pretty(pack)
            .map_err(|error| ContextError::Serialization(error.to_string()))
    }

    /// Parses canonical JSON and re-runs all semantic invariants.
    pub fn from_json(bytes: &[u8]) -> Result<ContextPack> {
        let pack: ContextPack = serde_json::from_slice(bytes)
            .map_err(|error| ContextError::Serialization(error.to_string()))?;
        pack.validate()?;
        Self::validate_recorded_size(&pack)?;
        Ok(pack)
    }

    /// Stable versioned Protobuf representation.
    pub fn to_protobuf(pack: &ContextPack) -> Result<Vec<u8>> {
        pack.validate()?;
        let bytes = Self::encode_protobuf_unchecked(pack)?;
        if usize::try_from(pack.compilation.usage.serialized_bytes).ok() != Some(bytes.len()) {
            return Err(ContextError::Serialization(format!(
                "recorded serialized size {} differs from canonical Protobuf size {}",
                pack.compilation.usage.serialized_bytes,
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Parses the v1 Protobuf schema and validates its domain reconstruction.
    pub fn from_protobuf(bytes: &[u8]) -> Result<ContextPack> {
        let wire = WireContextPackV1::decode(bytes)
            .map_err(|error| ContextError::Serialization(error.to_string()))?;
        let pack = wire.into_domain()?;
        pack.validate()?;
        if usize::try_from(pack.compilation.usage.serialized_bytes).ok() != Some(bytes.len()) {
            return Err(ContextError::Serialization(
                "protobuf byte length differs from its compilation report".to_owned(),
            ));
        }
        Ok(pack)
    }

    /// BLAKE3 digest over the canonical Protobuf bytes.
    pub fn digest(pack: &ContextPack) -> Result<String> {
        Ok(blake3::hash(&Self::to_protobuf(pack)?).to_hex().to_string())
    }

    pub(crate) fn encode_protobuf_unchecked(pack: &ContextPack) -> Result<Vec<u8>> {
        let wire = WireContextPackV1::from_domain(pack)?;
        Ok(wire.encode_to_vec())
    }

    fn validate_recorded_size(pack: &ContextPack) -> Result<()> {
        let bytes = Self::encode_protobuf_unchecked(pack)?;
        if usize::try_from(pack.compilation.usage.serialized_bytes).ok() != Some(bytes.len()) {
            return Err(ContextError::Serialization(
                "canonical pack has a stale serialized-byte counter".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Message)]
struct WireContextPackV1 {
    #[prost(string, tag = "1")]
    schema_version: String,
    #[prost(string, tag = "2")]
    id: String,
    #[prost(enumeration = "WirePackStatus", tag = "3")]
    status: i32,
    #[prost(string, tag = "4")]
    snapshot_json: String,
    #[prost(enumeration = "WirePackPurpose", tag = "5")]
    purpose: i32,
    #[prost(string, tag = "6")]
    scope_manifest_json: String,
    #[prost(message, repeated, tag = "7")]
    sections: Vec<WireSectionV1>,
    #[prost(string, repeated, tag = "8")]
    evidence_json: Vec<String>,
    #[prost(string, repeated, tag = "9")]
    use_directive_json: Vec<String>,
    #[prost(string, tag = "10")]
    freshness_json: String,
    #[prost(string, tag = "11")]
    provenance_json: String,
    #[prost(string, optional, tag = "12")]
    continuation_opaque: Option<String>,
    #[prost(string, tag = "13")]
    compilation_json: String,
    #[prost(string, optional, tag = "14")]
    no_memory_json: Option<String>,
    #[prost(string, tag = "15")]
    graph_manifest_json: String,
}

#[derive(Clone, PartialEq, Message)]
struct WireSectionV1 {
    #[prost(enumeration = "WireBlockKind", tag = "1")]
    kind: i32,
    #[prost(string, repeated, tag = "2")]
    block_json: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum WirePackStatus {
    Unknown = 0,
    Sufficient = 1,
    Partial = 2,
    NoMemory = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum WirePackPurpose {
    Unknown = 0,
    Conversation = 1,
    Continuity = 2,
    Autobiographical = 3,
    Knowledge = 4,
    Reflective = 5,
    Action = 6,
    Handoff = 7,
    Bootstrap = 8,
    Historical = 9,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum WireBlockKind {
    UnknownValue = 0,
    Situation = 1,
    SelfContext = 2,
    Participant = 3,
    SharedHistory = 4,
    Episode = 5,
    Fact = 6,
    Timeline = 7,
    Preference = 8,
    Boundary = 9,
    Relationship = 10,
    LegacyGoalOrOpenLoop = 11,
    Procedure = 12,
    Decision = 13,
    Conflict = 14,
    Unknown = 15,
    Goal = 16,
    Constraint = 17,
    OpenLoop = 18,
    RawObservation = 19,
}

impl WireContextPackV1 {
    fn from_domain(pack: &ContextPack) -> Result<Self> {
        let mut sections = Vec::new();
        for (kind, blocks) in section_slices(pack) {
            if blocks.is_empty() {
                continue;
            }
            sections.push(WireSectionV1 {
                kind: wire_kind(kind) as i32,
                block_json: blocks
                    .iter()
                    .map(canonical_string)
                    .collect::<Result<Vec<_>>>()?,
            });
        }
        Ok(Self {
            schema_version: pack.schema_version.clone(),
            id: pack.id.to_string(),
            status: wire_status(pack.status) as i32,
            snapshot_json: canonical_string(&pack.snapshot)?,
            purpose: wire_purpose(pack.purpose) as i32,
            scope_manifest_json: canonical_string(&pack.scope_manifest)?,
            sections,
            evidence_json: pack
                .evidence
                .iter()
                .map(canonical_string)
                .collect::<Result<Vec<_>>>()?,
            use_directive_json: pack
                .use_directives
                .iter()
                .map(canonical_string)
                .collect::<Result<Vec<_>>>()?,
            freshness_json: canonical_string(&pack.freshness)?,
            provenance_json: canonical_string(&pack.provenance)?,
            continuation_opaque: pack.continuation.as_ref().map(|token| token.opaque.clone()),
            compilation_json: canonical_string(&pack.compilation)?,
            no_memory_json: pack.no_memory.as_ref().map(canonical_string).transpose()?,
            graph_manifest_json: canonical_string(&pack.graph_manifest)?,
        })
    }

    fn into_domain(self) -> Result<ContextPack> {
        if self.schema_version != CONTEXT_PACK_SCHEMA_VERSION {
            return Err(ContextError::Serialization(format!(
                "unsupported ContextPack schema {}",
                self.schema_version
            )));
        }
        let status = domain_status(self.status)?;
        let purpose = domain_purpose(self.purpose)?;
        let mut sections = crate::PackSections::default();
        let mut previous_rank = None;
        for wire_section in self.sections {
            let expected_kind = domain_kind(wire_section.kind)?;
            let rank = kind_rank(expected_kind);
            if previous_rank.is_some_and(|previous| rank <= previous) {
                return Err(ContextError::Serialization(
                    "protobuf sections are not in canonical order".to_owned(),
                ));
            }
            previous_rank = Some(rank);
            let mut previous_id: Option<crate::BlockId> = None;
            for json in wire_section.block_json {
                let block: ContextBlock = parse_json(&json)?;
                if block.kind != expected_kind {
                    return Err(ContextError::Serialization(
                        "protobuf section kind differs from block kind".to_owned(),
                    ));
                }
                if previous_id.as_ref().is_some_and(|id| id >= &block.id) {
                    return Err(ContextError::Serialization(
                        "protobuf blocks are not in canonical ID order".to_owned(),
                    ));
                }
                previous_id = Some(block.id.clone());
                sections.push(block);
            }
        }
        Ok(ContextPack {
            schema_version: self.schema_version,
            id: ContextPackId::from_str(&self.id)
                .map_err(|error| ContextError::Serialization(error.to_string()))?,
            status,
            snapshot: parse_json(&self.snapshot_json)?,
            purpose,
            scope_manifest: parse_json(&self.scope_manifest_json)?,
            sections,
            evidence: self
                .evidence_json
                .iter()
                .map(|value| parse_json(value))
                .collect::<Result<Vec<_>>>()?,
            use_directives: self
                .use_directive_json
                .iter()
                .map(|value| parse_json(value))
                .collect::<Result<Vec<_>>>()?,
            graph_manifest: parse_json(&self.graph_manifest_json)?,
            freshness: parse_json(&self.freshness_json)?,
            provenance: parse_json(&self.provenance_json)?,
            continuation: self
                .continuation_opaque
                .map(|opaque| crate::ContextContinuationToken { opaque }),
            compilation: parse_json(&self.compilation_json)?,
            no_memory: self.no_memory_json.as_deref().map(parse_json).transpose()?,
        })
    }
}

fn canonical_string<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|error| ContextError::Serialization(error.to_string()))
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|error| ContextError::Serialization(error.to_string()))
}

fn section_slices(pack: &ContextPack) -> [(PackBlockKind, &[ContextBlock]); 18] {
    [
        (PackBlockKind::Situation, &pack.sections.situation),
        (PackBlockKind::SelfContext, &pack.sections.self_context),
        (PackBlockKind::Participant, &pack.sections.participants),
        (PackBlockKind::SharedHistory, &pack.sections.shared_history),
        (PackBlockKind::Episode, &pack.sections.episodes),
        (PackBlockKind::Fact, &pack.sections.facts),
        (PackBlockKind::Relationship, &pack.sections.relationships),
        (PackBlockKind::Preference, &pack.sections.preferences),
        (PackBlockKind::Boundary, &pack.sections.boundaries),
        (PackBlockKind::Goal, &pack.sections.goals),
        (PackBlockKind::Decision, &pack.sections.decisions),
        (PackBlockKind::Timeline, &pack.sections.timeline),
        (PackBlockKind::Procedure, &pack.sections.procedures),
        (PackBlockKind::Constraint, &pack.sections.constraints),
        (PackBlockKind::OpenLoop, &pack.sections.open_loops),
        (PackBlockKind::Conflict, &pack.sections.conflicts),
        (PackBlockKind::Unknown, &pack.sections.unknowns),
        (
            PackBlockKind::RawObservation,
            &pack.sections.raw_observations,
        ),
    ]
}

const fn wire_status(value: PackStatus) -> WirePackStatus {
    match value {
        PackStatus::Sufficient => WirePackStatus::Sufficient,
        PackStatus::Partial => WirePackStatus::Partial,
        PackStatus::NoMemory => WirePackStatus::NoMemory,
    }
}

fn domain_status(value: i32) -> Result<PackStatus> {
    match WirePackStatus::try_from(value) {
        Ok(WirePackStatus::Sufficient) => Ok(PackStatus::Sufficient),
        Ok(WirePackStatus::Partial) => Ok(PackStatus::Partial),
        Ok(WirePackStatus::NoMemory) => Ok(PackStatus::NoMemory),
        Ok(WirePackStatus::Unknown) | Err(_) => Err(ContextError::Serialization(
            "unknown ContextPack status enum".to_owned(),
        )),
    }
}

const fn wire_purpose(value: PackPurpose) -> WirePackPurpose {
    match value {
        PackPurpose::Conversation => WirePackPurpose::Conversation,
        PackPurpose::Continuity => WirePackPurpose::Continuity,
        PackPurpose::Autobiographical => WirePackPurpose::Autobiographical,
        PackPurpose::Knowledge => WirePackPurpose::Knowledge,
        PackPurpose::Historical => WirePackPurpose::Historical,
        PackPurpose::Reflective => WirePackPurpose::Reflective,
        PackPurpose::Action => WirePackPurpose::Action,
        PackPurpose::Handoff => WirePackPurpose::Handoff,
        PackPurpose::Bootstrap => WirePackPurpose::Bootstrap,
    }
}

fn domain_purpose(value: i32) -> Result<PackPurpose> {
    match WirePackPurpose::try_from(value) {
        Ok(WirePackPurpose::Conversation) => Ok(PackPurpose::Conversation),
        Ok(WirePackPurpose::Continuity) => Ok(PackPurpose::Continuity),
        Ok(WirePackPurpose::Autobiographical) => Ok(PackPurpose::Autobiographical),
        Ok(WirePackPurpose::Knowledge) => Ok(PackPurpose::Knowledge),
        Ok(WirePackPurpose::Historical) => Ok(PackPurpose::Historical),
        Ok(WirePackPurpose::Reflective) => Ok(PackPurpose::Reflective),
        Ok(WirePackPurpose::Action) => Ok(PackPurpose::Action),
        Ok(WirePackPurpose::Handoff) => Ok(PackPurpose::Handoff),
        Ok(WirePackPurpose::Bootstrap) => Ok(PackPurpose::Bootstrap),
        Ok(WirePackPurpose::Unknown) | Err(_) => Err(ContextError::Serialization(
            "unknown ContextPack purpose enum".to_owned(),
        )),
    }
}

const fn wire_kind(value: PackBlockKind) -> WireBlockKind {
    match value {
        PackBlockKind::Situation => WireBlockKind::Situation,
        PackBlockKind::SelfContext => WireBlockKind::SelfContext,
        PackBlockKind::Participant => WireBlockKind::Participant,
        PackBlockKind::SharedHistory => WireBlockKind::SharedHistory,
        PackBlockKind::Episode => WireBlockKind::Episode,
        PackBlockKind::Fact => WireBlockKind::Fact,
        PackBlockKind::Timeline => WireBlockKind::Timeline,
        PackBlockKind::Preference => WireBlockKind::Preference,
        PackBlockKind::Boundary => WireBlockKind::Boundary,
        PackBlockKind::Relationship => WireBlockKind::Relationship,
        PackBlockKind::Goal => WireBlockKind::Goal,
        PackBlockKind::Decision => WireBlockKind::Decision,
        PackBlockKind::Procedure => WireBlockKind::Procedure,
        PackBlockKind::Constraint => WireBlockKind::Constraint,
        PackBlockKind::OpenLoop => WireBlockKind::OpenLoop,
        PackBlockKind::Conflict => WireBlockKind::Conflict,
        PackBlockKind::Unknown => WireBlockKind::Unknown,
        PackBlockKind::RawObservation => WireBlockKind::RawObservation,
    }
}

fn domain_kind(value: i32) -> Result<PackBlockKind> {
    match WireBlockKind::try_from(value) {
        Ok(WireBlockKind::Situation) => Ok(PackBlockKind::Situation),
        Ok(WireBlockKind::SelfContext) => Ok(PackBlockKind::SelfContext),
        Ok(WireBlockKind::Participant) => Ok(PackBlockKind::Participant),
        Ok(WireBlockKind::SharedHistory) => Ok(PackBlockKind::SharedHistory),
        Ok(WireBlockKind::Episode) => Ok(PackBlockKind::Episode),
        Ok(WireBlockKind::Fact) => Ok(PackBlockKind::Fact),
        Ok(WireBlockKind::Timeline) => Ok(PackBlockKind::Timeline),
        Ok(WireBlockKind::Preference) => Ok(PackBlockKind::Preference),
        Ok(WireBlockKind::Boundary) => Ok(PackBlockKind::Boundary),
        Ok(WireBlockKind::Relationship) => Ok(PackBlockKind::Relationship),
        Ok(WireBlockKind::Goal) => Ok(PackBlockKind::Goal),
        Ok(WireBlockKind::Decision) => Ok(PackBlockKind::Decision),
        Ok(WireBlockKind::Procedure) => Ok(PackBlockKind::Procedure),
        Ok(WireBlockKind::Constraint) => Ok(PackBlockKind::Constraint),
        Ok(WireBlockKind::OpenLoop) => Ok(PackBlockKind::OpenLoop),
        Ok(WireBlockKind::Conflict) => Ok(PackBlockKind::Conflict),
        Ok(WireBlockKind::Unknown) => Ok(PackBlockKind::Unknown),
        Ok(WireBlockKind::RawObservation) => Ok(PackBlockKind::RawObservation),
        Ok(WireBlockKind::UnknownValue | WireBlockKind::LegacyGoalOrOpenLoop) | Err(_) => Err(
            ContextError::Serialization("unknown ContextPack block kind enum".to_owned()),
        ),
    }
}

const fn kind_rank(value: PackBlockKind) -> u8 {
    match value {
        PackBlockKind::Situation => 1,
        PackBlockKind::SelfContext => 2,
        PackBlockKind::Participant => 3,
        PackBlockKind::SharedHistory => 4,
        PackBlockKind::Episode => 5,
        PackBlockKind::Fact => 6,
        PackBlockKind::Relationship => 7,
        PackBlockKind::Preference => 8,
        PackBlockKind::Boundary => 9,
        PackBlockKind::Goal => 10,
        PackBlockKind::Decision => 11,
        PackBlockKind::Timeline => 12,
        PackBlockKind::Procedure => 13,
        PackBlockKind::Constraint => 14,
        PackBlockKind::OpenLoop => 15,
        PackBlockKind::Conflict => 16,
        PackBlockKind::Unknown => 17,
        PackBlockKind::RawObservation => 18,
    }
}

#[cfg(test)]
mod shared_fixture_tests {
    use super::*;

    #[test]
    fn shared_sdk_fixture_contains_exact_canonical_wire() {
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/fixtures/context_pack_v1.json");
        let fixture: serde_json::Value = serde_json::from_slice(
            &std::fs::read(fixture_path).expect("shared ContextPack fixture"),
        )
        .expect("fixture JSON");
        let response = &fixture["response"];
        let pack: ContextPack =
            serde_json::from_value(response["context_pack"].clone()).expect("fixture ContextPack");
        let bytes: Vec<u8> = serde_json::from_value(response["canonical_bytes"].clone())
            .expect("canonical byte array");
        let digest = response["canonical_digest"]
            .as_str()
            .expect("canonical digest");

        pack.validate().expect("valid fixture ContextPack");
        assert_eq!(
            response["canonical_encoding"],
            crate::CONTEXT_PACK_CANONICAL_ENCODING
        );
        assert_eq!(
            response["canonical_digest_algorithm"],
            crate::CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM
        );
        assert_eq!(
            CanonicalSerializer::to_protobuf(&pack).expect("canonical wire"),
            bytes
        );
        assert_eq!(blake3::hash(&bytes).to_hex().as_str(), digest);
        assert_eq!(
            CanonicalSerializer::from_protobuf(&bytes).expect("canonical round trip"),
            pack
        );
    }
}
