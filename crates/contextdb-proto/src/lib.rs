//! Generated ContextDB v1 Protobuf messages and optional gRPC stubs.
//!
//! The source of truth is `proto/contextdb/v1/contextdb.proto`. The bundled
//! protoc toolchain makes generation independent from a host installation.
//! Disable the default `grpc` feature for message and descriptor types without
//! a runtime Tonic dependency.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::allow_attributes_without_reason,
    reason = "Tonic 0.14 generated service stubs contain legacy allow attributes"
)]
#![allow(clippy::doc_markdown, reason = "generated API names follow Protobuf")]

#[cfg(feature = "grpc")]
mod bounded_codec;

#[cfg(feature = "grpc")]
pub use bounded_codec::BoundedProstCodec;

/// Canonical versioned public wire schema.
#[allow(
    missing_docs,
    unused_qualifications,
    clippy::all,
    clippy::pedantic,
    reason = "code generated from the canonical Protobuf schema"
)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/contextdb.v1.rs"));

    /// Deterministic descriptor set generated from the canonical schema.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/contextdb-v1.bin"));
}

/// Semantic version of the source wire contract.
pub const WIRE_SCHEMA_VERSION: &str = "contextdb.v1";

/// Stable schema-v1 capability keys for the quarantined candidate-only contract.
///
/// These open-map keys are intentionally strings on the wire so future
/// capabilities remain additive. Their presence does not advertise semantic
/// adjudication or canonical graph publication.
pub const CANDIDATE_RUNTIME_CAPABILITY_IDS_V1: [&str; 4] = [
    "candidate_hierarchy_dag",
    "policy_first_candidate_recall",
    "policy_first_candidate_traversal",
    "quarantined_memory_proposals",
];

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::v1::{RecallRequest, RequestContext};

    #[test]
    fn canonical_messages_round_trip_and_descriptor_is_present() {
        let value = RecallRequest {
            context: Some(RequestContext {
                request_id: "request:1".into(),
                workspace_id: "workspace:1".into(),
                subject_id: "subject:1".into(),
                audiences: vec!["subject:1".into()],
                scopes: vec!["project:test".into()],
                purpose: "assist".into(),
                clearance: 1,
                actor_id: None,
                agent_id: None,
                session_id: None,
                capability_grants: Vec::new(),
                authentication: None,
            }),
            query: "where is the decision?".into(),
            page_size: 20,
            at_commit: None,
            continuation: None,
        };

        let encoded = value.encode_to_vec();
        assert_eq!(RecallRequest::decode(encoded.as_slice()).ok(), Some(value));
        assert!(!super::v1::FILE_DESCRIPTOR_SET.is_empty());
    }

    #[test]
    fn candidate_capability_keys_are_documented_by_the_canonical_proto() {
        let schema = include_str!("../proto/contextdb/v1/contextdb.proto");
        for capability in super::CANDIDATE_RUNTIME_CAPABILITY_IDS_V1 {
            assert!(
                schema.contains(capability),
                "canonical Protobuf schema omits {capability}"
            );
        }
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn grpc_feature_generates_service_stubs() {
        use std::mem::size_of;

        type GeneratedServer = super::v1::observation_service_server::ObservationServiceServer<()>;
        type GeneratedClient = super::v1::observation_service_client::ObservationServiceClient<()>;

        assert!(size_of::<Option<GeneratedServer>>() > 0);
        assert!(size_of::<Option<GeneratedClient>>() > 0);
    }
}
