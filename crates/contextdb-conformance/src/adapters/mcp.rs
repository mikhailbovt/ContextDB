use std::sync::Arc;

use contextdb_mcp::{JsonRpcRequest, MCP_PROTOCOL_VERSION, McpServer};
use contextdb_service::{AuthenticatedRequestContext, CognitiveMemoryService};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{AdapterFuture, ConformanceAdapter};
use crate::{
    CanonicalError, CanonicalOperation, CanonicalResponse, CapabilityManifest, ConformanceError,
    InterfaceKind, mcp_manifest,
};

#[derive(Clone, Copy, Debug)]
enum ResponseKind {
    Observe,
    Recall,
    Explain,
    Export,
    Import,
    Verify,
}

/// Evidence for the stateless MCP 2026-07-28 contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpR19Proof {
    /// Requests without `_meta` fail closed.
    pub missing_meta_rejected: bool,
    /// Standard metadata-free `initialize` is available.
    pub standard_initialize_available: bool,
    /// Discovery advertises the exact protocol revision.
    pub discovery_version: String,
    /// Discovery and list results are explicitly complete.
    pub result_type_complete: bool,
    /// Public discovery cache metadata is present.
    pub public_cache_hint: bool,
    /// Server identity metadata is present.
    pub server_info_present: bool,
}

impl McpR19Proof {
    /// True only when every mandatory R19 behavior was observed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.missing_meta_rejected
            && self.standard_initialize_available
            && self.discovery_version == MCP_PROTOCOL_VERSION
            && self.result_type_complete
            && self.public_cache_hint
            && self.server_info_present
    }
}

/// MCP JSON-RPC adapter using the canonical stateless request metadata on every
/// call. The underlying server may retain authenticated trace handles, but no
/// handshake/session state is required.
pub struct McpAdapter {
    server: McpServer,
    next_id: u64,
}

impl std::fmt::Debug for McpAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpAdapter")
            .field("next_id", &self.next_id)
            .finish_non_exhaustive()
    }
}

impl McpAdapter {
    /// Creates a fail-closed MCP adapter for discovery and negative-boundary
    /// proofs. Tool invocation requires [`Self::with_fixed_session_authority`].
    #[must_use]
    pub fn new(service: Arc<dyn CognitiveMemoryService>) -> Self {
        Self {
            server: McpServer::new(service),
            next_id: 1,
        }
    }

    /// Creates an MCP adapter with one trusted fixed conformance session.
    pub fn with_fixed_session_authority(
        service: Arc<dyn CognitiveMemoryService>,
        context: AuthenticatedRequestContext,
    ) -> Result<Self, ConformanceError> {
        Ok(Self {
            server: McpServer::with_fixed_session_authority(service, context)
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
            next_id: 1,
        })
    }

    /// Exercises strict metadata before initialization, standard initialize,
    /// discovery, and result/cache hints.
    pub fn prove_r19(&mut self) -> McpR19Proof {
        let missing_id = self.take_id();
        let missing = self.server.handle(JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::json!(missing_id),
            method: "tools/list".to_owned(),
            params: Some(serde_json::json!({})),
        });
        let initialize_id = self.take_id();
        let initialize = self.server.handle(JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::json!(initialize_id),
            method: "initialize".to_owned(),
            params: Some(serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "contextdb-conformance",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
        });
        let standard_initialize_available = initialize
            .result
            .as_ref()
            .and_then(|result| result.get("protocolVersion"))
            == Some(&serde_json::json!("2025-06-18"));
        let discover = self.call("server/discover", serde_json::json!({}));
        let tools = self.call("tools/list", serde_json::json!({}));
        let discovered = discover.result.unwrap_or_default();
        let listed = tools.result.unwrap_or_default();
        McpR19Proof {
            missing_meta_rejected: missing.error.is_some_and(|error| error.code == -32602),
            standard_initialize_available,
            discovery_version: discovered
                .get("supportedVersions")
                .and_then(|versions| versions.get(0))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            result_type_complete: discovered.get("resultType")
                == Some(&serde_json::json!("complete"))
                && listed.get("resultType") == Some(&serde_json::json!("complete")),
            public_cache_hint: discovered.get("cacheScope") == Some(&serde_json::json!("public"))
                && discovered.get("ttlMs").and_then(serde_json::Value::as_u64) == Some(300_000),
            server_info_present: discovered
                .get("_meta")
                .and_then(|meta| meta.get("io.modelcontextprotocol/serverInfo"))
                .is_some_and(serde_json::Value::is_object),
        }
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    fn call(
        &mut self,
        method: &str,
        mut params: serde_json::Value,
    ) -> contextdb_mcp::JsonRpcResponse {
        if let Some(object) = params.as_object_mut() {
            object.insert("_meta".to_owned(), request_meta());
        }
        let id = self.take_id();
        self.server.handle(JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::json!(id),
            method: method.to_owned(),
            params: Some(params),
        })
    }
}

impl ConformanceAdapter for McpAdapter {
    fn interface(&self) -> InterfaceKind {
        InterfaceKind::Mcp
    }

    fn manifest(&self) -> CapabilityManifest {
        mcp_manifest()
    }

    fn invoke(&mut self, operation: CanonicalOperation) -> AdapterFuture<'_> {
        let (name, arguments, kind) = match encode_operation(operation) {
            Ok(encoded) => encoded,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let response = self.call(
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        );
        Box::pin(async move {
            if let Some(error) = response.error {
                return Err(ConformanceError::Protocol(format!(
                    "MCP error {}: {}",
                    error.code, error.message
                )));
            }
            let result = response
                .result
                .ok_or_else(|| ConformanceError::Protocol("MCP result is missing".to_owned()))?;
            if result.get("resultType") != Some(&serde_json::json!("complete")) {
                return Err(ConformanceError::Protocol(
                    "MCP resultType is not complete".to_owned(),
                ));
            }
            let structured = result.get("structuredContent").cloned().ok_or_else(|| {
                ConformanceError::Protocol("MCP structuredContent is missing".to_owned())
            })?;
            if result.get("isError").and_then(serde_json::Value::as_bool) == Some(true) {
                let error = serde_json::from_value::<CanonicalError>(structured)
                    .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
                return Ok(Err(error));
            }
            Ok(Ok(decode_success(kind, structured)?))
        })
    }
}

fn request_meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "contextdb-conformance",
            "version": env!("CARGO_PKG_VERSION")
        },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn encode_operation(
    operation: CanonicalOperation,
) -> Result<(&'static str, serde_json::Value, ResponseKind), ConformanceError> {
    let encoded = match operation {
        CanonicalOperation::Observe(request) => (
            "contextdb_observe",
            serde_json::to_value(request),
            ResponseKind::Observe,
        ),
        CanonicalOperation::Recall(request) => (
            "contextdb_recall",
            serde_json::to_value(request),
            ResponseKind::Recall,
        ),
        CanonicalOperation::ExplainRecall(request) => (
            "contextdb_explain",
            serde_json::to_value(request),
            ResponseKind::Explain,
        ),
        CanonicalOperation::Export(request) => (
            "contextdb_export",
            serde_json::to_value(request),
            ResponseKind::Export,
        ),
        CanonicalOperation::Import(request) => (
            "contextdb_import",
            serde_json::to_value(request),
            ResponseKind::Import,
        ),
        CanonicalOperation::Verify(request) => (
            "contextdb_verify",
            serde_json::to_value(request),
            ResponseKind::Verify,
        ),
    };
    encoded
        .1
        .map(|value| (encoded.0, value, encoded.2))
        .map_err(|error| ConformanceError::Protocol(error.to_string()))
}

fn decode_success(
    kind: ResponseKind,
    value: serde_json::Value,
) -> Result<CanonicalResponse, ConformanceError> {
    match kind {
        ResponseKind::Observe => decode(value).map(CanonicalResponse::Observe),
        ResponseKind::Recall => decode(value).map(CanonicalResponse::Recall),
        ResponseKind::Explain => decode(value).map(CanonicalResponse::ExplainRecall),
        ResponseKind::Export => decode(value).map(CanonicalResponse::Export),
        ResponseKind::Import => decode(value).map(CanonicalResponse::Import),
        ResponseKind::Verify => decode(value).map(CanonicalResponse::Verify),
    }
}

fn decode<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, ConformanceError> {
    serde_json::from_value(value).map_err(|error| ConformanceError::Protocol(error.to_string()))
}
