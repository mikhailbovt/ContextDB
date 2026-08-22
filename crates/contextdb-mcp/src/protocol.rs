use serde::{Deserialize, Serialize};

/// One MCP JSON-RPC 2.0 request or client notification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    /// Must be `2.0`.
    pub jsonrpc: String,
    /// Request correlation ID. A missing ID is represented as JSON null and
    /// identifies a notification, for which the transport emits no response.
    #[serde(default)]
    pub id: serde_json::Value,
    /// MCP method.
    pub method: String,
    /// Method parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    /// Returns true when this wire message is a JSON-RPC notification.
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_null()
    }
}

/// JSON-RPC protocol error.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcError {
    /// Stable JSON-RPC error code.
    pub code: i32,
    /// Content-free safe error text.
    pub message: String,
}

/// One MCP response. Exactly one of `result` or `error` is present.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcResponse {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Correlated request ID, or null for a framing/parse error.
    pub id: serde_json::Value,
    /// Successful result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Protocol error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub(crate) fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        let result = stamp_result(result);
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub(crate) fn error(id: serde_json::Value, code: i32, message: &'static str) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_owned(),
            }),
        }
    }
}

fn stamp_result(mut result: serde_json::Value) -> serde_json::Value {
    let Some(object) = result.as_object_mut() else {
        return serde_json::json!({
            "resultType": "complete",
            "value": result,
            "_meta": server_meta()
        });
    };
    object
        .entry("resultType")
        .or_insert_with(|| serde_json::json!("complete"));
    object
        .entry("_meta")
        .or_insert_with(|| serde_json::Value::Object(server_meta()));
    result
}

fn server_meta() -> serde_json::Map<String, serde_json::Value> {
    serde_json::Map::from_iter([(
        "io.modelcontextprotocol/serverInfo".to_owned(),
        serde_json::json!({
            "name": "contextdb",
            "version": env!("CARGO_PKG_VERSION")
        }),
    )])
}
