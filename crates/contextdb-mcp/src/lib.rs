//! External Model Context Protocol adapter for ContextDB.
//!
//! The MCP surface is deliberately outside every semantic and storage crate.
//! It translates standard initialized MCP JSON-RPC calls, or strict stateless
//! `2026-07-28` profile calls, into the same canonical application service used
//! by embedded, gRPC, HTTP, CLI, and SDK clients.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod candidate_identity;
mod protocol;
mod server;
mod stdio;

pub use protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
pub use server::{
    FixedMcpSessionAuthorizer, MCP_PROTOCOL_VERSION, MCP_STANDARD_PROTOCOL_VERSION, McpServer,
    McpSessionAuthorizer,
};
pub use stdio::{MAX_MCP_LINE_BYTES, serve_stdio};

#[cfg(test)]
mod tests;
