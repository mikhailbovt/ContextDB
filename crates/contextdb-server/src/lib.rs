//! Optional network adapters for the canonical ContextDB application service.
//!
//! This crate owns protocol translation only. It has no storage, graph,
//! retrieval, model-provider, or semantic-mutation dependency. `wire` enables
//! generated-message conversion, `server` enables the gRPC edge, and `http`
//! enables the HTTP/JSON edge. The default preserves both network adapters.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(any(feature = "server", feature = "http"))]
mod admission;
#[cfg(any(feature = "server", feature = "http"))]
mod auth;
#[cfg(feature = "wire")]
mod conversion;
#[cfg(feature = "server")]
mod grpc;
#[cfg(any(feature = "server", feature = "http"))]
mod health;
#[cfg(feature = "http")]
mod http;

#[cfg(any(feature = "server", feature = "http"))]
pub use admission::*;
#[cfg(any(feature = "server", feature = "http"))]
pub use auth::*;
#[cfg(feature = "wire")]
pub use conversion::*;
#[cfg(feature = "server")]
pub use grpc::{
    GrpcAdapter, serve_grpc, serve_grpc_listener_with_shutdown,
    serve_grpc_listener_with_shutdown_and_gateway,
    serve_grpc_listener_with_shutdown_gateway_and_admission, serve_grpc_with_gateway_authenticator,
    serve_grpc_with_shutdown, serve_grpc_with_shutdown_and_gateway,
};
#[cfg(any(feature = "server", feature = "http"))]
pub use health::*;
#[cfg(feature = "http")]
pub use http::{
    HttpErrorBody, http_router, http_router_with_gateway_authenticator,
    http_router_with_gateway_authenticator_and_health,
    http_router_with_gateway_authenticator_health_and_admission, http_router_with_health_provider,
    serve_http, serve_http_with_gateway_authenticator, serve_http_with_shutdown,
    serve_http_with_shutdown_and_gateway, serve_http_with_shutdown_gateway_and_health,
    serve_http_with_shutdown_gateway_health_and_admission,
};

/// Hard transport-level bound applied before domain validation.
pub const MAX_WIRE_BYTES: usize = 16 * 1024 * 1024;

#[cfg(all(test, feature = "server", feature = "http"))]
mod tests;
