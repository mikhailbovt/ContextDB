use std::sync::Arc;

use contextdb_service::CognitiveMemoryService;

use super::{AdapterFuture, ConformanceAdapter};
use crate::{
    CanonicalOperation, CanonicalResponse, CapabilityManifest, ConformanceResult, InterfaceKind,
    embedded_manifest,
};

/// Direct adapter over the canonical embedded service trait.
#[derive(Clone)]
pub struct EmbeddedAdapter {
    service: Arc<dyn CognitiveMemoryService>,
}

impl std::fmt::Debug for EmbeddedAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddedAdapter")
            .finish_non_exhaustive()
    }
}

impl EmbeddedAdapter {
    /// Creates a direct adapter.
    #[must_use]
    pub fn new(service: Arc<dyn CognitiveMemoryService>) -> Self {
        Self { service }
    }
}

impl ConformanceAdapter for EmbeddedAdapter {
    fn interface(&self) -> InterfaceKind {
        InterfaceKind::Embedded
    }

    fn manifest(&self) -> CapabilityManifest {
        embedded_manifest()
    }

    fn invoke(&mut self, operation: CanonicalOperation) -> AdapterFuture<'_> {
        let service = Arc::clone(&self.service);
        Box::pin(async move {
            let outcome = match operation {
                CanonicalOperation::Observe(request) => {
                    service.observe(request).map(CanonicalResponse::Observe)
                }
                CanonicalOperation::Recall(request) => {
                    service.recall(request).map(CanonicalResponse::Recall)
                }
                CanonicalOperation::ExplainRecall(request) => service
                    .explain_recall(request)
                    .map(CanonicalResponse::ExplainRecall),
                CanonicalOperation::Export(request) => service
                    .export_archive(request)
                    .map(CanonicalResponse::Export),
                CanonicalOperation::Import(request) => service
                    .import_archive(request)
                    .map(CanonicalResponse::Import),
                CanonicalOperation::Verify(request) => {
                    service.verify(request).map(CanonicalResponse::Verify)
                }
            };
            Ok(outcome.map_err(Into::into)) as ConformanceResult<_>
        })
    }
}
