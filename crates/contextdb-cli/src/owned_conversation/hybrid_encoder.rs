//! One process lease shared by projection and query encoding, with explicit cleanup.

use std::sync::Arc;
use std::time::Duration;

use contextdb_agent_runtime::OwnedLocalEmbedding;
use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::{ErrorCode, ServiceError, TextEmbeddingAdapter};

use super::config::HybridConfig;
use super::{
    HYBRID_SHUTDOWN_MAX_BYTES, HYBRID_SHUTDOWN_MAX_WORK, HYBRID_SHUTDOWN_TIME_MS,
    HYBRID_STARTUP_MAX_BYTES, HYBRID_STARTUP_MAX_WORK, HYBRID_STARTUP_TIME_MS,
};
use crate::CliResult;

/// The operation must release all adapter references before returning. Its
/// original failure takes precedence over cleanup failure or uncertain output.
pub(super) fn with_encoder<T>(
    config: Option<&HybridConfig>,
    operation: impl FnOnce(Option<Arc<OwnedLocalEmbedding>>) -> CliResult<T>,
) -> CliResult<T> {
    let Some(config) = config else {
        return operation(None);
    };
    let expected = config.embedding_profile()?;
    let mut startup = allowance(
        HYBRID_STARTUP_MAX_WORK,
        HYBRID_STARTUP_MAX_BYTES,
        HYBRID_STARTUP_TIME_MS,
    );
    let encoder = Arc::new(OwnedLocalEmbedding::launch(&config.encoder, &mut startup)?);
    let result = if encoder.profile() != &expected {
        Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "launched hybrid encoder differs from its bound profile",
            false,
        )
        .into())
    } else {
        operation(Some(encoder.clone()))
    };
    let cleanup = match Arc::try_unwrap(encoder) {
        Ok(mut encoder) => encoder
            .shutdown(&mut allowance(
                HYBRID_SHUTDOWN_MAX_WORK,
                HYBRID_SHUTDOWN_MAX_BYTES,
                HYBRID_SHUTDOWN_TIME_MS,
            ))
            .map_err(Into::into),
        Err(_) => Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "hybrid operation retained an encoder lease",
            false,
        )
        .into()),
    };
    match result {
        Err(error) => Err(error),
        Ok(value) => cleanup.map(|()| value),
    }
}

fn allowance(work: u64, bytes: u64, millis: u64) -> QueryBudget {
    QueryBudget::new(
        work,
        bytes,
        Duration::from_millis(millis),
        QueryCancellation::default(),
    )
}
