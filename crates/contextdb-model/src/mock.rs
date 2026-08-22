use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;

use crate::{
    ModelProvider, ProviderAttemptContext, ProviderError, ProviderErrorKind, ProviderId,
    ProviderRequest, ProviderResponse,
};

/// Scripted test-provider step.
#[derive(Clone, Debug)]
pub enum MockStep {
    /// Return a provider response.
    Response(ProviderResponse),
    /// Return a payload-free provider error.
    Error(ProviderError),
    /// Advance the injected fake timer, then return a response.
    AdvanceThenResponse {
        /// Fake elapsed milliseconds.
        advance_ms: u64,
        /// Response after advancing.
        response: ProviderResponse,
    },
    /// Advance the injected fake timer, then return an error.
    AdvanceThenError {
        /// Fake elapsed milliseconds.
        advance_ms: u64,
        /// Error after advancing.
        error: ProviderError,
    },
}

/// Payload-free captured attempt metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockAttemptRecord {
    /// Attempt context.
    pub context: ProviderAttemptContext,
    /// Capability.
    pub capability: crate::ModelCapability,
    /// Prompt digest.
    pub prompt_digest: contextdb_core::ContentDigest,
    /// Schema digest.
    pub schema_digest: contextdb_core::ContentDigest,
    /// Input digest.
    pub input_digest: contextdb_core::ContentDigest,
    /// Whether provider saw redacted input.
    pub redacted: bool,
    /// Number of bytes, never their contents.
    pub input_bytes: usize,
}

/// Deterministic scripted provider for reliability/adversarial tests. It can
/// share a `ManualTimer` with the gateway, avoiding sleeps.
pub struct MockProvider {
    id: ProviderId,
    timer: Option<std::sync::Arc<crate::ManualTimer>>,
    steps: Mutex<VecDeque<MockStep>>,
    attempts: Mutex<Vec<MockAttemptRecord>>,
}

impl fmt::Debug for MockProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MockProvider")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl MockProvider {
    /// Creates a provider with a fixed script.
    #[must_use]
    pub fn new(id: ProviderId, steps: impl IntoIterator<Item = MockStep>) -> Self {
        Self {
            id,
            timer: None,
            steps: Mutex::new(steps.into_iter().collect()),
            attempts: Mutex::new(Vec::new()),
        }
    }

    /// Shares a fake timer used to emulate deadlines without sleeping.
    #[must_use]
    pub fn with_timer(mut self, timer: std::sync::Arc<crate::ManualTimer>) -> Self {
        self.timer = Some(timer);
        self
    }

    /// Returns captured payload-free attempt metadata.
    pub fn attempts(&self) -> crate::Result<Vec<MockAttemptRecord>> {
        Ok(self
            .attempts
            .lock()
            .map_err(|_| crate::ModelRuntimeError::LockPoisoned)?
            .clone())
    }
}

impl ModelProvider for MockProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn invoke(
        &self,
        request: &ProviderRequest,
        context: &ProviderAttemptContext,
    ) -> Result<ProviderResponse, ProviderError> {
        self.attempts
            .lock()
            .map_err(|_| ProviderError::new(ProviderErrorKind::Internal))?
            .push(MockAttemptRecord {
                context: context.clone(),
                capability: request.capability.clone(),
                prompt_digest: request.prompt.digest,
                schema_digest: request.output_schema.digest,
                input_digest: request.input().digest,
                redacted: request.input().redacted,
                input_bytes: request.input().bytes().len(),
            });
        let step = self
            .steps
            .lock()
            .map_err(|_| ProviderError::new(ProviderErrorKind::Internal))?
            .pop_front()
            .ok_or_else(|| ProviderError::new(ProviderErrorKind::Unavailable))?;
        match step {
            MockStep::Response(response) => Ok(response),
            MockStep::Error(error) => Err(error),
            MockStep::AdvanceThenResponse {
                advance_ms,
                response,
            } => {
                if let Some(timer) = &self.timer {
                    timer.advance(advance_ms);
                }
                Ok(response)
            }
            MockStep::AdvanceThenError { advance_ms, error } => {
                if let Some(timer) = &self.timer {
                    timer.advance(advance_ms);
                }
                Err(error)
            }
        }
    }
}
