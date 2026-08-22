use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use contextdb_core::ContentDigest;

use crate::{
    ModelCapability, ModelRuntimeError, PreparedModelInput, PromptAssetRef, Result, SchemaRef,
};

/// Input to a rule-based no-model fallback.
#[derive(Clone, Debug)]
pub struct DeterministicFallbackRequest {
    /// Specialized operation.
    pub capability: ModelCapability,
    /// Schema that still validates fallback output.
    pub output_schema: SchemaRef,
    /// Prompt/version lineage used by the caller.
    pub prompt: PromptAssetRef,
    /// Protected deployment-local input.
    pub input: PreparedModelInput,
    /// Hard output token bound.
    pub max_output_tokens: u32,
}

/// Deterministic degraded-mode computation. It cannot publish mutations and its
/// output traverses the exact same schema registry as provider output.
pub trait DeterministicFallback: Send + Sync {
    /// Specialized capability implemented by this fallback.
    fn capability(&self) -> &ModelCapability;

    /// Exact output schema implemented by this fallback.
    fn output_schema(&self) -> &SchemaRef;

    /// Produces deterministic untrusted bytes or reports no applicable rule.
    fn evaluate(
        &self,
        request: &DeterministicFallbackRequest,
    ) -> std::result::Result<Option<Vec<u8>>, String>;
}

/// Registry of rule-based degraded-mode implementations.
#[derive(Default)]
pub struct FallbackRegistry {
    fallbacks: RwLock<BTreeMap<(ModelCapability, SchemaRef), Arc<dyn DeterministicFallback>>>,
}

impl fmt::Debug for FallbackRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FallbackRegistry")
            .finish_non_exhaustive()
    }
}

impl FallbackRegistry {
    /// Creates an empty fallback registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one exact capability/schema implementation.
    pub fn register(&self, fallback: Arc<dyn DeterministicFallback>) -> Result<()> {
        fallback.capability().validate()?;
        let key = (
            fallback.capability().clone(),
            fallback.output_schema().clone(),
        );
        let mut fallbacks = self
            .fallbacks
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        if fallbacks.contains_key(&key) {
            return Err(ModelRuntimeError::RegistryConflict(
                "deterministic fallback".to_owned(),
            ));
        }
        fallbacks.insert(key, fallback);
        Ok(())
    }

    pub(crate) fn get(
        &self,
        capability: &ModelCapability,
        schema: &SchemaRef,
    ) -> Result<Option<Arc<dyn DeterministicFallback>>> {
        Ok(self
            .fallbacks
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .get(&(capability.clone(), schema.clone()))
            .cloned())
    }
}

/// Deterministic recorded fallback keyed by protected input digest. Useful as a
/// reference local parser/evaluator and for no-network conformance tests.
pub struct RecordedFallback {
    capability: ModelCapability,
    schema: SchemaRef,
    outputs: RwLock<BTreeMap<ContentDigest, Vec<u8>>>,
}

impl fmt::Debug for RecordedFallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedFallback")
            .field("capability", &self.capability)
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

impl RecordedFallback {
    /// Creates an empty recorded fallback.
    #[must_use]
    pub fn new(capability: ModelCapability, schema: SchemaRef) -> Self {
        Self {
            capability,
            schema,
            outputs: RwLock::new(BTreeMap::new()),
        }
    }

    /// Adds one exact deterministic output.
    pub fn insert(&self, input_digest: ContentDigest, output: Vec<u8>) -> Result<()> {
        let mut outputs = self
            .outputs
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        if outputs.contains_key(&input_digest) {
            return Err(ModelRuntimeError::RegistryConflict(
                "recorded fallback response".to_owned(),
            ));
        }
        outputs.insert(input_digest, output);
        Ok(())
    }
}

impl DeterministicFallback for RecordedFallback {
    fn capability(&self) -> &ModelCapability {
        &self.capability
    }

    fn output_schema(&self) -> &SchemaRef {
        &self.schema
    }

    fn evaluate(
        &self,
        request: &DeterministicFallbackRequest,
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        self.outputs
            .read()
            .map_err(|_| "fallback output lock poisoned".to_owned())
            .map(|outputs| outputs.get(&request.input.digest).cloned())
    }
}
