use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::types::{MAX_ID_BYTES, MAX_TEXT_BYTES, canonical_digest, validate_text};
use crate::{
    BasisPoints, LanguageTag, ModelCapability, ModelRuntimeError, PromptAssetId, PromptAssetRef,
    Result, SchemaRef, Sensitivity,
};

const MAX_PROMPT_BYTES: usize = 1024 * 1024;

/// Versioned prompt source artifact bound to one capability and schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptAsset {
    /// Prompt family.
    pub id: PromptAssetId,
    /// Positive family-local version.
    pub version: u32,
    /// Specialized purpose.
    pub capability: ModelCapability,
    /// Expected strict output schema.
    pub output_schema: SchemaRef,
    /// Instruction-channel content kept separate from source data.
    pub system_text: String,
    /// Bounded human-readable purpose.
    pub purpose: String,
    /// Allowed ontology terms for this asset.
    pub allowed_ontology: BTreeSet<String>,
    /// Maximum prompt/input allocation expected by the asset.
    pub token_budget: u32,
    /// Highest content class the prompt was evaluated to handle.
    pub privacy_classification: Sensitivity,
    /// Change rationale for this revision.
    pub change_notes: String,
    /// Golden-suite floor required for production routing.
    pub minimum_golden_score: BasisPoints,
    /// Adversarial-suite floor required for production routing.
    pub minimum_adversarial_score: BasisPoints,
    /// Languages covered by the referenced golden/adversarial cases.
    pub evaluated_languages: BTreeSet<LanguageTag>,
    /// Digests of immutable multilingual golden cases.
    pub golden_case_digests: BTreeSet<contextdb_core::ContentDigest>,
    /// Digests of immutable adversarial/privacy cases.
    pub adversarial_case_digests: BTreeSet<contextdb_core::ContentDigest>,
    /// Exact immutable asset reference.
    pub reference: PromptAssetRef,
}

#[derive(Serialize)]
struct PromptDigestInput<'a> {
    id: &'a PromptAssetId,
    version: u32,
    capability: &'a ModelCapability,
    output_schema: &'a SchemaRef,
    system_text: &'a str,
    purpose: &'a str,
    allowed_ontology: &'a BTreeSet<String>,
    token_budget: u32,
    privacy_classification: Sensitivity,
    change_notes: &'a str,
    minimum_golden_score: BasisPoints,
    minimum_adversarial_score: BasisPoints,
    evaluated_languages: &'a BTreeSet<LanguageTag>,
    golden_case_digests: &'a BTreeSet<contextdb_core::ContentDigest>,
    adversarial_case_digests: &'a BTreeSet<contextdb_core::ContentDigest>,
}

/// Parameters used to create a prompt asset before its digest exists.
#[derive(Clone, Debug)]
pub struct PromptAssetDefinition {
    /// Prompt family.
    pub id: PromptAssetId,
    /// Positive family-local version.
    pub version: u32,
    /// Specialized purpose.
    pub capability: ModelCapability,
    /// Expected output schema.
    pub output_schema: SchemaRef,
    /// Instruction text.
    pub system_text: String,
    /// Human-readable purpose.
    pub purpose: String,
    /// Allowed ontology terms.
    pub allowed_ontology: BTreeSet<String>,
    /// Prompt/input token budget.
    pub token_budget: u32,
    /// Evaluated privacy boundary.
    pub privacy_classification: Sensitivity,
    /// Revision notes.
    pub change_notes: String,
    /// Golden-suite floor.
    pub minimum_golden_score: BasisPoints,
    /// Adversarial-suite floor.
    pub minimum_adversarial_score: BasisPoints,
    /// Evaluated languages.
    pub evaluated_languages: BTreeSet<LanguageTag>,
    /// Immutable multilingual golden cases.
    pub golden_case_digests: BTreeSet<contextdb_core::ContentDigest>,
    /// Immutable adversarial/privacy cases.
    pub adversarial_case_digests: BTreeSet<contextdb_core::ContentDigest>,
}

impl PromptAsset {
    /// Validates and hashes an immutable prompt asset.
    pub fn new(definition: PromptAssetDefinition) -> Result<Self> {
        if definition.version == 0 || definition.token_budget == 0 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "prompt_asset",
                reason: "version and token budget must be positive",
            });
        }
        definition.capability.validate()?;
        validate_text(
            &definition.system_text,
            "prompt_asset.system_text",
            MAX_PROMPT_BYTES,
        )?;
        validate_text(&definition.purpose, "prompt_asset.purpose", MAX_TEXT_BYTES)?;
        validate_text(
            &definition.change_notes,
            "prompt_asset.change_notes",
            MAX_TEXT_BYTES,
        )?;
        for value in &definition.allowed_ontology {
            validate_text(value, "prompt_asset.allowed_ontology", MAX_ID_BYTES)?;
        }
        if definition.evaluated_languages.is_empty()
            || definition.golden_case_digests.is_empty()
            || definition.adversarial_case_digests.is_empty()
            || definition
                .golden_case_digests
                .iter()
                .chain(&definition.adversarial_case_digests)
                .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
        {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "prompt_asset.evaluation_cases",
                reason: "languages, golden cases, and adversarial cases must be recorded",
            });
        }
        if definition.output_schema.version == 0 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "prompt_asset.output_schema",
                reason: "schema version must be positive",
            });
        }
        let digest = canonical_digest(
            b"contextdb-model-prompt-asset-v1\0",
            &PromptDigestInput {
                id: &definition.id,
                version: definition.version,
                capability: &definition.capability,
                output_schema: &definition.output_schema,
                system_text: &definition.system_text,
                purpose: &definition.purpose,
                allowed_ontology: &definition.allowed_ontology,
                token_budget: definition.token_budget,
                privacy_classification: definition.privacy_classification,
                change_notes: &definition.change_notes,
                minimum_golden_score: definition.minimum_golden_score,
                minimum_adversarial_score: definition.minimum_adversarial_score,
                evaluated_languages: &definition.evaluated_languages,
                golden_case_digests: &definition.golden_case_digests,
                adversarial_case_digests: &definition.adversarial_case_digests,
            },
        )?;
        Ok(Self {
            reference: PromptAssetRef {
                id: definition.id.clone(),
                version: definition.version,
                digest,
            },
            id: definition.id,
            version: definition.version,
            capability: definition.capability,
            output_schema: definition.output_schema,
            system_text: definition.system_text,
            purpose: definition.purpose,
            allowed_ontology: definition.allowed_ontology,
            token_budget: definition.token_budget,
            privacy_classification: definition.privacy_classification,
            change_notes: definition.change_notes,
            minimum_golden_score: definition.minimum_golden_score,
            minimum_adversarial_score: definition.minimum_adversarial_score,
            evaluated_languages: definition.evaluated_languages,
            golden_case_digests: definition.golden_case_digests,
            adversarial_case_digests: definition.adversarial_case_digests,
        })
    }

    /// Recomputes the prompt hash and metadata binding.
    pub fn verify(&self) -> Result<()> {
        let rebuilt = Self::new(PromptAssetDefinition {
            id: self.id.clone(),
            version: self.version,
            capability: self.capability.clone(),
            output_schema: self.output_schema.clone(),
            system_text: self.system_text.clone(),
            purpose: self.purpose.clone(),
            allowed_ontology: self.allowed_ontology.clone(),
            token_budget: self.token_budget,
            privacy_classification: self.privacy_classification,
            change_notes: self.change_notes.clone(),
            minimum_golden_score: self.minimum_golden_score,
            minimum_adversarial_score: self.minimum_adversarial_score,
            evaluated_languages: self.evaluated_languages.clone(),
            golden_case_digests: self.golden_case_digests.clone(),
            adversarial_case_digests: self.adversarial_case_digests.clone(),
        })?;
        if rebuilt.reference != self.reference {
            return Err(ModelRuntimeError::PromptUnavailable);
        }
        Ok(())
    }
}

/// Immutable prompt-asset registry.
#[derive(Default)]
pub struct PromptRegistry {
    assets: RwLock<BTreeMap<(PromptAssetId, u32), Arc<PromptAsset>>>,
}

impl fmt::Debug for PromptRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptRegistry")
            .finish_non_exhaustive()
    }
}

impl PromptRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an immutable prompt revision.
    pub fn register(&self, asset: PromptAsset) -> Result<PromptAssetRef> {
        asset.verify()?;
        let key = (asset.id.clone(), asset.version);
        let mut assets = self
            .assets
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        if let Some(existing) = assets.get(&key) {
            if existing.reference == asset.reference {
                return Ok(existing.reference.clone());
            }
            return Err(ModelRuntimeError::RegistryConflict(format!(
                "prompt {} version {}",
                asset.id, asset.version
            )));
        }
        let reference = asset.reference.clone();
        assets.insert(key, Arc::new(asset));
        Ok(reference)
    }

    /// Resolves an exact immutable prompt reference.
    pub fn get(&self, reference: &PromptAssetRef) -> Result<Arc<PromptAsset>> {
        let assets = self
            .assets
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        assets
            .get(&(reference.id.clone(), reference.version))
            .filter(|asset| asset.reference == *reference)
            .cloned()
            .ok_or(ModelRuntimeError::PromptUnavailable)
    }
}
