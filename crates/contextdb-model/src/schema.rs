use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use contextdb_core::ContentDigest;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::types::{MAX_TEXT_BYTES, canonical_digest, validate_text};
use crate::{ModelRuntimeError, Result, SchemaId, SchemaRef};

const MAX_SCHEMA_DEPTH: usize = 64;
const MAX_SCHEMA_COMPLEXITY: u32 = 100_000;

/// Executable strict-schema node used at the provider boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SchemaNode {
    /// JSON null.
    Null,
    /// JSON boolean.
    Boolean,
    /// Signed JSON integer.
    Integer {
        /// Optional inclusive minimum.
        minimum: Option<i64>,
        /// Optional inclusive maximum.
        maximum: Option<i64>,
    },
    /// Finite JSON number. Capability-specific ranges and normalization use a
    /// semantic validator so no binary floating-point value enters the schema
    /// hash or policy decisions.
    Number,
    /// UTF-8 string with a hard byte bound and optional ontology enumeration.
    String {
        /// Maximum UTF-8 bytes.
        max_bytes: usize,
        /// Empty means any bounded string; otherwise exact allowed values.
        allowed: BTreeSet<String>,
    },
    /// Homogeneous bounded array.
    Array {
        /// Item contract.
        items: Box<SchemaNode>,
        /// Minimum item count.
        min_items: usize,
        /// Maximum item count.
        max_items: usize,
    },
    /// Object with explicit properties. Unknown fields are rejected by default.
    Object {
        /// Named properties.
        properties: BTreeMap<String, SchemaNode>,
        /// Required property names.
        required: BTreeSet<String>,
        /// Explicit opt-in for extension fields.
        allow_unknown_fields: bool,
    },
    /// Exactly one alternative must match.
    OneOf {
        /// Alternatives.
        variants: Vec<SchemaNode>,
    },
}

impl SchemaNode {
    fn validate_definition(&self, depth: usize) -> Result<u32> {
        if depth > MAX_SCHEMA_DEPTH {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "schema.depth",
                reason: "schema nesting exceeds runtime limit",
            });
        }
        let child_complexity = match self {
            Self::Null | Self::Boolean | Self::Number => 0,
            Self::Integer { minimum, maximum } => {
                if minimum.zip(*maximum).is_some_and(|(min, max)| min > max) {
                    return Err(ModelRuntimeError::InvalidNumber {
                        field: "schema.integer",
                        reason: "minimum exceeds maximum",
                    });
                }
                0
            }
            Self::String { max_bytes, allowed } => {
                if *max_bytes == 0 || *max_bytes > MAX_TEXT_BYTES {
                    return Err(ModelRuntimeError::InvalidNumber {
                        field: "schema.string.max_bytes",
                        reason: "must be within runtime text bounds",
                    });
                }
                for value in allowed {
                    if value.len() > *max_bytes {
                        return Err(ModelRuntimeError::InvalidText {
                            field: "schema.string.allowed",
                            reason: "enumerated value exceeds string bound",
                        });
                    }
                }
                u32::try_from(allowed.len()).unwrap_or(u32::MAX)
            }
            Self::Array {
                items,
                min_items,
                max_items,
            } => {
                if max_items < min_items || *max_items > 100_000 {
                    return Err(ModelRuntimeError::InvalidNumber {
                        field: "schema.array",
                        reason: "invalid item bounds",
                    });
                }
                items.validate_definition(depth.saturating_add(1))?
            }
            Self::Object {
                properties,
                required,
                ..
            } => {
                if properties.len() > 10_000
                    || !required.is_subset(&properties.keys().cloned().collect())
                {
                    return Err(ModelRuntimeError::InvalidNumber {
                        field: "schema.object",
                        reason: "invalid property or required-field set",
                    });
                }
                let mut total = 0_u32;
                for (name, schema) in properties {
                    validate_text(name, "schema.object.property", 256)?;
                    total = total
                        .checked_add(schema.validate_definition(depth.saturating_add(1))?)
                        .ok_or(ModelRuntimeError::ArithmeticOverflow)?;
                }
                total
            }
            Self::OneOf { variants } => {
                if variants.len() < 2 || variants.len() > 64 {
                    return Err(ModelRuntimeError::InvalidNumber {
                        field: "schema.one_of",
                        reason: "must contain between 2 and 64 variants",
                    });
                }
                let mut total = 0_u32;
                for variant in variants {
                    total = total
                        .checked_add(variant.validate_definition(depth.saturating_add(1))?)
                        .ok_or(ModelRuntimeError::ArithmeticOverflow)?;
                }
                total
            }
        };
        child_complexity
            .checked_add(1)
            .ok_or(ModelRuntimeError::ArithmeticOverflow)
    }

    fn validate_value(&self, value: &Value, path: &str, depth: usize) -> Result<()> {
        if depth > MAX_SCHEMA_DEPTH {
            return Err(schema_violation(path, "value nesting exceeds schema limit"));
        }
        match self {
            Self::Null if value.is_null() => Ok(()),
            Self::Boolean if value.is_boolean() => Ok(()),
            Self::Integer { minimum, maximum } => {
                let integer = value
                    .as_i64()
                    .ok_or_else(|| schema_violation(path, "expected signed integer"))?;
                if minimum.is_some_and(|minimum| integer < minimum)
                    || maximum.is_some_and(|maximum| integer > maximum)
                {
                    return Err(schema_violation(path, "integer outside allowed range"));
                }
                Ok(())
            }
            Self::Number if value.is_number() => Ok(()),
            Self::String { max_bytes, allowed } => {
                let text = value
                    .as_str()
                    .ok_or_else(|| schema_violation(path, "expected string"))?;
                if text.len() > *max_bytes {
                    return Err(schema_violation(path, "string exceeds byte limit"));
                }
                if !allowed.is_empty() && !allowed.contains(text) {
                    return Err(schema_violation(path, "string is outside allowed ontology"));
                }
                Ok(())
            }
            Self::Array {
                items,
                min_items,
                max_items,
            } => {
                let values = value
                    .as_array()
                    .ok_or_else(|| schema_violation(path, "expected array"))?;
                if values.len() < *min_items || values.len() > *max_items {
                    return Err(schema_violation(path, "array outside item-count bounds"));
                }
                for (index, item) in values.iter().enumerate() {
                    items.validate_value(
                        item,
                        &format!("{path}/{index}"),
                        depth.saturating_add(1),
                    )?;
                }
                Ok(())
            }
            Self::Object {
                properties,
                required,
                allow_unknown_fields,
            } => {
                let object = value
                    .as_object()
                    .ok_or_else(|| schema_violation(path, "expected object"))?;
                for required in required {
                    if !object.contains_key(required) {
                        return Err(schema_violation(
                            &format!("{path}/{}", escape_pointer(required)),
                            "required property is missing",
                        ));
                    }
                }
                for (name, child) in object {
                    match properties.get(name) {
                        Some(schema) => schema.validate_value(
                            child,
                            &format!("{path}/{}", escape_pointer(name)),
                            depth.saturating_add(1),
                        )?,
                        None if !allow_unknown_fields => {
                            return Err(schema_violation(
                                &format!("{path}/{}", escape_pointer(name)),
                                "unknown property",
                            ));
                        }
                        None => {}
                    }
                }
                Ok(())
            }
            Self::OneOf { variants } => {
                let matches = variants
                    .iter()
                    .filter(|variant| variant.validate_value(value, path, depth).is_ok())
                    .count();
                if matches != 1 {
                    return Err(schema_violation(
                        path,
                        "expected exactly one matching variant",
                    ));
                }
                Ok(())
            }
            _ => Err(schema_violation(path, "JSON type does not match schema")),
        }
    }
}

/// Immutable executable structured-output schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredSchema {
    /// Schema family.
    pub id: SchemaId,
    /// Positive family-local version.
    pub version: u32,
    /// Root schema.
    pub root: SchemaNode,
    /// Maximum accepted provider response bytes.
    pub max_output_bytes: usize,
    /// Precomputed schema complexity score used for route compatibility.
    pub complexity: u32,
    /// Exact immutable reference.
    pub reference: SchemaRef,
}

#[derive(Serialize)]
struct SchemaDigestInput<'a> {
    id: &'a SchemaId,
    version: u32,
    root: &'a SchemaNode,
    max_output_bytes: usize,
    complexity: u32,
}

impl StructuredSchema {
    /// Builds, validates, and hashes an executable schema.
    pub fn new(
        id: SchemaId,
        version: u32,
        root: SchemaNode,
        max_output_bytes: usize,
    ) -> Result<Self> {
        if version == 0 || max_output_bytes == 0 || max_output_bytes > 64 * 1024 * 1024 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "structured_schema",
                reason: "version and byte budget must be within runtime limits",
            });
        }
        let complexity = root.validate_definition(0)?;
        if complexity > MAX_SCHEMA_COMPLEXITY {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "structured_schema.complexity",
                reason: "schema exceeds runtime complexity limit",
            });
        }
        let digest = canonical_digest(
            b"contextdb-model-schema-v1\0",
            &SchemaDigestInput {
                id: &id,
                version,
                root: &root,
                max_output_bytes,
                complexity,
            },
        )?;
        Ok(Self {
            reference: SchemaRef {
                id: id.clone(),
                version,
                digest,
            },
            id,
            version,
            root,
            max_output_bytes,
            complexity,
        })
    }

    /// Recomputes and checks the immutable schema reference.
    pub fn verify(&self) -> Result<()> {
        let rebuilt = Self::new(
            self.id.clone(),
            self.version,
            self.root.clone(),
            self.max_output_bytes,
        )?;
        if rebuilt.reference != self.reference || rebuilt.complexity != self.complexity {
            return Err(ModelRuntimeError::SchemaUnavailable(self.reference.clone()));
        }
        Ok(())
    }
}

/// Schema-specific validation after structural JSON checks, such as evidence
/// span containment or vector dimensions.
pub trait SemanticOutputValidator: Send + Sync {
    /// Returns a safe, payload-free violation code or message.
    fn validate(&self, value: &Value) -> std::result::Result<(), String>;
}

/// Validator which imposes no additional semantic constraint.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSemanticValidator;

impl SemanticOutputValidator for NoopSemanticValidator {
    fn validate(&self, _value: &Value) -> std::result::Result<(), String> {
        Ok(())
    }
}

struct SchemaContract {
    schema: StructuredSchema,
    semantic: Arc<dyn SemanticOutputValidator>,
}

impl fmt::Debug for SchemaContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaContract")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

/// Registry of immutable executable schemas.
#[derive(Default)]
pub struct SchemaRegistry {
    entries: RwLock<BTreeMap<(SchemaId, u32), Arc<SchemaContract>>>,
}

impl fmt::Debug for SchemaRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaRegistry")
            .finish_non_exhaustive()
    }
}

impl SchemaRegistry {
    /// Creates an empty schema registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an immutable schema and semantic validator. Re-registering an
    /// identical reference is idempotent; changing an existing version fails.
    pub fn register(
        &self,
        schema: StructuredSchema,
        semantic: Arc<dyn SemanticOutputValidator>,
    ) -> Result<SchemaRef> {
        schema.verify()?;
        let key = (schema.id.clone(), schema.version);
        let mut entries = self
            .entries
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        if let Some(existing) = entries.get(&key) {
            if existing.schema.reference == schema.reference {
                return Ok(existing.schema.reference.clone());
            }
            return Err(ModelRuntimeError::RegistryConflict(format!(
                "schema {} version {}",
                schema.id, schema.version
            )));
        }
        let reference = schema.reference.clone();
        entries.insert(key, Arc::new(SchemaContract { schema, semantic }));
        Ok(reference)
    }

    /// Registers a schema with structural validation only.
    pub fn register_structural(&self, schema: StructuredSchema) -> Result<SchemaRef> {
        self.register(schema, Arc::new(NoopSemanticValidator))
    }

    /// Validates one untrusted provider response into an opaque proposal.
    pub fn validate_raw(
        &self,
        schema_ref: &SchemaRef,
        raw: &[u8],
    ) -> Result<ValidatedModelProposal> {
        let contract = self.contract(schema_ref)?;
        if raw.len() > contract.schema.max_output_bytes {
            return Err(ModelRuntimeError::OutputTooLarge {
                maximum: contract.schema.max_output_bytes,
            });
        }
        let NoDuplicateValue(value) = serde_json::from_slice::<NoDuplicateValue>(raw)
            .map_err(|error| ModelRuntimeError::MalformedJson(error.to_string()))?;
        contract.schema.root.validate_value(&value, "", 0)?;
        contract.semantic.validate(&value).map_err(|message| {
            let safe = if message.len() <= 512 {
                message
            } else {
                "semantic validator returned an overlong violation".to_owned()
            };
            ModelRuntimeError::SemanticViolation(safe)
        })?;
        let output_digest = crate::types::digest_parts(
            b"contextdb-model-validated-output-v1\0",
            &[schema_ref.digest.as_bytes(), raw],
        );
        Ok(ValidatedModelProposal {
            schema: schema_ref.clone(),
            output_digest,
            raw: Arc::from(raw),
            value: Arc::new(value),
        })
    }

    /// Returns whether the exact immutable reference exists.
    pub fn contains(&self, schema_ref: &SchemaRef) -> bool {
        self.contract(schema_ref).is_ok()
    }

    /// Returns the schema complexity used by model-profile routing.
    pub fn complexity(&self, schema_ref: &SchemaRef) -> Result<u32> {
        Ok(self.contract(schema_ref)?.schema.complexity)
    }

    fn contract(&self, schema_ref: &SchemaRef) -> Result<Arc<SchemaContract>> {
        let entries = self
            .entries
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        entries
            .get(&(schema_ref.id.clone(), schema_ref.version))
            .filter(|contract| contract.schema.reference == *schema_ref)
            .cloned()
            .ok_or_else(|| ModelRuntimeError::SchemaUnavailable(schema_ref.clone()))
    }
}

/// Structurally and semantically validated provider proposal.
///
/// Its fields are private, so provider bytes cannot be confused with validated
/// output. Downstream mutation planning must accept this type or validate again.
#[derive(Clone)]
pub struct ValidatedModelProposal {
    schema: SchemaRef,
    output_digest: ContentDigest,
    raw: Arc<[u8]>,
    value: Arc<Value>,
}

impl fmt::Debug for ValidatedModelProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedModelProposal")
            .field("schema", &self.schema)
            .field("output_digest", &self.output_digest)
            .field("validated_bytes", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl ValidatedModelProposal {
    /// Exact schema used for validation.
    #[must_use]
    pub fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    /// Digest suitable for audit and derived-artifact lineage.
    #[must_use]
    pub const fn output_digest(&self) -> ContentDigest {
        self.output_digest
    }

    /// Validated JSON value.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Exact validated bytes for recorded replay.
    #[must_use]
    pub fn validated_bytes(&self) -> &[u8] {
        &self.raw
    }
}

fn schema_violation(path: &str, reason: &str) -> ModelRuntimeError {
    ModelRuntimeError::SchemaViolation {
        path: if path.is_empty() {
            "/".to_owned()
        } else {
            path.to_owned()
        },
        reason: reason.to_owned(),
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor).map(Self)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1_024));
        while let Some(NoDuplicateValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::with_capacity(map.size_hint().unwrap_or(0).min(1_024));
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let NoDuplicateValue(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
