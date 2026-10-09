//! Existing core types keep their ABI. This new record boundary checks nested
//! object/set duplicates before their ordinary serde collections can collapse them.

use serde::{
    Deserialize, Deserializer,
    de::{DeserializeOwned, Error, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::BTreeSet, fmt};

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("bounded core metadata without duplicate identities")
            }
            fn visit_bool<E: Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E: Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_u64<E: Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_f64<E: Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| StrictValue(Value::Number(value)))
                    .ok_or_else(|| E::custom("nonfinite core metadata"))
            }
            fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > super::MAX_RECORD_BYTES {
                    return Err(E::custom("excessive core metadata"));
                }
                Ok(StrictValue(Value::String(value.into())))
            }
            fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
                self.visit_str(&value)
            }
            fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
                self.visit_none()
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    if values.len() >= super::MAX_SCORES {
                        return Err(A::Error::custom("excessive core metadata array"));
                    }
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.len() >= 512 || key.len() > 16384 || values.contains_key(&key) {
                        return Err(A::Error::custom("duplicate or excessive core metadata key"));
                    }
                    let StrictValue(value) = map.next_value()?;
                    if matches!(
                        key.as_str(),
                        "scopes"
                            | "audiences"
                            | "alternatives"
                            | "missing_facets"
                            | "unresolved_conflicts"
                            | "blocking_unknowns"
                            | "unsupported_blocks"
                            | "selected_blocks"
                    ) && let Value::Array(items) = &value
                    {
                        let mut identities = BTreeSet::new();
                        for item in items {
                            let identity = serde_json::to_string(item).map_err(A::Error::custom)?;
                            if !identities.insert(identity) {
                                return Err(A::Error::custom("duplicate core set identity"));
                            }
                        }
                    }
                    values.insert(key, value);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

pub(super) fn core_value<'de, D: Deserializer<'de>, T: DeserializeOwned + serde::Serialize>(
    deserializer: D,
) -> Result<T, D::Error> {
    let StrictValue(value) = StrictValue::deserialize(deserializer)?;
    let typed: T = serde_json::from_value(value.clone()).map_err(D::Error::custom)?;
    if value != serde_json::to_value(&typed).map_err(D::Error::custom)? {
        return Err(D::Error::custom("noncanonical or unknown core metadata"));
    }
    Ok(typed)
}

pub(super) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    budget: &mut contextdb_recall::QueryBudget,
) -> crate::Result<T> {
    if bytes.len() > super::MAX_RECORD_BYTES {
        return Err(crate::ContextError::BudgetExceeded(
            "router input exceeds byte ceiling".into(),
        ));
    }
    super::charge(budget, 1, bytes.len() as u64)?;
    serde_json::from_slice(bytes)
        .map_err(|_| super::invalid("malformed or unsupported router record"))
}
