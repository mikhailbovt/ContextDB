use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::error::{ReferenceError, Result};

/// Serializes a value after recursively sorting all JSON object keys.
pub(crate) fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|error| ReferenceError::Serialization(error.to_string()))?;
    serde_json::to_vec(&canonicalize(value))
        .map_err(|error| ReferenceError::Serialization(error.to_string()))
}

/// Returns a stable BLAKE3 digest for a serializable logical value.
pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(blake3::hash(&to_vec(value)?).to_hex().to_string())
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::to_vec;

    #[test]
    fn recursively_sorts_object_keys() {
        let left = json!({"z": {"b": 2, "a": 1}, "a": 0});
        let right = json!({"a": 0, "z": {"a": 1, "b": 2}});
        assert_eq!(to_vec(&left), to_vec(&right));
    }
}
