use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalJsonError {
    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn canonicalize<T: Serialize>(value: &T) -> Result<String, CanonicalJsonError> {
    let value = sort_value(serde_json::to_value(value)?);
    Ok(serde_json::to_string(&value)?)
}

pub fn sha256_hex(canonical_json: &str) -> String {
    format!("{:x}", Sha256::digest(canonical_json.as_bytes()))
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sort_value(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_are_recursive_and_stable() {
        assert_eq!(
            canonicalize(&json!({"z":1,"a":{"y":2,"b":3}})).unwrap(),
            r#"{"a":{"b":3,"y":2},"z":1}"#
        );
    }
    #[test]
    fn stable_hash_vector() {
        assert_eq!(
            sha256_hex("{}"),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
}
