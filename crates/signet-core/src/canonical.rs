use crate::error::SignetError;

pub fn canonicalize(value: &serde_json::Value) -> Result<String, SignetError> {
    json_canon::to_string(value).map_err(|e| SignetError::CanonicalizeError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_determinism() {
        let value = json!({"b": 2, "a": 1, "c": {"z": 26, "a": 1}});
        let result1 = canonicalize(&value).unwrap();
        let result2 = canonicalize(&value).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_canonical_key_order() {
        let value = json!({"zebra": 1, "apple": 2, "mango": 3});
        let result = canonicalize(&value).unwrap();
        assert_eq!(result, r#"{"apple":2,"mango":3,"zebra":1}"#);
    }

    #[test]
    fn test_canonical_nested_key_order() {
        let value = json!({"b": {"d": 4, "c": 3}, "a": 1});
        let result = canonicalize(&value).unwrap();
        assert_eq!(result, r#"{"a":1,"b":{"c":3,"d":4}}"#);
    }

    #[test]
    fn test_canonical_no_whitespace() {
        let value = json!({"key": "value"});
        let result = canonicalize(&value).unwrap();
        assert!(!result.contains(' '));
        assert!(!result.contains('\n'));
    }

    // Cross-language test vectors (per SEP-1763 discussion with @desiorac).
    // Any Signet implementation in any language MUST produce identical output
    // for these inputs. If these tests fail, cross-language verification breaks.

    #[test]
    fn test_canonical_float_normalization() {
        // JCS: 1.0 and 1 must produce the same canonical form
        let value = json!({"value": 1.0});
        let result = canonicalize(&value).unwrap();
        assert_eq!(result, r#"{"value":1}"#);
    }

    #[test]
    fn test_canonical_non_ascii() {
        // Non-ASCII must survive canonicalization as UTF-8
        let value = json!({"name": "日本語"});
        let result = canonicalize(&value).unwrap();
        assert_eq!(result, "{\"name\":\"日本語\"}");
    }

    #[test]
    fn test_canonical_negative_zero() {
        // JCS: -0 normalizes to 0
        let value: serde_json::Value = serde_json::from_str(r#"{"value": -0.0}"#).unwrap();
        let result = canonicalize(&value).unwrap();
        assert_eq!(result, r#"{"value":0}"#);
    }

    #[test]
    fn test_canonical_hash_prefix_included() {
        // Hash prefix is part of the canonical representation.
        // A compound hash input MUST include the "sha256:" prefix.
        let value = json!({
            "prev_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "receipt": {"v": 1}
        });
        let result = canonicalize(&value).unwrap();
        assert!(result.contains("sha256:e3b0c44"));
    }
}
