use std::collections::HashSet;

use crate::error::SignetError;
use crate::policy::Policy;

/// Parse a policy from a YAML string.
pub fn parse_policy_yaml(yaml: &str) -> Result<Policy, SignetError> {
    serde_yaml::from_str(yaml)
        .map_err(|e| SignetError::PolicyParseError(format!("invalid YAML: {e}")))
}

/// Parse a policy from a JSON string.
pub fn parse_policy_json(json: &str) -> Result<Policy, SignetError> {
    serde_json::from_str(json)
        .map_err(|e| SignetError::PolicyParseError(format!("invalid JSON: {e}")))
}

/// Validate a policy for internal consistency.
pub fn validate_policy(policy: &Policy) -> Result<(), SignetError> {
    if policy.version != 1 {
        return Err(SignetError::PolicyParseError(format!(
            "unsupported policy version: {}, expected 1",
            policy.version
        )));
    }

    let mut seen_ids = HashSet::new();
    for rule in &policy.rules {
        if rule.id.is_empty() {
            return Err(SignetError::PolicyParseError(
                "rule ID must be non-empty".into(),
            ));
        }
        if !seen_ids.insert(&rule.id) {
            return Err(SignetError::PolicyParseError(format!(
                "duplicate rule ID: '{}'",
                rule.id
            )));
        }
    }

    Ok(())
}

/// Load a policy from a YAML or JSON file (detected by extension).
#[cfg(not(target_arch = "wasm32"))]
pub fn load_policy(path: &std::path::Path) -> Result<Policy, SignetError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| SignetError::PolicyParseError(format!("failed to read policy file: {e}")))?;

    let policy = match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => parse_policy_yaml(&content)?,
        Some("json") => parse_policy_json(&content)?,
        Some(ext) => {
            return Err(SignetError::PolicyParseError(format!(
                "unsupported policy file extension: .{ext} (use .yaml, .yml, or .json)"
            )))
        }
        None => {
            // Try YAML first, fall back to JSON
            parse_policy_yaml(&content)
                .or_else(|_| parse_policy_json(&content))
                .map_err(|_| {
                    SignetError::PolicyParseError(
                        "could not parse as YAML or JSON (no file extension to detect format)"
                            .into(),
                    )
                })?
        }
    };

    validate_policy(&policy)?;
    Ok(policy)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{compute_policy_hash, RuleAction};

    #[test]
    fn test_parse_yaml_minimal() {
        let yaml = "version: 1\nrules: []\n";
        let policy = parse_policy_yaml(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.rules.is_empty());
    }

    #[test]
    fn test_parse_yaml_full() {
        let yaml = r#"
version: 1
name: "test"
default_action: deny
rules:
  - id: "r1"
    match:
      tool: "Bash"
    action: deny
    reason: "no bash"
  - id: "r2"
    match:
      tool:
        one_of: ["Read", "Grep"]
    action: allow
"#;
        let policy = parse_policy_yaml(yaml).unwrap();
        assert_eq!(policy.name, "test");
        assert_eq!(policy.default_action, RuleAction::Deny);
        assert_eq!(policy.rules.len(), 2);
    }

    #[test]
    fn test_parse_yaml_invalid() {
        let yaml = "not: [valid: yaml: {{";
        assert!(parse_policy_yaml(yaml).is_err());
    }

    #[test]
    fn test_parse_json_valid() {
        let json = r#"{"version":1,"rules":[]}"#;
        let policy = parse_policy_json(json).unwrap();
        assert_eq!(policy.version, 1);
    }

    #[test]
    fn test_parse_json_invalid() {
        assert!(parse_policy_json("not json").is_err());
    }

    #[test]
    fn test_validate_empty_rules() {
        let policy = parse_policy_yaml("version: 1\nrules: []\n").unwrap();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_validate_version_1() {
        let policy = parse_policy_yaml("version: 1\nrules: []\n").unwrap();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_validate_version_0() {
        let policy = parse_policy_yaml("version: 0\nrules: []\n").unwrap();
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("unsupported policy version"));
    }

    #[test]
    fn test_validate_version_2() {
        let policy = parse_policy_yaml("version: 2\nrules: []\n").unwrap();
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_validate_duplicate_rule_ids() {
        let yaml = r#"
version: 1
rules:
  - id: "same"
    match: {tool: "A"}
    action: allow
  - id: "same"
    match: {tool: "B"}
    action: deny
"#;
        let policy = parse_policy_yaml(yaml).unwrap();
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("duplicate rule ID"));
    }

    #[test]
    fn test_validate_empty_rule_id() {
        let yaml = r#"
version: 1
rules:
  - id: ""
    match: {tool: "A"}
    action: allow
"#;
        let policy = parse_policy_yaml(yaml).unwrap();
        let err = validate_policy(&policy).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn test_hash_deterministic() {
        let yaml = "version: 1\nname: test\nrules: []\n";
        let p1 = parse_policy_yaml(yaml).unwrap();
        let p2 = parse_policy_yaml(yaml).unwrap();
        assert_eq!(
            compute_policy_hash(&p1).unwrap(),
            compute_policy_hash(&p2).unwrap()
        );
    }

    #[test]
    fn test_hash_format_independent() {
        let yaml = "version: 1\nname: test\nrules: []\n";
        let json = r#"{"version":1,"name":"test","rules":[]}"#;
        let py = parse_policy_yaml(yaml).unwrap();
        let pj = parse_policy_json(json).unwrap();
        assert_eq!(
            compute_policy_hash(&py).unwrap(),
            compute_policy_hash(&pj).unwrap()
        );
    }

    #[test]
    fn test_load_policy_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "version: 1\nname: file-test\nrules: []\n").unwrap();
        let policy = load_policy(&path).unwrap();
        assert_eq!(policy.name, "file-test");
    }

    #[test]
    fn test_load_policy_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, r#"{"version":1,"name":"json-test","rules":[]}"#).unwrap();
        let policy = load_policy(&path).unwrap();
        assert_eq!(policy.name, "json-test");
    }

    #[test]
    fn test_load_policy_missing_file() {
        let path = std::path::Path::new("/tmp/nonexistent-policy-12345.yaml");
        assert!(load_policy(path).is_err());
    }

    #[test]
    fn test_load_policy_validates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "version: 99\nrules: []\n").unwrap();
        let err = load_policy(&path).unwrap_err();
        assert!(err.to_string().contains("unsupported policy version"));
    }
}
