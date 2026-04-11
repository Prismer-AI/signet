use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::error::SignetError;

// ─── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u8,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_allow")]
    pub default_action: RuleAction,
    pub rules: Vec<Rule>,
}

fn default_allow() -> RuleAction {
    RuleAction::Allow
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    pub action: RuleAction,
    #[serde(default)]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
}

/// Deny=2 > RequireApproval=1 > Allow=0 for max-severity evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow = 0,
    RequireApproval = 1,
    Deny = 2,
}

impl std::fmt::Display for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleAction::Allow => write!(f, "allow"),
            RuleAction::RequireApproval => write!(f, "require_approval"),
            RuleAction::Deny => write!(f, "deny"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MatchSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<StringMatcher>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<StringMatcher>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<StringMatcher>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, ParamMatcher>>,
}

/// String matching — exact string or operator-based.
/// Exact must come first for serde(untagged) to try it before Operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringMatcher {
    Exact(String),
    Operator(StringMatchOp),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringMatchOp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_one_of: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
}

/// Parameter value matching — operator object or exact value.
/// Custom deserialization: if the YAML/JSON is an object containing
/// operator keys (gt, gte, lt, lte, eq, one_of, contains), parse as
/// Operator. Otherwise parse as Exact.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ParamMatcher {
    Operator(ParamMatchOp),
    Exact(serde_json::Value),
}

impl<'de> serde::Deserialize<'de> for ParamMatcher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let serde_json::Value::Object(ref map) = value {
            let operator_keys = ["gt", "gte", "lt", "lte", "eq", "one_of", "contains"];
            if map.keys().any(|k| operator_keys.contains(&k.as_str())) {
                let op: ParamMatchOp =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                return Ok(ParamMatcher::Operator(op));
            }
        }
        Ok(ParamMatcher::Exact(value))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParamMatchOp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gt: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gte: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lt: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lte: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eq: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_calls: u32,
    pub window_seconds: u64,
    #[serde(default)]
    pub scope: RateLimitScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    #[default]
    PerTool,
    PerAgent,
    Global,
}

// ─── Policy Attestation (embedded in signed receipt) ────────────────────────

/// Cryptographic policy attestation — included in the receipt signable payload.
/// This is Signet's differentiator: the receipt proves policy was satisfied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAttestation {
    pub policy_hash: String,
    pub policy_name: String,
    pub matched_rules: Vec<String>,
    pub decision: RuleAction,
    pub reason: String,
}

// ─── Evaluation Result ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyEvalResult {
    pub decision: RuleAction,
    pub matched_rules: Vec<String>,
    pub winning_rule: Option<String>,
    pub reason: String,
    pub evaluated_at: String,
    pub policy_name: String,
    pub policy_hash: String,
}

// ─── Policy Hash ────────────────────────────────────────────────────────────

/// Compute a deterministic hash of a policy (format-independent: YAML and JSON produce the same hash).
pub fn compute_policy_hash(policy: &Policy) -> Result<String, SignetError> {
    let json_value = serde_json::to_value(policy)?;
    let canonical = canonical::canonicalize(&json_value)?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hash)))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_action_ordering() {
        assert!(RuleAction::Deny > RuleAction::RequireApproval);
        assert!(RuleAction::RequireApproval > RuleAction::Allow);
        assert!(RuleAction::Deny > RuleAction::Allow);
    }

    #[test]
    fn test_rule_action_serde_roundtrip() {
        let json = serde_json::to_string(&RuleAction::Allow).unwrap();
        assert_eq!(json, "\"allow\"");
        let parsed: RuleAction = serde_json::from_str("\"deny\"").unwrap();
        assert_eq!(parsed, RuleAction::Deny);
        let parsed2: RuleAction = serde_json::from_str("\"require_approval\"").unwrap();
        assert_eq!(parsed2, RuleAction::RequireApproval);
    }

    #[test]
    fn test_policy_yaml_deser_minimal() {
        let yaml = "version: 1\nrules: []\n";
        let policy: Policy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.rules.is_empty());
        assert_eq!(policy.default_action, RuleAction::Allow);
    }

    #[test]
    fn test_policy_yaml_deser_full() {
        let yaml = r#"
version: 1
name: "test-policy"
description: "A test"
default_action: deny
rules:
  - id: "deny-rm"
    match:
      tool: "Bash"
      params:
        command:
          contains: "rm -rf"
    action: deny
    reason: "no rm"
  - id: "allow-read"
    match:
      tool:
        one_of: ["Read", "Grep"]
    action: allow
  - id: "limit-pay"
    match:
      tool: "payment"
      params:
        amount:
          gt: 1000
    action: require_approval
    reason: "over 1k"
  - id: "target-restrict"
    match:
      target:
        not_one_of: ["mcp://staging"]
    action: deny
    reason: "production only"
"#;
        let policy: Policy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.default_action, RuleAction::Deny);
        assert_eq!(policy.rules.len(), 4);
        assert_eq!(policy.rules[0].id, "deny-rm");
        assert_eq!(policy.rules[1].action, RuleAction::Allow);
        assert_eq!(policy.rules[2].action, RuleAction::RequireApproval);
    }

    #[test]
    fn test_string_matcher_exact_deser() {
        let yaml = "\"Bash\"";
        let m: StringMatcher = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(m, StringMatcher::Exact(s) if s == "Bash"));
    }

    #[test]
    fn test_string_matcher_one_of_deser() {
        let yaml = "one_of: [\"Read\", \"Grep\"]";
        let m: StringMatcher = serde_yaml::from_str(yaml).unwrap();
        match m {
            StringMatcher::Operator(op) => {
                assert_eq!(op.one_of.unwrap(), vec!["Read", "Grep"]);
            }
            _ => panic!("expected Operator"),
        }
    }

    #[test]
    fn test_param_matcher_numeric_deser() {
        let yaml = "gt: 1000";
        let m: ParamMatcher = serde_yaml::from_str(yaml).unwrap();
        match m {
            ParamMatcher::Operator(op) => assert_eq!(op.gt, Some(1000.0)),
            _ => panic!("expected Operator"),
        }
    }

    #[test]
    fn test_policy_attestation_serde_roundtrip() {
        let att = PolicyAttestation {
            policy_hash: "sha256:abc".into(),
            policy_name: "test".into(),
            matched_rules: vec!["rule1".into()],
            decision: RuleAction::Allow,
            reason: "ok".into(),
        };
        let json = serde_json::to_string(&att).unwrap();
        let parsed: PolicyAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.policy_hash, "sha256:abc");
        assert_eq!(parsed.decision, RuleAction::Allow);
    }

    #[test]
    fn test_compute_policy_hash_deterministic() {
        let policy = Policy {
            version: 1,
            name: "test".into(),
            description: String::new(),
            default_action: RuleAction::Allow,
            rules: vec![],
        };
        let h1 = compute_policy_hash(&policy).unwrap();
        let h2 = compute_policy_hash(&policy).unwrap();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
        assert_eq!(h1.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_compute_policy_hash_different() {
        let p1 = Policy {
            version: 1,
            name: "a".into(),
            description: String::new(),
            default_action: RuleAction::Allow,
            rules: vec![],
        };
        let p2 = Policy {
            version: 1,
            name: "b".into(),
            description: String::new(),
            default_action: RuleAction::Allow,
            rules: vec![],
        };
        assert_ne!(
            compute_policy_hash(&p1).unwrap(),
            compute_policy_hash(&p2).unwrap()
        );
    }

    #[test]
    fn test_rate_limit_scope_default() {
        let rl: RateLimit =
            serde_json::from_str(r#"{"max_calls":10,"window_seconds":60}"#).unwrap();
        assert_eq!(rl.scope, RateLimitScope::PerTool);
    }
}
