use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::DateTime;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SignetError;
use crate::receipt::{Action, Signer};

// ─── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationIdentity {
    pub pubkey: String, // "ed25519:<base64>"
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    pub tools: Vec<String>,   // tool names, or ["*"]
    pub targets: Vec<String>, // target URIs, or ["*"]
    pub max_depth: u32,       // 0 = cannot re-delegate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>, // RFC 3339 with UTC (Z)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<serde_json::Value>, // reserved for future use
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    pub v: u8, // always 1
    pub id: String,
    pub delegator: DelegationIdentity,
    pub delegate: DelegationIdentity,
    pub scope: Scope,
    pub issued_at: String, // RFC 3339 with UTC (Z)
    pub nonce: String,
    pub sig: String, // "ed25519:<base64>"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>, // unsigned annotation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub chain: Vec<DelegationToken>,
    pub chain_hash: String,  // "sha256:<hex>" of JCS-canonicalized chain
    pub root_pubkey: String, // must match chain[0].delegator.pubkey
}

// ─── Shared Crypto Helpers ───────────────────────────────────────────────────

/// Generate a cryptographically secure 128-bit nonce.
pub(crate) fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("rnd_{}", hex::encode(bytes))
}

/// Get current UTC timestamp in RFC 3339 format with milliseconds.
pub(crate) fn current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Derive a receipt/token ID from a signature.
pub(crate) fn derive_id(prefix: &str, sig_bytes: &[u8]) -> String {
    let hash = Sha256::digest(sig_bytes);
    format!("{}_{}", prefix, hex::encode(&hash[..16]))
}

/// Format an Ed25519 public key as "ed25519:<base64>".
pub(crate) fn format_pubkey(bytes: &[u8]) -> String {
    format!("ed25519:{}", BASE64.encode(bytes))
}

/// Format an Ed25519 signature as "ed25519:<base64>".
pub(crate) fn format_sig(sig_bytes: &[u8]) -> String {
    format!("ed25519:{}", BASE64.encode(sig_bytes))
}

/// Check if a scope list is a wildcard.
pub(crate) fn is_wildcard(items: &[String]) -> bool {
    items.len() == 1 && items[0] == "*"
}

// ─── Scope Narrowing ────────────────────────────────────────────────────────

pub fn validate_scope_narrowing(child: &Scope, parent: &Scope) -> Result<(), SignetError> {
    // Tools
    if !is_wildcard(&parent.tools) {
        if is_wildcard(&child.tools) {
            return Err(SignetError::ScopeViolation(
                "child cannot have wildcard tools when parent has explicit tools".to_string(),
            ));
        }
        for tool in &child.tools {
            if !parent.tools.contains(tool) {
                return Err(SignetError::ScopeViolation(format!(
                    "tool '{}' not in parent scope",
                    tool
                )));
            }
        }
    }

    // Targets
    if !is_wildcard(&parent.targets) {
        if is_wildcard(&child.targets) {
            return Err(SignetError::ScopeViolation(
                "child cannot have wildcard targets when parent has explicit targets".to_string(),
            ));
        }
        for target in &child.targets {
            if !parent.targets.contains(target) {
                return Err(SignetError::ScopeViolation(format!(
                    "target '{}' not in parent scope",
                    target
                )));
            }
        }
    }

    // max_depth: must be strictly less
    if parent.max_depth == 0 {
        return Err(SignetError::ScopeViolation(
            "parent max_depth is 0, cannot delegate".to_string(),
        ));
    }
    if child.max_depth >= parent.max_depth {
        return Err(SignetError::ScopeViolation(format!(
            "child max_depth {} must be strictly less than parent max_depth {}",
            child.max_depth, parent.max_depth
        )));
    }

    // Expiry
    if let Some(ref parent_expires) = parent.expires {
        match &child.expires {
            None => {
                return Err(SignetError::ScopeViolation(
                    "child must have expiry when parent does".to_string(),
                ));
            }
            Some(child_expires) => {
                let parent_dt = DateTime::parse_from_rfc3339(parent_expires).map_err(|e| {
                    SignetError::ScopeViolation(format!("invalid parent expiry: {}", e))
                })?;
                let child_dt = DateTime::parse_from_rfc3339(child_expires).map_err(|e| {
                    SignetError::ScopeViolation(format!("invalid child expiry: {}", e))
                })?;
                if child_dt > parent_dt {
                    return Err(SignetError::ScopeViolation(format!(
                        "child expiry {} is after parent expiry {}",
                        child_expires, parent_expires
                    )));
                }
            }
        }
    }

    Ok(())
}

// ─── Shared Signable Helpers ────────────────────────────────────────────────

/// Build the signable JSON for a DelegationToken.
/// Excludes: sig, id, correlation_id, budget.
pub(crate) fn build_delegation_signable(
    delegator: &DelegationIdentity,
    delegate: &DelegationIdentity,
    scope: &Scope,
    issued_at: &str,
    nonce: &str,
) -> serde_json::Value {
    let mut signable_scope = serde_json::json!({
        "tools": scope.tools,
        "targets": scope.targets,
        "max_depth": scope.max_depth,
    });
    if let Some(ref expires) = scope.expires {
        signable_scope["expires"] = serde_json::json!(expires);
    }

    serde_json::json!({
        "v": 1u8,
        "delegator": { "pubkey": delegator.pubkey, "name": delegator.name },
        "delegate": { "pubkey": delegate.pubkey, "name": delegate.name },
        "scope": signable_scope,
        "issued_at": issued_at,
        "nonce": nonce,
    })
}

/// Build the signable JSON for a v4 receipt.
/// Signs chain_hash and root_pubkey, NOT the full chain.
/// Used by sign_authorized() and verify_v4_signature_only().
pub(crate) fn build_v4_receipt_signable(
    action: &Action,
    signer: &Signer,
    chain_hash: &str,
    root_pubkey: &str,
    ts: &str,
    nonce: &str,
) -> serde_json::Value {
    serde_json::json!({
        "v": 4u8,
        "action": action,
        "signer": signer,
        "authorization": {
            "chain_hash": chain_hash,
            "root_pubkey": root_pubkey,
        },
        "ts": ts,
        "nonce": nonce,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(tools: &[&str], targets: &[&str], max_depth: u32, expires: Option<&str>) -> Scope {
        Scope {
            tools: tools.iter().map(|s| s.to_string()).collect(),
            targets: targets.iter().map(|s| s.to_string()).collect(),
            max_depth,
            expires: expires.map(|s| s.to_string()),
            budget: None,
        }
    }

    #[test]
    fn test_scope_narrowing_valid_subset() {
        let parent = scope(&["A", "B", "C"], &["mcp://a", "mcp://b"], 2, None);
        let child = scope(&["A", "B"], &["mcp://a"], 1, None);
        assert!(validate_scope_narrowing(&child, &parent).is_ok());
    }

    #[test]
    fn test_scope_narrowing_wildcard_parent_tools() {
        let parent = scope(&["*"], &["*"], 2, None);
        let child = scope(&["Bash", "Read"], &["mcp://github"], 1, None);
        assert!(validate_scope_narrowing(&child, &parent).is_ok());
    }

    #[test]
    fn test_scope_narrowing_child_wildcard_explicit_parent() {
        let parent = scope(&["Bash"], &["mcp://a"], 2, None);
        let child = scope(&["*"], &["mcp://a"], 1, None);
        let err = validate_scope_narrowing(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("wildcard tools"));
    }

    #[test]
    fn test_scope_narrowing_child_targets_wildcard_explicit_parent() {
        let parent = scope(&["*"], &["mcp://a"], 2, None);
        let child = scope(&["Bash"], &["*"], 1, None);
        let err = validate_scope_narrowing(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("wildcard targets"));
    }

    #[test]
    fn test_scope_narrowing_tool_not_in_parent() {
        let parent = scope(&["Bash", "Read"], &["*"], 2, None);
        let child = scope(&["Bash", "Write"], &["*"], 1, None);
        let err = validate_scope_narrowing(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("tool 'Write' not in parent"));
    }

    #[test]
    fn test_scope_narrowing_target_not_in_parent() {
        let parent = scope(&["*"], &["mcp://a"], 2, None);
        let child = scope(&["*"], &["mcp://b"], 1, None);
        let err = validate_scope_narrowing(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("target 'mcp://b' not in parent"));
    }

    #[test]
    fn test_scope_narrowing_max_depth_valid() {
        let parent = scope(&["*"], &["*"], 3, None);
        let child = scope(&["*"], &["*"], 2, None);
        assert!(validate_scope_narrowing(&child, &parent).is_ok());
    }

    #[test]
    fn test_scope_narrowing_max_depth_equal() {
        let parent = scope(&["*"], &["*"], 2, None);
        let child = scope(&["*"], &["*"], 2, None);
        let err = validate_scope_narrowing(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("strictly less"));
    }

    #[test]
    fn test_scope_narrowing_max_depth_zero_parent() {
        let parent = scope(&["*"], &["*"], 0, None);
        let child = scope(&["*"], &["*"], 0, None);
        let err = validate_scope_narrowing(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("max_depth is 0"));
    }

    #[test]
    fn test_scope_narrowing_expiry_valid() {
        let parent = scope(&["*"], &["*"], 2, Some("2026-04-10T00:00:00Z"));
        let child = scope(&["*"], &["*"], 1, Some("2026-04-09T00:00:00Z"));
        assert!(validate_scope_narrowing(&child, &parent).is_ok());
    }

    #[test]
    fn test_scope_narrowing_expiry_child_later() {
        let parent = scope(&["*"], &["*"], 2, Some("2026-04-09T00:00:00Z"));
        let child = scope(&["*"], &["*"], 1, Some("2026-04-10T00:00:00Z"));
        let err = validate_scope_narrowing(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("after parent expiry"));
    }

    #[test]
    fn test_scope_narrowing_expiry_parent_has_child_missing() {
        let parent = scope(&["*"], &["*"], 2, Some("2026-04-10T00:00:00Z"));
        let child = scope(&["*"], &["*"], 1, None);
        let err = validate_scope_narrowing(&child, &parent).unwrap_err();
        assert!(err.to_string().contains("must have expiry"));
    }

    #[test]
    fn test_scope_narrowing_expiry_parent_none() {
        let parent = scope(&["*"], &["*"], 2, None);
        let child = scope(&["*"], &["*"], 1, Some("2026-04-10T00:00:00Z"));
        assert!(validate_scope_narrowing(&child, &parent).is_ok());
    }

    #[test]
    fn test_scope_narrowing_both_wildcard() {
        let parent = scope(&["*"], &["*"], 2, None);
        let child = scope(&["*"], &["*"], 1, None);
        assert!(validate_scope_narrowing(&child, &parent).is_ok());
    }

    #[test]
    fn test_scope_narrowing_expiry_equal() {
        let parent = scope(&["*"], &["*"], 2, Some("2026-04-10T00:00:00Z"));
        let child = scope(&["*"], &["*"], 1, Some("2026-04-10T00:00:00Z"));
        assert!(validate_scope_narrowing(&child, &parent).is_ok());
    }
}
