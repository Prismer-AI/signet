//! Typed obligations — the "under what conditions" half of a policy rule.
//!
//! An obligation is a typed, versioned contract carried inside the signed
//! policy evidence (`AuthorizationDecision.obligations` in later phases).
//! The envelope (`type`, `version`) is what bounds the signed surface; the
//! `parameters` map is free-form but contract-scoped by that envelope.
//!
//! Registry semantics (spec: docs/specs/principal-authorization-spec.md §5):
//! - Well-known types are validated against their parameter schema at the
//!   latest implemented version. A well-known type with a **future** version
//!   fails validation — unknown semantics are never silently accepted.
//! - Anything else must use an `x-` namespace (syntax-checked only).
//! - Multiple obligations of the same type are conjunctive (all must hold);
//!   any-of belongs at the rule level.

use serde::{Deserialize, Serialize};

use crate::error::SignetError;

/// Well-known obligation types implemented by this version of signet-core.
pub const WELL_KNOWN_OBLIGATIONS: &[&str] =
    &["require_approval", "require_cosign", "sandbox", "audit"];

/// Latest implemented parameter-schema version per well-known type.
/// All well-known types are at v1 today; adding v2 later is additive.
const LATEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    #[serde(rename = "type")]
    pub ob_type: String,
    pub version: u32,
    pub parameters: serde_json::Map<String, serde_json::Value>,
}

impl Obligation {
    pub fn new(
        ob_type: &str,
        version: u32,
        parameters: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            ob_type: ob_type.to_string(),
            version,
            parameters,
        }
    }

    pub fn is_well_known(&self) -> bool {
        WELL_KNOWN_OBLIGATIONS.contains(&self.ob_type.as_str())
    }
}

fn invalid(ob: &Obligation, msg: impl std::fmt::Display) -> SignetError {
    SignetError::InvalidObligation(format!(
        "obligation '{}' v{}: {msg}",
        ob.ob_type, ob.version
    ))
}

/// Validate an obligation against the well-known registry (or the `x-`
/// namespace rules). Called from `validate_policy` and `evaluate_policy`.
pub fn validate_obligation(ob: &Obligation) -> Result<(), SignetError> {
    if ob.version == 0 {
        return Err(invalid(ob, "version must be >= 1"));
    }

    if ob.ob_type.is_empty()
        || !ob
            .ob_type
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(invalid(ob, "type must be lowercase [a-z0-9_-]"));
    }
    if ob.ob_type == "x-" {
        return Err(invalid(
            ob,
            "'x-' namespace requires a name after the prefix",
        ));
    }

    if !ob.is_well_known() {
        if !ob.ob_type.starts_with("x-") {
            return Err(invalid(
                ob,
                format!(
                    "unknown type (well-known: {WELL_KNOWN_OBLIGATIONS:?}; private extensions must use an 'x-' prefix)"
                ),
            ));
        }
        // x- namespace: syntax-checked only, parameters free-form.
        return Ok(());
    }

    if ob.version > LATEST_VERSION {
        return Err(invalid(
            ob,
            format!(
                "version {} is newer than the latest implemented version {LATEST_VERSION}; refusing unknown semantics",
                ob.version
            ),
        ));
    }

    match ob.ob_type.as_str() {
        "require_approval" => validate_require_approval(ob),
        "require_cosign" => validate_require_cosign(ob),
        "sandbox" => validate_sandbox(ob),
        "audit" => validate_audit(ob),
        _ => unreachable!("is_well_known gate above"),
    }
}

fn str_param<'a>(ob: &'a Obligation, key: &str) -> Option<&'a str> {
    ob.parameters.get(key).and_then(|v| v.as_str())
}

fn require_str<'a>(ob: &'a Obligation, key: &str) -> Result<&'a str, SignetError> {
    str_param(ob, key)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid(ob, format!("missing required string parameter '{key}'")))
}

/// `^[0-9]+(smhd)$` — same duration units as the delegation TTL CLI.
fn is_duration_string(s: &str) -> bool {
    let Some(inner) = s.strip_suffix(|u| matches!(u, 's' | 'm' | 'h' | 'd')) else {
        return false;
    };
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit())
}

fn validate_require_approval(ob: &Obligation) -> Result<(), SignetError> {
    if let Some(approver) = str_param(ob, "approver") {
        crate::principal::validate_principal(approver)
            .map_err(|e| invalid(ob, format!("'approver' must be a valid principal URI: {e}")))?;
    }
    if let Some(within) = str_param(ob, "within") {
        if !is_duration_string(within) {
            return Err(invalid(
                ob,
                format!("'within' must be a duration like \"10m\"/\"2h\", got \"{within}\""),
            ));
        }
    }
    Ok(())
}

fn validate_require_cosign(ob: &Obligation) -> Result<(), SignetError> {
    require_str(ob, "server")?;
    Ok(())
}

fn validate_sandbox(ob: &Obligation) -> Result<(), SignetError> {
    match ob.parameters.get("required") {
        Some(serde_json::Value::Bool(_)) => Ok(()),
        _ => Err(invalid(ob, "missing required boolean parameter 'required'")),
    }
}

fn validate_audit(ob: &Obligation) -> Result<(), SignetError> {
    let retention = require_str(ob, "retention")?;
    if !is_duration_string(retention) {
        return Err(invalid(
            ob,
            format!("'retention' must be a duration like \"7d\"/\"30d\", got \"{retention}\""),
        ));
    }
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ob(ob_type: &str, params: serde_json::Value) -> Obligation {
        let map = match params {
            serde_json::Value::Object(m) => m,
            other => {
                let mut m = serde_json::Map::new();
                m.insert("value".into(), other);
                m
            }
        };
        Obligation::new(ob_type, 1, map)
    }

    #[test]
    fn test_all_well_known_types_valid() {
        assert!(validate_obligation(&ob(
            "require_approval",
            json!({"approver": "user://prismer/alice", "within": "10m"})
        ))
        .is_ok());
        assert!(validate_obligation(&ob("require_approval", json!({}))).is_ok());
        assert!(
            validate_obligation(&ob("require_cosign", json!({"server": "mcp://github"}))).is_ok()
        );
        assert!(validate_obligation(&ob("sandbox", json!({"required": true}))).is_ok());
        assert!(validate_obligation(&ob("audit", json!({"retention": "7d"}))).is_ok());
    }

    #[test]
    fn test_x_namespace_passes_with_free_params() {
        let o = ob("x-acme-custom", json!({"anything": [1, 2, 3]}));
        assert!(validate_obligation(&o).is_ok());
        // The x- prefix itself is not enough: the name must still be a
        // syntactically clean lowercase identifier.
        assert!(validate_obligation(&ob("x-acme/custom", json!({}))).is_err());
        assert!(validate_obligation(&ob("x-", json!({}))).is_err());
    }

    #[test]
    fn test_unknown_type_without_x_prefix_rejected() {
        let err = validate_obligation(&ob("require_magic", json!({}))).unwrap_err();
        assert!(err.to_string().contains("unknown type"));
        assert!(matches!(err, SignetError::InvalidObligation(_)));
    }

    #[test]
    fn test_future_version_rejected() {
        let mut o = ob("sandbox", json!({"required": true}));
        o.version = 2;
        let err = validate_obligation(&o).unwrap_err();
        assert!(err.to_string().contains("newer than the latest"));
    }

    #[test]
    fn test_version_zero_rejected() {
        let mut o = ob("sandbox", json!({"required": true}));
        o.version = 0;
        assert!(validate_obligation(&o).is_err());
    }

    #[test]
    fn test_uppercase_type_rejected() {
        assert!(validate_obligation(&ob("Sandbox", json!({}))).is_err());
        assert!(validate_obligation(&ob("X-Acme/Custom", json!({}))).is_err());
    }

    #[test]
    fn test_require_approval_bad_approver_rejected() {
        let err = validate_obligation(&ob(
            "require_approval",
            json!({"approver": "not a principal"}),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("approver"));
    }

    #[test]
    fn test_require_approval_bad_within_rejected() {
        let err =
            validate_obligation(&ob("require_approval", json!({"within": "soon"}))).unwrap_err();
        assert!(err.to_string().contains("within"));
        // Compound durations are not supported (yet) — one unit only.
        assert!(validate_obligation(&ob("require_approval", json!({"within": "1h30m"}))).is_err());
    }

    #[test]
    fn test_require_cosign_missing_server_rejected() {
        let err = validate_obligation(&ob("require_cosign", json!({}))).unwrap_err();
        assert!(err.to_string().contains("server"));
        // Empty string is not a server either.
        assert!(validate_obligation(&ob("require_cosign", json!({"server": ""}))).is_err());
    }

    #[test]
    fn test_sandbox_missing_or_non_bool_required_rejected() {
        assert!(validate_obligation(&ob("sandbox", json!({}))).is_err());
        assert!(validate_obligation(&ob("sandbox", json!({"required": "yes"}))).is_err());
    }

    #[test]
    fn test_audit_bad_retention_rejected() {
        assert!(validate_obligation(&ob("audit", json!({"retention": "forever"}))).is_err());
        assert!(validate_obligation(&ob("audit", json!({}))).is_err());
    }

    #[test]
    fn test_serde_roundtrip_and_field_names() {
        let json = r#"{"type":"sandbox","version":1,"parameters":{"required":true}}"#;
        let o: Obligation = serde_json::from_str(json).unwrap();
        assert_eq!(o.ob_type, "sandbox");
        assert_eq!(o.version, 1);
        assert!(o.parameters.get("required").unwrap().as_bool().unwrap());
        let back = serde_json::to_string(&o).unwrap();
        let v: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert_eq!(v["type"], "sandbox");
        assert_eq!(v["version"], 1);
    }
}
