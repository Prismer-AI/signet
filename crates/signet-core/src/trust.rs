use std::collections::HashSet;
use std::sync::LazyLock;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::SignetError;

static ENV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_-]{0,31}$").expect("regex is valid"));

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustBundle {
    pub version: u8,
    pub bundle_id: String,
    pub org: String,
    pub env: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub roots: Vec<TrustKeyEntry>,
    #[serde(default)]
    pub agents: Vec<TrustKeyEntry>,
    #[serde(default)]
    pub servers: Vec<TrustKeyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustKeyEntry {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub pubkey: String,
    pub status: TrustKeyStatus,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustKeyStatus {
    Active,
    Disabled,
    Revoked,
}

impl TrustKeyEntry {
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        if self.status != TrustKeyStatus::Active {
            return false;
        }

        match &self.expires_at {
            Some(expires_at) => match parse_timestamp(expires_at) {
                Ok(expiry) => expiry >= now,
                Err(_) => false,
            },
            None => true,
        }
    }
}

impl TrustBundle {
    pub fn active_root_entry(&self, pubkey: &str, now: DateTime<Utc>) -> Option<&TrustKeyEntry> {
        self.roots
            .iter()
            .find(|entry| entry.pubkey == pubkey && entry.is_active_at(now))
    }

    pub fn active_agent_entry(&self, pubkey: &str, now: DateTime<Utc>) -> Option<&TrustKeyEntry> {
        self.agents
            .iter()
            .find(|entry| entry.pubkey == pubkey && entry.is_active_at(now))
    }

    pub fn active_server_entry(&self, pubkey: &str, now: DateTime<Utc>) -> Option<&TrustKeyEntry> {
        self.servers
            .iter()
            .find(|entry| entry.pubkey == pubkey && entry.is_active_at(now))
    }

    pub fn active_root_pubkeys_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<VerifyingKey>, SignetError> {
        active_pubkeys(&self.roots, now)
    }

    pub fn active_agent_pubkeys_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<VerifyingKey>, SignetError> {
        active_pubkeys(&self.agents, now)
    }

    pub fn active_server_pubkeys_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<VerifyingKey>, SignetError> {
        active_pubkeys(&self.servers, now)
    }
}

/// Parse a trust bundle from YAML.
pub fn parse_trust_bundle_yaml(yaml: &str) -> Result<TrustBundle, SignetError> {
    serde_yaml::from_str(yaml)
        .map_err(|e| SignetError::TrustBundleParseError(format!("invalid YAML: {e}")))
}

/// Parse a trust bundle from JSON.
pub fn parse_trust_bundle_json(json: &str) -> Result<TrustBundle, SignetError> {
    serde_json::from_str(json)
        .map_err(|e| SignetError::TrustBundleParseError(format!("invalid JSON: {e}")))
}

/// Validate a trust bundle for internal consistency.
pub fn validate_trust_bundle(bundle: &TrustBundle) -> Result<(), SignetError> {
    if bundle.version != 1 {
        return Err(SignetError::TrustBundleError(format!(
            "unsupported trust bundle version: {}, expected 1",
            bundle.version
        )));
    }

    if bundle.bundle_id.trim().is_empty() {
        return Err(SignetError::TrustBundleError(
            "bundle_id must be non-empty".into(),
        ));
    }

    if bundle.org.trim().is_empty() {
        return Err(SignetError::TrustBundleError(
            "org must be non-empty".into(),
        ));
    }

    if bundle.env.trim().is_empty() {
        return Err(SignetError::TrustBundleError(
            "env must be non-empty".into(),
        ));
    }

    if !ENV_RE.is_match(&bundle.env) {
        return Err(SignetError::TrustBundleError(format!(
            "invalid env '{}': must match ^[a-z0-9][a-z0-9_-]{{0,31}}$",
            bundle.env
        )));
    }

    validate_timestamp("generated_at", &bundle.generated_at)?;
    validate_entries("roots", &bundle.roots)?;
    validate_entries("agents", &bundle.agents)?;
    validate_entries("servers", &bundle.servers)?;

    Ok(())
}

fn validate_entries(section: &str, entries: &[TrustKeyEntry]) -> Result<(), SignetError> {
    let mut seen_ids = HashSet::new();
    let mut seen_pubkeys = HashSet::new();

    for entry in entries {
        if entry.id.trim().is_empty() {
            return Err(SignetError::TrustBundleError(format!(
                "{section}: entry id must be non-empty"
            )));
        }

        if entry.name.trim().is_empty() {
            return Err(SignetError::TrustBundleError(format!(
                "{section}: entry '{}' must have a non-empty name",
                entry.id
            )));
        }

        if entry.owner.trim().is_empty() {
            return Err(SignetError::TrustBundleError(format!(
                "{section}: entry '{}' must have a non-empty owner",
                entry.id
            )));
        }

        if !seen_ids.insert(entry.id.as_str()) {
            return Err(SignetError::TrustBundleError(format!(
                "{section}: duplicate entry id '{}'",
                entry.id
            )));
        }

        if !seen_pubkeys.insert(entry.pubkey.as_str()) {
            return Err(SignetError::TrustBundleError(format!(
                "{section}: duplicate pubkey '{}'",
                entry.pubkey
            )));
        }

        validate_pubkey(section, entry)?;
        validate_timestamp(
            &format!("{section}.{}.created_at", entry.id),
            &entry.created_at,
        )?;

        if let Some(expires_at) = &entry.expires_at {
            validate_timestamp(&format!("{section}.{}.expires_at", entry.id), expires_at)?;
            let created = parse_timestamp(&entry.created_at)?;
            let expires = parse_timestamp(expires_at)?;
            if expires < created {
                return Err(SignetError::TrustBundleError(format!(
                    "{section}.{}.expires_at must not be earlier than created_at",
                    entry.id
                )));
            }
        }

        if let Some(disabled_at) = &entry.disabled_at {
            validate_timestamp(&format!("{section}.{}.disabled_at", entry.id), disabled_at)?;
        }

        if let Some(revoked_at) = &entry.revoked_at {
            validate_timestamp(&format!("{section}.{}.revoked_at", entry.id), revoked_at)?;
        }

        match entry.status {
            TrustKeyStatus::Disabled if entry.disabled_at.is_none() => {
                return Err(SignetError::TrustBundleError(format!(
                    "{section}.{} is disabled but disabled_at is missing",
                    entry.id
                )))
            }
            TrustKeyStatus::Revoked if entry.revoked_at.is_none() => {
                return Err(SignetError::TrustBundleError(format!(
                    "{section}.{} is revoked but revoked_at is missing",
                    entry.id
                )))
            }
            _ => {}
        }
    }

    Ok(())
}

fn validate_pubkey(section: &str, entry: &TrustKeyEntry) -> Result<(), SignetError> {
    decode_trust_pubkey(&entry.pubkey).map_err(|err| match err {
        SignetError::TrustBundleError(msg) => {
            SignetError::TrustBundleError(format!("{section}.{} {msg}", entry.id))
        }
        other => other,
    })?;
    Ok(())
}

pub fn decode_trust_pubkey(pubkey: &str) -> Result<VerifyingKey, SignetError> {
    let b64 = pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::TrustBundleError("pubkey must start with 'ed25519:'".into()))?;
    let bytes = B64
        .decode(b64)
        .map_err(|e| SignetError::TrustBundleError(format!("pubkey is not valid base64: {e}")))?;
    if bytes.len() != 32 {
        return Err(SignetError::TrustBundleError(format!(
            "pubkey must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SignetError::TrustBundleError("pubkey must decode to 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| SignetError::TrustBundleError(format!("invalid pubkey: {e}")))
}

fn active_pubkeys(
    entries: &[TrustKeyEntry],
    now: DateTime<Utc>,
) -> Result<Vec<VerifyingKey>, SignetError> {
    entries
        .iter()
        .filter(|entry| entry.is_active_at(now))
        .map(|entry| decode_trust_pubkey(&entry.pubkey))
        .collect()
}

fn validate_timestamp(label: &str, value: &str) -> Result<(), SignetError> {
    parse_timestamp(value).map(|_| ()).map_err(|_| {
        SignetError::TrustBundleError(format!(
            "{label} must be RFC 3339 UTC (Z or +00:00), got '{}'",
            value
        ))
    })
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, SignetError> {
    let dt = DateTime::parse_from_rfc3339(value).map_err(|e| {
        SignetError::TrustBundleError(format!("invalid timestamp '{}': {e}", value))
    })?;

    if dt.offset().local_minus_utc() != 0 {
        return Err(SignetError::TrustBundleError(format!(
            "timestamp '{}' must use UTC (Z or +00:00)",
            value
        )));
    }

    Ok(dt.with_timezone(&Utc))
}

/// Load a trust bundle from a YAML or JSON file.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_trust_bundle(path: &std::path::Path) -> Result<TrustBundle, SignetError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        SignetError::TrustBundleParseError(format!("failed to read trust bundle file: {e}"))
    })?;

    let bundle = match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => parse_trust_bundle_yaml(&content)?,
        Some("json") => parse_trust_bundle_json(&content)?,
        Some(ext) => {
            return Err(SignetError::TrustBundleParseError(format!(
                "unsupported trust bundle file extension: .{ext} (use .yaml, .yml, or .json)"
            )))
        }
        None => parse_trust_bundle_yaml(&content)
            .or_else(|_| parse_trust_bundle_json(&content))
            .map_err(|_| {
                SignetError::TrustBundleParseError(
                    "could not parse as YAML or JSON (no file extension to detect format)".into(),
                )
            })?,
    };

    validate_trust_bundle(&bundle)?;
    Ok(bundle)
}

/// Save a trust bundle to a YAML or JSON file, inferred from extension.
#[cfg(not(target_arch = "wasm32"))]
pub fn save_trust_bundle(path: &std::path::Path, bundle: &TrustBundle) -> Result<(), SignetError> {
    validate_trust_bundle(bundle)?;

    let serialized = match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => serde_yaml::to_string(bundle).map_err(|e| {
            SignetError::TrustBundleParseError(format!(
                "failed to serialize trust bundle YAML: {e}"
            ))
        })?,
        Some("json") => serde_json::to_string_pretty(bundle).map_err(|e| {
            SignetError::TrustBundleParseError(format!(
                "failed to serialize trust bundle JSON: {e}"
            ))
        })?,
        Some(ext) => {
            return Err(SignetError::TrustBundleParseError(format!(
                "unsupported trust bundle file extension: .{ext} (use .yaml, .yml, or .json)"
            )))
        }
        None => {
            return Err(SignetError::TrustBundleParseError(
                "trust bundle output path must have .yaml, .yml, or .json extension".into(),
            ))
        }
    };

    std::fs::write(path, serialized).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const TEST_PUBKEY_A: &str = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const TEST_PUBKEY_B: &str = "ed25519:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn minimal_bundle_yaml() -> String {
        format!(
            r#"
version: 1
bundle_id: tb_dev
org: signet
env: dev
generated_at: "2026-04-25T10:30:00Z"
roots: []
agents:
  - id: agent1
    name: agent1
    owner: platform
    pubkey: "{TEST_PUBKEY_A}"
    status: active
    created_at: "2026-04-25T10:00:00Z"
servers:
  - id: server1
    name: server1
    owner: platform
    pubkey: "{TEST_PUBKEY_B}"
    status: active
    created_at: "2026-04-25T10:05:00Z"
"#
        )
    }

    #[test]
    fn test_parse_trust_bundle_yaml() {
        let bundle = parse_trust_bundle_yaml(&minimal_bundle_yaml()).unwrap();
        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.env, "dev");
        assert_eq!(bundle.agents.len(), 1);
        assert_eq!(bundle.servers.len(), 1);
    }

    #[test]
    fn test_parse_trust_bundle_json() {
        let json = format!(
            r#"{{
  "version": 1,
  "bundle_id": "tb_prod",
  "org": "signet",
  "env": "prod",
  "generated_at": "2026-04-25T10:30:00Z",
  "roots": [],
  "agents": [{{
    "id": "agent1",
    "name": "agent1",
    "owner": "platform",
    "pubkey": "{TEST_PUBKEY_A}",
    "status": "active",
    "created_at": "2026-04-25T10:00:00Z"
  }}],
  "servers": []
}}"#
        );
        let bundle = parse_trust_bundle_json(&json).unwrap();
        assert_eq!(bundle.bundle_id, "tb_prod");
        assert_eq!(bundle.agents.len(), 1);
    }

    #[test]
    fn test_validate_trust_bundle_ok() {
        let bundle = parse_trust_bundle_yaml(&minimal_bundle_yaml()).unwrap();
        validate_trust_bundle(&bundle).unwrap();
    }

    #[test]
    fn test_validate_trust_bundle_rejects_bad_version() {
        let yaml = minimal_bundle_yaml().replace("version: 1", "version: 2");
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("unsupported trust bundle version"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_empty_env() {
        let yaml = minimal_bundle_yaml().replace("env: dev", "env: \"\"");
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("env must be non-empty"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_invalid_env() {
        let yaml = minimal_bundle_yaml().replace("env: dev", "env: DEV");
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("invalid env"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_non_utc_timestamp() {
        let yaml = minimal_bundle_yaml().replace(
            "generated_at: \"2026-04-25T10:30:00Z\"",
            "generated_at: \"2026-04-25T10:30:00+08:00\"",
        );
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("RFC 3339 UTC"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_duplicate_ids() {
        let yaml = format!(
            r#"
version: 1
bundle_id: tb_dev
org: signet
env: dev
generated_at: "2026-04-25T10:30:00Z"
roots: []
agents:
  - id: dup
    name: a
    owner: platform
    pubkey: "{TEST_PUBKEY_A}"
    status: active
    created_at: "2026-04-25T10:00:00Z"
  - id: dup
    name: b
    owner: platform
    pubkey: "{TEST_PUBKEY_B}"
    status: active
    created_at: "2026-04-25T10:01:00Z"
servers: []
"#
        );
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("duplicate entry id"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_duplicate_pubkeys_in_section() {
        let yaml = format!(
            r#"
version: 1
bundle_id: tb_dev
org: signet
env: dev
generated_at: "2026-04-25T10:30:00Z"
roots: []
agents:
  - id: a
    name: a
    owner: platform
    pubkey: "{TEST_PUBKEY_A}"
    status: active
    created_at: "2026-04-25T10:00:00Z"
  - id: b
    name: b
    owner: platform
    pubkey: "{TEST_PUBKEY_A}"
    status: active
    created_at: "2026-04-25T10:01:00Z"
servers: []
"#
        );
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("duplicate pubkey"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_missing_ed25519_prefix() {
        let yaml = minimal_bundle_yaml().replace(TEST_PUBKEY_A, "plainbase64");
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("must start with 'ed25519:'"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_disabled_without_disabled_at() {
        let yaml = minimal_bundle_yaml().replace("status: active", "status: disabled");
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("disabled_at is missing"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_revoked_without_revoked_at() {
        let yaml = minimal_bundle_yaml().replace("status: active", "status: revoked");
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("revoked_at is missing"));
    }

    #[test]
    fn test_validate_trust_bundle_rejects_expires_before_created() {
        let yaml = format!(
            r#"
version: 1
bundle_id: tb_dev
org: signet
env: dev
generated_at: "2026-04-25T10:30:00Z"
roots: []
agents:
  - id: agent1
    name: agent1
    owner: platform
    pubkey: "{TEST_PUBKEY_A}"
    status: active
    created_at: "2026-04-25T10:00:00Z"
    expires_at: "2026-04-24T10:00:00Z"
servers: []
"#
        );
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let err = validate_trust_bundle(&bundle).unwrap_err();
        assert!(err.to_string().contains("expires_at must not be earlier"));
    }

    #[test]
    fn test_is_active_at_false_for_disabled() {
        let entry = TrustKeyEntry {
            id: "agent1".into(),
            name: "agent1".into(),
            owner: "platform".into(),
            pubkey: TEST_PUBKEY_A.into(),
            status: TrustKeyStatus::Disabled,
            created_at: "2026-04-25T10:00:00Z".into(),
            expires_at: None,
            disabled_at: Some("2026-04-25T10:10:00Z".into()),
            revoked_at: None,
            comment: None,
        };
        assert!(!entry.is_active_at(Utc.with_ymd_and_hms(2026, 4, 25, 10, 15, 0).unwrap()));
    }

    #[test]
    fn test_is_active_at_false_for_expired_entry() {
        let entry = TrustKeyEntry {
            id: "agent1".into(),
            name: "agent1".into(),
            owner: "platform".into(),
            pubkey: TEST_PUBKEY_A.into(),
            status: TrustKeyStatus::Active,
            created_at: "2026-04-25T10:00:00Z".into(),
            expires_at: Some("2026-04-25T11:00:00Z".into()),
            disabled_at: None,
            revoked_at: None,
            comment: None,
        };
        assert!(!entry.is_active_at(Utc.with_ymd_and_hms(2026, 4, 25, 11, 0, 1).unwrap()));
    }

    #[test]
    fn test_is_active_at_true_for_unexpired_active_entry() {
        let entry = TrustKeyEntry {
            id: "agent1".into(),
            name: "agent1".into(),
            owner: "platform".into(),
            pubkey: TEST_PUBKEY_A.into(),
            status: TrustKeyStatus::Active,
            created_at: "2026-04-25T10:00:00Z".into(),
            expires_at: Some("2026-04-25T11:00:00Z".into()),
            disabled_at: None,
            revoked_at: None,
            comment: None,
        };
        assert!(entry.is_active_at(Utc.with_ymd_and_hms(2026, 4, 25, 10, 59, 59).unwrap()));
    }

    #[test]
    fn test_active_agent_entry_matches_only_active_records() {
        let yaml = format!(
            r#"
version: 1
bundle_id: tb_prod
org: signet
env: prod
generated_at: "2026-04-25T10:30:00Z"
roots: []
agents:
  - id: active-agent
    name: active-agent
    owner: platform
    pubkey: "{TEST_PUBKEY_A}"
    status: active
    created_at: "2026-04-25T10:00:00Z"
  - id: disabled-agent
    name: disabled-agent
    owner: platform
    pubkey: "{TEST_PUBKEY_B}"
    status: disabled
    created_at: "2026-04-25T10:00:00Z"
    disabled_at: "2026-04-25T10:05:00Z"
servers: []
"#
        );
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 4, 25, 10, 10, 0).unwrap();
        assert_eq!(
            bundle.active_agent_entry(TEST_PUBKEY_A, now).unwrap().id,
            "active-agent"
        );
        assert!(bundle.active_agent_entry(TEST_PUBKEY_B, now).is_none());
    }

    #[test]
    fn test_active_agent_pubkeys_at_returns_only_active_keys() {
        let yaml = format!(
            r#"
version: 1
bundle_id: tb_prod
org: signet
env: prod
generated_at: "2026-04-25T10:30:00Z"
roots: []
agents:
  - id: active-agent
    name: active-agent
    owner: platform
    pubkey: "{TEST_PUBKEY_A}"
    status: active
    created_at: "2026-04-25T10:00:00Z"
  - id: expired-agent
    name: expired-agent
    owner: platform
    pubkey: "{TEST_PUBKEY_B}"
    status: active
    created_at: "2026-04-25T10:00:00Z"
    expires_at: "2026-04-25T10:01:00Z"
servers: []
"#
        );
        let bundle = parse_trust_bundle_yaml(&yaml).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 4, 25, 10, 10, 0).unwrap();
        let keys = bundle.active_agent_pubkeys_at(now).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_save_trust_bundle_json_roundtrip() {
        let bundle = parse_trust_bundle_yaml(&minimal_bundle_yaml()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        save_trust_bundle(&path, &bundle).unwrap();
        let restored = load_trust_bundle(&path).unwrap();
        assert_eq!(restored.bundle_id, "tb_dev");
        assert_eq!(restored.env, "dev");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_save_trust_bundle_yaml_roundtrip() {
        let bundle = parse_trust_bundle_yaml(&minimal_bundle_yaml()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.yaml");
        save_trust_bundle(&path, &bundle).unwrap();
        let restored = load_trust_bundle(&path).unwrap();
        assert_eq!(restored.bundle_id, "tb_dev");
        assert_eq!(restored.env, "dev");
    }
}
