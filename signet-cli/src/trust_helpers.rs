use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;

pub struct LoadedTrustBundle {
    pub bundle: signet_core::TrustBundle,
    pub loaded_at: DateTime<Utc>,
    pub active_root_pubkeys: Vec<VerifyingKey>,
    pub active_agent_pubkeys: Vec<VerifyingKey>,
    pub active_server_pubkeys: Vec<VerifyingKey>,
}

impl LoadedTrustBundle {
    pub fn describe(&self) -> String {
        format!("{} (env: {})", self.bundle.bundle_id, self.bundle.env)
    }

    pub fn find_active_agent_key(&self, pubkey: &str) -> Result<Option<VerifyingKey>> {
        match self.bundle.active_agent_entry(pubkey, self.loaded_at) {
            Some(_) => Ok(Some(signet_core::trust::decode_trust_pubkey(pubkey)?)),
            None => Ok(None),
        }
    }

    pub fn find_active_server_key(&self, pubkey: &str) -> Result<Option<VerifyingKey>> {
        match self.bundle.active_server_entry(pubkey, self.loaded_at) {
            Some(_) => Ok(Some(signet_core::trust::decode_trust_pubkey(pubkey)?)),
            None => Ok(None),
        }
    }
}

pub fn load_cli_trust_bundle(path: &str) -> Result<LoadedTrustBundle> {
    let bundle = signet_core::load_trust_bundle(std::path::Path::new(path))?;
    let loaded_at = Utc::now();
    let active_root_pubkeys = bundle.active_root_pubkeys_at(loaded_at)?;
    let active_agent_pubkeys = bundle.active_agent_pubkeys_at(loaded_at)?;
    let active_server_pubkeys = bundle.active_server_pubkeys_at(loaded_at)?;

    Ok(LoadedTrustBundle {
        bundle,
        loaded_at,
        active_root_pubkeys,
        active_agent_pubkeys,
        active_server_pubkeys,
    })
}

pub fn resolve_pubkey(dir: &std::path::Path, key_ref: &str) -> Result<VerifyingKey> {
    let key_path = std::path::Path::new(key_ref);
    if key_ref.ends_with(".pub") || key_path.exists() {
        let content = std::fs::read_to_string(key_ref)?;
        let pub_file: signet_core::keystore::PubKeyFile = serde_json::from_str(&content)?;
        return decode_pubkey_ref(&pub_file.pubkey);
    }

    if let Ok(vk) = signet_core::load_verifying_key(dir, key_ref) {
        return Ok(vk);
    }

    decode_pubkey_ref(key_ref)
}

pub fn resolve_pubkeys(dir: &std::path::Path, key_refs: &[String]) -> Result<Vec<VerifyingKey>> {
    key_refs
        .iter()
        .map(|key| resolve_pubkey(dir, key))
        .collect()
}

fn decode_pubkey_ref(key_ref: &str) -> Result<VerifyingKey> {
    let b64 = key_ref.strip_prefix("ed25519:").unwrap_or(key_ref);
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| anyhow!("'{}' is not a key name or valid base64: {}", key_ref, e))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("pubkey is not 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}
