use std::path::Path;

use anyhow::{anyhow, bail, Result};

pub fn materialize_receipt_for_output(
    dir: &Path,
    receipt: &serde_json::Value,
) -> Result<serde_json::Value> {
    let Some(kid) = encrypted_kid(receipt)? else {
        return Ok(receipt.clone());
    };

    let infos = signet_core::list_keys(dir)?;
    let Some(info) = infos
        .into_iter()
        .find(|info| format!("ed25519:{}", info.pubkey) == kid)
    else {
        bail!("encrypted params present for {kid} but no matching local identity was found");
    };

    let passphrase = std::env::var("SIGNET_PASSPHRASE")
        .ok()
        .filter(|value| !value.is_empty());
    let signing_key = signet_core::load_signing_key(dir, &info.name, passphrase.as_deref())
        .map_err(|err| match err {
            signet_core::SignetError::DecryptionError => anyhow!(
                "encrypted params present for {kid} but local identity '{}' could not be unlocked; set SIGNET_PASSPHRASE to decrypt params",
                info.name
            ),
            other => anyhow!(
                "encrypted params present for {kid} but failed to load local identity '{}': {other}",
                info.name
            ),
        })?;

    Ok(signet_core::audit::decrypt_receipt_params_for_audit(
        receipt,
        &signing_key,
    )?)
}

pub fn has_encrypted_params(receipt: &serde_json::Value) -> bool {
    receipt
        .get("action")
        .and_then(|action| action.get("params_encrypted"))
        .is_some()
}

fn encrypted_kid(receipt: &serde_json::Value) -> Result<Option<&str>> {
    let Some(action) = receipt.get("action").and_then(|action| action.as_object()) else {
        return Ok(None);
    };
    let Some(envelope) = action.get("params_encrypted") else {
        return Ok(None);
    };

    envelope
        .get("kid")
        .and_then(|value| value.as_str())
        .map(Some)
        .ok_or_else(|| anyhow!("action.params_encrypted.kid missing or not a string"))
}
