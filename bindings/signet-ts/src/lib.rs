use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use signet_core::receipt::Action;
use signet_core::{generate_keypair, sign, verify};

#[wasm_bindgen]
pub fn wasm_generate_keypair() -> Result<String, JsError> {
    let (signing_key, verifying_key) = generate_keypair();
    let secret_b64 = BASE64.encode(signing_key.to_keypair_bytes());
    let public_b64 = BASE64.encode(verifying_key.to_bytes());

    let result = serde_json::json!({
        "secret_key": secret_b64,
        "public_key": public_b64,
    });

    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_sign(
    secret_key_b64: &str,
    action_json: &str,
    signer_name: &str,
    signer_owner: &str,
) -> Result<String, JsError> {
    let key_bytes = BASE64
        .decode(secret_key_b64)
        .map_err(|e| JsError::new(&format!("invalid secret key base64: {e}")))?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("secret key must be 64 bytes"))?,
    )
    .map_err(|e| JsError::new(&format!("invalid signing key: {e}")))?;

    let action: Action = serde_json::from_str(action_json)
        .map_err(|e| JsError::new(&format!("invalid action JSON: {e}")))?;

    let receipt = sign(&signing_key, &action, signer_name, signer_owner)
        .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&receipt).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_verify(receipt_json: &str, public_key_b64: &str) -> Result<bool, JsError> {
    let pubkey_bytes = BASE64
        .decode(public_key_b64)
        .map_err(|e| JsError::new(&format!("invalid public key base64: {e}")))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("public key must be 32 bytes"))?,
    )
    .map_err(|e| JsError::new(&format!("invalid verifying key: {e}")))?;

    let receipt: signet_core::Receipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

    match verify(&receipt, &verifying_key) {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn wasm_sign_compound(
    secret_key_b64: &str,
    action_json: &str,
    response_content_json: &str,
    signer_name: &str,
    signer_owner: &str,
    ts_request: &str,
    ts_response: &str,
) -> Result<String, JsError> {
    let key_bytes = BASE64.decode(secret_key_b64)
        .map_err(|e| JsError::new(&format!("invalid secret key base64: {e}")))?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(
        key_bytes.as_slice().try_into()
            .map_err(|_| JsError::new("secret key must be 64 bytes"))?,
    ).map_err(|e| JsError::new(&format!("invalid signing key: {e}")))?;

    let action: signet_core::Action = serde_json::from_str(action_json)
        .map_err(|e| JsError::new(&format!("invalid action JSON: {e}")))?;
    let response_content: serde_json::Value = serde_json::from_str(response_content_json)
        .map_err(|e| JsError::new(&format!("invalid response JSON: {e}")))?;

    let receipt = signet_core::sign_compound(
        &signing_key, &action, &response_content,
        signer_name, signer_owner, ts_request, ts_response,
    ).map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&receipt).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_verify_any(receipt_json: &str, public_key_b64: &str) -> Result<bool, JsError> {
    let pubkey_bytes = BASE64.decode(public_key_b64)
        .map_err(|e| JsError::new(&format!("invalid public key base64: {e}")))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        pubkey_bytes.as_slice().try_into()
            .map_err(|_| JsError::new("public key must be 32 bytes"))?,
    ).map_err(|e| JsError::new(&format!("invalid verifying key: {e}")))?;

    match signet_core::verify_any(receipt_json, &verifying_key) {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn wasm_sign_bilateral(
    server_key_b64: &str,
    agent_receipt_json: &str,
    response_content_json: &str,
    server_name: &str,
    ts_response: &str,
) -> Result<String, JsError> {
    let key_bytes = BASE64
        .decode(server_key_b64)
        .map_err(|e| JsError::new(&format!("invalid server key base64: {e}")))?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("server key must be 64 bytes"))?,
    )
    .map_err(|e| JsError::new(&format!("invalid signing key: {e}")))?;

    let agent_receipt: signet_core::Receipt = serde_json::from_str(agent_receipt_json)
        .map_err(|e| JsError::new(&format!("invalid agent receipt JSON: {e}")))?;

    let response_content: serde_json::Value = serde_json::from_str(response_content_json)
        .map_err(|e| JsError::new(&format!("invalid response content JSON: {e}")))?;

    let bilateral = signet_core::sign_bilateral(
        &signing_key,
        &agent_receipt,
        &response_content,
        server_name,
        ts_response,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&bilateral).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_verify_bilateral(receipt_json: &str, server_pubkey_b64: &str) -> Result<bool, JsError> {
    let pubkey_bytes = BASE64
        .decode(server_pubkey_b64)
        .map_err(|e| JsError::new(&format!("invalid server pubkey base64: {e}")))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsError::new("server pubkey must be 32 bytes"))?,
    )
    .map_err(|e| JsError::new(&format!("invalid verifying key: {e}")))?;

    let receipt: signet_core::BilateralReceipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("invalid bilateral receipt JSON: {e}")))?;

    match signet_core::verify_bilateral(&receipt, &verifying_key) {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn wasm_content_hash(json: &str) -> Result<String, JsError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| JsError::new(&format!("invalid JSON: {e}")))?;
    let canonical = signet_core::canonical::canonicalize(&value)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hash)))
}
