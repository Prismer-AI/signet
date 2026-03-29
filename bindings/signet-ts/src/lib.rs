use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use wasm_bindgen::prelude::*;

use signet_core::receipt::Action;
use signet_core::{generate_keypair, sign, verify};

#[wasm_bindgen]
pub fn wasm_generate_keypair() -> Result<JsValue, JsError> {
    let (signing_key, verifying_key) = generate_keypair();
    let secret_b64 = BASE64.encode(signing_key.to_keypair_bytes());
    let public_b64 = BASE64.encode(verifying_key.to_bytes());

    let result = serde_json::json!({
        "secret_key": secret_b64,
        "public_key": public_b64,
    });

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
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
