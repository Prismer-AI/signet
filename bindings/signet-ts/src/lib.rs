use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use signet_core::delegation::{DelegationToken, Scope};
use signet_core::receipt::Action;
use signet_core::{generate_keypair, sign, verify};

/// Parse a secret key from base64: accepts both 32-byte seed and 64-byte keypair.
fn parse_signing_key(key_b64: &str) -> Result<ed25519_dalek::SigningKey, JsError> {
    let key_bytes = BASE64
        .decode(key_b64)
        .map_err(|e| JsError::new(&format!("invalid secret key base64: {e}")))?;
    match key_bytes.len() {
        32 => {
            let seed: [u8; 32] = key_bytes.try_into().unwrap();
            Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
        }
        64 => {
            let bytes: [u8; 64] = key_bytes.try_into().unwrap();
            ed25519_dalek::SigningKey::from_keypair_bytes(&bytes)
                .map_err(|e| JsError::new(&format!("invalid signing key: {e}")))
        }
        n => Err(JsError::new(&format!(
            "secret key must be 32 or 64 bytes, got {n}"
        ))),
    }
}

#[wasm_bindgen]
pub fn wasm_generate_keypair() -> Result<String, JsError> {
    let (signing_key, verifying_key) = generate_keypair();
    // Output 32-byte seed (compatible with CLI .key files)
    let secret_b64 = BASE64.encode(signing_key.to_bytes());
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
    let signing_key = parse_signing_key(secret_key_b64)?;

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
    let signing_key = parse_signing_key(secret_key_b64)?;

    let action: signet_core::Action = serde_json::from_str(action_json)
        .map_err(|e| JsError::new(&format!("invalid action JSON: {e}")))?;
    let response_content: serde_json::Value = serde_json::from_str(response_content_json)
        .map_err(|e| JsError::new(&format!("invalid response JSON: {e}")))?;

    let receipt = signet_core::sign_compound(
        &signing_key,
        &action,
        &response_content,
        signer_name,
        signer_owner,
        ts_request,
        ts_response,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&receipt).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_verify_any(receipt_json: &str, public_key_b64: &str) -> Result<bool, JsError> {
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
    let signing_key = parse_signing_key(server_key_b64)?;

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

/// Same as `wasm_sign_bilateral` but additionally records a final outcome
/// (executed / failed / rejected / verified) inside the signature scope.
///
/// `outcome_json` is a JSON object with shape:
///   { "status": "executed" | "failed" | "rejected" | "verified",
///     "reason": ?string, "error": ?string }
/// or the literal string "null" / empty string to omit the outcome.
#[wasm_bindgen]
pub fn wasm_sign_bilateral_with_outcome(
    server_key_b64: &str,
    agent_receipt_json: &str,
    response_content_json: &str,
    server_name: &str,
    ts_response: &str,
    outcome_json: &str,
) -> Result<String, JsError> {
    let signing_key = parse_signing_key(server_key_b64)?;

    let agent_receipt: signet_core::Receipt = serde_json::from_str(agent_receipt_json)
        .map_err(|e| JsError::new(&format!("invalid agent receipt JSON: {e}")))?;

    let response_content: serde_json::Value = serde_json::from_str(response_content_json)
        .map_err(|e| JsError::new(&format!("invalid response content JSON: {e}")))?;

    let outcome: Option<signet_core::Outcome> = if outcome_json.is_empty() || outcome_json == "null" {
        None
    } else {
        Some(serde_json::from_str(outcome_json).map_err(|e| {
            JsError::new(&format!("invalid outcome JSON (expected {{status, reason?, error?}}): {e}"))
        })?)
    };

    let bilateral = signet_core::sign_bilateral_with_outcome(
        &signing_key,
        &agent_receipt,
        &response_content,
        server_name,
        ts_response,
        outcome,
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
pub fn wasm_pubkey_from_seed(seed_b64: &str) -> Result<String, JsError> {
    let signing_key = parse_signing_key(seed_b64)?;
    let verifying_key = signing_key.verifying_key();
    Ok(BASE64.encode(verifying_key.to_bytes()))
}

#[wasm_bindgen]
pub fn wasm_content_hash(json: &str) -> Result<String, JsError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| JsError::new(&format!("invalid JSON: {e}")))?;
    let canonical =
        signet_core::canonical::canonicalize(&value).map_err(|e| JsError::new(&e.to_string()))?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hash)))
}

#[wasm_bindgen]
pub fn wasm_sign_delegation(
    delegator_key_b64: &str,
    delegator_name: &str,
    delegate_pubkey_b64: &str,
    delegate_name: &str,
    scope_json: &str,
    parent_scope_json: Option<String>,
) -> Result<String, JsError> {
    let delegator_key = parse_signing_key(delegator_key_b64)?;

    let delegate_bytes = BASE64
        .decode(delegate_pubkey_b64)
        .map_err(|e| JsError::new(&format!("invalid delegate pubkey base64: {e}")))?;
    let delegate_arr: [u8; 32] = delegate_bytes
        .try_into()
        .map_err(|_| JsError::new("delegate pubkey must be 32 bytes"))?;
    let delegate_vk = ed25519_dalek::VerifyingKey::from_bytes(&delegate_arr)
        .map_err(|e| JsError::new(&format!("invalid delegate pubkey: {e}")))?;

    let scope: Scope = serde_json::from_str(scope_json)
        .map_err(|e| JsError::new(&format!("invalid scope JSON: {e}")))?;
    let parent_scope: Option<Scope> = parent_scope_json
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid parent_scope JSON: {e}")))?;

    let token = signet_core::sign_delegation(
        &delegator_key,
        delegator_name,
        &delegate_vk,
        delegate_name,
        &scope,
        parent_scope.as_ref(),
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&token).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_verify_delegation(token_json: &str) -> Result<bool, JsError> {
    let token: DelegationToken = serde_json::from_str(token_json)
        .map_err(|e| JsError::new(&format!("invalid token JSON: {e}")))?;

    match signet_core::verify_delegation(&token, None) {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(signet_core::SignetError::DelegationExpired(_)) => Ok(false),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn wasm_sign_authorized(
    key_b64: &str,
    action_json: &str,
    signer_name: &str,
    chain_json: &str,
) -> Result<String, JsError> {
    let signing_key = parse_signing_key(key_b64)?;

    let action: Action = serde_json::from_str(action_json)
        .map_err(|e| JsError::new(&format!("invalid action JSON: {e}")))?;

    let chain: Vec<DelegationToken> = serde_json::from_str(chain_json)
        .map_err(|e| JsError::new(&format!("invalid chain JSON: {e}")))?;

    let receipt = signet_core::sign_authorized(&signing_key, &action, signer_name, chain)
        .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&receipt).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_verify_authorized(
    receipt_json: &str,
    trusted_roots_json: &str,
    clock_skew_secs: u64,
) -> Result<String, JsError> {
    let receipt: signet_core::Receipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

    let root_keys: Vec<String> = serde_json::from_str(trusted_roots_json)
        .map_err(|e| JsError::new(&format!("invalid trusted_roots JSON: {e}")))?;

    let trusted_roots: Vec<ed25519_dalek::VerifyingKey> = root_keys
        .iter()
        .map(|k| {
            let bytes = BASE64
                .decode(k)
                .map_err(|e| JsError::new(&format!("invalid root key base64: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| JsError::new("root key must be 32 bytes"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map_err(|e| JsError::new(&format!("invalid root key: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let opts = signet_core::AuthorizedVerifyOptions {
        trusted_roots,
        clock_skew_secs,
        max_chain_depth: 16,
    };

    let scope = signet_core::verify_authorized(&receipt, &opts)
        .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&scope).map_err(|e| JsError::new(&e.to_string()))
}

// ─── Bilateral verify options ────────────────────────────────────────────────

#[wasm_bindgen]
pub fn wasm_verify_bilateral_with_options(
    receipt_json: &str,
    server_pubkey_b64: &str,
    expected_session: &str,
    expected_call_id: &str,
    max_time_window_secs: u64,
) -> Result<bool, JsError> {
    let receipt: signet_core::BilateralReceipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

    let key_bytes = BASE64
        .decode(server_pubkey_b64)
        .map_err(|e| JsError::new(&format!("invalid server key: {e}")))?;
    let arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| JsError::new("server key must be 32 bytes"))?;
    let server_vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("invalid server key: {e}")))?;

    let opts = signet_core::BilateralVerifyOptions {
        max_time_window_secs,
        trusted_agent_pubkey: None,
        expected_session: if expected_session.is_empty() {
            None
        } else {
            Some(expected_session.to_string())
        },
        expected_call_id: if expected_call_id.is_empty() {
            None
        } else {
            Some(expected_call_id.to_string())
        },
        nonce_checker: None, // WASM has no persistent state for nonce checking
    };

    match signet_core::verify_bilateral_with_options(&receipt, &server_vk, &opts) {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(signet_core::SignetError::InvalidReceipt(ref msg))
            if msg.contains("mismatch") || msg.contains("does not match") =>
        {
            Ok(false)
        }
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

// ─── Expiration functions ────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn wasm_sign_with_expiration(
    secret_key_b64: &str,
    action_json: &str,
    signer_name: &str,
    signer_owner: &str,
    expires_at: &str,
) -> Result<String, JsError> {
    let signing_key = parse_signing_key(secret_key_b64)?;
    let action: Action = serde_json::from_str(action_json)
        .map_err(|e| JsError::new(&format!("invalid action JSON: {e}")))?;

    let receipt = signet_core::sign_with_expiration(
        &signing_key,
        &action,
        signer_name,
        signer_owner,
        expires_at,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&receipt).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_verify_allow_expired(
    receipt_json: &str,
    public_key_b64: &str,
) -> Result<bool, JsError> {
    let receipt: signet_core::Receipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

    let key_bytes = BASE64
        .decode(public_key_b64)
        .map_err(|e| JsError::new(&format!("invalid public key: {e}")))?;
    let arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| JsError::new("public key must be 32 bytes"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| JsError::new(&format!("invalid public key: {e}")))?;

    match signet_core::verify_allow_expired(&receipt, &vk) {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

// ─── Policy functions ────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn wasm_parse_policy_yaml(yaml: &str) -> Result<String, JsError> {
    let policy = signet_core::parse_policy_yaml(yaml).map_err(|e| JsError::new(&e.to_string()))?;
    signet_core::validate_policy(&policy).map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&policy).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_evaluate_policy(
    action_json: &str,
    agent_name: &str,
    policy_json: &str,
) -> Result<String, JsError> {
    let action: signet_core::Action = serde_json::from_str(action_json)
        .map_err(|e| JsError::new(&format!("invalid action JSON: {e}")))?;
    let policy: signet_core::Policy = serde_json::from_str(policy_json)
        .map_err(|e| JsError::new(&format!("invalid policy JSON: {e}")))?;

    let eval = signet_core::evaluate_policy(&action, agent_name, &policy, None);

    let result = serde_json::json!({
        "decision": eval.decision.to_string(),
        "matched_rules": eval.matched_rules,
        "winning_rule": eval.winning_rule,
        "reason": eval.reason,
        "policy_name": eval.policy_name,
        "policy_hash": eval.policy_hash,
    });
    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_sign_with_policy(
    secret_key_b64: &str,
    action_json: &str,
    signer_name: &str,
    signer_owner: &str,
    policy_json: &str,
) -> Result<String, JsError> {
    let signing_key = parse_signing_key(secret_key_b64)?;
    let action: signet_core::Action = serde_json::from_str(action_json)
        .map_err(|e| JsError::new(&format!("invalid action JSON: {e}")))?;
    let policy: signet_core::Policy = serde_json::from_str(policy_json)
        .map_err(|e| JsError::new(&format!("invalid policy JSON: {e}")))?;

    let (receipt, eval) = signet_core::sign_with_policy(
        &signing_key,
        &action,
        signer_name,
        signer_owner,
        &policy,
        None,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    let result = serde_json::json!({
        "receipt": receipt,
        "eval": {
            "decision": eval.decision.to_string(),
            "matched_rules": eval.matched_rules,
            "winning_rule": eval.winning_rule,
            "reason": eval.reason,
            "policy_name": eval.policy_name,
            "policy_hash": eval.policy_hash,
        }
    });
    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_compute_policy_hash(policy_json: &str) -> Result<String, JsError> {
    let policy: signet_core::Policy = serde_json::from_str(policy_json)
        .map_err(|e| JsError::new(&format!("invalid policy JSON: {e}")))?;
    signet_core::compute_policy_hash(&policy).map_err(|e| JsError::new(&e.to_string()))
}
