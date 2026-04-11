use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::canonical;
use crate::error::SignetError;
use crate::receipt::{BilateralReceipt, CompoundReceipt, Receipt};

pub fn verify(receipt: &Receipt, pubkey: &VerifyingKey) -> Result<(), SignetError> {
    let sig_b64 = receipt
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    let mut signable = serde_json::json!({
        "v": receipt.v,
        "action": receipt.action,
        "signer": receipt.signer,
        "ts": receipt.ts,
        "nonce": receipt.nonce,
    });
    // Include policy in signable if present (must match what sign_with_policy produced)
    if let Some(ref policy) = receipt.policy {
        signable.as_object_mut().unwrap().insert(
            "policy".to_string(),
            serde_json::to_value(policy).map_err(|e| {
                SignetError::InvalidReceipt(format!("failed to serialize policy: {e}"))
            })?,
        );
    }
    let canonical_bytes = canonical::canonicalize(&signable)?;

    pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)
}

pub fn verify_compound(
    receipt: &CompoundReceipt,
    pubkey: &VerifyingKey,
) -> Result<(), SignetError> {
    let sig_b64 = receipt
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    let signable = serde_json::json!({
        "v": receipt.v,
        "action": receipt.action,
        "response": receipt.response,
        "signer": receipt.signer,
        "ts_request": receipt.ts_request,
        "ts_response": receipt.ts_response,
        "nonce": receipt.nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;

    pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)
}

/// Version-detecting verify: parses JSON, checks "v", dispatches.
pub fn verify_any(receipt_json: &str, pubkey: &VerifyingKey) -> Result<(), SignetError> {
    let raw: serde_json::Value = serde_json::from_str(receipt_json)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid JSON: {e}")))?;
    let version = raw.get("v").and_then(|v| v.as_u64()).ok_or_else(|| {
        SignetError::InvalidReceipt("missing or non-integer 'v' field".to_string())
    })?;
    match version {
        1 => {
            let receipt: Receipt = serde_json::from_value(raw)
                .map_err(|e| SignetError::InvalidReceipt(format!("v1 parse: {e}")))?;
            verify(&receipt, pubkey)
        }
        2 => {
            let receipt: CompoundReceipt = serde_json::from_value(raw)
                .map_err(|e| SignetError::InvalidReceipt(format!("v2 parse: {e}")))?;
            verify_compound(&receipt, pubkey)
        }
        3 => Err(SignetError::InvalidReceipt(
            "v3 bilateral receipts require verify_bilateral(), not verify_any()".to_string(),
        )),
        4 => {
            let receipt: Receipt = serde_json::from_value(raw)
                .map_err(|e| SignetError::InvalidReceipt(format!("v4 parse: {e}")))?;
            // Check provided pubkey matches receipt's signer
            let expected_pubkey = format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode(pubkey.to_bytes())
            );
            if receipt.signer.pubkey != expected_pubkey {
                return Err(SignetError::SignatureMismatch);
            }
            crate::verify_delegation::verify_v4_signature_only(&receipt)
        }
        _ => Err(SignetError::InvalidReceipt(format!(
            "unsupported version: {version}"
        ))),
    }
}

/// Options for bilateral receipt verification.
pub struct BilateralVerifyOptions {
    /// Maximum allowed seconds between agent signing and server response.
    /// Default: 300 (5 minutes). Set to 0 to disable time window check.
    pub max_time_window_secs: u64,

    /// Optional trusted agent public key. When set, the embedded agent pubkey
    /// in the receipt is checked against this key. Without this, the function
    /// only verifies self-consistency (the agent receipt is valid under *its own*
    /// embedded key) but cannot confirm the agent's identity is authorized.
    pub trusted_agent_pubkey: Option<VerifyingKey>,
}

impl Default for BilateralVerifyOptions {
    fn default() -> Self {
        Self {
            max_time_window_secs: 300,
            trusted_agent_pubkey: None,
        }
    }
}

/// Verify a bilateral receipt with default options (5-minute window).
pub fn verify_bilateral(
    receipt: &BilateralReceipt,
    server_pubkey: &VerifyingKey,
) -> Result<(), SignetError> {
    verify_bilateral_with_options(receipt, server_pubkey, &BilateralVerifyOptions::default())
}

/// Verify a bilateral receipt with custom options.
pub fn verify_bilateral_with_options(
    receipt: &BilateralReceipt,
    server_pubkey: &VerifyingKey,
    options: &BilateralVerifyOptions,
) -> Result<(), SignetError> {
    // 0. Cross-check: caller's key must match receipt.server.pubkey
    let receipt_server_b64 = receipt
        .server
        .pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("server.pubkey missing prefix".to_string()))?;
    let receipt_server_bytes = BASE64
        .decode(receipt_server_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("server.pubkey base64: {e}")))?;
    if receipt_server_bytes.as_slice() != server_pubkey.as_bytes() {
        return Err(SignetError::InvalidReceipt(
            "caller-supplied server key does not match receipt.server.pubkey".to_string(),
        ));
    }

    // 1. Verify server signature over v3 body
    let sig_b64 = receipt
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    let signable = serde_json::json!({
        "v": receipt.v,
        "agent_receipt": receipt.agent_receipt,
        "response": receipt.response,
        "server": receipt.server,
        "ts_response": receipt.ts_response,
        "nonce": receipt.nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;

    server_pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)?;

    // 2. Verify embedded agent receipt using its own pubkey
    let agent_pubkey_b64 = receipt
        .agent_receipt
        .signer
        .pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("agent pubkey missing prefix".to_string()))?;
    let agent_pubkey_bytes = BASE64
        .decode(agent_pubkey_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid agent pubkey: {e}")))?;
    let agent_pubkey_arr: [u8; 32] = agent_pubkey_bytes
        .try_into()
        .map_err(|_| SignetError::InvalidReceipt("agent pubkey not 32 bytes".to_string()))?;
    let agent_vk = VerifyingKey::from_bytes(&agent_pubkey_arr)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid agent pubkey: {e}")))?;

    // 2a. If a trusted agent key was supplied, ensure the receipt's agent key matches
    if let Some(ref trusted) = options.trusted_agent_pubkey {
        if agent_vk.as_bytes() != trusted.as_bytes() {
            return Err(SignetError::InvalidReceipt(
                "agent pubkey in receipt does not match trusted_agent_pubkey".to_string(),
            ));
        }
    }

    verify(&receipt.agent_receipt, &agent_vk)?;

    // 3. Verify timestamp ordering: agent signed before server responded
    let agent_ts = chrono::DateTime::parse_from_rfc3339(&receipt.agent_receipt.ts)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid agent timestamp: {e}")))?;
    let server_ts = chrono::DateTime::parse_from_rfc3339(&receipt.ts_response)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid server timestamp: {e}")))?;

    if agent_ts > server_ts {
        return Err(SignetError::InvalidReceipt(
            "agent receipt timestamp is after server response timestamp".to_string(),
        ));
    }

    // 4. Check time window between agent signing and server response
    if options.max_time_window_secs > 0 {
        let gap = server_ts
            .signed_duration_since(agent_ts)
            .num_seconds()
            .unsigned_abs();
        if gap > options.max_time_window_secs {
            return Err(SignetError::InvalidReceipt(format!(
                "time gap between agent and server ({gap}s) exceeds max window ({}s)",
                options.max_time_window_secs
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_keypair;
    use crate::sign;
    use crate::sign::sign_compound;
    use crate::test_helpers::test_action;
    use serde_json::json;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        assert!(verify(&receipt, &verifying_key).is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let (signing_key, _) = generate_keypair();
        let (_, wrong_key) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();

        let result = verify(&receipt, &wrong_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignetError::SignatureMismatch
        ));
    }

    #[test]
    fn test_verify_tampered_action() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.action.tool = "evil_tool".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_signer() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.signer.name = "impostor".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_timestamp() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.ts = "2099-01-01T00:00:00.000Z".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_nonce() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.nonce = "rnd_0000000000000000".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    fn test_response() -> serde_json::Value {
        json!({"content": [{"type": "text", "text": "issue #42 created"}]})
    }

    #[test]
    fn test_compound_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        assert!(verify_compound(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_compound_verify_wrong_key() {
        let (sk, _) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let action = test_action();
        let receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        assert!(matches!(
            verify_compound(&receipt, &wrong_vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_compound_tampered_action() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        receipt.action.tool = "evil_tool".to_string();
        assert!(matches!(
            verify_compound(&receipt, &vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_compound_tampered_response() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        receipt.response.content_hash = "sha256:tampered".to_string();
        assert!(matches!(
            verify_compound(&receipt, &vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_compound_tampered_ts_response() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        receipt.ts_response = "2099-01-01T00:00:00.000Z".to_string();
        assert!(matches!(
            verify_compound(&receipt, &vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_bilateral_verify_roundtrip() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "issue #42"}]});
        let ts_response = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &ts_response,
        )
        .unwrap();
        assert!(verify_bilateral(&bilateral, &server_vk).is_ok());
    }

    #[test]
    fn test_bilateral_verify_wrong_server_key() {
        let (agent_key, _) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        // With the cross-check, passing a wrong key now returns InvalidReceipt
        // (key mismatch detected before signature verification)
        let result = verify_bilateral(&bilateral, &wrong_vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_bilateral_tampered_response() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let mut bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        bilateral.response.content_hash = "sha256:tampered".to_string();
        assert!(matches!(
            verify_bilateral(&bilateral, &server_vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_bilateral_tampered_agent_receipt() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let mut bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        bilateral.agent_receipt.signer.name = "impostor".to_string();
        assert!(matches!(
            verify_bilateral(&bilateral, &server_vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_any_v3_rejects() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        let json = serde_json::to_string(&bilateral).unwrap();
        let result = verify_any(&json, &server_vk);
        assert!(
            matches!(result, Err(SignetError::InvalidReceipt(ref msg)) if msg.contains("verify_bilateral"))
        );
    }

    #[test]
    fn test_verify_any_v1() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&sk, &action, "agent", "owner").unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(verify_any(&json, &vk).is_ok());
    }

    #[test]
    fn test_verify_any_v2() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(verify_any(&json, &vk).is_ok());
    }

    // --- Bilateral timestamp ordering tests ---

    fn make_bilateral_with_ts(ts_response: &str) -> (BilateralReceipt, VerifyingKey) {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "test-server",
            ts_response,
        )
        .unwrap();
        (bilateral, server_vk)
    }

    #[test]
    fn test_bilateral_timestamp_ordering_valid() {
        // ts_response must be after agent signs (Utc::now()), so add 1 second
        let ts = (chrono::Utc::now() + chrono::Duration::seconds(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&ts);
        assert!(verify_bilateral(&bilateral, &server_vk).is_ok());
    }

    #[test]
    fn test_bilateral_timestamp_ordering_reversed() {
        // Agent signs now, but server ts_response is 1 hour in the past
        let past = (chrono::Utc::now() - chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&past);
        let result = verify_bilateral(&bilateral, &server_vk);
        assert!(matches!(
            result,
            Err(SignetError::InvalidReceipt(ref msg)) if msg.contains("after server response")
        ));
    }

    #[test]
    fn test_bilateral_timestamp_gap_exceeded() {
        // Server responds 10 minutes later, but max window is 5 minutes
        let future = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&future);
        let result = verify_bilateral(&bilateral, &server_vk);
        assert!(matches!(
            result,
            Err(SignetError::InvalidReceipt(ref msg)) if msg.contains("exceeds max window")
        ));
    }

    #[test]
    fn test_bilateral_timestamp_gap_within_window() {
        // Server responds 2 minutes later — within default 5 min window
        let future = (chrono::Utc::now() + chrono::Duration::minutes(2))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&future);
        assert!(verify_bilateral(&bilateral, &server_vk).is_ok());
    }

    #[test]
    fn test_bilateral_timestamp_custom_window() {
        // Server responds 10 minutes later, window set to 20 minutes — ok
        let future = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&future);
        let opts = BilateralVerifyOptions {
            max_time_window_secs: 1200,
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }

    #[test]
    fn test_bilateral_timestamp_window_disabled() {
        // Server responds 1 hour later, but window is disabled (0)
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&future);
        let opts = BilateralVerifyOptions {
            max_time_window_secs: 0,
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }
}
