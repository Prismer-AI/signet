use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::canonical;
use crate::error::SignetError;
use crate::receipt::{CompoundReceipt, Receipt};

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

    let signable = serde_json::json!({
        "v": receipt.v,
        "action": receipt.action,
        "signer": receipt.signer,
        "ts": receipt.ts,
        "nonce": receipt.nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;

    pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)
}

pub fn verify_compound(receipt: &CompoundReceipt, pubkey: &VerifyingKey) -> Result<(), SignetError> {
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
    let version = raw.get("v").and_then(|v| v.as_u64()).unwrap_or(1);
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
        _ => Err(SignetError::InvalidReceipt(format!("unsupported version: {version}"))),
    }
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
        assert!(matches!(result.unwrap_err(), SignetError::SignatureMismatch));
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
            &sk, &action, &test_response(), "agent", "owner",
            "2026-04-02T10:00:00.000Z", "2026-04-02T10:00:00.150Z",
        ).unwrap();
        assert!(verify_compound(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_compound_verify_wrong_key() {
        let (sk, _) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let action = test_action();
        let receipt = sign_compound(
            &sk, &action, &test_response(), "agent", "owner",
            "2026-04-02T10:00:00.000Z", "2026-04-02T10:00:00.150Z",
        ).unwrap();
        assert!(matches!(verify_compound(&receipt, &wrong_vk), Err(SignetError::SignatureMismatch)));
    }

    #[test]
    fn test_compound_tampered_action() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk, &action, &test_response(), "agent", "owner",
            "2026-04-02T10:00:00.000Z", "2026-04-02T10:00:00.150Z",
        ).unwrap();
        receipt.action.tool = "evil_tool".to_string();
        assert!(matches!(verify_compound(&receipt, &vk), Err(SignetError::SignatureMismatch)));
    }

    #[test]
    fn test_compound_tampered_response() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk, &action, &test_response(), "agent", "owner",
            "2026-04-02T10:00:00.000Z", "2026-04-02T10:00:00.150Z",
        ).unwrap();
        receipt.response.content_hash = "sha256:tampered".to_string();
        assert!(matches!(verify_compound(&receipt, &vk), Err(SignetError::SignatureMismatch)));
    }

    #[test]
    fn test_compound_tampered_ts_response() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk, &action, &test_response(), "agent", "owner",
            "2026-04-02T10:00:00.000Z", "2026-04-02T10:00:00.150Z",
        ).unwrap();
        receipt.ts_response = "2099-01-01T00:00:00.000Z".to_string();
        assert!(matches!(verify_compound(&receipt, &vk), Err(SignetError::SignatureMismatch)));
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
            &sk, &action, &test_response(), "agent", "owner",
            "2026-04-02T10:00:00.000Z", "2026-04-02T10:00:00.150Z",
        ).unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(verify_any(&json, &vk).is_ok());
    }
}
