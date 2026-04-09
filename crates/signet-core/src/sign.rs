use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::delegation::{current_timestamp, derive_id, format_pubkey, format_sig, generate_nonce};
use crate::error::SignetError;
use crate::receipt::{
    Action, BilateralReceipt, CompoundReceipt, Receipt, Response, ServerInfo, Signer,
};

pub(crate) fn validate_params_hash(hash: &str) -> Result<(), SignetError> {
    if hash.is_empty() {
        return Ok(());
    }
    if let Some(hex_part) = hash.strip_prefix("sha256:") {
        if hex_part.len() == 64
            && hex_part
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Ok(());
        }
    }
    Err(SignetError::InvalidReceipt(format!(
        "params_hash must be empty or match sha256:[0-9a-f]{{64}}, got: {hash}"
    )))
}

pub(crate) fn compute_params_hash(action: &Action) -> Result<String, SignetError> {
    if action.params.is_null() && !action.params_hash.is_empty() {
        validate_params_hash(&action.params_hash)?;
        return Ok(action.params_hash.clone());
    }
    let params_to_hash = if action.params.is_null() {
        serde_json::json!({})
    } else {
        action.params.clone()
    };
    let canonical = canonical::canonicalize(&params_to_hash)?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hash)))
}

pub fn sign(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
) -> Result<Receipt, SignetError> {
    // 1. Compute params_hash from params
    let params_hash = compute_params_hash(action)?;

    // 2. Build action with computed hash
    let signed_action = Action {
        tool: action.tool.clone(),
        params: action.params.clone(),
        params_hash,
        target: action.target.clone(),
        transport: action.transport.clone(),
        session: action.session.clone(),
        call_id: action.call_id.clone(),
        response_hash: action.response_hash.clone(),
    };

    // 3. Build signer
    let signer = Signer {
        pubkey: format_pubkey(&key.verifying_key().to_bytes()),
        name: signer_name.to_string(),
        owner: signer_owner.to_string(),
    };

    // 4. Generate nonce + timestamp
    let nonce = generate_nonce();
    let ts = current_timestamp();

    // 5. Build signable JSON, canonicalize, sign
    let signable = serde_json::json!({
        "v": 1u8,
        "action": signed_action,
        "signer": signer,
        "ts": ts,
        "nonce": nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;
    let signature = key.sign(canonical_bytes.as_bytes());
    let sig = format_sig(&signature.to_bytes());
    let id = derive_id("rec", &signature.to_bytes());

    Ok(Receipt {
        v: 1,
        id,
        action: signed_action,
        signer,
        authorization: None,
        ts,
        nonce,
        sig,
    })
}

pub fn sign_compound(
    key: &SigningKey,
    action: &Action,
    response_content: &serde_json::Value,
    signer_name: &str,
    signer_owner: &str,
    ts_request: &str,
    ts_response: &str,
) -> Result<CompoundReceipt, SignetError> {
    // 1. Compute params_hash (same logic as sign())
    let params_hash = compute_params_hash(action)?;

    let signed_action = Action {
        tool: action.tool.clone(),
        params: action.params.clone(),
        params_hash,
        target: action.target.clone(),
        transport: action.transport.clone(),
        session: action.session.clone(),
        call_id: action.call_id.clone(),
        response_hash: action.response_hash.clone(),
    };

    // 2. Hash response content
    let canonical_response = canonical::canonicalize(response_content)?;
    let response_hash = Sha256::digest(canonical_response.as_bytes());
    let response = Response {
        content_hash: format!("sha256:{}", hex::encode(response_hash)),
    };

    // 3. Build signer
    let signer = Signer {
        pubkey: format_pubkey(&key.verifying_key().to_bytes()),
        name: signer_name.to_string(),
        owner: signer_owner.to_string(),
    };

    // 4. Generate nonce, build signable, canonicalize, sign
    let nonce = generate_nonce();
    let signable = serde_json::json!({
        "v": 2u8,
        "action": signed_action,
        "response": response,
        "signer": signer,
        "ts_request": ts_request,
        "ts_response": ts_response,
        "nonce": nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;
    let signature = key.sign(canonical_bytes.as_bytes());
    let sig = format_sig(&signature.to_bytes());
    let id = derive_id("rec", &signature.to_bytes());

    Ok(CompoundReceipt {
        v: 2,
        id,
        action: signed_action,
        response,
        signer,
        ts_request: ts_request.to_string(),
        ts_response: ts_response.to_string(),
        nonce,
        sig,
    })
}

pub fn sign_bilateral(
    server_key: &SigningKey,
    agent_receipt: &Receipt,
    response_content: &serde_json::Value,
    server_name: &str,
    ts_response: &str,
) -> Result<BilateralReceipt, SignetError> {
    // Hash response content
    let canonical_response = canonical::canonicalize(response_content)?;
    let response_hash = Sha256::digest(canonical_response.as_bytes());
    let response = Response {
        content_hash: format!("sha256:{}", hex::encode(response_hash)),
    };

    // Server info
    let server = ServerInfo {
        pubkey: format_pubkey(&server_key.verifying_key().to_bytes()),
        name: server_name.to_string(),
    };

    // Nonce, signable, canonicalize, sign
    let nonce = generate_nonce();
    let signable = serde_json::json!({
        "v": 3u8,
        "agent_receipt": agent_receipt,
        "response": response,
        "server": server,
        "ts_response": ts_response,
        "nonce": nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;
    let signature = server_key.sign(canonical_bytes.as_bytes());
    let sig = format_sig(&signature.to_bytes());
    let id = derive_id("rec", &signature.to_bytes());

    Ok(BilateralReceipt {
        v: 3,
        id,
        agent_receipt: agent_receipt.clone(),
        response,
        server,
        ts_response: ts_response.to_string(),
        nonce,
        sig,
        extensions: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_keypair;
    use crate::test_helpers::test_action;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde_json::json;

    #[test]
    fn test_sign_produces_receipt() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "test-agent", "willamhou").unwrap();

        assert_eq!(receipt.v, 1);
        assert!(receipt.id.starts_with("rec_"));
        assert!(receipt.sig.starts_with("ed25519:"));
        assert!(receipt.nonce.starts_with("rnd_"));
        assert!(receipt.signer.pubkey.starts_with("ed25519:"));
        assert_eq!(receipt.signer.name, "test-agent");
        assert_eq!(receipt.signer.owner, "willamhou");
        assert_eq!(receipt.action.tool, "github_create_issue");
    }

    #[test]
    fn test_params_hash_computed() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "test-agent", "owner").unwrap();

        let canonical_params = canonical::canonicalize(&action.params).unwrap();
        let expected_hash = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical_params.as_bytes()))
        );
        assert_eq!(receipt.action.params_hash, expected_hash);
    }

    #[test]
    fn test_params_hash_only_mode() {
        let (key, _) = generate_keypair();
        let action = Action {
            tool: "test".to_string(),
            params: serde_json::Value::Null,
            params_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            target: "mcp://test".to_string(),
            transport: "stdio".to_string(),
            session: None,
            call_id: None,
            response_hash: None,
        };
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        assert_eq!(
            receipt.action.params_hash,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_nonce_uniqueness() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let r1 = sign(&key, &action, "agent", "owner").unwrap();
        let r2 = sign(&key, &action, "agent", "owner").unwrap();
        assert_ne!(r1.nonce, r2.nonce);
    }

    #[test]
    fn test_receipt_id_from_sig() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "agent", "owner").unwrap();

        let sig_b64 = receipt.sig.strip_prefix("ed25519:").unwrap();
        let sig_bytes = BASE64.decode(sig_b64).unwrap();
        let sig_hash = Sha256::digest(&sig_bytes);
        let expected_id = format!("rec_{}", hex::encode(&sig_hash[..16]));
        assert_eq!(receipt.id, expected_id);
    }

    #[test]
    fn test_sign_bilateral_produces_v3() {
        let (agent_key, _) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "issue #42"}]});

        let bilateral = sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            "2026-04-03T10:00:00.150Z",
        )
        .unwrap();

        assert_eq!(bilateral.v, 3);
        assert!(bilateral.id.starts_with("rec_"));
        assert!(bilateral.sig.starts_with("ed25519:"));
        assert!(bilateral.response.content_hash.starts_with("sha256:"));
        assert_eq!(bilateral.server.name, "github-mcp");
        assert_eq!(bilateral.agent_receipt.id, agent_receipt.id);
        assert_eq!(bilateral.agent_receipt.sig, agent_receipt.sig);
    }

    #[test]
    fn test_sign_compound_produces_v2() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let receipt = sign_compound(
            &key,
            &action,
            &response,
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();

        assert_eq!(receipt.v, 2);
        assert!(receipt.id.starts_with("rec_"));
        assert!(receipt.sig.starts_with("ed25519:"));
        assert!(receipt.response.content_hash.starts_with("sha256:"));
        assert_eq!(receipt.ts_request, "2026-04-02T10:00:00.000Z");
        assert_eq!(receipt.ts_response, "2026-04-02T10:00:00.150Z");
        assert_eq!(receipt.action.tool, "github_create_issue");
    }
}
