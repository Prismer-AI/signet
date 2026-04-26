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

/// Internal options for sign_inner — controls which optional fields are
/// included in the signable and the resulting Receipt.
struct SignOptions {
    exp: Option<String>,
    policy: Option<crate::policy::PolicyAttestation>,
}

/// Core signing logic shared by sign(), sign_with_expiration(), and sign_with_policy().
fn sign_inner(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    opts: SignOptions,
) -> Result<Receipt, SignetError> {
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
        trace_id: action.trace_id.clone(),
        parent_receipt_id: action.parent_receipt_id.clone(),
    };

    let signer = Signer {
        pubkey: format_pubkey(&key.verifying_key().to_bytes()),
        name: signer_name.to_string(),
        owner: signer_owner.to_string(),
    };

    let nonce = generate_nonce();
    let ts = current_timestamp();

    // Build signable with optional fields. JCS canonicalization makes
    // key insertion order irrelevant.
    let mut signable = serde_json::json!({
        "v": 1u8,
        "action": signed_action,
        "signer": signer,
        "ts": ts,
        "nonce": nonce,
    });
    let obj = signable.as_object_mut().expect("just built as object");
    if let Some(ref policy) = opts.policy {
        obj.insert(
            "policy".to_string(),
            serde_json::to_value(policy)
                .map_err(|e| SignetError::InvalidReceipt(format!("policy serialize: {e}")))?,
        );
    }
    if let Some(ref exp) = opts.exp {
        obj.insert("exp".to_string(), serde_json::Value::String(exp.clone()));
    }

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
        policy: opts.policy,
        ts,
        exp: opts.exp,
        nonce,
        sig,
    })
}

pub fn sign(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
) -> Result<Receipt, SignetError> {
    sign_inner(
        key,
        action,
        signer_name,
        signer_owner,
        SignOptions {
            exp: None,
            policy: None,
        },
    )
}

/// Sign an action with an expiration time. Same as `sign()` but the receipt
/// carries an `exp` field (RFC 3339) inside the signature scope.
pub fn sign_with_expiration(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    expires_at: &str,
) -> Result<Receipt, SignetError> {
    sign_inner(
        key,
        action,
        signer_name,
        signer_owner,
        SignOptions {
            exp: Some(expires_at.to_string()),
            policy: None,
        },
    )
}

/// Sign an action with policy enforcement. Evaluates the policy first:
/// - Allow → receipt with PolicyAttestation embedded in signed payload
/// - Deny → Err(PolicyViolation)
/// - RequireApproval → Err(RequiresApproval)
pub fn sign_with_policy(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    policy: &crate::policy::Policy,
    rate_state: Option<&mut crate::policy_eval::RateLimitState>,
) -> Result<(Receipt, crate::policy::PolicyEvalResult), SignetError> {
    let eval = crate::policy_eval::evaluate_policy(action, signer_name, policy, rate_state);

    match eval.decision {
        crate::policy::RuleAction::Deny => {
            return Err(SignetError::PolicyViolation(eval.reason.clone()));
        }
        crate::policy::RuleAction::RequireApproval => {
            return Err(SignetError::RequiresApproval(eval.reason.clone()));
        }
        crate::policy::RuleAction::Allow => {}
    }

    let attestation = crate::policy::PolicyAttestation {
        policy_hash: eval.policy_hash.clone(),
        policy_name: eval.policy_name.clone(),
        matched_rules: eval.matched_rules.clone(),
        decision: eval.decision,
        reason: eval.reason.clone(),
    };

    let receipt = sign_inner(
        key,
        action,
        signer_name,
        signer_owner,
        SignOptions {
            exp: None,
            policy: Some(attestation),
        },
    )?;

    Ok((receipt, eval))
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
        trace_id: action.trace_id.clone(),
        parent_receipt_id: action.parent_receipt_id.clone(),
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
            trace_id: None,
            parent_receipt_id: None,
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
    fn test_sign_with_policy_allowed() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let policy = crate::policy_load::parse_policy_yaml(
            r#"
version: 1
name: test-policy
rules:
  - id: allow-all
    match:
      tool: "github_create_issue"
    action: allow
"#,
        )
        .unwrap();
        let (receipt, eval) =
            sign_with_policy(&key, &action, "agent", "owner", &policy, None).unwrap();
        assert_eq!(receipt.v, 1);
        assert!(receipt.policy.is_some());
        let att = receipt.policy.unwrap();
        assert_eq!(att.policy_name, "test-policy");
        assert_eq!(att.decision, crate::policy::RuleAction::Allow);
        assert!(att.policy_hash.starts_with("sha256:"));
        assert_eq!(eval.decision, crate::policy::RuleAction::Allow);
    }

    #[test]
    fn test_sign_with_policy_denied() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let policy = crate::policy_load::parse_policy_yaml(
            r#"
version: 1
name: deny-policy
default_action: deny
rules: []
"#,
        )
        .unwrap();
        let err = sign_with_policy(&key, &action, "agent", "owner", &policy, None).unwrap_err();
        assert!(matches!(err, SignetError::PolicyViolation(_)));
    }

    #[test]
    fn test_sign_with_policy_require_approval() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let policy = crate::policy_load::parse_policy_yaml(
            r#"
version: 1
name: approval-policy
rules:
  - id: needs-approval
    match:
      tool: "github_create_issue"
    action: require_approval
    reason: "issue creation requires approval"
"#,
        )
        .unwrap();
        let err = sign_with_policy(&key, &action, "agent", "owner", &policy, None).unwrap_err();
        assert!(matches!(err, SignetError::RequiresApproval(_)));
    }

    #[test]
    fn test_sign_with_policy_attestation_in_signature() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let policy = crate::policy_load::parse_policy_yaml(
            r#"
version: 1
name: sig-test
rules: []
"#,
        )
        .unwrap();
        let (receipt, _) =
            sign_with_policy(&key, &action, "agent", "owner", &policy, None).unwrap();
        // Verify the receipt — policy is inside the signed payload
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
        assert!(receipt.policy.is_some());
    }

    #[test]
    fn test_sign_with_policy_tampered_attestation_fails_verify() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let policy = crate::policy_load::parse_policy_yaml(
            r#"
version: 1
name: tamper-test
rules: []
"#,
        )
        .unwrap();
        let (mut receipt, _) =
            sign_with_policy(&key, &action, "agent", "owner", &policy, None).unwrap();
        // Tamper with policy attestation
        if let Some(ref mut att) = receipt.policy {
            att.policy_name = "forged-policy".to_string();
        }
        // Signature should now fail
        assert!(crate::verify::verify(&receipt, &vk).is_err());
    }

    #[test]
    fn test_sign_with_policy_no_policy_still_verifies() {
        // Receipts signed without policy (sign()) should still verify
        let (key, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        assert!(receipt.policy.is_none());
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
    }

    // ─── trace correlation tests ──────────────────────────────────────────

    #[test]
    fn test_sign_with_trace_id() {
        let (key, vk) = generate_keypair();
        let mut action = test_action();
        action.trace_id = Some("tr_workflow_001".to_string());
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        assert_eq!(receipt.action.trace_id, Some("tr_workflow_001".to_string()));
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_sign_with_parent_receipt_id() {
        let (key, vk) = generate_keypair();
        let mut action = test_action();
        action.parent_receipt_id = Some("rec_parent_123".to_string());
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        assert_eq!(
            receipt.action.parent_receipt_id,
            Some("rec_parent_123".to_string())
        );
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_sign_with_both_trace_fields() {
        let (key, vk) = generate_keypair();
        let mut action = test_action();
        action.trace_id = Some("tr_wf".to_string());
        action.parent_receipt_id = Some("rec_prev".to_string());
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        assert_eq!(receipt.action.trace_id, Some("tr_wf".to_string()));
        assert_eq!(
            receipt.action.parent_receipt_id,
            Some("rec_prev".to_string())
        );
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_trace_fields_none_by_default() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        assert!(receipt.action.trace_id.is_none());
        assert!(receipt.action.parent_receipt_id.is_none());
    }

    #[test]
    fn test_trace_id_in_signature_scope() {
        let (key, vk) = generate_keypair();
        let mut action = test_action();
        action.trace_id = Some("tr_legit".to_string());
        let mut receipt = sign(&key, &action, "agent", "owner").unwrap();
        // Tamper with trace_id
        receipt.action.trace_id = Some("tr_forged".to_string());
        assert!(crate::verify::verify(&receipt, &vk).is_err());
    }

    #[test]
    fn test_parent_receipt_id_in_signature_scope() {
        let (key, vk) = generate_keypair();
        let mut action = test_action();
        action.parent_receipt_id = Some("rec_real".to_string());
        let mut receipt = sign(&key, &action, "agent", "owner").unwrap();
        // Tamper with parent_receipt_id
        receipt.action.parent_receipt_id = Some("rec_fake".to_string());
        assert!(crate::verify::verify(&receipt, &vk).is_err());
    }

    #[test]
    fn test_trace_fields_absent_in_json_when_none() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("trace_id"));
        assert!(!json.contains("parent_receipt_id"));
    }

    #[test]
    fn test_trace_fields_present_in_json_when_set() {
        let (key, _) = generate_keypair();
        let mut action = test_action();
        action.trace_id = Some("tr_test".to_string());
        action.parent_receipt_id = Some("rec_p".to_string());
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("tr_test"));
        assert!(json.contains("rec_p"));
    }

    #[test]
    fn test_workflow_chain_sign_verify() {
        let (key, vk) = generate_keypair();

        // Workflow start
        let mut start_action = test_action();
        start_action.tool = "_workflow_start".to_string();
        start_action.trace_id = Some("tr_wf001".to_string());
        let start = sign(&key, &start_action, "agent", "owner").unwrap();

        // Child 1
        let mut child1_action = test_action();
        child1_action.trace_id = Some("tr_wf001".to_string());
        child1_action.parent_receipt_id = Some(start.id.clone());
        let child1 = sign(&key, &child1_action, "agent", "owner").unwrap();

        // Child 2
        let mut child2_action = test_action();
        child2_action.trace_id = Some("tr_wf001".to_string());
        child2_action.parent_receipt_id = Some(child1.id.clone());
        let child2 = sign(&key, &child2_action, "agent", "owner").unwrap();

        // All verify
        assert!(crate::verify::verify(&start, &vk).is_ok());
        assert!(crate::verify::verify(&child1, &vk).is_ok());
        assert!(crate::verify::verify(&child2, &vk).is_ok());

        // Chain intact
        assert_eq!(
            child1.action.parent_receipt_id.as_deref(),
            Some(start.id.as_str())
        );
        assert_eq!(
            child2.action.parent_receipt_id.as_deref(),
            Some(child1.id.as_str())
        );
        assert_eq!(child1.action.trace_id.as_deref(), Some("tr_wf001"));
        assert_eq!(child2.action.trace_id.as_deref(), Some("tr_wf001"));
    }

    #[test]
    fn test_bilateral_preserves_trace_fields() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let mut action = test_action();
        action.trace_id = Some("tr_bilateral".to_string());
        action.parent_receipt_id = Some("rec_prev".to_string());
        let agent_receipt = sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"text": "ok"});
        // Use a timestamp after the agent's ts to satisfy ordering check
        let server_ts = (chrono::Utc::now() + chrono::Duration::seconds(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral =
            sign_bilateral(&server_key, &agent_receipt, &response, "server", &server_ts).unwrap();
        // Trace fields survive in embedded agent receipt
        assert_eq!(
            bilateral.agent_receipt.action.trace_id.as_deref(),
            Some("tr_bilateral")
        );
        assert_eq!(
            bilateral.agent_receipt.action.parent_receipt_id.as_deref(),
            Some("rec_prev")
        );
        assert!(crate::verify::verify_bilateral(&bilateral, &server_vk).is_ok());
    }

    #[test]
    fn test_sign_with_policy_preserves_trace_fields() {
        let (key, vk) = generate_keypair();
        let mut action = test_action();
        action.trace_id = Some("tr_policy".to_string());
        let policy =
            crate::policy_load::parse_policy_yaml("version: 1\nname: trace-test\nrules: []\n")
                .unwrap();
        let (receipt, _) =
            sign_with_policy(&key, &action, "agent", "owner", &policy, None).unwrap();
        assert_eq!(receipt.action.trace_id.as_deref(), Some("tr_policy"));
        assert!(receipt.policy.is_some());
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_sign_compound_preserves_trace_fields() {
        let (key, _) = generate_keypair();
        let mut action = test_action();
        action.trace_id = Some("tr_compound".to_string());
        let response = json!({"text": "ok"});
        let receipt = sign_compound(
            &key,
            &action,
            &response,
            "agent",
            "owner",
            "2026-04-11T10:00:00.000Z",
            "2026-04-11T10:00:00.150Z",
        )
        .unwrap();
        assert_eq!(receipt.action.trace_id.as_deref(), Some("tr_compound"));
    }

    // ─── expiration tests ─────────────────────────────────────────────

    #[test]
    fn test_sign_without_expiration() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        assert!(receipt.exp.is_none());
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_sign_with_expiration_roundtrip() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let receipt = sign_with_expiration(&key, &action, "agent", "owner", &future).unwrap();
        assert_eq!(receipt.exp.as_deref(), Some(future.as_str()));
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_sign_with_expiration_expired_rejected() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let past = (chrono::Utc::now() - chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let receipt = sign_with_expiration(&key, &action, "agent", "owner", &past).unwrap();
        // verify() should reject expired receipt
        let err = crate::verify::verify(&receipt, &vk).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn test_sign_with_expiration_allow_expired() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let past = (chrono::Utc::now() - chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let receipt = sign_with_expiration(&key, &action, "agent", "owner", &past).unwrap();
        // verify_allow_expired should accept
        assert!(crate::verify::verify_allow_expired(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_expiration_in_signature_scope() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut receipt = sign_with_expiration(&key, &action, "agent", "owner", &future).unwrap();
        // Tamper: extend expiration
        receipt.exp = Some(
            (chrono::Utc::now() + chrono::Duration::days(365))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        );
        assert!(crate::verify::verify(&receipt, &vk).is_err());
    }

    #[test]
    fn test_expiration_absent_in_json_when_none() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("\"exp\""));
    }

    #[test]
    fn test_expiration_present_in_json_when_set() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let future = "2027-01-01T00:00:00.000Z";
        let receipt = sign_with_expiration(&key, &action, "agent", "owner", future).unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("2027-01-01T00:00:00.000Z"));
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
