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
    principal: Option<String>,
    acting_for: Option<String>,
    authz_decision: Option<crate::authorization::AuthorizationDecision>,
}

/// Core signing logic shared by sign(), sign_with_expiration(), and sign_with_policy().
fn sign_inner(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    opts: SignOptions,
) -> Result<Receipt, SignetError> {
    if let Some(ref p) = opts.principal {
        crate::principal::validate_principal(p)?;
    }
    if let Some(ref p) = opts.acting_for {
        crate::principal::validate_principal(p)?;
    }

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
        principal: opts.principal.clone(),
        acting_for: opts.acting_for.clone(),
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
    if let Some(ref decision) = opts.authz_decision {
        obj.insert(
            "authz_decision".to_string(),
            serde_json::to_value(decision).map_err(|e| {
                SignetError::InvalidReceipt(format!("authz_decision serialize: {e}"))
            })?,
        );
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
        authz_decision: opts.authz_decision,
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
            principal: None,
            acting_for: None,
            authz_decision: None,
        },
    )
}

/// Sign an action with canonical principal URIs on the signer.
///
/// `principal` identifies the acting agent (e.g. "agent://prismer/deploy-bot");
/// `acting_for` names the delegating principal it claims to represent
/// (e.g. "user://prismer/alice") — a claim, corroborated only when the receipt
/// also carries a v4 authorization chain rooted at the same principal.
/// Both are validated against the principal grammar and signed.
pub fn sign_with_principal(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    principal: Option<&str>,
    acting_for: Option<&str>,
) -> Result<Receipt, SignetError> {
    sign_inner(
        key,
        action,
        signer_name,
        signer_owner,
        SignOptions {
            exp: None,
            policy: None,
            principal: principal.map(|s| s.to_string()),
            acting_for: acting_for.map(|s| s.to_string()),
            authz_decision: None,
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
            principal: None,
            acting_for: None,
            authz_decision: None,
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
    sign_with_policy_inner(
        key,
        action,
        signer_name,
        signer_owner,
        policy,
        rate_state,
        None,
        None,
    )
}

/// `sign_with_policy` with canonical principal URIs on the signer.
/// Same policy semantics; both principals are validated and signed.
#[allow(clippy::too_many_arguments)]
pub fn sign_with_policy_with_principal(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    principal: Option<&str>,
    acting_for: Option<&str>,
    policy: &crate::policy::Policy,
    rate_state: Option<&mut crate::policy_eval::RateLimitState>,
) -> Result<(Receipt, crate::policy::PolicyEvalResult), SignetError> {
    sign_with_policy_inner(
        key,
        action,
        signer_name,
        signer_owner,
        policy,
        rate_state,
        principal,
        acting_for,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_with_policy_inner(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    policy: &crate::policy::Policy,
    rate_state: Option<&mut crate::policy_eval::RateLimitState>,
    principal: Option<&str>,
    acting_for: Option<&str>,
) -> Result<(Receipt, crate::policy::PolicyEvalResult), SignetError> {
    let eval = crate::policy_eval::evaluate_policy(action, signer_name, policy, rate_state)?;

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
            principal: principal.map(|s| s.to_string()),
            acting_for: acting_for.map(|s| s.to_string()),
            authz_decision: None,
        },
    )?;

    Ok((receipt, eval))
}

/// Two-step agent signing: carry a pre-made authority decision (spec §3.3).
///
/// The decision must be `allow`, verify against its authority key, bind to
/// this action's intent hash, be unexpired, and have its subject match the
/// signer principal — all checked before the receipt exists. `chain = Some`
/// produces a v4 receipt (delegation proof + decision in one artifact) and
/// runs the chain gates.
pub fn sign_with_decision(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    signer_principal: Option<&str>,
    decision: &crate::authorization::AuthorizationDecision,
    chain: Option<&str>,
) -> Result<Receipt, SignetError> {
    use crate::authorization::{verify_decision, verify_decision_for_action, DecisionType};

    // Q11: sign flows accept only allow decisions. Deny evidence comes from
    // the proxy's policy_violation path; a deny decision cannot back a receipt.
    if decision.decision != DecisionType::Allow {
        return Err(SignetError::DecisionInvalid(format!(
            "refusing to sign a receipt backed by a {:?} decision",
            decision.decision
        )));
    }
    verify_decision(decision)?;
    verify_decision_for_action(decision, action, signer_principal)?;

    match chain {
        Some(chain_json) => {
            let tokens: Vec<crate::delegation::DelegationToken> = serde_json::from_str(chain_json)
                .map_err(|e| SignetError::ChainError(format!("invalid chain JSON: {e}")))?;
            crate::sign_delegation::sign_authorized_inner(
                key,
                action,
                signer_name,
                signer_principal,
                None,
                Some(decision),
                tokens,
            )
        }
        None => sign_inner(
            key,
            action,
            signer_name,
            signer_owner,
            SignOptions {
                exp: None,
                policy: None,
                principal: signer_principal.map(|s| s.to_string()),
                acting_for: None,
                authz_decision: Some(decision.clone()),
            },
        ),
    }
}

/// One-step: evaluate policy, authority-sign a decision, then sign the
/// receipt carrying it (spec §3.3). `receipt.policy` is omitted — the
/// decision's Policy basis subsumes the attestation (Q4). Requires an agent
/// principal: the decision's subject must be corroboratable.
#[allow(clippy::too_many_arguments)]
pub fn sign_with_policy_authority(
    agent_key: &SigningKey,
    authority_key: &SigningKey,
    authority_principal: &str,
    agent_principal: &str,
    action: &Action,
    signer_name: &str,
    signer_owner: &str,
    policy: &crate::policy::Policy,
    rate_state: Option<&mut crate::policy_eval::RateLimitState>,
    chain: Option<&str>,
) -> Result<(Receipt, crate::policy::PolicyEvalResult), SignetError> {
    use crate::authorization::{authorize, CanonicalIntent, DecisionBasis, DecisionType};

    let eval = crate::policy_eval::evaluate_policy(action, signer_name, policy, rate_state)?;
    match eval.decision {
        crate::policy::RuleAction::Deny => {
            return Err(SignetError::PolicyViolation(eval.reason.clone()));
        }
        crate::policy::RuleAction::RequireApproval => {
            return Err(SignetError::RequiresApproval(eval.reason.clone()));
        }
        crate::policy::RuleAction::Allow => {}
    }

    let intent = CanonicalIntent::from_action(action)?;
    let basis = DecisionBasis::Policy {
        policy_hash: eval.policy_hash.clone(),
        policy_name: eval.policy_name.clone(),
        matched_rules: eval.matched_rules.clone(),
        reason: eval.reason.clone(),
    };
    let decision = authorize(
        authority_key,
        authority_principal,
        agent_principal,
        &intent,
        DecisionType::Allow,
        basis,
        vec![],
        eval.obligations.clone(),
        None,
        None,
    )?;

    let receipt = sign_with_decision(
        agent_key,
        action,
        signer_name,
        signer_owner,
        Some(agent_principal),
        &decision,
        chain,
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
        outcome: None,
    };

    // 3. Build signer
    let signer = Signer {
        pubkey: format_pubkey(&key.verifying_key().to_bytes()),
        name: signer_name.to_string(),
        owner: signer_owner.to_string(),
        principal: None,
        acting_for: None,
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
    sign_bilateral_with_outcome(
        server_key,
        agent_receipt,
        response_content,
        server_name,
        ts_response,
        None,
    )
}

/// Same as `sign_bilateral` but additionally records a final outcome
/// (executed / failed / rejected / verified) inside the signature scope.
///
/// Use this to upgrade a "signed intent" receipt into a "signed workflow
/// result" — the typical enterprise pilot requirement.
pub fn sign_bilateral_with_outcome(
    server_key: &SigningKey,
    agent_receipt: &Receipt,
    response_content: &serde_json::Value,
    server_name: &str,
    ts_response: &str,
    outcome: Option<crate::receipt::Outcome>,
) -> Result<BilateralReceipt, SignetError> {
    // Hash response content
    let canonical_response = canonical::canonicalize(response_content)?;
    let response_hash = Sha256::digest(canonical_response.as_bytes());
    let response = Response {
        content_hash: format!("sha256:{}", hex::encode(response_hash)),
        outcome,
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
        assert!(
            bilateral.response.outcome.is_none(),
            "default has no outcome"
        );
        assert_eq!(bilateral.server.name, "github-mcp");
        assert_eq!(bilateral.agent_receipt.id, agent_receipt.id);
        assert_eq!(bilateral.agent_receipt.sig, agent_receipt.sig);
    }

    #[test]
    fn test_sign_bilateral_with_outcome_executed() {
        use crate::receipt::{Outcome, OutcomeStatus};
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"ok": true});

        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral = sign_bilateral_with_outcome(
            &server_key,
            &agent_receipt,
            &response,
            "srv",
            &ts,
            Some(Outcome::executed()),
        )
        .unwrap();

        let outcome = bilateral.response.outcome.as_ref().expect("outcome");
        assert_eq!(outcome.status, OutcomeStatus::Executed);
        assert!(outcome.reason.is_none());
        assert!(outcome.error.is_none());
        // Verify outcome is inside signature scope. Use insecure_no_replay_check
        // so the in-memory nonce checker (default) doesn't interfere with this
        // assertion in test context.
        let opts = crate::verify::BilateralVerifyOptions::insecure_no_replay_check();
        let result = crate::verify::verify_bilateral_with_options(&bilateral, &server_vk, &opts);
        assert!(result.is_ok(), "verify failed: {:?}", result.err());
    }

    #[test]
    fn test_sign_bilateral_with_outcome_failed_carries_error() {
        use crate::receipt::{Outcome, OutcomeStatus};
        let (agent_key, _) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign(&agent_key, &action, "agent", "owner").unwrap();

        let bilateral = sign_bilateral_with_outcome(
            &server_key,
            &agent_receipt,
            &json!({}),
            "srv",
            "2026-04-28T10:00:00.000Z",
            Some(Outcome::failed("connection refused")),
        )
        .unwrap();

        let outcome = bilateral.response.outcome.as_ref().expect("outcome");
        assert_eq!(outcome.status, OutcomeStatus::Failed);
        assert_eq!(outcome.error.as_deref(), Some("connection refused"));
        assert!(outcome.reason.is_none());
    }

    #[test]
    fn test_sign_bilateral_with_outcome_requires_approval_carries_reason() {
        use crate::receipt::{Outcome, OutcomeStatus};
        let (agent_key, _) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign(&agent_key, &action, "agent", "owner").unwrap();

        let bilateral = sign_bilateral_with_outcome(
            &server_key,
            &agent_receipt,
            &json!({}),
            "srv",
            "2026-04-28T10:00:00.000Z",
            Some(Outcome::requires_approval("human approval required")),
        )
        .unwrap();

        let outcome = bilateral.response.outcome.as_ref().expect("outcome");
        assert_eq!(outcome.status, OutcomeStatus::RequiresApproval);
        assert_eq!(outcome.reason.as_deref(), Some("human approval required"));
        assert!(outcome.error.is_none());
    }

    #[test]
    fn test_outcome_tampering_invalidates_signature() {
        // The whole point of putting outcome inside the signed Response is
        // to detect post-hoc rewrites. Verify that.
        use crate::receipt::{Outcome, OutcomeStatus};
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign(&agent_key, &action, "agent", "owner").unwrap();

        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut bilateral = sign_bilateral_with_outcome(
            &server_key,
            &agent_receipt,
            &json!({}),
            "srv",
            &ts,
            Some(Outcome::failed("oops")),
        )
        .unwrap();

        // Pretend an attacker rewrites failure → success.
        bilateral.response.outcome = Some(Outcome {
            status: OutcomeStatus::Executed,
            reason: None,
            error: None,
        });

        let opts = crate::verify::BilateralVerifyOptions::insecure_no_replay_check();
        match crate::verify::verify_bilateral_with_options(&bilateral, &server_vk, &opts) {
            Err(_) => {} // expected — sig over original outcome
            Ok(_) => panic!("tampering with outcome must invalidate signature"),
        }
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

    // ─── authorization decision tests ──────────────────────────────────

    mod authz_tests {
        use super::*;
        use crate::authorization::{
            authorize, verify_decision_for_action, CanonicalIntent, DecisionBasis, DecisionType,
        };
        use crate::constraint::Constraint;

        fn action() -> Action {
            Action {
                tool: "github_merge_pr".into(),
                params: json!({"pr": 123}),
                params_hash: String::new(),
                target: "mcp://github".into(),
                transport: "stdio".into(),
                session: None,
                call_id: None,
                response_hash: None,
                trace_id: None,
                parent_receipt_id: None,
            }
        }

        fn make_decision(
            key: &ed25519_dalek::SigningKey,
            action: &Action,
        ) -> crate::authorization::AuthorizationDecision {
            authorize(
                key,
                "agent://prismer/security",
                "agent://prismer/deploy-bot",
                &CanonicalIntent::from_action(action).unwrap(),
                DecisionType::Allow,
                DecisionBasis::Policy {
                    policy_hash: "sha256:abc".into(),
                    policy_name: "prod".into(),
                    matched_rules: vec!["allow".into()],
                    reason: "ok".into(),
                },
                vec![],
                vec![],
                None,
                None,
            )
            .unwrap()
        }

        #[test]
        fn test_sign_with_decision_roundtrip() {
            let (agent_key, agent_vk) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();
            let dec = make_decision(&authority_key, &a);

            let receipt = sign_with_decision(
                &agent_key,
                &a,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                None,
            )
            .unwrap();

            assert_eq!(receipt.v, 1);
            assert!(receipt.authz_decision.is_some());
            // Q4: the attestation is subsumed by the decision's basis.
            assert!(receipt.policy.is_none());
            // Decision-aware verify() passes.
            assert!(crate::verify::verify(&receipt, &agent_vk).is_ok());
        }

        #[test]
        fn test_decision_tamper_and_strip_break_agent_sig() {
            let (agent_key, agent_vk) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();
            let dec = make_decision(&authority_key, &a);
            let receipt = sign_with_decision(
                &agent_key,
                &a,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                None,
            )
            .unwrap();

            // Tamper the embedded decision → agent signature breaks.
            let mut tampered = receipt.clone();
            tampered.authz_decision.as_mut().unwrap().authority = "agent://evil/root".into();
            assert!(crate::verify::verify(&tampered, &agent_vk).is_err());

            // Strip the decision entirely → agent signature breaks.
            let mut stripped = receipt.clone();
            stripped.authz_decision = None;
            assert!(crate::verify::verify(&stripped, &agent_vk).is_err());
        }

        #[test]
        fn test_decision_replay_onto_other_action_rejected() {
            let (agent_key, _) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();
            let dec = make_decision(&authority_key, &a);

            let mut other = action();
            other.params = json!({"pr": 999});

            let err = sign_with_decision(
                &agent_key,
                &other,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                None,
            )
            .unwrap_err();
            assert!(err.to_string().contains("does not authorize this action"));
        }

        #[test]
        fn test_deny_and_require_approval_decisions_refused() {
            let (agent_key, _) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();
            let mut dec = make_decision(&authority_key, &a);
            dec.decision = DecisionType::Deny;
            let err = sign_with_decision(
                &agent_key,
                &a,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                None,
            )
            .unwrap_err();
            assert!(err.to_string().contains("refusing to sign"));

            let mut dec = make_decision(&authority_key, &a);
            dec.decision = DecisionType::RequireApproval;
            assert!(sign_with_decision(
                &agent_key,
                &a,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                None,
            )
            .is_err());
        }

        #[test]
        fn test_sign_with_decision_requires_signer_principal() {
            let (agent_key, _) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();
            let dec = make_decision(&authority_key, &a);

            let err = sign_with_decision(&agent_key, &a, "deploy-bot", "alice", None, &dec, None)
                .unwrap_err();
            assert!(err.to_string().contains("cannot be corroborated"));
        }

        #[test]
        fn test_sign_with_policy_authority_one_step() {
            let (agent_key, agent_vk) = generate_keypair();
            let (authority_key, authority_vk) = generate_keypair();
            let a = action();

            let policy = crate::policy_load::parse_policy_yaml(
                "version: 1\nname: prod\nrules:\n  - id: allow-merge\n    match:\n      tool: github_merge_pr\n    action: allow\n",
            )
            .unwrap();

            let (receipt, eval) = sign_with_policy_authority(
                &agent_key,
                &authority_key,
                "agent://prismer/security",
                "agent://prismer/deploy-bot",
                &a,
                "deploy-bot",
                "alice",
                &policy,
                None,
                None,
            )
            .unwrap();

            assert_eq!(eval.decision, crate::policy::RuleAction::Allow);
            let dec = receipt.authz_decision.as_ref().unwrap();
            assert_eq!(dec.subject, "agent://prismer/deploy-bot");
            assert_eq!(dec.authority, "agent://prismer/security");
            assert!(
                receipt.policy.is_none(),
                "Q4: attestation subsumed by basis"
            );
            assert!(crate::verify::verify(&receipt, &agent_vk).is_ok());
            // Trusted authority verification passes; a different key fails.
            crate::authorization::verify_decision_trusted(dec, &[authority_vk]).unwrap();
            let (_, other_vk) = generate_keypair();
            assert!(matches!(
                crate::authorization::verify_decision_trusted(dec, &[other_vk]),
                Err(SignetError::AuthorityMismatch(_))
            ));
        }

        #[test]
        fn test_sign_with_policy_authority_denies() {
            let (agent_key, _) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();
            let policy = crate::policy_load::parse_policy_yaml(
                "version: 1\nname: deny-all\ndefault_action: deny\nrules: []\n",
            )
            .unwrap();
            let err = sign_with_policy_authority(
                &agent_key,
                &authority_key,
                "agent://prismer/security",
                "agent://prismer/deploy-bot",
                &a,
                "deploy-bot",
                "alice",
                &policy,
                None,
                None,
            )
            .unwrap_err();
            assert!(matches!(err, SignetError::PolicyViolation(_)));
        }

        #[test]
        fn test_v4_plus_decision_flagship() {
            let (root_key, _) = generate_keypair();
            let (agent_key, agent_vk) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();

            let scope = crate::delegation::Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 0,
                expires: None,
                budget: None,
            };
            let token = crate::sign_delegation::sign_delegation_with_principals(
                &root_key,
                "alice",
                Some("user://prismer/alice"),
                &agent_key.verifying_key(),
                "deploy-bot",
                Some("agent://prismer/deploy-bot"),
                &scope,
                None,
            )
            .unwrap();
            let chain_json = serde_json::to_string(&vec![token]).unwrap();

            let dec = make_decision(&authority_key, &a);
            let receipt = sign_with_decision(
                &agent_key,
                &a,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                Some(&chain_json),
            )
            .unwrap();

            assert_eq!(receipt.v, 4);
            assert!(receipt.authorization.is_some());
            assert!(receipt.authz_decision.is_some());
            assert_eq!(
                receipt.signer.acting_for.as_deref(),
                Some("user://prismer/alice")
            );
            assert!(crate::verify::verify(&receipt, &agent_vk).is_ok());

            let opts = crate::verify_delegation::AuthorizedVerifyOptions {
                trusted_roots: vec![root_key.verifying_key()],
                clock_skew_secs: 60,
                max_chain_depth: 16,
            };
            crate::verify_delegation::verify_authorized(&receipt, &opts).unwrap();
        }

        #[test]
        fn test_chain_gate_subject_mismatch_rejected() {
            let (root_key, _) = generate_keypair();
            let (agent_key, _) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();

            // Chain delegates to worker-A, but the decision grants worker-B.
            let scope = crate::delegation::Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 0,
                expires: None,
                budget: None,
            };
            let token = crate::sign_delegation::sign_delegation_with_principals(
                &root_key,
                "alice",
                Some("user://prismer/alice"),
                &agent_key.verifying_key(),
                "deploy-bot",
                Some("agent://prismer/worker-a"),
                &scope,
                None,
            )
            .unwrap();
            let chain_json = serde_json::to_string(&vec![token]).unwrap();

            let dec = make_decision(&authority_key, &a); // subject = deploy-bot
            let err = sign_with_decision(
                &agent_key,
                &a,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                Some(&chain_json),
            )
            .unwrap_err();
            assert!(err
                .to_string()
                .contains("does not match chain delegate principal"));
        }

        #[test]
        fn test_decision_with_constraints_signs_and_carries() {
            let (agent_key, agent_vk) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();
            let intent = CanonicalIntent::from_action(&a).unwrap();
            let dec = authorize(
                &authority_key,
                "agent://prismer/security",
                "agent://prismer/deploy-bot",
                &intent,
                DecisionType::Allow,
                DecisionBasis::Policy {
                    policy_hash: "sha256:abc".into(),
                    policy_name: "prod".into(),
                    matched_rules: vec![],
                    reason: String::new(),
                },
                vec![
                    Constraint::CallCount { max_calls: 5 },
                    Constraint::Monetary {
                        amount: "500.00".into(),
                        currency: "USD".into(),
                    },
                ],
                vec![],
                None,
                None,
            )
            .unwrap();

            let receipt = sign_with_decision(
                &agent_key,
                &a,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                None,
            )
            .unwrap();
            assert_eq!(
                receipt.authz_decision.as_ref().unwrap().constraints.len(),
                2
            );
            assert!(crate::verify::verify(&receipt, &agent_vk).is_ok());
        }

        #[test]
        fn test_verify_decision_for_action_expiry_via_receipt() {
            // Earliest-wins through verify(): decision expired while the
            // receipt itself has no exp.
            let (agent_key, agent_vk) = generate_keypair();
            let (authority_key, _) = generate_keypair();
            let a = action();
            let past = (chrono::Utc::now() - chrono::Duration::hours(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let intent = CanonicalIntent::from_action(&a).unwrap();
            let dec = authorize(
                &authority_key,
                "agent://prismer/security",
                "agent://prismer/deploy-bot",
                &intent,
                DecisionType::Allow,
                DecisionBasis::Policy {
                    policy_hash: "sha256:abc".into(),
                    policy_name: "prod".into(),
                    matched_rules: vec![],
                    reason: String::new(),
                },
                vec![],
                vec![],
                Some(&past),
                None,
            )
            .unwrap();
            // Signing with an already-expired decision is itself refused…
            assert!(sign_with_decision(
                &agent_key,
                &a,
                "deploy-bot",
                "alice",
                Some("agent://prismer/deploy-bot"),
                &dec,
                None,
            )
            .is_err());
            // …and the binding check reports the source by name.
            let err = verify_decision_for_action(&dec, &a, Some("agent://prismer/deploy-bot"))
                .unwrap_err();
            assert!(err.to_string().contains("decision expired"));
            let _ = (agent_vk, make_decision);
        }
    }

    // ─── principal tests ─────────────────────────────────────────────

    #[test]
    fn test_sign_with_principal_roundtrip() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign_with_principal(
            &key,
            &action,
            "deploy-bot",
            "alice",
            Some("agent://prismer/deploy-bot"),
            Some("user://prismer/alice"),
        )
        .unwrap();

        assert_eq!(
            receipt.signer.principal.as_deref(),
            Some("agent://prismer/deploy-bot")
        );
        assert_eq!(
            receipt.signer.acting_for.as_deref(),
            Some("user://prismer/alice")
        );
        assert!(crate::verify::verify(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_principal_in_signature_scope() {
        let (key, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_with_principal(
            &key,
            &action,
            "deploy-bot",
            "alice",
            Some("agent://prismer/deploy-bot"),
            None,
        )
        .unwrap();
        // Tamper: forge the principal claim
        receipt.signer.principal = Some("agent://evil/imposter".to_string());
        assert!(crate::verify::verify(&receipt, &vk).is_err());
    }

    #[test]
    fn test_sign_with_invalid_principal_rejected() {
        let (key, _) = generate_keypair();
        let action = test_action();
        // No trust domain — the flat v1 form is invalid
        let err = sign_with_principal(
            &key,
            &action,
            "bot",
            "owner",
            Some("agent://deploy-bot"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, SignetError::InvalidPrincipal(_)));

        let err = sign_with_principal(&key, &action, "bot", "owner", None, Some("not a principal"))
            .unwrap_err();
        assert!(matches!(err, SignetError::InvalidPrincipal(_)));
    }

    #[test]
    fn test_principal_absent_in_json_when_none() {
        let (key, _) = generate_keypair();
        let action = test_action();
        let receipt = sign(&key, &action, "agent", "owner").unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("\"principal\""));
        assert!(!json.contains("\"acting_for\""));
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
