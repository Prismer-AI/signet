use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::delegation::{
    build_delegation_signable, build_v4_receipt_signable, current_timestamp, derive_id,
    format_pubkey, format_sig, generate_nonce, validate_scope_narrowing, Authorization,
    DelegationIdentity, DelegationToken, Scope,
};
use crate::error::SignetError;
use crate::receipt::{Action, Receipt, Signer};
use crate::sign::compute_params_hash;

pub fn sign_delegation(
    delegator_key: &SigningKey,
    delegator_name: &str,
    delegate_pubkey: &VerifyingKey,
    delegate_name: &str,
    scope: &Scope,
    parent_scope: Option<&Scope>,
) -> Result<DelegationToken, SignetError> {
    sign_delegation_with_principals(
        delegator_key,
        delegator_name,
        None,
        delegate_pubkey,
        delegate_name,
        None,
        scope,
        parent_scope,
    )
}

/// `sign_delegation` with canonical principal URIs on both identities.
/// Principals are validated against the grammar and enter the token's
/// signature scope; tokens without them canonicalize exactly as before.
#[allow(clippy::too_many_arguments)]
pub fn sign_delegation_with_principals(
    delegator_key: &SigningKey,
    delegator_name: &str,
    delegator_principal: Option<&str>,
    delegate_pubkey: &VerifyingKey,
    delegate_name: &str,
    delegate_principal: Option<&str>,
    scope: &Scope,
    parent_scope: Option<&Scope>,
) -> Result<DelegationToken, SignetError> {
    if let Some(p) = delegator_principal {
        crate::principal::validate_principal(p)?;
    }
    if let Some(p) = delegate_principal {
        crate::principal::validate_principal(p)?;
    }

    // 0. Validate inputs
    if delegator_name.is_empty() {
        return Err(SignetError::InvalidKey(
            "delegator name must be non-empty".into(),
        ));
    }
    if delegate_name.is_empty() {
        return Err(SignetError::InvalidKey(
            "delegate name must be non-empty".into(),
        ));
    }
    if scope.tools.is_empty() {
        return Err(SignetError::ScopeViolation(
            "tools must not be empty".into(),
        ));
    }
    if scope.targets.is_empty() {
        return Err(SignetError::ScopeViolation(
            "targets must not be empty".into(),
        ));
    }
    // Validate expires format if present (catch malformed dates at sign time)
    if let Some(ref expires) = scope.expires {
        chrono::DateTime::parse_from_rfc3339(expires)
            .map_err(|e| SignetError::ScopeViolation(format!("invalid expires format: {e}")))?;
    }
    // Reject mixed wildcards (e.g. ["*", "Bash"])
    if scope.tools.contains(&"*".to_string()) && scope.tools.len() > 1 {
        return Err(SignetError::ScopeViolation(
            "tools cannot mix wildcard '*' with explicit values".into(),
        ));
    }
    if scope.targets.contains(&"*".to_string()) && scope.targets.len() > 1 {
        return Err(SignetError::ScopeViolation(
            "targets cannot mix wildcard '*' with explicit values".into(),
        ));
    }

    // 1. Validate scope narrowing if parent provided
    if let Some(ps) = parent_scope {
        validate_scope_narrowing(scope, ps)?;
    }

    // 2. Build identities
    let delegator = DelegationIdentity {
        pubkey: format_pubkey(&delegator_key.verifying_key().to_bytes()),
        name: delegator_name.to_string(),
        principal: delegator_principal.map(|s| s.to_string()),
    };
    let delegate = DelegationIdentity {
        pubkey: format_pubkey(&delegate_pubkey.to_bytes()),
        name: delegate_name.to_string(),
        principal: delegate_principal.map(|s| s.to_string()),
    };

    // 3. Generate nonce + timestamp
    let nonce = generate_nonce();
    let issued_at = current_timestamp();

    // 4. Build signable, canonicalize, sign
    let signable = build_delegation_signable(&delegator, &delegate, scope, &issued_at, &nonce);
    let canonical_bytes = canonical::canonicalize(&signable)?;
    let signature = delegator_key.sign(canonical_bytes.as_bytes());

    // 5. Derive ID
    let id = derive_id("del", &signature.to_bytes());

    Ok(DelegationToken {
        v: 1,
        id,
        delegator,
        delegate,
        scope: scope.clone(),
        issued_at,
        nonce,
        sig: format_sig(&signature.to_bytes()),
        correlation_id: None,
    })
}

/// Chain gates for the combined v4+decision path (spec §3.3).
///
/// Phase 3 scope: the decision's subject must match the chain's final
/// delegate principal when the chain carries one — the grant and the
/// delegation must point at the same agent. Revocation (fail-closed) and
/// call-count budget gates join here in their phases.
pub(crate) fn enforce_chain_gates(
    chain: &[DelegationToken],
    decision: &crate::authorization::AuthorizationDecision,
) -> Result<(), SignetError> {
    if let Some(final_principal) = chain.last().and_then(|t| t.delegate.principal.as_deref()) {
        if decision.subject != final_principal {
            return Err(SignetError::DecisionInvalid(format!(
                "decision subject '{}' does not match chain delegate principal '{final_principal}'",
                decision.subject
            )));
        }
    }
    Ok(())
}

/// Sign a tool call with authorization proof (v4 receipt).
pub fn sign_authorized(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    chain: Vec<DelegationToken>,
) -> Result<Receipt, SignetError> {
    sign_authorized_with_principal(key, action, signer_name, None, None, chain)
}

/// `sign_authorized` with canonical principals on the signer.
///
/// When `acting_for` is `None` and the chain root carries a principal, that
/// principal is used — the one place the claim is machine-corroborated.
pub fn sign_authorized_with_principal(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_principal: Option<&str>,
    acting_for: Option<&str>,
    chain: Vec<DelegationToken>,
) -> Result<Receipt, SignetError> {
    sign_authorized_inner(
        key,
        action,
        signer_name,
        signer_principal,
        acting_for,
        None,
        chain,
    )
}

/// The v4 + decision combined path. The chain gates run whenever a decision
/// rides a chain (subject consistency today; revocation and budget gates
/// land with their phases).
pub(crate) fn sign_authorized_inner(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    signer_principal: Option<&str>,
    acting_for: Option<&str>,
    decision: Option<&crate::authorization::AuthorizationDecision>,
    chain: Vec<DelegationToken>,
) -> Result<Receipt, SignetError> {
    if chain.is_empty() {
        return Err(SignetError::ChainError(
            "chain must contain at least one token".into(),
        ));
    }

    // Verify signing key matches final delegate in chain
    let expected_pubkey = format!("ed25519:{}", BASE64.encode(key.verifying_key().to_bytes()));
    if expected_pubkey != chain.last().unwrap().delegate.pubkey {
        return Err(SignetError::ChainError(
            "signing key does not match final delegate in chain".into(),
        ));
    }

    if let Some(p) = signer_principal {
        crate::principal::validate_principal(p)?;
    }
    let acting_for = match acting_for {
        Some(p) => {
            crate::principal::validate_principal(p)?;
            Some(p.to_string())
        }
        None => match chain[0].delegator.principal.clone() {
            Some(p) => {
                crate::principal::validate_principal(&p)?;
                Some(p)
            }
            None => None,
        },
    };

    if let Some(dec) = decision {
        enforce_chain_gates(&chain, dec)?;
    }

    // Extract from chain BEFORE moving it
    let root_pubkey = chain[0].delegator.pubkey.clone();
    let signer_owner = chain[0].delegator.name.clone();

    // Compute params_hash
    let signed_action = action.with_params_hash(compute_params_hash(action)?);

    let signer = Signer {
        pubkey: format_pubkey(&key.verifying_key().to_bytes()),
        name: signer_name.to_string(),
        owner: signer_owner,
        principal: signer_principal.map(|s| s.to_string()),
        acting_for,
    };

    // Compute chain_hash
    let chain_json = canonical::canonicalize(&serde_json::to_value(&chain)?)?;
    let chain_hash = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(chain_json.as_bytes()))
    );

    let authorization = Authorization {
        chain,
        chain_hash: chain_hash.clone(),
        root_pubkey: root_pubkey.clone(),
    };

    // Generate nonce + timestamp
    let nonce = generate_nonce();
    let ts = current_timestamp();

    // Build v4 signable (signs chain_hash, NOT full chain)
    let signable = build_v4_receipt_signable(
        &signed_action,
        &signer,
        &chain_hash,
        &root_pubkey,
        &ts,
        &nonce,
        decision,
    );
    let canonical_bytes = canonical::canonicalize(&signable?)?;
    let signature = key.sign(canonical_bytes.as_bytes());

    let id = derive_id("rec", &signature.to_bytes());
    let sig = format_sig(&signature.to_bytes());

    Ok(Receipt {
        v: 4,
        id,
        action: signed_action,
        signer,
        authorization: Some(authorization),
        policy: None,
        authz_decision: decision.cloned(),
        ts,
        exp: None,
        nonce,
        sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::Scope;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_scope() -> Scope {
        Scope {
            tools: vec!["Bash".to_string(), "Read".to_string()],
            targets: vec!["mcp://github".to_string()],
            max_depth: 1,
            expires: None,
            budget: None,
        }
    }

    #[test]
    fn test_sign_delegation_roundtrip() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = test_scope();

        let token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "deploy-bot",
            &scope,
            None,
        )
        .unwrap();

        // Verify with verify_delegation (tested in verify_delegation.rs)
        crate::verify_delegation::verify_delegation(&token, None).unwrap();
    }

    #[test]
    fn test_sign_delegation_fields() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = test_scope();

        let token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "deploy-bot",
            &scope,
            None,
        )
        .unwrap();

        assert_eq!(token.v, 1);
        assert!(token.id.starts_with("del_"));
        assert_eq!(token.id.len(), 4 + 32); // "del_" + 32 hex chars
        assert!(token.sig.starts_with("ed25519:"));
        assert!(token.nonce.starts_with("rnd_"));
        assert_eq!(token.delegator.name, "alice");
        assert_eq!(token.delegate.name, "deploy-bot");
        assert!(token.delegator.pubkey.starts_with("ed25519:"));
        assert!(token.delegate.pubkey.starts_with("ed25519:"));
    }

    #[test]
    fn test_sign_delegation_scope_violation() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let parent_scope = Scope {
            tools: vec!["Bash".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 2,
            expires: None,
            budget: None,
        };
        let child_scope = Scope {
            tools: vec!["Write".to_string()], // not in parent
            targets: vec!["*".to_string()],
            max_depth: 1,
            expires: None,
            budget: None,
        };

        let err = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &child_scope,
            Some(&parent_scope),
        )
        .unwrap_err();

        assert!(err.to_string().contains("Write"));
    }

    #[test]
    fn test_sign_delegation_no_parent() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec!["*".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 10,
            expires: None,
            budget: None,
        };

        // No parent scope — should succeed for any scope
        assert!(sign_delegation(
            &delegator_key,
            "root",
            &delegate_key.verifying_key(),
            "agent",
            &scope,
            None,
        )
        .is_ok());
    }

    #[test]
    fn test_sign_delegation_nonce_uniqueness() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = test_scope();

        let t1 = sign_delegation(
            &delegator_key,
            "a",
            &delegate_key.verifying_key(),
            "b",
            &scope,
            None,
        )
        .unwrap();
        let t2 = sign_delegation(
            &delegator_key,
            "a",
            &delegate_key.verifying_key(),
            "b",
            &scope,
            None,
        )
        .unwrap();

        assert_ne!(t1.nonce, t2.nonce);
        assert_ne!(t1.id, t2.id);
    }

    #[test]
    fn test_sign_delegation_empty_name_rejected() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = test_scope();

        let err = sign_delegation(
            &delegator_key,
            "",
            &delegate_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn test_sign_delegation_empty_tools_rejected() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec![],
            targets: vec!["mcp://test".to_string()],
            max_depth: 1,
            expires: None,
            budget: None,
        };

        let err = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("tools must not be empty"));
    }

    #[test]
    fn test_sign_delegation_malformed_expires_rejected() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec!["Bash".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 1,
            expires: Some("not-a-date".to_string()),
            budget: None,
        };

        let err = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid expires"));
    }

    #[test]
    fn test_sign_delegation_id_derived_from_sig() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = test_scope();

        let token = sign_delegation(
            &delegator_key,
            "a",
            &delegate_key.verifying_key(),
            "b",
            &scope,
            None,
        )
        .unwrap();

        // Verify ID derivation
        let sig_b64 = token.sig.strip_prefix("ed25519:").unwrap();
        let sig_bytes = BASE64.decode(sig_b64).unwrap();
        let sig_hash = Sha256::digest(&sig_bytes);
        let expected_id = format!("del_{}", hex::encode(&sig_hash[..16]));
        assert_eq!(token.id, expected_id);
    }

    #[test]
    fn test_sign_delegation_mixed_wildcard_rejected() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec!["Bash".to_string(), "*".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 1,
            expires: None,
            budget: None,
        };

        let err = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot mix wildcard"));
    }

    #[test]
    fn test_sign_delegation_with_principals_roundtrip() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = test_scope();

        let token = sign_delegation_with_principals(
            &delegator_key,
            "alice",
            Some("user://prismer/alice"),
            &delegate_key.verifying_key(),
            "deploy-bot",
            Some("agent://prismer/deploy-bot"),
            &scope,
            None,
        )
        .unwrap();

        assert_eq!(
            token.delegator.principal.as_deref(),
            Some("user://prismer/alice")
        );
        assert_eq!(
            token.delegate.principal.as_deref(),
            Some("agent://prismer/deploy-bot")
        );
        // Token signature verifies with principals in scope
        crate::verify_delegation::verify_delegation(&token, None).unwrap();
    }

    #[test]
    fn test_sign_delegation_invalid_principal_rejected() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = test_scope();

        let err = sign_delegation_with_principals(
            &delegator_key,
            "alice",
            Some("alice"), // no scheme
            &delegate_key.verifying_key(),
            "deploy-bot",
            None,
            &scope,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, SignetError::InvalidPrincipal(_)));
    }

    #[test]
    fn test_delegation_token_without_principal_unchanged() {
        // Tokens without principals must serialize exactly as v0.10 did.
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let scope = test_scope();
        let token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "deploy-bot",
            &scope,
            None,
        )
        .unwrap();
        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("\"principal\""));
    }

    #[test]
    fn test_sign_authorized_with_principal_and_auto_acting_for() {
        let (root_key, _) = crate::identity::generate_keypair();
        let (agent_key, _) = crate::identity::generate_keypair();

        let scope = test_scope();
        let token = sign_delegation_with_principals(
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

        let action = crate::receipt::Action {
            tool: "Bash".into(),
            params: serde_json::json!({"cmd": "ls"}),
            params_hash: String::new(),
            target: "mcp://test".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: None,
            parent_receipt_id: None,
        };

        // acting_for omitted → auto-filled from the chain root principal
        let receipt = sign_authorized_with_principal(
            &agent_key,
            &action,
            "deploy-bot",
            Some("agent://prismer/deploy-bot"),
            None,
            vec![token],
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
        // v4 signature (which covers signer incl. principals) verifies
        assert!(crate::verify_delegation::verify_v4_signature_only(&receipt).is_ok());
    }

    #[test]
    fn test_sign_authorized_principal_tamper_breaks_signature() {
        let (root_key, _) = crate::identity::generate_keypair();
        let (agent_key, _) = crate::identity::generate_keypair();

        let scope = test_scope();
        let token = sign_delegation(
            &root_key,
            "alice",
            &agent_key.verifying_key(),
            "deploy-bot",
            &scope,
            None,
        )
        .unwrap();

        let action = crate::receipt::Action {
            tool: "Bash".into(),
            params: serde_json::json!({}),
            params_hash: String::new(),
            target: "mcp://test".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: None,
            parent_receipt_id: None,
        };

        let mut receipt = sign_authorized_with_principal(
            &agent_key,
            &action,
            "deploy-bot",
            Some("agent://prismer/deploy-bot"),
            None,
            vec![token],
        )
        .unwrap();

        receipt.signer.principal = Some("agent://evil/imposter".to_string());
        assert!(crate::verify_delegation::verify_v4_signature_only(&receipt).is_err());
    }

    #[test]
    fn test_sign_authorized_key_mismatch_rejected() {
        use crate::sign_delegation::sign_authorized;
        let root_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec!["*".into()],
            targets: vec!["*".into()],
            max_depth: 0,
            expires: None,
            budget: None,
        };
        let token = sign_delegation(
            &root_key,
            "alice",
            &agent_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();
        let action = crate::receipt::Action {
            tool: "Bash".into(),
            params: serde_json::json!({}),
            params_hash: String::new(),
            target: "mcp://test".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: None,
            parent_receipt_id: None,
        };

        // Sign with wrong_key (not the delegate in the chain)
        let err = sign_authorized(&wrong_key, &action, "bot", vec![token]).unwrap_err();
        assert!(err
            .to_string()
            .contains("signing key does not match final delegate"));
    }

    #[test]
    fn test_sign_authorized_preserves_trace_fields() {
        let (root_key, _root_vk) = crate::identity::generate_keypair();
        let (agent_key, _agent_vk) = crate::identity::generate_keypair();

        let scope = Scope {
            tools: vec!["*".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 0,
            expires: None,
            budget: None,
        };
        let token = sign_delegation(
            &root_key,
            "alice",
            &agent_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();

        let action = crate::receipt::Action {
            tool: "Bash".into(),
            params: serde_json::json!({"cmd": "ls"}),
            params_hash: String::new(),
            target: "mcp://test".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: Some("tr_delegated_wf".to_string()),
            parent_receipt_id: Some("rec_prev_step".to_string()),
        };

        let receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();

        // v4 receipt preserves trace fields
        assert_eq!(receipt.v, 4);
        assert_eq!(receipt.action.trace_id.as_deref(), Some("tr_delegated_wf"));
        assert_eq!(
            receipt.action.parent_receipt_id.as_deref(),
            Some("rec_prev_step")
        );

        // Verify signature
        assert!(crate::verify_delegation::verify_v4_signature_only(&receipt).is_ok());
    }

    #[test]
    fn test_sign_authorized_trace_in_signature_scope() {
        let (root_key, _) = crate::identity::generate_keypair();
        let (agent_key, _) = crate::identity::generate_keypair();

        let scope = Scope {
            tools: vec!["*".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 0,
            expires: None,
            budget: None,
        };
        let token = sign_delegation(
            &root_key,
            "alice",
            &agent_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();

        let action = crate::receipt::Action {
            tool: "Bash".into(),
            params: serde_json::json!({}),
            params_hash: String::new(),
            target: "mcp://test".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: Some("tr_legit".to_string()),
            parent_receipt_id: None,
        };

        let mut receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();

        // Tamper with trace_id
        receipt.action.trace_id = Some("tr_forged".to_string());

        // Signature should fail
        assert!(crate::verify_delegation::verify_v4_signature_only(&receipt).is_err());
    }

    #[test]
    fn test_sign_authorized_full_verify_with_trace() {
        let (root_key, _) = crate::identity::generate_keypair();
        let (agent_key, _) = crate::identity::generate_keypair();

        let scope = Scope {
            tools: vec!["*".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 0,
            expires: None,
            budget: None,
        };
        let token = sign_delegation(
            &root_key,
            "alice",
            &agent_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();

        let action = crate::receipt::Action {
            tool: "Bash".into(),
            params: serde_json::json!({"cmd": "deploy"}),
            params_hash: String::new(),
            target: "mcp://prod".into(),
            transport: "stdio".into(),
            session: Some("sess_001".to_string()),
            call_id: Some("call_001".to_string()),
            response_hash: None,
            trace_id: Some("tr_deploy_wf".to_string()),
            parent_receipt_id: Some("rec_approval".to_string()),
        };

        let receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();

        // Full verify with trusted root
        let opts = crate::verify_delegation::AuthorizedVerifyOptions {
            trusted_roots: vec![root_key.verifying_key()],
            clock_skew_secs: 60,
            max_chain_depth: 16,
        };
        let scope_result = crate::verify_delegation::verify_authorized(&receipt, &opts).unwrap();

        // Trace fields preserved through full verification
        assert_eq!(receipt.action.trace_id.as_deref(), Some("tr_deploy_wf"));
        assert_eq!(
            receipt.action.parent_receipt_id.as_deref(),
            Some("rec_approval")
        );
        assert_eq!(scope_result.tools, vec!["*"]);
    }
}
