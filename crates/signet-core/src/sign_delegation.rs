use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::delegation::{
    build_delegation_signable, build_v4_receipt_signable, validate_scope_narrowing, Authorization,
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

    // 1. Validate scope narrowing if parent provided
    if let Some(ps) = parent_scope {
        validate_scope_narrowing(scope, ps)?;
    }

    // 2. Build identities
    let delegator = DelegationIdentity {
        pubkey: format!(
            "ed25519:{}",
            BASE64.encode(delegator_key.verifying_key().to_bytes())
        ),
        name: delegator_name.to_string(),
    };
    let delegate = DelegationIdentity {
        pubkey: format!("ed25519:{}", BASE64.encode(delegate_pubkey.to_bytes())),
        name: delegate_name.to_string(),
    };

    // 3. Generate nonce + timestamp
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = format!("rnd_{}", hex::encode(nonce_bytes));
    let issued_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // 4. Build signable, canonicalize, sign
    let signable = build_delegation_signable(&delegator, &delegate, scope, &issued_at, &nonce);
    let canonical_bytes = canonical::canonicalize(&signable)?;
    let signature = delegator_key.sign(canonical_bytes.as_bytes());

    // 5. Derive ID
    let sig_hash = Sha256::digest(signature.to_bytes());
    let id = format!("del_{}", hex::encode(&sig_hash[..16]));

    Ok(DelegationToken {
        v: 1,
        id,
        delegator,
        delegate,
        scope: scope.clone(),
        issued_at,
        nonce,
        sig: format!("ed25519:{}", BASE64.encode(signature.to_bytes())),
        correlation_id: None,
    })
}

/// Sign a tool call with authorization proof (v4 receipt).
pub fn sign_authorized(
    key: &SigningKey,
    action: &Action,
    signer_name: &str,
    chain: Vec<DelegationToken>,
) -> Result<Receipt, SignetError> {
    if chain.is_empty() {
        return Err(SignetError::ChainError(
            "chain must contain at least one token".into(),
        ));
    }

    // Extract from chain BEFORE moving it
    let root_pubkey = chain[0].delegator.pubkey.clone();
    let signer_owner = chain[0].delegator.name.clone();

    // Compute params_hash
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

    let signer = Signer {
        pubkey: format!("ed25519:{}", BASE64.encode(key.verifying_key().to_bytes())),
        name: signer_name.to_string(),
        owner: signer_owner,
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
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = format!("rnd_{}", hex::encode(nonce_bytes));
    let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // Build v4 signable (signs chain_hash, NOT full chain)
    let signable = build_v4_receipt_signable(
        &signed_action,
        &signer,
        &chain_hash,
        &root_pubkey,
        &ts,
        &nonce,
    );
    let canonical_bytes = canonical::canonicalize(&signable)?;
    let signature = key.sign(canonical_bytes.as_bytes());

    let sig_hash = Sha256::digest(signature.to_bytes());
    let id = format!("rec_{}", hex::encode(&sig_hash[..16]));
    let sig = format!("ed25519:{}", BASE64.encode(signature.to_bytes()));

    Ok(Receipt {
        v: 4,
        id,
        action: signed_action,
        signer,
        authorization: Some(authorization),
        ts,
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
}
