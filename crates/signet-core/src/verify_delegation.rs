use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::canonical;
use crate::delegation::{
    build_delegation_signable, build_v4_receipt_signable, is_wildcard, validate_scope_narrowing,
    DelegationToken, Scope,
};
use crate::error::SignetError;
use crate::receipt::Receipt;
use sha2::{Digest, Sha256};

/// Verify a single delegation token's signature and expiry.
pub fn verify_delegation(
    token: &DelegationToken,
    at: Option<DateTime<Utc>>,
) -> Result<(), SignetError> {
    // 0. Check version
    if token.v != 1 {
        return Err(SignetError::InvalidReceipt(format!(
            "unsupported delegation token version: {}, expected 1",
            token.v
        )));
    }

    // 1. Decode delegator pubkey
    let pubkey_b64 = token
        .delegator
        .pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| {
            SignetError::InvalidKey("delegator pubkey missing ed25519: prefix".to_string())
        })?;
    let pubkey_bytes = BASE64
        .decode(pubkey_b64)
        .map_err(|e| SignetError::InvalidKey(format!("invalid delegator pubkey base64: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| SignetError::InvalidKey("delegator pubkey must be 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| SignetError::InvalidKey(format!("invalid delegator pubkey: {e}")))?;

    // 2. Decode signature
    let sig_b64 = token
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    // 3. Reconstruct signable, canonicalize, verify
    let signable = build_delegation_signable(
        &token.delegator,
        &token.delegate,
        &token.scope,
        &token.issued_at,
        &token.nonce,
    );
    let canonical_bytes = canonical::canonicalize(&signable)?;
    verifying_key
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)?;

    // 4. Check expiry
    if let Some(ref expires) = token.scope.expires {
        let expires_dt = DateTime::parse_from_rfc3339(expires)
            .map_err(|e| SignetError::DelegationExpired(format!("invalid expiry format: {e}")))?
            .with_timezone(&Utc);
        let verification_time = at.unwrap_or_else(Utc::now);
        if expires_dt < verification_time {
            return Err(SignetError::DelegationExpired(expires.clone()));
        }
    }

    Ok(())
}

/// Verify an entire delegation chain from root to leaf.
/// Returns the effective scope of the final delegate on success.
pub fn verify_chain(
    chain: &[DelegationToken],
    trusted_roots: &[VerifyingKey],
    at: Option<DateTime<Utc>>,
    max_chain_depth: Option<usize>,
) -> Result<Scope, SignetError> {
    let max_depth = max_chain_depth.unwrap_or(16);

    if chain.is_empty() {
        return Err(SignetError::ChainError(
            "empty delegation chain".to_string(),
        ));
    }
    if chain.len() > max_depth {
        return Err(SignetError::ChainError(format!(
            "chain exceeds maximum depth of {}",
            max_depth
        )));
    }

    let verification_time = at.unwrap_or_else(Utc::now);

    // Check root is trusted
    let root_pubkey_b64 = chain[0]
        .delegator
        .pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidKey("root pubkey missing ed25519: prefix".into()))?;
    let root_pubkey_bytes = BASE64
        .decode(root_pubkey_b64)
        .map_err(|e| SignetError::InvalidKey(format!("invalid root pubkey base64: {e}")))?;
    let root_pubkey_arr: [u8; 32] = root_pubkey_bytes
        .try_into()
        .map_err(|_| SignetError::InvalidKey("root pubkey must be 32 bytes".into()))?;
    let root_vk = VerifyingKey::from_bytes(&root_pubkey_arr)
        .map_err(|e| SignetError::InvalidKey(format!("invalid root pubkey: {e}")))?;

    if !trusted_roots.contains(&root_vk) {
        return Err(SignetError::ChainError(format!(
            "root key {} not in trusted roots",
            chain[0].delegator.pubkey
        )));
    }

    for i in 0..chain.len() {
        // a. Verify signature + expiry
        verify_delegation(&chain[i], Some(verification_time))?;

        // b. Pubkey continuity
        if i > 0 && chain[i].delegator.pubkey != chain[i - 1].delegate.pubkey {
            return Err(SignetError::ChainError(format!(
                "pubkey continuity broken at index {}: delegator {} != previous delegate {}",
                i,
                chain[i].delegator.pubkey,
                chain[i - 1].delegate.pubkey
            )));
        }

        // c. Scope narrowing
        if i > 0 {
            validate_scope_narrowing(&chain[i].scope, &chain[i - 1].scope)?;
        }

        // d. Depth check: remaining levels below i must be <= max_depth at i
        let remaining = chain.len() - 1 - i;
        if remaining > chain[i].scope.max_depth as usize {
            return Err(SignetError::ChainError(format!(
                "depth limit exceeded at index {}: max_depth={} but {} levels remain",
                i, chain[i].scope.max_depth, remaining
            )));
        }
    }

    Ok(chain.last().unwrap().scope.clone())
}

/// Options for verify_authorized().
pub struct AuthorizedVerifyOptions {
    pub trusted_roots: Vec<VerifyingKey>,
    pub clock_skew_secs: u64,
    pub max_chain_depth: usize,
}

impl Default for AuthorizedVerifyOptions {
    fn default() -> Self {
        Self {
            trusted_roots: vec![],
            clock_skew_secs: 60,
            max_chain_depth: 16,
        }
    }
}

/// Verify a v4 receipt: signature, delegation chain, and scope authorization.
pub fn verify_authorized(
    receipt: &Receipt,
    options: &AuthorizedVerifyOptions,
) -> Result<Scope, SignetError> {
    // 1. Check v4 + authorization present
    if receipt.v != 4 {
        return Err(SignetError::InvalidReceipt(format!(
            "expected v4 receipt, got v{}",
            receipt.v
        )));
    }
    let auth = receipt
        .authorization
        .as_ref()
        .ok_or_else(|| SignetError::InvalidReceipt("v4 receipt missing authorization".into()))?;

    // 2. Verify receipt signature using v4 signable (includes chain_hash + root_pubkey)
    verify_v4_signature_only(receipt)?;

    // 3. Verify chain_hash matches actual chain
    let chain_json = canonical::canonicalize(&serde_json::to_value(&auth.chain)?)?;
    let computed_hash = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(chain_json.as_bytes()))
    );
    if computed_hash != auth.chain_hash {
        return Err(SignetError::ChainError(format!(
            "chain_hash mismatch: expected {}, got {}",
            auth.chain_hash, computed_hash
        )));
    }

    // 4. Compute verification time from receipt.ts + clock_skew
    let receipt_ts = DateTime::parse_from_rfc3339(&receipt.ts)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid receipt timestamp: {e}")))?
        .with_timezone(&Utc);
    let at = receipt_ts + chrono::Duration::seconds(options.clock_skew_secs as i64);

    // 5. Verify chain
    let effective_scope = verify_chain(
        &auth.chain,
        &options.trusted_roots,
        Some(at),
        Some(options.max_chain_depth),
    )?;

    // 6. Signer must match final delegate
    if receipt.signer.pubkey != auth.chain.last().unwrap().delegate.pubkey {
        return Err(SignetError::ChainError(
            "signer pubkey does not match final delegate".into(),
        ));
    }

    // 7. Root pubkey must match chain root
    if auth.root_pubkey != auth.chain[0].delegator.pubkey {
        return Err(SignetError::ChainError("root_pubkey mismatch".into()));
    }

    // 8. Check action is within scope
    if !is_wildcard(&effective_scope.tools) && !effective_scope.tools.contains(&receipt.action.tool)
    {
        return Err(SignetError::Unauthorized(format!(
            "tool '{}' not in scope",
            receipt.action.tool
        )));
    }
    if !is_wildcard(&effective_scope.targets)
        && !effective_scope.targets.contains(&receipt.action.target)
    {
        return Err(SignetError::Unauthorized(format!(
            "target '{}' not in scope",
            receipt.action.target
        )));
    }

    Ok(effective_scope)
}

/// Verify only the signature of a v4 receipt (no chain verification).
/// Used by verify_any() for audit-level verification.
pub(crate) fn verify_v4_signature_only(receipt: &Receipt) -> Result<(), SignetError> {
    let auth = receipt
        .authorization
        .as_ref()
        .ok_or_else(|| SignetError::InvalidReceipt("v4 receipt missing authorization".into()))?;

    // Reconstruct v4 signable
    let signable = build_v4_receipt_signable(
        &receipt.action,
        &receipt.signer,
        &auth.chain_hash,
        &auth.root_pubkey,
        &receipt.ts,
        &receipt.nonce,
    );
    let canonical_bytes = canonical::canonicalize(&signable)?;

    // Decode signer pubkey
    let pubkey_b64 = receipt
        .signer
        .pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidKey("signer pubkey missing ed25519: prefix".into()))?;
    let pubkey_bytes = BASE64
        .decode(pubkey_b64)
        .map_err(|e| SignetError::InvalidKey(format!("invalid signer pubkey base64: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| SignetError::InvalidKey("signer pubkey must be 32 bytes".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| SignetError::InvalidKey(format!("invalid signer pubkey: {e}")))?;

    // Decode signature
    let sig_b64 = receipt
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".into()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    verifying_key
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::Scope;
    use crate::sign_delegation::sign_delegation;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_scope() -> Scope {
        Scope {
            tools: vec!["Bash".to_string()],
            targets: vec!["mcp://test".to_string()],
            max_depth: 1,
            expires: None,
            budget: None,
        }
    }

    #[test]
    fn test_verify_delegation_roundtrip() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        let token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &test_scope(),
            None,
        )
        .unwrap();

        assert!(verify_delegation(&token, None).is_ok());
    }

    #[test]
    fn test_verify_delegation_wrong_key() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);

        let mut token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &test_scope(),
            None,
        )
        .unwrap();

        // Tamper: replace delegator pubkey with wrong key
        token.delegator.pubkey = format!(
            "ed25519:{}",
            base64::engine::general_purpose::STANDARD.encode(wrong_key.verifying_key().to_bytes())
        );

        let err = verify_delegation(&token, None).unwrap_err();
        assert!(matches!(err, SignetError::SignatureMismatch));
    }

    #[test]
    fn test_verify_delegation_tampered_scope() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        let mut token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &test_scope(),
            None,
        )
        .unwrap();

        token.scope.tools = vec!["Write".to_string()]; // tamper

        let err = verify_delegation(&token, None).unwrap_err();
        assert!(matches!(err, SignetError::SignatureMismatch));
    }

    #[test]
    fn test_verify_delegation_tampered_delegate() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        let mut token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &test_scope(),
            None,
        )
        .unwrap();

        token.delegate.name = "evil-bot".to_string(); // tamper

        let err = verify_delegation(&token, None).unwrap_err();
        assert!(matches!(err, SignetError::SignatureMismatch));
    }

    #[test]
    fn test_verify_delegation_expired() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        let scope = Scope {
            tools: vec!["Bash".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 1,
            expires: Some("2020-01-01T00:00:00Z".to_string()), // long past
            budget: None,
        };

        let token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();

        let err = verify_delegation(&token, None).unwrap_err();
        assert!(matches!(err, SignetError::DelegationExpired(_)));
    }

    #[test]
    fn test_verify_delegation_not_expired() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        let future = (Utc::now() + Duration::hours(1)).to_rfc3339();
        let scope = Scope {
            tools: vec!["Bash".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 1,
            expires: Some(future),
            budget: None,
        };

        let token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();

        assert!(verify_delegation(&token, None).is_ok());
    }

    #[test]
    fn test_verify_delegation_tampered_version() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        let mut token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &test_scope(),
            None,
        )
        .unwrap();

        token.v = 2; // tamper version
        let err = verify_delegation(&token, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported delegation token version"));
    }

    #[test]
    fn test_verify_delegation_tampered_nonce() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        let mut token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &test_scope(),
            None,
        )
        .unwrap();

        token.nonce = "rnd_0000000000000000".to_string(); // tamper
        let err = verify_delegation(&token, None).unwrap_err();
        assert!(matches!(err, SignetError::SignatureMismatch));
    }

    #[test]
    fn test_verify_delegation_unsigned_fields_ignored() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        let mut token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &test_scope(),
            None,
        )
        .unwrap();

        // Tamper unsigned fields — should NOT affect verification
        token.correlation_id = Some("tampered".to_string());
        token.scope.budget = Some(serde_json::json!({"amount": 999}));
        assert!(verify_delegation(&token, None).is_ok());
    }

    #[test]
    fn test_verify_delegation_expired_with_custom_at() {
        let delegator_key = SigningKey::generate(&mut OsRng);
        let delegate_key = SigningKey::generate(&mut OsRng);

        // Token expires at 2026-06-01
        let scope = Scope {
            tools: vec!["Bash".to_string()],
            targets: vec!["*".to_string()],
            max_depth: 1,
            expires: Some("2026-06-01T00:00:00Z".to_string()),
            budget: None,
        };

        let token = sign_delegation(
            &delegator_key,
            "alice",
            &delegate_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();

        // Verify at a time BEFORE expiry — should pass
        let before_expiry = DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(verify_delegation(&token, Some(before_expiry)).is_ok());

        // Verify at a time AFTER expiry — should fail
        let after_expiry = DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(verify_delegation(&token, Some(after_expiry)).is_err());
    }

    // ── Phase 2: verify_chain tests ──────────────────────────────────────

    fn build_chain(depth: usize) -> (Vec<DelegationToken>, Vec<SigningKey>, SigningKey) {
        let root_key = SigningKey::generate(&mut OsRng);
        let mut keys = vec![SigningKey::generate(&mut OsRng)]; // delegate keys
        let mut chain = vec![];

        let root_scope = Scope {
            tools: vec!["*".to_string()],
            targets: vec!["*".to_string()],
            max_depth: depth as u32,
            expires: None,
            budget: None,
        };

        // root -> keys[0]
        let t0 = sign_delegation(
            &root_key,
            "root",
            &keys[0].verifying_key(),
            "agent-0",
            &Scope {
                max_depth: (depth as u32) - 1,
                ..root_scope.clone()
            },
            Some(&root_scope),
        )
        .unwrap();
        chain.push(t0);

        for i in 1..depth {
            let new_key = SigningKey::generate(&mut OsRng);
            let parent_scope = &chain.last().unwrap().scope;
            let child_scope = Scope {
                tools: vec!["*".to_string()],
                targets: vec!["*".to_string()],
                max_depth: parent_scope.max_depth - 1,
                expires: None,
                budget: None,
            };
            let token = sign_delegation(
                &keys[i - 1],
                &format!("agent-{}", i - 1),
                &new_key.verifying_key(),
                &format!("agent-{}", i),
                &child_scope,
                Some(parent_scope),
            )
            .unwrap();
            chain.push(token);
            keys.push(new_key);
        }

        (chain, keys, root_key)
    }

    #[test]
    fn test_verify_chain_empty() {
        let err = verify_chain(&[], &[], None, None).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_verify_chain_single_token() {
        let root_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec!["Bash".to_string()],
            targets: vec!["mcp://test".to_string()],
            max_depth: 0,
            expires: None,
            budget: None,
        };
        let token = sign_delegation(
            &root_key,
            "root",
            &agent_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();

        let result = verify_chain(&[token], &[root_key.verifying_key()], None, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().tools, vec!["Bash".to_string()]);
    }

    #[test]
    fn test_verify_chain_three_level() {
        let (chain, _keys, root_key) = build_chain(3);
        let result = verify_chain(&chain, &[root_key.verifying_key()], None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_chain_depth_exceeded() {
        // Build a 3-level chain but set root max_depth=1
        let root_key = SigningKey::generate(&mut OsRng);
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let k3 = SigningKey::generate(&mut OsRng);

        let t1 = sign_delegation(
            &root_key,
            "root",
            &k1.verifying_key(),
            "a1",
            &Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 1,
                expires: None,
                budget: None,
            },
            None,
        )
        .unwrap();
        let t2 = sign_delegation(
            &k1,
            "a1",
            &k2.verifying_key(),
            "a2",
            &Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 0,
                expires: None,
                budget: None,
            },
            Some(&t1.scope),
        )
        .unwrap();
        let t3 = sign_delegation(
            &k2,
            "a2",
            &k3.verifying_key(),
            "a3",
            &Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 0,
                expires: None,
                budget: None,
            },
            None, // bypass narrowing to force the chain
        )
        .unwrap();

        let err = verify_chain(&[t1, t2, t3], &[root_key.verifying_key()], None, None).unwrap_err();
        assert!(err.to_string().contains("depth limit exceeded"));
    }

    #[test]
    fn test_verify_chain_pubkey_continuity_broken() {
        let root_key = SigningKey::generate(&mut OsRng);
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);

        let t1 = sign_delegation(
            &root_key,
            "root",
            &k1.verifying_key(),
            "a1",
            &Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 1,
                expires: None,
                budget: None,
            },
            None,
        )
        .unwrap();
        // t2 is signed by wrong_key, not k1
        let t2 = sign_delegation(
            &wrong_key,
            "wrong",
            &k2.verifying_key(),
            "a2",
            &Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 0,
                expires: None,
                budget: None,
            },
            None,
        )
        .unwrap();

        let err = verify_chain(&[t1, t2], &[root_key.verifying_key()], None, None).unwrap_err();
        assert!(err.to_string().contains("pubkey continuity"));
    }

    #[test]
    fn test_verify_chain_untrusted_root() {
        let root_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec!["*".into()],
            targets: vec!["*".into()],
            max_depth: 0,
            expires: None,
            budget: None,
        };
        let token = sign_delegation(
            &root_key,
            "root",
            &agent_key.verifying_key(),
            "bot",
            &scope,
            None,
        )
        .unwrap();

        // Use other_key as trusted, not root_key
        let err = verify_chain(&[token], &[other_key.verifying_key()], None, None).unwrap_err();
        assert!(err.to_string().contains("not in trusted roots"));
    }

    // ── Phase 2: sign_authorized + verify_authorized tests ───────────────

    #[test]
    fn test_sign_authorized_roundtrip() {
        use crate::sign_delegation::sign_authorized;
        let root_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec!["Bash".into()],
            targets: vec!["mcp://test".into()],
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
        };
        let receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();

        assert_eq!(receipt.v, 4);
        assert!(receipt.authorization.is_some());
        assert_eq!(receipt.signer.owner, "alice"); // auto-derived from chain root

        let opts = AuthorizedVerifyOptions {
            trusted_roots: vec![root_key.verifying_key()],
            clock_skew_secs: 60,
            max_chain_depth: 16,
        };
        let scope = verify_authorized(&receipt, &opts).unwrap();
        assert_eq!(scope.tools, vec!["Bash".to_string()]);
    }

    #[test]
    fn test_verify_authorized_wrong_root() {
        use crate::sign_delegation::sign_authorized;
        let root_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
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
        };
        let receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();

        let opts = AuthorizedVerifyOptions {
            trusted_roots: vec![other_key.verifying_key()], // wrong root
            clock_skew_secs: 60,
            max_chain_depth: 16,
        };
        assert!(verify_authorized(&receipt, &opts).is_err());
    }

    #[test]
    fn test_verify_authorized_tool_not_in_scope() {
        use crate::sign_delegation::sign_authorized;
        let root_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
        let scope = Scope {
            tools: vec!["Read".into()],
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
            tool: "Write".into(), // NOT in scope
            params: serde_json::json!({}),
            params_hash: String::new(),
            target: "mcp://test".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
        };
        let receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();

        let opts = AuthorizedVerifyOptions {
            trusted_roots: vec![root_key.verifying_key()],
            clock_skew_secs: 60,
            max_chain_depth: 16,
        };
        let err = verify_authorized(&receipt, &opts).unwrap_err();
        assert!(err.to_string().contains("tool 'Write' not in scope"));
    }

    #[test]
    fn test_verify_authorized_wildcard_scope() {
        use crate::sign_delegation::sign_authorized;
        let root_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
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
            tool: "AnyTool".into(),
            params: serde_json::json!({}),
            params_hash: String::new(),
            target: "mcp://anything".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
        };
        let receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();

        let opts = AuthorizedVerifyOptions {
            trusted_roots: vec![root_key.verifying_key()],
            clock_skew_secs: 60,
            max_chain_depth: 16,
        };
        assert!(verify_authorized(&receipt, &opts).is_ok());
    }

    #[test]
    fn test_verify_authorized_tampered_chain_hash() {
        use crate::sign_delegation::sign_authorized;
        let root_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
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
        };
        let mut receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();

        // Tamper chain_hash
        receipt.authorization.as_mut().unwrap().chain_hash =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();

        let opts = AuthorizedVerifyOptions {
            trusted_roots: vec![root_key.verifying_key()],
            clock_skew_secs: 60,
            max_chain_depth: 16,
        };
        // Should fail (sig mismatch because chain_hash is in signable)
        assert!(verify_authorized(&receipt, &opts).is_err());
    }

    #[test]
    fn test_verify_authorized_empty_chain() {
        use crate::sign_delegation::sign_authorized;
        let agent_key = SigningKey::generate(&mut OsRng);
        let action = crate::receipt::Action {
            tool: "Bash".into(),
            params: serde_json::json!({}),
            params_hash: String::new(),
            target: "mcp://test".into(),
            transport: "stdio".into(),
            session: None,
            call_id: None,
            response_hash: None,
        };
        let err = sign_authorized(&agent_key, &action, "bot", vec![]).unwrap_err();
        assert!(err.to_string().contains("at least one token"));
    }

    // ── Phase 2: verify_any v4 tests ─────────────────────────────────────

    #[test]
    fn test_verify_any_v4() {
        use crate::sign_delegation::sign_authorized;
        use crate::verify::verify_any;
        let root_key = SigningKey::generate(&mut OsRng);
        let agent_key = SigningKey::generate(&mut OsRng);
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
        };
        let receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();
        let json = serde_json::to_string(&receipt).unwrap();

        assert!(verify_any(&json, &agent_key.verifying_key()).is_ok());
    }

    #[test]
    fn test_verify_any_v4_wrong_key() {
        use crate::sign_delegation::sign_authorized;
        use crate::verify::verify_any;
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
        };
        let receipt = sign_authorized(&agent_key, &action, "bot", vec![token]).unwrap();
        let json = serde_json::to_string(&receipt).unwrap();

        let err = verify_any(&json, &wrong_key.verifying_key()).unwrap_err();
        assert!(matches!(err, SignetError::SignatureMismatch));
    }

    // ── Phase 2: v1 backward compat test ─────────────────────────────────

    #[test]
    fn test_v1_receipt_deserialize_with_authorization_field() {
        // v1 receipt JSON (no authorization) should deserialize to authorization: None
        let v1_json = r#"{"v":1,"id":"rec_test","action":{"tool":"Bash","params":{},"params_hash":"","target":"mcp://test","transport":"stdio"},"signer":{"pubkey":"ed25519:AAAA","name":"bot","owner":"alice"},"ts":"2026-04-09T00:00:00Z","nonce":"rnd_test","sig":"ed25519:BBBB"}"#;
        let receipt: crate::receipt::Receipt = serde_json::from_str(v1_json).unwrap();
        assert_eq!(receipt.v, 1);
        assert!(receipt.authorization.is_none());
    }
}
