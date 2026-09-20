//! AuthorizationDecision — the authority-signed grant object (spec §3).
//!
//! This closes "agent signed ≠ agent authorized": the policy decision gets a
//! second signature from a key other than the agent's. The decision binds to
//! one action via `intent_hash` (canonical intent subset — sign-time
//! correlation fields excluded so authority-side pre-authorization works),
//! names its subject principal, carries a polymorphic basis (policy today;
//! approval/delegation/risk/external schema-ready), and travels inside the
//! agent's receipt signature — stripping or altering it breaks the agent's
//! own signature.

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::constraint::Constraint;
use crate::delegation::{current_timestamp, derive_id, format_pubkey, format_sig, generate_nonce};
use crate::error::SignetError;
use crate::obligation::{validate_obligation, Obligation};
use crate::policy::RuleAction;
use crate::receipt::Action;

pub const DECISION_VERSION: u8 = 1;

// ─── DecisionType ───────────────────────────────────────────────────────────

/// The authorization vocabulary. Independent from `RuleAction` (the policy
/// enum) by design — the types must not couple, or Policy↔Authorization
/// reunifies through the type system (spec Q13). Wire values are identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionType {
    Allow,
    RequireApproval,
    Deny,
}

impl From<RuleAction> for DecisionType {
    fn from(ra: RuleAction) -> Self {
        match ra {
            RuleAction::Allow => DecisionType::Allow,
            RuleAction::RequireApproval => DecisionType::RequireApproval,
            RuleAction::Deny => DecisionType::Deny,
        }
    }
}

// ─── Canonical intent ───────────────────────────────────────────────────────

/// The intent subset an authority pre-authorizes: sign-time correlation
/// fields (`session`, `call_id`, `trace_id`, `parent_receipt_id`,
/// `response_hash`) are deliberately excluded — they differ between the
/// authority's decision and the agent's receipt and would break the two-step
/// flow (spec Q9). `transport` is normalized to lowercase on both sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalIntent {
    pub tool: String,
    pub params_hash: String,
    pub target: String,
    pub transport: String,
}

impl CanonicalIntent {
    /// Derive the canonical intent from an action. `params_hash` is computed
    /// when absent (raw params present); an explicit hash (hash-only mode)
    /// passes through. Transport is lowercased.
    pub fn from_action(action: &Action) -> Result<CanonicalIntent, SignetError> {
        Ok(CanonicalIntent {
            tool: action.tool.clone(),
            params_hash: crate::sign::compute_params_hash(action)?,
            target: action.target.clone(),
            transport: action.transport.to_lowercase(),
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tool": self.tool,
            "params_hash": self.params_hash,
            "target": self.target,
            "transport": self.transport,
        })
    }
}

/// `"sha256:" + hex(SHA-256(JCS(canonical intent)))`.
pub fn intent_hash(intent: &CanonicalIntent) -> Result<String, SignetError> {
    let canonical_bytes = canonical::canonicalize(&intent.to_json())?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_bytes.as_bytes()))
    ))
}

// ─── Decision basis ─────────────────────────────────────────────────────────

/// Why the authority granted. `Policy` is implemented end-to-end in 0.11;
/// the other arms parse, verify, and display but have no producing flow yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DecisionBasis {
    Policy {
        policy_hash: String,
        policy_name: String,
        matched_rules: Vec<String>,
        reason: String,
    },
    Approval {
        approver: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    Delegation {
        token_id: String,
        chain_hash: String,
    },
    Risk {
        engine: String,
        score: String,
        reason: String,
    },
    External {
        system: String,
        #[serde(rename = "ref")]
        reference: String,
    },
}

// ─── AuthorizationDecision ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub v: u8,                    // always 1
    pub decision_id: String,      // "dec_" + 32 hex; derived from sig, excluded from signable
    pub authority: String,        // principal URI — who granted
    pub authority_pubkey: String, // "ed25519:<base64>"
    pub subject: String,          // principal URI of the acting agent
    pub intent_hash: String,      // binds the decision to one action
    pub decision: DecisionType,
    pub basis: DecisionBasis,
    pub constraints: Vec<Constraint>, // may be empty; narrowing-only once Scope wiring lands
    pub obligations: Vec<Obligation>, // may be empty
    pub issued_at: String,            // RFC 3339 UTC (Z)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>, // earliest-wins against Receipt.exp at verify time
    pub nonce: String,                // "rnd_<hex>" — makes the artifact unique, not its use
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>, // "grant://..." claim — verbatim, never resolved in 0.11
    pub sig: String, // authority's Ed25519 over JCS of everything above (sig, decision_id excluded)
}

/// Build the signable JSON for a decision. Excludes `sig` and `decision_id`
/// (both derived from the signature — including them would be circular).
fn build_decision_signable(dec: &AuthorizationDecision) -> serde_json::Value {
    let mut signable = serde_json::json!({
        "v": dec.v,
        "authority": dec.authority,
        "authority_pubkey": dec.authority_pubkey,
        "subject": dec.subject,
        "intent_hash": dec.intent_hash,
        "decision": dec.decision,
        "basis": dec.basis,
        "constraints": dec.constraints,
        "obligations": dec.obligations,
        "issued_at": dec.issued_at,
        "nonce": dec.nonce,
    });
    let obj = signable.as_object_mut().expect("just built as object");
    if let Some(ref expires_at) = dec.expires_at {
        obj.insert(
            "expires_at".to_string(),
            serde_json::Value::String(expires_at.clone()),
        );
    }
    if let Some(ref credential_ref) = dec.credential_ref {
        obj.insert(
            "credential_ref".to_string(),
            serde_json::Value::String(credential_ref.clone()),
        );
    }
    signable
}

fn parse_pubkey(prefixed: &str) -> Result<VerifyingKey, SignetError> {
    crate::delegation::parse_verifying_key(prefixed)
}

// ─── authorize ──────────────────────────────────────────────────────────────

/// Compose and authority-sign a decision. All inputs are validated: the
/// principals against the grammar, the constraints and obligations against
/// their schemas, `expires_at` as RFC 3339.
#[allow(clippy::too_many_arguments)]
pub fn authorize(
    authority_key: &SigningKey,
    authority: &str,
    subject: &str,
    intent: &CanonicalIntent,
    decision: DecisionType,
    basis: DecisionBasis,
    constraints: Vec<Constraint>,
    obligations: Vec<Obligation>,
    expires_at: Option<&str>,
    credential_ref: Option<&str>,
) -> Result<AuthorizationDecision, SignetError> {
    crate::principal::validate_principal(authority)?;
    crate::principal::validate_principal(subject)?;
    for c in &constraints {
        c.validate()?;
    }
    for ob in &obligations {
        validate_obligation(ob)?;
    }
    if let Some(exp) = expires_at {
        chrono::DateTime::parse_from_rfc3339(exp)
            .map_err(|e| SignetError::DecisionInvalid(format!("invalid expires_at: {e}")))?;
    }

    let ih = intent_hash(intent)?;
    let nonce = generate_nonce();
    let issued_at = current_timestamp();

    let unsigned = AuthorizationDecision {
        v: DECISION_VERSION,
        decision_id: String::new(), // derived after signing
        authority: authority.to_string(),
        authority_pubkey: format_pubkey(&authority_key.verifying_key().to_bytes()),
        subject: subject.to_string(),
        intent_hash: ih,
        decision,
        basis,
        constraints,
        obligations,
        issued_at,
        expires_at: expires_at.map(|s| s.to_string()),
        nonce,
        credential_ref: credential_ref.map(|s| s.to_string()),
        sig: String::new(),
    };

    let canonical_bytes = canonical::canonicalize(&build_decision_signable(&unsigned))?;
    let signature = authority_key.sign(canonical_bytes.as_bytes());
    let sig = format_sig(&signature.to_bytes());
    let decision_id = derive_id("dec", &signature.to_bytes());

    Ok(AuthorizationDecision {
        decision_id,
        sig,
        ..unsigned
    })
}

// ─── verify ─────────────────────────────────────────────────────────────────

/// Self-contained verification: the authority signature over the decision
/// body must verify against the embedded `authority_pubkey`. Proves the
/// artifact is intact, not that the authority is trusted (see
/// `verify_decision_trusted`).
pub fn verify_decision(dec: &AuthorizationDecision) -> Result<(), SignetError> {
    if dec.v != DECISION_VERSION {
        return Err(SignetError::DecisionInvalid(format!(
            "unsupported decision version {}",
            dec.v
        )));
    }
    if dec.decision_id.is_empty() || dec.sig.is_empty() {
        return Err(SignetError::DecisionInvalid(
            "decision_id and sig must be present".to_string(),
        ));
    }
    // ID derivation check: catches a sig/ID swap.
    let signature = crate::delegation::parse_signature(&dec.sig)
        .map_err(|e| SignetError::DecisionInvalid(e.to_string()))?;
    let expected_id = derive_id("dec", &signature.to_bytes());
    if dec.decision_id != expected_id {
        return Err(SignetError::DecisionInvalid(
            "decision_id does not match sig".to_string(),
        ));
    }

    let authority_vk = parse_pubkey(&dec.authority_pubkey)?;
    let canonical_bytes = canonical::canonicalize(&build_decision_signable(dec))?;
    authority_vk
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)
}

/// Strict verification: the signature must verify AND the embedded authority
/// pubkey must be one of `trusted`. The auditor's entry point.
pub fn verify_decision_trusted(
    dec: &AuthorizationDecision,
    trusted: &[VerifyingKey],
) -> Result<(), SignetError> {
    verify_decision(dec)?;
    let embedded = parse_pubkey(&dec.authority_pubkey)?;
    if !trusted.iter().any(|k| k.as_bytes() == embedded.as_bytes()) {
        return Err(SignetError::AuthorityMismatch(format!(
            "decision authority {} is not in the trusted set",
            dec.authority
        )));
    }
    Ok(())
}

/// Binding check: the decision's `intent_hash` matches the action, it is not
/// expired, and its `subject` matches the signer's principal. The signer
/// principal is required — an uncorroborated subject is not acceptable
/// evidence (spec §3.3).
pub fn verify_decision_for_action(
    dec: &AuthorizationDecision,
    action: &Action,
    signer_principal: Option<&str>,
) -> Result<(), SignetError> {
    let intent = CanonicalIntent::from_action(action)?;
    let actual_hash = intent_hash(&intent)?;
    if actual_hash != dec.intent_hash {
        return Err(SignetError::DecisionInvalid(format!(
            "intent_hash mismatch: decision covers {}, action is {} — the decision does not authorize this action",
            dec.intent_hash, actual_hash
        )));
    }

    if let Some(ref expires_at) = dec.expires_at {
        let exp = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map_err(|e| SignetError::DecisionInvalid(format!("invalid expires_at: {e}")))?;
        if chrono::Utc::now() > exp {
            return Err(SignetError::DecisionInvalid(format!(
                "decision expired at {expires_at}"
            )));
        }
    }

    match signer_principal {
        Some(p) if p == dec.subject => Ok(()),
        Some(p) => Err(SignetError::DecisionInvalid(format!(
            "decision subject '{}' does not match signer principal '{p}'",
            dec.subject
        ))),
        None => Err(SignetError::DecisionInvalid(
            "receipt signer has no principal; decision subject cannot be corroborated".to_string(),
        )),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::Action;

    fn test_action() -> Action {
        Action {
            tool: "github_merge_pr".into(),
            params: serde_json::json!({"pr": 123}),
            params_hash: String::new(),
            target: "mcp://github".into(),
            transport: "Stdio".into(), // mixed case on purpose
            session: Some("sess-1".into()),
            call_id: None,
            response_hash: None,
            trace_id: Some("tr-1".into()),
            parent_receipt_id: None,
        }
    }

    fn test_intent(action: &Action) -> CanonicalIntent {
        CanonicalIntent::from_action(action).unwrap()
    }

    fn policy_basis() -> DecisionBasis {
        DecisionBasis::Policy {
            policy_hash: "sha256:abc".into(),
            policy_name: "prod-policy".into(),
            matched_rules: vec!["allow-merge".into()],
            reason: "merge allowed".into(),
        }
    }

    fn authorize_default(action: &Action) -> AuthorizationDecision {
        let (authority_key, _) = crate::identity::generate_keypair();
        authorize(
            &authority_key,
            "agent://prismer/security",
            "agent://prismer/deploy-bot",
            &test_intent(action),
            DecisionType::Allow,
            policy_basis(),
            vec![],
            vec![],
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_authorize_verify_roundtrip() {
        let action = test_action();
        let dec = authorize_default(&action);
        assert!(dec.decision_id.starts_with("dec_"));
        assert_eq!(dec.decision_id.len(), 4 + 32);
        assert!(dec.sig.starts_with("ed25519:"));
        verify_decision(&dec).unwrap();
    }

    #[test]
    fn test_intent_hash_transport_normalized() {
        let a1 = test_action();
        let mut a2 = test_action();
        a2.transport = "stdio".into();
        // Correlation fields differ — irrelevant to the intent.
        a2.session = None;
        a2.trace_id = None;
        let h1 = intent_hash(&test_intent(&a1)).unwrap();
        let h2 = intent_hash(&test_intent(&a2)).unwrap();
        assert_eq!(h1, h2, "Stdio vs stdio must hash identically");
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn test_verify_decision_for_action_binding() {
        let action = test_action();
        let dec = authorize_default(&action);
        verify_decision_for_action(&dec, &action, Some("agent://prismer/deploy-bot")).unwrap();
    }

    #[test]
    fn test_intent_mismatch_rejected() {
        let action = test_action();
        let dec = authorize_default(&action);
        let mut other = test_action();
        other.params = serde_json::json!({"pr": 999});
        let err = verify_decision_for_action(&dec, &other, Some("agent://prismer/deploy-bot"))
            .unwrap_err();
        assert!(matches!(err, SignetError::DecisionInvalid(_)));
        assert!(err.to_string().contains("does not authorize this action"));
    }

    #[test]
    fn test_subject_mismatch_and_missing_rejected() {
        let action = test_action();
        let dec = authorize_default(&action);
        let err =
            verify_decision_for_action(&dec, &action, Some("agent://evil/imposter")).unwrap_err();
        assert!(err.to_string().contains("does not match signer principal"));
        let err = verify_decision_for_action(&dec, &action, None).unwrap_err();
        assert!(err.to_string().contains("cannot be corroborated"));
    }

    #[test]
    fn test_expired_decision_rejected() {
        let action = test_action();
        let (authority_key, _) = crate::identity::generate_keypair();
        let past = (chrono::Utc::now() - chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let dec = authorize(
            &authority_key,
            "agent://prismer/security",
            "agent://prismer/deploy-bot",
            &test_intent(&action),
            DecisionType::Allow,
            policy_basis(),
            vec![],
            vec![],
            Some(&past),
            None,
        )
        .unwrap();
        let err = verify_decision_for_action(&dec, &action, Some("agent://prismer/deploy-bot"))
            .unwrap_err();
        assert!(err.to_string().contains("decision expired"));
    }

    #[test]
    fn test_tampered_decision_fails_authority_sig() {
        let action = test_action();
        let mut dec = authorize_default(&action);
        dec.basis = DecisionBasis::Policy {
            policy_hash: "sha256:forged".into(),
            policy_name: "forged".into(),
            matched_rules: vec![],
            reason: String::new(),
        };
        assert!(matches!(
            verify_decision(&dec),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_decision_id_sig_swap_rejected() {
        let action = test_action();
        let dec1 = authorize_default(&action);
        let mut dec2 = authorize_default(&action);
        dec2.decision_id = dec1.decision_id.clone();
        let err = verify_decision(&dec2).unwrap_err();
        assert!(err.to_string().contains("does not match sig"));
    }

    #[test]
    fn test_trusted_mismatch_rejected() {
        let action = test_action();
        let dec = authorize_default(&action);
        let (_, other_vk) = crate::identity::generate_keypair();
        let err = verify_decision_trusted(&dec, &[other_vk]).unwrap_err();
        assert!(matches!(err, SignetError::AuthorityMismatch(_)));
    }

    #[test]
    fn test_trusted_match_passes() {
        let action = test_action();
        let (authority_key, authority_vk) = crate::identity::generate_keypair();
        let dec = authorize(
            &authority_key,
            "agent://prismer/security",
            "agent://prismer/deploy-bot",
            &test_intent(&action),
            DecisionType::Allow,
            policy_basis(),
            vec![],
            vec![],
            None,
            None,
        )
        .unwrap();
        verify_decision_trusted(&dec, &[authority_vk]).unwrap();
    }

    #[test]
    fn test_authorize_validates_inputs() {
        let action = test_action();
        let (authority_key, _) = crate::identity::generate_keypair();
        // Bad authority principal
        let err = authorize(
            &authority_key,
            "security", // no scheme
            "agent://prismer/deploy-bot",
            &test_intent(&action),
            DecisionType::Allow,
            policy_basis(),
            vec![],
            vec![],
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, SignetError::InvalidPrincipal(_)));

        // Bad constraint
        let err = authorize(
            &authority_key,
            "agent://prismer/security",
            "agent://prismer/deploy-bot",
            &test_intent(&action),
            DecisionType::Allow,
            policy_basis(),
            vec![Constraint::Monetary {
                amount: "5".into(),
                currency: "usd".into(), // must be uppercase
            }],
            vec![],
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, SignetError::InvalidConstraint(_)));

        // Bad expires
        let err = authorize(
            &authority_key,
            "agent://prismer/security",
            "agent://prismer/deploy-bot",
            &test_intent(&action),
            DecisionType::Allow,
            policy_basis(),
            vec![],
            vec![],
            Some("not-a-date"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, SignetError::DecisionInvalid(_)));
    }

    #[test]
    fn test_credential_ref_roundtrips_verbatim() {
        let action = test_action();
        let (authority_key, _) = crate::identity::generate_keypair();
        let dec = authorize(
            &authority_key,
            "agent://prismer/security",
            "agent://prismer/deploy-bot",
            &test_intent(&action),
            DecisionType::Allow,
            policy_basis(),
            vec![],
            vec![],
            None,
            Some("grant://github/prismer"),
        )
        .unwrap();
        assert_eq!(
            dec.credential_ref.as_deref(),
            Some("grant://github/prismer")
        );
        // Roundtrip through JSON keeps it verbatim and inside the signature.
        let json = serde_json::to_string(&dec).unwrap();
        let back: AuthorizationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.credential_ref, dec.credential_ref);
        verify_decision(&back).unwrap();
    }

    #[test]
    fn test_decision_type_wire_values_match_rule_action() {
        assert_eq!(
            serde_json::to_string(&DecisionType::Allow).unwrap(),
            serde_json::to_string(&RuleAction::Allow).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&DecisionType::RequireApproval).unwrap(),
            serde_json::to_string(&RuleAction::RequireApproval).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&DecisionType::Deny).unwrap(),
            serde_json::to_string(&RuleAction::Deny).unwrap()
        );
        let dt: DecisionType = serde_json::from_str("\"require_approval\"").unwrap();
        assert_eq!(dt, DecisionType::RequireApproval);
    }

    #[test]
    fn test_basis_serde_roundtrip_all_arms() {
        // Schema-ready arms must parse and serialize (no producing flow yet).
        let json = r#"{"type":"approval","approver":"user://prismer/alice"}"#;
        let b: DecisionBasis = serde_json::from_str(json).unwrap();
        assert!(matches!(b, DecisionBasis::Approval { .. }));
        let json = r#"{"type":"delegation","token_id":"del_1","chain_hash":"sha256:x"}"#;
        assert!(matches!(
            serde_json::from_str::<DecisionBasis>(json).unwrap(),
            DecisionBasis::Delegation { .. }
        ));
        let json = r#"{"type":"risk","engine":"acme","score":"0.9","reason":"low"}"#;
        assert!(matches!(
            serde_json::from_str::<DecisionBasis>(json).unwrap(),
            DecisionBasis::Risk { .. }
        ));
        let json = r#"{"type":"external","system":"opa","ref":"decision/42"}"#;
        assert!(matches!(
            serde_json::from_str::<DecisionBasis>(json).unwrap(),
            DecisionBasis::External { .. }
        ));
    }
}
