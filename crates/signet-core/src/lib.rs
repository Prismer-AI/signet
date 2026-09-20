pub mod authorization;
pub mod canonical;
pub mod constraint;
pub mod delegation;
pub mod error;
pub mod identity;
pub mod obligation;
pub mod policy;
pub mod policy_eval;
pub mod policy_load;
pub mod principal;
pub mod receipt;
pub mod revocation;
pub mod sign;
pub mod sign_delegation;
pub mod trust;
pub mod verify;
pub mod verify_delegation;

#[cfg(not(target_arch = "wasm32"))]
pub mod keystore;

#[cfg(not(target_arch = "wasm32"))]
pub mod audit;

pub use authorization::{
    authorize, intent_hash, verify_decision, verify_decision_for_action, verify_decision_trusted,
    AuthorizationDecision, CanonicalIntent, DecisionBasis, DecisionType,
};
pub use constraint::{decimal_lte, Constraint, Decimal};
pub use delegation::{
    validate_scope_narrowing, Authorization, DelegationIdentity, DelegationToken, Scope,
};
pub use error::SignetError;
pub use identity::generate_keypair;
pub use obligation::{validate_obligation, Obligation, WELL_KNOWN_OBLIGATIONS};
pub use policy::{compute_policy_hash, Policy, PolicyAttestation, PolicyEvalResult, RuleAction};
pub use policy_eval::{evaluate_policy, RateLimitState};
pub use policy_load::{parse_policy_json, parse_policy_yaml, validate_policy};

#[cfg(not(target_arch = "wasm32"))]
pub use policy_load::load_policy;
pub use principal::{parse_principal, validate_principal, Principal};
pub use revocation::{
    check_revocation, sign_revocation, verify_revocation_record, ArtifactType, RevocationRecord,
    RevocationStatus,
};

pub use receipt::{
    Action, BilateralReceipt, CompoundReceipt, Outcome, OutcomeStatus, Receipt, Response,
    ServerInfo, Signer,
};
#[cfg(not(target_arch = "wasm32"))]
pub use revocation::fs_ops;
pub use sign::{
    sign, sign_bilateral, sign_bilateral_with_outcome, sign_compound, sign_with_decision,
    sign_with_expiration, sign_with_policy, sign_with_policy_authority,
    sign_with_policy_with_principal, sign_with_principal,
};
pub use sign_delegation::{
    sign_authorized, sign_authorized_with_principal, sign_delegation,
    sign_delegation_with_principals,
};
pub use trust::{
    parse_trust_bundle_json, parse_trust_bundle_yaml, validate_trust_bundle, TrustBundle,
    TrustKeyEntry, TrustKeyStatus,
};
#[cfg(not(target_arch = "wasm32"))]
pub use verify::FileNonceChecker;
pub use verify::{
    verify, verify_allow_expired, verify_any, verify_any_allow_expired, verify_bilateral,
    verify_bilateral_detailed, verify_bilateral_with_options,
    verify_bilateral_with_options_detailed, verify_compound, BilateralVerifyOptions,
    BilateralVerifyOutcome, InMemoryNonceChecker, NonceChecker,
};
pub use verify_delegation::{
    verify_authorized, verify_chain as verify_delegation_chain, verify_delegation,
    AuthorizedVerifyOptions,
};

#[cfg(not(target_arch = "wasm32"))]
pub use identity::fs_ops::{
    default_signet_dir, export_public_key, generate_and_save, generate_and_save_with_principal,
    list_keys, load_key_info, load_signing_key, load_verifying_key, validate_key_name, KeyInfo,
};
#[cfg(not(target_arch = "wasm32"))]
pub use trust::{load_trust_bundle, save_trust_bundle};

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::receipt::Action;
    use serde_json::json;

    pub fn test_action() -> Action {
        Action {
            tool: "github_create_issue".to_string(),
            params: json!({"title": "fix bug", "body": "details"}),
            params_hash: String::new(),
            target: "mcp://github.local".to_string(),
            transport: "stdio".to_string(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: None,
            parent_receipt_id: None,
        }
    }
}
