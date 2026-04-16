use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pyo3::prelude::*;

use crate::errors::{to_py_err, InvalidKeyError};
use crate::types::{PyBilateralReceipt, PyCompoundReceipt, PyKeyPair, PyReceipt};

#[pyfunction]
fn generate_keypair(py: Python<'_>) -> PyKeyPair {
    let (signing_key, verifying_key) = py.allow_threads(signet_core::generate_keypair);
    let secret_key = B64.encode(signing_key.to_keypair_bytes());
    let public_key = B64.encode(verifying_key.as_bytes());
    PyKeyPair {
        secret_key,
        public_key,
    }
}

#[pyfunction]
#[pyo3(signature = (secret_key, action, signer_name, signer_owner=None))]
fn sign(
    py: Python<'_>,
    secret_key: &str,
    action: crate::types::PyAction,
    signer_name: String,
    signer_owner: Option<String>,
) -> PyResult<PyReceipt> {
    let signing_key = parse_signing_key(secret_key)?;
    let inner_action = action.inner.clone();
    let owner = signer_owner.unwrap_or_default();

    let receipt = py
        .allow_threads(|| signet_core::sign(&signing_key, &inner_action, &signer_name, &owner))
        .map_err(to_py_err)?;

    Ok(PyReceipt { inner: receipt })
}

#[pyfunction]
fn verify(py: Python<'_>, receipt: crate::types::PyReceipt, public_key: &str) -> PyResult<bool> {
    let verifying_key = parse_verifying_key(public_key)?;
    let inner_receipt = receipt.inner.clone();

    let result = py.allow_threads(|| signet_core::verify(&inner_receipt, &verifying_key));

    match result {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(to_py_err(e)),
    }
}

#[pyfunction]
#[pyo3(signature = (secret_key, action, response_content, signer_name, signer_owner=None, ts_request=None, ts_response=None))]
#[allow(clippy::too_many_arguments)]
fn sign_compound(
    py: Python<'_>,
    secret_key: &str,
    action: crate::types::PyAction,
    response_content: Bound<'_, PyAny>,
    signer_name: String,
    signer_owner: Option<String>,
    ts_request: Option<String>,
    ts_response: Option<String>,
) -> PyResult<PyCompoundReceipt> {
    let signing_key = parse_signing_key(secret_key)?;
    let inner_action = action.inner.clone();
    let owner = signer_owner.unwrap_or_default();

    let response_json: serde_json::Value = pythonize::depythonize(&response_content)?;

    // Use provided timestamps or current time for both.
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let ts_req = ts_request.unwrap_or_else(|| now.clone());
    let ts_resp = ts_response.unwrap_or_else(|| now.clone());

    let receipt = py
        .allow_threads(|| {
            signet_core::sign_compound(
                &signing_key,
                &inner_action,
                &response_json,
                &signer_name,
                &owner,
                &ts_req,
                &ts_resp,
            )
        })
        .map_err(to_py_err)?;

    Ok(PyCompoundReceipt { inner: receipt })
}

#[pyfunction]
fn verify_any(py: Python<'_>, receipt_json: &str, public_key: &str) -> PyResult<bool> {
    let verifying_key = parse_verifying_key(public_key)?;
    let json_str = receipt_json.to_string();
    let result = py.allow_threads(|| signet_core::verify_any(&json_str, &verifying_key));

    match result {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(to_py_err(e)),
    }
}

fn parse_signing_key(secret_key: &str) -> PyResult<SigningKey> {
    let keypair_bytes = B64
        .decode(secret_key)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid base64 secret key: {e}")))?;
    match keypair_bytes.len() {
        32 => {
            let seed: [u8; 32] = keypair_bytes.try_into().unwrap();
            Ok(SigningKey::from_bytes(&seed))
        }
        64 => {
            let arr: [u8; 64] = keypair_bytes.try_into().unwrap();
            SigningKey::from_keypair_bytes(&arr)
                .map_err(|e| InvalidKeyError::new_err(format!("invalid signing key: {e}")))
        }
        _ => Err(InvalidKeyError::new_err(
            "secret key must be 32 or 64 bytes",
        )),
    }
}

fn parse_verifying_key(public_key: &str) -> PyResult<VerifyingKey> {
    let pubkey_bytes = B64
        .decode(public_key)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid base64 public key: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| InvalidKeyError::new_err("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| InvalidKeyError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (server_key, agent_receipt, response_content, server_name, ts_response=None))]
fn sign_bilateral(
    py: Python<'_>,
    server_key: &str,
    agent_receipt: crate::types::PyReceipt,
    response_content: Bound<'_, PyAny>,
    server_name: String,
    ts_response: Option<String>,
) -> PyResult<PyBilateralReceipt> {
    let signing_key = parse_signing_key(server_key)?;
    let inner_receipt = agent_receipt.inner.clone();
    let response_json: serde_json::Value = pythonize::depythonize(&response_content)?;
    let ts = ts_response
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));

    let bilateral = py
        .allow_threads(|| {
            signet_core::sign_bilateral(
                &signing_key,
                &inner_receipt,
                &response_json,
                &server_name,
                &ts,
            )
        })
        .map_err(to_py_err)?;

    Ok(PyBilateralReceipt { inner: bilateral })
}

#[pyfunction]
fn verify_bilateral(
    py: Python<'_>,
    receipt: crate::types::PyBilateralReceipt,
    server_public_key: &str,
) -> PyResult<bool> {
    let verifying_key = parse_verifying_key(server_public_key)?;
    let inner = receipt.inner.clone();

    let result = py.allow_threads(|| signet_core::verify_bilateral(&inner, &verifying_key));

    match result {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(signet_core::SignetError::InvalidReceipt(ref msg))
            if msg.contains("does not match") =>
        {
            Ok(false)
        }
        Err(e) => Err(to_py_err(e)),
    }
}

/// Verify a bilateral receipt with session/call_id cross-check and optional nonce replay protection.
#[pyfunction]
#[pyo3(signature = (receipt, server_public_key, expected_session=None, expected_call_id=None, check_nonce=false, max_time_window_secs=300))]
#[allow(clippy::too_many_arguments)]
fn verify_bilateral_with_options(
    py: Python<'_>,
    receipt: crate::types::PyBilateralReceipt,
    server_public_key: &str,
    expected_session: Option<String>,
    expected_call_id: Option<String>,
    check_nonce: bool,
    max_time_window_secs: u64,
) -> PyResult<bool> {
    let verifying_key = parse_verifying_key(server_public_key)?;
    let inner = receipt.inner.clone();

    // Build nonce checker if requested (in-memory, per-call — for persistent
    // replay protection, use a shared checker at the application level)
    let nonce_checker: Option<Box<dyn signet_core::NonceChecker>> = if check_nonce {
        Some(Box::new(signet_core::InMemoryNonceChecker::new(10000, 600)))
    } else {
        None
    };

    let opts = signet_core::BilateralVerifyOptions {
        max_time_window_secs,
        trusted_agent_pubkey: None,
        expected_session,
        expected_call_id,
        nonce_checker,
    };

    let result =
        py.allow_threads(|| signet_core::verify_bilateral_with_options(&inner, &verifying_key, &opts));

    match result {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(signet_core::SignetError::InvalidReceipt(ref msg))
            if msg.contains("does not match") || msg.contains("mismatch") =>
        {
            Ok(false)
        }
        Err(e) => Err(to_py_err(e)),
    }
}

/// Create a delegation token granting scoped authority.
#[pyfunction]
#[pyo3(signature = (delegator_key_b64, delegator_name, delegate_pubkey_b64, delegate_name, scope_json, parent_scope_json=None))]
fn sign_delegation(
    py: Python<'_>,
    delegator_key_b64: &str,
    delegator_name: String,
    delegate_pubkey_b64: String,
    delegate_name: String,
    scope_json: String,
    parent_scope_json: Option<String>,
) -> PyResult<String> {
    let delegator_key = parse_signing_key(delegator_key_b64)?;
    let delegate_bytes = B64
        .decode(&delegate_pubkey_b64)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid delegate pubkey: {e}")))?;
    let delegate_arr: [u8; 32] = delegate_bytes
        .try_into()
        .map_err(|_| InvalidKeyError::new_err("delegate pubkey must be 32 bytes"))?;
    let delegate_vk = VerifyingKey::from_bytes(&delegate_arr)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid delegate pubkey: {e}")))?;

    let scope: signet_core::Scope =
        serde_json::from_str(&scope_json).map_err(|e| to_py_err(e.into()))?;
    let parent_scope: Option<signet_core::Scope> = parent_scope_json
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|e| to_py_err(e.into()))?;

    let token = py
        .allow_threads(|| {
            signet_core::sign_delegation(
                &delegator_key,
                &delegator_name,
                &delegate_vk,
                &delegate_name,
                &scope,
                parent_scope.as_ref(),
            )
        })
        .map_err(to_py_err)?;

    serde_json::to_string(&token).map_err(|e| to_py_err(e.into()))
}

/// Verify a delegation token's signature.
#[pyfunction]
fn verify_delegation(_py: Python<'_>, token_json: &str) -> PyResult<bool> {
    let token: signet_core::DelegationToken =
        serde_json::from_str(token_json).map_err(|e| to_py_err(e.into()))?;
    match signet_core::verify_delegation(&token, None) {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(signet_core::SignetError::DelegationExpired(_)) => Ok(false),
        Err(e) => Err(to_py_err(e)),
    }
}

/// Sign an action with a delegation chain (produces v4 receipt).
#[pyfunction]
fn sign_authorized(
    py: Python<'_>,
    key_b64: &str,
    action_json: String,
    signer_name: String,
    chain_json: String,
) -> PyResult<String> {
    let signing_key = parse_signing_key(key_b64)?;
    let action: signet_core::Action =
        serde_json::from_str(&action_json).map_err(|e| to_py_err(e.into()))?;
    let chain: Vec<signet_core::DelegationToken> =
        serde_json::from_str(&chain_json).map_err(|e| to_py_err(e.into()))?;

    let receipt = py
        .allow_threads(|| signet_core::sign_authorized(&signing_key, &action, &signer_name, chain))
        .map_err(to_py_err)?;

    serde_json::to_string(&receipt).map_err(|e| to_py_err(e.into()))
}

/// Verify an authorized (v4) receipt against trusted root keys.
#[pyfunction]
#[pyo3(signature = (receipt_json, trusted_roots_b64, clock_skew_secs=60))]
fn verify_authorized(
    _py: Python<'_>,
    receipt_json: &str,
    trusted_roots_b64: Vec<String>,
    clock_skew_secs: u64,
) -> PyResult<String> {
    let receipt: signet_core::Receipt =
        serde_json::from_str(receipt_json).map_err(|e| to_py_err(e.into()))?;

    let trusted_roots: Vec<VerifyingKey> = trusted_roots_b64
        .iter()
        .map(|k| {
            let bytes = B64
                .decode(k)
                .map_err(|e| InvalidKeyError::new_err(format!("invalid root key: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| InvalidKeyError::new_err("root key must be 32 bytes"))?;
            VerifyingKey::from_bytes(&arr)
                .map_err(|e| InvalidKeyError::new_err(format!("invalid root key: {e}")))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let opts = signet_core::AuthorizedVerifyOptions {
        trusted_roots,
        clock_skew_secs,
        max_chain_depth: 16,
    };

    let scope = signet_core::verify_authorized(&receipt, &opts).map_err(to_py_err)?;
    serde_json::to_string(&scope).map_err(|e| to_py_err(e.into()))
}

// ─── Expiration functions ────────────────────────────────────────────────────

/// Sign an action with an expiration time. Same as sign() but includes exp in the signed payload.
#[pyfunction]
fn sign_with_expiration(
    py: Python<'_>,
    secret_key: &str,
    action: crate::types::PyAction,
    signer_name: String,
    signer_owner: String,
    expires_at: String,
) -> PyResult<crate::types::PyReceipt> {
    let signing_key = parse_signing_key(secret_key)?;
    let inner_action = action.inner.clone();

    let receipt = py
        .allow_threads(|| {
            signet_core::sign_with_expiration(
                &signing_key,
                &inner_action,
                &signer_name,
                &signer_owner,
                &expires_at,
            )
        })
        .map_err(to_py_err)?;

    Ok(crate::types::PyReceipt { inner: receipt })
}

/// Verify a receipt, allowing expired receipts (for audit/forensic contexts).
#[pyfunction]
fn verify_allow_expired(
    py: Python<'_>,
    receipt: crate::types::PyReceipt,
    public_key: &str,
) -> PyResult<bool> {
    let verifying_key = parse_verifying_key(public_key)?;
    let inner_receipt = receipt.inner.clone();

    let result =
        py.allow_threads(|| signet_core::verify_allow_expired(&inner_receipt, &verifying_key));

    match result {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(to_py_err(e)),
    }
}

// ─── Policy functions ────────────────────────────────────────────────────────

/// Parse and validate a YAML policy string. Returns the policy as JSON.
#[pyfunction]
fn parse_policy_yaml(_py: Python<'_>, yaml: &str) -> PyResult<String> {
    let policy = signet_core::parse_policy_yaml(yaml).map_err(to_py_err)?;
    signet_core::validate_policy(&policy).map_err(to_py_err)?;
    serde_json::to_string(&policy).map_err(|e| to_py_err(e.into()))
}

/// Parse and validate a JSON policy string. Returns the policy as JSON.
#[pyfunction]
fn parse_policy_json(_py: Python<'_>, json_str: &str) -> PyResult<String> {
    let policy = signet_core::parse_policy_json(json_str).map_err(to_py_err)?;
    signet_core::validate_policy(&policy).map_err(to_py_err)?;
    serde_json::to_string(&policy).map_err(|e| to_py_err(e.into()))
}

/// Evaluate a policy against an action. Returns the evaluation result as JSON.
#[pyfunction]
fn evaluate_policy(
    _py: Python<'_>,
    action_json: &str,
    agent_name: &str,
    policy_json: &str,
) -> PyResult<String> {
    let action: signet_core::Action =
        serde_json::from_str(action_json).map_err(|e| to_py_err(e.into()))?;
    let policy: signet_core::Policy =
        serde_json::from_str(policy_json).map_err(|e| to_py_err(e.into()))?;

    let eval = signet_core::evaluate_policy(&action, agent_name, &policy, None);

    let result = serde_json::json!({
        "decision": eval.decision.to_string(),
        "matched_rules": eval.matched_rules,
        "winning_rule": eval.winning_rule,
        "reason": eval.reason,
        "policy_name": eval.policy_name,
        "policy_hash": eval.policy_hash,
    });
    serde_json::to_string(&result).map_err(|e| to_py_err(e.into()))
}

/// Sign an action with policy enforcement. Returns (receipt_json, eval_json).
/// Raises PolicyViolationError on deny, RequiresApprovalError on require_approval.
#[pyfunction]
fn sign_with_policy(
    py: Python<'_>,
    key_b64: &str,
    action_json: String,
    signer_name: String,
    signer_owner: String,
    policy_json: String,
) -> PyResult<(String, String)> {
    let signing_key = parse_signing_key(key_b64)?;
    let action: signet_core::Action =
        serde_json::from_str(&action_json).map_err(|e| to_py_err(e.into()))?;
    let policy: signet_core::Policy =
        serde_json::from_str(&policy_json).map_err(|e| to_py_err(e.into()))?;

    let (receipt, eval) = py
        .allow_threads(|| {
            signet_core::sign_with_policy(
                &signing_key,
                &action,
                &signer_name,
                &signer_owner,
                &policy,
                None,
            )
        })
        .map_err(to_py_err)?;

    let receipt_json = serde_json::to_string(&receipt).map_err(|e| to_py_err(e.into()))?;
    let eval_result = serde_json::json!({
        "decision": eval.decision.to_string(),
        "matched_rules": eval.matched_rules,
        "winning_rule": eval.winning_rule,
        "reason": eval.reason,
        "policy_name": eval.policy_name,
        "policy_hash": eval.policy_hash,
    });
    let eval_json = serde_json::to_string(&eval_result).map_err(|e| to_py_err(e.into()))?;
    Ok((receipt_json, eval_json))
}

/// Compute the SHA-256 hash of a policy (JCS-canonicalized).
#[pyfunction]
fn compute_policy_hash(_py: Python<'_>, policy_json: &str) -> PyResult<String> {
    let policy: signet_core::Policy =
        serde_json::from_str(policy_json).map_err(|e| to_py_err(e.into()))?;
    signet_core::compute_policy_hash(&policy).map_err(to_py_err)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(sign_compound, m)?)?;
    m.add_function(wrap_pyfunction!(verify_any, m)?)?;
    m.add_function(wrap_pyfunction!(sign_bilateral, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bilateral, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bilateral_with_options, m)?)?;
    m.add_function(wrap_pyfunction!(sign_delegation, m)?)?;
    m.add_function(wrap_pyfunction!(verify_delegation, m)?)?;
    m.add_function(wrap_pyfunction!(sign_authorized, m)?)?;
    m.add_function(wrap_pyfunction!(verify_authorized, m)?)?;
    // Expiration functions
    m.add_function(wrap_pyfunction!(sign_with_expiration, m)?)?;
    m.add_function(wrap_pyfunction!(verify_allow_expired, m)?)?;
    // Policy functions
    m.add_function(wrap_pyfunction!(parse_policy_yaml, m)?)?;
    m.add_function(wrap_pyfunction!(parse_policy_json, m)?)?;
    m.add_function(wrap_pyfunction!(evaluate_policy, m)?)?;
    m.add_function(wrap_pyfunction!(sign_with_policy, m)?)?;
    m.add_function(wrap_pyfunction!(compute_policy_hash, m)?)?;
    Ok(())
}
