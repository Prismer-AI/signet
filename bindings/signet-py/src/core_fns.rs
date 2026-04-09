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

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(sign_compound, m)?)?;
    m.add_function(wrap_pyfunction!(verify_any, m)?)?;
    m.add_function(wrap_pyfunction!(sign_bilateral, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bilateral, m)?)?;
    m.add_function(wrap_pyfunction!(sign_delegation, m)?)?;
    m.add_function(wrap_pyfunction!(verify_delegation, m)?)?;
    m.add_function(wrap_pyfunction!(sign_authorized, m)?)?;
    m.add_function(wrap_pyfunction!(verify_authorized, m)?)?;
    Ok(())
}
