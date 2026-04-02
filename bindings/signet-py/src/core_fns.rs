use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pyo3::prelude::*;

use crate::errors::{to_py_err, InvalidKeyError};
use crate::types::{PyCompoundReceipt, PyKeyPair, PyReceipt};

#[pyfunction]
fn generate_keypair(py: Python<'_>) -> PyKeyPair {
    let (signing_key, verifying_key) = py.allow_threads(signet_core::generate_keypair);
    let secret_key = B64.encode(signing_key.to_keypair_bytes());
    let public_key = B64.encode(verifying_key.as_bytes());
    PyKeyPair { secret_key, public_key }
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
    let keypair_bytes = B64
        .decode(secret_key)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid base64 secret key: {e}")))?;
    let keypair_arr: [u8; 64] = keypair_bytes
        .try_into()
        .map_err(|_| InvalidKeyError::new_err("secret key must be 64 bytes"))?;
    let signing_key = SigningKey::from_keypair_bytes(&keypair_arr)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid signing key: {e}")))?;

    let inner_action = action.inner.clone();
    let owner = signer_owner.unwrap_or_default();

    let receipt = py
        .allow_threads(|| signet_core::sign(&signing_key, &inner_action, &signer_name, &owner))
        .map_err(to_py_err)?;

    Ok(PyReceipt { inner: receipt })
}

#[pyfunction]
fn verify(py: Python<'_>, receipt: crate::types::PyReceipt, public_key: &str) -> PyResult<bool> {
    let pubkey_bytes = B64
        .decode(public_key)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid base64 public key: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| InvalidKeyError::new_err("public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| InvalidKeyError::new_err(e.to_string()))?;

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
    let keypair_bytes = B64
        .decode(secret_key)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid base64 secret key: {e}")))?;
    let keypair_arr: [u8; 64] = keypair_bytes
        .try_into()
        .map_err(|_| InvalidKeyError::new_err("secret key must be 64 bytes"))?;
    let signing_key = SigningKey::from_keypair_bytes(&keypair_arr)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid signing key: {e}")))?;

    let inner_action = action.inner.clone();
    let owner = signer_owner.unwrap_or_default();

    let response_json: serde_json::Value = pythonize::depythonize(&response_content)?;

    // Use provided timestamps or current time for both.
    let now = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
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
    let pubkey_bytes = B64
        .decode(public_key)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid base64 public key: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| InvalidKeyError::new_err("public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| InvalidKeyError::new_err(e.to_string()))?;

    let json_str = receipt_json.to_string();
    let result = py.allow_threads(|| signet_core::verify_any(&json_str, &verifying_key));

    match result {
        Ok(()) => Ok(true),
        Err(signet_core::SignetError::SignatureMismatch) => Ok(false),
        Err(e) => Err(to_py_err(e)),
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(sign_compound, m)?)?;
    m.add_function(wrap_pyfunction!(verify_any, m)?)?;
    Ok(())
}
