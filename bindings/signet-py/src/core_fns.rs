use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pyo3::prelude::*;

use crate::errors::{to_py_err, InvalidKeyError};
use crate::types::{PyKeyPair, PyReceipt};

#[pyfunction]
fn generate_keypair(py: Python<'_>) -> PyKeyPair {
    let (signing_key, verifying_key) = py.allow_threads(|| signet_core::generate_keypair());
    let secret_key = B64.encode(signing_key.to_bytes());
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
    let seed_bytes = B64
        .decode(secret_key)
        .map_err(|e| InvalidKeyError::new_err(format!("invalid base64 secret key: {e}")))?;
    let seed_arr: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| InvalidKeyError::new_err("secret key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&seed_arr);

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

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    Ok(())
}
