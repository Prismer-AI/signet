use pyo3::exceptions::PyException;
use pyo3::prelude::*;

pyo3::create_exception!(signet_auth, SignetError, PyException);

pyo3::create_exception!(signet_auth, InvalidKeyError, SignetError);
pyo3::create_exception!(signet_auth, SignatureMismatchError, SignetError);
pyo3::create_exception!(signet_auth, InvalidReceiptError, SignetError);
pyo3::create_exception!(signet_auth, CanonicalizeError, SignetError);
pyo3::create_exception!(signet_auth, SerializeError, SignetError);
pyo3::create_exception!(signet_auth, KeyNotFoundError, SignetError);
pyo3::create_exception!(signet_auth, KeyExistsError, SignetError);
pyo3::create_exception!(signet_auth, InvalidNameError, SignetError);
pyo3::create_exception!(signet_auth, DecryptionError, SignetError);
pyo3::create_exception!(signet_auth, CorruptedFileError, SignetError);
pyo3::create_exception!(signet_auth, CorruptedRecordError, SignetError);
pyo3::create_exception!(signet_auth, SignetIOError, SignetError);
pyo3::create_exception!(signet_auth, UnsupportedFormatError, SignetError);
pyo3::create_exception!(signet_auth, ScopeViolationError, SignetError);
pyo3::create_exception!(signet_auth, ChainError, SignetError);
pyo3::create_exception!(signet_auth, DelegationExpiredError, SignetError);
pyo3::create_exception!(signet_auth, UnauthorizedError, SignetError);

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SignetError", m.py().get_type::<SignetError>())?;
    m.add("InvalidKeyError", m.py().get_type::<InvalidKeyError>())?;
    m.add(
        "SignatureMismatchError",
        m.py().get_type::<SignatureMismatchError>(),
    )?;
    m.add(
        "InvalidReceiptError",
        m.py().get_type::<InvalidReceiptError>(),
    )?;
    m.add("CanonicalizeError", m.py().get_type::<CanonicalizeError>())?;
    m.add("SerializeError", m.py().get_type::<SerializeError>())?;
    m.add("KeyNotFoundError", m.py().get_type::<KeyNotFoundError>())?;
    m.add("KeyExistsError", m.py().get_type::<KeyExistsError>())?;
    m.add("InvalidNameError", m.py().get_type::<InvalidNameError>())?;
    m.add("DecryptionError", m.py().get_type::<DecryptionError>())?;
    m.add(
        "CorruptedFileError",
        m.py().get_type::<CorruptedFileError>(),
    )?;
    m.add(
        "CorruptedRecordError",
        m.py().get_type::<CorruptedRecordError>(),
    )?;
    m.add("SignetIOError", m.py().get_type::<SignetIOError>())?;
    m.add(
        "UnsupportedFormatError",
        m.py().get_type::<UnsupportedFormatError>(),
    )?;
    m.add(
        "ScopeViolationError",
        m.py().get_type::<ScopeViolationError>(),
    )?;
    m.add("ChainError", m.py().get_type::<ChainError>())?;
    m.add(
        "DelegationExpiredError",
        m.py().get_type::<DelegationExpiredError>(),
    )?;
    m.add("UnauthorizedError", m.py().get_type::<UnauthorizedError>())?;
    Ok(())
}

#[allow(dead_code)]
pub fn to_py_err(err: signet_core::SignetError) -> PyErr {
    match err {
        signet_core::SignetError::InvalidKey(msg) => InvalidKeyError::new_err(msg),
        signet_core::SignetError::SignatureMismatch => {
            SignatureMismatchError::new_err("signature verification failed")
        }
        signet_core::SignetError::CanonicalizeError(msg) => CanonicalizeError::new_err(msg),
        signet_core::SignetError::InvalidReceipt(msg) => InvalidReceiptError::new_err(msg),
        signet_core::SignetError::SerializeError(e) => SerializeError::new_err(e.to_string()),
        signet_core::SignetError::ScopeViolation(msg) => ScopeViolationError::new_err(msg),
        signet_core::SignetError::ChainError(msg) => ChainError::new_err(msg),
        signet_core::SignetError::DelegationExpired(msg) => DelegationExpiredError::new_err(msg),
        signet_core::SignetError::Unauthorized(msg) => UnauthorizedError::new_err(msg),
        #[cfg(not(target_arch = "wasm32"))]
        signet_core::SignetError::KeyNotFound(msg) => KeyNotFoundError::new_err(msg),
        #[cfg(not(target_arch = "wasm32"))]
        signet_core::SignetError::KeyExists(msg) => KeyExistsError::new_err(msg),
        #[cfg(not(target_arch = "wasm32"))]
        signet_core::SignetError::InvalidName(msg) => InvalidNameError::new_err(msg),
        #[cfg(not(target_arch = "wasm32"))]
        signet_core::SignetError::DecryptionError => {
            DecryptionError::new_err("decryption failed: wrong passphrase or corrupted key")
        }
        #[cfg(not(target_arch = "wasm32"))]
        signet_core::SignetError::CorruptedFile(msg) => CorruptedFileError::new_err(msg),
        #[cfg(not(target_arch = "wasm32"))]
        signet_core::SignetError::CorruptedRecord(msg) => CorruptedRecordError::new_err(msg),
        #[cfg(not(target_arch = "wasm32"))]
        signet_core::SignetError::IoError(e) => SignetIOError::new_err(e.to_string()),
        #[cfg(not(target_arch = "wasm32"))]
        signet_core::SignetError::UnsupportedFormat(msg) => UnsupportedFormatError::new_err(msg),
    }
}
