use std::path::Path;

use chrono::{DateTime, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;

use crate::core_fns::parse_verifying_key;
use crate::errors::{to_py_err, DecryptionError, KeyNotFoundError};
use crate::types::{
    PyAuditRecord, PyChainBreak, PyChainStatus, PyReceipt, PyVerifyFailure, PyVerifyResult,
    PyVerifyWarning,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn parse_since(_py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<DateTime<Utc>> {
    // Try string first
    if let Ok(s) = obj.extract::<String>() {
        return signet_core::audit::parse_since(&s).map_err(to_py_err);
    }

    // Try Python datetime — check tzinfo is not None (reject naive)
    let tzinfo = obj.getattr("tzinfo")?;
    if tzinfo.is_none() {
        return Err(PyValueError::new_err(
            "since must be a timezone-aware datetime",
        ));
    }

    let ts: f64 = obj.call_method0("timestamp")?.extract::<f64>()?;
    let secs = ts.floor() as i64;
    let nsecs = ((ts - ts.floor()) * 1_000_000_000.0) as u32;
    let dt = DateTime::from_timestamp(secs, nsecs)
        .ok_or_else(|| PyValueError::new_err(format!("invalid timestamp: {ts}")))?;
    Ok(dt)
}

fn build_filter(
    py: Python<'_>,
    since: Option<&Bound<'_, PyAny>>,
    tool: Option<String>,
    signer: Option<String>,
    limit: Option<usize>,
) -> PyResult<signet_core::audit::AuditFilter> {
    let since_dt = match since {
        Some(obj) => Some(parse_since(py, obj)?),
        None => None,
    };
    Ok(signet_core::audit::AuditFilter {
        since: since_dt,
        tool,
        signer,
        limit,
    })
}

fn encrypted_kid(receipt: &serde_json::Value) -> PyResult<Option<String>> {
    let Some(action) = receipt.get("action").and_then(|action| action.as_object()) else {
        return Ok(None);
    };
    let Some(envelope) = action.get("params_encrypted") else {
        return Ok(None);
    };

    envelope
        .get("kid")
        .and_then(|value| value.as_str())
        .map(|kid| Some(kid.to_string()))
        .ok_or_else(|| PyValueError::new_err("action.params_encrypted.kid missing or not a string"))
}

fn materialize_receipt_for_query(
    path: &Path,
    receipt: &serde_json::Value,
    passphrase: Option<&str>,
) -> PyResult<serde_json::Value> {
    let Some(kid) = encrypted_kid(receipt)? else {
        return Ok(receipt.clone());
    };

    let infos = signet_core::list_keys(path).map_err(to_py_err)?;
    let Some(info) = infos
        .into_iter()
        .find(|info| format!("ed25519:{}", info.pubkey) == kid)
    else {
        return Err(KeyNotFoundError::new_err(format!(
            "encrypted params present for {kid} but no matching local identity was found"
        )));
    };

    let signing_key =
        signet_core::load_signing_key(path, &info.name, passphrase).map_err(|err| match err {
            signet_core::SignetError::DecryptionError => DecryptionError::new_err(format!(
                "encrypted params present for {kid} but local identity '{}' could not be unlocked",
                info.name
            )),
            other => to_py_err(other),
        })?;

    signet_core::audit::decrypt_receipt_params_for_audit(receipt, &signing_key).map_err(to_py_err)
}

// ─── audit_append ─────────────────────────────────────────────────────────────

#[pyfunction]
fn audit_append(py: Python<'_>, dir: String, receipt: &PyReceipt) -> PyResult<PyAuditRecord> {
    let path = Path::new(&dir).to_path_buf();
    let receipt_json = serde_json::to_value(&receipt.inner)
        .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))?;
    let record = py
        .allow_threads(|| signet_core::audit::append(&path, &receipt_json))
        .map_err(to_py_err)?;
    Ok(PyAuditRecord { inner: record })
}

#[pyfunction]
fn audit_append_encrypted(
    py: Python<'_>,
    dir: String,
    receipt: &PyReceipt,
    secret_key: &str,
) -> PyResult<PyAuditRecord> {
    let path = Path::new(&dir).to_path_buf();
    let receipt_json = serde_json::to_value(&receipt.inner)
        .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))?;
    let signing_key = crate::core_fns::parse_signing_key(secret_key)?;
    let record = py
        .allow_threads(|| signet_core::audit::append_encrypted(&path, &receipt_json, &signing_key))
        .map_err(to_py_err)?;
    Ok(PyAuditRecord { inner: record })
}

// ─── audit_query ──────────────────────────────────────────────────────────────

#[pyfunction]
#[pyo3(signature = (dir, *, since=None, tool=None, signer=None, limit=None, decrypt_params=false, passphrase=None))]
#[allow(clippy::too_many_arguments)]
fn audit_query(
    py: Python<'_>,
    dir: String,
    since: Option<&Bound<'_, PyAny>>,
    tool: Option<String>,
    signer: Option<String>,
    limit: Option<usize>,
    decrypt_params: bool,
    passphrase: Option<String>,
) -> PyResult<Vec<PyAuditRecord>> {
    let filter = build_filter(py, since, tool, signer, limit)?;
    let path = Path::new(&dir).to_path_buf();
    let mut records = py
        .allow_threads(|| signet_core::audit::query(&path, &filter))
        .map_err(to_py_err)?;

    if decrypt_params {
        records = records
            .into_iter()
            .map(|mut record| {
                record.receipt =
                    materialize_receipt_for_query(&path, &record.receipt, passphrase.as_deref())?;
                Ok(record)
            })
            .collect::<PyResult<_>>()?;
    }

    Ok(records
        .into_iter()
        .map(|r| PyAuditRecord { inner: r })
        .collect())
}

// ─── audit_verify_chain ───────────────────────────────────────────────────────

#[pyfunction]
fn audit_verify_chain(py: Python<'_>, dir: String) -> PyResult<PyChainStatus> {
    let path = Path::new(&dir).to_path_buf();
    let status = py
        .allow_threads(|| signet_core::audit::verify_chain(&path))
        .map_err(to_py_err)?;

    let break_point = status.break_point.map(|b| PyChainBreak {
        file: b.file,
        line: b.line,
        expected_hash: b.expected_hash,
        actual_hash: b.actual_hash,
    });

    Ok(PyChainStatus {
        total_records: status.total_records,
        valid: status.valid,
        break_point,
    })
}

// ─── audit_verify_signatures ──────────────────────────────────────────────────

#[pyfunction]
#[pyo3(signature = (dir, *, since=None, tool=None, signer=None, limit=None, trusted_agent_keys=None, trusted_server_keys=None))]
#[allow(clippy::too_many_arguments)]
fn audit_verify_signatures(
    py: Python<'_>,
    dir: String,
    since: Option<&Bound<'_, PyAny>>,
    tool: Option<String>,
    signer: Option<String>,
    limit: Option<usize>,
    trusted_agent_keys: Option<Vec<String>>,
    trusted_server_keys: Option<Vec<String>>,
) -> PyResult<PyVerifyResult> {
    let filter = build_filter(py, since, tool, signer, limit)?;
    let path = Path::new(&dir).to_path_buf();
    let parse_keys = |keys: Option<Vec<String>>| -> PyResult<Vec<ed25519_dalek::VerifyingKey>> {
        keys.unwrap_or_default()
            .into_iter()
            .map(|key| parse_verifying_key(&key))
            .collect()
    };
    let options = signet_core::audit::AuditVerifyOptions {
        trusted_agent_pubkeys: parse_keys(trusted_agent_keys)?,
        trusted_server_pubkeys: parse_keys(trusted_server_keys)?,
    };
    let result = py
        .allow_threads(|| {
            signet_core::audit::verify_signatures_with_options(&path, &filter, &options)
        })
        .map_err(to_py_err)?;

    let failures = result
        .failures
        .into_iter()
        .map(|f| PyVerifyFailure {
            file: if f.file.is_empty() {
                None
            } else {
                Some(f.file)
            },
            line: if f.line == 0 { None } else { Some(f.line) },
            receipt_id: f.receipt_id,
            reason: f.reason,
        })
        .collect();
    let warnings = result
        .warnings
        .into_iter()
        .map(|w| PyVerifyWarning {
            file: if w.file.is_empty() {
                None
            } else {
                Some(w.file)
            },
            line: if w.line == 0 { None } else { Some(w.line) },
            receipt_id: w.receipt_id,
            reason: w.reason,
        })
        .collect();

    Ok(PyVerifyResult {
        total: result.total,
        valid: result.valid,
        warnings,
        failures,
    })
}

// ─── register ─────────────────────────────────────────────────────────────────

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(audit_append, m)?)?;
    m.add_function(wrap_pyfunction!(audit_append_encrypted, m)?)?;
    m.add_function(wrap_pyfunction!(audit_query, m)?)?;
    m.add_function(wrap_pyfunction!(audit_verify_chain, m)?)?;
    m.add_function(wrap_pyfunction!(audit_verify_signatures, m)?)?;
    Ok(())
}
