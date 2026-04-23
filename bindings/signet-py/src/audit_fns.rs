use std::path::Path;

use chrono::{DateTime, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;

use crate::errors::to_py_err;
use crate::core_fns::parse_verifying_key;
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

// ─── audit_query ──────────────────────────────────────────────────────────────

#[pyfunction]
#[pyo3(signature = (dir, *, since=None, tool=None, signer=None, limit=None))]
fn audit_query(
    py: Python<'_>,
    dir: String,
    since: Option<&Bound<'_, PyAny>>,
    tool: Option<String>,
    signer: Option<String>,
    limit: Option<usize>,
) -> PyResult<Vec<PyAuditRecord>> {
    let filter = build_filter(py, since, tool, signer, limit)?;
    let path = Path::new(&dir).to_path_buf();
    let records = py
        .allow_threads(|| signet_core::audit::query(&path, &filter))
        .map_err(to_py_err)?;
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
        .allow_threads(|| signet_core::audit::verify_signatures_with_options(&path, &filter, &options))
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
    m.add_function(wrap_pyfunction!(audit_query, m)?)?;
    m.add_function(wrap_pyfunction!(audit_verify_chain, m)?)?;
    m.add_function(wrap_pyfunction!(audit_verify_signatures, m)?)?;
    Ok(())
}
