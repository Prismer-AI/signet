use pyo3::prelude::*;

// ─── Action ───────────────────────────────────────────────────────────────────

#[pyclass(name = "Action")]
#[derive(Clone)]
pub struct PyAction {
    pub inner: signet_core::receipt::Action,
}

#[pymethods]
impl PyAction {
    #[new]
    #[pyo3(signature = (tool, params=None, target=String::new(), transport=String::from("stdio"), session=None, call_id=None, response_hash=None, trace_id=None, parent_receipt_id=None))]
    fn new(
        tool: String,
        params: Option<Bound<'_, PyAny>>,
        target: String,
        transport: String,
        session: Option<String>,
        call_id: Option<String>,
        response_hash: Option<String>,
        trace_id: Option<String>,
        parent_receipt_id: Option<String>,
    ) -> PyResult<Self> {
        let json_params = match params {
            Some(p) => pythonize::depythonize(&p)?,
            None => serde_json::Value::Null,
        };
        Ok(PyAction {
            inner: signet_core::receipt::Action {
                tool,
                params: json_params,
                params_hash: String::new(),
                target,
                transport,
                session,
                call_id,
                response_hash,
                trace_id,
                parent_receipt_id,
            },
        })
    }

    #[classmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (tool, params_hash, *, target=String::new(), transport=String::from("stdio"), session=None, call_id=None, response_hash=None, trace_id=None, parent_receipt_id=None))]
    fn hash_only(
        _cls: &Bound<'_, pyo3::types::PyType>,
        tool: String,
        params_hash: String,
        target: String,
        transport: String,
        session: Option<String>,
        call_id: Option<String>,
        response_hash: Option<String>,
        trace_id: Option<String>,
        parent_receipt_id: Option<String>,
    ) -> Self {
        PyAction {
            inner: signet_core::receipt::Action {
                tool,
                params: serde_json::Value::Null,
                params_hash,
                target,
                transport,
                session,
                call_id,
                response_hash,
                trace_id,
                parent_receipt_id,
            },
        }
    }

    #[getter]
    fn tool(&self) -> &str {
        &self.inner.tool
    }

    #[getter]
    fn params<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        if self.inner.params.is_null() {
            Ok(None)
        } else {
            let obj = pythonize::pythonize(py, &self.inner.params)?;
            Ok(Some(obj))
        }
    }

    #[getter]
    fn params_hash(&self) -> &str {
        &self.inner.params_hash
    }

    #[getter]
    fn target(&self) -> &str {
        &self.inner.target
    }

    #[getter]
    fn transport(&self) -> &str {
        &self.inner.transport
    }

    #[getter]
    fn session(&self) -> Option<&str> {
        self.inner.session.as_deref()
    }

    #[getter]
    fn call_id(&self) -> Option<&str> {
        self.inner.call_id.as_deref()
    }

    #[getter]
    fn response_hash(&self) -> Option<&str> {
        self.inner.response_hash.as_deref()
    }

    #[getter]
    fn trace_id(&self) -> Option<&str> {
        self.inner.trace_id.as_deref()
    }

    #[getter]
    fn parent_receipt_id(&self) -> Option<&str> {
        self.inner.parent_receipt_id.as_deref()
    }
}

// ─── Signer ───────────────────────────────────────────────────────────────────

#[pyclass(name = "Signer")]
#[derive(Clone)]
pub struct PySigner {
    pub inner: signet_core::receipt::Signer,
}

#[pymethods]
impl PySigner {
    #[getter]
    fn pubkey(&self) -> &str {
        &self.inner.pubkey
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn owner(&self) -> &str {
        &self.inner.owner
    }
}

// ─── Receipt ──────────────────────────────────────────────────────────────────

#[pyclass(name = "Receipt")]
#[derive(Clone)]
pub struct PyReceipt {
    pub inner: signet_core::Receipt,
}

#[pymethods]
impl PyReceipt {
    #[getter]
    fn v(&self) -> u8 {
        self.inner.v
    }

    #[getter]
    fn id(&self) -> &str {
        &self.inner.id
    }

    #[getter]
    fn action(&self) -> PyAction {
        PyAction {
            inner: self.inner.action.clone(),
        }
    }

    #[getter]
    fn signer(&self) -> PySigner {
        PySigner {
            inner: self.inner.signer.clone(),
        }
    }

    #[getter]
    fn ts(&self) -> &str {
        &self.inner.ts
    }

    #[getter]
    fn nonce(&self) -> &str {
        &self.inner.nonce
    }

    #[getter]
    fn sig(&self) -> &str {
        &self.inner.sig
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))
    }

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner: signet_core::Receipt = serde_json::from_str(json_str)
            .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))?;
        Ok(PyReceipt { inner })
    }
}

// ─── KeyPair ──────────────────────────────────────────────────────────────────

#[pyclass(name = "KeyPair")]
pub struct PyKeyPair {
    #[pyo3(get)]
    pub secret_key: String,
    #[pyo3(get)]
    pub public_key: String,
}

#[pymethods]
impl PyKeyPair {
    fn __repr__(&self) -> String {
        format!(
            "KeyPair(public_key='{}', secret_key='<REDACTED>')",
            self.public_key
        )
    }
}

// ─── KeyInfo ──────────────────────────────────────────────────────────────────

#[pyclass(name = "KeyInfo")]
#[derive(Clone)]
pub struct PyKeyInfo {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub owner: Option<String>,
    #[pyo3(get)]
    pub pubkey: String,
    #[pyo3(get)]
    pub created_at: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<signet_core::KeyInfo> for PyKeyInfo {
    fn from(k: signet_core::KeyInfo) -> Self {
        PyKeyInfo {
            name: k.name,
            owner: k.owner,
            pubkey: k.pubkey,
            created_at: k.created_at,
        }
    }
}

// ─── AuditRecord ──────────────────────────────────────────────────────────────

#[pyclass(name = "AuditRecord")]
#[derive(Clone)]
pub struct PyAuditRecord {
    pub inner: signet_core::audit::AuditRecord,
}

#[pymethods]
impl PyAuditRecord {
    #[getter]
    fn receipt<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pythonize::pythonize(py, &self.inner.receipt)
            .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))
    }

    #[getter]
    fn prev_hash(&self) -> &str {
        &self.inner.prev_hash
    }

    #[getter]
    fn record_hash(&self) -> &str {
        &self.inner.record_hash
    }
}

// ─── ChainBreak ───────────────────────────────────────────────────────────────

#[pyclass(name = "ChainBreak")]
#[derive(Clone)]
pub struct PyChainBreak {
    #[pyo3(get)]
    pub file: String,
    #[pyo3(get)]
    pub line: usize,
    #[pyo3(get)]
    pub expected_hash: String,
    #[pyo3(get)]
    pub actual_hash: String,
}

// ─── ChainStatus ──────────────────────────────────────────────────────────────

#[pyclass(name = "ChainStatus")]
pub struct PyChainStatus {
    #[pyo3(get)]
    pub total_records: usize,
    #[pyo3(get)]
    pub valid: bool,
    pub break_point: Option<PyChainBreak>,
}

#[pymethods]
impl PyChainStatus {
    #[getter]
    fn break_point(&self) -> Option<PyChainBreak> {
        self.break_point.clone()
    }
}

// ─── VerifyFailure ────────────────────────────────────────────────────────────

#[pyclass(name = "VerifyFailure")]
#[derive(Clone)]
pub struct PyVerifyFailure {
    #[pyo3(get)]
    pub file: Option<String>,
    #[pyo3(get)]
    pub line: Option<usize>,
    #[pyo3(get)]
    pub receipt_id: String,
    #[pyo3(get)]
    pub reason: String,
}

// ─── VerifyResult ─────────────────────────────────────────────────────────────

#[pyclass(name = "VerifyResult")]
pub struct PyVerifyResult {
    #[pyo3(get)]
    pub total: usize,
    #[pyo3(get)]
    pub valid: usize,
    pub failures: Vec<PyVerifyFailure>,
}

#[pymethods]
impl PyVerifyResult {
    #[getter]
    fn failures(&self) -> Vec<PyVerifyFailure> {
        self.failures.clone()
    }
}

// ─── Response ─────────────────────────────────────────────────────────────────

#[pyclass(name = "Response")]
#[derive(Clone)]
pub struct PyResponse {
    pub inner: signet_core::receipt::Response,
}

#[pymethods]
impl PyResponse {
    #[getter]
    fn content_hash(&self) -> &str {
        &self.inner.content_hash
    }
}

// ─── CompoundReceipt ──────────────────────────────────────────────────────────

#[pyclass(name = "CompoundReceipt")]
#[derive(Clone)]
pub struct PyCompoundReceipt {
    pub inner: signet_core::CompoundReceipt,
}

#[pymethods]
impl PyCompoundReceipt {
    #[getter]
    fn v(&self) -> u8 {
        self.inner.v
    }

    #[getter]
    fn id(&self) -> &str {
        &self.inner.id
    }

    #[getter]
    fn action(&self) -> PyAction {
        PyAction {
            inner: self.inner.action.clone(),
        }
    }

    #[getter]
    fn response(&self) -> PyResponse {
        PyResponse {
            inner: self.inner.response.clone(),
        }
    }

    #[getter]
    fn signer(&self) -> PySigner {
        PySigner {
            inner: self.inner.signer.clone(),
        }
    }

    #[getter]
    fn ts_request(&self) -> &str {
        &self.inner.ts_request
    }

    #[getter]
    fn ts_response(&self) -> &str {
        &self.inner.ts_response
    }

    #[getter]
    fn nonce(&self) -> &str {
        &self.inner.nonce
    }

    #[getter]
    fn sig(&self) -> &str {
        &self.inner.sig
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))
    }

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner: signet_core::CompoundReceipt = serde_json::from_str(json_str)
            .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))?;
        Ok(PyCompoundReceipt { inner })
    }
}

// ─── ServerInfo ──────────────────────────────────────────────────────────────

#[pyclass(name = "ServerInfo")]
#[derive(Clone)]
pub struct PyServerInfo {
    pub inner: signet_core::receipt::ServerInfo,
}

#[pymethods]
impl PyServerInfo {
    #[getter]
    fn pubkey(&self) -> &str {
        &self.inner.pubkey
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }
}

// ─── BilateralReceipt ────────────────────────────────────────────────────────

#[pyclass(name = "BilateralReceipt")]
#[derive(Clone)]
pub struct PyBilateralReceipt {
    pub inner: signet_core::BilateralReceipt,
}

#[pymethods]
impl PyBilateralReceipt {
    #[getter]
    fn v(&self) -> u8 {
        self.inner.v
    }

    #[getter]
    fn id(&self) -> &str {
        &self.inner.id
    }

    #[getter]
    fn agent_receipt(&self) -> PyReceipt {
        PyReceipt {
            inner: self.inner.agent_receipt.clone(),
        }
    }

    #[getter]
    fn response(&self) -> PyResponse {
        PyResponse {
            inner: self.inner.response.clone(),
        }
    }

    #[getter]
    fn server(&self) -> PyServerInfo {
        PyServerInfo {
            inner: self.inner.server.clone(),
        }
    }

    #[getter]
    fn ts_response(&self) -> &str {
        &self.inner.ts_response
    }

    #[getter]
    fn nonce(&self) -> &str {
        &self.inner.nonce
    }

    #[getter]
    fn sig(&self) -> &str {
        &self.inner.sig
    }

    #[getter]
    fn extensions<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match &self.inner.extensions {
            Some(v) => Ok(Some(pythonize::pythonize(py, v)?)),
            None => Ok(None),
        }
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))
    }

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner: signet_core::BilateralReceipt = serde_json::from_str(json_str)
            .map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))?;
        Ok(PyBilateralReceipt { inner })
    }
}

// ─── register ─────────────────────────────────────────────────────────────────

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAction>()?;
    m.add_class::<PySigner>()?;
    m.add_class::<PyReceipt>()?;
    m.add_class::<PyResponse>()?;
    m.add_class::<PyCompoundReceipt>()?;
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyKeyInfo>()?;
    m.add_class::<PyAuditRecord>()?;
    m.add_class::<PyChainBreak>()?;
    m.add_class::<PyChainStatus>()?;
    m.add_class::<PyVerifyFailure>()?;
    m.add_class::<PyVerifyResult>()?;
    m.add_class::<PyServerInfo>()?;
    m.add_class::<PyBilateralReceipt>()?;
    Ok(())
}
