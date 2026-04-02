use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::path::Path;

use crate::errors::to_py_err;
use crate::types::PyKeyInfo;

#[pyfunction]
fn validate_key_name(name: &str) -> PyResult<()> {
    signet_core::validate_key_name(name).map_err(to_py_err)
}

#[pyfunction]
fn default_signet_dir() -> String {
    signet_core::default_signet_dir()
        .to_string_lossy()
        .into_owned()
}

#[pyfunction]
#[pyo3(signature = (dir, name, owner=None, passphrase=None))]
fn generate_and_save(
    py: Python<'_>,
    dir: String,
    name: String,
    owner: Option<String>,
    passphrase: Option<String>,
) -> PyResult<PyKeyInfo> {
    let dir_c = dir.clone();
    let name_c = name.clone();
    let owner_c = owner.clone();
    let passphrase_c = passphrase.clone();

    let info = py
        .allow_threads(move || {
            signet_core::generate_and_save(
                Path::new(&dir_c),
                &name_c,
                owner_c.as_deref(),
                passphrase_c.as_deref(),
                None,
            )
        })
        .map_err(to_py_err)?;

    Ok(PyKeyInfo::from(info))
}

#[pyfunction]
#[pyo3(signature = (dir, name, passphrase=None))]
fn load_signing_key(
    py: Python<'_>,
    dir: String,
    name: String,
    passphrase: Option<String>,
) -> PyResult<String> {
    let dir_c = dir.clone();
    let name_c = name.clone();
    let passphrase_c = passphrase.clone();

    let signing_key = py
        .allow_threads(move || {
            signet_core::load_signing_key(Path::new(&dir_c), &name_c, passphrase_c.as_deref())
        })
        .map_err(to_py_err)?;

    Ok(B64.encode(signing_key.to_keypair_bytes()))
}

#[pyfunction]
fn load_verifying_key(py: Python<'_>, dir: String, name: String) -> PyResult<String> {
    let dir_c = dir.clone();
    let name_c = name.clone();

    let verifying_key = py
        .allow_threads(move || {
            signet_core::load_verifying_key(Path::new(&dir_c), &name_c)
        })
        .map_err(to_py_err)?;

    Ok(B64.encode(verifying_key.as_bytes()))
}

#[pyfunction]
fn load_key_info(py: Python<'_>, dir: String, name: String) -> PyResult<PyKeyInfo> {
    let dir_c = dir.clone();
    let name_c = name.clone();

    let info = py
        .allow_threads(move || signet_core::load_key_info(Path::new(&dir_c), &name_c))
        .map_err(to_py_err)?;

    Ok(PyKeyInfo::from(info))
}

#[pyfunction]
fn list_keys(py: Python<'_>, dir: String) -> PyResult<Vec<PyKeyInfo>> {
    let dir_c = dir.clone();

    let keys = py
        .allow_threads(move || signet_core::list_keys(Path::new(&dir_c)))
        .map_err(to_py_err)?;

    Ok(keys.into_iter().map(PyKeyInfo::from).collect())
}

#[pyfunction]
fn export_public_key(py: Python<'_>, dir: String, name: String) -> PyResult<PyObject> {
    let dir_c = dir.clone();
    let name_c = name.clone();

    let pub_file = py
        .allow_threads(move || signet_core::export_public_key(Path::new(&dir_c), &name_c))
        .map_err(to_py_err)?;

    let value: serde_json::Value =
        serde_json::to_value(&pub_file).map_err(|e| crate::errors::SerializeError::new_err(e.to_string()))?;

    let dict = PyDict::new(py);
    if let serde_json::Value::Object(map) = value {
        for (k, v) in map {
            let py_val = pythonize::pythonize(py, &v)?;
            dict.set_item(k, py_val)?;
        }
    }

    Ok(dict.into())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(validate_key_name, m)?)?;
    m.add_function(wrap_pyfunction!(default_signet_dir, m)?)?;
    m.add_function(wrap_pyfunction!(generate_and_save, m)?)?;
    m.add_function(wrap_pyfunction!(load_signing_key, m)?)?;
    m.add_function(wrap_pyfunction!(load_verifying_key, m)?)?;
    m.add_function(wrap_pyfunction!(load_key_info, m)?)?;
    m.add_function(wrap_pyfunction!(list_keys, m)?)?;
    m.add_function(wrap_pyfunction!(export_public_key, m)?)?;
    Ok(())
}
