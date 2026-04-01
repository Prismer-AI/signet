use pyo3::prelude::*;

mod audit_fns;
mod core_fns;
mod errors;
mod identity_fns;
mod types;

#[pymodule]
fn _signet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    errors::register(m)?;
    types::register(m)?;
    core_fns::register(m)?;
    identity_fns::register(m)?;
    audit_fns::register(m)?;
    Ok(())
}
