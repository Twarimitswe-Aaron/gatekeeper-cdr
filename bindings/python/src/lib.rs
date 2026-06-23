use gatekeeper::{disarm as core_disarm, sniff_format as core_sniff_format, CdrError, FileFormat};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

create_exception!(gatekeeper_cdr, GatekeeperError, PyException);


/// Detect the format of an image/file payload without fully decoding it.
///
/// Returns the detected format as a string ('Jpeg', 'Png', 'Gif', 'Webp', 'Pdf', 'Office').
/// Raises `GatekeeperError` if the format is unknown or the payload is invalid.
#[pyfunction]
#[pyo3(signature = (payload, /))]
fn sniff_format<'py>(py: Python<'py>, payload: &[u8]) -> PyResult<Bound<'py, PyString>> {
    let format = core_sniff_format(payload)
        .map_err(|e| GatekeeperError::new_err(e.to_string()))?;
    
    let format_str = match format {
        FileFormat::Jpeg => "Jpeg",
        FileFormat::Png => "Png",
        FileFormat::Gif => "Gif",
        FileFormat::Webp => "Webp",
        FileFormat::Pdf => "Pdf",
        FileFormat::Office => "Office",
    };
    
    Ok(PyString::new_bound(py, format_str))
}

/// Disarm and reconstruct a file payload, stripping all metadata and potential exploits.
///
/// Accepts `bytes` and returns `bytes` representing the sanitized file.
/// Raises `GatekeeperError` if the payload is invalid, corrupt, or exceeds limits.
#[pyfunction]
#[pyo3(signature = (payload, /))]
fn disarm<'py>(py: Python<'py>, payload: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let clean = core_disarm(payload, None)
        .map_err(|e| GatekeeperError::new_err(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &clean.buffer))
}

/// A zero-trust Content Disarm and Reconstruction (CDR) engine.
#[pymodule]
fn gatekeeper_cdr(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("GatekeeperError", m.py().get_type_bound::<GatekeeperError>())?;
    m.add_function(wrap_pyfunction!(sniff_format, m)?)?;
    m.add_function(wrap_pyfunction!(disarm, m)?)?;
    Ok(())
}
