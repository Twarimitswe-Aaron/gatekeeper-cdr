#![allow(unexpected_cfgs)]
#![allow(unsafe_op_in_unsafe_fn)]

use gatekeeper::{disarm as core_disarm, sniff_format as core_sniff_format};
use gatekeeper::async_stream::disarm_bytes_async;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

create_exception!(gatekeeper_cdr, GatekeeperError, PyException);

#[pyclass]
pub struct DisarmResult {
    #[pyo3(get)]
    pub buffer: Py<PyBytes>,
    #[pyo3(get)]
    pub png_buffer: Option<Py<PyBytes>>,
    #[pyo3(get)]
    pub original_size_bytes: usize,
    #[pyo3(get)]
    pub final_size_bytes: usize,
    #[pyo3(get)]
    pub detected_format: String,
    #[pyo3(get)]
    pub output_format: String,
}

/// Detect the format of an image/file payload without fully decoding it.
///
/// Returns the detected format as a string ('Jpeg', 'Png', 'Gif', 'Webp', 'Pdf', 'Office').
/// Raises `GatekeeperError` if the format is unknown or the payload is invalid.
#[pyfunction]
#[pyo3(signature = (payload, /))]
fn sniff_format<'py>(py: Python<'py>, payload: &[u8]) -> PyResult<Bound<'py, PyString>> {
    let format = core_sniff_format(payload)
        .map_err(|e| GatekeeperError::new_err(e.to_string()))?;

    // Lowercase, matching `detected_format` / `output_format` returned by
    // `disarm` so callers see one consistent vocabulary everywhere.
    Ok(PyString::new_bound(py, format.as_str()))
}

/// Disarm and reconstruct a file payload, stripping all metadata and potential exploits.
///
/// Accepts `bytes` and returns a `DisarmResult` object.
/// Raises `GatekeeperError` if the payload is invalid, corrupt, or exceeds limits.
#[pyfunction]
#[pyo3(signature = (payload, /))]
fn disarm<'py>(py: Python<'py>, payload: &[u8]) -> PyResult<DisarmResult> {
    let clean = core_disarm(payload, None)
        .map_err(|e| GatekeeperError::new_err(e.to_string()))?;
        
    let buffer = PyBytes::new_bound(py, &clean.buffer).unbind();
    let png_buffer = clean.png_buffer.as_ref().map(|b| PyBytes::new_bound(py, b).unbind());

    Ok(DisarmResult {
        buffer,
        png_buffer,
        original_size_bytes: clean.original_size_bytes,
        final_size_bytes: clean.final_size_bytes,
        detected_format: clean.detected_format.to_string(),
        output_format: clean.output_format.to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
//  disarm_async — native Python coroutine via PyO3 allow_threads
// ─────────────────────────────────────────────────────────────────────────────

/// Async, non-blocking Content Disarm and Reconstruction pipeline.
///
/// Returns a Python `bytes` coroutine that can be awaited in any
/// asyncio-based framework (FastAPI, aiohttp, Starlette, etc.).
///
/// The heavy Rust work runs on a dedicated tokio worker thread so the Python
/// event loop is never blocked.
///
/// ## Usage
///
/// ```python
/// import asyncio
/// import gatekeeper_cdr
///
/// async def sanitize(data: bytes):
///     result = await gatekeeper_cdr.disarm_async(data)
///     return result.buffer
/// ```
///
/// Raises `GatekeeperError` on sanitisation failure.
#[pyfunction]
#[pyo3(signature = (payload, /))]
fn disarm_async<'py>(py: Python<'py>, payload: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let data = payload.to_vec();

    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let result = disarm_bytes_async(&data)
            .await
            .map_err(|e| GatekeeperError::new_err(e.to_string()))?;

        // Re-acquire the GIL to build the Python object.
        Python::with_gil(|py| {
            let buffer = PyBytes::new_bound(py, &result.buffer).unbind();
            let png_buffer = result.png_buffer.as_ref().map(|b| PyBytes::new_bound(py, b).unbind());

            let py_res = DisarmResult {
                buffer,
                png_buffer,
                original_size_bytes: result.original_size_bytes,
                final_size_bytes: result.final_size_bytes,
                detected_format: result.detected_format.to_string(),
                output_format: result.output_format.to_string(),
            };
            
            Ok(py_res.into_py(py))
        })
    })
}

/// A zero-trust Content Disarm and Reconstruction (CDR) engine.
#[pymodule]
fn gatekeeper_cdr(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("GatekeeperError", m.py().get_type_bound::<GatekeeperError>())?;
    m.add_class::<DisarmResult>()?;
    m.add_function(wrap_pyfunction!(sniff_format, m)?)?;
    m.add_function(wrap_pyfunction!(disarm, m)?)?;
    m.add_function(wrap_pyfunction!(disarm_async, m)?)?;
    Ok(())
}
