#![allow(unexpected_cfgs)]
#![allow(unsafe_op_in_unsafe_fn)]

use gatekeeper::{disarm as core_disarm, sniff_format as core_sniff_format, FileFormat};
use gatekeeper::async_stream::disarm_bytes_async;
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
/// async def sanitize(data: bytes) -> bytes:
///     return await gatekeeper_cdr.disarm_async(data)
///
/// # With FastAPI:
/// from fastapi import FastAPI, UploadFile
/// app = FastAPI()
///
/// @app.post("/sanitize")
/// async def upload(file: UploadFile):
///     raw = await file.read()
///     clean = await gatekeeper_cdr.disarm_async(raw)
///     return Response(content=clean, media_type="application/octet-stream")
/// ```
///
/// Raises `GatekeeperError` on sanitisation failure.
#[pyfunction]
#[pyo3(signature = (payload, /))]
fn disarm_async<'py>(py: Python<'py>, payload: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    // Copy the bytes so the async task owns them independently of the
    // Python frame lifetime.  This is a single allocation on the hot path.
    let data = payload.to_vec();

    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let result = disarm_bytes_async(&data)
            .await
            .map_err(|e| GatekeeperError::new_err(e.to_string()))?;

        // Re-acquire the GIL to build the Python bytes object.
        Python::with_gil(|py| {
            Ok(PyBytes::new_bound(py, &result.buffer).into_any().unbind())
        })
    })
}

/// A zero-trust Content Disarm and Reconstruction (CDR) engine.
#[pymodule]
fn gatekeeper_cdr(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("GatekeeperError", m.py().get_type_bound::<GatekeeperError>())?;
    m.add_function(wrap_pyfunction!(sniff_format, m)?)?;
    m.add_function(wrap_pyfunction!(disarm, m)?)?;
    m.add_function(wrap_pyfunction!(disarm_async, m)?)?;
    Ok(())
}
