#![deny(clippy::all)]

use napi_derive::napi;
use napi::bindgen_prelude::*;
use napi::Error as NapiError;
use napi::Status;
use napi::Task;
use gatekeeper::{disarm as core_disarm};
use gatekeeper::async_stream::disarm_bytes_async;

#[napi(object)]
pub struct NodeDisarmResult {
    /// The mathematically safe, reconstructed byte stream, returned as a Node.js Buffer.
    pub buffer: Buffer,
    pub png_buffer: Option<Buffer>,
    pub original_size_bytes: u32,
    pub final_size_bytes: u32,
    pub detected_format: String,
    pub output_format: String,
}

/// Zero-trust Content Disarm and Reconstruction pipeline.
/// Safely processes untrusted bytes and guarantees output is mathematically safe.
///
/// @param rawBuffer The untrusted file buffer
/// @param expectedFormat (Optional) Strict format hint (e.g. "pdf", "png"). Rejects if mismatch.
#[napi]
pub fn disarm(raw_buffer: &[u8], expected_format: Option<String>) -> Result<NodeDisarmResult> {
    // Convert Option<String> to Option<&str>
    let expected = expected_format.as_deref();

    // Call the core Rust engine
    match core_disarm(raw_buffer, expected) {
        Ok(result) => {
            Ok(NodeDisarmResult {
                // Convert the Rust Vec<u8> into a Node.js Buffer with zero-copy
                buffer: Buffer::from(result.buffer),
                png_buffer: result.png_buffer.map(Buffer::from),
                original_size_bytes: result.original_size_bytes as u32,
                final_size_bytes: result.final_size_bytes as u32,
                detected_format: result.detected_format.to_string(),
                output_format: result.output_format.to_string(),
            })
        }
        Err(e) => {
            // Translate the structured gatekeeper::errors::CdrError into a generic JS Error
            // so standard try/catch blocks work perfectly on the consumer end.
            Err(NapiError::new(Status::GenericFailure, e.to_string()))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  AsyncDisarmTask — bridges tokio futures into the libuv thread pool
// ─────────────────────────────────────────────────────────────────────────────

/// Owned payload carrier for the async task.
///
/// `Task` in NAPI-RS requires `Send + 'static`, so we cannot hold a borrowed
/// `&[u8]`. We copy the input bytes once here so the task is independent of
/// the calling JS frame's lifetime.
pub struct AsyncDisarmTask {
    data: Vec<u8>,
}

impl Task for AsyncDisarmTask {
    type Output = NodeDisarmResult;
    type JsValue = NodeDisarmResult;

    /// Runs on a libuv worker thread — never blocks the V8 event loop.
    fn compute(&mut self) -> Result<Self::Output> {
        // Build a single-threaded tokio runtime for the blocking thread.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| NapiError::new(Status::GenericFailure, e.to_string()))?;

        let result = rt
            .block_on(disarm_bytes_async(&self.data))
            .map_err(|e| NapiError::new(Status::GenericFailure, e.to_string()))?;

        Ok(NodeDisarmResult {
            buffer: Buffer::from(result.buffer),
            png_buffer: result.png_buffer.map(Buffer::from),
            original_size_bytes: result.original_size_bytes as u32,
            final_size_bytes: result.final_size_bytes as u32,
            detected_format: result.detected_format.to_string(),
            output_format: result.output_format.to_string(),
        })
    }

    fn resolve(&mut self, _env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Async, non-blocking Content Disarm and Reconstruction pipeline.
///
/// Returns a `Promise<NodeDisarmResult>` that resolves on a background
/// thread pool, leaving the Node.js event loop completely free.
///
/// @example
/// ```js
/// const { disarmAsync } = require('gatekeeper-cdr');
/// const fs = require('fs');
///
/// async function sanitize(path) {
///   const input = fs.readFileSync(path);
///   const result = await disarmAsync(input);
///   return result.buffer; // clean, safe bytes
/// }
/// ```
#[napi]
pub fn disarm_async(raw_buffer: Buffer) -> AsyncTask<AsyncDisarmTask> {
    AsyncTask::new(AsyncDisarmTask {
        data: raw_buffer.to_vec(),
    })
}
