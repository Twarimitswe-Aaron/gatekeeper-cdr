#![deny(clippy::all)]

use napi_derive::napi;
use napi::bindgen_prelude::*;
use napi::Error as NapiError;
use napi::Status;
use gatekeeper::{disarm as core_disarm};

#[napi(object)]
pub struct NodeDisarmResult {
    /// The mathematically safe, reconstructed byte stream, returned as a Node.js Buffer.
    pub buffer: Buffer,
    pub original_size_bytes: u32,
    pub final_size_bytes: u32,
    pub detected_format: String,
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
                original_size_bytes: result.original_size_bytes as u32,
                final_size_bytes: result.final_size_bytes as u32,
                detected_format: result.detected_format.to_string(),
            })
        }
        Err(e) => {
            // Translate the structured gatekeeper::errors::CdrError into a generic JS Error
            // so standard try/catch blocks work perfectly on the consumer end.
            Err(NapiError::new(Status::GenericFailure, e.to_string()))
        }
    }
}
