use ext_php_rs::prelude::*;
use gatekeeper::{disarm, sniff_format};

/// Sniff the format of a file payload without fully decoding it.
///
/// @param string $raw
/// @return string
#[php_function]
pub fn gatekeeper_sniff_format(raw: &[u8]) -> Result<String, String> {
    let format = sniff_format(raw).map_err(|e| e.to_string())?;

    // Lowercase, matching `detected_format` / `output_format` from `disarm`.
    Ok(format.as_str().to_string())
}

/// Disarm and reconstruct a file payload.
///
/// @param string $raw
/// @return string
#[php_function]
pub fn gatekeeper_disarm(raw: &[u8]) -> Result<Vec<u8>, String> {
    let clean = disarm(raw, None).map_err(|e| e.to_string())?;
    Ok(clean.buffer)
}

// Required to register the extension with PHP
#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
