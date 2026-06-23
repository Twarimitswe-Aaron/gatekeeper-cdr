use ext_php_rs::prelude::*;
use gatekeeper::{disarm, sniff_format, FileFormat};

/// Sniff the format of a file payload without fully decoding it.
///
/// @param string $raw
/// @return string
#[php_function]
pub fn gatekeeper_sniff_format(raw: &[u8]) -> Result<String, String> {
    let format = sniff_format(raw).map_err(|e| e.to_string())?;
    
    let format_str = match format {
        FileFormat::Jpeg => "Jpeg",
        FileFormat::Png => "Png",
        FileFormat::Gif => "Gif",
        FileFormat::Webp => "Webp",
        FileFormat::Office => "Office",
        FileFormat::Pdf => "Pdf",
    };
    
    Ok(format_str.to_string())
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
