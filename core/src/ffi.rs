use crate::{disarm, sniff_format, FileFormat};
use std::slice;

#[repr(C)]
pub struct CdrResult {
    pub ok: bool,
    pub data: *mut u8,
    pub len: usize,
    pub error_code: i32,
}

impl CdrResult {
    fn error(code: i32) -> Self {
        CdrResult {
            ok: false,
            data: std::ptr::null_mut(),
            len: 0,
            error_code: code,
        }
    }

    fn success(mut vec: Vec<u8>) -> Self {
        vec.shrink_to_fit();
        let len = vec.len();
        let data = vec.as_mut_ptr();
        std::mem::forget(vec);
        CdrResult {
            ok: true,
            data,
            len,
            error_code: 0,
        }
    }
}

/// Sniff the format of a file without fully decoding it.
///
/// Returns 0 on success, or a non-zero error code.
/// If successful, the format name (e.g. "Jpeg", "Png") is copied into `out_fmt`.
/// `out_len` specifies the maximum capacity of `out_fmt`.
#[unsafe(no_mangle)]
pub extern "C" fn gatekeeper_sniff_format(
    raw: *const u8,
    len: usize,
    out_fmt: *mut u8,
    out_len: usize,
) -> i32 {
    if raw.is_null() || len == 0 || out_fmt.is_null() || out_len == 0 {
        return 1; // Generic invalid argument error
    }

    let payload = unsafe { slice::from_raw_parts(raw, len) };

    match sniff_format(payload) {
        Ok(format) => {
            let format_str: &[u8] = match format {
                FileFormat::Jpeg => b"Jpeg",
                FileFormat::Png => b"Png",
                FileFormat::Gif => b"Gif",
                FileFormat::Webp => b"Webp",
                FileFormat::Office => b"Office",
                FileFormat::Pdf => b"Pdf",
            };

            let bytes_to_copy = std::cmp::min(format_str.len(), out_len - 1); // -1 for null terminator
            let out_slice = unsafe { slice::from_raw_parts_mut(out_fmt, out_len) };
            
            out_slice[..bytes_to_copy].copy_from_slice(&format_str[..bytes_to_copy]);
            out_slice[bytes_to_copy] = 0; // null terminator

            0
        }
        Err(_) => 2, // Could map specific errors if needed
    }
}

/// Disarm and reconstruct a file payload.
///
/// Returns a `CdrResult`. If `ok` is true, `data` points to the sanitized bytes.
/// The caller MUST pass the result to `gatekeeper_free_result` to avoid memory leaks.
#[unsafe(no_mangle)]
pub extern "C" fn gatekeeper_disarm(raw: *const u8, len: usize) -> CdrResult {
    if raw.is_null() || len == 0 {
        return CdrResult::error(1); // Invalid argument
    }

    let payload = unsafe { slice::from_raw_parts(raw, len) };

    match disarm(payload, None) {
        Ok(clean) => CdrResult::success(clean.buffer),
        Err(_) => CdrResult::error(2), // Could map specific errors to distinct codes
    }
}

/// Free a `CdrResult` returned by `gatekeeper_disarm`.
///
/// It is safe to call this on an error result (where `data` is null).
#[unsafe(no_mangle)]
pub extern "C" fn gatekeeper_free_result(result: CdrResult) {
    if result.ok && !result.data.is_null() && result.len > 0 {
        unsafe {
            // Retake ownership of the vector to drop it properly
            let _ = Vec::from_raw_parts(result.data, result.len, result.len);
        }
    }
}
