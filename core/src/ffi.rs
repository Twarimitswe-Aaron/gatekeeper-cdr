#![allow(clippy::not_unsafe_ptr_arg_deref)]
use crate::errors::CdrError;
use crate::{disarm, sniff_format};
use std::slice;

/// Transfer ownership of a `Vec<u8>` to C as a raw `(ptr, len)` pair.
///
/// The buffer is converted to a `Box<[u8]>` first so its backing allocation is
/// exactly `len` bytes.  This is the invariant that makes the paired free in
/// [`gatekeeper_free_result`] sound: reconstructing the boxed slice from
/// `(ptr, len)` deallocates with the correct `Layout`.
///
/// An empty buffer returns a null pointer (and length 0), which the free path
/// treats as "nothing to release".
fn into_raw_bytes(vec: Vec<u8>) -> (*mut u8, usize) {
    if vec.is_empty() {
        return (std::ptr::null_mut(), 0);
    }
    let boxed: Box<[u8]> = vec.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    (ptr, len)
}

/// Inverse of [`into_raw_bytes`]: reclaim and drop a buffer previously handed
/// to C.  Safe to call with a null pointer (no-op).
///
/// # Safety
/// `ptr` must either be null or have come from [`into_raw_bytes`] with the same
/// `len`, and must not have been freed already.
unsafe fn drop_raw_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // Reconstruct the exact `Box<[u8]>` allocation and let it drop.
    let slice_ptr = std::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(unsafe { Box::from_raw(slice_ptr) });
}

#[repr(C)]
pub struct CdrResult {
    pub ok: bool,
    pub data: *mut u8,
    pub len: usize,
    pub png_data: *mut u8,
    pub png_len: usize,
    pub output_format: [u8; 16], // inline string for format
    pub error_code: i32,
}

impl CdrResult {
    fn error(code: i32) -> Self {
        CdrResult {
            ok: false,
            data: std::ptr::null_mut(),
            len: 0,
            png_data: std::ptr::null_mut(),
            png_len: 0,
            output_format: [0; 16],
            error_code: code,
        }
    }

    fn success(vec: Vec<u8>, png_opt: Option<Vec<u8>>, format: &str) -> Self {
        // SAFETY/CORRECTNESS: we hand ownership to C via `Box<[u8]>::into_raw`,
        // NOT `Vec::as_mut_ptr` + `mem::forget`.  The previous approach called
        // `shrink_to_fit()` and then reconstructed the Vec with `capacity ==
        // len`, but `shrink_to_fit` is best-effort: the allocator may keep
        // excess capacity, so freeing with `capacity == len` deallocated with
        // the wrong `Layout` → undefined behaviour / heap corruption.
        //
        // A boxed slice has an allocation whose size is EXACTLY its length, so
        // the matching free in `gatekeeper_free_result` (reconstructing the
        // boxed slice from `(ptr, len)`) is always sound.
        let (data, len) = into_raw_bytes(vec);

        let (png_data, png_len) = match png_opt {
            Some(pvec) => into_raw_bytes(pvec),
            None => (std::ptr::null_mut(), 0),
        };

        let mut output_format = [0u8; 16];
        let bytes_to_copy = std::cmp::min(format.len(), 15);
        output_format[..bytes_to_copy].copy_from_slice(&format.as_bytes()[..bytes_to_copy]);
        output_format[bytes_to_copy] = 0; // null terminator

        CdrResult {
            ok: true,
            data,
            len,
            png_data,
            png_len,
            output_format,
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

    // Trap any decoder panic so a crafted file cannot abort the FFI host.
    let sniffed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sniff_format(payload)));

    match sniffed {
        Ok(Ok(format)) => {
            // Lowercase names, matching `FileFormat::as_str` and the
            // `detected_format` / `output_format` fields returned by disarm —
            // keeping a single, consistent vocabulary across the whole ABI.
            let format_str = format.as_str().as_bytes();

            let bytes_to_copy = std::cmp::min(format_str.len(), out_len - 1); // -1 for null terminator
            let out_slice = unsafe { slice::from_raw_parts_mut(out_fmt, out_len) };

            out_slice[..bytes_to_copy].copy_from_slice(&format_str[..bytes_to_copy]);
            out_slice[bytes_to_copy] = 0; // null terminator

            0
        }
        Ok(Err(e)) => e.code(),
        Err(_) => CdrError::SanitizerPanicked { format: "sniff" }.code(),
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

    // `disarm` already traps sanitizer panics internally, but we add a belt-and
    // -braces guard so even a panic in the success/marshalling path cannot
    // unwind across the `extern "C"` boundary (which would be UB).
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| disarm(payload, None)));

    match outcome {
        Ok(Ok(clean)) => CdrResult::success(clean.buffer, clean.png_buffer, clean.output_format),
        Ok(Err(e)) => CdrResult::error(e.code()),
        Err(_) => CdrResult::error(CdrError::SanitizerPanicked { format: "ffi" }.code()),
    }
}

/// Free a `CdrResult` returned by `gatekeeper_disarm`.
///
/// It is safe to call this on an error result (where `data` is null).
#[unsafe(no_mangle)]
pub extern "C" fn gatekeeper_free_result(result: CdrResult) {
    if result.ok {
        unsafe {
            drop_raw_bytes(result.data, result.len);
            drop_raw_bytes(result.png_data, result.png_len);
        }
    }
}
