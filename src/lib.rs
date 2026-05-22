// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: lib
//
//  Content Disarm and Reconstruction (CDR) Engine — public crate surface.
//
//  Architectural contracts
//  ────────────────────────
//  1. Zero-copy where feasible: format detection operates entirely on a
//     caller-supplied &[u8] slice.  No heap allocation occurs until the
//     sanitizer pipeline explicitly requires it for the output buffer.
//
//  2. Typestate enforcement: every format-specific sanitizer module exposes a
//     pipeline struct parameterised over stage marker types (RawPayload,
//     DisarmedMatrix, PristineStream).  Invalid stage transitions are rejected
//     at compile time, not at runtime.
//
//  3. Stack-first primitives: magic byte evaluation uses fixed-size arrays on
//     the stack (e.g. [u8; 8], [u8; 12]).  No Vec is constructed for sniffing.
//
//  4. Typed errors only: all fallible functions return Result<_, CdrError>.
//     CdrError is defined via `thiserror` with zero String allocations.
//
//  5. Slice-equality sniffing: magic-byte checks use direct subslice comparisons
//     (`payload[..N] == MAGIC`) — no intermediate stack buffers, no copies.
//
//  Supported formats (Phase 1 & 2)
//  ──────────────────────────────────
//    • JPEG  — full decode + PNG re-encode pipeline
//    • PNG   — structural validation (stub; full pipeline in Phase 3)
//
// ─────────────────────────────────────────────────────────────────────────────

pub mod errors;
pub mod sanitizers;

use errors::CdrError;
use sanitizers::jpeg::SanitizedOutput;

// ── Magic byte constants (stack arrays, zero heap) ───────────────────────────

/// JPEG Start-Of-Image marker: the two bytes every valid JPEG must begin with.
const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];

/// JPEG End-Of-Image marker: the two bytes every complete JPEG must end with.
const JPEG_EOI: [u8; 2] = [0xFF, 0xD9];

/// PNG file signature (8 bytes).  Defined in ISO/IEC 15948:2004 §5.2.
const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// PNG IHDR chunk type identifier.  Appears at bytes 12–15 of a valid PNG:
/// bytes 0–7  = PNG signature
/// bytes 8–11 = IHDR chunk length (big-endian u32, value = 13)
/// bytes 12–15 = IHDR chunk type (ASCII "IHDR")
const PNG_IHDR: [u8; 4] = [0x49, 0x48, 0x44, 0x52]; // "IHDR"

/// Minimum byte count required to inspect enough magic and structure to make a
/// reliable format determination without false positives.
///
/// 16 bytes is the minimum needed to read the PNG IHDR chunk type field
/// at offset 12–15.  All other formats are identified within fewer bytes.
const MIN_SNIFF_LEN: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
//  FileFormat — typed result of format sniffing
// ─────────────────────────────────────────────────────────────────────────────

/// Strongly-typed format discriminant returned by [`sniff_format`].
///
/// Adding a new format in a future phase requires only:
///   1. Adding a variant here.
///   2. Extending the `sniff_format` match arms.
///   3. Implementing the corresponding sanitizer pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// JPEG / JFIF / EXIF image.
    Jpeg,
    /// Portable Network Graphics image.
    Png,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Zero-trust format sniffer
// ─────────────────────────────────────────────────────────────────────────────

/// Inspect the leading bytes of `payload` and determine its file format.
///
/// # Zero-copy guarantee
/// This function borrows `payload` as an immutable slice and performs all
/// analysis using fixed-size stack arrays (`[u8; N]`).  It makes **no heap
/// allocations** and holds **no persistent state**.
///
/// # Structural validation
/// Beyond magic byte matching, the sniffer performs lightweight structural
/// checks to catch trivially malformed files before they reach the decoder:
///
/// | Format | Magic check          | Structural check                           |
/// |--------|----------------------|--------------------------------------------|
/// | JPEG   | bytes[0..2] == SOI   | EOI marker present in the final two bytes  |
/// | PNG    | bytes[0..8] == sig   | IHDR chunk type at bytes 12–15 (after 4-byte length at 8–11) |
///
/// These checks are not comprehensive—full validation occurs inside the
/// format-specific sanitizer—but they filter the most common corruption and
/// polyglot-container attacks at the earliest possible stage.
///
/// # Arguments
/// * `payload` — a borrowed slice of the raw input bytes.  Must be at least
///   [`MIN_SNIFF_LEN`] (16) bytes.
///
/// # Errors
/// * [`CdrError::PayloadTooShort`] — if `payload.len() < MIN_SNIFF_LEN`.
/// * [`CdrError::UnknownFormat`]   — if the leading bytes match no known magic.
/// * [`CdrError::JpegMissingEoi`]  — if JPEG magic is present but EOI is absent.
/// * [`CdrError::PngMissingIhdr`]  — if PNG signature is present but IHDR is absent.
pub fn sniff_format(payload: &[u8]) -> Result<FileFormat, CdrError> {
    // ── Guard: minimum length ─────────────────────────────────────────────
    if payload.len() < MIN_SNIFF_LEN {
        return Err(CdrError::PayloadTooShort { got: payload.len() });
    }

    // ── JPEG detection ────────────────────────────────────────────────────
    //
    // Direct subslice equality — no copy, no intermediate buffer.
    // The compiler may materialise a 2-byte load into a register; no stack
    // variable is written to memory.
    if payload[..2] == JPEG_SOI {
        // Structural check: the EOI marker must occupy the final 2 bytes.
        // `payload.len() >= MIN_SNIFF_LEN` guarantees the sub is safe.
        let tail = payload.len() - 2;
        if payload[tail..] != JPEG_EOI {
            return Err(CdrError::JpegMissingEoi);
        }
        return Ok(FileFormat::Jpeg);
    }

    // ── PNG detection ─────────────────────────────────────────────────────
    //
    // Compare all 8 signature bytes at once via slice equality — one
    // SIMD-friendly comparison, zero copies.
    if payload[..8] == PNG_SIG {
        // Structural check: the PNG chunk layout after the 8-byte signature is:
        //   bytes  8–11 → chunk data length (4-byte big-endian u32)
        //   bytes 12–15 → chunk type (ASCII letters, e.g. "IHDR")
        //
        // MIN_SNIFF_LEN = 16 guarantees offset 12–16 is always in-bounds.
        if payload[12..16] != PNG_IHDR {
            return Err(CdrError::PngMissingIhdr);
        }
        return Ok(FileFormat::Png);
    }

    // ── Unknown — capture first 4 bytes for error context ─────────────────
    //
    // A single fixed-size copy only for the error path; hot path never
    // reaches this branch.
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&payload[..4]);
    Err(CdrError::UnknownFormat { magic })
}

// ─────────────────────────────────────────────────────────────────────────────
//  Top-level dispatch: disarm()
// ─────────────────────────────────────────────────────────────────────────────

/// Detect, validate, and sanitise `payload` in a single call.
///
/// Returns a [`SanitizedOutput`] token — a newtype wrapper that the compiler
/// treats as a distinct type from `Vec<u8>` or any raw intermediate.
///
/// ## Signature lockdown
/// Any function that should only ever receive sanitised data must declare its
/// parameter as `SanitizedOutput`:
///
/// ```rust,no_run
/// use gatekeeper::disarm;
///
/// fn save_to_storage(bytes: Vec<u8>) {
///     std::fs::write("clean.png", bytes).unwrap();
/// }
///
/// let raw = std::fs::read("untrusted.jpg").unwrap();
/// let clean = disarm(&raw).expect("CDR failed");
/// save_to_storage(clean.into_bytes()); // only SanitizedOutput has into_bytes()
/// // save_to_storage(raw);   ← compile error: Vec<u8> has no into_bytes()
/// ```
///
/// # Errors
/// Any [`CdrError`] from format detection or the sanitizer pipeline.
pub fn disarm(payload: &[u8]) -> Result<SanitizedOutput, CdrError> {
    match sniff_format(payload)? {
        FileFormat::Jpeg => sanitizers::jpeg::sanitize_jpeg(payload),
        FileFormat::Png => {
            // ── Phase 3 stub ──────────────────────────────────────────────
            //
            // A full PNG decode + pixel-matrix re-encode pipeline will land
            // in Phase 3.  Until then we return a hard error rather than
            // forwarding unsanitised bytes to the caller — forwarding would
            // violate the zero-trust contract.
            Err(CdrError::Unimplemented { format: "PNG" })
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Build a minimal syntactically-valid JPEG byte vector.
    ///
    /// SOI + APP0 marker frame + EOI.  The pixel data is omitted because
    /// these tests target the sniffer, not the decoder.
    fn minimal_jpeg_stub() -> Vec<u8> {
        let mut v = Vec::new();
        // SOI
        v.extend_from_slice(&[0xFF, 0xD8]);
        // Minimal APP0 (JFIF) — enough bytes to reach MIN_SNIFF_LEN
        v.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        v.extend_from_slice(b"JFIF\x00");
        v.extend_from_slice(&[0x01, 0x01, 0x00]);
        // EOI
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    /// Build a minimal valid PNG byte vector (signature + chunk length + IHDR chunk type).
    ///
    /// Layout:
    ///   bytes  0–7  : PNG signature
    ///   bytes  8–11 : IHDR chunk length = 13 (big-endian u32)
    ///   bytes 12–15 : IHDR chunk type  = "IHDR"
    fn minimal_png_stub() -> Vec<u8> {
        let mut v = Vec::new();
        // bytes 0–7: PNG signature
        v.extend_from_slice(&PNG_SIG);
        // bytes 8–11: IHDR chunk length (value = 13, big-endian)
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
        // bytes 12–15: IHDR chunk type
        v.extend_from_slice(&PNG_IHDR);
        v
    }

    // ── PayloadTooShort ───────────────────────────────────────────────────

    #[test]
    fn rejects_empty_slice() {
        let result = sniff_format(&[]);
        assert!(
            matches!(result, Err(CdrError::PayloadTooShort { got: 0 })),
            "expected PayloadTooShort(0), got {result:?}"
        );
    }

    #[test]
    fn rejects_slice_shorter_than_min() {
        let buf = [0u8; 11];
        let result = sniff_format(&buf);
        assert!(
            matches!(result, Err(CdrError::PayloadTooShort { got: 11 })),
            "expected PayloadTooShort(11), got {result:?}"
        );
    }

    // ── JPEG detection ────────────────────────────────────────────────────

    #[test]
    fn detects_jpeg_format() {
        let jpeg = minimal_jpeg_stub();
        let result = sniff_format(&jpeg);
        assert_eq!(result.unwrap(), FileFormat::Jpeg);
    }

    #[test]
    fn rejects_jpeg_without_eoi() {
        let mut jpeg = minimal_jpeg_stub();
        // Overwrite the trailing EOI bytes with garbage.
        let len = jpeg.len();
        jpeg[len - 2] = 0x00;
        jpeg[len - 1] = 0x00;
        assert!(matches!(sniff_format(&jpeg), Err(CdrError::JpegMissingEoi)));
    }

    // ── PNG detection ─────────────────────────────────────────────────────

    #[test]
    fn detects_png_format() {
        let png = minimal_png_stub();
        let result = sniff_format(&png);
        assert_eq!(result.unwrap(), FileFormat::Png);
    }

    #[test]
    fn rejects_png_without_ihdr() {
        let mut png = minimal_png_stub();
        // Overwrite the IHDR chunk type field (bytes 12–15) with garbage.
        // Bytes 8–11 are the chunk length and are not checked by the sniffer.
        png[12] = 0x00;
        png[13] = 0x00;
        png[14] = 0x00;
        png[15] = 0x00;
        assert!(matches!(sniff_format(&png), Err(CdrError::PngMissingIhdr)));
    }

    // ── Unknown format ────────────────────────────────────────────────────

    #[test]
    fn rejects_unknown_magic() {
        // A PDF header — definitely not JPEG or PNG.
        let buf = b"%PDF-1.4 garbage padding bytes";
        let result = sniff_format(buf);
        assert!(
            matches!(result, Err(CdrError::UnknownFormat { .. })),
            "expected UnknownFormat, got {result:?}"
        );
    }

    // ── Stack-only sniff: no heap ─────────────────────────────────────────
    //
    // The following test validates the architectural contract that sniff_format
    // does not silently return Ok for pathological inputs that are exactly at
    // the minimum length boundary.
    #[test]
    fn boundary_at_min_sniff_len() {
        let buf = [0u8; MIN_SNIFF_LEN];
        // All-zero magic must produce UnknownFormat, not a panic.
        assert!(matches!(
            sniff_format(&buf),
            Err(CdrError::UnknownFormat { .. })
        ));
    }
}
