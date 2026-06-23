//! # Gatekeeper CDR Engine
//!
//! A **zero-trust Content Disarm and Reconstruction (CDR) engine** for
//! multi-format file sanitisation.  Gatekeeper accepts an untrusted byte
//! slice, fully decodes it to raw pixel data, and re-encodes a clean output
//! that shares **zero bytes** with the original — stripping all metadata,
//! steganographic payloads, and polyglot-container trailing bytes.
//!
//! ## Architectural contracts
//!
//! 1. **Zero-copy parsing** — format detection operates entirely on the
//!    caller's `&[u8]` slice via direct subslice equality.
//!    No intermediate buffers, no `Vec`, no heap allocation in the sniffer.
//!
//! 2. **Newtype typestate pipeline** — every sanitiser module defines its
//!    stages as newtype tuple structs (e.g. `RawPayload<'a>(&'a [u8])`).
//!    Inner data is accessible only via formal destructuring; stage
//!    transitions are **consuming methods** — calling them out of order is
//!    a *compile error*, not a runtime panic.
//!
//! 3. **Nominal output token** — the terminal pipeline stage yields
//!    [`SanitizedOutput`], a distinct public newtype.  Any save/persist
//!    function that requires a sanitised file **must** accept
//!    `SanitizedOutput`; passing a raw `Vec<u8>` is rejected by the compiler.
//!
//! 4. **Typed errors only** — all fallible functions return
//!    `Result<_, CdrError>`.  [`CdrError`] is defined via `thiserror` with
//!    zero `String` allocations in any variant.
//!
//! ## Supported formats
//!
//! | Format | Status |
//! |--------|--------|
//! | JPEG   | complete (decode → PNG re-encode) |
//! | PNG    | complete (decode → PNG re-encode) |
//! | GIF    | complete (decode first frame → PNG re-encode) |
//! | WebP   | complete (decode → PNG re-encode) |
//! | Office | complete (ZIP unwrap, `.bin` strip → ZIP re-encode) |
//! | PDF    | complete (Structural strip of Actions/JS → PDF re-encode) |
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use gatekeeper::disarm;
//!
//! let raw = std::fs::read("untrusted.jpg").unwrap();
//! let clean = disarm(&raw, None).expect("CDR failed");
//! std::fs::write("clean.png", clean.buffer).unwrap();
//! ```

pub mod errors;
pub mod ffi;
pub mod sanitizers;
pub mod sniffer;
pub mod stream;
pub mod async_stream;

// ── Public API facade ────────────────────────────────────────────────────────
// All items below are re-exported at the crate root so downstream consumers
// never need to reach into internal module paths.

/// Primary CDR error taxonomy — re-exported from [`errors`].
pub use errors::CdrError;

/// Top-level CDR entry point and format discriminant — re-exported from [`sniffer`].
pub use sniffer::{FileFormat, disarm, sniff_format};

/// Streaming, optional-payload wrapper — re-exported from [`stream`].
pub use stream::ImageStream;

/// Async streaming wrapper and convenience function — re-exported from [`async_stream`].
pub use async_stream::{AsyncImageStream, disarm_bytes_async};

/// Terminal sanitised-output token and its JPEG-pipeline alias.
pub use sanitizers::jpeg::{DisarmedPayload, SanitizedOutput, sanitize_jpeg};

/// Typestate pipeline entry point for JPEG inputs.
pub use sanitizers::jpeg::RawPayload;
/// Convenience free-function CDR entry point for PNG inputs.
pub use sanitizers::png::sanitize_png;

/// Typestate pipeline entry point for PNG inputs.
pub use sanitizers::png::RawPngPayload;

/// Convenience free-function CDR entry point for GIF inputs.
pub use sanitizers::gif::sanitize_gif;

/// Typestate pipeline entry point for GIF inputs.
pub use sanitizers::gif::RawGifPayload;

/// Convenience free-function CDR entry point for WebP inputs.
pub use sanitizers::webp::sanitize_webp;

/// Typestate pipeline entry point for WebP inputs.
pub use sanitizers::webp::RawWebpPayload;

/// Convenience free-function CDR entry point for Office inputs.
pub use sanitizers::office::sanitize_office;

/// Typestate pipeline entry point for Office inputs.
pub use sanitizers::office::RawOfficePayload;

/// Convenience free-function CDR entry point for PDF inputs.
pub use sanitizers::pdf::sanitize_pdf;

/// Typestate pipeline entry point for PDF inputs.
pub use sanitizers::pdf::RawPdfPayload;

// ─────────────────────────────────────────────────────────────────────────────
//  Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniffer::{JPEG_EOI, MIN_SNIFF_LEN, PNG_IHDR, PNG_SIG};

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
        v.extend_from_slice(&JPEG_EOI);
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
        // A generic random string — definitely not JPEG, PNG, GIF, WebP, Office, or PDF.
        let buf = b"UNKNOWN_MAGIC_BYTES_123";
        let result = sniff_format(buf);
        assert!(
            matches!(result, Err(CdrError::UnknownFormat { .. })),
            "expected UnknownFormat, got {result:?}"
        );
    }

    #[test]
    fn rejects_format_mismatch() {
        let png = minimal_png_stub();
        let result = sniffer::disarm(&png, Some("pdf"));
        assert!(
            matches!(result, Err(CdrError::FormatMismatch { .. })),
            "expected FormatMismatch, got {result:?}"
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

    // ── ImageStream ───────────────────────────────────────────────────────

    /// `ImageStream::empty()` must hit the `let…else` guard and return
    /// `PayloadTooShort { got: 0 }` without inspecting any bytes.
    #[test]
    fn image_stream_rejects_absent_payload() {
        let result = ImageStream::empty().route();
        assert!(
            matches!(result, Err(CdrError::PayloadTooShort { got: 0 })),
            "expected PayloadTooShort(0) for absent payload, got {result:?}"
        );
    }

    /// `ImageStream::new()` with a too-short slice must hit guard 2 and
    /// return `PayloadTooShort` with the actual length.
    #[test]
    fn image_stream_rejects_short_payload() {
        let buf = [0u8; 4]; // below MIN_SNIFF_LEN = 16
        let result = ImageStream::new(&buf).route();
        assert!(
            matches!(result, Err(CdrError::PayloadTooShort { got: 4 })),
            "expected PayloadTooShort(4), got {result:?}"
        );
    }

    /// A slice whose magic bytes match no known format must return
    /// `UnknownFormat` via the wildcard arm.
    #[test]
    fn image_stream_rejects_unknown_format() {
        let buf = b"%PDF-1.4 garbage padding bytes";
        let result = ImageStream::new(buf).route();
        assert!(
            matches!(result, Err(CdrError::UnknownFormat { .. })),
            "expected UnknownFormat, got {result:?}"
        );
    }

    /// A syntactically-valid JPEG stub must reach the JPEG pipeline arm and
    /// be dispatched correctly.  The sniffer stub doesn't carry real DCT
    /// data, so `JpegDecodeFailed` is the expected terminal error — but the
    /// routing itself succeeded (JPEG arm was chosen, not UnknownFormat).
    #[test]
    fn image_stream_routes_jpeg_to_pipeline() {
        let jpeg = minimal_jpeg_stub();
        let result = ImageStream::new(&jpeg).route();
        // The stub is not a real JPEG bitstream, so the decoder rejects it.
        // What we assert is that routing did NOT produce UnknownFormat or
        // Unimplemented — the JPEG arm was definitely selected.
        assert!(
            !matches!(result, Err(CdrError::UnknownFormat { .. })),
            "JPEG stub was mis-routed to UnknownFormat: {result:?}"
        );
        assert!(
            !matches!(result, Err(CdrError::Unimplemented { .. })),
            "JPEG stub was mis-routed to Unimplemented: {result:?}"
        );
    }

    /// A PNG stub passed to the sniff layer passes the structural check but the
    /// truncated fixture is rejected by the decoder.  We assert the error is
    /// NOT `UnknownFormat` or `Unimplemented` — routing reached the PNG arm.
    #[test]
    fn image_stream_routes_png_to_pipeline() {
        let png = minimal_png_stub();
        let result = ImageStream::new(&png).route();
        // minimal_png_stub is structurally valid (sig + IHDR) but has no IDAT,
        // so the decoder returns PngDecodeFailed — not Unimplemented or UnknownFormat.
        assert!(
            !matches!(result, Err(CdrError::UnknownFormat { .. })),
            "PNG stub was mis-routed to UnknownFormat: {result:?}"
        );
        assert!(
            !matches!(result, Err(CdrError::Unimplemented { .. })),
            "PNG pipeline is not yet wired: {result:?}"
        );
    }

    /// Build a real 1×1 red RGB PNG in memory using the `png` encoder,
    /// then run it through the full CDR pipeline.  The output must be an
    /// `Ok(SanitizedOutput)` whose bytes decode as a valid PNG.
    #[test]
    fn png_cdr_round_trip() {
        use png::{BitDepth, ColorType, Encoder};

        // ── Build a real 1×1 RGB PNG fixture ─────────────────────────────
        let mut fixture: Vec<u8> = Vec::new();
        {
            let mut enc = Encoder::new(&mut fixture, 1, 1);
            enc.set_color(ColorType::Rgb);
            enc.set_depth(BitDepth::Eight);
            let mut writer = enc.write_header().expect("encoder header");
            writer
                .write_image_data(&[0xFF, 0x00, 0x00])
                .expect("pixel write"); // red pixel
        }

        // ── Run the full CDR pipeline ─────────────────────────────────────
        let result = disarm(&fixture, None);
        assert!(result.is_ok(), "PNG CDR round-trip failed: {result:?}");

        // ── Verify the output is a valid PNG ──────────────────────────────
        let clean = result.unwrap().buffer;
        // Every valid PNG starts with the 8-byte signature.
        assert_eq!(
            &clean[..8],
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            "sanitized output does not begin with PNG signature"
        );
    }

    /// A PNG whose IHDR claims dimensions that exceed MAX_DIMENSION must be
    /// rejected with `DimensionTooLarge` before any pixel allocation occurs.
    ///
    /// ## Fixture construction
    /// We use `mem::forget` on the encoder writer to suppress IEND, then
    /// manually append a zero-length IDAT chunk.  This lets `read_info()`
    /// complete (it stops when it sees the IDAT chunk-type marker) so our
    /// geometry guard fires before `next_frame()` is ever called.
    ///
    /// CRC32 of the bare chunk-type bytes b"IDAT" = 0x35AF061E — a well-known
    /// PNG constant, precomputed offline.
    #[test]
    fn rejects_png_decompression_bomb() {
        use png::{BitDepth, ColorType, Encoder};

        let mut fixture: Vec<u8> = Vec::new();
        {
            let mut enc = Encoder::new(&mut fixture, 16_385, 16_385);
            enc.set_color(ColorType::Rgba);
            enc.set_depth(BitDepth::Eight);
            let writer = enc.write_header().expect("header write");
            // Suppress IEND: dropping `writer` would write it, preventing
            // our guards from being reached.
            std::mem::forget(writer);
        }
        // Append a minimal zero-length IDAT so `read_info()` can return
        // successfully with the geometry metadata.
        fixture.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // chunk length = 0
        fixture.extend_from_slice(b"IDAT"); // chunk type
        fixture.extend_from_slice(&[0x35, 0xAF, 0x06, 0x1E]); // CRC32(b"IDAT")

        let result = sanitize_png(&fixture);
        assert!(
            matches!(result, Err(CdrError::DimensionTooLarge { .. })),
            "expected DimensionTooLarge for 16385×16385 PNG, got {result:?}"
        );
    }

    /// A PNG at exactly MAX_DIMENSION (16 384 px) per axis with 4 RGBA
    /// channels = 16384 × 16384 × 4 = 1 GiB — exceeds MAX_PIXEL_BYTES
    /// (256 MiB).  Must be rejected with `ImageTooLarge`.
    ///
    /// 16384 ≤ MAX_DIMENSION so `DimensionTooLarge` must NOT fire;
    /// `ImageTooLarge` must fire at the budget check that follows.
    #[test]
    fn rejects_png_at_max_dimension_rgba() {
        use png::{BitDepth, ColorType, Encoder};

        let mut fixture: Vec<u8> = Vec::new();
        {
            let mut enc = Encoder::new(&mut fixture, 16_384, 16_384);
            enc.set_color(ColorType::Rgba); // 4 channels → 1 GiB pixel budget
            enc.set_depth(BitDepth::Eight);
            let writer = enc.write_header().expect("header write");
            std::mem::forget(writer); // suppress IEND
        }
        fixture.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        fixture.extend_from_slice(b"IDAT");
        fixture.extend_from_slice(&[0x35, 0xAF, 0x06, 0x1E]);

        let result = sanitize_png(&fixture);
        assert!(
            matches!(result, Err(CdrError::ImageTooLarge { .. })),
            "expected ImageTooLarge for 16384×16384 RGBA PNG, got {result:?}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  Async streaming tests
// ───────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod async_tests {
    use crate::errors::CdrError;
    use crate::async_stream::disarm_bytes_async;

    /// An empty buffer must immediately return `PayloadTooShort` without panicking.
    #[tokio::test]
    async fn async_rejects_empty_payload() {
        let err = disarm_bytes_async(&[]).await.unwrap_err();
        assert!(
            matches!(err, CdrError::PayloadTooShort { got: 0 }),
            "expected PayloadTooShort{{got:0}}, got {err:?}"
        );
    }

    /// A buffer shorter than MIN_SNIFF_LEN (16 bytes) must return `PayloadTooShort`.
    #[tokio::test]
    async fn async_rejects_short_payload() {
        let short = vec![0u8; 8];
        let err = disarm_bytes_async(&short).await.unwrap_err();
        assert!(
            matches!(err, CdrError::PayloadTooShort { got: 8 }),
            "expected PayloadTooShort{{got:8}}, got {err:?}"
        );
    }

    /// Garbage bytes with no recognised magic must return `UnknownFormat`.
    #[tokio::test]
    async fn async_rejects_unknown_format() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B];
        let err = disarm_bytes_async(&garbage).await.unwrap_err();
        assert!(
            matches!(err, CdrError::UnknownFormat { .. }),
            "expected UnknownFormat, got {err:?}"
        );
    }

    /// A structurally valid JPEG (SOI + EOI with no image data) must
    /// route through the async pipeline and fail at decode, NOT at format
    /// detection, confirming that async dispatch works end-to-end.
    #[tokio::test]
    async fn async_routes_jpeg_to_decoder() {
        // SOI + 14 zero-padded bytes + EOI — detectable as JPEG but
        // degenerate, so the decoder must reject it rather than the sniffer.
        let mut jpeg = vec![0xFF, 0xD8];
        jpeg.extend_from_slice(&[0x00; 14]);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        let err = disarm_bytes_async(&jpeg).await.unwrap_err();
        assert!(
            !matches!(err, CdrError::UnknownFormat { .. }),
            "JPEG magic should be recognised; sniffer should not reject it as UnknownFormat. Got {err:?}"
        );
    }
}
