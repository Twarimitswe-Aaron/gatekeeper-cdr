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

pub mod async_stream;
pub mod errors;
pub mod ffi;
pub mod sanitizers;
pub mod sniffer;
pub mod stream;

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
pub use sanitizers::jpeg::{DisarmedPayload, SanitizedOutput, sanitize_jpeg, sanitize_jpeg_to_png};

/// Typestate pipeline entry point for JPEG inputs.
pub use sanitizers::jpeg::RawPayload;
/// Convenience free-function CDR entry point for PNG inputs.
pub use sanitizers::png::sanitize_png;

/// Typestate pipeline entry point for PNG inputs.
pub use sanitizers::png::RawPngPayload;

/// Convenience free-function CDR entry point for GIF inputs.
pub use sanitizers::gif::{sanitize_gif, sanitize_gif_to_png};

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
//  Async streaming tests  —  comprehensive suite
// ───────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod async_tests {
    use crate::async_stream::{AsyncImageStream, disarm_bytes_async};
    use crate::errors::CdrError;
    use crate::sniffer::{JPEG_EOI, PNG_IHDR, PNG_SIG};
    use std::io::Cursor;

    // ── Shared fixture helpers ────────────────────────────────────────────────

    fn minimal_jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        v.extend_from_slice(b"JFIF\x00");
        v.extend_from_slice(&[0x01, 0x01, 0x00]);
        v.extend_from_slice(&JPEG_EOI);
        v
    }

    fn minimal_png_stub() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&PNG_SIG);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]); // IHDR length
        v.extend_from_slice(&PNG_IHDR); // "IHDR"
        v
    }

    fn gif87a_stub() -> Vec<u8> {
        let mut v = b"GIF87a".to_vec();
        v.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // descriptor
        v.extend_from_slice(&[0x2C, 0x00, 0x00, 0x00, 0x00]); // image descriptor
        v
    }

    fn gif89a_stub() -> Vec<u8> {
        let mut v = b"GIF89a".to_vec();
        v.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        v.extend_from_slice(&[0x2C, 0x00, 0x00, 0x00, 0x00]);
        v
    }

    fn webp_stub() -> Vec<u8> {
        // RIFF....WEBP header (12 bytes) + 4 padding
        let mut v = b"RIFF".to_vec();
        v.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // file size
        v.extend_from_slice(b"WEBP");
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // pad to 16 bytes
        v
    }

    fn pdf_stub() -> Vec<u8> {
        let mut v = b"%PDF-1.4".to_vec();
        v.extend_from_slice(&[0x0A; 8]); // pad to 16 bytes
        v
    }

    fn zip_stub() -> Vec<u8> {
        // ZIP local file header magic
        let mut v = vec![0x50, 0x4B, 0x03, 0x04];
        v.extend_from_slice(&[0x00; 12]); // pad to 16 bytes
        v
    }

    // ── 1. Boundary / PayloadTooShort ──────────────────────────────────────

    #[tokio::test]
    async fn rejects_empty_payload() {
        let err = disarm_bytes_async(&[]).await.unwrap_err();
        assert!(
            matches!(err, CdrError::PayloadTooShort { got: 0 }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_one_byte_payload() {
        let err = disarm_bytes_async(&[0xFF]).await.unwrap_err();
        assert!(
            matches!(err, CdrError::PayloadTooShort { got: 1 }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_15_bytes_exactly_below_min_sniff_len() {
        let data = vec![0xFFu8; 15];
        let err = disarm_bytes_async(&data).await.unwrap_err();
        assert!(
            matches!(err, CdrError::PayloadTooShort { got: 15 }),
            "got {err:?}"
        );
    }

    // ── 2. UnknownFormat ───────────────────────────────────────────────

    #[tokio::test]
    async fn rejects_all_zeros() {
        let data = vec![0u8; 32];
        let err = disarm_bytes_async(&data).await.unwrap_err();
        assert!(matches!(err, CdrError::UnknownFormat { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_all_ones() {
        let data = vec![0xFFu8; 32];
        let err = disarm_bytes_async(&data).await.unwrap_err();
        assert!(matches!(err, CdrError::UnknownFormat { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_random_garbage() {
        let data = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07,
        ];
        let err = disarm_bytes_async(&data).await.unwrap_err();
        match err {
            CdrError::UnknownFormat { magic } => {
                assert_eq!(magic, [0xDE, 0xAD, 0xBE, 0xEF], "wrong magic bytes")
            }
            other => panic!("expected UnknownFormat, got {other:?}"),
        }
    }

    // ── 3. Format recognition (routing) ─────────────────────────────────
    // These tests confirm the async sniffer correctly routes each format
    // to its pipeline (not UnknownFormat). Decoder errors are expected
    // because the stubs are minimal, not fully-valid files.

    #[tokio::test]
    async fn routes_jpeg_not_unknown() {
        let err = disarm_bytes_async(&minimal_jpeg()).await.unwrap_err();
        assert!(
            !matches!(err, CdrError::UnknownFormat { .. }),
            "JPEG should not be UnknownFormat, got {err:?}"
        );
    }

    #[tokio::test]
    async fn routes_jpeg_missing_eoi_gives_jpeg_error() {
        // SOI present, EOI absent — must fail with JpegMissingEoi
        let mut data = vec![0xFF, 0xD8];
        data.extend_from_slice(&[0x00; 14]); // no EOI
        let err = disarm_bytes_async(&data).await.unwrap_err();
        assert!(
            matches!(err, CdrError::JpegMissingEoi),
            "expected JpegMissingEoi, got {err:?}"
        );
    }

    #[tokio::test]
    async fn routes_png_not_unknown() {
        let err = disarm_bytes_async(&minimal_png_stub()).await.unwrap_err();
        assert!(
            !matches!(err, CdrError::UnknownFormat { .. }),
            "PNG should not be UnknownFormat, got {err:?}"
        );
    }

    #[tokio::test]
    async fn routes_png_missing_ihdr_gives_png_error() {
        // Valid PNG sig but no IHDR chunk
        let mut data = PNG_SIG.to_vec();
        data.extend_from_slice(&[0x00; 8]); // garbage where IHDR should be
        let err = disarm_bytes_async(&data).await.unwrap_err();
        assert!(
            matches!(err, CdrError::PngMissingIhdr),
            "expected PngMissingIhdr, got {err:?}"
        );
    }

    #[tokio::test]
    async fn routes_gif87a_not_unknown() {
        let err = disarm_bytes_async(&gif87a_stub()).await.unwrap_err();
        assert!(
            !matches!(err, CdrError::UnknownFormat { .. }),
            "GIF87a should not be UnknownFormat, got {err:?}"
        );
    }

    #[tokio::test]
    async fn routes_gif89a_not_unknown() {
        let err = disarm_bytes_async(&gif89a_stub()).await.unwrap_err();
        assert!(
            !matches!(err, CdrError::UnknownFormat { .. }),
            "GIF89a should not be UnknownFormat, got {err:?}"
        );
    }

    #[tokio::test]
    async fn routes_webp_not_unknown() {
        let err = disarm_bytes_async(&webp_stub()).await.unwrap_err();
        assert!(
            !matches!(err, CdrError::UnknownFormat { .. }),
            "WebP should not be UnknownFormat, got {err:?}"
        );
    }

    #[tokio::test]
    async fn routes_pdf_not_unknown() {
        let err = disarm_bytes_async(&pdf_stub()).await.unwrap_err();
        assert!(
            !matches!(err, CdrError::UnknownFormat { .. }),
            "PDF should not be UnknownFormat, got {err:?}"
        );
    }

    #[tokio::test]
    async fn routes_zip_office_not_unknown() {
        let err = disarm_bytes_async(&zip_stub()).await.unwrap_err();
        assert!(
            !matches!(err, CdrError::UnknownFormat { .. }),
            "ZIP/Office should not be UnknownFormat, got {err:?}"
        );
    }

    // ── 4. End-to-end success (real CDR round-trip) ──────────────────────

    /// Build a real 1x1 PNG with the `png` crate and pass it through the
    /// full async CDR pipeline.  The output must be a valid PNG buffer.
    #[tokio::test]
    async fn async_png_round_trip_succeeds() {
        use png::{BitDepth, ColorType, Encoder};
        let mut raw: Vec<u8> = Vec::new();
        {
            let mut enc = Encoder::new(&mut raw, 1, 1);
            enc.set_color(ColorType::Rgb);
            enc.set_depth(BitDepth::Eight);
            let mut writer = enc.write_header().expect("header");
            writer.write_image_data(&[255u8, 0, 0]).expect("pixels");
        }
        let result = disarm_bytes_async(&raw)
            .await
            .expect("1x1 PNG round-trip must succeed");
        // Output must start with PNG signature
        assert!(
            result.buffer.starts_with(&PNG_SIG),
            "output buffer must be valid PNG"
        );
        assert!(!result.buffer.is_empty());
    }

    // ── 5. AsyncImageStream constructor directly ─────────────────────────

    /// Prove that `AsyncImageStream::new()` accepts any `AsyncRead + Unpin`
    /// source, not just the `disarm_bytes_async` convenience wrapper.
    #[tokio::test]
    async fn async_image_stream_new_accepts_cursor() {
        let data = vec![0u8; 32]; // garbage — will be UnknownFormat
        let cursor = Cursor::new(data);
        let reader = tokio::io::BufReader::new(cursor);
        let err = AsyncImageStream::new(reader)
            .route_async()
            .await
            .unwrap_err();
        assert!(matches!(err, CdrError::UnknownFormat { .. }), "got {err:?}");
    }

    // ── 6. Concurrency: 100 simultaneous async calls ─────────────────────

    /// Fire 100 `disarm_bytes_async` calls concurrently.  Each must
    /// resolve independently without data races or panics.
    #[tokio::test]
    async fn concurrent_async_calls_do_not_panic() {
        use tokio::task::JoinSet;
        let mut set = JoinSet::new();
        for _ in 0..100 {
            set.spawn(async { disarm_bytes_async(&[0u8; 32]).await });
        }
        while let Some(result) = set.join_next().await {
            let inner = result.expect("task did not panic");
            assert!(
                matches!(inner, Err(CdrError::UnknownFormat { .. })),
                "expected UnknownFormat from garbage, got {inner:?}"
            );
        }
    }

    /// Mix of valid and invalid payloads in parallel.
    #[tokio::test]
    async fn concurrent_mixed_payloads_all_resolve() {
        use tokio::task::JoinSet;
        let mut set = JoinSet::new();
        // 50 valid PNGs + 50 garbage payloads
        for i in 0..100u8 {
            let payload = if i % 2 == 0 {
                // garbage — UnknownFormat
                vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            } else {
                // PNG stub — routed to PNG pipeline (will fail at decode)
                let mut v = PNG_SIG.to_vec();
                v.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
                v.extend_from_slice(&PNG_IHDR);
                v
            };
            set.spawn(async move { disarm_bytes_async(&payload).await });
        }
        let mut count = 0usize;
        while let Some(result) = set.join_next().await {
            let _ = result.expect("task must not panic");
            count += 1;
        }
        assert_eq!(count, 100);
    }

    // ── 7. Large payload (1 MiB of garbage) ───────────────────────────

    #[tokio::test]
    async fn handles_large_unknown_payload_without_oom() {
        let big = vec![0xAAu8; 1024 * 1024]; // 1 MiB
        let err = disarm_bytes_async(&big).await.unwrap_err();
        assert!(matches!(err, CdrError::UnknownFormat { .. }), "got {err:?}");
    }
}

// ───────────────────────────────────────────────────────────────────────────────
//  Hardening regression tests
//
//  These lock in the security/correctness fixes so they cannot silently regress:
//    • PNG  — indexed-palette images round-trip (palette + tRNS carried).
//    • GIF  — colour is preserved (no greyscale fallback) via NeuQuant re-encode.
//    • PDF  — actions are stripped recursively (nested-in-array + stream dicts).
//    • Office — macros dropped case-insensitively; DDE fails closed.
//    • FFI  — disarm→free round-trip is sound (boxed-slice ownership transfer).
// ───────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod hardening_tests {
    use super::*;
    use crate::errors::CdrError;

    // ── PNG: indexed palette round-trip (H2) ──────────────────────────────────

    /// Before the fix, an indexed PNG was re-encoded as `Indexed` WITHOUT its
    /// PLTE palette, producing an invalid/broken file (or an encoder error).
    /// Now the palette (and tRNS) must survive the pipeline.
    #[test]
    fn png_indexed_palette_round_trips() {
        use png::{BitDepth, ColorType, Decoder, Encoder};

        let mut fixture: Vec<u8> = Vec::new();
        {
            let mut enc = Encoder::new(&mut fixture, 2, 2);
            enc.set_color(ColorType::Indexed);
            enc.set_depth(BitDepth::Eight);
            enc.set_palette(vec![255, 0, 0, 0, 255, 0, 0, 0, 255]); // R, G, B
            enc.set_trns(vec![0u8]); // index 0 fully transparent
            let mut w = enc.write_header().expect("indexed header");
            w.write_image_data(&[0, 1, 2, 0]).expect("indices");
        }

        let clean = disarm(&fixture, None).expect("indexed PNG must sanitize");
        assert_eq!(clean.output_format, "png");

        // Re-decode the sanitized output: it must be a valid, still-indexed PNG
        // that carries a palette.
        let reader = Decoder::new(std::io::Cursor::new(&clean.buffer))
            .read_info()
            .expect("sanitized indexed PNG must be valid");
        assert_eq!(reader.info().color_type, ColorType::Indexed);
        assert!(
            reader.info().palette.is_some(),
            "PLTE palette must be carried into the sanitized output"
        );
    }

    // ── GIF: colour preserved, not greyscale (H3) ─────────────────────────────

    /// Build a solid-red GIF, sanitize it, and confirm the decoded output is
    /// still red.  The old greyscale-fallback path would have turned it grey.
    #[test]
    fn gif_preserves_colour_not_greyscale() {
        use gif::{Encoder, Frame, Repeat};

        // ── Source: a 4×4 solid-red GIF ──────────────────────────────────────
        let mut src: Vec<u8> = Vec::new();
        let mut rgba = vec![0u8; 4 * 4 * 4];
        for px in rgba.chunks_mut(4) {
            px.copy_from_slice(&[255, 0, 0, 255]);
        }
        {
            let frame = Frame::from_rgba_speed(4, 4, &mut rgba.clone(), 10);
            let mut enc = Encoder::new(&mut src, 4, 4, &[]).expect("gif encoder");
            enc.set_repeat(Repeat::Infinite).unwrap();
            enc.write_frame(&frame).expect("write src frame");
        }

        let clean = disarm(&src, None).expect("GIF must sanitize");
        assert_eq!(clean.output_format, "gif");
        assert!(clean.buffer.starts_with(b"GIF"), "output must be a GIF");

        // Decode the sanitized GIF and verify the first pixel is still red.
        let mut opts = gif::DecodeOptions::new();
        opts.set_color_output(gif::ColorOutput::RGBA);
        let mut dec = opts
            .read_info(std::io::Cursor::new(&clean.buffer))
            .expect("valid sanitized GIF");
        let frame = dec.read_next_frame().unwrap().expect("a frame").clone();
        let p = &frame.buffer[..4];
        assert!(
            p[0] > 200 && p[1] < 60 && p[2] < 60,
            "colour must survive quantization (got {p:?}), not collapse to grey"
        );
    }

    // ── PDF: recursive action stripping (C1) ──────────────────────────────────

    /// A PDF with `/OpenAction` at the catalog level AND `/JS` hidden inside a
    /// dictionary nested in an array must come out with BOTH removed — proving
    /// the traversal recurses instead of only scanning top-level dicts.
    #[test]
    fn pdf_strips_nested_and_toplevel_actions() {
        use lopdf::{Dictionary, Document, Object};

        fn build() -> Vec<u8> {
            let mut doc = Document::with_version("1.5");

            let mut open_action = Dictionary::new();
            open_action.set("S", Object::Name(b"JavaScript".to_vec()));
            open_action.set("JS", Object::string_literal("app.alert('evil');"));

            // A dictionary carrying /JS, hidden one level deep inside an array.
            let mut nested = Dictionary::new();
            nested.set("JS", Object::string_literal("nested_evil();"));

            let mut catalog = Dictionary::new();
            catalog.set("Type", Object::Name(b"Catalog".to_vec()));
            catalog.set("OpenAction", Object::Dictionary(open_action));
            catalog.set("Decoy", Object::Array(vec![Object::Dictionary(nested)]));

            let root_id = doc.add_object(Object::Dictionary(catalog));
            doc.trailer.set("Root", root_id);

            let mut out = Vec::new();
            doc.save_to(&mut out).expect("save fixture pdf");
            out
        }

        let raw = build();
        let clean = sanitize_pdf(&raw).expect("pdf sanitize").into_bytes();

        // Re-parse the sanitized PDF and assert NO dictionary anywhere still
        // carries a dangerous key.
        let doc = lopdf::Document::load_mem(&clean).expect("sanitized pdf must parse");

        fn dict_is_clean(d: &lopdf::Dictionary) -> bool {
            for bad in [b"JS".as_slice(), b"OpenAction".as_slice(), b"JavaScript".as_slice()] {
                if d.get(bad).is_ok() {
                    return false;
                }
            }
            d.iter().all(|(_, v)| obj_is_clean(v))
        }
        fn obj_is_clean(o: &lopdf::Object) -> bool {
            match o {
                lopdf::Object::Dictionary(d) => dict_is_clean(d),
                lopdf::Object::Stream(s) => dict_is_clean(&s.dict),
                lopdf::Object::Array(a) => a.iter().all(obj_is_clean),
                _ => true,
            }
        }

        assert!(
            doc.objects.values().all(obj_is_clean),
            "all dangerous keys must be stripped recursively"
        );
    }

    // ── Office helpers + tests (C2) ───────────────────────────────────────────

    fn build_ooxml(extra: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::write::SimpleFileOptions;

        let mut buf = Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let o = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            z.start_file("[Content_Types].xml", o).unwrap();
            z.write_all(b"<?xml version=\"1.0\"?><Types/>").unwrap();
            z.start_file("word/document.xml", o).unwrap();
            z.write_all(b"<?xml version=\"1.0\"?><w:document/>").unwrap();
            for (name, data) in extra {
                z.start_file(*name, o).unwrap();
                z.write_all(data).unwrap();
            }
            z.finish().unwrap();
        }
        buf.into_inner()
    }

    /// A macro project named with uppercase extension (`vbaProject.BIN`) must be
    /// dropped — the old case-sensitive `.ends_with(".bin")` let it through.
    #[test]
    fn office_drops_case_variant_macro() {
        let raw = build_ooxml(&[(
            "word/vbaProject.BIN",
            b"\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00 fake OLE macro",
        )]);

        let clean = disarm(&raw, None).expect("docx must sanitize");
        assert_eq!(clean.output_format, "office");

        let archive =
            zip::ZipArchive::new(std::io::Cursor::new(&clean.buffer)).expect("valid output zip");
        for name in archive.file_names() {
            assert!(
                !name.to_ascii_lowercase().contains("vbaproject"),
                "macro project must be removed regardless of filename case: {name}"
            );
        }
    }

    /// A document carrying a DDEAUTO field instruction cannot be neutralised by
    /// dropping a part, so the engine must fail closed rather than emit a file
    /// that still auto-executes.
    #[test]
    fn office_fails_closed_on_dde() {
        let raw = build_ooxml(&[(
            "word/document2.xml",
            b"<w:p><w:instrText> DDEAUTO c:\\\\evil cmd </w:instrText></w:p>",
        )]);

        let err = disarm(&raw, None).expect_err("DDE document must be rejected");
        assert!(
            matches!(err, CdrError::OfficeDangerousContent { .. }),
            "expected OfficeDangerousContent, got {err:?}"
        );
    }

    // ── FFI: disarm → free round-trip soundness (C3) ──────────────────────────

    /// Exercises the boxed-slice ownership transfer + free path on a real PNG.
    /// A capacity-mismatch bug would corrupt the allocator on free; running
    /// under the test allocator gives us a concrete soundness check.
    #[test]
    fn ffi_disarm_free_round_trip_is_sound() {
        use png::{BitDepth, ColorType, Encoder};

        let mut fixture: Vec<u8> = Vec::new();
        {
            let mut enc = Encoder::new(&mut fixture, 2, 2);
            enc.set_color(ColorType::Rgb);
            enc.set_depth(BitDepth::Eight);
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&[
                255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0,
            ])
            .unwrap();
        }

        let res = crate::ffi::gatekeeper_disarm(fixture.as_ptr(), fixture.len());
        assert!(res.ok, "FFI disarm should succeed (error_code {})", res.error_code);
        assert!(res.len > 0);

        // output_format is the inline C string; confirm the lowercase vocabulary.
        let fmt_end = res
            .output_format
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(res.output_format.len());
        assert_eq!(&res.output_format[..fmt_end], b"png");

        // Must not corrupt the heap; double-checked by the allocator on drop.
        crate::ffi::gatekeeper_free_result(res);
    }

    /// An invalid payload must produce a distinct, non-generic error code via
    /// the C ABI (M5), not collapse everything into one value.
    #[test]
    fn ffi_unknown_format_has_distinct_code() {
        let junk = [0xDEu8; 32];
        let res = crate::ffi::gatekeeper_disarm(junk.as_ptr(), junk.len());
        assert!(!res.ok);
        assert_eq!(res.error_code, CdrError::UnknownFormat { magic: [0; 4] }.code());
        crate::ffi::gatekeeper_free_result(res);
    }

    // ── Output size: PNG encoder tuning ─────────────────────────────────────

    /// Regression: sanitized PNG must not balloon vs a well-compressed source.
    ///
    /// Before adaptive Paeth filtering was enabled, Gatekeeper used zlib level 9
    /// but the `png` crate default (`Sub`, non-adaptive), producing IDAT streams
    /// often **2–3× larger** than the original despite stripping metadata.
    #[test]
    fn png_sanitized_size_stays_near_adaptive_source() {
        use crate::sanitizers::encode::tune_png_encoder;
        use png::{BitDepth, ColorType, Encoder};

        let w = 640u32;
        let h = 480u32;
        let mut source: Vec<u8> = Vec::new();
        {
            let mut enc = Encoder::new(&mut source, w, h);
            enc.set_color(ColorType::Rgb);
            enc.set_depth(BitDepth::Eight);
            tune_png_encoder(&mut enc);
            let mut writer = enc.write_header().expect("header");
            let pixels: Vec<u8> = (0..(w as usize * h as usize * 3))
                .map(|i| ((i * 37) % 256) as u8)
                .collect();
            writer.write_image_data(&pixels).expect("pixels");
        }

        let clean = disarm(&source, None).expect("png disarm").buffer;

        // Same pixels + same encoder tuning → output within ~25% of source.
        // (Chunk layout / filter heuristics can differ slightly row-to-row.)
        let max_allowed = source.len() + source.len() / 4;
        assert!(
            clean.len() <= max_allowed,
            "sanitized PNG ({} bytes) should stay near adaptive source ({} bytes); \
             check PNG filter/compression tuning",
            clean.len(),
            source.len()
        );
    }
}
