// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: sniffer
//
//  Zero-trust format detection, structural pre-validation, and top-level
//  disarm() dispatch for the CDR engine.
//
//  ## Responsibility boundary
//  This module owns everything required to answer one question:
//    "Given an untrusted &[u8], which sanitizer pipeline should handle it?"
//
//  It does NOT perform decoding, re-encoding, or pixel-level processing.
//  Those concerns live in `crate::sanitizers::*`.
//
//  ## Privacy model
//  •  `PngChunkHeader`  — `pub(crate)`: a parse-internal struct used only
//     inside `sniff_format()`.  External callers have no legitimate reason
//     to construct or inspect raw chunk headers.
//  •  `FileFormat`      — `pub`: callers of `sniff_format()` match on it.
//  •  `sniff_format()`  — `pub`: useful as a standalone format probe.
//  •  `disarm()`        — `pub`: the primary crate-level CDR entry point.
//  •  All magic constants — `pub(crate)`: shared with `crate::stream` for
//     the `ImageStream::route()` slice-pattern match; never escape the crate.
// ─────────────────────────────────────────────────────────────────────────────

use crate::errors::CdrError;
use crate::sanitizers::jpeg::{sanitize_jpeg, SanitizedOutput};
use crate::sanitizers::png::sanitize_png;

// ── Magic byte constants (stack arrays, zero heap) ───────────────────────────
//
// Declared `pub(crate)` so `crate::stream::ImageStream::route()` can use them
// in its slice-pattern match without duplicating the literals.

/// JPEG Start-Of-Image marker (ISO/IEC 10918-1 §B.1.1).
pub(crate) const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];

/// JPEG End-Of-Image marker.  Absence indicates a truncated or
/// polyglot-container file.
pub(crate) const JPEG_EOI: [u8; 2] = [0xFF, 0xD9];

/// PNG file signature (ISO/IEC 15948:2004 §5.2).
pub(crate) const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// PNG IHDR chunk type identifier.
/// bytes 0–7  = PNG signature
/// bytes 8–11 = IHDR chunk length (big-endian u32, value = 13)
/// bytes 12–15 = IHDR chunk type (ASCII "IHDR")
pub(crate) const PNG_IHDR: [u8; 4] = [0x49, 0x48, 0x44, 0x52]; // "IHDR"

/// Minimum byte count required to inspect enough magic and structure to make a
/// reliable format determination without false positives.
///
/// 16 bytes covers:
///   • JPEG: 2-byte SOI at offset 0
///   • PNG:  8-byte signature + 4-byte IHDR length + 4-byte IHDR type (offset 12)
pub(crate) const MIN_SNIFF_LEN: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
//  PngChunkHeader — crate-internal parse helper
// ─────────────────────────────────────────────────────────────────────────────

/// A zero-copy, borrowed view over the 8-byte PNG chunk header that begins
/// immediately after the 8-byte PNG file signature.
///
/// ## PNG chunk wire layout (§5.3 of ISO/IEC 15948:2004)
/// ```text
/// offset  0– 3  (bytes  8–11 from file start): chunk data length (big-endian u32)
/// offset  4– 7  (bytes 12–15 from file start): chunk type (4 ASCII bytes)
/// offset  8–N   (bytes 16–N  from file start): chunk data (length bytes)
/// offset  N+0–3 (after data):                  CRC-32 (4 bytes)
/// ```
///
/// ## Privacy
/// `pub(crate)` — this is a parse-internal struct.  No external caller (FFI
/// binding, CLI consumer, test outside this crate) has a legitimate reason to
/// construct or inspect a raw PNG chunk header.  The public surface exposed to
/// callers is `FileFormat`, `sniff_format()`, and `disarm()`.
///
/// ## Memory layout
/// Occupies exactly 8 bytes on the stack (`&[u8; 8]` = one pointer).
/// Field accesses compile to direct byte-offset reads; no heap allocation,
/// no indirection.
pub(crate) struct PngChunkHeader<'a> {
    /// Fixed-size reference to bytes 8–15 of the payload (the first chunk header).
    raw: &'a [u8; 8],
}

#[allow(dead_code)]
impl<'a> PngChunkHeader<'a> {
    // ── Byte offsets relative to the start of the chunk header ────────────
    // (not relative to file start — those are +8 from these values)
    const LENGTH_OFFSET: usize = 0; // bytes 0–3: big-endian u32 chunk length
    const TYPE_OFFSET:   usize = 4; // bytes 4–7: 4-byte ASCII chunk type

    /// Borrow a `PngChunkHeader` view from a payload slice.
    ///
    /// Returns `None` if the slice is too short to safely index bytes 8–15.
    /// Callers must ensure `payload.len() >= MIN_SNIFF_LEN` before calling.
    #[inline]
    pub(crate) fn from_payload(payload: &'a [u8]) -> Option<Self> {
        // TryFrom<&[u8]> for &[u8; 8] produces a compile-time-sized borrow.
        payload.get(8..16)?.try_into().ok().map(|raw| Self { raw })
    }

    /// The declared data length of this chunk (big-endian u32).
    ///
    /// For the IHDR chunk the PNG specification mandates this value is 13.
    #[inline]
    #[must_use]
    pub(crate) fn data_length(&self) -> u32 {
        let bytes = &self.raw[Self::LENGTH_OFFSET..Self::LENGTH_OFFSET + 4];
        u32::from_be_bytes(bytes.try_into().expect("slice is exactly 4 bytes"))
    }

    /// The 4-byte chunk type tag (e.g. `b"IHDR"`, `b"IDAT"`, `b"IEND"`).
    #[inline]
    #[must_use]
    pub(crate) fn chunk_type(&self) -> &[u8; 4] {
        self.raw[Self::TYPE_OFFSET..Self::TYPE_OFFSET + 4]
            .try_into()
            .expect("slice is exactly 4 bytes")
    }
}

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
/// Borrows `payload` as an immutable slice.  All analysis uses fixed-size
/// stack constants; no heap allocation occurs in the sniffer.
///
/// # Structural validation
/// Beyond magic byte matching, the sniffer performs lightweight structural
/// checks before the payload reaches a decoder:
///
/// | Format | Magic check          | Structural check                                  |
/// |--------|----------------------|---------------------------------------------------|
/// | JPEG   | bytes[0..2] == SOI   | EOI marker present in the final two bytes          |
/// | PNG    | bytes[0..8] == sig   | IHDR chunk type at bytes 12–15                     |
///
/// # Examples
///
/// ```rust,no_run
/// use gatekeeper::{sniff_format, FileFormat};
///
/// // Happy path — a file that is a valid JPEG.
/// let raw = std::fs::read("image.jpg").unwrap();
/// match sniff_format(&raw) {
///     Ok(FileFormat::Jpeg) => println!("JPEG confirmed"),
///     Ok(FileFormat::Png)  => println!("PNG confirmed"),
///     Err(e)               => eprintln!("rejected: {e}"),
/// }
/// ```
///
/// # Errors
/// * [`CdrError::PayloadTooShort`] — `payload.len() < MIN_SNIFF_LEN`.
/// * [`CdrError::UnknownFormat`]   — leading bytes match no known magic.
/// * [`CdrError::JpegMissingEoi`]  — JPEG magic present but EOI absent.
/// * [`CdrError::PngMissingIhdr`]  — PNG signature present but IHDR absent.
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
        // Structural check: EOI marker must occupy the final 2 bytes.
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
        // Structural check: parse the first chunk header as a named struct.
        // PngChunkHeader borrows directly from the payload — no allocation.
        let header = PngChunkHeader::from_payload(payload)
            .ok_or(CdrError::PayloadTooShort { got: payload.len() })?;

        if header.chunk_type() != &PNG_IHDR {
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
        FileFormat::Jpeg => sanitize_jpeg(payload),
        FileFormat::Png => sanitize_png(payload),
    }
}
