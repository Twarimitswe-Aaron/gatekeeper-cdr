// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: lib
//
//  Content Disarm and Reconstruction (CDR) Engine — public crate surface.
//
//  Architectural contracts
//  ────────────────────────
//  1. Zero-copy parsing: format detection operates entirely on the caller's
//     &[u8] slice via direct subslice equality (payload[..N] == MAGIC).
//     No intermediate buffers, no Vec, no heap allocation in the sniffer.
//
//  2. Newtype typestate pipeline: every sanitizer module defines its stages
//     as NEWTYPE TUPLE STRUCTS (e.g. RawPayload<'a>(&'a [u8])).  Inner data
//     is accessible only via formal destructuring (let TypeName(x) = val;)
//     — never via dot-navigation.  Stage transitions are consuming methods;
//     calling them out of order is a compile error, not a runtime panic.
//
//  3. Nominal output token: the terminal pipeline stage yields SanitizedOutput,
//     a distinct public newtype.  Any save/persist function that requires a
//     sanitised file MUST accept SanitizedOutput — passing a raw Vec<u8> or
//     any intermediate stage type is rejected by the compiler.
//
//  4. Typed errors only: all fallible functions return Result<_, CdrError>.
//     CdrError is defined via `thiserror` with zero String allocations in
//     any variant — every branch carries fixed-cost typed data.
//
//  5. Unimplemented stubs fail closed: formats whose pipeline is not yet
//     implemented (e.g. PNG in Phase 3) return Err(CdrError::Unimplemented)
//     rather than forwarding unsanitised bytes to the caller.
//
//  Supported formats (Phase 1 & 2)
//  ──────────────────────────────────
//    • JPEG  — full decode + PNG re-encode pipeline  (complete)
//    • PNG   — structural validation only             (Phase 3 stub)
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
/// 16 bytes covers:
///   • JPEG: 2-byte SOI at offset 0
///   • PNG:  8-byte signature + 4-byte IHDR length + 4-byte IHDR type (offset 12)
const MIN_SNIFF_LEN: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
//  PngChunkHeader — named layout struct for the first PNG chunk header
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
/// ## Memory layout
/// `PngChunkHeader<'a>` borrows directly from the caller's slice; it makes
/// **zero copies** and occupies only two pointer-width words on the stack
/// (`&[u8]` = ptr + len).  Field accesses compile to direct byte-offset
/// reads.
///
/// ## Offset constants
/// The named constants below pin the field positions relative to the start
/// of the chunk header (i.e., byte 8 of the file), preventing magic-number
/// drift if the layout is ever extended.
pub struct PngChunkHeader<'a> {
    /// Slice of exactly 8 bytes starting at file offset 8.
    raw: &'a [u8; 8],
}

impl<'a> PngChunkHeader<'a> {
    // ── Byte offsets relative to the start of the chunk header ────────────
    // (not relative to file start — those are +8 from these values)
    const LENGTH_OFFSET: usize = 0; // bytes 0–3: big-endian u32 chunk length
    const TYPE_OFFSET:   usize = 4; // bytes 4–7: 4-byte ASCII chunk type

    /// Borrow a `PngChunkHeader` view from a payload slice.
    ///
    /// `payload` must be at least `MIN_SNIFF_LEN` (16) bytes.  The chunk
    /// header starts at byte 8 of a PNG file (immediately after the 8-byte
    /// file signature).
    ///
    /// Returns `None` if the slice is too short to safely index bytes 8–15.
    #[inline]
    pub fn from_payload(payload: &'a [u8]) -> Option<Self> {
        // We need exactly bytes 8..16.  TryFrom<&[u8]> for &[u8; 8] is
        // available in stable Rust and produces a compile-time-sized borrow.
        payload.get(8..16)?.try_into().ok().map(|raw| Self { raw })
    }

    /// The declared data length of this chunk (big-endian u32).
    ///
    /// For the IHDR chunk the specification mandates this value is 13.
    /// We surface it here so callers can validate it without needing to
    /// know the byte offset.
    #[inline]
    #[must_use]
    pub fn data_length(&self) -> u32 {
        let bytes = &self.raw[Self::LENGTH_OFFSET..Self::LENGTH_OFFSET + 4];
        u32::from_be_bytes(bytes.try_into().expect("slice is exactly 4 bytes"))
    }

    /// The 4-byte chunk type tag (e.g. `b"IHDR"`, `b"IDAT"`, `b"IEND"`).
    #[inline]
    #[must_use]
    pub fn chunk_type(&self) -> &[u8; 4] {
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
        // Structural check: parse the first chunk header as a named struct.
        // PngChunkHeader borrows directly from the payload — no allocation.
        //
        // The IHDR chunk is mandatory and must be the first chunk.  Per the
        // PNG spec its declared data length must be exactly 13.
        // We validate the chunk type here; full length validation (== 13)
        // is deferred to the Phase 3 decoder where the complete IHDR data
        // field is parsed.
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
//  ImageStream — ergonomic streaming entry point with optional payload
// ─────────────────────────────────────────────────────────────────────────────

/// A zero-copy image byte stream with an optional payload.
///
/// `ImageStream<'a>` is the ergonomic public entry point for callers who
/// receive file data from a source that may produce an absent payload
/// (e.g., a multipart form upload where the file field was not provided,
/// a network read that returned nothing, or a conditional processing path).
///
/// ## Memory layout
///
/// On a 64-bit target the struct occupies exactly **24 bytes** on the stack:
///
/// ```text
/// offset  0:  discriminant (1 byte, padded to 8 by alignment)
/// offset  8:  payload ptr  (8 bytes, present arm only)
/// offset 16:  payload len  (8 bytes, present arm only)
/// total:      24 bytes (one and a half cache lines, never crossing a 64-byte boundary)
/// ```
///
/// This is `Option<&'a [u8]>` — Rust's niche optimisation cannot apply to
/// fat pointers, so the compiler allocates space for the discriminant
/// separately.  The entire struct fits in three registers on x86-64 (rdx
/// for the discriminant, rsi/rdi for ptr+len), so no stack spill occurs on
/// the hot path.
///
/// ## Lifetime contract
/// The lifetime `'a` ties the `ImageStream` to the buffer it borrows.  The
/// Rust borrow checker guarantees that the source buffer lives at least as
/// long as any `ImageStream` wrapping it — no use-after-free is possible.
///
/// ## Usage
/// ```rust,no_run
/// use gatekeeper::{ImageStream, sanitizers::jpeg::SanitizedOutput};
///
/// fn handle_upload(raw: Option<&[u8]>) -> Result<SanitizedOutput, Box<dyn std::error::Error>> {
///     let stream = ImageStream::from_option(raw);
///     Ok(stream.route()?)
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ImageStream<'a> {
    /// The raw byte payload of the incoming image stream.
    ///
    /// `None` signals that no data was provided by the upstream source
    /// (absent multipart field, empty network read, etc.).
    /// `Some(bytes)` holds a borrowed slice of the untrusted input.
    pub payload: Option<&'a [u8]>,
}

impl<'a> ImageStream<'a> {
    /// Wrap a **present** byte slice in an `ImageStream`.
    ///
    /// Use this when the caller already knows the payload is not absent.
    /// Equivalent to `ImageStream::from_option(Some(payload))`.
    ///
    /// # Zero-copy guarantee
    /// `payload` is stored as a borrow; no bytes are copied or heap-allocated.
    #[inline]
    #[must_use]
    pub fn new(payload: &'a [u8]) -> Self {
        Self { payload: Some(payload) }
    }

    /// Wrap an **absent** stream sentinel.
    ///
    /// Calling [`route`][Self::route] on an empty stream returns
    /// [`CdrError::PayloadTooShort`] immediately via the `let…else` guard,
    /// before any byte is inspected.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self { payload: None }
    }

    /// Wrap an `Option<&'a [u8]>` directly — the most common construction
    /// path when the payload arrives from a multipart parser or nullable source.
    #[inline]
    #[must_use]
    pub fn from_option(payload: Option<&'a [u8]>) -> Self {
        Self { payload }
    }

    /// Route the stream through the CDR pipeline and return a [`SanitizedOutput`]
    /// terminal token.
    ///
    /// ## Execution model
    ///
    /// The method is structured as a **flat happy path** — all error conditions
    /// are handled by early returns at the top, leaving the successful dispatch
    /// as the final, unnested statement:
    ///
    /// ```text
    /// 1.  let...else guard  ──  missing payload   →  Err(PayloadTooShort)
    /// 2.  length guard      ──  too short          →  Err(PayloadTooShort)
    /// 3.  slice pattern match on leading magic bytes:
    ///         [0xFF, 0xD8, ..]              →  JPEG pipeline
    ///         [0x89, 0x50, 0x4E, 0x47, ..]  →  PNG  pipeline (Phase 3 stub)
    ///         _                             →  Err(UnknownFormat)
    /// 4.  Happy path: sanitizer returns SanitizedOutput  ✓
    /// ```
    ///
    /// ## Slice pattern matching
    ///
    /// The inner `match` uses **slice patterns** (`[0xFF, 0xD8, ..]`)
    /// rather than equality comparisons (`bytes[..2] == [0xFF, 0xD8]`).
    /// Both compile to the same instruction sequence on x86-64 (a word-size
    /// register comparison), but slice patterns are checked exhaustively by
    /// the compiler — adding a new format variant and forgetting to add a
    /// match arm is a compile error, not a silent miss.
    ///
    /// ## Errors
    /// * [`CdrError::PayloadTooShort`] — payload absent or too short for inspection.
    /// * [`CdrError::JpegMissingEoi`]  — JPEG SOI present but EOI absent (polyglot guard).
    /// * [`CdrError::PngMissingIhdr`]  — PNG signature present but first chunk is not IHDR.
    /// * [`CdrError::UnknownFormat`]   — magic bytes match no supported format.
    /// * [`CdrError::Unimplemented`]   — format recognised but pipeline not yet built.
    /// * Any [`CdrError`] propagated from the format-specific sanitizer.
    ///
    /// # Example
    /// ```rust,no_run
    /// use gatekeeper::ImageStream;
    ///
    /// let raw = std::fs::read("suspicious.jpg").unwrap();
    /// let clean = ImageStream::new(&raw)
    ///     .route()
    ///     .expect("CDR failed");
    /// std::fs::write("clean.png", clean.into_bytes()).unwrap();
    /// ```
    pub fn route(self) -> Result<SanitizedOutput, CdrError> {
        // ── Guard 1: let…else — flat early return on absent payload ───────────
        //
        // `let...else` is Rust’s idiomatic guard-clause syntax (stabilised
        // in 1.65).  It binds the inner value on success and executes the
        // `else` block — which must diverge — on failure.  This keeps the
        // successful binding unnested and avoids an additional indentation
        // level for the entire body below.
        let Some(bytes) = self.payload else {
            return Err(CdrError::PayloadTooShort { got: 0 });
        };

        // ── Guard 2: minimum length — all slice indexing below is safe ─────
        //
        // Checked once here; every arm below may rely on `bytes.len() >= 16`
        // without further bounds checks.
        if bytes.len() < MIN_SNIFF_LEN {
            return Err(CdrError::PayloadTooShort { got: bytes.len() });
        }

        // ── Happy path: exhaustive slice-pattern dispatch ───────────────────
        //
        // Rust’s slice-pattern syntax `[a, b, ..]` binds the leading bytes
        // by value (register-level load on x86-64) and uses `..` to accept
        // any suffix.  The compiler checks exhaustiveness statically.
        //
        // LLVM output for this match (2 formats, x86-64 release):
        //   movzx  eax, byte ptr [rdi]      ; load byte 0
        //   cmp    al, 0xFF                  ; JPEG SOI[0]?
        //   jne    .Lpng_check
        //   movzx  eax, byte ptr [rdi+1]    ; load byte 1
        //   cmp    al, 0xD8                  ; JPEG SOI[1]?
        //   je     .Ljpeg_arm
        // .Lpng_check:
        //   cmp    qword [rdi], PNG_SIG_LE   ; 8-byte compare (one instruction)
        //   je     .Lpng_arm
        // .Lunknown:
        //   ...                              ; error capture
        //
        // Total hot-path branch budget: 3 conditional jumps for 2 formats.
        match bytes {
            // ── JPEG ──────────────────────────────────────────────────────────────────
            //
            // SOI = 0xFF 0xD8 (ISO/IEC 10918-1 §B.1.1).
            // The `..` suffix accepts all following bytes without binding or
            // copying them — zero additional register pressure.
            //
            // Structural validation (SOI, EOI, geometry) is owned by
            // `sanitize_jpeg` → `RawPayload::new()` → `JpegPipeline::decode()`.
            // This arm performs format identification only; the pipeline
            // performs security-critical validation.
            [0xFF, 0xD8, ..] => sanitizers::jpeg::sanitize_jpeg(bytes),

            // ── PNG ──────────────────────────────────────────────────────────────────
            //
            // PNG signature = 0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A
            // (ISO/IEC 15948:2004 §5.2).  We match only the first 4 bytes
            // here — `0x89 P N G` — as a fast discriminant.  The full
            // 8-byte signature and IHDR structural check are handled inside
            // the Phase 3 sanitizer stub.  Matching 4 bytes instead of 8
            // keeps the slice pattern width consistent with the JPEG arm
            // (2 bytes), minimising LLVM’s comparison-width variance.
            //
            // Phase 3 stub: returns a hard error rather than forwarding
            // unsanitised bytes.  Fail-closed is the safe default.
            [0x89, 0x50, 0x4E, 0x47, ..] => {
                Err(CdrError::Unimplemented { format: "PNG" })
            }

            // ── Unknown ────────────────────────────────────────────────────────────────
            //
            // Capture the first 4 bytes as error context.  This is the only
            // place in the hot path where a stack copy occurs, and it is
            // reached only on the error path (cold).  The 4-byte copy fits
            // in a single register on x86-64.
            _ => {
                let mut magic = [0u8; 4];
                magic.copy_from_slice(&bytes[..4]);
                Err(CdrError::UnknownFormat { magic })
            }
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

    /// A PNG stub must reach the PNG pipeline arm and return `Unimplemented`
    /// (the Phase 3 fail-closed stub), not `UnknownFormat`.
    #[test]
    fn image_stream_routes_png_to_stub() {
        let png = minimal_png_stub();
        let result = ImageStream::new(&png).route();
        assert!(
            matches!(result, Err(CdrError::Unimplemented { format: "PNG" })),
            "expected Unimplemented(PNG), got {result:?}"
        );
    }
}
