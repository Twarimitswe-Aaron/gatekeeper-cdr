// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: sanitizers :: jpeg
//
//  JPEG Content Disarm and Reconstruction pipeline.
//
//  ┌─────────────────────────────────────────────────────────────────────────┐
//  │  Threat model                                                           │
//  │                                                                         │
//  │  A JPEG file may carry:                                                 │
//  │    • Steganographic payloads hidden in DCT coefficient LSBs             │
//  │    • Arbitrary code / exploit shellcode inside APP0-APP15 markers       │
//  │    • EXIF GPS coordinates, device fingerprints, author PII              │
//  │    • ICC colour profiles with embedded executables                      │
//  │    • Comment (COM) markers with tracking/fingerprinting data            │
//  │    • Trailing bytes after the EOI marker (polyglot containers)          │
//  │                                                                         │
//  │  Mitigation: never "scrub" in-place.  Fully decode to a raw pixel       │
//  │  colour matrix, then re-encode from scratch.  The output file shares    │
//  │  *zero* bytes with the input.                                           │
//  └─────────────────────────────────────────────────────────────────────────┘
//
//  Typestate chain (newtype tuple structs)
//  ────────────────────────────────────────
//
//  RawPayload<'a>(&'a [u8])           – borrows untrusted input; zero copies
//       │  consumed by JpegPipeline::new()
//       │  .decode()
//       ▼
//  DisarmedMatrix(PixelMatrix)        – opaque wrapper around the decoded
//       │                              pixel matrix; carries no JPEG markers
//       │  .reconstruct()
//       ▼
//  PristineStream(Vec<u8>)            – opaque wrapper around a freshly
//       │                              encoded PNG; carries zero input bytes
//       │  .into_sanitized()
//       ▼
//  SanitizedOutput(Vec<u8>)           – public terminal token.  Only a
//                                       completed pipeline can produce this
//                                       type.  `fn save(f: SanitizedOutput)`
//                                       is the only compilable save call.
//
//  All stage types are NEWTYPE TUPLE STRUCTS.  Inner data is accessible only
//  via the `let TypeName(inner) = value;` destructuring pattern — never via
//  loose dot-navigation.  This is enforced because the inner fields are
//  private and the types are not Copy.
// ─────────────────────────────────────────────────────────────────────────────

use crate::errors::CdrError;
use png::{BitDepth, ColorType, Encoder};
use zune_core::{bytestream::ZCursor, colorspace::ColorSpace, options::DecoderOptions};
use zune_jpeg::JpegDecoder;

// ─────────────────────────────────────────────────────────────────────────────
//  Internal geometry record (not a stage type — a plain data bag)
// ─────────────────────────────────────────────────────────────────────────────

/// Raw pixel geometry produced by the JPEG decoder and consumed by the PNG
/// encoder.
///
/// ## Field order and layout
/// `#[repr(C)]` pins the field order to the declaration order, making the
/// struct safe to expose through FFI in a future phase without silent
/// reordering.  On a 64-bit target the layout is:
///
/// ```text
/// offset  0: pixels  (Vec<u8>)  — 24 bytes (ptr 8 + len 8 + cap 8)
/// offset 24: width   (u32)      —  4 bytes
/// offset 28: height  (u32)      —  4 bytes
/// total:                          32 bytes, zero padding
/// ```
///
/// Kept private to this module.  Callers never see or touch these fields
/// directly; they are consumed in a single named destructuring at the start
/// of `reconstruct()`.
#[repr(C)]
struct PixelMatrix {
    /// Flat, interleaved RGB bytes; 3 bytes per pixel, row-major.
    pixels: Vec<u8>,
    /// Image width in pixels (widened from JPEG's u16 to u32 for PNG encoder).
    width: u32,
    /// Image height in pixels.
    height: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 0: RawPayload<'a> — newtype tuple struct
// ─────────────────────────────────────────────────────────────────────────────

/// Borrows the caller's raw, untrusted input slice.
///
/// `RawPayload<'a>` is a **newtype tuple struct**.  Its inner `&'a [u8]` is
/// private; the only way to obtain the slice is via the formal destructuring
/// pattern `let RawPayload(bytes) = payload;`.  No dot-access is possible.
///
/// The lifetime `'a` ensures the pipeline cannot outlive the buffer it
/// borrows.  This invariant is enforced by the Rust borrow checker, not by a
/// runtime check.
pub struct RawPayload<'a>(&'a [u8]);

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 1: DisarmedMatrix — newtype tuple struct
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque wrapper around the decoded, metadata-free pixel matrix.
///
/// `DisarmedMatrix` is a **newtype tuple struct**.  The `PixelMatrix` inside
/// is private to this module; it can only be extracted via
/// `let DisarmedMatrix(matrix) = value;`.  There is no public constructor
/// other than the one produced by `JpegPipeline::decode()`.
///
/// This type is the compile-time proof that the JPEG decode step has
/// completed successfully.  No code can construct a `DisarmedMatrix` without
/// going through `decode()`.
pub struct DisarmedMatrix(PixelMatrix);

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 2: PristineStream — newtype tuple struct
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque wrapper around the freshly re-encoded PNG output.
///
/// `PristineStream` is a **newtype tuple struct**.  The `Vec<u8>` inside is
/// private; it can only be extracted via `let PristineStream(bytes) = value;`.
/// There is no public constructor; only `JpegPipeline::reconstruct()` can
/// produce this type.
///
/// The existence of this type is compile-time proof that the PNG re-encode
/// step completed.  It is still an internal pipeline token — callers receive
/// `SanitizedOutput`, not `PristineStream`.
pub struct PristineStream(Vec<u8>);

// ─────────────────────────────────────────────────────────────────────────────
//  Terminal token: SanitizedOutput — the only type a save routine may accept
// ─────────────────────────────────────────────────────────────────────────────

/// The public terminal token produced by a fully completed CDR pipeline.
///
/// `SanitizedOutput` is a **newtype tuple struct**.  The inner `Vec<u8>`
/// is private; callers extract the bytes via the formal pattern
/// `let SanitizedOutput(bytes) = output;` or call `.into_bytes()`.
///
/// ## Signature lockdown
///
/// Any persistence / storage function that should only accept sanitised data
/// **must** declare its parameter as `SanitizedOutput`:
///
/// ```rust,no_run
/// use gatekeeper::sanitizers::jpeg::SanitizedOutput;
///
/// fn save_to_storage(file: SanitizedOutput) {
///     // Extract the bytes via the public API — the inner field is private.
///     let bytes = file.into_bytes();
///     // … write `bytes` to disk / object store …
/// }
/// ```
///
/// Inside the `gatekeeper` crate itself, the formal destructuring pattern
/// `let SanitizedOutput(bytes) = file;` is used instead — see `into_bytes()`.
///
/// It is **structurally impossible** to call `save_to_storage` with a raw
/// `Vec<u8>`, a `RawPayload`, a `DisarmedMatrix`, or any other type —
/// the compiler rejects all such call sites without even running.
#[derive(Debug)]
pub struct SanitizedOutput(Vec<u8>);

impl SanitizedOutput {
    /// Consume the token and return ownership of the sanitised bytes.
    ///
    /// Inside this crate, prefer formal destructuring:
    /// ```text
    /// let SanitizedOutput(bytes) = value;
    /// ```
    /// External callers (and anywhere a `let`-binding is not available) use
    /// this method directly:
    /// ```rust,no_run
    /// # use gatekeeper::sanitizers::jpeg::SanitizedOutput;
    /// # fn get() -> SanitizedOutput { todo!() }
    /// let output: SanitizedOutput = get();
    /// let bytes: Vec<u8> = output.into_bytes();
    /// ```
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        let SanitizedOutput(bytes) = self; // formal destructure — not dot-access
        bytes
    }

    /// **Test-only** constructor that bypasses the pipeline.
    ///
    /// Prefixed `_test_only` to make misuse obvious in code review.
    /// Must not be called in production paths.
    #[cfg(test)]
    pub fn _test_only_new(v: Vec<u8>) -> Self {
        SanitizedOutput(v)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Generic pipeline shell
// ─────────────────────────────────────────────────────────────────────────────

/// Typestate pipeline shell parameterised over the current stage `S`.
///
/// `S` is one of `RawPayload<'a>`, `DisarmedMatrix`, or `PristineStream`.
/// The pipeline holds exactly one value of type `S`; the compiler never
/// allows the wrong stage's data to exist inside the wrong parameterisation.
pub struct JpegPipeline<S> {
    stage: S,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 0 → Stage 1
// ─────────────────────────────────────────────────────────────────────────────

impl<'a> JpegPipeline<RawPayload<'a>> {
    /// Wrap an untrusted input slice in the pipeline.
    ///
    /// # Zero-copy guarantee
    /// `input` is stored as a `&'a [u8]` borrow inside `RawPayload<'a>`.
    /// No bytes are copied.  The compiler tracks the lifetime through the
    /// generic parameter so the pipeline cannot outlive the source buffer.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            stage: RawPayload(input),
        }
    }

    /// Advance from `RawPayload` to `DisarmedMatrix`.
    ///
    /// ## What this does
    /// 1. Extracts the borrowed slice via **formal destructuring**
    ///    `let RawPayload(bytes) = self.stage;`.
    /// 2. Wraps it in a `ZCursor` (zero allocation) for `zune-jpeg`.
    /// 3. Decodes to an interleaved RGB pixel buffer, discarding every JPEG
    ///    structural marker (APP0-APP15, EXIF, ICC, COM, DRI).
    /// 4. Validates pixel-buffer geometry against the decoder-reported
    ///    dimensions.
    /// 5. Wraps the result in `DisarmedMatrix(PixelMatrix { … })`.
    ///
    /// ## Errors
    /// * [`CdrError::JpegDecodeFailed`] — invalid bitstream.
    /// * [`CdrError::MissingImageInfo`] — decoder returned no geometry.
    /// * [`CdrError::DegenerateDimensions`] — zero width or height.
    /// * [`CdrError::PixelBufferMismatch`] — buffer size ≠ geometry.
    pub fn decode(self) -> Result<JpegPipeline<DisarmedMatrix>, CdrError> {
        // ── Formal destructure — no dot-access ───────────────────────────
        let RawPayload(bytes) = self.stage;

        // ── Decoder configuration ─────────────────────────────────────────
        let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGB);

        // `ZCursor::new` borrows `bytes`; no allocation needed.
        let cursor = ZCursor::new(bytes);
        let mut decoder = JpegDecoder::new_with_options(cursor, options);

        // ── Decode: mandatory single allocation ───────────────────────────
        //
        // `decode()` returns a fresh `Vec<u8>` of interleaved RGB triples.
        // All JPEG markers are consumed by the internal DCT engine.
        let pixels = decoder.decode()?;

        // ── Geometry validation ───────────────────────────────────────────
        let info = decoder.info().ok_or(CdrError::MissingImageInfo)?;

        if info.width == 0 || info.height == 0 {
            return Err(CdrError::DegenerateDimensions {
                width: info.width,
                height: info.height,
            });
        }

        // RGB = 3 bytes per pixel.  Checked multiplication to avoid overflow
        // on pathological width × height values.
        let expected = (info.width as usize)
            .checked_mul(info.height as usize)
            .and_then(|n| n.checked_mul(3))
            .unwrap_or(usize::MAX);

        if pixels.len() != expected {
            return Err(CdrError::PixelBufferMismatch {
                expected,
                got: pixels.len(),
            });
        }

        Ok(JpegPipeline {
            stage: DisarmedMatrix(PixelMatrix {
                pixels,
                width: info.width as u32,
                height: info.height as u32,
            }),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 1 → Stage 2
// ─────────────────────────────────────────────────────────────────────────────

impl JpegPipeline<DisarmedMatrix> {
    /// Advance from `DisarmedMatrix` to `PristineStream`.
    ///
    /// Re-encodes the pixel matrix as a lossless PNG.  The encoder is
    /// configured to write exactly IHDR + IDAT + IEND — no metadata.
    ///
    /// ## Errors
    /// Returns [`CdrError::PngEncodeFailed`] on encoder I/O faults.
    pub fn reconstruct(self) -> Result<JpegPipeline<PristineStream>, CdrError> {
        // ── Formal destructure of the stage newtype ───────────────────────
        let DisarmedMatrix(matrix) = self.stage;

        // ── Formal destructure of the inner geometry record ───────────────
        let PixelMatrix {
            pixels,
            width,
            height,
        } = matrix;

        // ── Allocate output buffer ────────────────────────────────────────
        //
        // One allocation for the re-encode leg.  Pre-sized to avoid
        // incremental growth: worst case is uncompressed RGB + chunk framing.
        let cap = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(3)
            .saturating_add(1024);
        let mut output: Vec<u8> = Vec::with_capacity(cap);

        // ── PNG encode ────────────────────────────────────────────────────
        {
            let mut encoder = Encoder::new(&mut output, width, height);
            encoder.set_color(ColorType::Rgb);
            encoder.set_depth(BitDepth::Eight);

            let mut writer = encoder.write_header()?; // emits PNG sig + IHDR
            writer.write_image_data(&pixels)?;         // emits IDAT
        } // ← drop flushes IEND

        Ok(JpegPipeline {
            stage: PristineStream(output),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 2 → SanitizedOutput terminal
// ─────────────────────────────────────────────────────────────────────────────

impl JpegPipeline<PristineStream> {
    /// Consume the terminal pipeline stage and return the public
    /// [`SanitizedOutput`] token.
    ///
    /// Only this method can produce a `SanitizedOutput` in non-test code.
    /// Any function that accepts `SanitizedOutput` as a parameter is therefore
    /// statically proven to only receive data that has completed the full CDR
    /// pipeline.
    ///
    /// ## Formal destructuring
    /// The inner `Vec<u8>` is extracted via `let PristineStream(bytes) = self.stage`
    /// — never via dot-navigation.
    #[must_use]
    pub fn into_sanitized(self) -> SanitizedOutput {
        let PristineStream(bytes) = self.stage; // formal destructure
        SanitizedOutput(bytes)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public convenience entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Sanitise a JPEG byte slice end-to-end, returning a [`SanitizedOutput`] token.
///
/// The caller receives a `SanitizedOutput`, not a raw `Vec<u8>`.  Any storage
/// routine can enforce that it only accepts this token:
///
/// ```rust,no_run
/// use gatekeeper::sanitizers::jpeg::{sanitize_jpeg, SanitizedOutput};
///
/// fn save_to_storage(file: SanitizedOutput) {
///     // into_bytes() is the public API for extracting the clean buffer.
///     let bytes = file.into_bytes();
///     std::fs::write("clean.png", bytes).unwrap();
/// }
///
/// let raw = std::fs::read("suspicious.jpg").unwrap();
/// let clean = sanitize_jpeg(&raw).expect("CDR failed");
/// save_to_storage(clean); // ← only compiles because `clean` is SanitizedOutput
/// ```
///
/// # Errors
/// Propagates any [`CdrError`] from the decode or reconstruct stages.
///
/// [`CdrError`]: crate::errors::CdrError
pub fn sanitize_jpeg(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    Ok(JpegPipeline::new(input)
        .decode()?
        .reconstruct()?
        .into_sanitized())
}
