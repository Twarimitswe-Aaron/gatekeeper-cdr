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
//  Public API surface
//  ───────────────────
//
//  RawPayload<'a>(&'a [u8])           – borrows untrusted input; zero copies
//       │  constructor: RawPayload::new(&bytes)?  validates SOI + EOI markers
//       │  consuming:   .sanitize()               drives the full CDR pipeline
//       │
//  ──── internal pipeline machinery ────────────────────────────────────────────
//
//  JpegPipeline<RawPayload<'a>>       – pipeline entry wrapping the borrow
//       │  .decode()                  – zune-jpeg strips all metadata markers
//       ▼
//  JpegPipeline<DisarmedMatrix>       – opaque wrapper; carries no JPEG markers
//       │  .reconstruct()             – PNG encoder writes IHDR + IDAT + IEND only
//       ▼
//  JpegPipeline<PristineStream>       – opaque wrapper; shares zero bytes with input
//       │  .into_sanitized()
//       ▼
//  SanitizedOutput(Vec<u8>)           – public terminal token; also exported as
//   aka DisarmedPayload                  DisarmedPayload (Phase 1–3 spec name).
//                                        `fn save(f: DisarmedPayload)` is the
//                                        only compilable save call.
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
//  JPEG magic byte constants (module-private, stack-allocated)
// ─────────────────────────────────────────────────────────────────────────────

/// JPEG Start-Of-Image (SOI) marker.  Every valid JPEG bitstream begins
/// with these two bytes (ISO/IEC 10918-1 §B.1.1).
const SOI: [u8; 2] = [0xFF, 0xD8];

/// JPEG End-Of-Image (EOI) marker.  Every complete JPEG bitstream ends
/// with these two bytes.  Absence of EOI indicates a truncated or
/// polyglot-container file.
const EOI: [u8; 2] = [0xFF, 0xD9];

/// Minimum byte length required to validate a JPEG signature.
/// SOI (2 bytes) + at least one payload byte + EOI (2 bytes) = 5 bytes.
/// We use 4 as the hard floor since a 2-byte SOI and 2-byte EOI with
/// nothing between them is structurally degenerate but parseable.
const MIN_JPEG_LEN: usize = 4;

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
///
/// ## Construction
/// Use [`RawPayload::new`] — it validates the JPEG magic bytes and EOI
/// marker before wrapping the slice.  The constructor is the only way to
/// produce a `RawPayload`; there is no public field and no unsafe bypass.
///
/// ## Consumption
/// Call [`RawPayload::sanitize`] to drive the full CDR pipeline.  `sanitize`
/// takes `self` by value, rendering the original object permanently invalid
/// at compile time — the borrow checker prevents any further use of a
/// consumed `RawPayload`.
pub struct RawPayload<'a>(&'a [u8]);

// ─────────────────────────────────────────────────────────────────────────────
//  RawPayload behaviour: constructor + consuming sanitize()
// ─────────────────────────────────────────────────────────────────────────────

impl<'a> RawPayload<'a> {
    /// Validate JPEG magic bytes and wrap the input slice in `RawPayload<'a>`.
    ///
    /// ## What this validates
    /// 1. **Minimum length** — `input` must be at least [`MIN_JPEG_LEN`] (4) bytes.
    /// 2. **SOI marker** — `input[0..2]` must equal `\xFF\xD8` (JPEG start-of-image).
    /// 3. **EOI marker** — `input[input.len()-2..]` must equal `\xFF\xD9` (JPEG
    ///    end-of-image).  Absence of EOI is a strong indicator of a truncated or
    ///    polyglot-container file.
    ///
    /// ## Zero-copy guarantee
    /// `new` borrows `input` without copying any bytes.  All three checks
    /// resolve against the caller's existing buffer; no heap allocation occurs.
    ///
    /// ## Errors
    /// * [`CdrError::PayloadTooShort`] — input shorter than [`MIN_JPEG_LEN`] bytes.
    /// * [`CdrError::UnknownFormat`]   — SOI marker absent.
    /// * [`CdrError::JpegMissingEoi`]  — EOI marker absent from the tail.
    ///
    /// # Example
    /// ```rust,no_run
    /// use gatekeeper::sanitizers::jpeg::RawPayload;
    ///
    /// let bytes = std::fs::read("suspicious.jpg").unwrap();
    /// let payload = RawPayload::new(&bytes).expect("not a valid JPEG");
    /// ```
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        // ── Guard: minimum length ─────────────────────────────────────────
        if input.len() < MIN_JPEG_LEN {
            return Err(CdrError::PayloadTooShort { got: input.len() });
        }

        // ── Guard: SOI marker — direct subslice equality, zero copy ───────
        //
        // The compiler resolves `input[..2] == SOI` as a 2-byte register
        // comparison; no intermediate buffer is written to the stack.
        if input[..2] != SOI {
            // Capture the first 4 bytes as error context.  We know `input`
            // is at least MIN_JPEG_LEN bytes, so the indexing is safe.
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&input[..4]);
            return Err(CdrError::UnknownFormat { magic });
        }

        // ── Guard: EOI marker — tail check, zero copy ─────────────────────
        //
        // A missing EOI is the primary indicator of a polyglot container
        // (e.g. a JPEG with a ZIP or PDF appended after the image data).
        // Rejecting at this stage prevents the decoder from ever receiving
        // a file with trailing executable bytes.
        let tail = input.len() - 2;
        if input[tail..] != EOI {
            return Err(CdrError::JpegMissingEoi);
        }

        Ok(Self(input))
    }

    /// Run the full CDR pipeline and return a [`DisarmedPayload`] terminal token.
    ///
    /// ## Ownership semantics
    /// `sanitize` takes `self` **by value** (`self`, not `&self` or `&mut self`).
    /// This is an intentional security constraint: once called, the original
    /// `RawPayload` is moved and permanently destroyed.  The Rust compiler
    /// will reject any attempt to use the consumed `RawPayload` after this
    /// call — no runtime check needed.
    ///
    /// ## Pipeline steps
    /// 1. Feeds the borrowed slice into `JpegPipeline::new()` (zero copy).
    /// 2. `decode()` passes the slice to `zune-jpeg` via `ZCursor` (zero
    ///    copy into the decoder).  The decoder discards every APP/EXIF/COM
    ///    marker and returns a flat RGB pixel buffer (one mandatory alloc).
    /// 3. `reconstruct()` re-encodes the pixel buffer as a lossless PNG
    ///    containing only IHDR + IDAT + IEND — no metadata (one alloc).
    /// 4. `into_sanitized()` wraps the PNG buffer in `SanitizedOutput`,
    ///    which is also exported as [`DisarmedPayload`].
    ///
    /// ## Errors
    /// Propagates any [`CdrError`] from the decode or reconstruct stages.
    ///
    /// # Example
    /// ```rust,no_run
    /// use gatekeeper::sanitizers::jpeg::RawPayload;
    ///
    /// let bytes = std::fs::read("suspicious.jpg").unwrap();
    /// let clean = RawPayload::new(&bytes)
    ///     .expect("not a valid JPEG")
    ///     .sanitize()
    ///     .expect("CDR pipeline failed");
    /// std::fs::write("clean.png", clean.into_bytes()).unwrap();
    /// ```
    pub fn sanitize(self) -> Result<DisarmedPayload, CdrError> {
        // Formal destructure — extracts the inner &'a [u8] without dot-access.
        let RawPayload(bytes) = self;
        // Feed into the existing JpegPipeline machinery.  The compiler
        // verifies stage ordering at zero runtime cost.
        Ok(JpegPipeline::new(bytes)
            .decode()?
            .reconstruct()?
            .into_sanitized())
    }
}

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
/// Also exported as [`DisarmedPayload`] — the name used in the Phases 1–3
/// specification.  Both names refer to the identical type.
///
/// ## Signature lockdown
///
/// Any persistence / storage function that should only accept sanitised data
/// **must** declare its parameter as `SanitizedOutput` (or `DisarmedPayload`):
///
/// ```rust,no_run
/// use gatekeeper::sanitizers::jpeg::DisarmedPayload;
///
/// fn save_to_storage(file: DisarmedPayload) {
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

/// Type alias: `DisarmedPayload` is the Phase 1–3 specification name for
/// [`SanitizedOutput`] — the nominal terminal token produced when a `RawPayload`
/// successfully completes the full CDR pipeline.
///
/// Both names refer to the identical type.  `DisarmedPayload` is the
/// ergonomic name for JPEG-pipeline consumers; `SanitizedOutput` is the
/// format-agnostic name used at the crate level in `disarm()`.
///
/// ## Usage
/// ```rust,no_run
/// use gatekeeper::sanitizers::jpeg::{RawPayload, DisarmedPayload};
///
/// fn save(payload: DisarmedPayload) {
///     let bytes = payload.into_bytes();
///     std::fs::write("clean.png", bytes).unwrap();
/// }
///
/// let raw = std::fs::read("untrusted.jpg").unwrap();
/// let clean: DisarmedPayload = RawPayload::new(&raw)
///     .expect("invalid JPEG")
///     .sanitize()
///     .expect("CDR failed");
/// save(clean);
/// ```
pub type DisarmedPayload = SanitizedOutput;

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

/// Sanitise a JPEG byte slice end-to-end, returning a [`DisarmedPayload`] token.
///
/// This is a convenience wrapper over [`RawPayload::new`] and
/// [`RawPayload::sanitize`].  Prefer the method chain when you want to
/// keep a named `RawPayload` binding for clarity:
///
/// ```rust,no_run
/// use gatekeeper::sanitizers::jpeg::{RawPayload, DisarmedPayload};
///
/// // Method chain (explicit, preferred for complex pipelines):
/// let raw = std::fs::read("suspicious.jpg").unwrap();
/// let clean: DisarmedPayload = RawPayload::new(&raw)
///     .expect("invalid JPEG")
///     .sanitize()
///     .expect("CDR failed");
///
/// // Free function (convenient for one-liners):
/// use gatekeeper::sanitizers::jpeg::sanitize_jpeg;
/// let clean2 = sanitize_jpeg(&raw).expect("CDR failed");
/// ```
///
/// # Errors
/// Propagates any [`CdrError`] from [`RawPayload::new`] or
/// [`RawPayload::sanitize`].
///
/// [`CdrError`]: crate::errors::CdrError
pub fn sanitize_jpeg(input: &[u8]) -> Result<DisarmedPayload, CdrError> {
    RawPayload::new(input)?.sanitize()
}
