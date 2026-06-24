// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: sanitizers :: png
//
//  PNG Content Disarm and Reconstruction pipeline.
//
//  ┌─────────────────────────────────────────────────────────────────────────┐
//  │  Threat model                                                           │
//  │                                                                         │
//  │  A PNG file may carry:                                                  │
//  │    • Arbitrary metadata in tEXt / iTXt / zTXt text chunks              │
//  │    • GPS / author PII in tEXt key–value pairs                           │
//  │    • ICC colour profiles with embedded executables (iCCP chunk)        │
//  │    • Steganographic payloads in ancillary chunks (bKGD, hIST, sPLT…)   │
//  │    • Trailing bytes after the IEND chunk (polyglot containers)          │
//  │    • Malformed chunk lengths designed to trigger decoder bugs           │
//  │                                                                         │
//  │  Mitigation: never scrub in-place.  Fully decode to raw RGBA/RGB        │
//  │  pixels, then re-encode from scratch.  The output shares ZERO bytes    │
//  │  with the input — only IHDR + IDAT + IEND are written.                 │
//  └─────────────────────────────────────────────────────────────────────────┘
//
//  Public API surface
//  ───────────────────
//
//  RawPngPayload<'a>(&'a [u8])       – borrows untrusted input; zero copies
//       │  constructor: RawPngPayload::new(&bytes)?  validates PNG sig + IHDR
//       │  consuming:   .sanitize()                  drives the full CDR pipeline
//       │
//  ──── internal pipeline machinery ─────────────────────────────────────────
//
//  PngPipeline<RawPngPayload<'a>>    – pipeline entry wrapping the borrow
//       │  .decode()                 – png crate strips all ancillary chunks
//       ▼
//  PngPipeline<DisarmedPngMatrix>    – opaque wrapper; carries only raw pixels
//       │  .reconstruct()            – PNG encoder writes IHDR + IDAT + IEND
//       ▼
//  PngPipeline<PristinePngStream>    – opaque wrapper; shares zero bytes with input
//       │  .into_sanitized()
//       ▼
//  SanitizedOutput(Vec<u8>)          – shared terminal token from jpeg module
//
//  All stage types are NEWTYPE TUPLE STRUCTS.  Inner data is accessible only
//  via the `let TypeName(inner) = value;` destructuring pattern — never via
//  loose dot-navigation.  This is enforced because the inner fields are
//  private and the types are not Copy.
// ─────────────────────────────────────────────────────────────────────────────

use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;
use png::{BitDepth, ColorType, Compression, Decoder, Encoder, FilterType};

// ─────────────────────────────────────────────────────────────────────────────
//  PNG magic byte constants (module-private, stack-allocated)
// ─────────────────────────────────────────────────────────────────────────────

/// PNG file signature — all 8 bytes (ISO/IEC 15948:2004 §5.2).
const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// IHDR chunk type identifier (ASCII "IHDR").
const PNG_IHDR: [u8; 4] = [0x49, 0x48, 0x44, 0x52];

/// Minimum byte length required to validate a PNG signature.
/// 8-byte sig + 4-byte IHDR length + 4-byte IHDR type = 16 bytes.
const MIN_PNG_LEN: usize = 16;

/// Maximum allowed width or height per axis.
///
/// 16 384 px per side covers 16K resolution images, well above any
/// real-world upload whilst preventing integer-overflow in geometry
/// arithmetic.  A 16384×16384 RGBA image would be 1 GiB — caught next
/// by the pixel-budget guard before any allocation is made.
const MAX_DIMENSION: u32 = 16_384;

/// Maximum allowed decoded pixel buffer size (decompression bomb guard).
///
/// 256 MiB accommodates a 9102×9102 RGBA image — generous for uploads
/// but hard enough to prevent multi-gigabyte allocation attacks.
/// This limit is checked against the computed geometry, before the
/// `vec!` initialisation, so no allocation occurs on rejection.
const MAX_PIXEL_BYTES: usize = 256 * 1024 * 1024; // 256 MiB

/// Maximum allowed compressed input size.
///
/// 32 MiB is a generous ceiling for real-world PNG uploads.  The check
/// fires in `RawPngPayload::new()` — before any decoder work begins — so
/// a multi-gigabyte malicious upload never reaches the parser.
const MAX_COMPRESSED_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

// ─────────────────────────────────────────────────────────────────────────────
//  Internal geometry record (module-private, not a stage type)
// ─────────────────────────────────────────────────────────────────────────────

/// Raw pixel geometry produced by the PNG decoder and consumed by the encoder.
///
/// ## Field order and layout
/// `#[repr(C)]` pins the field order to the declaration order, making the
/// struct safe to expose through FFI in a future phase without silent
/// reordering.  On a 64-bit target the layout is:
///
/// ```text
/// offset  0: pixels     (Vec<u8>)    — 24 bytes (ptr 8 + len 8 + cap 8)
/// offset 24: width      (u32)        —  4 bytes
/// offset 28: height     (u32)        —  4 bytes
/// offset 32: color_type (ColorType)  —  1 byte, padded to 4 by alignment
/// offset 36: bit_depth  (BitDepth)   —  1 byte, padded to 4 by alignment
/// total:                               40 bytes
/// ```
///
/// Kept private to this module.  Callers never see or touch these fields
/// directly; they are consumed in a single named destructuring at the start
/// of `reconstruct()`.
#[repr(C)]
struct PngPixelMatrix {
    /// Flat, interleaved pixel bytes; channel count depends on `color_type`.
    pixels: Vec<u8>,
    /// Image width in pixels.
    width: u32,
    /// Image height in pixels.
    height: u32,
    /// Color type as reported by the decoder (RGB, RGBA, Grayscale, etc.).
    color_type: ColorType,
    /// Bit depth as reported by the decoder.
    bit_depth: BitDepth,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 0: RawPngPayload<'a> — newtype tuple struct
// ─────────────────────────────────────────────────────────────────────────────

/// Borrows the caller's raw, untrusted PNG input slice.
///
/// `RawPngPayload<'a>` is a **newtype tuple struct**.  Its inner `&'a [u8]` is
/// private; the only way to obtain the slice is via the formal destructuring
/// pattern `let RawPngPayload(bytes) = payload;`.  No dot-access is possible.
///
/// The lifetime `'a` ensures the pipeline cannot outlive the buffer it borrows.
///
/// ## Construction
/// Use [`RawPngPayload::new`] — it validates the PNG signature and IHDR chunk
/// presence before wrapping the slice.
///
/// ## Consumption
/// Call [`RawPngPayload::sanitize`] to drive the full CDR pipeline.
pub struct RawPngPayload<'a>(&'a [u8]);

impl<'a> RawPngPayload<'a> {
    /// Validate PNG magic bytes and wrap the input slice in `RawPngPayload<'a>`.
    ///
    /// ## What this validates
    /// 1. **Maximum size** — `input` must not exceed [`MAX_COMPRESSED_BYTES`] (32 MiB).
    /// 2. **Minimum length** — `input` must be at least [`MIN_PNG_LEN`] (16) bytes.
    /// 3. **PNG signature** — `input[0..8]` must equal the 8-byte PNG signature.
    /// 4. **IHDR presence** — `input[12..16]` must equal `b"IHDR"`, confirming the
    ///    first chunk is well-formed.
    ///
    /// ## Zero-copy guarantee
    /// `new` borrows `input` without copying any bytes.  All four checks
    /// resolve against the caller's existing buffer; no heap allocation occurs.
    ///
    /// ## Errors
    /// * [`CdrError::PayloadTooLarge`] — input larger than [`MAX_COMPRESSED_BYTES`].
    /// * [`CdrError::PayloadTooShort`] — input shorter than [`MIN_PNG_LEN`] bytes.
    /// * [`CdrError::UnknownFormat`]   — PNG signature absent.
    /// * [`CdrError::PngMissingIhdr`]  — IHDR chunk absent at offset 12.
    ///
    /// # Example
    /// ```rust,no_run
    /// use gatekeeper::sanitizers::png::RawPngPayload;
    ///
    /// let bytes = std::fs::read("suspicious.png").unwrap();
    /// let payload = RawPngPayload::new(&bytes).expect("not a valid PNG");
    /// ```
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        // ── Guard: maximum compressed input size ──────────────────────────
        //
        // Fires FIRST — before length or magic checks — so a multi-gigabyte
        // upload never reaches the PNG parser at all.
        if input.len() > MAX_COMPRESSED_BYTES {
            return Err(CdrError::PayloadTooLarge {
                got: input.len(),
                limit: MAX_COMPRESSED_BYTES,
            });
        }

        // ── Guard: minimum length ─────────────────────────────────────────
        if input.len() < MIN_PNG_LEN {
            return Err(CdrError::PayloadTooShort { got: input.len() });
        }

        // ── Guard: PNG signature — 8-byte slice equality, zero copy ───────
        if input[..8] != PNG_SIG {
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&input[..4]);
            return Err(CdrError::UnknownFormat { magic });
        }

        // ── Guard: IHDR chunk type at bytes 12–15 ─────────────────────────
        //
        // The PNG spec mandates that the first chunk after the 8-byte
        // signature is always IHDR (bytes 8–11 are the chunk length,
        // bytes 12–15 are the chunk type).  A missing or corrupted IHDR
        // is a strong indicator of file tampering.
        if input[12..16] != PNG_IHDR {
            return Err(CdrError::PngMissingIhdr);
        }

        Ok(Self(input))
    }

    /// Run the full CDR pipeline and return a [`SanitizedOutput`] terminal token.
    ///
    /// ## Ownership semantics
    /// `sanitize` takes `self` **by value**.  Once called, the original
    /// `RawPngPayload` is moved and permanently destroyed — the borrow
    /// checker prevents any further use.
    ///
    /// ## Pipeline steps
    /// 1. Feeds the borrowed slice into `PngPipeline::new()` (zero copy).
    /// 2. `decode()` passes the slice to the `png` crate via an in-memory
    ///    reader.  The decoder discards every ancillary chunk (tEXt, iTXt,
    ///    iCCP, bKGD, hIST, etc.) and returns raw pixel bytes.
    /// 3. `reconstruct()` re-encodes the pixel buffer as a clean PNG
    ///    containing only IHDR + IDAT + IEND — no metadata.
    /// 4. `into_sanitized()` wraps the PNG buffer in `SanitizedOutput`.
    ///
    /// ## Errors
    /// Propagates any [`CdrError`] from the decode or reconstruct stages.
    ///
    /// # Example
    /// ```rust,no_run
    /// use gatekeeper::sanitizers::png::RawPngPayload;
    ///
    /// let bytes = std::fs::read("suspicious.png").unwrap();
    /// let clean = RawPngPayload::new(&bytes)
    ///     .expect("not a valid PNG")
    ///     .sanitize()
    ///     .expect("CDR pipeline failed");
    /// std::fs::write("clean.png", clean.into_bytes()).unwrap();
    /// ```
    pub fn sanitize(self) -> Result<SanitizedOutput, CdrError> {
        // Formal destructure — extracts the inner &'a [u8] without dot-access.
        let RawPngPayload(bytes) = self;
        Ok(PngPipeline::new(bytes)
            .decode()?
            .reconstruct()?
            .into_sanitized())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 1: DisarmedPngMatrix — newtype tuple struct
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque wrapper around the decoded, metadata-free PNG pixel matrix.
///
/// `DisarmedPngMatrix` is a **newtype tuple struct**.  The `PngPixelMatrix`
/// inside is private; it can only be extracted via
/// `let DisarmedPngMatrix(matrix) = value;`.
///
/// This type is the compile-time proof that the PNG decode step has
/// completed successfully.  No code can construct a `DisarmedPngMatrix`
/// without going through `PngPipeline::decode()`.
pub struct DisarmedPngMatrix(PngPixelMatrix);

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 2: PristinePngStream — newtype tuple struct
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque wrapper around the freshly re-encoded PNG output.
///
/// `PristinePngStream` is a **newtype tuple struct**.  The `Vec<u8>` inside is
/// private; it can only be extracted via `let PristinePngStream(bytes) = value;`.
/// Only `PngPipeline::reconstruct()` can produce this type.
///
/// The existence of this type is compile-time proof that the PNG re-encode
/// step completed.  Callers receive `SanitizedOutput`, not `PristinePngStream`.
pub struct PristinePngStream(Vec<u8>);

// ─────────────────────────────────────────────────────────────────────────────
//  Generic pipeline shell
// ─────────────────────────────────────────────────────────────────────────────

/// Typestate pipeline shell parameterised over the current stage `S`.
///
/// `S` is one of `RawPngPayload<'a>`, `DisarmedPngMatrix`, or `PristinePngStream`.
pub struct PngPipeline<S> {
    stage: S,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 0 → Stage 1
// ─────────────────────────────────────────────────────────────────────────────

impl<'a> PngPipeline<RawPngPayload<'a>> {
    /// Wrap an untrusted input slice in the pipeline.
    ///
    /// # Zero-copy guarantee
    /// `input` is stored as a `&'a [u8]` borrow inside `RawPngPayload<'a>`.
    /// No bytes are copied.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            stage: RawPngPayload(input),
        }
    }

    /// Advance from `RawPngPayload` to `DisarmedPngMatrix`.
    ///
    /// ## What this does
    /// 1. Extracts the borrowed slice via **formal destructuring**.
    /// 2. Wraps it in a `std::io::Cursor` (zero allocation) for the `png` crate.
    /// 3. Decodes to a flat pixel buffer, discarding every ancillary chunk.
    /// 4. Validates pixel-buffer geometry against decoder-reported dimensions.
    /// 5. Wraps the result in `DisarmedPngMatrix(PngPixelMatrix { … })`.
    ///
    /// ## Errors
    /// * [`CdrError::PngDecodeFailed`]    — invalid or corrupt PNG bitstream.
    /// * [`CdrError::MissingImageInfo`]   — decoder returned no output info.
    /// * [`CdrError::DegenerateDimensions`] — zero width or height.
    /// * [`CdrError::PixelBufferMismatch`]  — buffer size ≠ geometry.
    pub fn decode(self) -> Result<PngPipeline<DisarmedPngMatrix>, CdrError> {
        // ── Formal destructure — no dot-access ───────────────────────────
        let RawPngPayload(bytes) = self.stage;

        // ── Decoder setup ─────────────────────────────────────────────────
        //
        // `std::io::Cursor` wraps the borrowed slice so the `png` crate can
        // use it as a `Read` source.  No heap allocation; the cursor is a
        // stack-allocated (ptr, position) pair.
        let cursor = std::io::Cursor::new(bytes);
        let decoder = Decoder::new(cursor);

        // `read_info()` parses all chunks up to the first IDAT.  Ancillary
        // chunks (tEXt, iTXt, iCCP, bKGD, hIST, etc.) are discarded by the
        // `png` crate before pixel data is read.
        //
        // RESIDUAL SURFACE: the `png` 0.17 crate processes zTXt and iCCP
        // chunks (which involve zlib decompression) before IDAT is reached.
        // Hostile ancillary chunks could burn parser CPU before geometry
        // guards fire.  The `png` 0.17 public API does not expose a way to
        // suppress ancillary-chunk parsing entirely; this is a known residual
        // risk documented for tracking.  The MAX_COMPRESSED_BYTES input cap
        // (32 MiB) bounds the worst-case decompression work to a finite
        // amount proportional to the compressed input size.
        let mut reader = decoder
            .read_info()
            .map_err(|e| CdrError::PngDecodeFailed { source: e })?;

        // ── Geometry validation ───────────────────────────────────────────
        let info = reader.info();

        // G4: PNG widths are u32 natively — no cast needed, no truncation risk.
        if info.width == 0 || info.height == 0 {
            return Err(CdrError::DegenerateDimensions {
                width: info.width,
                height: info.height,
            });
        }

        // G2: per-axis dimension cap — fires before the budget multiplication.
        if info.width > MAX_DIMENSION || info.height > MAX_DIMENSION {
            return Err(CdrError::DimensionTooLarge {
                dimension: info.width.max(info.height),
                limit: MAX_DIMENSION,
            });
        }

        let color_type = info.color_type;
        let bit_depth = info.bit_depth;
        let width = info.width;
        let height = info.height;

        // Compute our expected byte count from the decoder-reported geometry.
        let channels: usize = color_type.samples();
        let bits: usize = bit_depth as usize;
        let bytes_per_row = (width as usize)
            .saturating_mul(channels)
            .saturating_mul(bits)
            .saturating_add(7)
            / 8; // round up for < 8-bit depths

        let expected = bytes_per_row.saturating_mul(height as usize);

        // G1: decompression bomb guard — reject before any allocation.
        if expected > MAX_PIXEL_BYTES {
            return Err(CdrError::ImageTooLarge {
                bytes: expected,
                limit: MAX_PIXEL_BYTES,
            });
        }

        // G3 fix: cross-check our manual geometry calculation against the
        // decoder's own `output_buffer_size()`.  If they disagree the file
        // has internally inconsistent geometry — reject it.
        //
        // This replaces the previous dead assertion
        //   `if pixels.len() != expected { ... }`
        // which could never fire because `vec![0u8; expected]` sets
        // `.len() == expected` by construction before next_frame is called.
        let decoder_expected = reader.output_buffer_size();
        if decoder_expected != expected {
            return Err(CdrError::PixelBufferMismatch {
                expected,
                got: decoder_expected,
            });
        }

        // ── Decode: mandatory single allocation ───────────────────────────
        //
        // `next_frame` requires a &mut [u8] of exactly `output_buffer_size()`
        // bytes.  We've confirmed expected == decoder_expected above.
        let mut pixels = vec![0u8; expected];
        reader
            .next_frame(&mut pixels)
            .map_err(|e| CdrError::PngDecodeFailed { source: e })?;
        // pixels.len() == expected by construction — no further assertion needed.

        Ok(PngPipeline {
            stage: DisarmedPngMatrix(PngPixelMatrix {
                pixels,
                width,
                height,
                color_type,
                bit_depth,
            }),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 1 → Stage 2
// ─────────────────────────────────────────────────────────────────────────────

impl PngPipeline<DisarmedPngMatrix> {
    /// Advance from `DisarmedPngMatrix` to `PristinePngStream`.
    ///
    /// Re-encodes the pixel matrix as a lossless PNG.  The encoder is
    /// configured to write exactly IHDR + IDAT + IEND — no metadata.
    ///
    /// ## Errors
    /// Returns [`CdrError::PngEncodeFailed`] on encoder I/O faults.
    pub fn reconstruct(self) -> Result<PngPipeline<PristinePngStream>, CdrError> {
        // ── Formal destructure of the stage newtype ───────────────────────
        let DisarmedPngMatrix(matrix) = self.stage;

        // ── Formal destructure of the inner geometry record ───────────────
        let PngPixelMatrix {
            pixels,
            width,
            height,
            color_type,
            bit_depth,
        } = matrix;

        // ── Allocate output buffer ────────────────────────────────────────
        //
        // One allocation for the re-encode leg.  Pre-sized to the raw pixel
        // count (worst case for uncompressed) plus 1 KiB for chunk framing.
        let channels: usize = color_type.samples();
        let cap = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(channels)
            .saturating_add(1024);
        let mut output: Vec<u8> = Vec::with_capacity(cap);

        // ── PNG encode ────────────────────────────────────────────────────
        {
            let mut encoder = Encoder::new(&mut output, width, height);
            encoder.set_color(color_type);
            encoder.set_depth(bit_depth);
            encoder.set_compression(Compression::Best);


            let mut writer = encoder
                .write_header()
                .map_err(|e| CdrError::PngEncodeFailed { source: e })?; // emits PNG sig + IHDR
            writer
                .write_image_data(&pixels)
                .map_err(|e| CdrError::PngEncodeFailed { source: e })?; // emits IDAT
        } // ← drop flushes IEND

        Ok(PngPipeline {
            stage: PristinePngStream(output),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 2 → SanitizedOutput terminal
// ─────────────────────────────────────────────────────────────────────────────

impl PngPipeline<PristinePngStream> {
    /// Consume the terminal pipeline stage and return the public
    /// [`SanitizedOutput`] token.
    ///
    /// ## Formal destructuring
    /// The inner `Vec<u8>` is extracted via `let PristinePngStream(bytes) = self.stage`
    /// — never via dot-navigation.
    #[must_use]
    pub fn into_sanitized(self) -> SanitizedOutput {
        let PristinePngStream(bytes) = self.stage; // formal destructure
        // SAFETY: SanitizedOutput's constructor is pub(crate) within this crate.
        // We share the same crate, so we can call the internal constructor directly.
        // The bytes here went through the full CDR pipeline: decode + re-encode.
        SanitizedOutput::_crate_new(bytes)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public convenience entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Sanitise a PNG byte slice end-to-end, returning a [`SanitizedOutput`] token.
///
/// This is a convenience wrapper over [`RawPngPayload::new`] and
/// [`RawPngPayload::sanitize`].
///
/// ```rust,no_run
/// use gatekeeper::sanitizers::png::sanitize_png;
///
/// let raw = std::fs::read("suspicious.png").unwrap();
/// let clean = sanitize_png(&raw).expect("CDR failed");
/// std::fs::write("clean.png", clean.into_bytes()).unwrap();
/// ```
///
/// # Errors
/// Propagates any [`CdrError`] from [`RawPngPayload::new`] or
/// [`RawPngPayload::sanitize`].
///
/// [`CdrError`]: crate::errors::CdrError
pub fn sanitize_png(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    RawPngPayload::new(input)?.sanitize()
}
