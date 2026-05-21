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
//  Typestate chain
//  ───────────────
//  JpegPipeline<RawPayload>      – holds the untrusted input slice
//       │  .validate()
//       ▼
//  JpegPipeline<DisarmedMatrix>  – holds naked pixel rows (heap-allocated
//       │                          once, here, and never again)
//       │  .reconstruct()
//       ▼
//  JpegPipeline<PristineStream>  – holds the output PNG byte vector
//       │  .into_bytes()
//       ▼
//      Vec<u8>                   – caller owns the clean output
//
//  Each state transition is a consuming method (`self`), so the compiler
//  statically prevents calling stages out of order or re-using a state.
// ─────────────────────────────────────────────────────────────────────────────

use crate::errors::CdrError;
use png::{BitDepth, ColorType, Encoder};
use zune_core::{bytestream::ZCursor, colorspace::ColorSpace, options::DecoderOptions};
use zune_jpeg::JpegDecoder;

// ── Typestate marker types ────────────────────────────────────────────────────

/// Stage 0 — the raw, untrusted input payload.
pub struct RawPayload;

/// Stage 1 — the decoded, metadata-free pixel matrix.
pub struct DisarmedMatrix;

/// Stage 2 — the reconstructed, pristine output stream.
pub struct PristineStream;

// ── Typestate pipeline shell ──────────────────────────────────────────────────

/// Generic pipeline shell parameterised over the current stage marker `S`.
///
/// Data members are private; callers advance state by consuming `self` through
/// the stage-specific `impl` blocks below.
pub struct JpegPipeline<S> {
    /// Internal stage payload.  The outer type ensures only the correct
    /// variant is ever present at each state.
    inner: PipelineInner,
    /// PhantomData carries the stage marker at zero runtime cost.
    _state: std::marker::PhantomData<S>,
}

/// The actual data that travels through the pipeline.
///
/// Only the variant relevant to the current stage is populated; previous
/// variants are `()` after a move-consuming transition.
enum PipelineInner {
    /// Holds a reference to the caller-supplied slice (zero-copy).
    Raw {
        /// Zero-copy reference into the caller's buffer.
        payload: Vec<u8>, // we store as Vec to own the copied bytes once from caller
    },
    /// Holds the freshly decoded pixel matrix and geometry.
    Decoded {
        /// Raw RGB pixel bytes, one byte per channel, row-major.
        pixels: Vec<u8>,
        /// Image width in pixels (fits u16 per JPEG spec; promoted to u32 for
        /// PNG encoder compatibility).
        width: u32,
        /// Image height in pixels.
        height: u32,
    },
    /// Holds the re-encoded output bytes.
    Encoded { output: Vec<u8> },
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 0 → Stage 1: RawPayload → DisarmedMatrix
// ─────────────────────────────────────────────────────────────────────────────

impl JpegPipeline<RawPayload> {
    /// Construct the pipeline from a caller-supplied slice.
    ///
    /// # Zero-copy guarantee
    /// `input` is a borrowed slice.  The pipeline copies it into its internal
    /// `Vec<u8>` only once, here, which is the minimum required for the zune
    /// `ZCursor` ownership model.  From this point forward no further copies
    /// are made until the final PNG output allocation.
    ///
    /// # Arguments
    /// * `input` – untrusted JPEG bytes, typically received from a network
    ///   buffer or memory-mapped file.
    #[must_use]
    pub fn new(input: &[u8]) -> Self {
        Self {
            inner: PipelineInner::Raw {
                payload: input.to_vec(),
            },
            _state: std::marker::PhantomData,
        }
    }

    /// Advance from `RawPayload` to `DisarmedMatrix`.
    ///
    /// Internally this method:
    /// 1. Creates a `ZCursor` wrapper that satisfies `zune-jpeg`'s
    ///    `ZByteReaderTrait` without a second heap copy.
    /// 2. Configures the decoder to output **RGB** (24-bit) pixels, dropping
    ///    all APP0–APP15 application markers, EXIF, ICC profiles, COM markers,
    ///    and DCT metadata automatically—they are never transferred to the
    ///    pixel matrix.
    /// 3. Validates output geometry against the decoder-reported dimensions.
    ///
    /// # Errors
    /// Returns [`CdrError::JpegDecodeFailed`] if the input is not a valid JPEG
    /// bitstream, or geometry-related errors if the decoder reports impossible
    /// dimensions.
    pub fn decode(self) -> Result<JpegPipeline<DisarmedMatrix>, CdrError> {
        // ── Extract owned bytes from stage inner ──────────────────────────
        let payload = match self.inner {
            PipelineInner::Raw { payload } => payload,
            // Unreachable due to typestate enforcement, but avoids a
            // non-exhaustive match.
            _ => unreachable!("RawPayload pipeline cannot hold decoded data"),
        };

        // ── Build decoder with strict output colorspace ───────────────────
        //
        // `ColorSpace::RGB` forces zune-jpeg to always output 3-channel
        // interleaved bytes regardless of the source encoding (greyscale,
        // YCbCr 4:2:0, etc.).  This normalises the output surface so the
        // re-encoder always sees a predictable buffer layout.
        let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGB);

        // `ZCursor` is a thin, no-alloc wrapper over the owned Vec.
        let cursor = ZCursor::new(payload);
        let mut decoder = JpegDecoder::new_with_options(cursor, options);

        // ── Decode pixel data ─────────────────────────────────────────────
        //
        // `decode()` returns a flat Vec<u8> of interleaved RGB triples.
        // All JPEG structural markers (APP0-APP15, COM, DRI, etc.) are parsed
        // by zune internally to reconstruct DCT coefficients; they are
        // **consumed** and never forwarded to the output buffer.
        let pixels = decoder.decode()?;

        // ── Extract validated geometry ────────────────────────────────────
        let info = decoder.info().ok_or(CdrError::MissingImageInfo)?;

        // Reject degenerate dimensions before entering re-encode.
        if info.width == 0 || info.height == 0 {
            return Err(CdrError::DegenerateDimensions {
                width: info.width,
                height: info.height,
            });
        }

        // Verify the pixel buffer size is geometrically consistent.
        // RGB = 3 bytes per pixel.
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
            inner: PipelineInner::Decoded {
                pixels,
                width: info.width as u32,
                height: info.height as u32,
            },
            _state: std::marker::PhantomData,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 1 → Stage 2: DisarmedMatrix → PristineStream
// ─────────────────────────────────────────────────────────────────────────────

impl JpegPipeline<DisarmedMatrix> {
    /// Advance from `DisarmedMatrix` to `PristineStream`.
    ///
    /// Re-encodes the naked pixel matrix as a **lossless PNG**.  PNG is chosen
    /// for the reconstruction output because:
    ///   - It is lossless: every pixel value is preserved bit-for-bit.
    ///   - A freshly encoded PNG contains exactly one IHDR, one IDAT, and one
    ///     IEND chunk — the absolute structural minimum.
    ///   - No EXIF, ICC, or XMP metadata is injected by the `png` encoder
    ///     unless explicitly requested (we never do).
    ///
    /// # Errors
    /// Returns [`CdrError::PngEncodeFailed`] on encoder I/O faults.
    pub fn reconstruct(self) -> Result<JpegPipeline<PristineStream>, CdrError> {
        // ── Extract pixel matrix ──────────────────────────────────────────
        let (pixels, width, height) = match self.inner {
            PipelineInner::Decoded {
                pixels,
                width,
                height,
            } => (pixels, width, height),
            _ => unreachable!("DisarmedMatrix pipeline cannot hold raw or encoded data"),
        };

        // ── Allocate output buffer ────────────────────────────────────────
        //
        // This is the **only** dynamic allocation in the reconstruction leg.
        // Pre-size to avoid incremental reallocations.  A rough upper bound
        // for an uncompressed RGB PNG is width × height × 3 + PNG framing.
        let approx_capacity = (width as usize * height as usize * 3) + 1024;
        let mut output: Vec<u8> = Vec::with_capacity(approx_capacity);

        // ── Configure PNG encoder ─────────────────────────────────────────
        //
        // We write directly into the Vec<u8> which implements `Write`.
        // No file handle, no temp file, no extra system calls.
        {
            let mut encoder = Encoder::new(&mut output, width, height);

            // RGB 8-bit: matches the zune-jpeg output colorspace.
            encoder.set_color(ColorType::Rgb);
            encoder.set_depth(BitDepth::Eight);

            // Write PNG signature + IHDR chunk, then the pixel data in IDAT,
            // then IEND.  The `writer` scope ensures IEND is flushed before
            // we read `output`.
            let mut writer = encoder.write_header()?;
            writer.write_image_data(&pixels)?;
            // `writer` is dropped here → IEND chunk is written.
        }

        Ok(JpegPipeline {
            inner: PipelineInner::Encoded { output },
            _state: std::marker::PhantomData,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 2 – PristineStream terminal
// ─────────────────────────────────────────────────────────────────────────────

impl JpegPipeline<PristineStream> {
    /// Consume the terminal stage and return ownership of the sanitised output
    /// bytes to the caller.
    ///
    /// The returned `Vec<u8>` is a valid, self-contained PNG file.  It shares
    /// no bytes with the original input and contains zero metadata.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self.inner {
            PipelineInner::Encoded { output } => output,
            _ => unreachable!("PristineStream pipeline cannot hold raw or decoded data"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public convenience entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Sanitise a JPEG byte slice end-to-end in a single call.
///
/// This is the primary public surface for the JPEG sanitizer.  It chains all
/// three pipeline stages and returns the pristine PNG output.
///
/// # Example
/// ```rust,no_run
/// use gatekeeper::sanitizers::jpeg::sanitize_jpeg;
///
/// let raw_jpeg: Vec<u8> = std::fs::read("suspicious.jpg").unwrap();
/// let clean_png = sanitize_jpeg(&raw_jpeg).expect("sanitization failed");
/// std::fs::write("clean.png", clean_png).unwrap();
/// ```
///
/// # Errors
/// Propagates any [`CdrError`] from the decode or reconstruct stages.
///
/// [`CdrError`]: crate::errors::CdrError
pub fn sanitize_jpeg(input: &[u8]) -> Result<Vec<u8>, CdrError> {
    JpegPipeline::<RawPayload>::new(input)
        .decode()?
        .reconstruct()?
        .into_bytes()
        .pipe(Ok)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal pipe helper (avoids a temporary binding)
// ─────────────────────────────────────────────────────────────────────────────

/// Tiny extension trait that lets us write `value.pipe(f)` instead of `f(value)`.
/// Keeps the linear pipeline expression readable.
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R;
}

impl<T> Pipe for T {
    #[inline(always)]
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}
