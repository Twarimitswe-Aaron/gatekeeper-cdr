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
//  JpegPipeline<RawPayload<'a>>     – borrows the caller slice; zero copies
//       │  .decode()
//       ▼
//  JpegPipeline<DisarmedMatrix>     – owns the naked pixel matrix and geometry
//       │  .reconstruct()
//       ▼
//  JpegPipeline<PristineStream>     – owns the output PNG byte vector
//       │  .into_bytes()
//       ▼
//      Vec<u8>                      – caller owns the clean output
//
//  Data lives INSIDE the marker type, not in a shared inner enum.
//  Consequence: every `unreachable!()` guard from the old design is gone.
//  The compiler statically proves that only the correct data variant exists
//  at each stage because the enum no longer exists at all.
// ─────────────────────────────────────────────────────────────────────────────

use crate::errors::CdrError;
use png::{BitDepth, ColorType, Encoder};
use zune_core::{bytestream::ZCursor, colorspace::ColorSpace, options::DecoderOptions};
use zune_jpeg::JpegDecoder;

// ── Typestate marker types — each carries its own data ───────────────────────

/// Stage 0 — borrows the caller's raw, untrusted input slice.
///
/// The lifetime `'a` ties the pipeline to the caller's buffer; no copy is
/// ever made of the input.  The pipeline cannot outlive the slice it borrows.
pub struct RawPayload<'a> {
    /// Immutable borrow of the caller's buffer.  Zero bytes are written.
    pub(crate) bytes: &'a [u8],
}

/// Stage 1 — owns the decoded, metadata-free pixel matrix.
///
/// This is the first and only heap allocation in the decode leg: the pixel
/// buffer returned by `zune-jpeg`.  Every JPEG structural marker
/// (APP0-APP15, COM, DRI, EXIF, ICC) is consumed by the decoder's internal
/// Huffman + DCT engine and is **never** written to this buffer.
pub struct DisarmedMatrix {
    /// Flat, interleaved RGB bytes; 3 bytes per pixel, row-major.
    pixels: Vec<u8>,
    /// Image width in pixels (u16 per JPEG spec; widened to u32 for the PNG
    /// encoder API).
    width: u32,
    /// Image height in pixels.
    height: u32,
}

/// Stage 2 — owns the reconstructed, pristine PNG output stream.
pub struct PristineStream {
    /// A valid PNG byte stream that shares zero bytes with the original input.
    output: Vec<u8>,
}

// ── Generic pipeline shell ────────────────────────────────────────────────────

/// Typestate pipeline shell parameterised over the current stage `S`.
///
/// `S` is not merely a zero-sized marker — it *is* the data for that stage.
/// There is no shared inner enum; the compiler cannot mix stage variants.
pub struct JpegPipeline<S> {
    /// Current stage, carrying its own data.
    stage: S,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 0 → Stage 1: RawPayload → DisarmedMatrix
// ─────────────────────────────────────────────────────────────────────────────

impl<'a> JpegPipeline<RawPayload<'a>> {
    /// Construct the pipeline from a caller-supplied slice.
    ///
    /// # Zero-copy guarantee
    ///
    /// No bytes are copied.  The pipeline stores a `&'a [u8]` borrow that
    /// must remain valid for the duration of the `decode()` call.  The
    /// lifetime `'a` is propagated through the pipeline shell so the Rust
    /// borrow checker enforces this at compile time.
    ///
    /// # Arguments
    /// * `input` — untrusted JPEG bytes, typically a memory-mapped file or a
    ///   network-received buffer.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            stage: RawPayload { bytes: input },
        }
    }

    /// Advance from `RawPayload` to `DisarmedMatrix`.
    ///
    /// Internally this method:
    /// 1. Wraps the borrowed slice in a `ZCursor` — a thin reader that
    ///    satisfies `ZByteReaderTrait` with zero extra allocation.
    /// 2. Configures the decoder to output **RGB** (24-bit) pixels, dropping
    ///    all APP0–APP15, EXIF, ICC, and COM markers automatically.
    /// 3. Validates output geometry against the decoder-reported dimensions.
    ///
    /// # Errors
    /// * [`CdrError::JpegDecodeFailed`] — invalid JPEG bitstream.
    /// * [`CdrError::MissingImageInfo`] — decoder reported no geometry.
    /// * [`CdrError::DegenerateDimensions`] — zero width or height.
    /// * [`CdrError::PixelBufferMismatch`] — pixel count inconsistent with geometry.
    pub fn decode(self) -> Result<JpegPipeline<DisarmedMatrix>, CdrError> {
        let bytes: &[u8] = self.stage.bytes;

        // ── Build decoder with strict RGB output colorspace ───────────────
        //
        // `ColorSpace::RGB` forces 3-channel interleaved output regardless of
        // the source encoding (greyscale, YCbCr 4:2:0, CMYK, etc.), giving
        // the re-encoder a single, predictable buffer layout.
        let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGB);

        // `ZCursor::new` accepts `&[u8]` directly — no `.to_vec()` needed.
        // The cursor borrows `bytes` for the duration of `decode()`.
        let cursor = ZCursor::new(bytes);
        let mut decoder = JpegDecoder::new_with_options(cursor, options);

        // ── Decode pixel data ─────────────────────────────────────────────
        //
        // `decode()` returns a fresh Vec<u8> of interleaved RGB triples.
        // This is the mandatory allocation: pixel data must live somewhere.
        // All JPEG markers are consumed internally; none reach the output.
        let pixels = decoder.decode()?;

        // ── Extract and validate geometry ─────────────────────────────────
        let info = decoder.info().ok_or(CdrError::MissingImageInfo)?;

        if info.width == 0 || info.height == 0 {
            return Err(CdrError::DegenerateDimensions {
                width: info.width,
                height: info.height,
            });
        }

        // RGB = 3 bytes per pixel.  Use checked arithmetic to guard against
        // astronomically large dimensions producing overflow.
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
            stage: DisarmedMatrix {
                pixels,
                width: info.width as u32,
                height: info.height as u32,
            },
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
    /// because:
    ///   - It is lossless: every pixel value is preserved bit-for-bit.
    ///   - A freshly encoded PNG contains exactly IHDR + IDAT + IEND — the
    ///     structural minimum.
    ///   - The `png` encoder never injects EXIF, ICC, or XMP metadata unless
    ///     explicitly requested (we never do).
    ///
    /// # Errors
    /// Returns [`CdrError::PngEncodeFailed`] on encoder faults.
    pub fn reconstruct(self) -> Result<JpegPipeline<PristineStream>, CdrError> {
        let DisarmedMatrix {
            pixels,
            width,
            height,
        } = self.stage;

        // ── Allocate the output buffer ────────────────────────────────────
        //
        // This is the only allocation in the reconstruction leg.
        // Pre-size to avoid incremental reallocations during PNG framing.
        // Upper bound: uncompressed RGB data + PNG chunk overhead.
        let approx_capacity = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(3)
            .saturating_add(1024);
        let mut output: Vec<u8> = Vec::with_capacity(approx_capacity);

        // ── Configure and run PNG encoder ─────────────────────────────────
        //
        // Write directly into the Vec<u8> (impl Write).
        // No file handle, no temp file, no extra system calls.
        {
            let mut encoder = Encoder::new(&mut output, width, height);
            encoder.set_color(ColorType::Rgb);
            encoder.set_depth(BitDepth::Eight);

            // write_header() emits the PNG signature and IHDR chunk.
            // write_image_data() emits IDAT chunk(s).
            // Dropping `writer` emits the IEND chunk.
            let mut writer = encoder.write_header()?;
            writer.write_image_data(&pixels)?;
        } // ← IEND flushed here

        Ok(JpegPipeline {
            stage: PristineStream { output },
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 2 – PristineStream terminal
// ─────────────────────────────────────────────────────────────────────────────

impl JpegPipeline<PristineStream> {
    /// Consume the terminal stage and transfer ownership of the sanitised
    /// output bytes to the caller.
    ///
    /// The returned `Vec<u8>` is a valid, self-contained PNG.  It shares
    /// **zero** bytes with the original JPEG input and contains no metadata.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.stage.output
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public convenience entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Sanitise a JPEG byte slice end-to-end in a single call.
///
/// Chains all three pipeline stages:
///   1. `JpegPipeline::<RawPayload>::new(input)` — zero-copy borrow.
///   2. `.decode()`                               — decode to pixel matrix.
///   3. `.reconstruct()`                          — re-encode as PNG.
///   4. `.into_bytes()`                           — transfer output ownership.
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
    Ok(JpegPipeline::new(input).decode()?.reconstruct()?.into_bytes())
}
