use crate::errors::CdrError;
use crate::sanitizers::encode::tune_png_encoder;
use crate::sanitizers::jpeg::SanitizedOutput;
use gif::{ColorOutput, DecodeOptions, Encoder as GifEncoder, Frame, Repeat};
use png::{BitDepth, ColorType as PngColorType, Encoder as PngEncoder};

const MAX_DIMENSION: u32 = 16_384;
const MAX_PIXEL_BYTES: usize = 256 * 1024 * 1024;
const MAX_COMPRESSED_BYTES: usize = 32 * 1024 * 1024;
const MIN_GIF_LEN: usize = 6;

/// Quantizer effort for GIF re-encode (`gif::Frame::from_rgba_speed`).
///
/// The valid range is 1 (best quality, slowest) … 30 (lowest quality, fastest).
/// 10 is a balanced default that runs in roughly O(pixels) via NeuQuant —
/// replacing the previous hand-rolled O(pixels × palette) nearest-colour scan,
/// which was a CPU-exhaustion vector at the allowed image dimensions.
const GIF_QUANT_SPEED: i32 = 10;

struct GifPixelMatrix {
    /// Raw RGBA pixels from the first frame of the decoded GIF.
    pixels: Vec<u8>,
    width: u16,
    height: u16,
}

pub struct RawGifPayload<'a>(&'a [u8]);

impl<'a> RawGifPayload<'a> {
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        if input.len() > MAX_COMPRESSED_BYTES {
            return Err(CdrError::PayloadTooLarge {
                got: input.len(),
                limit: MAX_COMPRESSED_BYTES,
            });
        }
        if input.len() < MIN_GIF_LEN {
            return Err(CdrError::PayloadTooShort { got: input.len() });
        }
        if input[..6] != *b"GIF87a" && input[..6] != *b"GIF89a" {
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&input[..4]);
            return Err(CdrError::UnknownFormat { magic });
        }
        Ok(Self(input))
    }

    pub fn sanitize(self) -> Result<SanitizedOutput, CdrError> {
        let RawGifPayload(bytes) = self;
        Ok(GifPipeline::new(bytes)
            .decode()?
            .reconstruct()?
            .into_sanitized())
    }
}

pub struct DisarmedGifMatrix(GifPixelMatrix);
pub struct PristineGifStream(Vec<u8>);

pub struct GifPipeline<S> {
    stage: S,
}

impl<'a> GifPipeline<RawGifPayload<'a>> {
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            stage: RawGifPayload(input),
        }
    }

    pub fn decode(self) -> Result<GifPipeline<DisarmedGifMatrix>, CdrError> {
        let RawGifPayload(bytes) = self.stage;
        let cursor = std::io::Cursor::new(bytes);

        let mut options = DecodeOptions::new();
        options.set_color_output(ColorOutput::RGBA);
        let mut decoder = options
            .read_info(cursor)
            .map_err(|e| CdrError::GifDecodeFailed { source: e })?;

        let width = decoder.width();
        let height = decoder.height();

        if width == 0 || height == 0 {
            return Err(CdrError::DegenerateDimensions {
                width: width as u32,
                height: height as u32,
            });
        }
        if width as u32 > MAX_DIMENSION || height as u32 > MAX_DIMENSION {
            return Err(CdrError::DimensionTooLarge {
                dimension: (width as u32).max(height as u32),
                limit: MAX_DIMENSION,
            });
        }

        let expected = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(4);
        if expected > MAX_PIXEL_BYTES {
            return Err(CdrError::ImageTooLarge {
                bytes: expected,
                limit: MAX_PIXEL_BYTES,
            });
        }

        let frame = decoder
            .read_next_frame()
            .map_err(|e| CdrError::GifDecodeFailed { source: e })?
            .ok_or(CdrError::MissingImageInfo)?;

        let mut pixels = vec![0u8; expected];
        if frame.buffer.len() != expected {
            return Err(CdrError::PixelBufferMismatch {
                expected,
                got: frame.buffer.len(),
            });
        }
        pixels.copy_from_slice(&frame.buffer);

        Ok(GifPipeline {
            stage: DisarmedGifMatrix(GifPixelMatrix {
                pixels,
                width,
                height,
            }),
        })
    }
}

impl GifPipeline<DisarmedGifMatrix> {
    /// Re-encodes the pixel matrix as a clean GIF.
    /// Only pixel data survives — all extension blocks, comment blocks,
    /// and application-extension payloads from the original are discarded.
    ///
    /// The frame is re-quantised from raw RGBA via NeuQuant
    /// (`Frame::from_rgba_speed`), which builds a fresh, image-appropriate local
    /// palette.  This both fixes the previous behaviour (colour images falling
    /// back to a greyscale ramp when the source had no global palette) and
    /// removes the quadratic nearest-colour scan that was a CPU-DoS at large
    /// dimensions.  Transparency is preserved by `from_rgba_speed` itself.
    pub fn reconstruct(self) -> Result<GifPipeline<PristineGifStream>, CdrError> {
        let DisarmedGifMatrix(matrix) = self.stage;
        let GifPixelMatrix {
            mut pixels,
            width,
            height,
        } = matrix;

        let mut output: Vec<u8> = Vec::new();
        {
            // Empty global palette: each frame carries its own local palette
            // produced by the quantizer.
            let mut encoder = GifEncoder::new(&mut output, width, height, &[])
                .map_err(|e| CdrError::GifEncodeFailed { source: e })?;
            encoder
                .set_repeat(Repeat::Finite(0))
                .map_err(|e| CdrError::GifEncodeFailed { source: e })?;

            let frame = Frame::from_rgba_speed(width, height, &mut pixels, GIF_QUANT_SPEED);
            encoder
                .write_frame(&frame)
                .map_err(|e| CdrError::GifEncodeFailed { source: e })?;
        }

        Ok(GifPipeline {
            stage: PristineGifStream(output),
        })
    }
}

impl GifPipeline<PristineGifStream> {
    #[must_use]
    pub fn into_sanitized(self) -> SanitizedOutput {
        let PristineGifStream(bytes) = self.stage;
        SanitizedOutput::_crate_new(bytes)
    }
}

pub fn sanitize_gif(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    RawGifPayload::new(input)?.sanitize()
}

/// Sanitise a GIF byte slice and return a lossless **PNG** version.
///
/// Decodes the first GIF frame to raw RGBA pixels and re-encodes as a
/// lossless PNG — the mathematically guaranteed zero-trust output.
pub fn sanitize_gif_to_png(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    let RawGifPayload(bytes) = RawGifPayload::new(input)?;
    let cursor = std::io::Cursor::new(bytes);

    let mut options = DecodeOptions::new();
    options.set_color_output(ColorOutput::RGBA);
    let mut decoder = options
        .read_info(cursor)
        .map_err(|e| CdrError::GifDecodeFailed { source: e })?;

    let width = decoder.width() as u32;
    let height = decoder.height() as u32;

    if width == 0 || height == 0 {
        return Err(CdrError::DegenerateDimensions { width, height });
    }
    if width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(CdrError::DimensionTooLarge {
            dimension: width.max(height),
            limit: MAX_DIMENSION,
        });
    }

    let expected = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(4);
    if expected > MAX_PIXEL_BYTES {
        return Err(CdrError::ImageTooLarge {
            bytes: expected,
            limit: MAX_PIXEL_BYTES,
        });
    }

    let frame = decoder
        .read_next_frame()
        .map_err(|e| CdrError::GifDecodeFailed { source: e })?
        .ok_or(CdrError::MissingImageInfo)?;

    if frame.buffer.len() != expected {
        return Err(CdrError::PixelBufferMismatch {
            expected,
            got: frame.buffer.len(),
        });
    }

    let cap = expected.saturating_add(1024);
    let mut output: Vec<u8> = Vec::with_capacity(cap);
    {
        let mut enc = PngEncoder::new(&mut output, width, height);
        enc.set_color(PngColorType::Rgba);
        enc.set_depth(BitDepth::Eight);
        tune_png_encoder(&mut enc);
        let mut writer = enc
            .write_header()
            .map_err(|e| CdrError::PngEncodeFailed { source: e })?;
        writer
            .write_image_data(&frame.buffer)
            .map_err(|e| CdrError::PngEncodeFailed { source: e })?;
    }

    Ok(SanitizedOutput::_crate_new(output))
}
