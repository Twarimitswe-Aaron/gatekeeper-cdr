use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;
use png::{BitDepth, ColorType, Encoder};
use gif::DecodeOptions;

const MAX_DIMENSION: u32 = 16_384;
const MAX_PIXEL_BYTES: usize = 256 * 1024 * 1024;
const MAX_COMPRESSED_BYTES: usize = 32 * 1024 * 1024;
const MIN_GIF_LEN: usize = 6;

#[repr(C)]
struct GifPixelMatrix {
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    color_type: ColorType,
    bit_depth: BitDepth,
}

pub struct RawGifPayload<'a>(&'a [u8]);

impl<'a> RawGifPayload<'a> {
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        if input.len() > MAX_COMPRESSED_BYTES {
            return Err(CdrError::PayloadTooLarge { got: input.len(), limit: MAX_COMPRESSED_BYTES });
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
        Ok(GifPipeline::new(bytes).decode()?.reconstruct()?.into_sanitized())
    }
}

pub struct DisarmedGifMatrix(GifPixelMatrix);
pub struct PristinePngStream(Vec<u8>);

pub struct GifPipeline<S> {
    stage: S,
}

impl<'a> GifPipeline<RawGifPayload<'a>> {
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { stage: RawGifPayload(input) }
    }

    pub fn decode(self) -> Result<GifPipeline<DisarmedGifMatrix>, CdrError> {
        let RawGifPayload(bytes) = self.stage;
        let cursor = std::io::Cursor::new(bytes);
        
        let mut decoder = DecodeOptions::new()
            .read_info(cursor)
            .map_err(|e| CdrError::GifDecodeFailed { source: e })?;

        let width = decoder.width() as u32;
        let height = decoder.height() as u32;

        if width == 0 || height == 0 {
            return Err(CdrError::DegenerateDimensions { width, height });
        }
        if width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(CdrError::DimensionTooLarge { dimension: width.max(height), limit: MAX_DIMENSION });
        }

        let expected = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(4); // RGBA

        if expected > MAX_PIXEL_BYTES {
            return Err(CdrError::ImageTooLarge { bytes: expected, limit: MAX_PIXEL_BYTES });
        }

        // Read the first frame
        let frame = decoder.read_next_frame()
            .map_err(|e| CdrError::GifDecodeFailed { source: e })?
            .ok_or(CdrError::MissingImageInfo)?; // No frames?

        // The gif crate gives us RGBA pixels
        let mut pixels = vec![0u8; expected];
        // However, the frame buffer size might be different if it's interlaced or localized.
        // `frame.buffer` contains the RGBA pixels of this frame.
        if frame.buffer.len() != expected {
            return Err(CdrError::PixelBufferMismatch { expected, got: frame.buffer.len() });
        }
        pixels.copy_from_slice(&frame.buffer);

        Ok(GifPipeline {
            stage: DisarmedGifMatrix(GifPixelMatrix {
                pixels,
                width,
                height,
                color_type: ColorType::Rgba,
                bit_depth: BitDepth::Eight,
            }),
        })
    }
}

impl GifPipeline<DisarmedGifMatrix> {
    pub fn reconstruct(self) -> Result<GifPipeline<PristinePngStream>, CdrError> {
        let DisarmedGifMatrix(matrix) = self.stage;
        let GifPixelMatrix { pixels, width, height, color_type, bit_depth } = matrix;

        let cap = (width as usize).saturating_mul(height as usize).saturating_mul(4).saturating_add(1024);
        let mut output: Vec<u8> = Vec::with_capacity(cap);

        {
            let mut encoder = Encoder::new(&mut output, width, height);
            encoder.set_color(color_type);
            encoder.set_depth(bit_depth);

            let mut writer = encoder.write_header().map_err(|e| CdrError::PngEncodeFailed { source: e })?;
            writer.write_image_data(&pixels).map_err(|e| CdrError::PngEncodeFailed { source: e })?;
        }

        Ok(GifPipeline { stage: PristinePngStream(output) })
    }
}

impl GifPipeline<PristinePngStream> {
    #[must_use]
    pub fn into_sanitized(self) -> SanitizedOutput {
        let PristinePngStream(bytes) = self.stage;
        SanitizedOutput::_crate_new(bytes)
    }
}

pub fn sanitize_gif(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    RawGifPayload::new(input)?.sanitize()
}
