use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;
use png::{BitDepth, ColorType, Compression, Encoder};
use image_webp::WebPDecoder;

const MAX_DIMENSION: u32 = 16_384;
const MAX_PIXEL_BYTES: usize = 256 * 1024 * 1024;
const MAX_COMPRESSED_BYTES: usize = 32 * 1024 * 1024;
const MIN_WEBP_LEN: usize = 12;

#[repr(C)]
struct WebpPixelMatrix {
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    color_type: ColorType,
    bit_depth: BitDepth,
}

pub struct RawWebpPayload<'a>(&'a [u8]);

impl<'a> RawWebpPayload<'a> {
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        if input.len() > MAX_COMPRESSED_BYTES {
            return Err(CdrError::PayloadTooLarge { got: input.len(), limit: MAX_COMPRESSED_BYTES });
        }
        if input.len() < MIN_WEBP_LEN {
            return Err(CdrError::PayloadTooShort { got: input.len() });
        }
        if input[..4] != *b"RIFF" || input[8..12] != *b"WEBP" {
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&input[..4]);
            return Err(CdrError::UnknownFormat { magic });
        }
        Ok(Self(input))
    }

    pub fn sanitize(self) -> Result<SanitizedOutput, CdrError> {
        let RawWebpPayload(bytes) = self;
        Ok(WebpPipeline::new(bytes).decode()?.reconstruct()?.into_sanitized())
    }
}

pub struct DisarmedWebpMatrix(WebpPixelMatrix);
pub struct PristinePngStream(Vec<u8>);

pub struct WebpPipeline<S> {
    stage: S,
}

impl<'a> WebpPipeline<RawWebpPayload<'a>> {
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { stage: RawWebpPayload(input) }
    }

    pub fn decode(self) -> Result<WebpPipeline<DisarmedWebpMatrix>, CdrError> {
        let RawWebpPayload(bytes) = self.stage;
        let cursor = std::io::Cursor::new(bytes);
        
        let mut decoder = WebPDecoder::new(cursor)
            .map_err(|e| CdrError::WebpDecodeFailed { source: e })?;

        let (width, height) = decoder.dimensions();

        if width == 0 || height == 0 {
            return Err(CdrError::DegenerateDimensions { width, height });
        }
        if width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(CdrError::DimensionTooLarge { dimension: width.max(height), limit: MAX_DIMENSION });
        }

        // WebP can be lossy (YUV/RGB) or lossless (RGBA).
        // Let's decode to RGBA to be safe, or check color type.
        // image-webp usually provides an easy way to read image data.
        let color_type = if decoder.has_alpha() {
            ColorType::Rgba
        } else {
            ColorType::Rgb
        };
        let channels = if decoder.has_alpha() { 4 } else { 3 };

        let expected = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(channels);

        if expected > MAX_PIXEL_BYTES {
            return Err(CdrError::ImageTooLarge { bytes: expected, limit: MAX_PIXEL_BYTES });
        }

        let mut pixels = vec![0u8; expected];
        decoder.read_image(&mut pixels).map_err(|e| CdrError::WebpDecodeFailed { source: e })?;

        Ok(WebpPipeline {
            stage: DisarmedWebpMatrix(WebpPixelMatrix {
                pixels,
                width,
                height,
                color_type,
                bit_depth: BitDepth::Eight,
            }),
        })
    }
}

impl WebpPipeline<DisarmedWebpMatrix> {
    pub fn reconstruct(self) -> Result<WebpPipeline<PristinePngStream>, CdrError> {
        let DisarmedWebpMatrix(matrix) = self.stage;
        let WebpPixelMatrix { pixels, width, height, color_type, bit_depth } = matrix;

        let channels = match color_type {
            ColorType::Rgba => 4,
            ColorType::Rgb => 3,
            _ => 4,
        };
        let cap = (width as usize).saturating_mul(height as usize).saturating_mul(channels).saturating_add(1024);
        let mut output: Vec<u8> = Vec::with_capacity(cap);

        {
            let mut encoder = Encoder::new(&mut output, width, height);
            encoder.set_color(color_type);
            encoder.set_depth(bit_depth);
            encoder.set_compression(Compression::Best);

            let mut writer = encoder.write_header().map_err(|e| CdrError::PngEncodeFailed { source: e })?;
            writer.write_image_data(&pixels).map_err(|e| CdrError::PngEncodeFailed { source: e })?;
        }

        Ok(WebpPipeline { stage: PristinePngStream(output) })
    }
}

impl WebpPipeline<PristinePngStream> {
    #[must_use]
    pub fn into_sanitized(self) -> SanitizedOutput {
        let PristinePngStream(bytes) = self.stage;
        SanitizedOutput::_crate_new(bytes)
    }
}

pub fn sanitize_webp(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    RawWebpPayload::new(input)?.sanitize()
}
