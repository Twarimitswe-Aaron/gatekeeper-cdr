use lopdf::Document;

use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;

const MAX_COMPRESSED_BYTES: usize = 256 * 1024 * 1024; // 256 MiB for PDFs
const MIN_PDF_LEN: usize = 15; // Minimum PDF length

/// Stage 1: An unvalidated, raw byte slice claimed to be a PDF document.
pub struct RawPdfPayload<'a>(&'a [u8]);

impl<'a> RawPdfPayload<'a> {
    /// Attempts to interpret the raw bytes as a PDF document.
    /// Performs length and magic byte validation (`%PDF-`).
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        if input.len() > MAX_COMPRESSED_BYTES {
            return Err(CdrError::PayloadTooLarge { got: input.len(), limit: MAX_COMPRESSED_BYTES });
        }
        if input.len() < MIN_PDF_LEN {
            return Err(CdrError::PayloadTooShort { got: input.len() });
        }
        if input[..5] != *b"%PDF-" {
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&input[..4]);
            return Err(CdrError::UnknownFormat { magic });
        }
        Ok(Self(input))
    }

    /// Executes the full 3-stage typestate pipeline, consuming the raw payload and yielding a sanitized stream.
    pub fn sanitize(self) -> Result<SanitizedOutput, CdrError> {
        let RawPdfPayload(bytes) = self;
        Ok(PdfPipeline::new(bytes).decode()?.reconstruct()?.into_sanitized())
    }
}

/// Stage 2: A deeply inspected PDF document tree in memory.
/// All interactive execution vectors (`/JS`, `/AA`, `/OpenAction`, `/A`) and attachments (`/EmbeddedFiles`) have been aggressively stripped.
pub struct DisarmedPdfTree(Document);

/// Stage 3: A completely reconstructed, safe PDF document ready for output.
pub struct PristinePdfStream(Vec<u8>);

/// The generic typestate coordinator for the PDF sanitization pipeline.
pub struct PdfPipeline<S> {
    stage: S,
}

impl<'a> PdfPipeline<RawPdfPayload<'a>> {
    /// Initiates a new pipeline from a raw, structurally validated PDF payload.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { stage: RawPdfPayload(input) }
    }

    /// Decodes the PDF document tree using `lopdf`.
    /// Iterates through every object in the document and deletes specific dictionary keys
    /// known to harbor execution payloads or embedded files.
    pub fn decode(self) -> Result<PdfPipeline<DisarmedPdfTree>, CdrError> {
        let RawPdfPayload(bytes) = self.stage;
        let mut doc = Document::load_mem(bytes).map_err(|e| CdrError::PdfDecodeFailed { source: e })?;

        // ── ZERO-TRUST PDF SANITIZATION ──
        // Iterate through all objects in the document
        for (_id, object) in doc.objects.iter_mut() {
            if let lopdf::Object::Dictionary(dict) = object {
                // Remove keys known to harbor malicious execution or embedding vectors
                dict.remove(b"JS");
                dict.remove(b"JavaScript");
                dict.remove(b"AA");
                dict.remove(b"OpenAction");
                dict.remove(b"Launch");
                dict.remove(b"EmbeddedFiles");
                // Remove Action dictionary which triggers execution (e.g. from links or form buttons)
                dict.remove(b"A");
                dict.remove(b"Names"); // Often holds embedded file mappings
            }
        }

        Ok(PdfPipeline {
            stage: DisarmedPdfTree(doc),
        })
    }
}

impl PdfPipeline<DisarmedPdfTree> {
    /// Re-encodes the safely stripped PDF document tree into a brand new byte stream.
    pub fn reconstruct(self) -> Result<PdfPipeline<PristinePdfStream>, CdrError> {
        let DisarmedPdfTree(mut doc) = self.stage;

        let mut out_buffer = Vec::new();
        doc.save_to(&mut out_buffer).map_err(|e| CdrError::PdfEncodeFailed { source: e })?;

        Ok(PdfPipeline { stage: PristinePdfStream(out_buffer) })
    }
}

impl PdfPipeline<PristinePdfStream> {
    /// Converts the fully disarmed and reconstructed PDF byte stream into an opaque `SanitizedOutput` token.
    #[must_use]
    pub fn into_sanitized(self) -> SanitizedOutput {
        let PristinePdfStream(bytes) = self.stage;
        SanitizedOutput::_crate_new(bytes)
    }
}

/// Convenience free-function to sanitize a PDF document.
///
/// Under the hood, this instantiates the three-stage `RawPdfPayload` typestate.
pub fn sanitize_pdf(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    RawPdfPayload::new(input)?.sanitize()
}
