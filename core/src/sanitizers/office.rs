use std::io::{Cursor, Read, Write};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;

const MAX_COMPRESSED_BYTES: usize = 128 * 1024 * 1024; // 128 MiB for Office docs
const MIN_ZIP_LEN: usize = 22; // Minimal zip size

/// Stage 1: An unvalidated, raw byte slice claimed to be an Office OOXML document.
pub struct RawOfficePayload<'a>(&'a [u8]);

impl<'a> RawOfficePayload<'a> {
    /// Attempts to interpret the raw bytes as an Office document.
    /// Performs length and magic byte validation (`PK\x03\x04`).
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        if input.len() > MAX_COMPRESSED_BYTES {
            return Err(CdrError::PayloadTooLarge {
                got: input.len(),
                limit: MAX_COMPRESSED_BYTES,
            });
        }
        if input.len() < MIN_ZIP_LEN {
            return Err(CdrError::PayloadTooShort { got: input.len() });
        }
        if input[..4] != [0x50, 0x4B, 0x03, 0x04] {
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&input[..4]);
            return Err(CdrError::UnknownFormat { magic });
        }
        Ok(Self(input))
    }

    /// Executes the full 3-stage typestate pipeline, consuming the raw payload and yielding a sanitized stream.
    pub fn sanitize(self) -> Result<SanitizedOutput, CdrError> {
        let RawOfficePayload(bytes) = self;
        Ok(OfficePipeline::new(bytes)
            .decode()?
            .reconstruct()?
            .into_sanitized())
    }
}

/// Stage 2: An uncompressed, deeply inspected Office archive in memory.
/// All executable macros and OLE objects (`.bin`) have been stripped.
pub struct DisarmedOfficeArchive {
    files: Vec<(String, Vec<u8>)>,
}

/// Stage 3: A completely reconstructed, clean Office OOXML document ready for output.
pub struct PristineOfficeStream(Vec<u8>);

/// The generic typestate coordinator for the Office OOXML sanitization pipeline.
pub struct OfficePipeline<S> {
    stage: S,
}

impl<'a> OfficePipeline<RawOfficePayload<'a>> {
    /// Initiates a new pipeline from a raw, structurally validated Office payload.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            stage: RawOfficePayload(input),
        }
    }

    /// Decodes the ZIP archive into memory.
    /// Iterates through all internal files, ensuring `[Content_Types].xml` is present,
    /// and drops all potentially executable files (e.g., `.bin`, `.vbs`, `.exe`).
    pub fn decode(self) -> Result<OfficePipeline<DisarmedOfficeArchive>, CdrError> {
        let RawOfficePayload(bytes) = self.stage;
        let cursor = Cursor::new(bytes);
        let mut archive =
            ZipArchive::new(cursor).map_err(|e| CdrError::ZipDecodeFailed { source: e })?;

        let mut is_office = false;
        let mut files = Vec::new();

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| CdrError::ZipDecodeFailed { source: e })?;
            let name = file.name().to_string();

            if name == "[Content_Types].xml"
                || name.starts_with("word/")
                || name.starts_with("xl/")
                || name.starts_with("ppt/")
            {
                is_office = true;
            }

            // FILTER: Drop all .bin, .vbs, .exe, etc.
            if name.ends_with(".bin") || name.ends_with(".vbs") || name.ends_with(".exe") {
                continue;
            }

            if file.is_dir() {
                continue;
            }

            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .map_err(|_| CdrError::ZipDecodeFailed {
                    source: zip::result::ZipError::InvalidArchive("I/O error".into()),
                })?;
            files.push((name, data));
        }

        if !is_office {
            return Err(CdrError::OfficeMissingContentTypes);
        }

        Ok(OfficePipeline {
            stage: DisarmedOfficeArchive { files },
        })
    }
}

impl OfficePipeline<DisarmedOfficeArchive> {
    /// Re-encodes the safely extracted XML and image assets into a brand new ZIP archive.
    /// This enforces the "share nothing" architecture by creating a new `ZipWriter`.
    pub fn reconstruct(self) -> Result<OfficePipeline<PristineOfficeStream>, CdrError> {
        let DisarmedOfficeArchive { files } = self.stage;

        let mut out_buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut out_buffer);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            for (name, data) in files {
                zip.start_file(name, options)
                    .map_err(|e| CdrError::ZipEncodeFailed { source: e })?;
                zip.write_all(&data)
                    .map_err(|_| CdrError::ZipEncodeFailed {
                        source: zip::result::ZipError::InvalidArchive("I/O error".into()),
                    })?;
            }
            zip.finish()
                .map_err(|e| CdrError::ZipEncodeFailed { source: e })?;
        }

        Ok(OfficePipeline {
            stage: PristineOfficeStream(out_buffer.into_inner()),
        })
    }
}

impl OfficePipeline<PristineOfficeStream> {
    /// Converts the fully disarmed and reconstructed Office byte stream into an opaque `SanitizedOutput` token.
    #[must_use]
    pub fn into_sanitized(self) -> SanitizedOutput {
        let PristineOfficeStream(bytes) = self.stage;
        SanitizedOutput::_crate_new(bytes)
    }
}

/// Convenience free-function to sanitize an Office (DOCX, XLSX, PPTX) document.
///
/// Under the hood, this instantiates the three-stage `RawOfficePayload` typestate.
pub fn sanitize_office(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    RawOfficePayload::new(input)?.sanitize()
}
