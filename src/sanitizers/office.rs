use std::io::{Cursor, Read, Write};
use zip::{ZipArchive, ZipWriter};
use zip::write::SimpleFileOptions;

use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;

const MAX_COMPRESSED_BYTES: usize = 128 * 1024 * 1024; // 128 MiB for Office docs
const MIN_ZIP_LEN: usize = 22; // Minimal zip size

pub struct RawOfficePayload<'a>(&'a [u8]);

impl<'a> RawOfficePayload<'a> {
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        if input.len() > MAX_COMPRESSED_BYTES {
            return Err(CdrError::PayloadTooLarge { got: input.len(), limit: MAX_COMPRESSED_BYTES });
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

    pub fn sanitize(self) -> Result<SanitizedOutput, CdrError> {
        let RawOfficePayload(bytes) = self;
        Ok(OfficePipeline::new(bytes).decode()?.reconstruct()?.into_sanitized())
    }
}

pub struct DisarmedOfficeArchive {
    files: Vec<(String, Vec<u8>)>,
}

pub struct PristineOfficeStream(Vec<u8>);

pub struct OfficePipeline<S> {
    stage: S,
}

impl<'a> OfficePipeline<RawOfficePayload<'a>> {
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { stage: RawOfficePayload(input) }
    }

    pub fn decode(self) -> Result<OfficePipeline<DisarmedOfficeArchive>, CdrError> {
        let RawOfficePayload(bytes) = self.stage;
        let cursor = Cursor::new(bytes);
        let mut archive = ZipArchive::new(cursor).map_err(|e| CdrError::ZipDecodeFailed { source: e })?;

        let mut is_office = false;
        let mut files = Vec::new();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| CdrError::ZipDecodeFailed { source: e })?;
            let name = file.name().to_string();

            if name == "[Content_Types].xml" || name.starts_with("word/") || name.starts_with("xl/") || name.starts_with("ppt/") {
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
            file.read_to_end(&mut data).map_err(|_| CdrError::ZipDecodeFailed { source: zip::result::ZipError::InvalidArchive("I/O error".into()) })?;
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
    pub fn reconstruct(self) -> Result<OfficePipeline<PristineOfficeStream>, CdrError> {
        let DisarmedOfficeArchive { files } = self.stage;

        let mut out_buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut out_buffer);
            let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            for (name, data) in files {
                zip.start_file(name, options.clone()).map_err(|e| CdrError::ZipEncodeFailed { source: e })?;
                zip.write_all(&data).map_err(|_| CdrError::ZipEncodeFailed { source: zip::result::ZipError::InvalidArchive("I/O error".into()) })?;
            }
            zip.finish().map_err(|e| CdrError::ZipEncodeFailed { source: e })?;
        }

        Ok(OfficePipeline { stage: PristineOfficeStream(out_buffer.into_inner()) })
    }
}

impl OfficePipeline<PristineOfficeStream> {
    #[must_use]
    pub fn into_sanitized(self) -> SanitizedOutput {
        let PristineOfficeStream(bytes) = self.stage;
        SanitizedOutput::_crate_new(bytes)
    }
}

pub fn sanitize_office(input: &[u8]) -> Result<SanitizedOutput, CdrError> {
    RawOfficePayload::new(input)?.sanitize()
}
