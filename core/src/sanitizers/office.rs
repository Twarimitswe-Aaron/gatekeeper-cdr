use std::io::{Cursor, Read, Write};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;

const MAX_COMPRESSED_BYTES: usize = 128 * 1024 * 1024; // 128 MiB compressed input cap
/// Per-part decompressed ceiling — bounds the memory a single hostile entry can
/// inflate to (zip-bomb guard).  No legitimate OOXML part approaches this.
const MAX_PART_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
/// Total decompressed ceiling across all surviving parts (zip-bomb guard).
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
const MIN_ZIP_LEN: usize = 22; // Minimal zip size

/// File extensions that carry executable or scripting payloads.  Matched
/// case-insensitively, because a ZIP entry named `vbaProject.BIN` is loaded
/// just fine by Office on case-insensitive consumers and must not slip through.
const DANGEROUS_EXTENSIONS: &[&str] = &[
    ".bin", ".vbs", ".vbe", ".vba", ".exe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".bat",
    ".cmd", ".com", ".scr", ".dll", ".hta", ".msi", ".reg", ".lnk", ".sct", ".jar", ".class",
];

/// Path fragments (lowercased) that identify active-content parts:
/// VBA macro projects, ActiveX controls, OLE embeddings, and external links.
/// Any entry whose normalised path contains one of these is dropped wholesale.
const DANGEROUS_PATH_FRAGMENTS: &[&str] = &[
    "vbaproject",
    "vbadata",
    "/activex",
    "activex/",
    "/embeddings/",
    "externallink",
    "/macros/",
    "macrosheet",
];

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
/// All executable macros, ActiveX controls, OLE embeddings, and external links
/// have been stripped, and the surviving parts have been screened for
/// non-removable active content (DDE / remote templates).
pub struct DisarmedOfficeArchive {
    files: Vec<(String, Vec<u8>)>,
}

/// Stage 3: A completely reconstructed, clean Office OOXML document ready for output.
pub struct PristineOfficeStream(Vec<u8>);

/// The generic typestate coordinator for the Office OOXML sanitization pipeline.
pub struct OfficePipeline<S> {
    stage: S,
}

/// Returns true if `name` (any case) ends with a dangerous executable extension.
fn has_dangerous_extension(name_lower: &str) -> bool {
    DANGEROUS_EXTENSIONS
        .iter()
        .any(|ext| name_lower.ends_with(ext))
}

/// Returns true if `name` (any case) lives in an active-content part of the package.
fn has_dangerous_path(name_lower: &str) -> bool {
    DANGEROUS_PATH_FRAGMENTS
        .iter()
        .any(|frag| name_lower.contains(frag))
}

/// Case-insensitive substring search over raw bytes (ASCII).
fn contains_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return false;
    }
    haystack
        .windows(needle_lower.len())
        .any(|w| w.eq_ignore_ascii_case(needle_lower))
}

/// Screen a surviving XML/rels part for content-level attacks that cannot be
/// neutralised by simply dropping a part.  We fail closed rather than emit a
/// document that still auto-executes.
///
/// * **DDE / DDEAUTO** field instructions — classic macro-free code execution.
/// * **Remote template injection** — a relationship that both targets an
///   external location and wires up an `attachedTemplate`, which Word fetches
///   and runs on open.
fn screen_part_for_active_content(name_lower: &str, data: &[u8]) -> Result<(), CdrError> {
    if name_lower.ends_with(".xml") || name_lower.ends_with(".rels") {
        if contains_ci(data, b"ddeauto") || contains_ci(data, b"dde ") {
            return Err(CdrError::OfficeDangerousContent {
                kind: "DDE field instruction",
            });
        }
        if contains_ci(data, b"attachedtemplate") && contains_ci(data, b"external") {
            return Err(CdrError::OfficeDangerousContent {
                kind: "remote template auto-load",
            });
        }
    }
    Ok(())
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
    ///
    /// For every entry it:
    ///   1. drops directories,
    ///   2. drops active-content parts (macros / ActiveX / OLE / external links)
    ///      by case-insensitive extension and path,
    ///   3. inflates the survivor under a strict per-part and total size budget
    ///      (zip-bomb guard),
    ///   4. screens the survivor for non-removable active content and fails
    ///      closed if any is present.
    pub fn decode(self) -> Result<OfficePipeline<DisarmedOfficeArchive>, CdrError> {
        let RawOfficePayload(bytes) = self.stage;
        let cursor = Cursor::new(bytes);
        let mut archive =
            ZipArchive::new(cursor).map_err(|e| CdrError::ZipDecodeFailed { source: e })?;

        let mut is_office = false;
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let mut total_bytes: usize = 0;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| CdrError::ZipDecodeFailed { source: e })?;
            let name = file.name().to_string();
            let name_lower = name.to_ascii_lowercase();

            if name_lower == "[content_types].xml"
                || name_lower.starts_with("word/")
                || name_lower.starts_with("xl/")
                || name_lower.starts_with("ppt/")
            {
                is_office = true;
            }

            if file.is_dir() {
                continue;
            }

            // FILTER: drop all active-content parts (case-insensitive).
            if has_dangerous_extension(&name_lower) || has_dangerous_path(&name_lower) {
                continue;
            }

            // Inflate under a per-part ceiling so a bomb entry cannot exhaust
            // memory: read one byte past the cap and treat overflow as hostile.
            let mut data = Vec::new();
            let mut limited = file.by_ref().take(MAX_PART_BYTES as u64 + 1);
            limited
                .read_to_end(&mut data)
                .map_err(|_| CdrError::ZipDecodeFailed {
                    source: zip::result::ZipError::InvalidArchive("I/O error".into()),
                })?;
            if data.len() > MAX_PART_BYTES {
                return Err(CdrError::OfficeArchiveTooLarge {
                    bytes: data.len(),
                    limit: MAX_PART_BYTES,
                });
            }

            total_bytes = total_bytes.saturating_add(data.len());
            if total_bytes > MAX_TOTAL_BYTES {
                return Err(CdrError::OfficeArchiveTooLarge {
                    bytes: total_bytes,
                    limit: MAX_TOTAL_BYTES,
                });
            }

            // Content-level screen: fail closed on DDE / remote templates.
            screen_part_for_active_content(&name_lower, &data)?;

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
