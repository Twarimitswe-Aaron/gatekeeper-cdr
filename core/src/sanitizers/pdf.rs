use lopdf::{Dictionary, Document, Object};

use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;

const MAX_COMPRESSED_BYTES: usize = 64 * 1024 * 1024; // 64 MiB compressed input cap
/// Decompression-bomb guard: reject if the rebuilt PDF balloons past this.
const MAX_OUTPUT_BYTES: usize = 512 * 1024 * 1024; // 512 MiB rebuilt-output cap
const MIN_PDF_LEN: usize = 15; // Minimum PDF length

/// Dictionary keys that carry active content, scripting, auto-actions, or
/// embedded/remote payloads.  Removed from **every** dictionary in the object
/// graph — including stream dictionaries and inline dictionaries nested inside
/// arrays — so the blacklist cannot be evaded by hiding an action one level
/// deeper than a naive top-level scan would reach.
///
/// `lopdf` normalises name tokens (e.g. the `/J#53` hex-escape decodes to
/// `JS`), so matching on the canonical byte form is sufficient.
const DANGEROUS_KEYS: &[&[u8]] = &[
    b"JS",            // JavaScript action body
    b"JavaScript",    // JavaScript name-tree / action
    b"AA",            // Additional-Actions (triggers on open/close/focus/etc.)
    b"OpenAction",    // runs automatically when the document opens
    b"Launch",        // Launch action — spawns external programs
    b"EmbeddedFile",  // embedded file stream
    b"EmbeddedFiles", // embedded-files name tree
    b"Names",         // often hosts the EmbeddedFiles / JavaScript name trees
    b"A",             // generic Action dictionary (links, form buttons)
    b"URI",           // URI action — data exfiltration / C2 callback
    b"SubmitForm",    // submits form data to a remote endpoint
    b"ImportData",    // pulls remote form data
    b"GoToR",         // remote go-to (opens another file/URL)
    b"GoToE",         // embedded go-to
    b"RichMedia",     // Flash / 3D / embedded media execution
    b"Movie",         // legacy multimedia execution
    b"Sound",         // legacy multimedia execution
    b"Rendition",     // multimedia rendition action
    b"SetState",      // state-change action
    b"Trans",         // presentation transition action chains
];

/// Stage 1: An unvalidated, raw byte slice claimed to be a PDF document.
pub struct RawPdfPayload<'a>(&'a [u8]);

impl<'a> RawPdfPayload<'a> {
    /// Attempts to interpret the raw bytes as a PDF document.
    /// Performs length and magic byte validation (`%PDF-`).
    pub fn new(input: &'a [u8]) -> Result<Self, CdrError> {
        if input.len() > MAX_COMPRESSED_BYTES {
            return Err(CdrError::PayloadTooLarge {
                got: input.len(),
                limit: MAX_COMPRESSED_BYTES,
            });
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
        Ok(PdfPipeline::new(bytes)
            .decode()?
            .reconstruct()?
            .into_sanitized())
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
        Self {
            stage: RawPdfPayload(input),
        }
    }

    /// Decodes the PDF document tree using `lopdf` and recursively strips every
    /// active-content vector from the entire object graph.
    ///
    /// ## Why recursion is mandatory
    /// The previous implementation only inspected top-level `Object::Dictionary`
    /// values.  That missed **stream dictionaries** (`Object::Stream` carries its
    /// own `dict`) and **inline dictionaries nested inside arrays** or inside
    /// other dicts.  An attacker could therefore place an `/OpenAction` or `/JS`
    /// one level below the scan and sail through.  We now walk every reachable
    /// node.
    ///
    /// Indirect `Object::Reference`s are intentionally NOT followed during the
    /// walk — the object they point at is itself a top-level entry in
    /// `doc.objects`, so it is visited exactly once on its own.  This also makes
    /// the traversal acyclic and panic-free regardless of reference cycles.
    pub fn decode(self) -> Result<PdfPipeline<DisarmedPdfTree>, CdrError> {
        let RawPdfPayload(bytes) = self.stage;
        let mut doc =
            Document::load_mem(bytes).map_err(|e| CdrError::PdfDecodeFailed { source: e })?;

        // ── ZERO-TRUST PDF SANITIZATION (full graph walk) ──
        for (_id, object) in doc.objects.iter_mut() {
            sanitize_object(object);
        }

        Ok(PdfPipeline {
            stage: DisarmedPdfTree(doc),
        })
    }
}

/// Strip every [`DANGEROUS_KEYS`] entry from a dictionary, then recurse into the
/// values that survive so nested dictionaries are cleaned too.
fn sanitize_dictionary(dict: &mut Dictionary) {
    for key in DANGEROUS_KEYS {
        dict.remove(key);
    }
    for (_k, v) in dict.iter_mut() {
        sanitize_object(v);
    }
}

/// Recursively sanitise a single object.  Handles dictionaries, stream
/// dictionaries, and arrays of inline objects.  Scalars and references are
/// leaves and need no work.
fn sanitize_object(object: &mut Object) {
    match object {
        Object::Dictionary(dict) => sanitize_dictionary(dict),
        Object::Stream(stream) => sanitize_dictionary(&mut stream.dict),
        Object::Array(items) => {
            for item in items.iter_mut() {
                sanitize_object(item);
            }
        }
        _ => {}
    }
}

impl PdfPipeline<DisarmedPdfTree> {
    /// Re-encodes the safely stripped PDF document tree into a brand new byte stream.
    pub fn reconstruct(self) -> Result<PdfPipeline<PristinePdfStream>, CdrError> {
        let DisarmedPdfTree(mut doc) = self.stage;

        let mut out_buffer = Vec::new();
        doc.save_to(&mut out_buffer)
            .map_err(|e| CdrError::PdfEncodeFailed { source: e })?;

        // Decompression-bomb guard: a small input with heavily compressed
        // object/cross-reference streams can rebuild into a gigabyte-scale
        // document.  Reject anything past the output budget instead of handing
        // a memory bomb back to the caller.
        if out_buffer.len() > MAX_OUTPUT_BYTES {
            return Err(CdrError::PdfTooLarge {
                bytes: out_buffer.len(),
                limit: MAX_OUTPUT_BYTES,
            });
        }

        Ok(PdfPipeline {
            stage: PristinePdfStream(out_buffer),
        })
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
