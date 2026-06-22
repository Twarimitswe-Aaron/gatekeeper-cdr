// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: stream
//
//  Ergonomic streaming entry point for callers whose file payload may be absent.
//
//  ## Responsibility boundary
//  This module owns `ImageStream<'a>` — a thin, zero-copy wrapper over
//  `Option<&'a [u8]>` that introduces `let…else` guard-clause semantics and
//  exhaustive slice-pattern dispatch before delegating to `crate::sniffer`.
//
//  ## Privacy model
//  •  `ImageStream`      — `pub`: the primary streaming API for CDR callers.
//  •  `ImageStream.payload` — `pub`: intentionally readable; callers building
//     multipart upload handlers or streaming middleware need to inspect or
//     reassign the payload directly.
//  •  All methods        — `pub`: part of the public API surface.
//
//  ## Dependency direction
//  stream → sniffer → sanitizers → errors
//  No circular dependencies.  `stream` does not import from `sanitizers`
//  directly; it delegates to `sniffer::disarm()` and re-exports the output
//  token type alias through the crate root.
// ─────────────────────────────────────────────────────────────────────────────

use crate::errors::CdrError;
use crate::sanitizers::jpeg::SanitizedOutput;
use crate::sniffer::MIN_SNIFF_LEN;

// ─────────────────────────────────────────────────────────────────────────────
//  ImageStream — optional-payload streaming wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// A zero-copy image byte stream with an optional payload.
///
/// `ImageStream<'a>` is the ergonomic public entry point for callers who
/// receive file data from a source that may produce an absent payload
/// (e.g., a multipart form upload where the file field was not provided,
/// a network read that returned nothing, or a conditional processing path).
///
/// ## Memory layout
///
/// On a 64-bit target the struct occupies exactly **24 bytes** on the stack:
///
/// ```text
/// offset  0:  discriminant (1 byte, padded to 8 by alignment)
/// offset  8:  payload ptr  (8 bytes, present arm only)
/// offset 16:  payload len  (8 bytes, present arm only)
/// total:      24 bytes — fits in three registers, no stack spill on the hot path
/// ```
///
/// ## Lifetime contract
/// The lifetime `'a` ties the `ImageStream` to the buffer it borrows.  The
/// Rust borrow checker guarantees that the source buffer lives at least as
/// long as any `ImageStream` wrapping it — no use-after-free is possible.
///
/// ## Usage
/// ```rust,no_run
/// use gatekeeper::{ImageStream, sanitizers::jpeg::SanitizedOutput};
///
/// fn handle_upload(raw: Option<&[u8]>) -> Result<SanitizedOutput, Box<dyn std::error::Error>> {
///     let stream = ImageStream::from_option(raw);
///     Ok(stream.route()?)
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ImageStream<'a> {
    /// The raw byte payload of the incoming image stream.
    ///
    /// `None` signals that no data was provided by the upstream source
    /// (absent multipart field, empty network read, etc.).
    /// `Some(bytes)` holds a borrowed slice of the untrusted input.
    pub payload: Option<&'a [u8]>,
}

impl<'a> ImageStream<'a> {
    /// Wrap a **present** byte slice in an `ImageStream`.
    ///
    /// Use this when the caller already knows the payload is not absent.
    /// Equivalent to `ImageStream::from_option(Some(payload))`.
    ///
    /// # Zero-copy guarantee
    /// `payload` is stored as a borrow; no bytes are copied or heap-allocated.
    #[inline]
    #[must_use]
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            payload: Some(payload),
        }
    }

    /// Wrap an **absent** stream sentinel.
    ///
    /// Calling [`route`][Self::route] on an empty stream returns
    /// [`CdrError::PayloadTooShort`] immediately via the `let…else` guard,
    /// before any byte is inspected.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self { payload: None }
    }

    /// Wrap an `Option<&'a [u8]>` directly — the most common construction
    /// path when the payload arrives from a multipart parser or nullable source.
    #[inline]
    #[must_use]
    pub fn from_option(payload: Option<&'a [u8]>) -> Self {
        Self { payload }
    }

    /// Route the stream through the CDR pipeline and return a [`SanitizedOutput`]
    /// terminal token.
    ///
    /// ## Execution model
    ///
    /// The method is structured as a **flat happy path** — all error conditions
    /// are handled by early returns at the top, leaving the successful dispatch
    /// as the final, unnested statement:
    ///
    /// ```text
    /// 1.  let...else guard  ──  missing payload   →  Err(PayloadTooShort)
    /// 2.  length guard      ──  too short          →  Err(PayloadTooShort)
    /// 3.  slice pattern match on leading magic bytes:
    ///         [0xFF, 0xD8, ..]              →  JPEG pipeline
    ///         [0x89, 0x50, 0x4E, 0x47, ..]  →  PNG  pipeline (Phase 3 stub)
    ///         _                             →  Err(UnknownFormat)
    /// 4.  Happy path: sanitizer returns SanitizedOutput  ✓
    /// ```
    ///
    /// ## Slice pattern matching
    ///
    /// The inner `match` uses **slice patterns** (`[0xFF, 0xD8, ..]`)
    /// rather than equality comparisons (`bytes[..2] == [0xFF, 0xD8]`).
    /// Both compile to the same instruction sequence on x86-64, but slice
    /// patterns are checked exhaustively by the compiler — adding a new
    /// format variant and forgetting to add a match arm is a compile error.
    ///
    /// ## Errors
    /// * [`CdrError::PayloadTooShort`] — payload absent or too short.
    /// * [`CdrError::JpegMissingEoi`]  — JPEG SOI present but EOI absent.
    /// * [`CdrError::PngMissingIhdr`]  — PNG sig present but IHDR absent.
    /// * [`CdrError::UnknownFormat`]   — magic bytes match no supported format.
    /// * [`CdrError::Unimplemented`]   — format recognised but pipeline not built.
    /// * Any [`CdrError`] propagated from the format-specific sanitizer.
    ///
    /// # Example
    /// ```rust,no_run
    /// use gatekeeper::ImageStream;
    ///
    /// let raw = std::fs::read("suspicious.jpg").unwrap();
    /// let clean = ImageStream::new(&raw)
    ///     .route()
    ///     .expect("CDR failed");
    /// std::fs::write("clean.png", clean.into_bytes()).unwrap();
    /// ```
    pub fn route(self) -> Result<SanitizedOutput, CdrError> {
        // ── Guard 1: let…else — flat early return on absent payload ──────────
        //
        // `let...else` is Rust's idiomatic guard-clause syntax (stabilised
        // in 1.65).  It binds the inner value on success and the `else` block
        // — which must diverge — handles failure.  The successful binding is
        // unnested; zero extra indentation for the body below.
        let Some(bytes) = self.payload else {
            return Err(CdrError::PayloadTooShort { got: 0 });
        };

        // ── Guard 2: minimum length ───────────────────────────────────────────
        //
        // Checked once here; every arm below may rely on `bytes.len() >= 16`
        // without further bounds checks.
        if bytes.len() < MIN_SNIFF_LEN {
            return Err(CdrError::PayloadTooShort { got: bytes.len() });
        }

        // ── Happy path: exhaustive slice-pattern dispatch ─────────────────────
        //
        // Rust's slice-pattern syntax `[a, b, ..]` binds the leading bytes
        // by value (register-level load on x86-64) and uses `..` to accept
        // any suffix.  The compiler checks exhaustiveness statically; adding
        // a new format arm to this match is enforced at compile time.
        match bytes {
            // ── JPEG ──────────────────────────────────────────────────────────
            //
            // SOI = 0xFF 0xD8 (ISO/IEC 10918-1 §B.1.1).
            // Full structural validation (EOI, geometry) is owned by
            // `sanitize_jpeg` → `RawPayload::new()` → `JpegPipeline::decode()`.
            [0xFF, 0xD8, ..] => crate::sniffer::disarm(bytes, None),

            // ── PNG ───────────────────────────────────────────────────────────
            //
            // Matches first 4 bytes: 0x89 P N G.
            // Phase 3 stub: fail-closed rather than forwarding unsanitised bytes.
            [0x89, 0x50, 0x4E, 0x47, ..] => crate::sniffer::disarm(bytes, None),

            // ── Unknown ───────────────────────────────────────────────────────
            //
            // Error path only — 4-byte stack copy for forensic context.
            _ => {
                let mut magic = [0u8; 4];
                magic.copy_from_slice(&bytes[..4]);
                Err(CdrError::UnknownFormat { magic })
            }
        }
    }
}
