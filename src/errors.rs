// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: errors
//
//  All error variants that can surface from the CDR pipeline are defined here.
//  Design invariant: *no* generic String is used inside any variant.  Every
//  branch carries a fixed, typed description so error paths generate zero heap
//  allocations at the Rust level.
//
//  The `thiserror` macro derives `std::error::Error` and the `Display` impl
//  automatically from the `#[error("...")]` attribute, keeping the enum as the
//  single source of truth.
// ─────────────────────────────────────────────────────────────────────────────

use thiserror::Error;

/// Strongly-typed CDR error taxonomy.
///
/// Variants are ordered from earliest pipeline stage (format detection) to
/// latest (re-encoding).  Each variant carries only fixed-cost metadata so
/// error propagation never silently allocates.
#[derive(Debug, Error)]
pub enum CdrError {
    // ── Stage 0 – Format detection ─────────────────────────────────────────

    /// The supplied byte slice is too short to contain any recognisable magic.
    ///
    /// `got` is the number of bytes actually provided; the engine requires at
    /// least 12 bytes to perform a reliable sniff.
    #[error("payload too short for format detection: got {got} byte(s), need ≥ 12")]
    PayloadTooShort { got: usize },

    /// The supplied byte slice exceeds the maximum allowed compressed input size.
    ///
    /// `got` is the number of bytes provided; `limit` is the enforced cap.
    /// This guard fires before any decoding work begins, preventing
    /// multi-gigabyte allocations from oversized compressed inputs.
    #[error("payload too large: got {got} bytes, limit is {limit} bytes")]
    PayloadTooLarge { got: usize, limit: usize },

    /// The magic signature at offset 0 does not match any supported format.
    ///
    /// `magic` captures the first 4 raw bytes for forensic logging without
    /// allocating a heap String.
    #[error("unrecognised file magic: {magic:02X?}")]
    UnknownFormat { magic: [u8; 4] },

    // ── Stage 1 – Format validation ────────────────────────────────────────

    /// A JPEG SOI marker (0xFF 0xD8) was found but the EOI trailer (0xFF 0xD9)
    /// is absent.  The file is structurally incomplete.
    #[error("JPEG is structurally malformed: SOI present but EOI marker is absent")]
    JpegMissingEoi,

    /// A PNG signature was detected but the IHDR chunk is not present at the
    /// expected offset 8, indicating the file has been tampered with.
    #[error("PNG is structurally malformed: IHDR chunk absent at offset 8")]
    PngMissingIhdr,

    // ── Stage 2 – Decoding ─────────────────────────────────────────────────

    /// The underlying `zune-jpeg` decoder returned a hard error.
    ///
    /// We box the zune error to avoid polluting the CDR error size with the
    /// large internal zune type, while still preserving full Display/Debug
    /// through the source chain.
    #[error("JPEG decode failure: {source}")]
    JpegDecodeFailed { source: zune_jpeg::errors::DecodeErrors },

    /// The PNG decoder surfaced a structural error in the input stream.
    #[error("PNG decode failure: {source}")]
    PngDecodeFailed { source: png::DecodingError },

    // ── Stage 3 – Pixel-geometry validation ───────────────────────────────

    /// After decode the decoder reported no image info (width / height /
    /// colorspace).  This should be unreachable on valid input but is captured
    /// here for the zero-trust invariant.
    #[error("decoder produced no image geometry after a successful decode")]
    MissingImageInfo,

    /// Width or height reported by the decoder is zero.
    #[error("image has degenerate dimensions: {width}×{height}")]
    DegenerateDimensions { width: u32, height: u32 },

    /// A single image axis (width or height) exceeds the per-dimension safety
    /// cap.  The cap prevents integer-overflow in geometry arithmetic and
    /// limits the worst-case allocation before the pixel budget check fires.
    ///
    /// `dimension` is the offending axis length; `limit` is the cap in pixels.
    #[error("image dimension too large: {dimension}px exceeds the safety cap of {limit}px")]
    DimensionTooLarge { dimension: u32, limit: u32 },

    /// The decoded pixel buffer would exceed the maximum allowed byte count.
    ///
    /// This is the primary decompression-bomb guard: a compressed file can
    /// claim enormous dimensions that result in a multi-gigabyte allocation.
    /// Gatekeeper rejects such files before a single allocation is made.
    ///
    /// `bytes` is the computed pixel budget; `limit` is the safety cap.
    #[error("image pixel budget too large: {bytes} bytes exceeds the safety cap of {limit} bytes")]
    ImageTooLarge { bytes: usize, limit: usize },

    /// The decoded pixel buffer length is inconsistent with the reported image
    /// geometry.  `expected` and `got` are byte counts.
    #[error("pixel buffer size mismatch: expected {expected} bytes, got {got}")]
    PixelBufferMismatch { expected: usize, got: usize },

    // ── Stage 4 – Re-encoding ─────────────────────────────────────────────

    /// The PNG encoder returned an I/O error while writing into the output
    /// buffer.  In practice this signals an internal logic fault because the
    /// output is a `Vec<u8>`.
    #[error("PNG re-encode failure: {source}")]
    PngEncodeFailed { source: png::EncodingError },

    // ── Stage 0 – Unimplemented format stub ───────────────────────────────

    /// The format was recognised but its sanitisation pipeline has not yet
    /// been implemented.
    ///
    /// Using `&'static str` keeps the error zero-allocation; the format name
    /// is always a compile-time constant (e.g. `"PNG"`).
    ///
    /// This variant is intentionally returned instead of forwarding the raw
    /// input to the caller, which would violate the zero-trust contract.
    #[error("format '{format}' is recognised but its CDR pipeline is not yet implemented")]
    Unimplemented { format: &'static str },
}
