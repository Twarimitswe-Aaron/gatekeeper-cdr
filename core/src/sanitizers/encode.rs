// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: sanitizers :: encode
//
//  Shared encoder tuning for the re-encode leg of every image pipeline.
//  Security requires decode → strip → re-encode from pixels; these helpers
//  configure the encoders for the best **real-time** compression without
//  weakening the zero-trust guarantee (pixels are unchanged).
// ─────────────────────────────────────────────────────────────────────────────

use png::{AdaptiveFilterType, Compression, Encoder, FilterType};

/// JPEG re-encode quality for the native `buffer` output.
///
/// Every JPEG passes through a full decode → RGB matrix → re-quantize cycle,
/// which destroys steganographic DCT-coefficient payloads regardless of the
/// exact quality value.  **85** is chosen (not 95–100) so the sanitized file
/// is usually *similar in size* to a typical camera/export JPEG (q75–85) instead
/// of systematically inflating low-quality uploads.
pub const JPEG_REENCODE_QUALITY: u8 = 85;

/// Configure a PNG encoder for strong real-time compression.
///
/// ## Why this exists
/// The `png` crate defaults to `FilterType::Sub` with
/// `AdaptiveFilterType::NonAdaptive`.  That combination produces IDAT streams
/// **much larger** than a well-compressed source PNG even when deflate level is
/// `Compression::Best` (zlib level 9).  Most production PNGs (and tools like
/// `pngcrush` / `optipng`) use per-row adaptive filtering — typically Paeth.
///
/// Gatekeeper previously set `Compression::Best` but left the default filter,
/// so sanitized PNGs could be **2–3× larger than the original** despite
/// stripping metadata (which should have made them *smaller*).  Enabling
/// adaptive Paeth fixes that logic error without touching pixel values.
pub fn tune_png_encoder<W: std::io::Write>(encoder: &mut Encoder<'_, W>) {
    encoder.set_compression(Compression::Best);
    encoder.set_filter(FilterType::Paeth);
    encoder.set_adaptive_filter(AdaptiveFilterType::Adaptive);
}
