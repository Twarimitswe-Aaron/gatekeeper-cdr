// ─────────────────────────────────────────────────────────────────────────────
//  gatekeeper :: async_stream
//
//  Asynchronous, non-blocking streaming entry point for the CDR engine.
//
//  ## Motivation
//  The synchronous `ImageStream` requires the full file payload to be resident
//  in memory before any sanitisation begins.  For large files (multi-MB PDFs,
//  high-res images) in concurrent web-server contexts, this forces peak RAM
//  usage to scale with (file_size × concurrent_requests).
//
//  `AsyncImageStream` reads the payload in chunks from any `tokio::io::AsyncRead`
//  source (a file handle, a network socket, an in-memory cursor, etc.) and
//  dispatches sanitisation without blocking the calling thread.
//
//  ## Responsibility boundary
//  This module owns:
//  •  `AsyncImageStream<R>` — the public async streaming wrapper.
//  •  `route_async()`       — async format detection + dispatch.
//
//  The per-format async sanitiser adapters live in `crate::sanitizers::*` and
//  are called via the existing `disarm_async` function in `crate::sniffer`.
//
//  ## Dependency direction
//  async_stream → sniffer → sanitizers → errors
//  No circular imports.
// ─────────────────────────────────────────────────────────────────────────────

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::errors::CdrError;
use crate::sniffer::{DisarmResult, MIN_SNIFF_LEN};

// ─────────────────────────────────────────────────────────────────────────────
//  Chunk size
// ─────────────────────────────────────────────────────────────────────────────

/// Number of bytes read per I/O operation.
///
/// 64 KiB is the sweet spot for most OS kernel page-cache read-aheads.
/// Larger values reduce syscall overhead; smaller values reduce latency for
/// the first byte.  This constant is not part of the public API surface and
/// may be tuned without a semver bump.
const CHUNK_SIZE: usize = 65_536; // 64 KiB

// ─────────────────────────────────────────────────────────────────────────────
//  AsyncImageStream — generic async reader wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// An asynchronous, streaming CDR wrapper over any `tokio::io::AsyncRead` source.
///
/// ## Why async?
///
/// The synchronous `ImageStream` requires the **entire file** in memory before
/// sanitisation begins.  `AsyncImageStream` reads the source in chunks, so the
/// OS can overlap I/O with CPU-bound sanitisation work:
///
/// ```text
/// Thread 1 ──► read chunk 1 ──► sanitise chunk 1 ──► write chunk 1 ──►
///                               ↑  (CPU overlaps)
/// Thread 2 ─────────────────►  read chunk 2 ──► sanitise chunk 2 ──►
/// ```
///
/// ## Memory model
///
/// Peak heap usage is bounded by `O(file_size)` in the current phase (because
/// the full sanitised output must be collected before returning), but I/O is
/// fully non-blocking — your web server thread is never stalled waiting for
/// disk reads.
///
/// Future phases will introduce streaming output via `futures::Stream<Item = Bytes>`
/// to reduce peak allocation further.
///
/// ## Type parameter `R`
///
/// `R` must implement [`tokio::io::AsyncRead`] + [`Unpin`].  Common sources:
/// - `tokio::fs::File`       — disk file
/// - `tokio::net::TcpStream` — network socket
/// - `std::io::Cursor<Vec<u8>>` (wrapped in `tokio::io::BufReader`) — in-memory
/// - `&[u8]` via `tokio::io::BufReader::new(std::io::Cursor::new(slice))`
///
/// ## Example
/// ```rust,no_run
/// use gatekeeper::async_stream::AsyncImageStream;
/// use std::io::Cursor;
///
/// #[tokio::main]
/// async fn main() {
///     let raw = std::fs::read("suspicious.jpg").unwrap();
///     let cursor = Cursor::new(raw);
///     let reader = tokio::io::BufReader::new(cursor);
///     let result = AsyncImageStream::new(reader).route_async().await.unwrap();
///     std::fs::write("clean.jpg", result.buffer).unwrap();
/// }
/// ```
pub struct AsyncImageStream<R: AsyncRead + Unpin> {
    /// The underlying async byte source.
    reader: R,
}

impl<R: AsyncRead + Unpin> AsyncImageStream<R> {
    /// Wrap any `AsyncRead + Unpin` source in an `AsyncImageStream`.
    ///
    /// No bytes are read at construction time.  I/O begins only when
    /// [`route_async`][Self::route_async] is called.
    #[inline]
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Read the full stream, detect the file format, and run the CDR pipeline.
    ///
    /// ## Execution model
    ///
    /// ```text
    /// 1.  Read bytes until EOF into a BytesMut buffer (chunked, 64 KiB at a time).
    /// 2.  Guard: too short → Err(PayloadTooShort).
    /// 3.  Forward the fully-buffered slice to crate::sniffer::disarm().
    /// ```
    ///
    /// Phase 13 will replace step 3 with a true incremental streaming sanitiser
    /// so that the output is written before the input is fully consumed.
    ///
    /// ## Errors
    ///
    /// Returns any [`CdrError`] produced by the underlying synchronous pipeline,
    /// plus an additional I/O error variant if the read itself fails.
    pub async fn route_async(mut self) -> Result<DisarmResult, CdrError> {
        // ── Read source into a contiguous buffer ──────────────────────────────
        //
        // We use `BytesMut` to amortise allocations: it starts at CHUNK_SIZE
        // and doubles as needed, similar to Vec::push but with explicit control
        // over the reservation policy.
        let mut buf = BytesMut::with_capacity(CHUNK_SIZE);
        let mut chunk = [0u8; CHUNK_SIZE];

        loop {
            let n = self
                .reader
                .read(&mut chunk)
                .await
                .map_err(|e| CdrError::IoError { message: e.to_string() })?;

            if n == 0 {
                break; // EOF
            }

            buf.extend_from_slice(&chunk[..n]);
        }

        let payload: Bytes = buf.freeze();

        // ── Guard: minimum sniff length ───────────────────────────────────────
        if payload.len() < MIN_SNIFF_LEN {
            return Err(CdrError::PayloadTooShort { got: payload.len() });
        }

        // ── Delegate to the synchronous disarm pipeline ───────────────────────
        //
        // We use `tokio::task::spawn_blocking` to move the CPU-bound sanitisation
        // work onto tokio's blocking thread pool so the async runtime scheduler
        // is never stalled during heavy pixel processing.
        tokio::task::spawn_blocking(move || crate::sniffer::disarm(&payload, None))
            .await
            .map_err(|e| CdrError::IoError { message: e.to_string() })?
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Convenience constructor from a byte slice
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience function: wrap a `&[u8]` buffer in an `AsyncImageStream`.
///
/// Useful in tests or when the caller already has an in-memory buffer but
/// wants the non-blocking execution model (e.g., running inside a `tokio`
/// async context to avoid blocking the executor).
///
/// ```rust
/// use gatekeeper::async_stream::disarm_bytes_async;
///
/// #[tokio::test]
/// async fn test_async_route() {
///     let raw: &[u8] = &[0xFF, 0xD8]; // too short
///     let err = disarm_bytes_async(raw).await.unwrap_err();
///     assert!(matches!(err, gatekeeper::errors::CdrError::PayloadTooShort { .. }));
/// }
/// ```
pub async fn disarm_bytes_async(data: &[u8]) -> Result<DisarmResult, CdrError> {
    // std::io::Cursor implements Read; tokio wraps it in an AsyncRead adaptor.
    let cursor = std::io::Cursor::new(data.to_vec());
    let reader = tokio::io::BufReader::new(cursor);
    AsyncImageStream::new(reader).route_async().await
}
