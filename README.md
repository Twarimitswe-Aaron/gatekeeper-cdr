<div align="center">

# 🛡️ Gatekeeper

**A zero-trust Content Disarm and Reconstruction (CDR) engine written in pure, memory-safe Rust.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust Edition](https://img.shields.io/badge/Rust%20Edition-2024-orange)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> Strip every byte of hidden metadata, embedded exploits, steganographic payloads, and trailing attachments from incoming file streams — and reconstruct a mathematically clean output from raw pixel data up.

</div>

---

## Table of Contents

- [What is Gatekeeper?](#what-is-gatekeeper)
- [Why CDR?](#why-cdr)
- [Architecture](#architecture)
  - [Memory Model](#memory-model)
  - [Typestate Pipeline](#typestate-pipeline)
  - [Error Model](#error-model)
- [Supported Formats](#supported-formats)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Run Tests](#run-tests)
  - [Run the CLI Example](#run-the-cli-example)
- [Using Gatekeeper as a Library](#using-gatekeeper-as-a-library)
  - [As a Rust Dependency](#as-a-rust-dependency)
  - [API Reference](#api-reference)
- [FFI Bindings (Planned)](#ffi-bindings-planned)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
<!-- - [Support the Project](#support-the-project) — coming soon -->
- [License](#license)

---

## What is Gatekeeper?

Gatekeeper is a **static library** that accepts multi-format file byte streams, surgically removes all non-pixel content, and reconstructs an immaculate output binary from the raw colour matrix upward. It is designed to be embedded directly into application source repositories via native FFI bindings — no infrastructure changes required.

**It does not scrub files in place.** The entire philosophy is:

> _Decode to naked pixels. Re-encode from zero. Share nothing with the original._

---

## Why CDR?

A file that "looks" clean to a human viewer can carry:

| Threat Vector | Example |
|---|---|
| Steganographic payloads | Data hidden in JPEG DCT coefficient LSBs |
| Exploit shellcode | Embedded in APP0–APP15 markers |
| Personal data leakage | EXIF GPS coordinates, device serial numbers |
| Tracking fingerprints | ICC profile unique identifiers |
| Polyglot containers | Executable bytes after the EOI/IEND marker |
| C2 callbacks | URLs encoded inside COM/XMP marker blocks |

Classic AV scanning **misses all of these**. CDR eliminates the attack surface entirely by making it structurally impossible for the output to contain anything other than colour values.

---

## Architecture

### Memory Model

Gatekeeper enforces a strict **zero-copy architecture** at the format-detection layer:

```
caller buffer (&[u8])
       │
       ▼
 sniff_format()   ← direct slice equality payload[..N] == MAGIC, zero heap
       │
       ▼
 disarm()         ← ZCursor borrows the slice; no copy until decode
       │
       ▼
 sanitizer        ← one heap allocation for the decoded pixel buffer
       │
       ▼
SanitizedOutput   ← one heap allocation for the re-encoded PNG output
```

The sniffer compares magic bytes using **direct subslice equality** (`payload[..2] == JPEG_SOI`). No intermediate buffers or `Vec` are constructed during format detection — the comparison resolves in a single register-level load.

### Typestate Pipeline

Every sanitizer enforces its stage transitions at **compile time** using Rust's typestate pattern with **newtype tuple structs**. Calling stages out of order is a **compile error**, not a runtime panic. Passing raw bytes to a save routine is also a **compile error** — only `SanitizedOutput` is accepted.

```
RawPayload<'a>(&'a [u8])       – zero-copy borrow; no data written
       │  .decode()              – zune-jpeg decodes; all APP/EXIF/COM discarded
       ▼
DisarmedMatrix(PixelMatrix)    – opaque wrapper; only formal destructuring allowed
       │  .reconstruct()         – png encoder writes IHDR + IDAT + IEND only
       ▼
PristineStream(Vec<u8>)        – opaque wrapper; shares zero bytes with input
       │  .into_sanitized()
       ▼
SanitizedOutput(Vec<u8>)       – public token; only type a save routine may accept
       │  .into_bytes()
       ▼
     Vec<u8>                    – caller-owned, metadata-free PNG
```

Inside the crate, inner values are always extracted via the formal pattern:
```rust
let RawPayload(bytes)   = stage;  // not stage.bytes
let DisarmedMatrix(mat) = stage;  // not stage.0 or stage.pixels
let PristineStream(buf) = stage;  // not stage.output
let SanitizedOutput(v)  = output; // not output.0
```

### Error Model

All errors are defined in [`src/errors.rs`](src/errors.rs) as a single `CdrError` enum backed by `thiserror`. **No `String` allocations** occur at any error variant — every branch carries fixed-size typed data.

```rust
pub enum CdrError {
    PayloadTooShort      { got: usize },
    PayloadTooLarge      { got: usize, limit: usize },
    UnknownFormat        { magic: [u8; 4] },
    JpegMissingEoi,
    PngMissingIhdr,
    JpegDecodeFailed     { source: zune_jpeg::errors::DecodeErrors },
    PngDecodeFailed      { source: png::DecodingError },
    GifDecodeFailed      { source: gif::DecodingError },
    MissingImageInfo,
    DegenerateDimensions { width: u32, height: u32 },
    DimensionTooLarge    { dimension: u32, limit: u32 },
    ImageTooLarge        { bytes: usize, limit: usize },
    PixelBufferMismatch  { expected: usize, got: usize },
    PngEncodeFailed      { source: png::EncodingError },
    GifEncodeFailed      { source: gif::EncodingError },
    Unimplemented        { format: &'static str },  // stub — fails closed
}
```

### Dual-Output Contract

Every call to `disarm()` returns a `DisarmResult` containing **two buffers**:

```
DisarmResult {
    buffer:           Vec<u8>         // sanitized in the ORIGINAL input format
    png_buffer:       Option<Vec<u8>> // lossless PNG version (None when buffer IS already PNG)
    detected_format:  &'static str    // "jpeg" | "png" | "gif" | "webp" | "office" | "pdf"
    output_format:    &'static str    // format of buffer
    original_size_bytes: usize
    final_size_bytes:    usize        // size of buffer
}
```

| Input | `buffer` | `png_buffer` | Rationale |
|-------|----------|-------------|----------|
| JPEG | JPEG (q85, metadata stripped) | `Some(PNG)` | Two distinct representations |
| PNG | PNG (lossless) | `None` | `buffer` IS already the lossless PNG |
| GIF | GIF (extensions stripped) | `Some(PNG)` | Two distinct representations |
| WebP | PNG (no Rust WebP encoder) | `None` | `buffer` IS already the lossless PNG |
| PDF | PDF (actions stripped) | `None` | Not an image |
| Office | Office/ZIP (active content stripped) | `None` | Not an image |

### Why is the sanitized file a different size?

Gatekeeper **never** scrubs bytes in place. Every image passes through:

```text
compressed file  →  decode to raw pixels  →  re-encode from scratch
     (input)            (memory only)           (output buffer)
```

The output shares **zero bytes** with the input. Size changes are normal and come from three separate causes:

#### 1. Format change (often much larger — expected)

| What you compare | Why it grows |
|------------------|--------------|
| **JPEG in → `png_buffer` out** | Lossy JPEG discards information; lossless PNG stores every decoded pixel exactly. Typically **2–5× larger**. This is correct — use `buffer` (JPEG) when size matters, `png_buffer` when you need a mathematically exact pixel guarantee. |
| **GIF in → `png_buffer` out** | GIF is palette-indexed and LZW-compressed; the PNG companion is full RGBA lossless. Usually larger. |
| **WebP in → `buffer` out** | No pure-Rust WebP encoder exists yet, so WebP is decoded to pixels and emitted as PNG. |

#### 2. Lossy generation loss (JPEG / GIF native `buffer`)

| Path | Behaviour |
|------|-----------|
| **JPEG → JPEG** (`buffer`) | Fully decoded to RGB, then re-quantized at **quality 85**. This destroys steganographic DCT payloads. Size vs the original depends on the **source** quality: a q60 upload may grow; a q95 upload may shrink. Gatekeeper does not copy the original quantization tables — that would preserve hidden data. |
| **GIF → GIF** (`buffer`) | Re-quantized with NeuQuant into a fresh local palette. Extension/comment blocks are dropped (smaller), but LZW efficiency may differ from the hand-tuned original. |

#### 3. Re-compression of lossless formats (PNG native `buffer`)

PNG sanitization decodes pixels and writes a **new** PNG containing only `IHDR + PLTE/tRNS (if needed) + IDAT + IEND`. All metadata chunks (`tEXt`, `iCCP`, `eXIf`, trailing polyglot bytes) are removed — which **reduces** size.

The remaining IDAT size depends on deflate level **and** PNG filter strategy:

| Setting | Effect |
|---------|--------|
| `Compression::Best` (zlib level 9) | Strong deflate — already used. |
| **Adaptive Paeth filtering** (per scanline) | Critical for size. Without it, IDAT can be **2–3× larger** than the source even after metadata is stripped. Gatekeeper enables adaptive Paeth on every PNG encode path. |

PNG outputs may still be slightly larger than files passed through slow offline optimizers (`optipng -o7`, Zopfli, brute-force filter search). Gatekeeper targets **real-time** sanitization, not maximum offline compression.

#### Quick reference: which buffer should I use?

| Goal | Use |
|------|-----|
| Smallest image output | `buffer` (native format: JPEG/GIF/PNG) |
| Exact pixel proof / zero-trust archive | `png_buffer` when present, or `buffer` for PNG/WebP inputs |
| Compare size fairly | Compare `buffer` to the **same format** as the input, not `png_buffer` to a JPEG |

#### Size fields on `DisarmResult`

```text
original_size_bytes  — length of the untrusted input you passed in
final_size_bytes     — length of `buffer` only (png_buffer is extra)
```

To log both outputs: `result.buffer.len()` and `result.png_buffer.as_ref().map(|p| p.len())`.

---

## Enterprise Readiness Analysis

### What Gatekeeper Already Does Right

| Property | Status | Detail |
|----------|--------|--------|
| Zero-copy format detection | ✅ | Magic bytes compared via direct slice equality, no allocations |
| Decompression-bomb guards | ✅ | Geometry + pixel-budget checks fire **before** any allocation |
| Typestate pipeline | ✅ | Stage transitions are compile errors, not runtime panics |
| Dual-output (native + PNG) | ✅ | Single call returns both the native format and a lossless PNG |
| No `String` on error paths | ✅ | Every `CdrError` variant carries typed structured data |
| Async streaming | ✅ | `AsyncImageStream` + `disarm_bytes_async()` via Tokio |
| Input size caps | ✅ | Hard limits enforced before any decoder work begins |

### Known Gaps vs. Enterprise CDR

Commercial CDR products (Glasswall, Votiro, OPSWAT MetaDefender) address the following that Gatekeeper does not yet:

| Gap | Impact | Planned Fix |
|-----|--------|-------------|
| **Double decode for JPEG dual-output** | 2× CPU cost per JPEG; highest-priority fix | `sanitize_jpeg_dual()` — decode once, encode to both JPEG and PNG from the same pixel buffer (Phase 12) |
| **32 MiB hard input cap** | Blocks large document workflows | `CdrPolicy` struct passed into `disarm()` with configurable limits (Phase 13) |
| **No deterministic JPEG output** | Encoder version changes produce different bytes for the same input | Use a fixed published quantization table instead of quality parameter |
| **No audit receipt** | Cannot cryptographically prove a file was sanitized | Return a `Blake3` hash of the output buffer alongside the bytes |
| **No policy engine** | One fixed set of limits for all callers | `CdrPolicy { max_bytes, jpeg_quality, allowed_formats, … }` |
| **WebP output is PNG** | Format change surprises callers expecting WebP back | Add `libwebp` bindings via `webp` crate for true WebP→WebP |
| **GIF nearest-colour quantization** | Palette-heavy images shift colours visibly | NeuQuant re-encode (done); Wu/median-cut optional |

### Is the Current Approach Production-Ready?

For **embedded / edge deployments** (IoT gateways, upload proxies, CI artifact scanning) — **yes**. The architecture is sound: zero-copy parsing, compile-time stage enforcement, bomb guards, and dual-output with no wasted allocations.

For **enterprise SaaS at scale** (100k+ files/day), the single highest-impact change is eliminating the **double decode** for JPEG:

```rust
// Current: 2 decode passes per JPEG
let jpeg_bytes = sanitize_jpeg(payload)?.into_bytes();
let png_bytes  = sanitize_jpeg_to_png(payload)?.into_bytes();

// Phase 12 target: 1 decode, 2 encodes
let (jpeg_bytes, png_bytes) = sanitize_jpeg_dual(payload)?;
//                             ^^ decode once → encode to JPEG + PNG simultaneously
```

This single change halves CPU cost for all JPEG inputs. Everything else in the roadmap is additive.

---

## Supported Formats

| Format | Detection | Sanitize | Native Output | PNG Output | Status |
|--------|-----------|----------|---------------|------------|--------|
| JPEG   | ✅ Magic + EOI check | ✅ zune-jpeg decode | ✅ JPEG (q85, metadata stripped) | ✅ Lossless PNG | **Complete** |
| PNG    | ✅ Magic + IHDR check | ✅ png crate decode | ✅ PNG (lossless, adaptive Paeth) | — (buffer IS the PNG) | **Complete** |
| GIF    | ✅ Magic check | ✅ gif crate decode | ✅ GIF (NeuQuant re-indexed) | ✅ Lossless RGBA PNG | **Complete** |
| WebP   | ✅ RIFF+WEBP check | ✅ image-webp decode | ✅ PNG (no pure-Rust WebP encoder) | — (buffer IS the PNG) | **Complete** |
| Office | ✅ ZIP Magic check | ✅ ZIP unwrap + active-content strip | ✅ ZIP re-encode | — (not an image) | **Complete** |
| PDF    | ✅ `%PDF-` check | ✅ `lopdf` recursive strip | ✅ PDF re-encode | — (not an image) | **Complete** |

---

## Project Structure

```
gatekeeper/
├── Cargo.toml                  # Workspace manifest + release profiles
├── AGENTS.md                   # AI agent / release SOP
├── LICENSE                     # AGPLv3
├── CONTRIBUTING.md
├── README.md
│
├── core/                       # Rust CDR engine (crate: gatekeeper)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs              # Public API + tests
│       ├── sniffer.rs          # Format detection + disarm() dispatch
│       ├── errors.rs           # CdrError taxonomy
│       ├── ffi.rs              # C ABI for Go / Java
│       ├── stream.rs           # ImageStream (sync)
│       ├── async_stream.rs     # AsyncImageStream (Tokio)
│       └── sanitizers/
│           ├── encode.rs       # Shared encoder tuning (PNG filters, JPEG q)
│           ├── jpeg.rs           # JPEG pipeline
│           ├── png.rs            # PNG pipeline
│           ├── gif.rs            # GIF pipeline
│           ├── webp.rs           # WebP pipeline
│           ├── pdf.rs            # PDF pipeline
│           └── office.rs         # Office OOXML pipeline
│
├── bindings/
│   ├── node/                   # npm: gatekeeper-cdr (napi-rs)
│   ├── python/                 # PyPI: gatekeeper-cdr (PyO3)
│   ├── go/                     # pkg.go.dev (CGo + static libs)
│   ├── java/                   # Maven (JNI)
│   └── php/                    # Packagist (ext-php-rs)
│
└── examples/
    └── disarm_image.rs         # CLI driver
```

---

## Getting Started

### Prerequisites

- **Rust 1.85+** (Edition 2024 requires Rust ≥ 1.85)
  ```bash
  rustup update stable
  rustc --version
  ```

### Build

```bash
git clone https://github.com/Twarimitswe-Aaron/gatekeeper-cdr.git
cd gatekeeper-cdr
cargo build
```

This produces:
- `target/debug/libgatekeeper.rlib` — Rust linkable library
- `target/debug/libgatekeeper.so` — Native shared library (cdylib)

For a release (optimised) build:
```bash
cargo build --release
```

### Run Tests

```bash
# All unit tests + doc-tests
cargo test

# A specific test by name
cargo test detects_jpeg_format

# With output (useful for debugging)
cargo test -- --nocapture
```

Expected output:
```
running 8 tests
test tests::boundary_at_min_sniff_len ... ok
test tests::detects_jpeg_format       ... ok
test tests::detects_png_format        ... ok
test tests::rejects_empty_slice       ... ok
test tests::rejects_jpeg_without_eoi  ... ok
test tests::rejects_png_without_ihdr  ... ok
test tests::rejects_slice_shorter_than_min ... ok
test tests::rejects_unknown_magic     ... ok

test result: ok. 8 passed; 0 failed
```

### Run the CLI Example

The `examples/disarm_image.rs` driver lets you test the full pipeline against any real file:

```bash
# Auto-named output  →  photo.sanitized.png
cargo run --example disarm_image -- photo.jpg

# Explicit output path
cargo run --example disarm_image -- suspicious.jpg clean.png

# Works on PNG input too (format sniffer validates first)
cargo run --example disarm_image -- image.png stripped.png
```

Sample output:
```
▶ Reading  : suspicious.jpg
  Size     : 204800 bytes (200.00 KB)
  Format   : Jpeg
▶ Disarming...
  Output   : 187392 bytes (183.00 KB)
▶ Writing  : suspicious.sanitized.png
✔ Done. Sanitized PNG written to: suspicious.sanitized.png
```

---

## Using Gatekeeper as a Library

### As a Rust Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
gatekeeper = { git = "https://github.com/Twarimitswe-Aaron/gatekeeper-cdr.git" }
```

Or for a local checkout:
```toml
[dependencies]
gatekeeper = { path = "../gatekeeper" }
```

### API Reference

#### `gatekeeper::disarm(payload: &[u8]) -> Result<SanitizedOutput, CdrError>`

The primary entry point. Detects format, runs the full CDR pipeline, and returns a `SanitizedOutput` token — a distinct type that can only be produced by a completed pipeline run.

```rust
use gatekeeper::disarm;

let raw = std::fs::read("untrusted.jpg")?;
let clean = disarm(&raw)?;            // Returns SanitizedOutput, not Vec<u8>
std::fs::write("clean.png", clean.into_bytes())?;
```

To enforce that a save function only ever accepts sanitised data:

```rust
use gatekeeper::{disarm, sanitizers::jpeg::SanitizedOutput};

fn save(file: SanitizedOutput) {      // raw Vec<u8> cannot be passed here
    std::fs::write("out.png", file.into_bytes()).unwrap();
}

let raw = std::fs::read("untrusted.jpg")?;
save(disarm(&raw)?);
```

#### `gatekeeper::sniff_format(payload: &[u8]) -> Result<FileFormat, CdrError>`

Identify the format of a byte slice without modifying or decoding it. Useful for routing in larger pipelines.

```rust
use gatekeeper::{sniff_format, FileFormat};

match sniff_format(&bytes)? {
    FileFormat::Jpeg => println!("It's a JPEG"),
    FileFormat::Png  => println!("It's a PNG"),
}
```

#### `gatekeeper::sanitizers::jpeg::sanitize_jpeg(input: &[u8]) -> Result<SanitizedOutput, CdrError>`

Call the JPEG sanitizer directly, bypassing the format sniffer.

```rust
use gatekeeper::sanitizers::jpeg::sanitize_jpeg;

let output = sanitize_jpeg(&jpeg_bytes)?;  // Returns SanitizedOutput
let clean_png = output.into_bytes();
```

---

## FFI Bindings (Planned)

The `cdylib` target is already compiled and emits a native shared library (`.so` / `.dll` / `.dylib`).
The sections below show the **planned** import and usage API for each target language.
These bindings do not exist yet — they are the design target for Phases 7–11.

| Language | Bridge / tool | Install package | Status |
|----------|--------------|-----------------|--------|
| Node.js  | `napi-rs`    | `npm install gatekeeper-cdr` | Phase 7 — complete |
| Python   | `PyO3`       | `pip install gatekeeper-cdr` | Phase 8 — complete |
| PHP      | `ext-php-rs` | `composer require gatekeeper/cdr` | Phase 9 — complete |
| C / C++  | Raw `extern "C"` | Link `libgatekeeper.so` | Phase 9 — complete |
| Go       | CGo + `extern "C"` | `go get github.com/Twarimitswe-Aaron/gatekeeper-cdr/bindings/go` | Phase 10 — complete |
| Java     | JNI via `jni` crate | Maven / Gradle dependency | Phase 11 — pending Maven Central |

---

### Node.js (via napi-rs)



```js
// Install:
//   npm install gatekeeper-cdr
//   yarn add gatekeeper-cdr

const { disarm, sniffFormat } = require('gatekeeper-cdr');

// --- Detect format ---
const fs = require('fs');
const raw = fs.readFileSync('suspicious.jpg');

const format = sniffFormat(raw);   // Returns 'Jpeg' | 'Png'
console.log('Detected:', format);

// --- Sanitize (Dual-Output ABI returns both Native and PNG formats) ---
const result = disarm(raw);
fs.writeFileSync(`clean.${result.outputFormat.toLowerCase()}`, result.buffer);

if (result.pngBuffer) {
    fs.writeFileSync('clean_zerotrust.png', result.pngBuffer);
}
console.log(`Sanitized: ${result.originalSizeBytes} bytes -> ${result.finalSizeBytes} bytes`);

// --- ES Module import (planned) ---
// import { disarm, sniffFormat } from 'gatekeeper-cdr';
```



---

### Python (via PyO3)



```python
# Install:
#   pip install gatekeeper-cdr

import gatekeeper_cdr

# --- Detect format ---
with open("suspicious.jpg", "rb") as f:
    raw: bytes = f.read()

fmt: str = gatekeeper_cdr.sniff_format(raw)   # Returns 'Jpeg' or 'Png'
print(f"Detected: {fmt}")

# --- Sanitize (Dual-Output ABI returns both Native and PNG formats) ---
result = gatekeeper_cdr.disarm(raw)

with open(f"clean.{result.output_format.lower()}", "wb") as f:
    f.write(result.buffer)

if result.png_buffer:
    with open("clean_zerotrust.png", "wb") as f:
        f.write(result.png_buffer)

print(f"Sanitized: {result.original_size_bytes} bytes -> {result.final_size_bytes} bytes")

# --- Async variant (planned for Phase 10) ---
# clean = await gatekeeper_cdr.disarm_async(raw)
```



---

### PHP (via ext-php-rs)



```php
<?php
// Install:
//   Add the compiled libgatekeeper.so to your php.ini:
//   extension=/path/to/gatekeeper_cdr.so
//
//   Or via Composer (planned):
//   composer require gatekeeper/cdr

// --- Detect format ---
$raw = file_get_contents('suspicious.jpg');

$format = gatekeeper_sniff_format($raw);  // Returns "Jpeg" or "Png"
echo "Detected: $format\n";

// --- Sanitize (Dual-Output ABI returns both Native and PNG formats) ---
$result = gatekeeper_disarm($raw);

file_put_contents('clean.' . strtolower($result['output_format']), $result['buffer']);

if (!empty($result['png_buffer'])) {
    file_put_contents('clean_zerotrust.png', $result['png_buffer']);
}

echo "Sanitized: {$result['original_size_bytes']} bytes -> {$result['final_size_bytes']} bytes\n";
?>
```

<!-- END PLANNED -->

---

### C / C++ (Raw FFI)



```c
// Link against:  -L. -lgatekeeper -Wl,-rpath,.
// Header:        #include "gatekeeper.h"

#include <stdio.h>
#include <stdlib.h>
#include "gatekeeper.h"

int main(void) {
    /* Read file into buffer (caller-managed memory) */
    FILE *f = fopen("suspicious.jpg", "rb");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);
    uint8_t *raw = malloc(len);
    fread(raw, 1, len, f);
    fclose(f);

    /* Sanitize — returns a heap-allocated CdrResult */
    CdrResult result = gatekeeper_disarm(raw, len);

    if (result.ok) {
        FILE *out = fopen("clean.native", "wb");
        fwrite(result.data, 1, result.len, out);
        fclose(out);
        
        if (result.png_len > 0 && result.png_data != NULL) {
            FILE *png_out = fopen("clean_zerotrust.png", "wb");
            fwrite(result.png_data, 1, result.png_len, png_out);
            fclose(png_out);
        }
    } else {
        fprintf(stderr, "CDR error code: %d\n", result.error_code);
    }

    /* Always free the CdrResult buffer through the library */
    gatekeeper_free_result(result);
    free(raw);
    return 0;
}
```



---

### Go (via CGo)

<!-- PLANNED — not yet implemented. Will be distributed as a Go module on pkg.go.dev. -->
```go
// Install:
//   go get github.com/Twarimitswe-Aaron/gatekeeper-cdr/bindings/go

package main

import (
    "fmt"
    "os"
    gatekeeper "github.com/Twarimitswe-Aaron/gatekeeper-cdr/bindings/go"
)

func main() {
    raw, err := os.ReadFile("suspicious.jpg")
    if err != nil {
        panic(err)
    }

    // Detect format (does not allocate, stack-only in Rust)
    fmt, err := gatekeeper.SniffFormat(raw)
    if err != nil {
        panic(err)
    }
    fmt.Println("Detected:", fmt) // "Jpeg" or "Png"

    // Sanitize (Dual-Output ABI returns both Native and PNG formats)
    result, err := gatekeeper.Disarm(raw)
    if err != nil {
        panic(err)
    }

    os.WriteFile("clean.native", result.Buffer, 0644)
    
    if len(result.PngBuffer) > 0 {
        os.WriteFile("clean_zerotrust.png", result.PngBuffer, 0644)
    }
    
    fmt.Printf("Sanitized: %s\n", result.OutputFormat)
}
```

<!-- END PLANNED -->

---

<!--
### Java (via JNI)


```xml
<!-- Maven (pom.xml) -->
<dependency>
    <groupId>io.github.twarimitswe-aaron</groupId>
    <artifactId>gatekeeper-cdr</artifactId>
    <version>0.1.0</version>
</dependency>
```

```groovy
// Gradle (build.gradle)
implementation 'io.github.twarimitswe-aaron:gatekeeper-cdr:0.1.0'
```

```java
import io.github.gatekeeper.GatekeeperCdr;
import io.github.gatekeeper.FileFormat;

import java.nio.file.Files;
import java.nio.file.Path;

public class Main {
    public static void main(String[] args) throws Exception {
        byte[] raw = Files.readAllBytes(Path.of("suspicious.jpg"));

        // Detect format
        FileFormat fmt = GatekeeperCdr.sniffFormat(raw);
        System.out.println("Detected: " + fmt); // JPEG or PNG

        // Sanitize (Dual-Output ABI returns both Native and PNG formats)
        // DisarmResult result = GatekeeperCdr.disarm(raw);
        // Files.write(Path.of("clean." + result.getOutputFormat().toLowerCase()), result.getBuffer());
        //
        // if (result.getPngBuffer() != null) {
        //     Files.write(Path.of("clean_zerotrust.png"), result.getPngBuffer());
        // }
    }
}
```
-->



---

## Roadmap

- [x] **Phase 1** — Cargo manifest, error model, format sniffer
- [x] **Phase 2** — JPEG sanitization pipeline (typestate + zune-jpeg + png)
- [x] **Phase 3** — PNG sanitization pipeline
- [x] **Phase 4** — GIF and WebP support
- [x] **Phase 5** — PDF sanitization (remove embedded JavaScript, OLE streams)
- [x] **Phase 6** — Office format sanitization (DOCX / XLSX / PPTX)
- [x] **Phase 7** — `napi-rs` Node.js bindings → publish to npm
- [x] **Phase 8** — `PyO3` Python bindings → publish to PyPI
- [x] **Phase 9** — `ext-php-rs` PHP bindings + C/C++ raw header → publish to Packagist
- [x] **Phase 10** — CGo Go bindings → publish Go module to pkg.go.dev
- [x] **Phase 11** — JNI Java bindings → *pending Maven Central publish*
- [ ] **Phase 12** — Single-pass JPEG dual-output (`sanitize_jpeg_dual`) to eliminate double-decode
- [ ] **Phase 13** — `CdrPolicy` struct: configurable size limits, quality, format allowlist
- [x] **Phase 14** — Async pipeline via Tokio for streaming large files
- [ ] **Phase 15** — WASM target for browser-side CDR

---

## Contributing

Gatekeeper is open-source under AGPLv3 and **actively welcomes contributions**. Please read the full guide before opening a PR:

👉 **[CONTRIBUTING.md](CONTRIBUTING.md)**

Quick summary:

1. **Fork** the repository
2. **Create a branch** — `git checkout -b feat/png-sanitizer`
3. **Write tests** — new code must include unit tests
4. **Check** — `cargo test && cargo clippy && cargo fmt --check`
5. **Open a PR** against `main` using the PR template

For larger changes (new format support, architectural changes), please **open an issue first** to discuss the approach before writing code.

---

<!-- ## Support the Project

Donation links will be added here once the payment platforms are set up.
Uncomment this section and fill in the real URLs when ready.

Gatekeeper is free, open-source, and built on volunteer time. If it saves you hours
of security engineering work, consider supporting continued development:

| Platform | Link |
|---|---|
| ☕ Buy Me a Coffee | [buymeacoffee.com/YOUR_USERNAME](https://buymeacoffee.com/YOUR_USERNAME) |
| 💖 Ko-fi | [ko-fi.com/YOUR_USERNAME](https://ko-fi.com/YOUR_USERNAME) |
| 🌟 GitHub Sponsors | [github.com/sponsors/YOUR_USERNAME](https://github.com/sponsors/YOUR_USERNAME) |

Your support directly funds:
- New format sanitizer implementations
- FFI binding development (Node.js, Python, PHP)
- Security audits of the core parsing layer
- Documentation and example improvements

-->

## License

Gatekeeper is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.

This means:
- ✅ You may use, modify, and distribute this code freely
- ✅ You may use it in commercial applications
- ⚠️ If you modify it and run it as a network service, you **must** publish your modifications under the same license
- ⚠️ All derivative works must carry the AGPLv3 license

See [`LICENSE`](LICENSE) for the full text.

---

<div align="center">
  <sub>Built with 🦀 Rust · Licensed under AGPLv3 · Contributions welcome</sub>
</div>
