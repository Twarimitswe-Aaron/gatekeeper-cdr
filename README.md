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
    MissingImageInfo,
    DegenerateDimensions { width: u32, height: u32 },
    DimensionTooLarge    { dimension: u32, limit: u32 },
    ImageTooLarge        { bytes: usize, limit: usize },
    PixelBufferMismatch  { expected: usize, got: usize },
    PngEncodeFailed      { source: png::EncodingError },
    Unimplemented        { format: &'static str },  // stub — fails closed
}
```

---

## Supported Formats

| Format | Detection | Sanitize | Re-encode | Status |
|--------|-----------|----------|-----------|--------|
| JPEG   | ✅ Magic + EOI check | ✅ zune-jpeg decode | ✅ PNG output | **Phase 2 — complete** |
| PNG    | ✅ Magic + IHDR check | ✅ png crate decode | ✅ PNG output | **Phase 3 — complete** |
| GIF    | ✅ Magic check | ✅ gif crate decode | ✅ PNG output | **Phase 4 — complete** |
| WebP   | ✅ RIFF+WEBP check | ✅ image-webp decode | ✅ PNG output | **Phase 4 — complete** |
| Office | ✅ ZIP Magic check | ✅ ZIP unwrap, drop `.bin` | ✅ ZIP re-encode | **Phase 6 — complete** |
| PDF    | ✅ `%PDF-` check | ✅ `lopdf` AST load | ✅ AST strip / re-encode | **Phase 5 — complete** |

---

## Project Structure

```
gatekeeper/
├── Cargo.toml                  # Manifest: cdylib + rlib targets, dependencies
├── LICENSE                     # AGPLv3
├── CONTRIBUTING.md             # Contribution guide and PR workflow
├── README.md                   # You are here
│
├── examples/
│   └── disarm_image.rs         # CLI driver: run CDR against a real file
│
└── src/
    ├── lib.rs                  # Public API surface + format sniffer + unit tests
    ├── errors.rs               # CdrError — strongly-typed, zero-alloc error enum
    └── sanitizers/
        ├── mod.rs              # Sanitizer module index
        ├── jpeg.rs             # JPEG → pixel matrix → PNG pipeline
        └── png.rs              # PNG → pixel matrix → PNG pipeline
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
| Java     | JNI via `jni` crate | Maven / Gradle dependency | Phase 11 — complete |

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

// --- Sanitize (returns a Buffer containing a clean PNG) ---
const clean = disarm(raw);
fs.writeFileSync('clean.png', clean);

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

# --- Sanitize (returns bytes containing a clean PNG) ---
clean: bytes = gatekeeper_cdr.disarm(raw)

with open("clean.png", "wb") as f:
    f.write(clean)

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

// --- Sanitize (returns a string of raw PNG bytes) ---
$clean = gatekeeper_disarm($raw);

file_put_contents('clean.png', $clean);
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
        FILE *out = fopen("clean.png", "wb");
        fwrite(result.data, 1, result.len, out);
        fclose(out);
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

    // Sanitize — returns []byte containing a clean PNG
    clean, err := gatekeeper.Disarm(raw)
    if err != nil {
        panic(err)
    }

    os.WriteFile("clean.png", clean, 0644)
}
```

<!-- END PLANNED -->

---

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

        // Sanitize — returns byte[] containing a clean PNG
        byte[] clean = GatekeeperCdr.disarm(raw);

        Files.write(Path.of("clean.png"), clean);
    }
}
```



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
- [x] **Phase 11** — JNI Java bindings → publish to Maven Central / Gradle
- [ ] **Phase 12** — Async pipeline via Tokio for streaming large files
- [ ] **Phase 13** — WASM target for browser-side CDR

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
