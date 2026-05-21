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
- [Support the Project](#support-the-project)
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
 sniff_format()   ← stack-only arrays [u8; N], zero heap allocation
       │
       ▼
 disarm()         ← one heap copy into ZCursor for the decoder
       │
       ▼
 sanitizer        ← one heap allocation for the output Vec<u8>
```

The sniffer evaluates file magic using **fixed-size stack arrays** (`[u8; 2]`, `[u8; 8]`, `[u8; 4]`). No `Vec` is constructed until the final output buffer.

### Typestate Pipeline

Every sanitizer enforces its stage transitions at **compile time** using Rust's typestate pattern. Calling stages out of order is a **compile error**, not a runtime panic.

```
JpegPipeline<RawPayload>
       │  .decode()          — zune-jpeg discards all APP/EXIF/COM markers
       ▼
JpegPipeline<DisarmedMatrix>
       │  .reconstruct()     — png encoder writes IHDR + IDAT + IEND only
       ▼
JpegPipeline<PristineStream>
       │  .into_bytes()
       ▼
     Vec<u8>                 — caller-owned, metadata-free PNG
```

### Error Model

All errors are defined in [`src/errors.rs`](src/errors.rs) as a single `CdrError` enum backed by `thiserror`. **No `String` allocations** occur at any error variant — every branch carries fixed-size typed data.

```rust
pub enum CdrError {
    PayloadTooShort { got: usize },
    UnknownFormat   { magic: [u8; 4] },
    JpegMissingEoi,
    PngMissingIhdr,
    JpegDecodeFailed  { source: zune_jpeg::errors::DecodeErrors },
    PngDecodeFailed   { source: png::DecodingError },
    MissingImageInfo,
    DegenerateDimensions { width: u16, height: u16 },
    PixelBufferMismatch  { expected: usize, got: usize },
    PngEncodeFailed   { source: png::EncodingError },
}
```

---

## Supported Formats

| Format | Detection | Sanitize | Re-encode | Status |
|--------|-----------|----------|-----------|--------|
| JPEG   | ✅ Magic + EOI check | ✅ zune-jpeg decode | ✅ PNG output | **Phase 2 — complete** |
| PNG    | ✅ Magic + IHDR check | 🔧 Planned | 🔧 Planned | Phase 3 |
| GIF    | 🔧 Planned | 🔧 Planned | 🔧 Planned | Phase 4 |
| WebP   | 🔧 Planned | 🔧 Planned | 🔧 Planned | Phase 4 |
| PDF    | 🔧 Planned | 🔧 Planned | 🔧 Planned | Phase 5 |
| DOCX   | 🔧 Planned | 🔧 Planned | 🔧 Planned | Phase 6 |

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
        └── jpeg.rs             # Full JPEG → pixel matrix → PNG pipeline
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

#### `gatekeeper::disarm(payload: &[u8]) -> Result<Vec<u8>, CdrError>`

The primary entry point. Detects format, runs the full CDR pipeline, returns clean bytes.

```rust
use gatekeeper::disarm;

let raw = std::fs::read("untrusted.jpg")?;
let clean = disarm(&raw)?; // Returns a sanitized PNG
std::fs::write("clean.png", clean)?;
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

#### `gatekeeper::sanitizers::jpeg::sanitize_jpeg(input: &[u8]) -> Result<Vec<u8>, CdrError>`

Call the JPEG sanitizer directly, bypassing the format sniffer.

```rust
use gatekeeper::sanitizers::jpeg::sanitize_jpeg;

let clean_png = sanitize_jpeg(&jpeg_bytes)?;
```

---

## FFI Bindings (Planned)

The `cdylib` target is already compiled. Phase 7+ will add idiomatic wrappers for:

| Language | Crate / Tool | Status |
|----------|-------------|--------|
| Node.js  | `napi-rs`   | Planned |
| Python   | `PyO3`      | Planned |
| PHP      | `ext-php-rs`| Planned |
| C / C++  | Raw `extern "C"` | Planned |

---

## Roadmap

- [x] **Phase 1** — Cargo manifest, error model, format sniffer
- [x] **Phase 2** — JPEG sanitization pipeline (typestate + zune-jpeg + png)
- [ ] **Phase 3** — PNG sanitization pipeline
- [ ] **Phase 4** — GIF and WebP support
- [ ] **Phase 5** — PDF sanitization (remove embedded JavaScript, OLE streams)
- [ ] **Phase 6** — DOCX / XLSX / PPTX Office format sanitization
- [ ] **Phase 7** — `napi-rs` Node.js bindings
- [ ] **Phase 8** — `PyO3` Python bindings
- [ ] **Phase 9** — `ext-php-rs` PHP bindings
- [ ] **Phase 10** — Async pipeline via Tokio for streaming large files
- [ ] **Phase 11** — WASM target for browser-side CDR

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

## Support the Project

Gatekeeper is free, open-source, and built on volunteer time. If it saves you hours of security engineering work, consider supporting continued development:

| Platform | Link |
|---|---|
| ☕ Buy Me a Coffee | [buymeacoffee.com/twarimitsweaaron](https://buymeacoffee.com/twarimitsweaaron) |
| 💖 Ko-fi | [ko-fi.com/twarimitsweaaron](https://ko-fi.com/twarimitsweaaron) |
| 🌟 GitHub Sponsors | [github.com/sponsors/Twarimitswe-Aaron](https://github.com/sponsors/Twarimitswe-Aaron) |

Your support directly funds:
- New format sanitizer implementations
- FFI binding development (Node.js, Python, PHP)
- Security audits of the core parsing layer
- Documentation and example improvements

---

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
