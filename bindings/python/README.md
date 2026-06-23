# Gatekeeper CDR (Python)

This package provides native Python bindings to the Gatekeeper CDR core, a zero-trust Content Disarm and Reconstruction engine. It sanitizes potentially malicious files by deeply inspecting and rebuilding them from raw pixel data, effectively stripping away any steganography, macros, or hidden exploits.

## Installation

```bash
pip install gatekeeper-cdr
```

*(Note: Pre-built wheels are provided for Linux, macOS, and Windows. You do not need Rust installed to use this package).*

## Usage

```python
import gatekeeper_cdr

# 1. Read a suspicious file
with open("suspicious.jpg", "rb") as f:
    raw_payload = f.read()

# 2. Detect the true format of the file without fully parsing it
try:
    fmt = gatekeeper_cdr.sniff_format(raw_payload)
    print(f"Detected Format: {fmt}") # "Jpeg", "Png", etc.
except Exception as e:
    print(f"Unknown or invalid format: {e}")

# 3. Disarm the file (returns a clean bytes object)
try:
    clean_payload = gatekeeper_cdr.disarm(raw_payload)
    with open("clean.png", "wb") as f:
        f.write(clean_payload)
    print("File successfully sanitized and saved as clean.png!")
except Exception as e:
    print(f"Failed to sanitize file: {e}")
```

## Security

If the file is malformed, structurally invalid, or contains an unknown format, Gatekeeper will intentionally raise an Exception rather than attempting to process it. This default-deny stance ensures that only provably safe files make it into your application's storage.
