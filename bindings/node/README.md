# Gatekeeper CDR (Node.js)

This package provides native Node.js bindings to the Gatekeeper CDR core, a zero-trust Content Disarm and Reconstruction engine. It sanitizes potentially malicious files by deeply inspecting and rebuilding them from raw pixel data, effectively stripping away any steganography, macros, or hidden exploits.

## Installation

```bash
npm install gatekeeper-cdr
```

*(Note: Because this is a native Rust addon, pre-built binaries are downloaded automatically during installation for Linux, macOS, and Windows. You do not need Rust installed to use this package).*

## Usage

```javascript
const fs = require('fs');
const gatekeeper = require('gatekeeper-cdr');

// 1. Read a suspicious file
const rawPayload = fs.readFileSync('suspicious.jpg');

// 2. Detect the true format of the file without fully parsing it
try {
  const format = gatekeeper.sniffFormat(rawPayload);
  console.log(`Detected Format: ${format}`); // "Jpeg", "Png", etc.
} catch (err) {
  console.error("Unknown or invalid format:", err);
}

// 3. Disarm the file (returns a clean Buffer)
try {
  const cleanPayload = gatekeeper.disarm(rawPayload);
  fs.writeFileSync('clean.png', cleanPayload);
  console.log("File successfully sanitized and saved as clean.png!");
} catch (err) {
  console.error("Failed to sanitize file:", err);
}
```

## Security

If the file is malformed, structurally invalid, or contains an unknown format, Gatekeeper will intentionally throw an error rather than attempting to process it. This default-deny stance ensures that only provably safe files make it into your application's storage.
