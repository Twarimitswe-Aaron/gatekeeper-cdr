# Gatekeeper Node.js / Express Integration Guide

This guide demonstrates how to intercept an incoming file upload in an Express.js server, sanitize the file natively in memory using the `gatekeeper-cdr` Node.js bindings, and save the disarmed file securely.

## 1. Installation

```bash
npm install gatekeeper-cdr
# If using Express:
npm install express multer
```

## 2. Express.js Integration Example

We will use `multer` to intercept the multipart form upload into memory, and then pass the `Buffer` directly to Gatekeeper. 

```javascript
const express = require('express');
const multer = require('multer');
const { disarm } = require('gatekeeper-cdr');
const fs = require('fs/promises');

const app = express();

// Configure multer to hold the uploaded file purely in RAM
const upload = multer({ storage: multer.memoryStorage() });

app.post('/upload', upload.single('document'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "No file uploaded" });
        }

        const rawBuffer = req.file.buffer;

        // 🛡️ ZERO-TRUST SANITIZATION 🛡️
        // Pass the raw memory buffer directly into the Rust CDR engine.
        // This strips all execution vectors without allocating to disk.
        const sanitizedBuffer = disarm(rawBuffer);

        // Save the sanitized safe file
        const safePath = `./uploads/safe_${req.file.originalname}`;
        await fs.writeFile(safePath, sanitizedBuffer);

        res.status(200).json({ 
            message: "File successfully sanitized and saved.",
            safe_path: safePath
        });

    } catch (error) {
        // Gatekeeper will throw an error if the file format is completely
        // unrecognized, structurally malformed, or highly corrupted.
        console.error("Sanitization failed:", error.message);
        res.status(406).json({ error: "Rejected: Invalid or malicious file structure." });
    }
});

app.listen(3000, () => {
    console.log("Gatekeeper Node.js server running on port 3000");
});
```

## How It Works
- **Zero Disk I/O Before Sanitization:** By using `multer.memoryStorage()`, the potentially malicious file never touches your server's disk.
- **Synchronous Native Execution:** The `disarm()` function jumps from Node.js into native Rust compiled code. It processes the buffer extremely fast without blocking the Node.js event loop for long, though for massive files (>100MB), consider using the async equivalent `disarmAsync()` (coming soon).
