# Gatekeeper CDR (PHP)

This package provides native PHP bindings to the Gatekeeper CDR core, a zero-trust Content Disarm and Reconstruction engine. It sanitizes potentially malicious files by deeply inspecting and rebuilding them from raw pixel data, effectively stripping away any steganography, macros, or hidden exploits.

## Installation

```bash
composer require gatekeeper/cdr
```

*(Note: The PHP extension must be loaded in your `php.ini` file before these functions can be called).*

## Usage

```php
<?php

// 1. Read a suspicious file
$raw_payload = file_get_contents('suspicious.jpg');

// 2. Detect the true format of the file without fully parsing it
try {
    $format = gatekeeper_sniff_format($raw_payload);
    echo "Detected Format: " . $format . "\n"; // "Jpeg", "Png", etc.
} catch (Exception $e) {
    echo "Unknown or invalid format: " . $e->getMessage() . "\n";
}

// 3. Disarm the file (returns a clean string buffer)
try {
    $clean_payload = gatekeeper_disarm($raw_payload);
    file_put_contents('clean.png', $clean_payload);
    echo "File successfully sanitized and saved as clean.png!\n";
} catch (Exception $e) {
    echo "Failed to sanitize file: " . $e->getMessage() . "\n";
}
```

## Security

If the file is malformed, structurally invalid, or contains an unknown format, Gatekeeper will intentionally throw an Exception rather than attempting to process it. This default-deny stance ensures that only provably safe files make it into your application's storage.
