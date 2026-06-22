# Gatekeeper PHP Integration Guide

This guide demonstrates how to intercept an incoming file upload in a PHP backend using the `ext-php-rs` compiled extension.

## 1. Installation

The PHP binding is compiled as a native `.so` module.
You must add it to your `php.ini`:
```ini
extension=gatekeeper.so
```

## 2. Core PHP `$_FILES` Integration

In standard PHP, uploaded files are temporarily written to the `/tmp/` directory by the web server (e.g., Apache/Nginx). We will read from this temp location, pass it to the Gatekeeper extension, and write the sanitized data to our persistent storage.

```php
<?php

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['document'])) {
    
    $tmpPath = $_FILES['document']['tmp_name'];
    $originalName = $_FILES['document']['name'];
    $error = $_FILES['document']['error'];

    if ($error !== UPLOAD_ERR_OK) {
        die("Upload failed with error code: " . $error);
    }

    // Read the temporarily cached file into memory
    $rawBytes = file_get_contents($tmpPath);

    try {
        // 🛡️ ZERO-TRUST SANITIZATION 🛡️
        // The gatekeeper_disarm function is provided globally by the gatekeeper.so extension.
        // It drops into native Rust code and returns a clean string of bytes.
        $safeBytes = gatekeeper_disarm($rawBytes);
        
        // Save the sanitized file
        $safePath = './uploads/safe_' . basename($originalName);
        file_put_contents($safePath, $safeBytes);
        
        // Delete the potentially dangerous temporary file
        unlink($tmpPath);

        http_response_code(200);
        echo json_encode([
            "message" => "File successfully sanitized and saved.",
            "safe_path" => $safePath
        ]);

    } catch (GatekeeperException $e) {
        // If the file is structurally invalid or recognized as highly malformed
        unlink($tmpPath);
        http_response_code(406);
        echo json_encode(["error" => "Rejected: " . $e->getMessage()]);
    }
} else {
    http_response_code(400);
    echo "No file provided.";
}

?>
```

## Security Consideration
Unlike Node.js or Python environments where files can easily be held exclusively in RAM (`multer.memoryStorage()`), PHP typically writes the raw upload to a `/tmp/` folder before your script executes. It is **critical** to configure your server such that the PHP `/tmp/` directory has strict `noexec` (no execution) permissions at the OS level to ensure the malicious payload cannot be triggered before Gatekeeper has the chance to sanitize it.
