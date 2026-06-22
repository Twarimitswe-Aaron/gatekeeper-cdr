# Gatekeeper Java / Spring Boot Integration Guide

This guide demonstrates how to intercept an incoming file upload in a Java Spring Boot backend, sanitize the file in-memory using the JNI (Java Native Interface) Gatekeeper bindings, and securely save it.

## 1. Installation

```xml
<!-- Add the Maven dependency -->
<dependency>
    <groupId>com.gatekeeper</groupId>
    <artifactId>gatekeeper-cdr</artifactId>
    <version>1.0.0</version>
</dependency>
```

Ensure the native shared library (`libgatekeeper.so` / `gatekeeper.dll` / `libgatekeeper.dylib`) is available in your `java.library.path`.

## 2. Spring Boot Integration Example

We use `MultipartFile` in Spring Boot, which provides direct access to the byte array.

```java
package com.example.gatekeeper.controller;

import com.gatekeeper.GatekeeperCDR;
import com.gatekeeper.exceptions.GatekeeperException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@RestController
@RequestMapping("/api")
public class DocumentController {

    @PostMapping("/upload")
    public ResponseEntity<String> uploadDocument(@RequestParam("document") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("No file uploaded");
        }

        try {
            // Read raw bytes into memory
            byte[] rawBytes = file.getBytes();

            // 🛡️ ZERO-TRUST SANITIZATION 🛡️
            // GatekeeperCDR.disarm acts as a static JNI bridge to the Rust engine
            byte[] safeBytes = GatekeeperCDR.disarm(rawBytes);

            // Save the sanitized safe file
            File safeFile = new File("./uploads/safe_" + file.getOriginalFilename());
            try (FileOutputStream fos = new FileOutputStream(safeFile)) {
                fos.write(safeBytes);
            }

            return ResponseEntity.ok("File successfully sanitized and saved at: " + safeFile.getPath());

        } catch (GatekeeperException e) {
            // Gatekeeper throws a checked GatekeeperException if the structural format is invalid
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE)
                    .body("Rejected: Invalid or malicious file structure. " + e.getMessage());
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("I/O Error while processing file.");
        }
    }
}
```

## How It Works
- **JNI Translation:** The Java `byte[]` array is pinned in memory by the JVM, and a direct pointer is passed to the Rust layer. Rust processes the data and returns a new strictly allocated `byte[]` array.
- **Exception Mapping:** Internal Rust `Result::Err` enums are systematically caught and automatically instantiated as native Java `GatekeeperException` objects (with specific error strings), ensuring idiomatic Java error handling.
