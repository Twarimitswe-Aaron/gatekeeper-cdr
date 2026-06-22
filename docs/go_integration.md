# Gatekeeper Go Integration Guide

This guide demonstrates how to bind the Gatekeeper C FFI header to Go via `cgo`, intercepting `multipart/form-data` uploads directly from an `http.Handler`.

## 1. Installation

```bash
# Assuming the C header (gatekeeper.h) and shared library (libgatekeeper.so/.dylib/.dll) 
# are in your library path.
go get github.com/Twarimitswe-Aaron/gatekeeper-go
```

## 2. Standard `net/http` Integration Example

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	
	"github.com/Twarimitswe-Aaron/gatekeeper-go/gatekeeper"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// Restrict memory allocation to 32MB max
	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("document")
	if err != nil {
		http.Error(w, "Missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read file fully into memory
	rawBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// 🛡️ ZERO-TRUST SANITIZATION 🛡️
	// The CGo binding passes the byte array pointer to the Rust engine
	safeBytes, err := gatekeeper.Disarm(rawBytes)
	if err != nil {
		// e.g. "UnknownFormat", "JpegMissingEoi"
		http.Error(w, fmt.Sprintf("Rejected: %v", err), http.StatusNotAcceptable)
		return
	}

	// Save securely
	safePath := "./uploads/safe_" + header.Filename
	err = os.WriteFile(safePath, safeBytes, 0644)
	if err != nil {
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File successfully sanitized and saved."))
}

func main() {
	http.HandleFunc("/upload", uploadHandler)
	log.Println("Gatekeeper Go server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Memory Management Notice
The Go wrapper gracefully handles the C FFI pointer allocations. Because the Rust engine dynamically allocates the resulting safe file buffer, the Go wrapper utilizes a `defer C.gatekeeper_free_buffer(safe_ptr)` command internally so you do not need to worry about memory leaks.
