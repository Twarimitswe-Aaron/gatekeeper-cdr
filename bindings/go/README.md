# Gatekeeper Go Bindings

This package provides native Go bindings to the Gatekeeper CDR core using CGo.

Because the underlying engine is written in Rust, you must have the Rust toolchain (`cargo`) installed on your system to compile the static library (`libgatekeeper.a`) before your Go code can link to it.

## Installation & Setup

1. **Install the package:**
   ```bash
   go get github.com/Twarimitswe-Aaron/gatekeeper-cdr/bindings/go
   ```

2. **Generate the Rust backend:**
   This module uses `go:generate` to invoke Cargo automatically. Run:
   ```bash
   go generate github.com/Twarimitswe-Aaron/gatekeeper-cdr/bindings/go
   ```
   *(Alternatively, you can manually run `cargo build --release` in the project root).*

3. **Build your Go project:**
   ```bash
   go build
   ```

## Usage

```go
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

	// Detect format
	fmtType, err := gatekeeper.SniffFormat(raw)
	if err != nil {
		panic(err)
	}
	fmt.Println("Detected:", fmtType) // "Jpeg" or "Png"

	// Sanitize — returns []byte containing a clean PNG
	clean, err := gatekeeper.Disarm(raw)
	if err != nil {
		panic(err)
	}

	os.WriteFile("clean.png", clean, 0644)
}
```
