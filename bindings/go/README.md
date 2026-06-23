# Gatekeeper Go Bindings

This package provides native Go bindings to the Gatekeeper CDR core using CGo.

We distribute pre-compiled static libraries for Linux, macOS, and Windows directly in this repository. This means you do **not** need Rust installed to use this package in your Go projects!

## Installation & Setup

1. **Install the package:**
   ```bash
   go get github.com/Twarimitswe-Aaron/gatekeeper-cdr/bindings/go
   ```

2. **Build your Go project:**
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

## Contributing

If you modify the underlying Rust core (`gatekeeper`), you must recompile the static libraries and copy them into the Go module before committing.

We have provided a helper script to do this automatically for your current OS:

```bash
cd bindings/go
./build_go.sh
```

This will run `cargo build` and copy the resulting `libgatekeeper.a` and `gatekeeper.h` into the `bindings/go/lib/` directory.
