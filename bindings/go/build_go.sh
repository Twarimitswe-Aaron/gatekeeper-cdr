#!/usr/bin/env bash
set -e

# This script builds the Rust static library and copies it into the Go module.
# Contributors can run this after modifying the Rust core.

echo "Building Rust core..."
cargo build --release -p gatekeeper --manifest-path ../../Cargo.toml

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

echo "Copying header and static library for $OS..."
cp ../../core/gatekeeper.h ./gatekeeper.h

if [[ "$OS" == *"linux"* ]]; then
    cp ../../target/release/libgatekeeper.a ./lib/linux/libgatekeeper.a
elif [[ "$OS" == *"darwin"* ]]; then
    cp ../../target/release/libgatekeeper.a ./lib/darwin/libgatekeeper.a
elif [[ "$OS" == *"mingw"* || "$OS" == *"msys"* ]]; then
    cp ../../target/release/gatekeeper.lib ./lib/windows/gatekeeper.lib
else
    echo "Unsupported OS: $OS"
    exit 1
fi

echo "✅ Go bindings updated with the latest compiled Rust core!"
