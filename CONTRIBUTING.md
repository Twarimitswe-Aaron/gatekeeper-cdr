# Contributing to Gatekeeper

Thank you for your interest in making Gatekeeper better. This document covers everything you need to know to contribute effectively — from filing a bug report to landing a production-quality PR.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Before You Start](#before-you-start)
- [Development Setup](#development-setup)
  - [1. Fork and clone](#1-fork-and-clone)
  - [2. Verify toolchain](#2-verify-toolchain)
  - [3. Enable the Git hooks](#3-enable-the-git-hooks)
  - [4. Confirm the baseline passes](#4-confirm-the-baseline-passes)
- [Project Structure](#project-structure)
- [Branching Strategy](#branching-strategy)
- [Making a Pull Request (Step-by-Step)](#making-a-pull-request-step-by-step)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Commit Message Format](#commit-message-format)
- [Working on a Specific Binding](#working-on-a-specific-binding)
- [Using the Cross-Platform Testbed](#using-the-cross-platform-testbed)
- [What Makes a Good PR](#what-makes-a-good-pr)
- [Review Process](#review-process)
- [Architecture Primer](#architecture-primer)

---

## Code of Conduct

This project follows a simple rule: **be professional and constructive**. Critique code, not people. All communication must be respectful. Contributors who violate this will be removed from the project without warning.

---

## Ways to Contribute

You do not need to write code to contribute. Here are all the ways you can help:

| Type | Description |
|------|-------------|
| 🐛 **Bug report** | Found something that produces wrong output or panics? Open an issue. |
| 💡 **Feature request** | New format support, API idea, or integration? Open a discussion. |
| 📖 **Documentation** | Fix a typo, improve an explanation, add an example. |
| ✅ **Tests** | Add unit tests for edge cases not currently covered. |
| 🔧 **Code** | Implement a feature from the roadmap or fix a confirmed bug. |
| 🔒 **Security audit** | Review the parsing layer for memory-safety issues. |
| 🌍 **Binding improvement** | Add a feature to an existing Node.js, Python, PHP, or Go binding. |
| 🧪 **Testbed** | Improve or extend the cross-platform interactive testbed. |

---

## Before You Start

### For bug fixes and small improvements
Just open a PR. No prior discussion needed.

### For new format sanitizers or architectural changes
**Open an issue first.** Explain:
- What format you want to support
- Your proposed approach (especially the decode + re-encode libraries)
- Any known edge cases or threat model considerations

This prevents duplicate work and ensures alignment with the project's zero-trust architecture before you invest significant time.

---

## Development Setup

### 1. Fork and clone

```bash
# Fork via GitHub UI, then:
git clone https://github.com/YOUR_USERNAME/gatekeeper-cdr.git
cd gatekeeper-cdr

# Add upstream remote so you can pull future changes
git remote add upstream https://github.com/Twarimitswe-Aaron/gatekeeper-cdr.git
```

### 2. Verify toolchain

Gatekeeper uses **Rust Edition 2024**, which requires Rust 1.85 or later.

```bash
rustc --version    # Must be 1.85.0 or later
cargo --version
cargo clippy --version
```

If your toolchain is older:
```bash
rustup update stable
```

### 3. Enable the Git hooks

The repository ships a `pre-push` hook that runs the core test suite before every push. Enable it once after cloning:

```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-push
```

This ensures you never accidentally push code that breaks `cargo test -p gatekeeper`.

### 4. Confirm the baseline passes

```bash
cd core
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

All three must pass before you start making changes, and again before you open a PR.

---

## Project Structure

```
gatekeeper-cdr/
│
├── core/                        # ← The Rust CDR engine (source of truth)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs               # Public API + format sniffer + unit tests
│       ├── errors.rs            # CdrError — zero-alloc typed errors
│       ├── ffi.rs               # C FFI exports (gatekeeper_disarm, gatekeeper_sniff_format)
│       ├── sniffer.rs           # Format detection + disarm() dispatcher
│       ├── stream.rs            # Sync ImageStream wrapper
│       ├── async_stream.rs      # Async Tokio streaming wrapper
│       └── sanitizers/
│           ├── mod.rs
│           ├── jpeg.rs          # JPEG typestate pipeline (reference implementation)
│           ├── png.rs           # PNG typestate pipeline
│           ├── gif.rs           # GIF typestate pipeline
│           ├── webp.rs          # WebP typestate pipeline
│           ├── office.rs        # Office/ZIP sanitizer
│           └── pdf.rs           # PDF sanitizer
│
├── bindings/
│   ├── node/                    # napi-rs → npm package (gatekeeper-cdr)
│   ├── python/                  # PyO3 → PyPI package (gatekeeper-cdr)
│   ├── php/                     # FFI → Packagist (twarimitswe-aaron/gatekeeper-cdr)
│   ├── go/                      # CGo → Go module (bindings/go)
│   └── java/                    # JNI → Maven (pending Central publish)
│
├── test-gatekeeper-cdr/         # ← Cross-platform interactive testbed
│   ├── frontend/                # SvelteKit UI
│   ├── backend-node/            # Express server on port 3001
│   ├── backend-go/              # Go server on port 3002
│   ├── backend-java/            # Spring Boot server on port 3003 (disabled)
│   ├── backend-php/             # PHP built-in server on port 3004
│   └── backend-python/          # FastAPI server on port 3005
│
├── composer.json                # PHP package manifest (published to Packagist)
├── CONTRIBUTING.md              # This file
└── README.md                    # Project overview
```

The **engine lives in `core/`**. The bindings in `bindings/` are thin wrappers that call into the compiled core. The testbed in `test-gatekeeper-cdr/` is for integration-level testing across all language runtimes.

---

## Branching Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, always passes `cargo test` |
| `feat/*` | New feature development |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation-only changes |
| `refactor/*` | Internal restructuring with no behaviour change |
| `test/*` | Adding or improving tests only |
| `binding/*` | Changes scoped to a specific language binding |

**Always branch off `main`:**
```bash
git checkout main
git pull upstream main
git checkout -b feat/gif-sanitizer
```

---

## Making a Pull Request (Step-by-Step)

### Step 1 — Implement your change

Follow the [Code Standards](#code-standards) below. Keep your changes focused — one logical change per PR.

### Step 2 — Write or update tests

Every code change must be accompanied by tests. See [Testing Requirements](#testing-requirements).

### Step 3 — Run the full check suite locally

```bash
cd core

# 1. All tests must pass
cargo test

# 2. No Clippy warnings (treated as errors in CI)
cargo clippy -- -D warnings

# 3. Code must be formatted
cargo fmt

# 4. Docs must compile
cargo doc --no-deps
```

### Step 4 — Commit your changes

Follow the [Commit Message Format](#commit-message-format) below.

```bash
git add .
git commit -m "[+]: implement GIF transparency preservation in sanitizer"
```

### Step 5 — Push your branch

The pre-push hook will run `cargo test -p gatekeeper` automatically before the push completes.

```bash
git push origin feat/your-branch-name
```

### Step 6 — Open the PR on GitHub

1. Go to your fork on GitHub
2. Click **"Compare & pull request"**
3. Fill in the PR template (it will appear automatically)
4. Set the base branch to `main`
5. Add a clear title and description
6. Link any related issues: `Closes #42`
7. Request a review if you know who to tag; otherwise leave it open

### Step 7 — Respond to review feedback

- Address every comment — either fix it or explain why you disagree
- Push new commits to the same branch (do **not** force-push after review has started)
- Re-request review once you've addressed all comments

---

## Code Standards

### General rules

- All code must be **safe Rust** — no `unsafe` blocks without explicit prior approval and a written justification in the PR description
- Use **explicit types** on all function signatures — avoid relying on inference for public-facing items
- Every public function, struct, enum, and constant must have a **doc comment** (`///`)
- Every `unwrap()` or `expect()` inside non-test code must include a comment explaining why the panic is impossible
- Keep functions **short and focused** — if a function exceeds ~60 lines, consider splitting it

### Memory rules

- **Stack allocation first**: use `[u8; N]` arrays for fixed-size analysis buffers
- **No unnecessary heap allocation**: avoid `Vec`, `String`, or `Box` in hot paths unless required for the output buffer
- Any `Vec<u8>` allocation in the sanitizer pipelines must be pre-sized with `Vec::with_capacity`
- The format sniffer (`sniff_format`) must remain **heap-allocation free** — verified by inspection

### Error handling

- **Never use `.unwrap()` in library code** (only in tests and examples)
- All errors must be returned as `CdrError` variants
- Never add a `CdrError` variant that contains a `String` — use fixed primitive types

### New sanitizer checklist

If you are implementing a new format sanitizer:

- [ ] Add detection to `sniff_format()` in `core/src/sniffer.rs`
- [ ] Add a `FormatMissing*` error variant to `CdrError` in `core/src/errors.rs`
- [ ] Create `core/src/sanitizers/<format>.rs` with the full typestate pipeline
- [ ] Register the module in `core/src/sanitizers/mod.rs`
- [ ] Add a dispatch arm in `disarm()` in `core/src/sniffer.rs`
- [ ] Expose the new sanitize function from `core/src/lib.rs`
- [ ] Write at minimum: one decode test, one re-encode test, one malformed-input test
- [ ] Update the format support table in `README.md`

---

## Testing Requirements

Every PR that changes behaviour must include tests. The bar is:

| Change type | Minimum tests required |
|---|---|
| Bug fix | One test that **fails** before the fix and **passes** after |
| New format support | Decode test, re-encode output validity test, malformed-input rejection test |
| New `CdrError` variant | One test that triggers it |
| Format sniffer change | Tests covering valid input, invalid magic, and truncated input |
| Refactor | All existing tests must still pass; no new tests required if behaviour is unchanged |

Tests live in:
- **Unit tests** — `#[cfg(test)] mod tests` inside the relevant source file in `core/src/`
- **Integration tests** — `core/tests/` directory (for end-to-end `disarm()` calls with real files)
- **Doc-tests** — inline in `///` doc comments using ` ```rust ` blocks

---

## Commit Message Format

Commits use a symbolic prefix format:

```
[<symbol>]: <short description in lowercase>
```

**Symbols:**

| Symbol | Meaning |
|--------|---------|
| `[+]` | New feature, new file, new functionality |
| `[~]` | Modification, update, improvement to existing code |
| `[-]` | Deletion, removal of code or a file |
| `[x]` | Bug fix |
| `[docs]` | Documentation-only change |
| `[test]` | Adding or fixing tests |
| `[chore]` | Dependency bumps, CI config, tooling, formatting |

**Examples:**

```
[+]: implement GIF transparency preservation in sanitizer
[~]: update Node.js binding to expose dual-output pngBuffer field
[x]: fix out-of-bounds slice in PNG IHDR validation
[-]: remove unused FilterType import from png.rs
[docs]: update README FFI examples to reflect dual-output ABI
[test]: add concurrent async CDR round-trip test
[chore]: bump png crate to 0.17.15
```

Keep the subject line short (≤72 characters). Use the body for explaining *why*, not *what*.

---

## Working on a Specific Binding

Each language binding in `bindings/` is a thin FFI wrapper that calls into the pre-built `libgatekeeper.so` / `libgatekeeper.a`. Before working on a binding, rebuild the native library:

```bash
cd core
cargo build --release
```

Then copy the output to the binding's expected location:

```bash
# For PHP and Java (shared library)
cp core/target/release/libgatekeeper.so bindings/php/lib/linux/libgatekeeper.so
cp core/target/release/libgatekeeper.so bindings/java/src/main/resources/native/linux/libgatekeeper_java.so

# For Go (static library)
cp core/target/release/libgatekeeper.a bindings/go/lib/linux/libgatekeeper.a
```

Node.js and Python bindings are built with their own Rust compilation step via `napi-rs` / `maturin`:

```bash
# Node.js
cd bindings/node
npm run build            # Compiles and links against core

# Python
cd bindings/python
pip install maturin
maturin develop          # Builds and installs a local dev wheel
```

### Testing a binding locally

Each binding has its own test suite:

```bash
# Node.js
cd bindings/node && npm test

# Python
cd bindings/python && pytest

# Go
cd bindings/go && go test ./...

# PHP
cd bindings/php && php vendor/bin/phpunit tests/

# Java
cd bindings/java && mvn test -DskipTests=false
```

---

## Using the Cross-Platform Testbed

The `test-gatekeeper-cdr/` directory contains a full interactive testbed that runs all active language backends simultaneously and displays results in a SvelteKit UI. This is the fastest way to validate that a change to the core engine produces correct, consistent output across all language bindings.

### Starting the testbed

**1. Start the backends** (each in a separate terminal):

```bash
# Node.js backend — port 3001
cd test-gatekeeper-cdr/backend-node && npm install && node server.js

# Go backend — port 3002
cd test-gatekeeper-cdr/backend-go && go build -o gatekeeper-go-backend . && ./gatekeeper-go-backend

# PHP backend — port 3004
cd test-gatekeeper-cdr/backend-php && php composer.phar install && php -S localhost:3004 index.php

# Python backend — port 3005
cd test-gatekeeper-cdr/backend-python && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && python main.py
```

**2. Start the frontend:**

```bash
cd test-gatekeeper-cdr/frontend && npm install && npm run dev
```

**3. Open** `http://localhost:3000` in your browser.

### What to look for

- Upload a JPEG → all backends should return the same native file size (within 1–2 bytes) and the same PNG companion size
- Upload a PNG → all backends should return the same sanitized PNG size
- The UI shows **NATIVE** and **ZERO-TRUST PNG** columns side-by-side for every backend so you can spot any discrepancy immediately

If you see different output sizes across backends for the same input file, it means one or more backends are running a stale native library. Rebuild and restart the affected backend.

---

## What Makes a Good PR

✅ **Focused** — one logical change, clearly scoped  
✅ **Tested** — includes tests that would catch regressions  
✅ **Documented** — updates docs and inline comments as needed  
✅ **Clean history** — no merge commits from upstream, no "WIP" or "fix typo x5" commits  
✅ **CI green** — `cargo test`, `cargo clippy`, `cargo fmt --check` all pass  
✅ **Linked** — references the issue it closes  

❌ **Do not** open a PR with failing tests  
❌ **Do not** mix unrelated changes in one PR  
❌ **Do not** use `unsafe` without prior discussion  
❌ **Do not** add dependencies to `Cargo.toml` without justification in the PR  

---

## Review Process

1. **Automated checks** run on every PR (Clippy, tests, formatting)
2. A **maintainer review** happens within 7 days for most PRs
3. If a PR has no activity from the author for **14 days** after review comments, it may be closed — you can always re-open it
4. PRs that pass review are merged with **squash merge** to keep the main branch history clean

---

## Architecture Primer

If you are new to the codebase, read these files in order:

1. [`core/src/errors.rs`](core/src/errors.rs) — understand the error taxonomy first
2. [`core/src/sniffer.rs`](core/src/sniffer.rs) — the format detector and `disarm()` dispatcher
3. [`core/src/lib.rs`](core/src/lib.rs) — the public API surface and unit tests
4. [`core/src/sanitizers/jpeg.rs`](core/src/sanitizers/jpeg.rs) — the reference typestate pipeline implementation
5. [`core/src/ffi.rs`](core/src/ffi.rs) — the C FFI layer used by Go, PHP, and Java bindings

The key architectural invariants to preserve in all contributions:

| Invariant | Location enforced |
|---|---|
| No heap allocation in `sniff_format()` | `core/src/sniffer.rs` |
| No `String` in any `CdrError` variant | `core/src/errors.rs` |
| Typestate transitions must be consuming (`self`) | All sanitizer modules |
| Output shares zero bytes with input | All `reconstruct()` implementations |
| No `unsafe` blocks in core | `core/src/` (except `ffi.rs` boundary layer) |
| Pre-push tests always run | `.githooks/pre-push` |

---

Thank you for contributing to Gatekeeper. Every PR — big or small — makes file processing safer for everyone. 🛡️
