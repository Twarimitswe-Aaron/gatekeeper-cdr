# Contributing to Gatekeeper

Thank you for your interest in making Gatekeeper better. This document covers everything you need to know to contribute effectively — from filing a bug report to landing a production-quality PR.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Before You Start](#before-you-start)
- [Development Setup](#development-setup)
- [Branching Strategy](#branching-strategy)
- [Making a Pull Request (Step-by-Step)](#making-a-pull-request-step-by-step)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Commit Message Format](#commit-message-format)
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
| 🌍 **Translations** | Translate docs or error messages for non-English users. |

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

```bash
rustc --version    # Should be 1.85.0 or later (Edition 2024 requirement)
cargo --version
cargo clippy --version
```

If your toolchain is older:
```bash
rustup update stable
```

### 3. Confirm the baseline passes

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

All three must pass before you start making changes, and again before you open a PR.

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

**Always branch off `main`:**
```bash
git checkout main
git pull upstream main
git checkout -b feat/png-sanitizer
```

---

## Making a Pull Request (Step-by-Step)

### Step 1 — Implement your change

Follow the [Code Standards](#code-standards) below. Keep your changes focused — one logical change per PR.

### Step 2 — Write or update tests

Every code change must be accompanied by tests. See [Testing Requirements](#testing-requirements).

### Step 3 — Run the full check suite locally

```bash
# 1. All tests must pass
cargo test

# 2. No Clippy warnings (warnings are treated as errors in CI)
cargo clippy -- -D warnings

# 3. Code must be formatted
cargo fmt

# 4. Check that docs compile
cargo doc --no-deps
```

### Step 4 — Commit your changes

Follow the [Commit Message Format](#commit-message-format) below.

```bash
git add .
git commit -m "feat(jpeg): add DCT coefficient validation before decode"
```

### Step 5 — Push your branch

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

- [ ] Add detection to `sniff_format()` in `src/lib.rs`
- [ ] Add a `FormatMissing*` error variant to `CdrError` for structural validation failures
- [ ] Create `src/sanitizers/<format>.rs` with the full typestate pipeline
- [ ] Register the module in `src/sanitizers/mod.rs`
- [ ] Add a dispatch arm in `disarm()` in `src/lib.rs`
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
- **Unit tests** — `#[cfg(test)] mod tests` inside the relevant source file
- **Integration tests** — `tests/` directory (for end-to-end `disarm()` calls with real files)
- **Doc-tests** — inline in `///` doc comments using `\`\`\`rust` blocks

---

## Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body — explain WHY, not WHAT]

[optional footer — Closes #issue, Breaking-Change: ...]
```

**Types:**

| Type | When to use |
|------|-------------|
| `feat` | New feature or format support |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or fixing tests |
| `refactor` | Code change with no behaviour change |
| `perf` | Performance improvement |
| `chore` | Dependency bumps, CI config, tooling |
| `security` | Security-relevant fix |

**Scopes:** `jpeg`, `png`, `gif`, `sniffer`, `errors`, `ffi`, `deps`, `ci`, `docs`

**Examples:**
```
feat(png): implement PNG decode + re-encode sanitizer pipeline
fix(sniffer): correct IHDR chunk type offset from 8 to 12
docs(readme): add FFI bindings section and roadmap
test(jpeg): add malformed EOI rejection test
security(jpeg): reject payloads with truncated SOS segment
```

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

1. [`src/errors.rs`](src/errors.rs) — understand the error taxonomy first
2. [`src/lib.rs`](src/lib.rs) — the public API surface and format sniffer
3. [`src/sanitizers/jpeg.rs`](src/sanitizers/jpeg.rs) — the reference typestate pipeline implementation

The key architectural invariants to preserve in all contributions:

| Invariant | Location enforced |
|---|---|
| No heap allocation in `sniff_format()` | `src/lib.rs` |
| No `String` in any `CdrError` variant | `src/errors.rs` |
| Typestate transitions must be consuming (`self`) | All sanitizer modules |
| Output shares zero bytes with input | All `reconstruct()` implementations |
| No `unsafe` blocks | Entire codebase |

---

Thank you for contributing to Gatekeeper. Every PR — big or small — makes file processing safer for everyone. 🛡️
