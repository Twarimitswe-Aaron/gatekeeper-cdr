# AI Agent Workflow Instructions

This document serves as the Standard Operating Procedure (SOP) for any AI Agent working on the Gatekeeper-CDR repository. Follow these exact instructions when adding new features or publishing releases.

## 1. Modifying Core Code
- Make all core engine changes inside the `core/` directory in Rust.
- **Do not break the FFI boundaries.** If you modify the `disarm` function signature or `DisarmResult`, you MUST update the `bindings/` wrappers (Node, Python, Java, Go, PHP) to match.
- Validate your code locally by running: `cargo test --workspace`

## 2. Standard Commits (No Publish)
- If you are just fixing bugs or writing standard features without intending to publish them to package managers, push directly to `main`:
  ```bash
  git add .
  git commit -m "feat/fix: description"
  git push origin main
  ```
- Pushing to `main` triggers standard CI testing and statically compiles the Go binaries, but **will not publish** anything to NPM, PyPI, or Maven.

## 3. Creating a Release (Publishing)
When the user explicitly asks to "release", "publish", or "distribute" the engine, you must perform a fully synchronized version bump:

**Step A: Bump Version Strings**
Update the exact version string (e.g. from `0.4.3` to `0.5.0`) in ALL of the following 5 files:
1. `core/Cargo.toml`
2. `bindings/python/Cargo.toml`
3. `bindings/java/Cargo.toml`
4. `bindings/java/pom.xml`
5. `bindings/node/package.json`

**Step B: Commit and Tag**
Create a commit and a Git tag prefixed with `v` (e.g., `v0.5.0`). This is strictly mandatory. The automated package registries **only deploy on `v*` tags**.
```bash
git add core/Cargo.toml bindings/python/Cargo.toml bindings/java/Cargo.toml bindings/java/pom.xml bindings/node/package.json
git commit -m "chore: bump versions to v0.5.0"
git tag v0.5.0
git push origin main
git push origin v0.5.0
```

## 4. CI/CD Architecture Reference
- **Go:** GitHub Actions compiles multi-platform static libraries (`.a`/`.lib`) directly into `bindings/go/lib/` and automatically commits them back to `main`. Do NOT manually compile or commit Go binaries yourself.
- **Node (NPM):** Deploys to `npmjs.com` only on `v*` tags. Takes 10-15 minutes for Rust cross-compilation across Windows/Mac/Linux.
- **Python (PyPI):** Deploys `maturin` wheels to PyPI only on `v*` tags.
- **Java (Maven):** Deploys `.jar` and `.pom` to GitHub Packages only on `v*` tags. *(Note: The URL `<id>` must match the lowercase repository owner name to avoid 401 Unauthorized errors).*
- **PHP (Packagist):** Packagist is configured to automatically ingest new tags directly from GitHub. No explicit GitHub Action deploy is required.
