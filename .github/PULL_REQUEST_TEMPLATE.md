## Summary

<!-- One or two sentences: what does this PR change and why? -->

Closes #<!-- issue number, if applicable -->

---

## Type of Change

<!-- Check all that apply -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (new format support, new API surface)
- [ ] 🔒 Security fix
- [ ] 📖 Documentation update
- [ ] ✅ Tests only (no production code changed)
- [ ] ♻️ Refactor (no behaviour change)
- [ ] ⚡ Performance improvement
- [ ] 🔧 Chore (dependency bump, CI, tooling)

---

## Changes Made

<!-- List the key changes, file by file if helpful -->

- 
- 
- 

---

## Checklist

<!-- Every box must be checked before requesting review -->

- [ ] `cargo test` passes locally
- [ ] `cargo clippy -- -D warnings` produces no warnings
- [ ] `cargo fmt --check` passes (run `cargo fmt` if it fails)
- [ ] `cargo doc --no-deps` compiles without errors
- [ ] New or changed behaviour is covered by tests
- [ ] Public functions and types have `///` doc comments
- [ ] No `unwrap()` or `expect()` added to library code (only in tests/examples)
- [ ] No `unsafe` blocks added (or: explained in detail below)
- [ ] `README.md` updated if the format support table or API changed
- [ ] Commit messages follow the Conventional Commits format

---

## Testing Evidence

<!-- Paste `cargo test` output, or describe how you tested this manually -->

```
cargo test output here
```

---

## Notes for Reviewer

<!-- Anything the reviewer should pay special attention to, or open questions -->

---

## `unsafe` Justification (if applicable)

<!-- If you added any unsafe block, explain here exactly why it is sound and why a safe alternative is not possible -->
