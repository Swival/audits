# Zig ziglibc Audit Findings

Security audit of ziglibc, the Zig standard library's C compatibility layer. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 5** -- High: 2, Medium: 3

## Findings

### Memory allocation

| # | Finding | Severity |
|---|---------|----------|
| [001](001-malloc-integer-overflow.md) | malloc integer overflow | High |
| [003](003-posix-memalign-missing-alignment-validation.md) | posix_memalign missing alignment validation | Medium |

### C library shims

| # | Finding | Severity |
|---|---------|----------|
| [001](001-signed-minimum-overflows-in-abs-shims.md) | Signed minimum overflows in abs shims | Medium |
| [002](002-memccpy-omits-matched-byte-and-never-returns-null.md) | memccpy omits matched byte and never returns NULL | High |
| [003](003-strtok-r-leaves-save-state-stale-when-input-is-all-delimiter.md) | strtok_r leaves save state stale when input is all delimiter | Medium |
