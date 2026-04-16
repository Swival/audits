# Zero-entry symtab triggers division by zero

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/ElfFile.zig:211`

## Summary
`searchSymtab` performs `symtab.bytes.len % symtab.entry_size` before validating that `symtab.entry_size` is nonzero. A malformed ELF with `.symtab.sh_entsize == 0` reaches a modulo-by-zero trap instead of returning `error.BadSymtab`, causing denial of service.

## Provenance
- Verified from the supplied reproducer and code path analysis
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker-controlled ELF is loaded
- `.symtab` is present with `sh_entsize == 0`
- `.strtab` is present so execution reaches `searchSymtab`

## Proof
- `loadInner` copies section header metadata from the ELF without rejecting zero `.symtab.sh_entsize`
- `load` stores that value into `symtab.entry_size`
- `searchSymtab` executes:
```zig
if (symtab.bytes.len % symtab.entry_size != 0) return error.BadSymtab;
```
- With `symtab.entry_size == 0`, the modulo traps immediately
- Reproducer confirms runtime panic at `lib/std/debug/ElfFile.zig:258:26` with `division by zero`

## Why This Is A Real Bug
The crash is reachable through a public method on a loaded `ElfFile`, and standard library code uses this path as a fallback when DWARF data is unavailable. The malformed input need only supply a `.symtab` with zero entry size; symbol decoding is not required. This converts malformed-input handling into process termination.

## Fix Requirement
Reject `symtab.entry_size == 0` before any modulo or entry-count computation, and return `error.BadSymtab`.

## Patch Rationale
The patch adds an explicit zero check ahead of the modulo in `searchSymtab`. This preserves existing malformed-input behavior, prevents the trap, and cleanly classifies the ELF as a bad symbol table.

## Residual Risk
None

## Patch
Patched in `032-zero-entry-symtab-triggers-division-by-zero.patch` by guarding `symtab.entry_size` before modulo in `lib/std/debug/ElfFile.zig`, returning `error.BadSymtab` for zero-sized symbol table entries.