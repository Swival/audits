# Unchecked STAB symbol index causes out-of-bounds slice

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/MachOFile.zig:202`
- `lib/std/debug/MachOFile.zig:217`
- `lib/std/debug/MachOFile.zig:230`
- `lib/std/debug/MachOFile.zig:387`

## Summary
`std.debug.MachOFile.load` accepts attacker-controlled STAB `n_strx` values and stores them into `last_sym.strx` without validating that they reference the loaded string table. A later call to `appendStabSymbol` slices `strings[last_sym.strx..]`, which aborts on malformed indices and makes parsing attacker-supplied Mach-O input crash.

## Provenance
- Verified from the supplied reproducer and source analysis.
- Scanner provenance: https://swival.dev

## Preconditions
- Attacker-controlled Mach-O with STAB symbol table is loaded.

## Proof
- `load` derives `strings` from `symtab.stroff/strsize`, then propagates STAB `sym.n_strx` into `last_sym.strx` during `.fun` / related STAB handling at `lib/std/debug/MachOFile.zig:202`, `lib/std/debug/MachOFile.zig:217`, and `lib/std/debug/MachOFile.zig:230`.
- No check ensures `sym.n_strx` is nonzero and `< strings.len` before the value is retained.
- `appendStabSymbol` performs `strings[last_sym.strx..]` at `lib/std/debug/MachOFile.zig:387`, which panics when `last_sym.strx > strings.len`.
- The reproducer builds a minimal Mach-O with `N_FUN(n_strx=100)` and a 5-byte string table; `zig run macho_oob_poc.zig` terminates with `panic: start index 100 is larger than end index 5`, with the stack reaching `appendStabSymbol`.

## Why This Is A Real Bug
This is reachable on malformed input through a public parser path and causes immediate process abort from a bounds-checked slice. Because the index is sourced from untrusted file contents and validated nowhere in `load`, the failure is attacker-triggerable denial of service, not a theoretical invariant violation.

## Fix Requirement
Reject STAB symbols whose `n_strx` is zero or greater than or equal to `strings.len` before storing the index or slicing with it.

## Patch Rationale
The patch adds explicit bounds validation for STAB string indices in `lib/std/debug/MachOFile.zig` before `last_sym.strx` is assigned or later consumed. This aligns `load` with the existing expectation that symbol name offsets must resolve inside the loaded string table and converts malformed input from a panic into a clean parse failure.

## Residual Risk
None

## Patch
- `059-unchecked-stab-symbol-index-causes-out-of-bounds-slice.patch` adds STAB `n_strx` validation in `lib/std/debug/MachOFile.zig` so malformed string offsets are rejected before any slice operation can occur.
- The patch preserves normal parsing behavior for valid Mach-O files and removes the reproduced crash path in `appendStabSymbol`.