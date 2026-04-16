# Unchecked Mach-O string index causes out-of-bounds slice

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/MachOFile.zig:391`
- `lib/std/debug/MachOFile.zig:109`
- `lib/std/debug/MachOFile.zig:145`
- `lib/std/debug/MachOFile.zig:470`

## Summary
`MachOFile.load` trusted attacker-controlled `LC_SYMTAB` string-table metadata and symbol `n_strx` values too far. It derived `strings` from file-backed Mach-O data without first validating the declared string-table bounds, then sliced with `strings[sym.n_strx..]` for both regular symbols and STAB handling while only filtering `n_strx == 0`. A crafted Mach-O object can therefore trigger an out-of-bounds slice during parsing.

## Provenance
- Verified from the supplied reproducer and patch context
- Reproduced against the parser behavior in `lib/std/debug/MachOFile.zig`
- Scanner source: https://swival.dev

## Preconditions
- Attacker controls parsed Mach-O symbol table entries

## Proof
- `MachOFile.load` forms `strings` from `mapped_macho[stroff + 1 ..][0 .. strsize - 1]` without the explicit `stroff + strsize` bounds validation present in `loadOFile` at `lib/std/debug/MachOFile.zig:470`.
- During symbol iteration, both the normal symbol path and the `appendStabSymbol` path use `sym.n_strx` as a direct slice start via `strings[sym.n_strx..]`.
- Only `sym.n_strx == 0` was treated specially; nonzero indices were not checked against `strings.len`.
- The reproducer creates `poc.macho` with a declared 4-byte string table, yielding `strings.len == 3`, and a symbol entry with `n_strx = 5`.
- Running `zig run macho_poc.zig` crashes in `MachOFile.load` with `panic: start index 5 is larger than end index 3` at `lib/std/debug/MachOFile.zig:145`, confirming reachable out-of-bounds slicing from attacker-controlled input.

## Why This Is A Real Bug
The crash occurs while parsing a reachable external file format and is driven entirely by untrusted Mach-O metadata. This is not a theoretical invariant violation: the supplied malformed file deterministically triggers a parser panic in practice. In checked builds this is a denial of service; in unchecked/less-safe builds the same missing validation permits invalid slice formation and must be treated as memory-unsafe behavior.

## Fix Requirement
Reject any symbol whose `n_strx` is nonzero and not strictly less than `strings.len`, and validate the declared string-table bounds before deriving the `strings` slice from mapped file data.

## Patch Rationale
The patch should align `load` with the safer `loadOFile` behavior by validating `stroff + strsize` before slicing the backing Mach-O mapping, then enforcing `sym.n_strx < strings.len` before any `strings[sym.n_strx..]` use. This prevents both malformed-table slicing and per-symbol out-of-bounds access in all symbol-processing paths.

## Residual Risk
None

## Patch
- Patch file: `060-unchecked-object-file-string-table-index-causes-out-of-bound.patch`
- The patch adds upfront validation for Mach-O string-table bounds in `MachOFile.load`.
- The patch rejects symbols whose nonzero `n_strx` falls outside `strings.len` before regular symbol-name extraction.
- The patch applies the same `n_strx` validation to the STAB symbol path so both consumers of `strings[sym.n_strx..]` are covered.
- This converts attacker-controlled invalid indices from a parser panic into clean input rejection.