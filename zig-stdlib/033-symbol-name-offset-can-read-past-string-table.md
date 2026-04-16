# Symbol name offset can crash ELF symbol resolution

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/ElfFile.zig:296`
- `lib/std/debug/SelfInfo/Elf.zig:74`

## Summary
`searchSymtab` uses untrusted `st_name` from ELF symbol data as a start index into `.strtab` without validating that the offset is within bounds. A malformed symbol entry can therefore trigger a bounds panic during symbol-name resolution, crashing parsing of attacker-supplied ELF files.

## Provenance
- Verified from the supplied reproducer and source review
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker controls ELF `.symtab` and `.strtab` contents
- The target parses that ELF for symbolization, reaching `searchSymtab`

## Proof
- `openElf` reaches `loadPath`, which parses attacker-controlled ELF input for symbolization at `lib/std/debug/SelfInfo/Elf.zig:74`.
- `loadInner` maps section data directly into `strtab` and `symtab`, and `searchSymtab` interprets symbols from that untrusted data.
- After finding a matching symbol, `searchSymtab` returns `std.mem.sliceTo(strtab[sym.st_name..], 0)` at `lib/std/debug/ElfFile.zig:296`.
- No check ensures `sym.st_name < strtab.len` before slicing.
- A reproduced in-memory case with a 3-byte `strtab` and a matching symbol with `st_name = 10` aborts with `panic: start index 10 is larger than end index 3`, confirming attacker-controlled malformed ELF data can crash this path.

## Why This Is A Real Bug
The failing operation is performed on attacker-derived metadata before any bounds validation. In Zig, an oversized slice start index traps immediately, so this is a reliable denial-of-service condition during symbol resolution. The original finding’s “read past string table” wording overstates the mechanism; the source-grounded impact is a deterministic bounds panic and process termination or failed symbol lookup.

## Fix Requirement
Validate `sym.st_name` against `strtab.len` before slicing the string table. If the offset is invalid, reject the symbol by returning `.unknown` or propagating a parsing error such as `error.BadSymtab`.

## Patch Rationale
The patch adds an explicit bounds check for `st_name` before `strtab[sym.st_name..]` is formed. This removes the panic condition at the trust boundary while preserving existing behavior for well-formed ELF symbol tables. Invalid symbol-name offsets are treated as malformed input instead of crashing the parser.

## Residual Risk
None

## Patch
- `033-symbol-name-offset-can-read-past-string-table.patch` adds a guard in `searchSymtab` to ensure `sym.st_name` is within `strtab` bounds before creating the name slice.
- On invalid offsets, the code now rejects the malformed symbol path instead of trapping on an out-of-bounds slice.