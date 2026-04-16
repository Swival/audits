# Unchecked main string-table index causes out-of-bounds slice

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/MachOFile.zig:118`
- `lib/std/debug/MachOFile.zig:145`

## Summary
`std.debug.MachOFile.load` iterates attacker-controlled `macho.nlist_64` entries and uses `sym.n_strx` as an index into the main string table without validating it against `strings.len`. A non-STAB `.sect` symbol reaches `std.mem.sliceTo(strings[sym.n_strx..], 0)` directly, causing an out-of-bounds slice and process trap on malformed Mach-O input instead of returning `error.InvalidMachO`.

## Provenance
- Reproduced from the verified report and patch workflow
- Scanner source: https://swival.dev

## Preconditions
- Attacker controls a parsed Mach-O symbol table entry

## Proof
A malformed Mach-O was built at `scratch/bad.macho` with:
- `strsize = 1`, yielding `strings.len == 0`
- one `.sect` symbol with `n_strx = 4`

A repro driver at `scratch/repro.zig` called `std.debug.MachOFile.load` on that file. Running `zig run scratch/repro.zig` aborted with:
```text
panic: start index 4 is larger than end index 0
```

The stack pointed to `lib/std/debug/MachOFile.zig:145`, where the non-STAB path performs:
```zig
std.mem.sliceTo(strings[sym.n_strx..], 0)
```

This confirms malformed input reaches an unchecked slice start before any `error.InvalidMachO` is returned.

## Why This Is A Real Bug
The panic is triggerable from file-backed Mach-O metadata and converts malformed-input handling into a denial of service. The code already treats invalid Mach-O structure as recoverable parse failure elsewhere, including `loadOFile`, which validates related symbol and string table bounds. The missing check in `load` is therefore a real consistency and robustness defect, not a theoretical edge case.

## Fix Requirement
Reject any symbol entry where `sym.n_strx` is nonzero and `sym.n_strx >= strings.len` before any path can evaluate `strings[sym.n_strx..]` or persist that index for later dereference, and return `error.InvalidMachO`.

## Patch Rationale
The patch adds a bounds check in `std.debug.MachOFile.load` before all uses of `sym.n_strx` derived from the main string table. This aligns `load` with the existing defensive checks in `loadOFile`, converts the reproduced trap into structured invalid-input rejection, and covers both immediate non-STAB dereference and deferred STAB consumers that store `strx` for later lookup.

## Residual Risk
None

## Patch
- Patch file: `058-unchecked-main-string-table-index-causes-out-of-bounds-slice.patch`
- Change: validate `sym.n_strx` against `strings.len` in `lib/std/debug/MachOFile.zig` before any dereference or storage
- Result: malformed Mach-O symbol entries now return `error.InvalidMachO` instead of panicking on an out-of-bounds slice