# Archive symtab offset validation prevents null dereference crash

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/CheckObject.zig:1187`
- `lib/std/Build/Step/CheckObject.zig:1835`

## Summary
Malformed archive symbol tables can declare symbol offsets that do not correspond to any parsed archive member. During `checkInArchiveSymtab`, `parseSymtab` accepts such entries and `dumpSymtab` later performs `files.get(off).?`, blindly unwrapping a missing map entry and crashing the build runner with `panic: attempt to use null value`. The original report described an offset-underflow path; reproduction confirmed the reachable impact is a deterministic denial of service via invalid archive symtab contents.

## Provenance
- Verified from the supplied reproducer and patched in the referenced source tree
- Scanner source: https://swival.dev

## Preconditions
- Malformed archive symbol table with oversized or invalid symbol metadata
- User runs `std.Build.Step.CheckObject.checkInArchiveSymtab()` on the attacker-controlled archive

## Proof
A minimal archive containing only a `/` symbol-table member with body `00 00 00 01 00 00 00 00` is sufficient:
- `parseSymtab` reads `num = 1`
- It records one symbol entry with archive offset `0`
- No object members are parsed, so `ctx.objects` remains empty
- `dumpSymtab` looks up the recorded offset with `files.get(off).?`
- The lookup returns `null`, and the forced unwrap panics at `lib/std/Build/Step/CheckObject.zig:1835`

This was reproduced by running a minimal `zig build` invoking `std.Build.Step.CheckObject.create(...).checkInArchiveSymtab()` against the malformed archive, producing `panic: attempt to use null value` with the top frame at `lib/std/Build/Step/CheckObject.zig:1835`.

## Why This Is A Real Bug
The crash is reachable from archive bytes loaded through normal `CheckObject` processing, requires no special environment beyond attacker-controlled archive input, and terminates the build step. Even though the reproduced failure is not an out-of-bounds memory access, it is still a concrete input-validation bug that enables reliable denial of service in a standard library build helper.

## Fix Requirement
Reject malformed archive symtabs before later consumers assume symbol offsets are valid object-member references. In particular:
- guard offset-derived table boundaries before subtraction or slicing
- reject symbol entries whose referenced archive offsets are absent from parsed object headers

## Patch Rationale
The patch hardens archive symtab parsing so invalid table geometry is rejected early and symtab entries cannot survive unless they are structurally consistent with the parsed archive. This removes the later `null` unwrap crash path in `dumpSymtab` and converts malformed input into an ordinary parse failure instead of a panic.

## Residual Risk
None

## Patch
- Patched in `042-archive-symbol-table-offsets-underflow-into-out-of-bounds-sl.patch`
- The fix adds explicit archive symtab validation in `lib/std/Build/Step/CheckObject.zig` so malformed offsets and table bounds are rejected before `dumpSymtab` consumes them