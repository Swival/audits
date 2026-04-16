# Line Subsection Headers Read Before Bounds Check

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/Pdb.zig:581`
- `lib/std/debug/Pdb.zig:689`

## Summary
`getLineNumberInfo` and `getModule` parse PDB module subsection streams by casting `&subsect_info[sect_offset]` to `pdb.DebugSubsectionHeader` and reading `kind` / `length` before confirming enough bytes remain for the header. A truncated or malformed `subsect_info` can therefore trigger an out-of-bounds read before the later size check runs.

## Provenance
- Verified from the supplied finding and reproducer
- Reproduced with a Zig proof-of-concept matching the parser’s control flow
- Reference: `https://swival.dev`

## Preconditions
- Caller parses attacker-controlled PDB module subsection bytes

## Proof
A malformed subsection stream with a first header `length = 0` is sufficient:
```text
subsect_info.len = 9
iteration 1: sect_offset = 0
- header is read from bytes [0..8)
- body advances sect_offset by sizeof(DebugSubsectionHeader) = 8
- skip_len = 0, so loop post-expression keeps sect_offset = 8

iteration 2: sect_offset = 8
- parser casts &subsect_info[8] to DebugSubsectionHeader
- reading kind/length consumes 8 bytes starting one byte before slice end
- only after that does the code reject the offset as invalid
```

The reproduced PoC showed the second iteration assembling a header from bytes beyond the visible slice (`kind=0xddccbbaa`, `length=0x11223344`) before the invalid condition fired, demonstrating that dereference precedes validation.

This is reachable because `getModule` loads `mod.subsect_info` directly from file-backed bytes and iterates subsection headers without validating that each header fits the remaining slice. `getLineNumberInfo` is also reachable during normal Windows symbolization flow via `lib/std/debug/SelfInfo/Windows.zig:370`.

## Why This Is A Real Bug
The read occurs before any bounds check guaranteeing `sizeof(DebugSubsectionHeader)` bytes remain. That is a concrete memory-safety violation at the parser boundary, not just a logical parse failure. On attacker-controlled PDB input, this can disclose adjacent memory contents, crash the process, or produce misparsed state depending on allocator layout and build mode.

## Fix Requirement
Before any cast or field access:
- verify `subsect_info.len - sect_offset >= @sizeOf(pdb.DebugSubsectionHeader)`
- then parse the header
- then verify the declared subsection payload length stays within the remaining bytes before advancing

## Patch Rationale
The patch in `068-line-subsection-headers-are-dereferenced-before-size-validat.patch` adds a pre-dereference size check so the parser never forms a `DebugSubsectionHeader` pointer unless the full header is in-bounds. It then preserves payload-length validation after reading the now-safe header. This directly removes the out-of-bounds read primitive while keeping existing rejection behavior for malformed subsection lengths.

## Residual Risk
None

## Patch
- File: `068-line-subsection-headers-are-dereferenced-before-size-validat.patch`
- Change: add remaining-bytes validation for `pdb.DebugSubsectionHeader` before `@ptrCast` in both subsection-walking loops in `lib/std/debug/Pdb.zig`, then validate `header.length` against the remaining subsection bytes before advancing.