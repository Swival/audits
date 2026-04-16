# Data directory count slices beyond optional header

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/coff.zig:778`
- `lib/std/coff.zig:948`
- `lib/std/coff.zig:1007`

## Summary
`Coff.init` accepts attacker-controlled PE/COFF bytes and only validates that an optional header exists. `getDataDirectories` then trusts the header-reported `number_of_rva_and_sizes` and constructs an `ImageDataDirectory` slice from `self.data[offset..]` without ensuring the optional header actually contains that many entries or that the backing input buffer is long enough. This allows returned directory entries to be read from bytes beyond the declared file-backed slice.

## Provenance
- Reproduced from the verified report and local PoC
- Reference: https://swival.dev

## Preconditions
- Parse attacker-controlled PE/COFF image bytes

## Proof
A local PoC built a PE/COFF buffer whose optional header declared 16 data directories while `size_of_optional_header` left no space for any directory entries. Parsing succeeded, and `getDataDirectories()` returned a 16-entry slice anyway. Observed output showed directory fields sourced from bytes past the declared input extent:
- `data.len=188`
- `dirs.len=16`
- `first.size=0x11111111`
- `debug.va=0x22222222`
- `debug.size=0x33333333`

`getPdbPath` is a direct reachable consumer. It calls `getDataDirectories()`, checks only that index 6 exists, then reads `data_dirs[6]` at `lib/std/coff.zig:1007` and again at `lib/std/coff.zig:1010`, immediately consuming out-of-bounds-derived values.

## Why This Is A Real Bug
The bug is not theoretical: the parser returns a typed slice whose length is controlled by untrusted header fields rather than bounded by the optional header size and remaining file bytes. That is an out-of-bounds read of attacker-influenced memory relative to the declared input slice. Even where later reads are bounded by `self.data.len`, the oversized directory slice itself already discloses memory contents and can also drive downstream panic/DoS behavior on truncated inputs.

## Fix Requirement
Reject or clamp invalid data-directory counts so the returned slice cannot exceed:
- the bytes available within `size_of_optional_header` after the fixed optional-header fields, and
- the bytes remaining in `self.data` from the computed directory offset.

## Patch Rationale
The patch bounds the reported directory count against both the optional-header-declared space and the actual remaining input bytes before constructing the `ImageDataDirectory` slice. This preserves valid images while preventing header-controlled overextension of the returned slice and blocking reachable consumers such as `getPdbPath` from observing out-of-bounds-derived entries.

## Residual Risk
None

## Patch
- Patched in `009-data-directory-count-slices-beyond-optional-header.patch`
- The fix updates `lib/std/coff.zig` to derive the maximum safe `ImageDataDirectory` count from the optional header size and `self.data.len`, then uses that bounded count when exposing data directories.