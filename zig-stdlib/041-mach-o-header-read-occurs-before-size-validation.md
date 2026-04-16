# Mach-O header read before minimum-size validation

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/CheckObject.zig:1025`
- `lib/std/Build/Step/CheckObject.zig:1580`

## Summary
`std.Build.Step.CheckObject` accepts any `LazyPath` input. For Mach-O checks, parsing reaches `parseAndDumpObject`, which dereferences `bytes.ptr` as `macho.mach_header_64` before confirming `bytes.len >= @sizeOf(macho.mach_header_64)`. Empty input reproduces a build-time segmentation fault; undersized input generally still triggers an out-of-bounds header read before validation.

## Provenance
- Verified from the provided reproducer and code path in `lib/std/Build/Step/CheckObject.zig`
- Reproduced via public API usage of `std.Build.Step.CheckObject.create`
- Reference: https://swival.dev

## Preconditions
- Mach-O object checking is invoked on empty or undersized input
- The input is supplied through any reachable `CheckObject` `LazyPath`

## Proof
A minimal build script creates an empty file and passes it to `std.Build.Step.CheckObject.create(b, empty, .macho)`, then calls `check.checkInHeaders()`. Running `zig build test` crashes at the Mach-O header cast:

```text
Segmentation fault at address 0x1
/opt/zig/lib/std/Build/Step/CheckObject.zig:1580:63: in parseAndDumpObject
        const hdr = @as(*align(1) const macho.mach_header_64, @ptrCast(bytes.ptr)).*;
```

The call chain is:
- `make()` reads file bytes into `contents`
- `.macho` dispatch calls `MachODumper.parseAndDump`
- `parseAndDumpObject` immediately casts and dereferences `bytes.ptr` as `macho.mach_header_64`
- only after that dereference does logic inspect `hdr.magic`

This proves the minimum-size invariant is violated before validation.

## Why This Is A Real Bug
This is reachable from public build APIs, not just compiler-internal outputs. An attacker-controlled or malformed input file can crash the build process with empty input, causing a reliable denial of service. Even when a given undersized input does not crash, the parser still performs an unchecked read past the valid byte range, which is memory-unsafe behavior and invalid by construction.

## Fix Requirement
Reject inputs where `bytes.len < @sizeOf(macho.mach_header_64)` before any cast or dereference of Mach-O header bytes.

## Patch Rationale
The patch adds an explicit length guard at the start of Mach-O object parsing, before constructing `macho.mach_header_64` from raw bytes. This enforces the parser’s minimum-size precondition at the trust boundary and converts the crash path into a normal parse error.

## Residual Risk
None

## Patch
- `041-mach-o-header-read-occurs-before-size-validation.patch` adds a pre-dereference size check in `lib/std/Build/Step/CheckObject.zig` so undersized Mach-O inputs are rejected before header access.