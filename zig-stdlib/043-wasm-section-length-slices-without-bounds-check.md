# Wasm section length out-of-bounds slice in CheckObject

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/CheckObject.zig:1600`

## Summary
`CheckObject` parses attacker-controlled WebAssembly bytes and trusts each section's declared `section_length` when slicing the backing buffer. A malformed wasm file can declare a section length larger than the remaining bytes, causing an out-of-bounds slice panic instead of a handled parse failure. This aborts the build/check process.

## Provenance
- Verified by reproduction against the reported code path
- Scanner source: https://swival.dev

## Preconditions
- An attacker controls a wasm file read by `CheckObject`

## Proof
A minimal malformed wasm file reproduces the fault:
```text
00 61 73 6d 01 00 00 00 01 05
```

Observed behavior:
- `make()` reads the file into `contents`
- `WasmDumper.parseAndDumpInner()` reads section id `0x01`
- It parses `section_length = 5` via LEB128
- At that point `reader.seek == 10` and `bytes.len == 10`
- The code slices `bytes[reader.seek..][0..section_length]`, effectively `bytes[10..][0..5]`
- Zig aborts with `panic: index out of bounds`

Runtime evidence from `zig build`:
- process aborts with `thread ... panic: index out of bounds: index 15, len 10`
- top frame points into `std/Build/Step/CheckObject.zig`

## Why This Is A Real Bug
The panic is reachable through normal `CheckObject` usage on `.wasm` inputs, including build-script-controlled paths. The failure mode is not a rejected malformed file but an unconditional process abort, which is a denial of service against the build/check step. The reproduced input is only 10 bytes and requires no special environment beyond supplying malformed wasm bytes.

## Fix Requirement
Before slicing a section payload, validate that the declared `section_length` does not exceed the remaining bytes (`reader.seek + section_length <= bytes.len`). If it does, return a parse error instead of slicing.

## Patch Rationale
The patch adds an explicit bounds check before constructing the section slice in the wasm parser. This converts malformed section lengths from a runtime panic into a regular parse failure, preserving existing behavior for valid wasm while hardening the parser against truncated or malicious inputs.

## Residual Risk
None

## Patch
Patched in `043-wasm-section-length-slices-without-bounds-check.patch` by validating the wasm section length against remaining input before slicing and returning a parse error on truncation.