# Single-byte literals section writes past empty caller buffer

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/compress/zstd/Decompress.zig:1322`
- `lib/std/compress/zstd/Decompress.zig:1337`

## Summary
`Decompress.LiteralsSection.decode` accepts a caller-supplied `buffer: []u8` and, in the `.rle` literals branch, wrote `buffer[0]` without first proving the slice was non-empty. When called with `buffer.len == 0`, this violates slice bounds in safe builds and performs an out-of-bounds write in unsafe builds.

## Provenance
- Verified from the provided reproducer and source inspection
- Patched in `064-single-byte-literals-section-writes-past-empty-caller-buffer.patch`
- Scanner reference: https://swival.dev

## Preconditions
- Caller invokes `Decompress.LiteralsSection.decode` with an empty output slice
- The input encodes an RLE literals section

## Proof
A minimal reproducer directly invoked `Decompress.LiteralsSection.decode` with:
- an RLE literals header byte (`0x01`)
- an empty destination slice

Observed results:
- In the default safe build, execution panicked with `index out of bounds: index 0, len 0` at `lib/std/compress/zstd/Decompress.zig:1322`
- In `-O ReleaseFast`, using a zero-length slice backed by a 1-byte array, `decode` returned successfully and mutated the hidden backing byte from `0x00` to `0x41`

This demonstrates that the `.rle` branch performed an unchecked write through an empty caller buffer.

## Why This Is A Real Bug
The function contract accepts an arbitrary caller-provided slice. The `.rle` path previously failed to enforce the same output-capacity invariant already enforced in the other literals decoding paths. As a result:
- safe builds abort on valid control flow reaching the write
- unsafe builds can corrupt adjacent memory

This is a concrete memory-safety failure at the API boundary, independent of whether a higher-level caller currently guarantees a non-empty buffer.

## Fix Requirement
Reject `.rle` literals sections when the caller buffer cannot hold the single output byte, before any write occurs.

## Patch Rationale
The patch adds an explicit capacity check in the `.rle` branch:
- if `total_streams_size > buffer.len`, return `error.MalformedLiteralsSection`
- only then read the repeated byte and store it into `buffer[0]`

This matches the existing guard pattern used by the other literals-section decoding branches and preserves the function's error model.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/std/compress/zstd/Decompress.zig b/lib/std/compress/zstd/Decompress.zig
index 0000000..0000000 100644
--- a/lib/std/compress/zstd/Decompress.zig
+++ b/lib/std/compress/zstd/Decompress.zig
@@ -1334,6 +1334,8 @@ pub const LiteralsSection = struct {
                 .rle => {
                     const total_streams_size = 1;
                     remaining -= 1;
+                    if (total_streams_size > buffer.len)
+                        return error.MalformedLiteralsSection;
                     buffer[0] = try in.takeByte();
                     return .{
                         .literals = buffer[0..1],
```