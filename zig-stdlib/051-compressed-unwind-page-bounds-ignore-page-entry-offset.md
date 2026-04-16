# Compressed unwind page bounds ignore page entry offset

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/SelfInfo/MachO.zig:191`

## Summary
- Mach-O unwinding trusts `entries_byte_count` against `start_offset` alone for `.COMPRESSED` second-level unwind pages, but slices entries from `start_offset + page_header.entryPageOffset`.
- A malformed `__unwind_info` page with a non-zero inflated `entryPageOffset` can pass the existing check and still drive an out-of-bounds read during unwinding.

## Provenance
- Verified from the provided reproducer and code-path analysis.
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- Malformed in-memory `__unwind_info` section is processed during unwinding.

## Proof
- `Module.loadUnwindInfo` exposes loader-mapped `__unwind_info` bytes that are later consumed by `unwindFrameInner`.
- In the `.COMPRESSED` branch, the code validates `unwind_info.len < start_offset + entries_byte_count`.
- The subsequent slice starts at `start_offset + page_header.entryPageOffset`, not `start_offset`.
- Therefore, when `page_header.entryPageOffset > 0`, inputs can satisfy the existing check while still making `start_offset + page_header.entryPageOffset + entries_byte_count > unwind_info.len`.
- The reproducer confirms this exact shape causes a reliable bounds failure in safe builds and unchecked out-of-bounds access in less safe configurations.

## Why This Is A Real Bug
- The validated bound does not match the actual memory range later read.
- This discrepancy is directly reachable from normal unwinding logic for compressed second-level pages.
- In safe builds, Zig traps on the invalid slice, turning malformed unwind metadata into a denial of service.
- In less safe configurations, the same path becomes an unchecked out-of-bounds read.

## Fix Requirement
- Before slicing compressed entries, validate the full accessed range using `start_offset + page_header.entryPageOffset + entries_byte_count`.
- Reject the page if that computed end exceeds `unwind_info.len`.

## Patch Rationale
- The patch aligns validation with the actual slice base used by `.COMPRESSED` page parsing.
- This closes the reproduced out-of-bounds condition without changing expected behavior for well-formed unwind pages.
- The fix is minimal and directly targets the unsafe range computation in `lib/std/debug/SelfInfo/MachO.zig`.

## Residual Risk
- None

## Patch
- Patched in `051-compressed-unwind-page-bounds-ignore-page-entry-offset.patch`.