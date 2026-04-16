# Regular unwind page bounds ignore page entry offset

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/SelfInfo/MachO.zig:170`
- `lib/std/debug/SelfInfo/MachO.zig:235`
- `lib/std/debug/SelfInfo/MachO.zig:236`
- `lib/std/debug/SelfInfo/MachO.zig:238`

## Summary
`unwindFrameInner` validates regular-page entry bounds without including `page_header.entryPageOffset`, then slices from `start_offset + page_header.entryPageOffset`. A malformed in-memory `__unwind_info` page can therefore satisfy the existing check while still pushing the actual slice start past `unwind_info.len`, causing a bounds panic in safety-checked builds and out-of-bounds read/undefined behavior in less checked builds. The same missing offset term is present in the compressed-page entry validation path.

## Provenance
- Verified from the provided reproducer and source inspection
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker controls malformed in-memory `__unwind_info` page header values

## Proof
- `loadUnwindInfo` exposes mapped Mach-O `__unwind_info`, and `unwindFrameInner` parses page headers during compact unwind processing at `lib/std/debug/SelfInfo/MachO.zig:124`, `lib/std/debug/SelfInfo/MachO.zig:153`, `lib/std/debug/SelfInfo/MachO.zig:162`, `lib/std/debug/SelfInfo/MachO.zig:448`.
- In the `.REGULAR` path, the code checks `unwind_info.len >= start_offset + entries_byte_count` but then slices from `unwind_info[start_offset + page_header.entryPageOffset ..][0..entries_byte_count]` at `lib/std/debug/SelfInfo/MachO.zig:170`.
- If `entryPageOffset > 0`, the validation can pass while `start_offset + page_header.entryPageOffset + entries_byte_count > unwind_info.len`, violating the slice precondition.
- A minimal Zig runtime repro confirms that `buf[start..][0..len]` with `start + len > buf.len` aborts with `panic: index out of bounds` in safety-checked builds; in less checked builds, the same pattern permits out-of-bounds access.
- The compressed-page path repeats the same omission around `entryPageOffset` in its entry bounds logic at `lib/std/debug/SelfInfo/MachO.zig:235`, `lib/std/debug/SelfInfo/MachO.zig:236`, `lib/std/debug/SelfInfo/MachO.zig:238`.

## Why This Is A Real Bug
The current guard does not prove safety for the subsequent slice expression. Because the code slices from `start_offset + entryPageOffset` but validates only `start_offset + entries_byte_count`, an attacker-controlled nonzero page entry offset bypasses the intended bounds check. This is directly reachable on unwind parsing for loaded Mach-O images using compact unwind info, so malformed unwind metadata can crash the process or trigger memory-unsafe reads depending on build mode.

## Fix Requirement
Validate the full effective slice range before parsing entries: `start_offset + entryPageOffset + entries_byte_count <= unwind_info.len`. Apply the same correction to compressed-page entry validation.

## Patch Rationale
The patch in `050-regular-unwind-page-bounds-ignore-page-entry-offset.patch` strengthens the bounds checks to include `entryPageOffset` before any entry slice is formed. This aligns the validation with the actual indexed region in both regular and compressed unwind-page parsing, converting malformed metadata into a clean parse failure instead of a panic or out-of-bounds access.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/std/debug/SelfInfo/MachO.zig b/lib/std/debug/SelfInfo/MachO.zig
--- a/lib/std/debug/SelfInfo/MachO.zig
+++ b/lib/std/debug/SelfInfo/MachO.zig
@@
-                if (unwind_info.len < start_offset + entries_byte_count) return error.InvalidMachOUnwindInfo;
+                if (unwind_info.len < start_offset + page_header.entryPageOffset + entries_byte_count) {
+                    return error.InvalidMachOUnwindInfo;
+                }
@@
-                if (unwind_info.len < start_offset + entries_byte_count) return error.InvalidMachOUnwindInfo;
+                if (unwind_info.len < start_offset + page_header.entryPageOffset + entries_byte_count) {
+                    return error.InvalidMachOUnwindInfo;
+                }
```