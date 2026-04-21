# wcsnlen slices with maxInt(usize) on sentinel-terminated pointer

## Classification

Logic Error — Medium Severity

## Affected Locations

- `lib/c/wchar.zig:83` — `wcslen` passes `maxInt(usize)` to `wcsnlen`
- `lib/c/wchar.zig:86` — `wcsnlen` slices sentinel-terminated pointer with caller-provided length

## Summary

`wcslen` calls `wcsnlen(str, maxInt(usize))`, which in turn executes `str[0..maxInt(usize)]` on a `[*:0]const wchar_t`. This creates a slice with length `maxInt(usize)` that vastly exceeds the actual accessible memory. The subsequent `std.mem.findScalar` call on this oversized slice uses SIMD-accelerated search, which loads aligned blocks that can read past the end of the actual allocation before encountering the sentinel. This causes SIGSEGV crashes on strings placed near page boundaries in **all** optimization modes.

## Provenance

Detected by [Swival Security Scanner](https://swival.dev)

## Preconditions

- `wcslen` is called on a sentinel-terminated wide string, OR `wcsnlen` is called with a `maxlen` exceeding the accessible memory region after the string.
- The string is positioned such that a SIMD block read extends past the end of mapped memory (e.g., string near a page boundary with a guard page following).

## Proof

A reproducer allocated a 3-element wide string (`"AB\0"` = 12 bytes of `u32`) at the end of a memory page with an unmapped guard page immediately following. Calling `wcslen` on this string triggered `wcsnlen` which sliced the pointer to `maxInt(usize)` elements. The SIMD path in `std.mem.findScalar` attempted to load a 16-byte block (4 × `u32`) starting at the string, but only 12 bytes were accessible. This produced a **SIGSEGV** at `mem.zig:1267: const block: Block = slice[i..][0..block_len].*;`. The safe alternative `std.mem.len(str)` — already used by `wcpcpy` in the same file — uses element-by-element pointer iteration and does not crash in the same scenario.

## Why This Is A Real Bug

The oversized slice synthesizes a fat pointer whose length misrepresents the accessible memory region. SIMD optimizations in `findScalar` legitimately assume the slice bounds are valid and load multi-element blocks within those bounds. When the slice length exceeds mapped memory, these loads cause segmentation faults. This is not a theoretical concern — it crashes reliably on strings near page boundaries in all build modes.

## Fix Requirement

Replace the `maxInt(usize)` slice-based approach with pointer-level iteration that does not create an oversized slice. Use `std.mem.len(str)` (which uses `findSentinel` with safe element-by-element pointer walking) for the `wcslen` case, and avoid slicing beyond accessible memory in `wcsnlen`.

## Patch Rationale

The patch rewrites `wcslen` to use `std.mem.len`, which safely iterates the sentinel-terminated pointer element-by-element. For `wcsnlen`, instead of slicing the pointer to `maxlen` and searching the resulting (potentially oversized) slice, the patch iterates with a bounded pointer loop that checks both the count limit and the sentinel, never creating a slice that exceeds the actual data. This matches the pattern already used by other functions in the same file (e.g., `wcpcpy` uses `std.mem.len`).

## Residual Risk

None

## Patch

```patch
--- a/lib/c/wchar.zig
+++ b/lib/c/wchar.zig
@@ -79,11 +79,15 @@ pub export fn wcsstr(haystack: ?[*:0]const wchar_t, needle: ?[*:0]const wchar_t
 }
 
 pub export fn wcslen(str: [*:0]const wchar_t) usize {
-    return wcsnlen(str, std.math.maxInt(usize));
+    return std.mem.len(str);
 }
 
 pub export fn wcsnlen(str: [*:0]const wchar_t, maxlen: usize) usize {
-    const slice: []const wchar_t = str[0..maxlen];
-    const index = std.mem.findScalar(wchar_t, slice, 0);
-    return index orelse maxlen;
+    var i: usize = 0;
+    while (i < maxlen) : (i += 1) {
+        if (str[i] == 0) {
+            return i;
+        }
+    }
+    return maxlen;
 }
```