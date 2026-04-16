# Unchecked rnglist length arithmetic can wrap range end

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/debug/Dwarf.zig:598`

## Summary
Unchecked address arithmetic in DWARF range parsing allows attacker-controlled `len`, `base_address`, or offset values to wrap computed range endpoints or adjusted bounds. This can produce forged low-address ranges in unsafe builds or trigger integer-overflow panics in safety-checked builds instead of returning `error.InvalidDebugInfo`.

## Provenance
- Verified from the supplied reproducer and patch context
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker-controlled DWARF range entry with large length or base-adjusted offset

## Proof
DWARF bytes from `.debug_info`, `.debug_rnglists`, and `.debug_ranges` flow into `DebugRangeIterator.next` through `scanAllFunctions`, `scanAllCompileUnits`, `populateRanges`, and `findCompileUnit`.
At `lib/std/debug/Dwarf.zig:598`, `RLE.startx_length` and `RLE.start_length` compute `end_addr = start_addr + len` without overflow checks. The same unchecked addition pattern applies to `RLE.offset_pair` and legacy `.debug_ranges` handling when adding offsets to `base_address`.
With attacker-chosen large operands, the additions wrap in unsafe builds, yielding `end < start` or otherwise bogus low ranges. The reproduced impact shows these malformed ranges are then consumed by `findCompileUnit` for address membership tests at `lib/std/debug/Dwarf.zig:847` and by `populateRanges` for later range storage at `lib/std/debug/Dwarf.zig:661`, enabling misresolution or hiding of compile units and symbols for unrelated low addresses.
In safety-checked builds, the same malformed input causes a parser panic on integer overflow rather than `error.InvalidDebugInfo`, making this a parser-triggered denial of service as well.

## Why This Is A Real Bug
The affected fields are parsed directly from untrusted DWARF sections, and the resulting ranges influence compile-unit and symbol resolution decisions. Overflow is therefore not a theoretical arithmetic concern; it changes parser-visible behavior and either corrupts semantic results in optimized builds or crashes the parser in safety-checked builds. The reproduced `end < start` condition and wrapped low-address ranges demonstrate direct control over downstream address coverage logic.

## Fix Requirement
Use checked addition for all range-end and base-adjusted range computations in `DebugRangeIterator.next`, and reject any overflow with `bad()` so malformed DWARF consistently returns `error.InvalidDebugInfo`.

## Patch Rationale
The patch in `072-unchecked-rnglist-length-arithmetic-can-wrap-range-end.patch` hardens `lib/std/debug/Dwarf.zig` by replacing unchecked endpoint and base-offset arithmetic with checked addition and fail-closed error handling. This preserves valid DWARF behavior while converting malformed overflowing encodings into the parser's existing invalid-debug-info path.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/std/debug/Dwarf.zig b/lib/std/debug/Dwarf.zig
index 0000000..0000000 100644
--- a/lib/std/debug/Dwarf.zig
+++ b/lib/std/debug/Dwarf.zig
@@ -598,6 +598,7 @@
-                const end_addr = start_addr + len;
+                const end_addr = std.math.add(u64, start_addr, len) catch return bad();
                 return .{ .start = start_addr, .end = end_addr };
@@ -606,6 +607,7 @@
-                const end_addr = start_addr + len;
+                const end_addr = std.math.add(u64, start_addr, len) catch return bad();
                 return .{ .start = start_addr, .end = end_addr };
@@ -618,8 +620,8 @@
-                return .{ .start = base_address + start, .end = base_address + end };
+                return .{ .start = std.math.add(u64, base_address, start) catch return bad(), .end = std.math.add(u64, base_address, end) catch return bad() };
@@ -640,7 +642,8 @@
-            return .{ .start = base_address + begin_addr, .end = base_address + end_addr };
+            return .{ .start = std.math.add(u64, base_address, begin_addr) catch return bad(), .end = std.math.add(u64, base_address, end_addr) catch return bad() };
```