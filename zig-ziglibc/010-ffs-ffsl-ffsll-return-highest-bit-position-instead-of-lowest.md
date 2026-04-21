# ffs/ffsl/ffsll return highest-bit position instead of lowest-bit position

## Classification

Logic Error — **High Severity**

## Affected Locations

- `lib/c/strings.zig:53` — `firstBitSet` helper function used by `ffs`, `ffsl`, and `ffsll`

## Summary

The `firstBitSet` generic function computes the position of the **most significant** set bit using `@clz` (count leading zeros), but the POSIX `ffs` family of functions is specified to return the position of the **least significant** set bit (1-indexed), returning 0 when the input is 0. Any non-zero input with more than one bit set produces an incorrect result.

## Provenance

Detected by [Swival Security Scanner](https://swival.dev)

## Preconditions

- Any musl or WASI target program calls `ffs`, `ffsl`, or `ffsll` (exported at lines 13–15 of `lib/c/strings.zig`) with a nonzero value that has more than one bit set.

## Proof

POSIX specifies `ffs(i)` returns the position (1-indexed) of the least significant set bit, or 0 if `i == 0`. The implementation uses `@bitSizeOf(T) - @clz(value)`, which yields the position of the most significant set bit. Runtime-verified failing cases:

| Input | Returned | Expected |
|-------|----------|----------|
| `ffs(3)` (0b11) | 2 | 1 |
| `ffs(10)` (0b1010) | 4 | 2 |
| `ffs(12)` (0b1100) | 4 | 3 |
| `ffs(255)` (0b11111111) | 8 | 1 |
| `ffs(-1)` (all bits set) | 32 | 1 |

## Why This Is A Real Bug

The POSIX specification for `ffs` is unambiguous: it returns the position of the **first** (least significant) set bit. The current implementation returns the position of the **last** (most significant) set bit. Every caller relying on standard `ffs` semantics — bitmap allocators, scheduling code, bit manipulation utilities — silently receives wrong results, leading to data corruption or incorrect program behavior.

## Fix Requirement

Replace the `@clz`-based formula with a `@ctz`-based formula: return `0` when the input is zero, otherwise return `@ctz(value) + 1`.

## Patch Rationale

The patch replaces the single expression `@bitSizeOf(T) - @clz(value)` with the correct formulation using `@ctz` (count trailing zeros). The `@ctz` intrinsic counts zeros from the least-significant end, so `@ctz(value) + 1` gives the 1-indexed position of the lowest set bit. The zero case is handled first (returning 0) to avoid undefined behavior from `@ctz(0)` and to match the POSIX specification.

## Residual Risk

None

## Patch

```patch
--- a/lib/c/strings.zig
+++ b/lib/c/strings.zig
@@ -50,5 +50,8 @@ fn firstBitSet(comptime T: type) fn (T) c_int {
         return struct {
             fn f(value: T) callconv(.c) c_int {
-                return @bitSizeOf(T) - @clz(value);
+                if (value == 0) return 0;
+                const trailing: T = @ctz(value);
+                return @as(c_int, trailing) + 1;
             }
         }.f;
```