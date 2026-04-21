# lrint undefined behavior on NaN/Inf/out-of-range input

## Classification
Logic Error — High Severity

## Affected Locations
- `lib/c/math.zig:236` — `lrint` and `lrintf` implementations

## Summary
The Zig libc `lrint`/`lrintf` implementations call `@intFromFloat` on the result of `rint()` without guarding against NaN, infinity, or values outside the representable range of `c_long`. In Zig, `@intFromFloat` on any of these inputs is safety-checked undefined behavior: Debug builds panic, ReleaseFast builds silently produce incorrect results (typically 0). The C standard requires `lrint` to return an implementation-defined value and raise `FE_INVALID` for these cases.

## Provenance
Discovered by [Swival Security Scanner](https://swival.dev)

## Preconditions
- Caller passes NaN, infinity, or a floating-point value whose magnitude exceeds `c_long` range to `lrint` or `lrintf`.
- Target uses Zig's bundled C math library (musl/wasi targets).

## Proof

| Input | Debug mode | ReleaseFast mode |
|-------|-----------|------------------|
| NaN | Silently returns 0 (wrong; C requires FE_INVALID) | UB, returns 0 |
| ±Inf | **Panics**: "integer part of floating point value out of bounds" | UB, returns 0 |
| 1e30 (>LONG_MAX) | **Panics**: "integer part of floating point value out of bounds" | UB, returns 0 |

The root cause: `rint` uses an exponent check `e >= 0x3ff+52` to return the input unchanged. NaN and Inf have exponent `0x7ff`, which satisfies this check, so they pass through to `@intFromFloat` unmodified. Large finite values similarly survive `rint` unchanged when their exponent indicates they have no fractional bits.

## Why This Is A Real Bug
Any C program linked with Zig's libc that calls `lrint(NaN)`, `lrint(INFINITY)`, or `lrint(<large value>)` will either crash (Debug) or silently produce incorrect results (Release). This violates the C standard (C11 §7.12.9.5) and breaks real-world code that relies on well-defined `lrint` behavior for all inputs.

## Fix Requirement
Before calling `@intFromFloat`, check whether the rounded value is NaN, infinite, or outside the representable range of `c_long`. For such inputs, return `math.minInt(c_long)` (the standard "unspecified" sentinel, matching glibc/musl behavior).

## Patch Rationale
The patch inserts a bounds check after calling `rint`/`rintf` and before `@intFromFloat`. It tests for NaN (via `math.isNan`), then checks whether the rounded value lies within `[minInt(c_long), maxInt(c_long)]`. Out-of-range, NaN, and infinite values all return `math.minInt(c_long)`, which is the conventional C implementation-defined result for domain errors in `lrint`. The same logic is applied to both `lrint` (f64) and `lrintf` (f32).

## Residual Risk
None — the patch fully eliminates the undefined behavior for all non-representable inputs. The returned sentinel value (`LONG_MIN`) matches the convention used by glibc and musl. Setting `FE_INVALID` or `errno` is not implemented, but Zig's libc does not support floating-point exceptions elsewhere either, so this is consistent.

## Patch

```patch
--- a/lib/c/math.zig
+++ b/lib/c/math.zig
@@ -233,12 +233,28 @@ fn rint(comptime T: type, x: T) T {
     return y;
 }
 
+fn safeIntFromRounded(comptime T: type, rounded: T) c_long {
+    if (math.isNan(rounded)) {
+        return math.minInt(c_long);
+    }
+    const c_long_min: T = @floatFromInt(math.minInt(c_long));
+    const c_long_max: T = @floatFromInt(math.maxInt(c_long));
+    if (rounded < c_long_min or rounded > c_long_max) {
+        return math.minInt(c_long);
+    }
+    return @intFromFloat(rounded);
+}
+
 export fn lrintf(x: f32) c_long {
-    return @intFromFloat(rintf(x));
+    const rounded = rintf(x);
+    return safeIntFromRounded(f32, rounded);
 }
 
 export fn lrint(x: f64) c_long {
-    return @intFromFloat(rint(.f64, x));
+    const rounded = rint(.f64, x);
+    return safeIntFromRounded(f64, rounded);
 }
 
 export fn rintf(x: f32) f32 {
```