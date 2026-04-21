# getgroupsLinux @intCast of negative size causes panic

## Classification

Invariant Violation — Medium Severity

## Affected Locations

- `lib/c/unistd.zig`: function `getgroupsLinux`, line containing `@intCast(size)` (approximately line 143–144)

## Summary

The `getgroupsLinux` function accepts a `c_int` parameter `size` and converts it to an unsigned type via `@intCast(size)` before passing it to the Linux syscall. When `size` is negative, `@intCast` panics in safe builds ("attempt to cast negative value to unsigned integer") or triggers undefined behavior in unsafe builds. POSIX requires that `getgroups(-1, ...)` return `-1` with `errno` set to `EINVAL`, but the process crashes before the syscall is ever reached.

## Provenance

Detected by [Swival Security Scanner](https://swival.dev)

## Preconditions

1. The target platform is Linux with the Zig-provided musl C library (so `getgroupsLinux` is the active implementation exported as the C `getgroups` symbol).
2. A caller passes a negative value for the `size` parameter (e.g., `getgroups(-1, NULL)`).

## Proof

Calling `getgroups(-1, NULL)` from C code linked against this libc causes execution to reach `getgroupsLinux`. The function attempts `@intCast(size)` where `size` is `-1` (a `c_int`) and the target type is `u32`. In safe builds, this produces a deterministic panic: `"attempt to cast negative value to unsigned integer"`. In unsafe/release builds, this is undefined behavior. The Linux kernel would correctly return `-EINVAL` for a negative size, but the `@intCast` prevents the value from ever reaching the syscall.

## Why This Is A Real Bug

The function is the public C ABI `getgroups` entry point. POSIX explicitly permits negative `size` values and mandates an `EINVAL` error return. Crashing the process instead of returning an error violates the POSIX contract and breaks any C program that relies on standard error handling for invalid arguments.

## Fix Requirement

Before performing `@intCast(size)`, check whether `size` is negative. If it is, return the `EINVAL` error through the standard errno mechanism, matching POSIX semantics and the behavior the Linux kernel would produce.

## Patch Rationale

A guard is inserted immediately before the `@intCast` call. If `size` is negative, the function returns `EINVAL` via the same `errnoIgn` path used for other syscall errors, ensuring POSIX-compliant behavior without reaching the illegal cast. This is the minimal change: no other code paths are affected, and the fix is consistent with how the function already handles syscall error codes.

## Residual Risk

None

## Patch

```patch
--- a/lib/c/unistd.zig
+++ b/lib/c/unistd.zig
@@ -140,6 +140,9 @@ const getgroupsLinux = struct {
     fn getgroupsLinux(size: c_int, list: [*]linux.gid_t) callconv(.c) c_int {
         const val = linux.getgroups(
+            if (size < 0)
+                return errnoIgn(linux.E.INVAL)
+            else
             @intCast(size),
             list,
         );
```