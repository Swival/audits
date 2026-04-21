# mprotectLinux aligns len without accounting for addr alignment delta

## Classification

Logic Error — High Severity

## Affected Locations

- `lib/c/sys/mman.zig:51`: `aligned_len` computation uses original `len` instead of `len + (addr - start)`.

## Summary

In `mprotectLinux`, when `addr` is not page-aligned, `start` is aligned backward to the page boundary, but `aligned_len` is computed by aligning only the original `len` forward to a page boundary. The delta between `addr` and `start` (up to `page_size - 1` bytes) is not added to `len` before alignment, causing the syscall to protect a region that is too short. The tail of the caller's intended range is left with its prior protection bits.

## Provenance

Detected by [Swival Security Scanner](https://swival.dev)

## Preconditions

- `addr` is not page-aligned **and** `addr + len` crosses a page boundary relative to the backward-aligned `start`.

## Proof

The function computes:
```zig
const start = alignBackward(usize, @intFromPtr(addr), page_size);
const aligned_len = alignForward(usize, len, page_size);
// syscall(mprotect, start, aligned_len, prot)
```

When `addr = page_base + delta` (where `delta > 0`), the actual byte range that needs protection from `start` is `delta + len` bytes, but only `alignForward(len)` bytes are passed to the kernel. This leaves up to `page_size - 1` bytes at the tail unprotected.

Musl's reference implementation correctly accounts for this:
```c
start = (size_t)addr & -PAGE_SIZE;
end = (size_t)((char *)addr + len + PAGE_SIZE-1) & -PAGE_SIZE;
return syscall(SYS_mprotect, start, end-start, prot);
```

Any C or Zig code calling the exported `mprotect` symbol on a musl libc target can trigger this.

## Why This Is A Real Bug

A caller intending to mark memory non-writable or non-executable will leave the tail page(s) writable or executable. Conversely, a caller marking memory readable/writable may leave the tail inaccessible, causing segfaults. This is a memory protection bypass that undermines security invariants for any non-page-aligned address.

## Fix Requirement

Add the backward-alignment delta (`@intFromPtr(addr) - start`) to `len` before computing `aligned_len`.

## Patch Rationale

The fix adds the delta between the original `addr` and the backward-aligned `start` to `len` before the forward alignment, matching musl's semantics. This ensures the full byte range `[start, start + aligned_len)` covers every byte in the caller's original `[addr, addr + len)` range.

## Residual Risk

None

## Patch

```patch
--- a/lib/c/sys/mman.zig
+++ b/lib/c/sys/mman.zig
@@ -48,7 +48,7 @@
 fn mprotectLinux(addr: ?[*]const u8, len: usize, prot: c_uint) callconv(.c) c_int {
     const page_size = std.heap.pageSize();
     const start = alignBackward(usize, @intFromPtr(addr), page_size);
-    const aligned_len = alignForward(usize, len, page_size);
+    const aligned_len = alignForward(usize, len + (@intFromPtr(addr) - start), page_size);
     return mprotectSyscall(@ptrFromInt(start), aligned_len, prot);
 }
```