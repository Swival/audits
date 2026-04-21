# malloc Integer Overflow

## Classification
Vulnerability — High Severity

## Affected Locations
- `lib/c/malloc.zig:92`

## Summary
On 32-bit targets, `malloc` adds `alignment_bytes` to the user-requested size `n` before calling the backing allocator. If `n` exceeds `maxInt(usize) - alignment_bytes`, the addition wraps to a small value. The allocator under-allocates the block, the returned user pointer is computed past the true allocation end, and the caller’s first write is an out-of-bounds heap access.

## Provenance
Swival Security Scanner — https://swival.dev

## Preconditions
- 32-bit target.
- `malloc(n)` invoked with `n > maxInt(usize) - alignment_bytes` (e.g., `malloc(0xFFFFFFFF)`).
- Reached directly or via internal callers such as `calloc` and `realloc`.

## Proof
- **Input:** `n` near `usize` max on a 32-bit build.
- **Path:** The size cast to `Header.Size` succeeds. At line 92, `n + alignment_bytes` overflows before `vtable.alloc` is called.
- **Condition:** The wrapped sum is a small value, causing the backing allocator to provide a block of only `alignment_bytes` (or similarly insufficient) size.
- **Impact:** `base = ptr + alignment_bytes` points at or past the actual allocation boundary. Because the caller believes it owns `n` bytes, the first store through the returned pointer is a heap buffer overflow. The path is practically triggerable by any program requesting a very large allocation on 32-bit systems.

## Why This Is A Real Bug
The overflow is reachable through standard allocator entry points on a supported target width. It converts an attacker-controlled request size into a guaranteed under-allocation and an immediate out-of-bounds write, satisfying the classic integer-overflow-to-buffer-overflow pattern.

## Fix Requirement
Validate `n <= maxInt(usize) - alignment_bytes` before performing the addition; return `null` if the check fails.

## Patch Rationale
Inserting an explicit saturation check before the size arithmetic eliminates the wrap-around condition entirely. The check preserves the fast path for all valid requests and aligns with safe integer handling practices in allocator implementations.

## Residual Risk
None.

## Patch
`001-malloc-integer-overflow.patch`
```diff
--- a/lib/c/malloc.zig
+++ b/lib/c/malloc.zig
@@ -89,6 +89,10 @@ pub export fn malloc(n: usize) ?*anyopaque {
     const alignment_bytes = @max(@alignOf(Header), page_size);
+    if (n > std.math.maxInt(usize) - alignment_bytes) {
+        return null;
+    }
     const total_size = n + alignment_bytes;
     const ptr = vtable.alloc(total_size, alignment_bytes, @returnAddress()) orelse return null;
     const base = ptr + alignment_bytes;
```