# Zero-length read buffer triggers invalid iovec access

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Io/Kqueue.zig:841`

## Summary
`netRead` builds an `iovec` array from caller-provided destination buffers and assumes at least one non-empty entry exists before checking `dest[0].len`. When all input buffers are empty, the filtered slice length is `0`, and `dest[0]` becomes an invalid access. The patch returns `0` when no non-empty buffers are collected, matching existing vectored-read behavior elsewhere.

## Provenance
- Verified from the provided reproducer and source inspection
- Reference: https://swival.dev

## Preconditions
- `netRead` is called with only empty buffers

## Proof
`netRead` iterates over `data: [][]u8`, copies only non-empty buffers into `iovecs_buffer`, and tracks the count in `i`. It then forms `dest = iovecs_buffer[0..i]`. If every caller buffer is empty, `i == 0`, so `dest.len == 0`. The subsequent `assert(dest[0].len > 0)` indexes past a zero-length slice before any syscall occurs. Returning `0` at `i == 0` prevents the invalid access and matches the semantics already used by the `readv` path that treats a zero-length vector as a successful zero-byte read.

## Why This Is A Real Bug
The failing condition is fully controlled by API input and does not rely on undefined external state. A caller can supply an all-empty destination vector, causing an assertion failure in checked builds or an out-of-bounds access at the invariant point. This is a reachable denial-of-service condition and contradicts established vectored-read handling that returns `0` for an empty effective vector.

## Fix Requirement
Add a guard after filtering destination buffers and before any `dest[0]` access: if no non-empty buffers were collected, return `0`.

## Patch Rationale
The patch is minimal and preserves intended semantics. It enforces the non-empty-`iovec` invariant locally in `Kqueue.netRead`, avoids invalid indexing, and aligns behavior with `lib/std/Io/Dispatch.zig`, which already returns `0` when `iovlen == 0` before issuing `readv`.

## Residual Risk
None

## Patch
- Patch file: `019-zero-length-read-buffer-triggers-invalid-iovec-access.patch`
- Change: in `lib/std/Io/Kqueue.zig`, return `0` when the filtered destination vector is empty before evaluating `dest[0]`