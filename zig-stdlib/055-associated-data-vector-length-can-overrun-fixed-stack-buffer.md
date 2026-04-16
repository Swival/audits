# Associated-data vector length can overrun fixed stack buffer

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/crypto/aes_siv.zig:230`
- `lib/std/crypto/aes_siv.zig:245`

## Summary
`encryptWithAdVector` and `decryptWithAdVector` build an S2V input list in a fixed stack buffer `strings_buf: [128][]const u8`, copying all associated-data slices and then appending the message slice. The public API does not validate `ad.len` before these writes. When `ad.len >= 128`, the append of `m` writes past the end of `strings_buf`; in unchecked builds this becomes an out-of-bounds stack write before authentication or tag verification.

## Provenance
- Verified from the provided reproducer and source inspection in `lib/std/crypto/aes_siv.zig`
- Scanner source: https://swival.dev

## Preconditions
- Caller passes 128 or more associated-data components to the public AD-vector API

## Proof
- `encryptWithAdVector` and `decryptWithAdVector` allocate `strings_buf: [128][]const u8` and increment `strings_len` once per `ad` element before appending `m`.
- With `ad.len == 128`, the loop fills indices `0..127`, then `strings_buf[strings_len] = m` writes index `128`, one past the array bound.
- Reproduced behavior:
  - Debug, `ad.len == 127`: aborts later in `s2v` due to `assert(strings.len <= 127)`, confirming the caller can exceed the S2V input limit.
  - Debug, `ad.len == 128`: aborts at `lib/std/crypto/aes_siv.zig:245` with `index out of bounds: index 128, len 128`.
  - `ReleaseFast`, `ad.len == 128`: completes without trapping, demonstrating the bounds check/assert are removed and the write occurs unchecked.
- The same pattern exists in both encrypt and decrypt paths, and decrypt performs the write before tag verification.

## Why This Is A Real Bug
This is memory corruption on a public, caller-controlled API surface. The failure is not limited to debug assertions: release builds permit the out-of-bounds stack write, so malformed input can corrupt memory before any cryptographic verification occurs. The bug affects both encryption and decryption and is reachable with a simple length-only condition on `ad`.

## Fix Requirement
Reject oversized associated-data vectors before populating `strings_buf`, specifically ensuring capacity for all AD entries plus the trailing message entry. A correct bound is `ad.len <= 127` for S2V input count, and `ad.len <= 126` if the implementation reserves one slot for `m` within a 128-entry temporary buffer.

## Patch Rationale
The patch in `055-associated-data-vector-length-can-overrun-fixed-stack-buffer.patch` adds explicit input validation before writing into the fixed stack buffer, preventing any `strings_buf` overrun in both encrypt and decrypt flows. This aligns the public API with the internal S2V input-count constraint and ensures invalid inputs fail safely before stack memory is touched.

## Residual Risk
None

## Patch
```diff
--- a/lib/std/crypto/aes_siv.zig
+++ b/lib/std/crypto/aes_siv.zig
@@
-    var strings_buf: [128][]const u8 = undefined;
+    if (ad.len > 126) return error.InvalidAssociatedData;
+    var strings_buf: [128][]const u8 = undefined;
@@
-    var strings_buf: [128][]const u8 = undefined;
+    if (ad.len > 126) return error.InvalidAssociatedData;
+    var strings_buf: [128][]const u8 = undefined;
```