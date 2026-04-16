# Release Builds Permit Mismatched Buffer Lengths

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/crypto/isap.zig:97`

## Summary
`xor` enforced `in.len == out.len` only with `debug.assert`, so release builds skipped the check. `encrypt` and `decrypt` forwarded caller-controlled slices into `xor`, allowing `out.len < in.len` to produce out-of-bounds writes instead of a clean failure.

## Provenance
- Verified from the provided finding and release-build reproducer
- Reproduced in-worktree with `ReleaseFast`
- Scanner reference: https://swival.dev

## Preconditions
- Release build
- Caller passes `out.len < in.len` to `xor` through `encrypt` or `decrypt`

## Proof
In the vulnerable path, `xor` computed work from `in.len` and then wrote to `out` without a runtime length guard. When `left >= 8`, it wrote `out[i..][0..8]`; otherwise it wrote the remaining tail to `out[i..]`. Because bounds were derived from `in.len`, a shorter `out` slice caused writes past the declared output slice in release builds.

The provided `ReleaseFast` reproducer showed practical memory corruption: invoking `IsapA128A.encrypt` with a 16-byte input and an 8-byte output slice modified bytes 8..15 of the backing allocation, changing sentinel bytes outside the output slice.

## Why This Is A Real Bug
This is a concrete memory-safety failure, not a theoretical invariant mismatch. The reproducer demonstrates attacker-controlled length mismatch propagating through public encryption entry points and corrupting adjacent memory in optimized builds. Debug-only assertions do not preserve the API contract in production.

## Fix Requirement
Replace the debug-only length assertion with a runtime validation that rejects mismatched buffer lengths and returns an error before any write occurs.

## Patch Rationale
The patch in `049-release-builds-permit-mismatched-buffer-lengths.patch` hardens `xor` by enforcing the buffer-length invariant at runtime, ensuring both debug and release builds fail safely on malformed inputs. This aligns the implementation with the existing caller-visible contract and removes the out-of-bounds write primitive.

## Residual Risk
None

## Patch
- `049-release-builds-permit-mismatched-buffer-lengths.patch` adds a runtime `in.len != out.len` guard in `lib/std/crypto/isap.zig` and returns an error on mismatch before processing begins.