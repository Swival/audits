# CTR-DRBG `incV` unsigned underflow

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/ml_kem.zig:1088`

## Summary
`incV` reverse-iterates a 16-byte counter using `var j: usize = 15; while (j >= 0) : (j -= 1)`. When `g.v` is all `0xff`, every byte carries, the loop reaches `j == 0`, and the post-iteration decrement underflows `usize`. In checked builds this traps; in unchecked optimized builds it wraps to `maxInt(usize)` and the next `g.v[j]` access is out of bounds.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner source: https://swival.dev

## Preconditions
- `g.v` is all `0xff` bytes when `incV` executes

## Proof
- `NistDRBG.fill()` and `NistDRBG.update()` call `incV()` on internal state `g.v`.
- In `lib/std/crypto/ml_kem.zig:1088`, `incV` initializes `j` as unsigned `usize` and decrements it in the loop post-step.
- The reproduced seed drives `g.v` to `ff...ff` immediately after `init()`.
- On the next `fill()`, `incV()` processes bytes 15 down to 0, zeroing each due to carry.
- After the `j == 0` iteration, the loop post-step performs `j -= 1`, which underflows `usize`.
- Checked/debug builds trap on that arithmetic underflow; unchecked optimized builds wrap and then evaluate `g.v[j]` with an invalid index.

## Why This Is A Real Bug
The bug is reachable through normal DRBG state evolution, not only through synthetic state corruption. The reproduced seed makes the committed implementation enter the failing state immediately after initialization. The resulting behavior is not a benign counter wrap: it is either a deterministic runtime trap or undefined out-of-bounds memory access, violating both correctness and memory safety expectations.

## Fix Requirement
Rewrite the reverse counter increment so termination does not depend on decrementing an unsigned index past zero. Use a signed index or a reverse-iteration construct that cannot underflow.

## Patch Rationale
The patch replaces the unsigned-decrement loop with a reverse traversal that preserves the intended carry propagation across all 16 bytes while making the zero case explicit and non-underflowing. This maintains CTR-DRBG semantics and removes both the checked-build trap and unchecked-build out-of-bounds path.

## Residual Risk
None

## Patch
Patched in `057-ctr-drbg-counter-increment-underflows-loop-index.patch`.