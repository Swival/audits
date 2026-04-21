# posix_memalign missing alignment validation

## Classification
Validation gap. Medium severity. Confidence: certain.

## Affected Locations
- `lib/c/malloc.zig:186`

## Summary
`posix_memalign` does not validate that `alloc_alignment` is a power of two before forwarding it to `aligned_alloc_inner` → `Alignment.fromByteUnits`. In release builds, the debug assertion inside `fromByteUnits` is elided, allowing non-power-of-two values to propagate silently. This produces an under-aligned pointer and incorrect header metadata, violating POSIX `EINVAL` requirements and internal allocator invariants.

## Provenance
[Swival Security Scanner](https://swival.dev)

## Preconditions
- Caller passes a non-power-of-two value to the `alloc_alignment` argument of `posix_memalign`.

## Proof
- **Path:** `posix_memalign` → `aligned_alloc_inner` → `Alignment.fromByteUnits`.
- **Condition:** No power-of-two validation guards `alloc_alignment` before it reaches the allocator.
- **Runtime evidence:** In `ReleaseFast`, `Alignment.fromByteUnits(24)` returned `.8` instead of panicking, confirming the assert is elided. Replicating the exact `aligned_alloc_inner` logic with `alloc_alignment = 48` computed `max_align = 16`, which is strictly smaller than requested.
- **Impact:** The allocator commits to 16-byte alignment while the caller requested 48, returning an under-aligned pointer. The stored header reflects the reduced alignment, breaking the API contract.
- **Reachability:** Direct C API call.

## Why This Is A Real Bug
POSIX requires `posix_memalign` to return `EINVAL` when alignment is not a power of two. Returning an under-aligned pointer violates this contract and causes undefined behavior in caller code that depends on the requested alignment for atomic operations, SIMD, or DMA.

## Fix Requirement
Add a power-of-two check for `alloc_alignment` at the entry of `posix_memalign`. Return `EINVAL` if the check fails, before invoking the allocator.

## Patch Rationale
The patch inserts explicit validation of `alloc_alignment` at the start of `posix_memalign`. This enforces the POSIX precondition, prevents the under-alignment path from executing, and stops invalid values from corrupting allocator metadata.

## Residual Risk
None.

## Patch
`003-posix-memalign-missing-alignment-validation.patch`