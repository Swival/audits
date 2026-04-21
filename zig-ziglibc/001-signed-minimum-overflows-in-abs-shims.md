# Signed minimum overflows in abs shims

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/c/stdlib.zig:42`
- `lib/c/inttypes.zig:17`

## Summary
On musl and WASI libc targets, the exported C shims `abs`, `labs`, `llabs`, and `imaxabs` computed `@abs(a)` and then narrowed the result back to the original signed type. For the minimum signed input, the mathematical absolute value is not representable in the same signed type, so the narrowing step violates the functions' signed-range invariant and can trap or otherwise fail.

## Provenance
- Verified from repository source and reproduced from the reported path.
- Reference: Swival Security Scanner - https://swival.dev

## Preconditions
- Target uses the musl or WASI libc shims.
- A caller invokes `abs(INT_MIN)`, `labs(LONG_MIN)`, `llabs(LLONG_MIN)`, or `imaxabs(INTMAX_MIN)`.

## Proof
- `lib/c/stdlib.zig` exports the C symbols behind the musl/WASI guard and implemented `abs`-family helpers as `@intCast(@abs(a))`.
- `lib/c/inttypes.zig:17` implemented `imaxabs` with the same `@intCast(@abs(a))` pattern.
- For any signed type `T`, `@abs(std.math.minInt(T))` is one greater than `std.math.maxInt(T)`, so converting that value back to `T` is not representable.
- The tree already encodes the intended non-trapping behavior in C translation builtins by special-casing `minInt` and returning the negative input.

## Why This Is A Real Bug
The affected functions are exported C ABI entry points and are directly reachable by external callers. Their return type is the same signed type as the input, so producing an unrepresentable intermediate and narrowing it back violates a concrete type invariant at runtime. This is not speculative: the minimum signed value is a valid input, and the repository already documents that C-library-compatible handling keeps that value negative rather than trapping.

## Fix Requirement
Special-case `minInt` before taking the absolute value, and return the original negative input for that case; otherwise compute the absolute value and cast safely.

## Patch Rationale
The patch aligns the musl/WASI shims with existing repository behavior for translated C builtins and with practical C-library compatibility expectations. Returning the unchanged minimum signed value avoids the invalid narrowing conversion while preserving the established non-trapping behavior for these ABI shims. The same fix is applied to `imaxabs` because it had the identical bug pattern.

## Residual Risk
None

## Patch
Patched in `001-signed-minimum-overflows-in-abs-shims.patch`:
- `lib/c/stdlib.zig` now guards `abs`, `labs`, and `llabs` against `std.math.minInt(...)` and returns the input unchanged in that case.
- `lib/c/inttypes.zig` now applies the same `minInt` guard to `imaxabs`.
