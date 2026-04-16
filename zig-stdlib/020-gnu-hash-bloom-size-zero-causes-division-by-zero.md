# GNU hash zero-sized tables trigger modulo-by-zero

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/dynamic_library.zig:418`
- `lib/std/dynamic_library.zig:468`
- `lib/std/dynamic_library.zig:478`
- `lib/std/dynamic_library.zig:492`

## Summary
`ElfDynLib.open` accepts `DT_GNU_HASH` metadata without validating required nonzero table sizes. Later, `ElfDynLib.lookupAddress` performs `% gnu_hash_header.bloom_size` and `% gnu_hash_header.nbuckets`. If either field is zero, symbol lookup traps on modulo-by-zero, causing a denial of service for any caller that loads the malformed ELF and performs a lookup.

## Provenance
- Verified from the provided reproducer and source inspection in `lib/std/dynamic_library.zig`
- Reproduced finding: GNU-hash lookup uses unchecked `bloom_size` and `nbuckets` in modulo operations
- Reference: https://swival.dev

## Preconditions
- A GNU-hash ELF shared object with `DT_GNU_HASH` is loaded
- `bloom_size == 0` or `nbuckets == 0`
- A caller invokes `lookup` or `lookupAddress`

## Proof
- `ElfDynLib.open` stores the raw GNU-hash header from `DT_GNU_HASH` without rejecting zero-sized tables at `lib/std/dynamic_library.zig:418`
- In `ElfDynLib.lookupAddress`, GNU-hash lookup computes:
```zig
const bloom_index = (hash / @bitSizeOf(usize)) % gnu_hash_header.bloom_size;
```
at `lib/std/dynamic_library.zig:468` and again at `lib/std/dynamic_library.zig:478`
- The same path later computes:
```zig
const bucket_index = hash % gnu_hash_header.nbuckets;
```
at `lib/std/dynamic_library.zig:492`
- With either divisor equal to zero, lookup traps before any protective bounds check, producing a deterministic crash

## Why This Is A Real Bug
The crash is directly reachable from public lookup APIs after a malformed library is opened. Although `open` documents that loading malicious libraries is unsafe and not a security boundary, the runtime fault is still real, deterministic, and caused by missing validation in loader logic. This makes the issue a valid denial-of-service bug in the implementation.

## Fix Requirement
Reject GNU-hash headers with `bloom_size == 0` or `nbuckets == 0` before storing or using them, or guard both modulo sites before the operations occur.

## Patch Rationale
Validate GNU-hash header invariants once during load in `ElfDynLib.open`. Rejecting zero-sized GNU-hash tables prevents both modulo-by-zero sites and avoids carrying invalid metadata deeper into symbol resolution.

## Residual Risk
None

## Patch
Patched in `020-gnu-hash-bloom-size-zero-causes-division-by-zero.patch` by adding GNU-hash header validation in `lib/std/dynamic_library.zig` so `DT_GNU_HASH` entries with zero `bloom_size` or zero `nbuckets` are rejected before `lookupAddress` can execute modulo operations on those fields.