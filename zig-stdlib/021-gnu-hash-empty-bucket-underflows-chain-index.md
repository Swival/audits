# GNU hash empty bucket underflows chain index

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/dynamic_library.zig:431`

## Summary
- `ElfDynLib.lookupAddress` subtracts `header.symoffset` from a GNU-hash bucket value without handling the ELF empty-bucket sentinel `0`.
- When `buckets[bucket_index] == 0`, `chain_index = 0 - symoffset` underflows `u32`.
- In safe builds this is a reliable crash via integer overflow; in wrapping builds it produces a huge index and drives an out-of-bounds read from the GNU hash chain table.

## Provenance
- Verified from the provided reproducer and patch requirements.
- Reference: https://swival.dev

## Preconditions
- Linux `ElfDynLib.lookupAddress` processes attacker-controlled ELF metadata loaded through `open` or `openZ`.
- The ELF contains `DT_GNU_HASH` with the selected bucket set to `0`.
- The requested symbol passes the GNU bloom filter and reaches bucket/chain traversal.

## Proof
- The vulnerable logic is:
```zig
const bucket_index = hash % header.nbuckets;
const chain_index = buckets[bucket_index] - header.symoffset;
```
- GNU hash uses `0` as the empty-bucket sentinel; that value is not a valid symbol index and must not be decremented by `symoffset`.
- The reproducer set `buckets[0] = 0` and reached this subtraction.
- Observed behavior:
  - Debug / ReleaseSafe: integer overflow trap at the subtraction.
  - ReleaseFast: wraps to `4294967295`, which then flows into `current_index` and the subsequent `chains[current_index]` access.

## Why This Is A Real Bug
- The code accepts untrusted ELF dynamic-linker metadata and violates the GNU-hash bucket invariant by treating sentinel `0` as a normal symbol index.
- This is directly reachable during symbol lookup.
- The result is attacker-controlled denial of service in safe builds and an out-of-bounds read path in wrapping builds.

## Fix Requirement
- Before subtracting `header.symoffset`, check whether `buckets[bucket_index] == 0`.
- If the bucket is empty, return `null`.

## Patch Rationale
- Returning `null` on bucket value `0` matches GNU-hash semantics for an empty bucket.
- The guard removes both failure modes: overflow in checked builds and wrapped wild indexing in unchecked builds.
- The change is minimal and preserves existing lookup behavior for valid bucket entries.

## Residual Risk
- None

## Patch
- Patch file: `021-gnu-hash-empty-bucket-underflows-chain-index.patch`
- Required change in `lib/std/dynamic_library.zig:431`:
```diff
 const bucket_index = hash % header.nbuckets;
-const chain_index = buckets[bucket_index] - header.symoffset;
+const bucket = buckets[bucket_index];
+if (bucket == 0) return null;
+const chain_index = bucket - header.symoffset;
```