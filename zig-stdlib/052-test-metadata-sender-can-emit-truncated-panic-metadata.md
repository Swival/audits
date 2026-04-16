# Test metadata sender emits malformed frame on slice length mismatch

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/zig/Server.zig:249`

## Summary
`serveTestMetadata` trusts caller-supplied `TestMetadata` slice lengths. It computes `tests_len` and `bytes_len` from `names.len`, then serializes both `names` and `expected_panic_msgs`. If those slice lengths differ, the emitted `test_metadata` frame is internally inconsistent and violates the protocol invariant required by the build runner.

## Provenance
- Verified from the provided finding and reproducer analysis
- Swival Security Scanner: https://swival.dev

## Preconditions
- `expected_panic_msgs.len` differs from `names.len`

## Proof
`serveTestMetadata` accepts caller-controlled `TestMetadata` and derives the frame header from `names.len` before writing the payload. The payload writer then iterates over `expected_panic_msgs` independently. When `expected_panic_msgs.len < names.len`, the sender advertises a larger body than it actually emits for panic metadata. The receiver first waits for the full declared body length in `lib/std/Build/Step/Run.zig:1888`, then parses it in `lib/std/Build/Step/Run.zig:1917`; a short body therefore stalls until EOF or timeout instead of cleanly consuming metadata. The receiver also assumes `expected_panic_msgs` has one entry per test and indexes accordingly in `lib/std/Build/Step/Run.zig:2548`, confirming the invariant is mandatory.

## Why This Is A Real Bug
The protocol requires aligned per-test metadata arrays. A malformed `test_metadata` frame is reachable from `serveTestMetadata` whenever mismatched slices are provided, and the build runner behavior demonstrates concrete failure: it blocks waiting for bytes that will never arrive or later operates on invalid assumptions. Even if the current in-tree caller usually passes equal lengths, the callee boundary is still unsafe and the malformed frame construction is real.

## Fix Requirement
Reject mismatched `names` and `expected_panic_msgs` slice lengths before computing the header or writing any output.

## Patch Rationale
The patch adds a length check at the start of `serveTestMetadata` and returns an error on mismatch. This enforces the protocol invariant at the serialization boundary, preventing inconsistent `tests_len`/`bytes_len` fields and ensuring no malformed `test_metadata` frame is emitted.

## Residual Risk
None

## Patch
Patched in `052-test-metadata-sender-can-emit-truncated-panic-metadata.patch`.