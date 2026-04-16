# Empty batch initialization underflows storage index

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Io.zig:403`

## Summary
`Io.Batch.init` accepts caller-controlled `storage: []Operation.Storage` and unconditionally initializes a linked free-list using `storage[storage.len - 1]`. When `storage.len == 0`, this underflows the index and immediately performs an out-of-bounds access, while also fabricating invalid non-empty list metadata for `unused.head` and `unused.tail`.

## Provenance
- Reproduced from the verified report and patch workflow
- Reference: https://swival.dev

## Preconditions
- `Batch.init` is called with `storage.len == 0`

## Proof
A minimal caller can reach the bug directly through the public API:
```zig
var storage: [0]Io.Operation.Storage = .{};
_ = Io.Batch.init(&storage);
```

With an empty slice:
- the initialization loop is skipped
- `storage[storage.len - 1].unused.next = .none` underflows to `storage[usize_max]`
- `.unused.head = Operation.Index.fromIndex(0)` and `.unused.tail = Operation.Index.fromIndex(storage.len - 1)` create invalid non-empty free-list state

This yields an immediate out-of-bounds access during initialization, and any later free-list operation would also dereference bogus indices.

## Why This Is A Real Bug
The fault is directly reachable from a public constructor with no internal guard. In checked builds it should trap on bounds validation; in unchecked builds it can corrupt memory and violate `Batch`'s core storage/free-list invariant. The resulting state is not a benign edge case because both initialization and subsequent list consumers assume at least one valid backing element exists.

## Fix Requirement
`Batch.init` must handle `storage.len == 0` before any indexing, either by rejecting empty storage with an assertion or by constructing a valid empty-list state with `.none` head/tail values.

## Patch Rationale
The patch makes empty storage an explicit case in `Batch.init`, avoiding all `len - 1` indexing and ensuring the returned batch encodes an actually empty unused-list state. This preserves existing behavior for non-empty storage while restoring the invariant that free-list metadata only references valid storage entries.

## Residual Risk
None

## Patch
Saved as `004-empty-batch-initialization-reads-before-slice.patch`.