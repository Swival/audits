# batchCancel pending-loop hang

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Io/Dispatch.zig:1122`

## Summary
`batchCancel` iterates `batch.pending` with `while (index != .none)` but never advances `index`. On any non-empty pending list, it repeatedly cancels the same pending node, never reaches queue drain, and never clears `batch.userdata`.

## Provenance
- Verified finding reproduced against the current codebase
- Scanner source: https://swival.dev

## Preconditions
- A batch has at least one pending operation when `Io.Batch.cancel` dispatches to `batchCancel`

## Proof
At `lib/std/Io/Dispatch.zig:1122`, `batchCancel` initializes from `batch.pending.head` and loops until `index == .none`. Inside the loop it reloads the same pending storage entry and calls `operation_userdata.source.cancel()`, but does not assign `index = pending.node.next` before the cancel.

Because the loop variable never changes, control re-enters the loop with the same non-`.none` index and reprocesses the same node indefinitely. This blocks the subsequent cleanup path, including draining pending state and restoring `batch.userdata = null`.

The bug is reachable through committed callers that cancel batches while work may still be pending, including:
- `lib/std/Io/File/MultiReader.zig:99`
- `lib/std/Io/File/MultiReader.zig:202`
- `lib/std/Progress.zig:694`

## Why This Is A Real Bug
This is not a theoretical invariant violation; it is a concrete infinite-loop condition on a reachable API path. The documented postcondition for batch cancellation requires pending work to be drained and userdata cleared, but this implementation can hang forever before either occurs whenever the pending list is non-empty.

## Fix Requirement
Advance to the next pending node exactly once per iteration, before invoking cancellation on the current node.

## Patch Rationale
The patch stores `pending.node.next` into `index` before calling `operation_userdata.source.cancel()`. This preserves safe traversal even if cancellation mutates or removes the current pending node, and guarantees loop progress toward `.none` so batch cleanup can complete.

## Residual Risk
None

## Patch
Applied in `006-batchcancel-never-advances-pending-index.patch`.