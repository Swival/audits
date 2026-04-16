# Double free of step_names_trailing during teardown

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/WebServer.zig:140`

## Summary
`WebServer.deinit` frees `ws.step_names_trailing` twice on the normal teardown path after a successful `WebServer.init`. The first `gpa.free(ws.step_names_trailing)` executes near the start of `deinit`, and the same slice is freed again at function end without reassignment or nulling. This creates allocator misuse on every successful init/deinit lifecycle.

## Provenance
- Verified finding reproduced from the provided report
- Scanner source: https://swival.dev
- Reproducer confirms reachability through the public `WebServer` lifecycle and real build-runner usage

## Preconditions
- `WebServer.init` succeeds
- `WebServer.deinit` is called once on that instance

## Proof
- `init` stores an allocated slice in `ws.step_names_trailing`
- In `deinit`, `gpa.free(ws.step_names_trailing)` is called before other teardown work
- The same `ws.step_names_trailing` slice is freed again at the end of `deinit`
- No reassignment, nulling, or ownership transfer occurs between the two calls
- Reproduction shows this path is exercised by the normal `init`/`deinit` API and aborts under `std.heap.DebugAllocator` with explicit double-free detection

## Why This Is A Real Bug
This is not speculative or input-dependent: once `init` succeeds, a single call to `deinit` deterministically issues two frees for the same allocation. That violates allocator ownership rules. Under Zig's debug allocator, this is an immediate panic; under other allocators, it is undefined behavior with possible heap corruption. The bug is reachable from the intended `WebServer` lifecycle used by the build runner.

## Fix Requirement
Remove the second, redundant free of `ws.step_names_trailing` from `WebServer.deinit` so the allocation is released exactly once.

## Patch Rationale
The allocation already has a matching free earlier in `deinit`. Deleting the trailing duplicate free is the minimal, behavior-preserving fix that restores one-allocation/one-free ownership semantics without changing teardown order for unrelated resources.

## Residual Risk
None

## Patch
`015-double-free-of-step-names-trailing-during-teardown.patch` removes the final redundant `gpa.free(ws.step_names_trailing)` from `WebServer.deinit` in `lib/std/Build/WebServer.zig`.