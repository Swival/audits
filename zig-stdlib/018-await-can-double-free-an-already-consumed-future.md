# Await Double-Consume Double-Free

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Io/Kqueue.zig:576`

## Summary
`Io.Kqueue.await()` recycles the heap-allocated `Fiber` backing an `Io.AnyFuture` every time the raw future handle is awaited. Completion only marks the fiber as finished, not consumed, so a second call through the public raw `await` vtable entry skips waiting and recycles the same allocation again, causing use-after-free and double-free.

## Provenance
- Verified finding reproduced from the provided report and code inspection
- Reference scanner: https://swival.dev

## Preconditions
- The same raw `*Io.AnyFuture` handle is awaited more than once
- Caller reaches the public raw vtable entry instead of relying solely on the idempotent high-level wrapper

## Proof
`concurrent()` returns a heap-allocated `Fiber` wrapped as `Io.AnyFuture`. In `lib/std/Io/Kqueue.zig:576`, `await()`:
- waits only if `future_fiber.awaiter != Fiber.finished`
- always copies `future_fiber.resultBytes(...)`
- unconditionally calls `k.recycle(future_fiber)`

Completion paths set `fiber.awaiter = Fiber.finished`, but no consumed marker is recorded. Therefore:
1. First raw `await()` returns the result and recycles the `Fiber`
2. Second raw `await()` on the same handle observes `awaiter == Fiber.finished`, skips waiting, reads from freed memory, and recycles the same allocation again

The reproducer is source-supported because `std.Io.concurrent()` exposes the raw future through `Io.Future.any_future`, allowing callers to retain `future.any_future.?` and invoke `io.vtable.await(...)` twice.

## Why This Is A Real Bug
The vulnerable entrypoint is publicly reachable, the backing object is heap-allocated, and repeated raw awaits operate on the same pointer after it has been freed. This is not a theoretical misuse blocked by the API surface: the raw handle is exposed by design, and the implementation lacks a one-time consumption guard at the allocator ownership boundary.

## Fix Requirement
`await()` must atomically mark a future as consumed and only recycle the `Fiber` on the first successful consume. Subsequent raw awaits must not read or free the already-consumed allocation.

## Patch Rationale
The patch adds consumption tracking in `lib/std/Io/Kqueue.zig` so `await()` transitions the future into a consumed state before recycling. This enforces single ownership transfer at the raw vtable boundary and prevents both post-free reads and duplicate frees while preserving normal first-await behavior.

## Residual Risk
None

## Patch
- `018-await-can-double-free-an-already-consumed-future.patch`