# Sleep cancellation callback uses wrong waiter callback

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Io/Dispatch.zig:2382`

## Summary
Cancelable sleep initializes its cancellation hook with `&Futex.Waiter.canceled` instead of the sleep-specific `&SleepWaiter.canceled`. When cancellation happens before the timer fires, the runtime invokes the futex waiter callback with a `SleepWaiter.cancelable` pointer. That callback reconstructs the parent as `*Futex.Waiter`, violating object layout assumptions and causing invalid memory access.

## Provenance
- Verified finding reproduced from scanner report
- Scanner source: https://swival.dev
- Reproducer confirmed the bad callback path is reachable and executes prior to normal sleep cancellation handling

## Preconditions
- A cancelable sleep is canceled before its timer fires

## Proof
At `lib/std/Io/Dispatch.zig:2382`, `sleep()` assigns the cancellation callback for a `SleepWaiter` to `&Futex.Waiter.canceled`.

On cancellation, fiber cancellation dispatches that callback with the `SleepWaiter.cancelable` field pointer. `Futex.Waiter.canceled` then performs `@fieldParentPtr("cancelable", cancelable)` as though the enclosing object were `Futex.Waiter`. That assumption is false: the actual parent object is `SleepWaiter`.

The reproduced execution shows the resulting mis-cast is not benign:
- the callback treats the `SleepWaiter` storage as a full `Futex.Waiter`
- it reads fields at offsets corresponding to `waiter.futex`, `waiter.node`, and `waiter.timer`
- in `SleepWaiter`, those offsets instead overlap the dispatch timer handle, a `started` boolean plus padding, and memory beyond the 48-byte object
- it then calls `waiter.remove()`, which mutates memory through a bogus `*Futex` and fake list node

This yields a concrete memory corruption / crash path instead of the intended sleep-specific cancellation behavior.

## Why This Is A Real Bug
The bug is reachable under a simple documented condition: cancelable sleep canceled before timeout. The wrong callback is invoked deterministically from the cancellation path, and the callback performs parent-pointer reconstruction against the wrong enclosing type. The reproduced trace confirms subsequent reads and writes occur through invalid pointers, including an out-of-bounds field access and list mutation through corrupted state. This is a real safety issue, not a theoretical type mismatch.

## Fix Requirement
Replace the cancel callback used for sleep waiters so cancellation dispatch targets `SleepWaiter.canceled`, preserving the correct enclosing type and sleep-specific cancellation semantics.

## Patch Rationale
The patch updates the sleep waiter initialization to use `&SleepWaiter.canceled` in `lib/std/Io/Dispatch.zig`. That aligns callback type, enclosing object layout, and intended behavior:
- cancellation reconstructs the correct `SleepWaiter`
- the sleep path only records cancel intent and cancels the timer
- no futex waiter removal logic runs on a non-futex object

## Residual Risk
None

## Patch
- `005-sleep-cancellation-callback-casts-wrong-waiter-type.patch` changes the sleep waiter cancel callback in `lib/std/Io/Dispatch.zig` from `&Futex.Waiter.canceled` to `&SleepWaiter.canceled`