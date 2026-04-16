# Shared lock path races lazy debug-info cache

## Classification
- Type: race condition
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/SelfInfo/Windows.zig:258`
- `lib/std/debug/SelfInfo/Windows.zig:394`
- `lib/std/debug/SelfInfo/Windows.zig:53`
- `lib/std/debug/SelfInfo/Windows.zig:56`
- `lib/std/debug.zig:315`
- `lib/std/debug.zig:318`
- `lib/std/debug.zig:1205`

## Summary
`SelfInfo.getSymbols` resolves modules while holding only `si.lock.lockShared`, but the path lazily initializes `module.di` through `module.getDebugInfo`. That cache write occurs without exclusive synchronization. Two threads resolving symbols for the same uncached module can both observe `module.di == null` and concurrently initialize and store separate `DebugInfo` instances into the same field. This is a real data race on shared memory and can also leak the overwritten allocation because `module.deinit` later frees only the final stored value.

## Provenance
- Verified from the provided reproducer and code-path analysis.
- Scanner source: https://swival.dev

## Preconditions
- Two threads call symbol resolution concurrently.
- Both threads target the same module instance in the process-global `SelfInfo`.
- The module debug-info cache is still uninitialized.

## Proof
`std.debug.getSelfDebugInfo()` exposes a process-global `SelfInfo`, and `SelfInfo.getSymbols` is a public callable API with no thread-affinity restriction at `lib/std/debug.zig:315`, `lib/std/debug.zig:318`, and `lib/std/debug.zig:1205`.

On Windows, `getSymbols` takes only the shared lock, then reaches `findModule` and `module.getDebugInfo` at `lib/std/debug/SelfInfo/Windows.zig:258`. The lazy cache logic performs `if (module.di == null) module.di = loadDebugInfo(...)` while still in that reader-locked region. Because shared locking permits concurrent readers, two threads can simultaneously:
- read `module.di == null`;
- construct independent debug-info objects for the same module;
- write back to `module.di` with plain unsynchronized stores.

The reproducer confirmed this interleaving and its consequence: one initialized `DebugInfo` can be overwritten and leaked, while only the surviving pointer is later released by `module.deinit` at `lib/std/debug/SelfInfo/Windows.zig:394`.

A related cache write exists in `getModuleName`, which assigns `module.name` under only the shared lock at `lib/std/debug/SelfInfo/Windows.zig:53` and `lib/std/debug/SelfInfo/Windows.zig:56`, confirming the Windows implementation mutates module caches from reader-only sections.

## Why This Is A Real Bug
This is not a theoretical lock-order concern; it is an actual unsynchronized read/write race on shared state reachable through public APIs. The code performs non-atomic lazy initialization while only a shared lock is held. Concurrent execution can corrupt cache semantics, leak initialized state, and invoke undefined behavior under the language memory model. The reproducer shows the path is practically reachable with two concurrent symbol lookups for the same uncached module.

## Fix Requirement
The lazy initialization of `module.di` must not occur while only a shared lock protects the module table. The cache write needs exclusive synchronization, either by:
- upgrading to an exclusive lock around initialization and publication; or
- protecting each module cache field with a dedicated once/mutex primitive.

Any fix should apply the same rule to other mutable lazy caches in the file, including `module.name`.

## Patch Rationale
The patch in `036-shared-lock-path-lazily-caches-debug-info.patch` serializes lazy cache initialization so `module.di` is published exactly once under exclusive synchronization instead of being written from a shared-lock path. This removes the data race, prevents duplicate initialization from being lost, and aligns cache mutation with the locking contract. The same rationale extends to other lazily written module fields that were previously mutated under reader-only locking.

## Residual Risk
None

## Patch
- `036-shared-lock-path-lazily-caches-debug-info.patch` updates the Windows `SelfInfo` path to stop mutating lazy module caches from shared-lock regions and to require exclusive synchronization for debug-info cache initialization and publication.