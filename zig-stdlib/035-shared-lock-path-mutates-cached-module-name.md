# Shared lock path mutates cached module name

## Classification
- Type: race condition
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/SelfInfo/Windows.zig:75`
- `lib/std/debug/SelfInfo/Windows.zig:55`
- `lib/std/debug/SelfInfo/Windows.zig:636`
- `lib/std/debug/SelfInfo/Windows.zig:648`
- `lib/std/debug/SelfInfo/Windows.zig:660`
- `lib/std/debug/SelfInfo/Windows.zig:675`
- `lib/std/debug/SelfInfo/Windows.zig:684`

## Summary
`getModuleName` executes under `si.lock.lockShared()` but reaches code that mutates shared process-global `SelfInfo` state. On an uncached module, concurrent callers can both observe `module.name == null` and write `module.name` without exclusive synchronization. The same shared-lock path also reaches `findModule`, which mutates `si.modules`, `si.notification_cookie`, and `si.ntdll_handle`. This creates a real, triggerable race in normal debug and stack-printing flows.

## Provenance
- Verified finding reproduced from runtime code inspection and call-path analysis
- Swival Security Scanner: https://swival.dev
- Reproducer result: reproduced

## Preconditions
- Two or more threads call `getModuleName` on the process-global `SelfInfo`
- At least one call targets a module whose cached metadata is not yet initialized
- Normal debug or stack-printing paths invoke `getSelfDebugInfo` and then `getModuleName`

## Proof
Under `si.lock.lockShared()`, `getModuleName` calls `findModule` and then conditionally initializes `module.name`.

Relevant behavior:
- `getSelfDebugInfo` returns process-global static `SelfInfo` at `lib/std/debug.zig:315`
- `getModuleName` is reachable from standard debug paths at `lib/std/debug.zig:733` and `lib/std/debug.zig:1265`
- `getModuleName` acquires a shared lock and enters mutation-capable logic at `lib/std/debug/SelfInfo/Windows.zig:75`
- Before `module.name` initialization, `findModule` can mutate:
  - `si.modules` at `lib/std/debug/SelfInfo/Windows.zig:636`, `lib/std/debug/SelfInfo/Windows.zig:675`, `lib/std/debug/SelfInfo/Windows.zig:684`
  - `si.notification_cookie` at `lib/std/debug/SelfInfo/Windows.zig:648`
  - `si.ntdll_handle` at `lib/std/debug/SelfInfo/Windows.zig:660`

Race sequence:
```text
T1: lockShared()
T1: findModule() returns module with name == null
T2: lockShared()
T2: findModule() returns same module with name == null
T1: allocate UTF-8 name
T2: allocate UTF-8 name
T1: module.name = ptr1
T2: module.name = ptr2
```

This permits unsynchronized concurrent writes to the same field and can leak the overwritten allocation. Because the same path also mutates container and handle state under only a shared lock, the bug is broader than a benign cache fill and is directly reachable in practice.

## Why This Is A Real Bug
A shared/read lock only preserves correctness if guarded operations are read-only. Here, code executed while holding `lockShared()` performs writes to shared state. That violates the lock contract, enables data races, and can corrupt cache invariants or lose allocations. The affected object is process-global and used by ordinary debugging paths, so concurrent access is realistic rather than hypothetical.

## Fix Requirement
The shared-lock path must not mutate `SelfInfo` state. Initialization of `module.name` and any `findModule` side effects must occur only under exclusive locking, or via a separate one-time initialization mechanism with equivalent synchronization guarantees.

## Patch Rationale
The patch in `035-shared-lock-path-mutates-cached-module-name.patch` moves uncached-module initialization off the shared-lock path and requires exclusive synchronization before writing cached module metadata or other `SelfInfo` fields. This restores the read-only invariant for shared locking and prevents concurrent writers from racing on `module.name` or related mutable state.

## Residual Risk
None

## Patch
- `035-shared-lock-path-mutates-cached-module-name.patch` enforces exclusive synchronization for module-cache initialization and removes mutation from the shared-lock path in `lib/std/debug/SelfInfo/Windows.zig`.