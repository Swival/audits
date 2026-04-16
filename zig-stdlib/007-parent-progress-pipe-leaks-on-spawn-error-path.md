# Post-fork spawn error leaks child process and parent-owned pipe fds

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Io/Dispatch.zig:4120`
- `lib/std/Io/Dispatch.zig:4121`
- `lib/std/Io/Dispatch.zig:4143`
- `lib/std/Io/Dispatch.zig:4273`
- `lib/std/Io/Dispatch.zig:4274`
- `lib/std/Io/Dispatch.zig:4563`
- `lib/std/Io/Dispatch.zig:4591`
- `lib/std/Io/Dispatch.zig:4612`

## Summary
The originally reported progress-pipe leak is not the primary bug in the verified code path. The real reproduced issue is narrower and more severe in practice: when `spawn` reaches the post-fork parent path and the child reports setup failure before `exec`, the function returns that error without reaping the child and without closing parent-owned stdio/progress pipe fds that are only cleaned up on successful spawn lifecycle paths.

## Provenance
- Verified from local source inspection and reproduction against the referenced implementation
- Scanner provenance: https://swival.dev

## Preconditions
- `process.spawn` reaches a successful `fork`
- Child setup fails before `exec`
- Parent receives the failure through the error pipe
- Spawn configuration includes resources whose cleanup is deferred to successful-child lifecycle handling, such as `.pipe` stdio and optionally a progress node

## Proof
- Parent-side spawn reads child setup failure from the error pipe and returns it directly at `lib/std/Io/Dispatch.zig:4120`, `lib/std/Io/Dispatch.zig:4121`, and `lib/std/Io/Dispatch.zig:4143`
- Parent-owned pipe handles are installed earlier for spawned child management at `lib/std/Io/Dispatch.zig:4273` and `lib/std/Io/Dispatch.zig:4274`
- Cleanup for those handles occurs in `childCleanup`-driven success paths only, reached from `childWait` / `childKill` at `lib/std/Io/Dispatch.zig:4563`, `lib/std/Io/Dispatch.zig:4591`, and `lib/std/Io/Dispatch.zig:4612`
- On child-setup failure before `exec`, those success-only cleanup paths are never reached
- Reproducer conditions include invalid post-fork child setup such as invalid `cwd`, invalid uid/gid/pgid, or nonexistent executable; under these conditions the child exits after reporting failure, while the parent returns the error without `wait4()` and without local fd cleanup

## Why This Is A Real Bug
This is a real resource lifecycle failure because the parent has already created and retained process-associated resources, then exits the spawn path on a child-reported error without releasing them. The child becomes a zombie until externally reaped, and any parent-owned `.pipe` stdio fds remain open. This is observable, repeatable, and directly attributable to the missing cleanup on the post-fork error-return path.

## Fix Requirement
On the parent path that handles child-reported setup failure before successful spawn return, perform the same essential cleanup that successful lifecycle code eventually guarantees:
- reap the failed child
- close any parent-owned stdio/progress pipe fds already installed for that spawn attempt

## Patch Rationale
The patch in `007-parent-progress-pipe-leaks-on-spawn-error-path.patch` corrects the verified bug by adding cleanup on the post-fork parent error path instead of relying solely on success-path lifecycle handlers. This matches actual ownership at the time of failure and ensures resources are released even when `spawn` cannot return a live child handle.

## Residual Risk
None

## Patch
- Added parent-side cleanup on the post-fork child-setup-failure path in `lib/std/Io/Dispatch.zig`
- Ensured the failed child is reaped before returning the propagated spawn error
- Closed parent-owned pipe resources that were previously only reclaimed by successful `childCleanup` paths
- Captured in patch file `007-parent-progress-pipe-leaks-on-spawn-error-path.patch`