# Coverage mappings and source tables leak on deinit

## Classification
Resource lifecycle bug; severity: medium; confidence: certain.

## Affected Locations
- `lib/std/Build/Fuzz.zig:69`
- `lib/std/Build/Fuzz.zig:123`
- `lib/std/Build/Fuzz.zig:129`
- `lib/std/Build/WebServer.zig:188`
- `lib/compiler/build_runner.zig:27`

## Summary
`prepareTables` allocates persistent coverage state by `mmap`-ing coverage files and heap-allocating source metadata, then stores that state in `coverage_files`. `Fuzz.deinit` does not release any `coverage_files` entries, and `CoverageMap.deinit` was incomplete, so rebuild-driven teardown in the long-lived build runner leaked mappings and heap memory on each successful fuzz coverage initialization.

## Provenance
Verified from the provided reproducer and patch context against the affected Zig sources. Scanner reference: https://swival.dev

## Preconditions
`prepareTables` successfully populated at least one coverage map.

## Proof
`prepareTables` creates coverage state and stores it in `coverage_files`, including:
- mapped coverage file memory in `mapped_memory`
- heap allocations for `source_locations`
- heap allocations for `entry_points`

Before the patch:
- `Fuzz.deinit` did not iterate `coverage_files`
- `CoverageMap.deinit` only unmapped `mapped_memory` and deinitialized `coverage`
- `source_locations`, `entry_points`, and the `coverage_files` backing storage remained live

This is reachable in a persistent process:
- `Fuzz.start` runs inside the web fuzzing flow at `lib/std/Build/Fuzz.zig:129`
- the build runner is explicitly not always short-lived at `lib/compiler/build_runner.zig:27`
- `WebServer.startBuild` calls `fuzz.deinit()` before replacing the instance at `lib/std/Build/WebServer.zig:188`

Reproduction path:
1. Start web UI fuzzing.
2. Let `prepareTables` succeed once.
3. Trigger a rebuild.
4. `fuzz.deinit()` runs in the still-live process.
5. Previous coverage mappings and heap allocations are abandoned.

## Why This Is A Real Bug
This is not a shutdown-only leak. The affected process is intentionally long-lived across rebuilds, and the application explicitly deinitializes and recreates `Fuzz` instances during that lifetime. As a result, each rebuild after successful coverage preparation leaks VM mappings and heap allocations, causing cumulative resource growth and eventual instability in normal use.

## Fix Requirement
- Make `Fuzz.deinit` deinitialize every stored coverage map.
- Extend `CoverageMap.deinit` to free all owned allocations, including `source_locations` and `entry_points`.
- Deinitialize the `coverage_files` container itself after releasing its elements.

## Patch Rationale
The patch closes the lifecycle gap at both layers:
- element cleanup is completed in `CoverageMap.deinit`
- owner cleanup is added in `Fuzz.deinit`

That matches the allocation sites and ensures all resources created by `prepareTables` are released during rebuild teardown in the persistent build-runner process.

## Residual Risk
None

## Patch
Patched in `016-coverage-mappings-and-source-tables-leak-on-deinit.patch`, updating `lib/std/Build/Fuzz.zig` so `CoverageMap.deinit` frees `source_locations` and `entry_points`, and `Fuzz.deinit` walks and deinitializes `coverage_files` before releasing the container.