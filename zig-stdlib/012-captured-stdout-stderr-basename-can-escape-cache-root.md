# Captured stdio basename escapes step cache directory

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/Run.zig:1088`

## Summary
`CapturedStdIo.Options.basename` is stored and later joined into the cache output path without enforcing that it is a single path component. An attacker-controlled value containing traversal such as `../` causes captured stdout or stderr files to be written outside the intended `o/<digest>` step subdirectory and elsewhere under the cache root.

## Provenance
- Verified from the provided reproducer and code path analysis
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker controls `captureStdOut` or `captureStdErr` basename input

## Proof
`CapturedStdIo.Options.basename` flows through `captureStdOut` and `captureStdErr` into `captured.output.basename` unchanged. In `runCommand`, the code builds `sub_path` with `b.pathJoin(&.{ output_dir_path, captured.output.basename })` and uses that path with both `b.cache_root.handle.createDirPath` and `writeFile`. No validation rejects separators or traversal components before this join.

The reproducer confirms `createDirPath` does not reject `..` and that a basename such as `../pwned/stdout.txt` resolves from `<cache_root>/o/<digest>/../pwned/stdout.txt` to `<cache_root>/o/pwned/stdout.txt`. The same escaped path is then exposed through generated file publication at `lib/std/Build/Step/Run.zig:1160` and `lib/std/Build/Step/Run.zig:1166`.

## Why This Is A Real Bug
This breaks the confinement invariant for captured stdio artifacts. Any build script that passes attacker-influenced text into these APIs can create or overwrite files outside the per-step cache directory, still within the cache root, with no further mitigation on the write path. The behavior is reachable in normal API use and directly contradicts the expected meaning of a `basename`.

## Fix Requirement
Reject invalid capture names before storing or using them. The accepted value must be exactly one path component with no directory separators, traversal elements, or equivalent platform-specific path forms.

## Patch Rationale
The patch enforces basename-only validation at the capture API boundary in `lib/std/Build/Step/Run.zig`, so unsafe names are rejected before they can reach path construction, directory creation, generated-file publication, or file writes. This matches the API contract implied by the field name and preserves confinement to the step cache directory.

## Residual Risk
None

## Patch
- `012-captured-stdout-stderr-basename-can-escape-cache-root.patch`