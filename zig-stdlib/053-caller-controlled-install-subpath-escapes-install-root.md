# Caller-controlled install subpath escapes install root

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/InstallArtifact.zig:115`
- `lib/std/Build/Step.zig:525`
- `lib/std/Io/Dir.zig:715`

## Summary
`Options.dest_sub_path` is caller-controlled, stored without validation, and later used to compute the install destination. A value containing parent traversal such as `../../outside` escapes the intended install root and causes the artifact to be written outside the selected install directory.

## Provenance
- Verified from source and reproducer details provided by the user
- Scanner: https://swival.dev

## Preconditions
- Caller can set `Options.dest_sub_path`
- `dest_dir` is non-null

## Proof
- In `lib/std/Build/Step/InstallArtifact.zig:115`, `dest_sub_path` is accepted from caller input and retained for later use.
- In `make`, that value is passed into install path computation via `b.getInstallPath(dest_dir, install_artifact.dest_sub_path)` with no traversal rejection.
- The resulting path is written directly by `Step.installFile` in `lib/std/Build/Step.zig:525`.
- The file write path is materialized by `Io.Dir.updateFile(..., .cwd(), dest_path, ...)`, which creates parent directories as needed through `createFileAtomic(... .make_path = true ...)` in `lib/std/Io/Dir.zig:715`.
- There is no containment check after resolution, so `../../outside` from a base like `zig-out/bin` resolves outside `zig-out`.

## Why This Is A Real Bug
This is a direct path traversal in a build-time file write primitive. The caller-controlled subpath influences the final filesystem destination, and the write path creation logic honors the escaped path. The issue is practically reachable through `std.Build.addInstallArtifact(..., .{ .dest_sub_path = "../../outside" })`, allowing artifact installation outside the configured install root.

## Fix Requirement
Reject `dest_sub_path` values that contain parent-directory traversal before storing or using them. Absolute paths should also remain disallowed.

## Patch Rationale
The patch adds early validation in `InstallArtifact` so unsafe `dest_sub_path` values are rejected before install path computation. This is the narrowest fix at the trust boundary and prevents downstream file-write code from receiving escaping paths.

## Residual Risk
None

## Patch
`053-caller-controlled-install-subpath-escapes-install-root.patch`