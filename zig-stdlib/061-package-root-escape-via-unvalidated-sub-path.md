# Package-root escape via unvalidated sub_path

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/UpdateSourceFiles.zig:71`

## Summary
`Build.Step.UpdateSourceFiles` accepted caller-controlled `sub_path` values without validating that they were normalized, relative, and contained within the package root. During `make`, that unchecked path was passed into directory creation and file write/update operations rooted at `b.build_root.handle`, enabling `..` traversal and, on Windows, absolute-path escape from the intended package-root destination.

## Provenance
- Verified from the supplied reproducer and code-path analysis
- Reproduced finding: package-root escape via unvalidated `sub_path`
- Reference: https://swival.dev

## Preconditions
- Caller can supply `sub_path` to update-source APIs

## Proof
`addCopyFileToSource` and `addBytesToSource` stored the provided `sub_path` unchanged in `output_source_files`. In `make`, the same value was used directly with filesystem operations against `b.build_root.handle`.

The reproduced path showed:
- `writeFile` consumes `.sub_path` without containment checks
- `createDirPath` operates on the unchecked path
- `Io.Dir.updateFile` forwards the destination into atomic file creation and rename flows
- `..` segments traverse outside the package root on all platforms
- Absolute paths bypass the root directory on Windows, because absolute destinations clear the rooted handle and operate on the absolute location instead

This makes writes outside the intended package root reachable whenever attacker-controlled `sub_path` reaches these APIs.

## Why This Is A Real Bug
The vulnerable API is explicitly meant to update source files relative to the package/build root. Accepting traversal or absolute-style destinations violates that contract and changes the security boundary from “package-local update” to “arbitrary filesystem write reachable by caller input.” The reproducer traces the unchecked value from API input to concrete write primitives, so this is not theoretical or dead code.

## Fix Requirement
Reject `sub_path` values unless they are normalized, relative, and non-escaping before they are stored or used for filesystem writes.

## Patch Rationale
The patch adds validation in `lib/std/Build/Step/UpdateSourceFiles.zig` so update-source entries only accept safe package-root-relative paths. By failing early on non-normalized, traversal, or absolute-style inputs, it preserves the intended API contract and blocks both `..` escapes and Windows absolute-path bypasses before any filesystem side effect occurs.

## Residual Risk
None

## Patch
- `061-package-root-escape-via-unvalidated-sub-path.patch` validates `sub_path` before enqueueing or writing update-source outputs
- The change enforces package-root-relative destinations and rejects traversal or absolute-path forms that could escape containment