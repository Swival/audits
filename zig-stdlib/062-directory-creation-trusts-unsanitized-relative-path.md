# Directory traversal via unsanitized `sub_path`
## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/UpdateSourceFiles.zig:64`

## Summary
`UpdateSourceFiles` accepts caller-controlled `sub_path` values and uses them for directory creation and file writes without rejecting traversal segments. A path such as `../x/file` is treated as relative to the package root handle and causes `createDirPath` and subsequent file operations to target locations outside the intended package root.

## Provenance
- Verified from source and behavior in the local tree
- Swival Security Scanner: https://swival.dev

## Preconditions
- Caller controls `sub_path` passed to `addCopyFileToSource` or `addBytesToSource`

## Proof
- `addCopyFileToSource` and `addBytesToSource` store the provided `sub_path` unchanged in `UpdateSourceFiles.OutputSourceFile`
- In `make`, `fs.path.dirname(output_source_file.sub_path)` is passed directly to `b.build_root.handle.createDirPath(...)`
- Zig documents that `createDirPath` does not normalize away `..` on non-Windows in `lib/std/Io/Dir.zig:833`
- Existing filesystem tests show path-based file APIs accept traversal-containing relative paths such as `"./subdir/../file"` in `lib/std/fs/test.zig:2047`
- Therefore, supplying `sub_path = "../x/file"` makes directory creation and the later write/copy operate outside the package root, contradicting the API contract comment that the path is relative to the package root

## Why This Is A Real Bug
The vulnerable behavior is directly reachable from public update-source APIs with no sanitization barrier. The sink is not theoretical: the underlying directory and file APIs preserve `..` semantics rather than constraining access to descendants of the opened root. That makes writes escape the package root and mutate unintended filesystem locations.

## Fix Requirement
Reject any `sub_path` that is absolute or contains `.` or `..` path segments before calling `createDirPath` or performing file writes/copies.

## Patch Rationale
The patch adds explicit path validation in `UpdateSourceFiles` so only normalized descendant-relative paths are accepted. Blocking absolute paths and traversal segments at this boundary preserves the documented package-root constraint and prevents both directory creation and file output from escaping the intended root.

## Residual Risk
None

## Patch
- `062-directory-creation-trusts-unsanitized-relative-path.patch` adds `sub_path` validation in `lib/std/Build/Step/UpdateSourceFiles.zig` before directory creation and file operations
- The patch rejects absolute paths and `.` / `..` segments, failing closed at the API boundary where the untrusted path first becomes actionable