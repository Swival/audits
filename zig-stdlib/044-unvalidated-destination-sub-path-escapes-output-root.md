# Unvalidated destination `sub_path` escapes output root

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/WriteFile.zig:289`

## Summary
`std.Build.Step.WriteFile` accepts caller-controlled destination `sub_path` values and later uses them for file and directory writes without enforcing containment under the step output root. Traversal segments and absolute paths therefore escape the intended generated-output directory and can create or overwrite files elsewhere on the filesystem.

## Provenance
- Verified from the provided reproducer and source review
- Scanner source: https://swival.dev

## Preconditions
- Attacker controls `sub_path` for an added file or directory

## Proof
- `add`, `addCopyFile`, and `addCopyDirectory` store caller-provided `sub_path` unchanged into `File.sub_path` and `Directory.sub_path`.
- In `operate`, file destinations are passed into `cache_dir.writeFile` and `Io.Dir.updateFile`, and directory destinations are joined into `dest_path`, with no validation that the resulting path remains under `root_path`.
- The reproducer confirms the underlying path handling normalizes `..` and accepts rooted or absolute forms instead of rejecting them, making payloads such as `../../outside`, `/tmp/pwned`, and `C:\\temp\\pwned` effective.
- Because all `make` modes reach `operate`, the issue is reachable wherever untrusted input can influence `sub_path`.

## Why This Is A Real Bug
This is a direct write-path traversal in build output handling. The implementation treats `sub_path` as trusted relative output metadata, but filesystem resolution semantics allow attacker-supplied traversal or absolute paths to target locations outside the designated output root. That breaks the step's containment boundary and enables arbitrary file or directory creation or overwrite with build-process privileges.

## Fix Requirement
Reject any `sub_path` that is absolute, rooted, or contains escaping traversal before it is stored or used for output writes.

## Patch Rationale
The patch adds destination-path validation in `lib/std/Build/Step/WriteFile.zig` so only safe relative paths are accepted for `sub_path`. This closes the bug at the boundary where untrusted values enter the step, preventing all downstream write paths from resolving outside the output root across file-add, file-copy, and directory-copy flows.

## Residual Risk
None

## Patch
- Patch file: `044-unvalidated-destination-sub-path-escapes-output-root.patch`
- Patched component: `lib/std/Build/Step/WriteFile.zig`
- Security effect: blocks absolute and escaping destination paths before any filesystem write occurs