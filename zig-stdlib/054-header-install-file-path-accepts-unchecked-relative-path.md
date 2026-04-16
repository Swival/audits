# Header install path traversal in header file installs

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/InstallArtifact.zig:147`

## Summary
`InstallArtifact.make()` accepts `artifact.installed_headers.items[].file.dest_rel_path` without validating that it is a normalized relative path. That value is passed into `b.getInstallPath(h_dir, file.dest_rel_path)` and then written by `step.installFile(...)`. On POSIX, path resolution collapses `..`, so attacker-controlled header destinations can escape the intended header install directory and, with enough traversal, escape the install prefix entirely.

## Provenance
- Verified from source and reproduction
- Scanner: https://swival.dev

## Preconditions
- A build script controls the installed header destination path

## Proof
- Input reaches the sink through `artifact.installed_headers.items[].file.dest_rel_path`.
- In `lib/std/Build/Step/InstallArtifact.zig:147`, `make()` computes the destination with `b.getInstallPath(h_dir, file.dest_rel_path)` and then installs via `step.installFile(file.source, full_dest_path)`.
- No rejection of traversal or absolute-style path segments occurs before install path computation in this branch.
- On POSIX, `lib/std/fs/path.zig:1116` and `lib/std/fs/path.zig:1126` show resolution collapses `..` against the absolute base.
- `lib/std/Build/Step.zig:525` writes to the resolved destination with `Io.Dir.updateFile(..., .cwd(), dest_path, ...)`.
- Reproduced with a minimal `build.zig`:
  - `lib.installHeader(..., "../escaped.h")` created `<prefix>/escaped.h`
  - `lib.installHeader(..., "../../outside.h")` created `<workdir>/outside.h`

## Why This Is A Real Bug
This is not a harmless path-shape issue. The unchecked destination is used for an actual filesystem write, and the underlying path resolver removes traversal segments instead of preserving them. As a result, a build script can redirect header installation outside `include/` and even outside the configured install prefix. That is an arbitrary file write primitive reachable through normal header installation APIs on POSIX.

## Fix Requirement
Reject header destination paths unless they are normalized relative paths with no traversal segments and no absolute-style forms before calling `getInstallPath`.

## Patch Rationale
The patch in `054-header-install-file-path-accepts-unchecked-relative-path.patch` adds validation at the header file install call site so only safe relative destinations are accepted. Fixing this before `getInstallPath` is the correct boundary because it prevents traversal from entering install-path construction and preserves expected install-tree containment semantics for header artifacts.

## Residual Risk
None

## Patch
- `054-header-install-file-path-accepts-unchecked-relative-path.patch` rejects unsafe `dest_rel_path` values for header file installs before destination path construction, preventing `..` traversal and absolute-style escapes from reaching `getInstallPath` and `installFile`.