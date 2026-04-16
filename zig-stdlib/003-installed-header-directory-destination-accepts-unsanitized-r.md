# Installed header directory destination path traversal rejected

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/Compile.zig:424`
- `lib/std/Build/Step/InstallArtifact.zig:183`
- `lib/std/Build/Module.zig:184`
- `lib/std/Build.zig:1925`

## Summary
`installHeadersDirectory` accepted caller-controlled `dest_rel_path` without validation and preserved it into header installation records. That value was later reused for include-tree population and install-time path construction, allowing relative traversal segments such as `../escaped` to escape the intended header destination and write into sibling locations.

## Provenance
- Verified from the reported code path and local reproduction
- Scanner reference: https://swival.dev

## Preconditions
- Build script controls `dest_rel_path` for `installHeadersDirectory`

## Proof
- `installHeadersDirectory` stored `dest_rel_path` unchanged in `HeaderInstallation.Directory.dest_rel_path` at `lib/std/Build/Step/Compile.zig:424`.
- `getEmittedIncludeTree` replayed directory header installs into `addHeaderInstallationToIncludeTree`, which forwarded `dir.dest_rel_path` directly into `wf.addCopyDirectory(...)`.
- No normalization or traversal rejection was present on that path before include-tree copy scheduling.
- Install-time handling was also reachable: `lib/std/Build/Step/InstallArtifact.zig:183` passed `dir.dest_rel_path` into `b.getInstallPath(...)`.
- `getInstallPath` in `lib/std/Build.zig:1925` rejected absolute paths but still resolved relative traversal, so `../escaped` escaped `h_dir`.
- Reproduction used `installHeadersDirectory(..., "../escaped", ...)` with `addInstallArtifact(..., .h_dir = "out/include")`; the build succeeded and placed `poc.h` at `zig-out/out/escaped/poc.h` instead of under `zig-out/out/include`.

## Why This Is A Real Bug
The observed behavior is an actual filesystem write escape from the configured header directory. Even though dependent modules add `-I` only for the include-tree root and that limits reliable header poisoning, the bug still permits clobbering paths outside the intended install/include subtree. That violates destination confinement and is directly reachable from build-script input.

## Fix Requirement
Reject `dest_rel_path` values that are absolute or contain traversal semantics before storing or consuming them for header directory installation.

## Patch Rationale
The patch adds validation at the `installHeadersDirectory` entry point so invalid destinations are rejected once, before they are recorded in `HeaderInstallation.Directory` and before either include-tree emission or install-path generation can reuse them. This is the narrowest fix because it blocks both affected sinks with one invariant: header directory destinations must remain confined relative paths.

## Residual Risk
None

## Patch
- Patched in `003-installed-header-directory-destination-accepts-unsanitized-r.patch`
- The patch enforces validation on `dest_rel_path` for header directory installs, rejecting absolute and traversal-containing values before they enter the build graph