# Output basename path traversal escapes cache root

## Classification
High severity validation gap
Confidence: certain

## Affected Locations
- `lib/std/Build/Step/Run.zig:739`
- `lib/std/Build/Step/Run.zig:789`
- `lib/std/Build/Step/Run.zig:796`
- `lib/std/Build/Step/Run.zig:803`
- `lib/std/Build/Step/Run.zig:811`
- `lib/std/Build/Step/Run.zig:820`

## Summary
`Run` accepted attacker-controlled output basenames with only an empty-string check, then joined them into cache-managed paths during `make`. Relative traversal segments such as `../` escape the intended `b.cache_root` subtree, causing directory creation, file writes, and generated-path propagation outside the cache.

## Provenance
Verified by reproduction and patching against the reported sink paths in `Run.make`; scanner reference: https://swival.dev

## Preconditions
Attacker controls `basename` passed to `addPrefixedOutputFileArg`, `addPrefixedOutputDirectoryArg`, `addPrefixedDepFileOutputArg`, `captureStdOut`, or `captureStdErr`.

## Proof
The reproduced issue showed:
- User-controlled `basename` values flow into `Output` and capture configuration with only emptiness validation.
- `Run.make` uses those values in cache path construction and file operations, including `b.pathJoin(&.{ output_dir_path, placeholder.output.basename })`, `createDirPath`, `writeFile`, and generated-path publication.
- Inputs like `../../outside`, `../../dir`, `../../dep.d`, and capture basenames such as `../../pwn` cause writes and reported generated paths to land outside `b.cache_root`.
- Absolute-path overwrite was not reproduced because path join here is concatenative; the confirmed bug is traversal through relative `..` components.

## Why This Is A Real Bug
This is a direct path traversal in build-system-controlled filesystem writes. A malicious or untrusted build script can make `Run` pre-create directories, emit files, or advertise generated artifacts outside the cache boundary that callers expect to contain all generated output. The behavior is reachable through documented output/capture APIs and does not depend on undefined behavior.

## Fix Requirement
Reject unsafe basenames before storing them in `Output` or capture state. Validation must deny traversal-containing values and other non-local path forms so later cache joins cannot escape the intended subtree.

## Patch Rationale
The patch centralizes basename validation in `lib/std/Build/Step/Run.zig` and applies it at each API entry point that accepts output or capture basenames. This fails fast at configuration time, prevents unsafe values from reaching `make`, and preserves existing cache-path logic for valid local names.

## Residual Risk
None

## Patch
`011-output-basename-can-escape-cache-root.patch`