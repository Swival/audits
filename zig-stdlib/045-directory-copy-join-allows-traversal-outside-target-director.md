# Directory copy join allows traversal outside target directory

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/Build/Step/WriteFile.zig:326`

## Summary
`addCopyDirectory` accepts a caller-controlled `sub_path` and stores it unchanged. During `operate`, that value becomes the destination base for each copied entry, and the resulting joined path is passed directly to directory creation and file update routines. Because neither absolute paths nor traversing components are rejected, writes can escape the generated output root.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Reproduced against committed code
- Scanner reference: https://swival.dev

## Preconditions
- Attacker controls `addCopyDirectory` `sub_path`

## Proof
- `addCopyDirectory` stores caller input in `Directory.sub_path`.
- In `operate`, `dest_dirname = dir.sub_path`.
- For each walked source entry, `dest_path = b.pathJoin(&.{ dest_dirname, entry.path })`.
- `dest_path` is then used by `cache_dir.createDirPath(...)` and `Io.Dir.updateFile(...)` without normalization or containment checks.
- Runtime reproduction confirmed:
  - `sub_path = "../escaped"` created `.zig-cache/o/escaped/hello.txt`, outside the intended hashed output directory.
  - Absolute `sub_path` created `/tmp/zig-writefile-abs-target.../payload/hello.txt` directly outside the build cache.
- The standard library documentation for `createDirPath` also notes `..` is passed through to `mkdirat` on non-Windows, so the escape is not mitigated downstream.

## Why This Is A Real Bug
The intended invariant is that `WriteFile` outputs remain rooted under the generated directory selected by `root_path`. This code violates that invariant by allowing destination path selection to be influenced by untrusted path syntax. A caller can therefore create or overwrite files and directories at locations reachable by the build process, which is a direct filesystem integrity impact.

## Fix Requirement
Reject unsafe `sub_path` values before storing or using them for destination path construction. At minimum, reject absolute paths and any path containing traversal components such as `..`.

## Patch Rationale
The patch enforces destination-root containment at the trust boundary for `addCopyDirectory` input, preventing both relative traversal and absolute-path escape before any filesystem operation occurs. This is the narrowest fix that preserves existing copy behavior for valid relative subpaths.

## Residual Risk
None

## Patch
- Patched in `045-directory-copy-join-allows-traversal-outside-target-director.patch`
- The fix adds validation in `lib/std/Build/Step/WriteFile.zig` to reject absolute or traversing `sub_path` values before they can influence `pathJoin`, `createDirPath`, or `updateFile`