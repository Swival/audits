# Symlink extraction permits targets outside destination root

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/tar.zig:570`
- `lib/std/tar.zig:588`
- `lib/std/tar.zig:652`
- `lib/std/Io/Threaded.zig:4812`
- `lib/std/Io/Threaded.zig:4819`
- `lib/std/fs/test.zig:1313`

## Summary
Tar extraction validates `file.name` against path traversal, but does not validate symbolic-link targets taken from `header.linkName` or pax `linkpath`. Extraction then passes the unchecked target to `dir.symLink(...)`, allowing an archive to create symlinks that resolve outside the destination root. Because later extraction also follows existing symlink path components during directory creation and file open, a crafted archive can use an earlier symlink entry to redirect subsequent file extraction out of tree.

## Provenance
- Verified from the provided finding and reproducer against the Zig standard library extraction flow in `lib/std/tar.zig`
- Swival Security Scanner: https://swival.dev

## Preconditions
- Extracting a tar containing a symbolic link entry
- Attacker controls archive contents and entry ordering
- Target platform permits symlink creation/following during extraction

## Proof
- Tar link targets are sourced from `header.linkName` or pax `linkpath` into `file.link_name`, then used unchanged by extraction.
- `extract` sanitizes `file.name`, but not `link_name`, before calling symlink creation at `lib/std/tar.zig:570`.
- The symlink target is passed directly to `dir.symLink(io, link_name, file_name, .{})`, so absolute targets and `..` escapes are accepted.
- Existing tests explicitly permit a target like `"../../../file1"`, demonstrating intended acceptance of escaping symlink targets.
- Later archive entries can traverse those symlinked path components because path resolution defaults permit following links and do not require beneath-only resolution in `lib/std/Io/Threaded.zig:4812` and `lib/std/Io/Threaded.zig:4819`.
- `createDirAndFile` calls `dir.createDirPath` before retrying file creation at `lib/std/tar.zig:652`, and `createDirPath` is tested to operate through an existing valid symlink in `lib/std/fs/test.zig:1313`.
- Reproducer: a tar containing `pivot -> ../escape` followed by `pivot/payload.txt` causes `payload.txt` to be written outside the extraction root, contradicting the stated invariant at `lib/std/tar.zig:588`.

## Why This Is A Real Bug
The documented behavior says extraction should fail if a file would be extracted outside `dir`. That guarantee is bypassed by symlink entries because the archive can first install an out-of-root indirection and then place later files through it. This is a direct integrity violation during extraction on normal Unix-like systems and is not a theoretical edge case.

## Fix Requirement
Reject symlink targets that are absolute or that escape the extraction root via `..` before calling `dir.symLink(...)`. Extraction must enforce the same confinement policy for symlink targets that it already enforces for extracted entry paths.

## Patch Rationale
The patch in `037-symlink-extraction-permits-targets-outside-destination-root.patch` adds validation on symlink targets during tar extraction, preventing absolute targets and traversal escapes before symlink creation. This closes both the immediate out-of-root symlink planting issue and the demonstrated follow-on write-redirection primitive for later archive members, while preserving valid in-tree relative symlinks.

## Residual Risk
None

## Patch
- `037-symlink-extraction-permits-targets-outside-destination-root.patch` rejects unsafe symlink targets during extraction before `dir.symLink(...)` is invoked.
- The change aligns symlink-target handling with the existing extraction-root confinement intent already documented in `lib/std/tar.zig:588`.
- Valid relative symlink targets that remain within the destination root continue to extract normally.