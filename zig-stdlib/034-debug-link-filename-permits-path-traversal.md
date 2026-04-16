# Debuglink filename traversal escapes intended search paths

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/debug/ElfFile.zig:145`

## Summary
- The `.gnu_debuglink` filename is read from attacker-controlled ELF contents and passed unchanged into `loadSeparateDebugFile` path construction.
- The code formats candidate paths like `"{s}/{s}"`, `"{s}/.debug/{s}"`, and `"{s}/{s}/{s}"` without validating that the debuglink value is a basename.
- A debuglink containing `/` and `..` can traverse out of the intended debug-file lookup directories and trigger unintended file opens, and can be adopted as the separate debug ELF if CRC and format checks also match.

## Provenance
- Verified from the reported code path and reproducer details in `lib/std/debug/ElfFile.zig`
- Scanner source: https://swival.dev

## Preconditions
- Attacker controls `.gnu_debuglink` contents in an inspected ELF

## Proof
- `load` reads `.gnu_debuglink` from `result.sections.get(.gnu_debuglink)` and extracts `debug_filename` with `std.mem.sliceTo(section.bytes, 0)`.
- That value is passed unchanged into `loadSeparateDebugFile` path formatting at `lib/std/debug/ElfFile.zig:145`.
- No basename validation is applied before attempting `openFile` on joined paths rooted at the executable directory and debug subdirectories.
- Because path separators and `..` are accepted, a crafted debuglink can escape the intended basename-only search area.
- The reproducer confirms practical reachability: the attacker can also choose the embedded CRC and supply a compatible escaped-to ELF, allowing successful adoption when checks at `lib/std/debug/ElfFile.zig:384` and `lib/std/debug/ElfFile.zig:403` pass.

## Why This Is A Real Bug
- `.gnu_debuglink` is intended to name a separate debug file, not an arbitrary relative path.
- Treating it as an unchecked path expands resolution beyond the documented search locations and lets attacker input steer file access outside those directories.
- Even when later CRC or ELF validation rejects the target, the unintended file-open attempts already occurred.
- The reproducer narrows the issue correctly: this is relative traversal via separators and `..`, not direct absolute-path injection from the debuglink alone.

## Fix Requirement
- Reject `.gnu_debuglink` values that are not plain basenames before constructing candidate paths.
- At minimum, reject names containing path separators or traversal components such as `..`.

## Patch Rationale
- The patch enforces basename-only semantics on the debuglink filename before any path formatting or file-open attempt.
- This preserves valid debuglink resolution while preventing traversal outside the intended search directories.
- The fix matches the proven issue scope and avoids overstating absolute-path injection.

## Residual Risk
- None

## Patch
- Patch file: `034-debug-link-filename-permits-path-traversal.patch`
- The patch adds input validation in `lib/std/debug/ElfFile.zig` to reject unsafe `.gnu_debuglink` names containing traversal or separator characters before calling `loadSeparateDebugFile`.