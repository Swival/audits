# Compile error notes range is unchecked

## Classification
- Severity: Medium
- Type: Trust-boundary violation
- Confidence: certain

## Affected Locations
- `lib/std/zig/Zoir.zig:195`
- `lib/std/zig/Zoir.zig:247`
- `lib/std/zig/ErrorBundle.zig:624`
- `lib/std/zig/ErrorBundle.zig:626`
- `lib/std/zon/parse.zig:54`

## Summary
Malformed serialized ZOIR can set `CompileError.first_note` and `note_count` to an invalid range. The compiler then trusts those fields while iterating or slicing `zoir.error_notes`, causing an out-of-bounds trap in safety-checked builds and unchecked memory access in unsafe builds during diagnostic handling.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker-controlled serialized ZOIR with compile errors is loaded
- The forged cache entry is accepted as current, including matching stored source metadata so stale-cache checks do not reject it

## Proof
`CompileError.first_note` and `note_count` are deserialized from attacker-influenced `extern struct` data. The implementation trusts that range at multiple call sites:
- `lib/std/zig/Zoir.zig:195` returns a slice derived from `err.first_note` and `err.note_count` without validating the full range
- `lib/std/zig/ErrorBundle.zig:624` starts iterating from `err.first_note`
- `lib/std/zig/ErrorBundle.zig:626` indexes `zoir.error_notes[zoir_note_idx]` for `err.note_count` iterations
- `lib/std/zig/Zoir.zig:247` is also unchecked and reachable from `lib/std/zon/parse.zig:54`

If `first_note > zoir.error_notes.len` or `first_note + note_count > zoir.error_notes.len`, the compiler violates the array-bounds invariant. In safe builds this reliably traps and aborts compilation; in unsafe builds the same path becomes unchecked memory access.

## Why This Is A Real Bug
The note range crosses a serialization trust boundary and is consumed without validation. The reproduced path demonstrates attacker-controlled metadata can crash the compiler during error reporting, which is a real denial of service. The issue is not limited to the narrow `getNotes` helper; the same unchecked range is consumed directly in `ErrorBundle`, confirming exploitable invalid-state propagation from malformed loaded ZOIR.

## Fix Requirement
Validate `first_note` and `note_count` against `zoir.error_notes.len` before slicing or iterating. Invalid serialized note ranges must be rejected or safely clamped before any access occurs.

## Patch Rationale
The patch in `048-compile-error-notes-slice-trusts-serialized-range.patch` adds range validation at the trust boundary so malformed serialized note metadata cannot drive out-of-bounds access in downstream diagnostic consumers. This preserves normal behavior for valid ZOIR while converting invalid serialized state into a handled failure instead of a crash.

## Residual Risk
None

## Patch
- Patch file: `048-compile-error-notes-slice-trusts-serialized-range.patch`
- Intent: validate compile-error note ranges before any slice or indexed access of `zoir.error_notes`
- Result: malformed serialized ZOIR no longer crashes diagnostic processing through unchecked note-range consumption