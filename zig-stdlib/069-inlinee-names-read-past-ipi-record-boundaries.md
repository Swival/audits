# Inlinee names read past IPI record boundaries

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/Pdb.zig:466`

## Summary
- `findInlineeName` parses attacker-controlled IPI records and reads `.func_id` / `.mfunc_id` names with `std.mem.sliceTo` from `&func.name[0]`.
- The code trusts record structure but does not verify that a NUL terminator exists within the current `LfRecordPrefix.len` boundary.
- A malformed record therefore causes name scanning to continue into subsequent IPI records, returning a cross-record symbol name and violating record-local parsing.
- If no zero byte appears before the end of the allocated IPI buffer, the same logic can continue into out-of-bounds memory.

## Provenance
- Verified from the provided finding and reproducer against `lib/std/debug/Pdb.zig`.
- External scanner provenance: https://swival.dev
- Reproduced behavior confirms the parser consumes bytes past the current record when a terminator is absent in-bounds.

## Preconditions
- Attacker controls IPI stream `FuncId` / `MFuncId` record contents.

## Proof
- `parseIpiStream` stores raw IPI bytes in `self.ipi`, preserving attacker-provided record contents for later parsing.
- `findInlineeName` advances records using `LfRecordPrefix.len`, but for `.func_id` / `.mfunc_id` it casts the current record body to `LfFuncId` / `LfMFuncId` and then calls `std.mem.sliceTo([*:0]const u8, &func.name[0])`.
- No check constrains the scan to the current record payload, so a missing NUL makes `sliceTo` continue into later bytes.
- The reproducer demonstrates this directly: scanning `{ 'A', 'B', 'C', 0x05, 0x00, 0x99 }` as a sentinel-terminated string returns `{65, 66, 67, 5}`, proving the read crosses the intended boundary and stops only when a later zero byte is encountered.
- In practice, the next record header commonly contains such a zero byte in the high byte of little-endian `len`, so the returned inlinee name can include subsequent record bytes.

## Why This Is A Real Bug
- PDB record parsing is length-delimited; consuming bytes beyond `LfRecordPrefix.len` breaks the file format's isolation guarantees.
- The bug is triggerable with attacker-controlled IPI contents and does not depend on undefined record layout assumptions beyond omission of the in-record NUL.
- The reproduced outcome is an unintended cross-record disclosure in the parsed symbol name, which is already a concrete correctness and exposure issue.
- The same missing-boundary condition also creates a credible path to out-of-bounds read if no zero byte exists before the end of `self.ipi`.

## Fix Requirement
- Bound `.func_id` / `.mfunc_id` name parsing to the current record length.
- Reject records whose name field lacks a NUL terminator within the current record body.

## Patch Rationale
- The patch derives the remaining bytes available for the name from the current record's declared length instead of treating the field as unbounded sentinel memory.
- It searches for a terminator only within that bounded slice and returns an error if none is present.
- This preserves valid record handling while restoring record-local parsing and eliminating cross-record scanning.

## Residual Risk
- None

## Patch
- Patched in `069-inlinee-names-read-past-ipi-record-boundaries.patch`.
- The fix updates `lib/std/debug/Pdb.zig` to validate `.func_id` and `.mfunc_id` name fields against `LfRecordPrefix.len` before constructing the inlinee name.
- Records with missing in-bounds NUL termination are now rejected instead of being parsed across record boundaries.