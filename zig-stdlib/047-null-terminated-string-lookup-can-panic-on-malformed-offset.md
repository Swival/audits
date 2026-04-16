# Null-terminated string lookup panics on malformed offset

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/zig/Zoir.zig:112`
- `lib/std/zig/Zoir.zig:118`
- `lib/std/zig/Zoir.zig:180`

## Summary
`Node.Index.get` forwards attacker-controlled serialized offsets into `NullTerminatedString.get` for `.enum_literal` and `.string_literal_null`. `NullTerminatedString.get` slices from that offset and force-unwraps the result of `findScalar(..., 0)`. If the offset is in bounds but the remaining suffix has no NUL terminator, the unwrap traps and crashes the process.

## Provenance
- Verified by reproduction against the affected code paths
- Reference: Swival Security Scanner, https://swival.dev

## Preconditions
- Attacker controls serialized `NullTerminatedString` offset
- The chosen offset is within `zoir.string_bytes` but no trailing `0` exists after it

## Proof
`Node.Index.get` passes `repr.data` into `NullTerminatedString.get` for `.enum_literal` and `.string_literal_null` at `lib/std/zig/Zoir.zig:112` and `lib/std/zig/Zoir.zig:118`. `NullTerminatedString.get` then executes logic equivalent to:
```zig
const bytes = zoir.string_bytes[@intFromEnum(nts)..];
const len = std.mem.indexOfScalar(u8, bytes, 0).?;
```
At `lib/std/zig/Zoir.zig:180`, the optional unwrap panics when `indexOfScalar`/`findScalar` returns `null`. This is reachable from malformed serialized ZOIR during semantic lowering, including paths in `src/Sema/LowerZon.zig:74`, `src/Sema/LowerZon.zig:104`, `src/Sema/LowerZon.zig:177`, `src/Sema/LowerZon.zig:644`, `src/Sema/LowerZon.zig:678`, `src/Sema/LowerZon.zig:921`, and `src/Sema/LowerZon.zig:938`.

## Why This Is A Real Bug
This is not a theoretical invariant violation. The serialized offset is treated as trusted, but malformed cached or on-disk ZOIR can satisfy the slice bounds check while still omitting any later NUL byte. In that state, decoding deterministically aborts the compiler with a panic, yielding denial of service from attacker-controlled serialized input.

## Fix Requirement
Reject or safely handle `NullTerminatedString` offsets unless both conditions hold: the offset is in range and the suffix beginning at that offset contains a terminating NUL. Construction and decode paths must not rely on unchecked optional unwraps for serialized data.

## Patch Rationale
The patch adds validation around `NullTerminatedString` decoding so malformed offsets without a trailing terminator are treated as invalid serialized input instead of triggering a panic. This converts a process-aborting trust failure into explicit input handling at the boundary where untrusted serialized data is decoded.

## Residual Risk
None

## Patch
- Patched in `047-null-terminated-string-lookup-can-panic-on-malformed-offset.patch`
- The patch hardens `lib/std/zig/Zoir.zig` to validate null-terminated string offsets before dereferencing or unwrapping the terminator lookup, eliminating the malformed-offset panic path.