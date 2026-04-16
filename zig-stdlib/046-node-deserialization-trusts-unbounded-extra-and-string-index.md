# Node deserialization trusts unbounded extra and string indexes

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/zig/Zoir.zig:93`
- `lib/std/zig/Zoir.zig:137`
- `lib/std/zig/Zoir.zig:230`
- `lib/std/zig/Zoir.zig:247`
- `lib/std/zig/ErrorBundle.zig:611`
- `lib/std/zig/ErrorBundle.zig:641`

## Summary
Deserialization consumed attacker-controlled `Node.Repr.data`, `extra`, limb ranges, and string indexes as trusted slice bounds and null-terminated string offsets. Malformed serialized ZOIR or cached compile-error data could therefore trigger bounds traps or optional unwrap failure during compiler input processing, causing deterministic denial of service.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner: [Swival Security Scanner](https://swival.dev)
- Patch artifact: `046-node-deserialization-trusts-unbounded-extra-and-string-index.patch`

## Preconditions
- Attacker controls serialized ZOIR header/body contents

## Proof
`Node.Index.get` in `lib/std/zig/Zoir.zig:93` used serialized values directly in slice expressions such as:
```zig
zoir.extra[repr.data..][0..N]
zoir.limbs[limbs_idx..][0..limb_count]
zoir.string_bytes[start..][0..len]
```
These operations had no preceding range validation.

`string_literal_null` also trusted serialized string offsets. `lib/std/zig/Zoir.zig:137` passed `@enumFromInt(repr.data)` into `NullTerminatedString.get`, and `lib/std/zig/Zoir.zig:230` then executed:
```zig
zoir.string_bytes[@intFromEnum(nts)..]
std.mem.indexOfScalar(u8, bytes, 0).?
```
An out-of-range offset caused a slice bounds trap; an in-range but unterminated string caused `.?` to fail.

Compile-error note/message decoding had the same issue. `lib/std/zig/Zoir.zig:247` trusted `first_note` and `note_count`, while `lib/std/zig/ErrorBundle.zig:611` and `lib/std/zig/ErrorBundle.zig:641` called `err.msg.get(zoir)` and `note.msg.get(zoir)` on cached data, so poisoned cache content could crash before semantic lowering completed.

## Why This Is A Real Bug
The failing operations occur on untrusted serialized input before validation. In Zig, these unchecked slice bounds and optional unwraps fail fast under runtime safety, which still makes malformed inputs able to terminate compilation deterministically. That is a real denial-of-service condition for any workflow that consumes attacker-influenced cache or serialized IR data.

## Fix Requirement
Validate all serialized offsets, counts, and string indexes before slicing backing arrays or resolving null-terminated strings. Reject malformed input through structured deserialization error handling instead of relying on runtime traps.

## Patch Rationale
The patch adds explicit bounds checks around `extra`, limb, note, and string access paths in `lib/std/zig/Zoir.zig` and the compile-error message resolution flow, ensuring deserialization fails closed on invalid indexes. This preserves existing behavior for valid inputs while converting crash-on-bad-data cases into handled parse rejection.

## Residual Risk
None

## Patch
- `046-node-deserialization-trusts-unbounded-extra-and-string-index.patch`