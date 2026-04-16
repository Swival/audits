# Unchecked `high_pc` offset can wrap function ranges

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/debug/Dwarf.zig:391`
- `lib/std/debug/Dwarf.zig:661`
- `lib/std/debug/Dwarf.zig:847`

## Summary
Unchecked addition of attacker-controlled DWARF `.udata` `DW_AT.high_pc` offsets to `DW_AT.low_pc` allows `pc_end` to overflow. In safety-enabled builds this aborts on integer overflow; in `ReleaseFast` it wraps and stores corrupted ranges used by symbol and compile-unit lookups.

## Provenance
- Verified from the reported finding and reproduced against the affected code paths.
- Reference: Swival Security Scanner at https://swival.dev

## Preconditions
- Attacker controls parsed DWARF `DW_AT.high_pc` offset data.

## Proof
- `scanAllFunctions` reads `DW_AT.low_pc`, then for `.udata` `DW_AT.high_pc` computes `pc_end = low_pc + offset` without overflow validation at `lib/std/debug/Dwarf.zig:391`.
- The same unchecked pattern is present in later compile-unit/range handling paths at `lib/std/debug/Dwarf.zig:661` and `lib/std/debug/Dwarf.zig:847`.
- Reproduction confirmed attacker-controlled DWARF reaches these range-table writes.
- A standalone PoC confirmed Zig overflow behavior for `u64 + u64`: safety-enabled builds abort with `integer overflow`, while `ReleaseFast` wraps.
- Therefore malformed DWARF causes either process abort or wrapped end addresses instead of a clean `InvalidDebugInfo` rejection.

## Why This Is A Real Bug
The parser consumes untrusted debug metadata and uses the computed end addresses to populate `PcRange` and related lookup tables. Unchecked arithmetic on those values is externally reachable, leads to incorrect state in optimized builds, and causes abnormal termination in safety-enabled builds. Both outcomes violate expected input validation behavior.

## Fix Requirement
Use checked addition for every `low_pc + offset` computation derived from `.udata` `DW_AT.high_pc`, and return `error.InvalidDebugInfo` on overflow.

## Patch Rationale
The patch replaces unchecked additions with checked arithmetic at each affected site in `lib/std/debug/Dwarf.zig`, ensuring malformed DWARF is rejected uniformly across build modes rather than aborting or wrapping. This preserves existing semantics for valid inputs and converts overflow into the parser's established validation error.

## Residual Risk
None

## Patch
- Patch file: `071-unchecked-high-pc-offset-can-wrap-function-ranges.patch`
- Change: replace unchecked `low_pc + offset` with checked addition and map overflow to `error.InvalidDebugInfo` in `lib/std/debug/Dwarf.zig:391`, `lib/std/debug/Dwarf.zig:661`, and `lib/std/debug/Dwarf.zig:847`