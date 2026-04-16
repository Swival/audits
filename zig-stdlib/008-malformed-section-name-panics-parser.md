# Malformed section name panics parser

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/coff.zig:371`
- `lib/std/coff.zig:476`
- `lib/std/coff.zig:1146`
- `lib/std/coff.zig:1154`

## Summary
- COFF section names are parsed from untrusted bytes in `SectionHeader.name`.
- Slash-prefixed names are treated as string-table offsets, but `lib/std/coff.zig:371` uses `std.fmt.parseInt(... ) catch unreachable`.
- A malformed name such as `"/abc"` triggers a panic instead of a recoverable parse failure.
- This yields a denial of service during normal section-name lookup.

## Provenance
- Verified from the provided finding and reproducer.
- Reproduced against the local code path described in the report.
- Scanner source: https://swival.dev

## Preconditions
- The parser processes a COFF section header whose name begins with `/` and whose suffix is not valid decimal digits.
- The code path resolves section names, such as via `getSectionByName(...)`.

## Proof
- `Coff.getSectionName` resolves names by calling `sect_hdr.getName()`, then falls through to offset-based lookup for slash-prefixed names.
- `SectionHeader.getNameOffset` parses the suffix with `std.fmt.parseInt(u32, self.name[1..len], 10) catch unreachable` at `lib/std/coff.zig:371`.
- With a crafted section name `"/abc"`, `parseInt` returns `error.InvalidCharacter`; the `catch unreachable` converts that into a panic.
- The reproduced stack reached the panic through normal section scanning and lookup, with top frames at `lib/std/coff.zig:476`, `lib/std/coff.zig:1146`, and `lib/std/coff.zig:1154`.
- The reproducer used a synthetic PE/COFF buffer with one malformed section name and a valid-looking string-table header; `parsed.getSectionByName(".debug_info")` aborted with `thread panic: attempt to unwrap error: InvalidCharacter`.

## Why This Is A Real Bug
- The input bytes are attacker-controlled COFF metadata, not an internal invariant.
- The panic is reachable through standard library parsing paths used by Windows debug-info loading.
- The failure is not recoverable by the caller because the panic occurs before an error is returned.
- This turns malformed input into process termination, which is a concrete denial-of-service condition.

## Fix Requirement
- Replace the `unreachable` on string-offset parsing failure with a normal error or null result.
- Propagate that failure through section-name resolution so malformed names are skipped or rejected without aborting.
- Preserve existing handling for valid slash-prefixed string-table references.

## Patch Rationale
- The patch makes malformed slash-prefixed section names fail closed via ordinary error propagation instead of panicking.
- This aligns parser behavior with untrusted-input expectations and keeps callers in control of failure handling.
- The change is narrowly scoped to section-name parsing and lookup, minimizing behavioral impact for valid COFF files.

## Residual Risk
- None

## Patch
- Patch file: `008-malformed-section-name-panics-parser.patch`
- The patch updates `lib/std/coff.zig` to remove the `catch unreachable` path for malformed numeric suffixes in slash-prefixed section names.
- It propagates the parse failure through section-name lookup so malformed headers no longer crash the parser during `getSectionByName(...)`.