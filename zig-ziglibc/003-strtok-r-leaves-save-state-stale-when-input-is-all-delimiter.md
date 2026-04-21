# strtok_r stale save state on delimiter-only input

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/c/string.zig:155`

## Summary
`strtok_r` returns `null` for an input string made entirely of delimiters, but it exits before updating `state.*`. If `state` still holds a pointer from an earlier parse, later continuation calls can resume from that stale buffer instead of reflecting that the new parse is complete.

## Provenance
- Verified from the supplied reproduction and source analysis
- Scanner source: https://swival.dev

## Preconditions
- `strtok_r` is called on a delimiter-only string
- `state` is non-null and already contains a pointer from a prior tokenization sequence

## Proof
- In `lib/c/string.zig:155`, `strtok_r` derives `str_bytes` from `maybe_str` or `state.*`.
- It computes `tok_start = findNone(str_bytes, values_bytes) orelse return null;`.
- For an all-delimiter string, `findNone` returns `null`, so control returns immediately.
- Because that return happens before any write to `state.*`, the prior save pointer remains unchanged.
- Reproduced flow:
  - tokenize `"a,b"`; after first token, `state` points to `"b"`
  - call `strtok_r(",,,", ",", &state)`; it returns `NULL` and leaves `state` at `"b"`
  - call `strtok_r(NULL, ",", &state)`; it incorrectly returns `"b"` from the previous buffer

## Why This Is A Real Bug
The tokenizer contract requires the save pointer to reflect consumed input state for the current parse. Returning `NULL` for a new delimiter-only string should mark parsing complete for that string. Leaving `state.*` unchanged violates that invariant and allows cross-buffer continuation into unrelated prior input, causing incorrect parsing through the exported `strtok_r` entrypoint.

## Fix Requirement
Before returning `null` when no non-delimiter byte exists, set `state.*` to the end of the current string so the save state reflects completed consumption of the new input.

## Patch Rationale
Update the early-return path in `strtok_r` so the no-token case stores an end-of-string pointer into `state.*` before returning `null`. This preserves continuation semantics and prevents stale state reuse across tokenization sequences.

## Residual Risk
None

## Patch
- `003-strtok-r-leaves-save-state-stale-when-input-is-all-delimiter.patch` updates `lib/c/string.zig` so the `findNone(... ) == null` path advances `state.*` to the current string terminator before returning `null`.