# Token printer can overflow `g_actual`

## Classification
High severity vulnerability. Confidence: certain.

## Affected Locations
- `src/testdriver.c:141`
- `src/testdriver.c:198`
- `src/testdriver.c:207`

## Summary
`read_file` accumulates formatted parser output into the fixed-size stack buffer `g_actual[8192]`. The SQL and HTML token printer helpers append at `buf + len` without enforcing remaining capacity, so sufficiently token-dense input causes writes past the end of `g_actual` and corrupts stack memory.

## Provenance
- Verified from the provided reproducer and patch target in `src/testdriver.c`
- Reproduced under AddressSanitizer with the supplied build and runtime flow
- Scanner reference: https://swival.dev

## Preconditions
Input must produce enough printed tokens to make the cumulative formatted output exceed 8192 bytes.

## Proof
The issue is reachable from `read_file` when handling test types `0`, `1`, or `3`:
- `read_file` initializes local `g_actual[8192]` and tracks only the current formatted length
- For SQL tokenization paths, each token is appended through `print_token`
- For HTML5 tokenization, each token is appended through `print_html5_token`
- The helpers format at `buf + len` using `sprintf`/`snprintf` semantics without rejecting or capping writes once `len` reaches the buffer limit

This was reproduced with ASan. The crashing write occurs in `print_token` during the trailing newline append after prior appends advanced `len` beyond the end of `g_actual`. ASan reports a stack-buffer-overflow on the `g_actual` stack slot in `read_file`, with the faulting path reaching `src/testdriver.c:141` from `src/testdriver.c:207`.

## Why This Is A Real Bug
This is not a theoretical truncation issue. The formatter writes beyond a fixed stack buffer under attacker-controlled input volume, and ASan confirms an out-of-bounds stack write in a real execution path. Because the overflow occurs on the stack, it can corrupt adjacent locals and control-sensitive state and can crash or destabilize the process.

## Fix Requirement
All token-printer appends must track remaining capacity against `sizeof(g_actual)` and stop or safely truncate before any write would exceed the destination buffer.

## Patch Rationale
The patch in `008-token-printer-can-overflow-g-actual.patch` hardens the append logic by making capacity an explicit part of token printing. Instead of advancing an unbounded logical length and continuing to write at `buf + len`, the patched code checks remaining space on each append and truncates or stops once the destination buffer is full. This directly removes the out-of-bounds write primitive while preserving existing output generation semantics as far as buffer space permits.

## Residual Risk
None

## Patch
`008-token-printer-can-overflow-g-actual.patch` updates `src/testdriver.c` to bound token-printer output by the actual destination size, preventing `g_actual` from being overrun during SQL and HTML token formatting.