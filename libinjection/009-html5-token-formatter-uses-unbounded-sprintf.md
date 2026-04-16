# HTML5 token formatter overflows fixed-size output buffer

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `src/testdriver.c:103`
- `src/testdriver.c:117`
- `src/testdriver.c:239`

## Summary
`print_html5_token()` formatted parser-controlled token text into the caller-supplied output buffer with `sprintf(buf + len, "%s,%d,%s\n", ...)` and no remaining-size check. In the HTML5 tokenizer test path, `read_file()` accumulates repeated token output into `g_actual[8192]`, so sufficiently verbose token streams overflow the fixed stack buffer and corrupt adjacent memory.

## Provenance
- Verified from the supplied reproducer and source inspection
- Reproduced with AddressSanitizer against the project test driver
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- HTML5 tokenization output exceeds the remaining capacity of `g_actual[8192]`
- Execution reaches the `testtype == 3` path in `read_file()`
- Token text is emitted through repeated calls to `print_html5_token()`

## Proof
- `read_file()` appends HTML5 token output into `g_actual[8192]` and passes the growing `slen` to `print_html5_token()` on each token.
- `print_html5_token()` copies parser-controlled `hs->token_start`/`hs->token_len` into a temporary string and appends with unbounded `sprintf`.
- A generated PoC at `.swival/poc/test-html5-overflow.txt` with `n = 282` is only 1131 bytes of input, below `g_input[8096]`, but produces 8215 bytes of formatted token output, exceeding `g_actual[8192]`.
- ASan execution aborts with `AddressSanitizer: stack-buffer-overflow`, showing the write path `sprintf -> print_html5_token` at `testdriver.c:117` -> `read_file` at `testdriver.c:239`, and identifies `g_actual` as the overflowed stack object as captured in `.swival/poc/stderr.txt:18`.

## Why This Is A Real Bug
This is a direct stack buffer overflow on reachable input. The triggering input is well within the driver's accepted file size, and the overflow occurs before any final trimming or comparison logic. Although the bug is in the shipped test driver rather than the library API, it still permits a crafted test case to crash the process and overwrite adjacent stack state.

## Fix Requirement
Replace the unbounded append with a bounded formatter that receives the remaining destination capacity, and detect truncation so writes never exceed `g_actual`.

## Patch Rationale
The patch updates the token formatter to use `snprintf` with the remaining buffer size instead of `sprintf`, and propagates/handles truncation so the HTML5 token accumulation path cannot write past `g_actual[8192]`. This preserves existing output semantics for valid-sized cases while converting oversized output into a safe bounded result.

## Residual Risk
None

## Patch
- Patch file: `009-html5-token-formatter-uses-unbounded-sprintf.patch`
- The patch replaces the unsafe append in `src/testdriver.c` with bounded formatting based on remaining capacity and truncation handling, eliminating the reproduced overflow path.