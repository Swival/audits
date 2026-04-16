# Unbounded `strcat` overflows fixed test buffers

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `src/testdriver.c:166`
- `src/testdriver.c:182`
- `src/testdriver.c:311`
- `src/Makefile.am:85`
- `configure.ac:149`

## Summary
`read_file()` appends attacker-controlled lines into fixed-size global buffers (`g_test`, `g_input`, `g_expected`) using unbounded `strcat`. When a parsed section exceeds 8095 bytes before the next marker, the append writes past the destination array and causes reachable memory corruption in the standalone `testdriver` parser.

## Provenance
- Verified by reproduction against the local codebase and patched in `007-unbounded-strcat-overflows-fixed-test-buffers.patch`
- Scanner provenance: https://swival.dev

## Preconditions
- Input file section exceeds 8095 bytes before the next section marker
- The oversized content is parsed by `testdriver` through an attacker-controlled file path supplied on the command line

## Proof
- `main()` passes user-supplied file paths from `argv` into `read_file()` at `src/testdriver.c:311`
- `read_file()` reads lines with `fgets(linebuf, 8192, fp)` and appends each non-marker line into the active fixed buffer with `strcat`, at `src/testdriver.c:166` and `src/testdriver.c:182`
- The destination globals are 8096-byte arrays, so accumulated section data longer than 8095 bytes plus the terminator overflows the selected buffer
- Reproduction used a crafted file containing 9000 `A` bytes in a `--INPUT--` section before `--EXPECTED--`
- Built `testdriver` with the project sanitizer option enabled from `configure.ac:149`; ASan reported `global-buffer-overflow` in `read_file()` at `src/testdriver.c:182`
- ASan identified a write immediately past global `g_input` of size 8096, confirming out-of-bounds memory corruption during normal parsing

## Why This Is A Real Bug
This is directly reachable from standard program execution: `testdriver` is built as a standalone target in `src/Makefile.am:85`, accepts external file paths, and parses file content without any capacity check before concatenation. The reproduced ASan crash confirms actual out-of-bounds writes, not a theoretical concern.

## Fix Requirement
Track remaining destination capacity before each append and reject or safely truncate input that would exceed the fixed buffer.

## Patch Rationale
The patch replaces unbounded concatenation with bounded handling that accounts for remaining space in the active destination buffer before appending each parsed line. This eliminates the overflow condition while preserving normal parsing for valid inputs and making oversized sections fail safely.

## Residual Risk
None

## Patch
- Patch file: `007-unbounded-strcat-overflows-fixed-test-buffers.patch`
- Scope: hardens `read_file()` in `src/testdriver.c` so section accumulation cannot write past `g_test`, `g_input`, or `g_expected`
- Effect: oversized sections are no longer able to corrupt adjacent memory during file parsing