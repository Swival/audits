# URL decode heap off-by-one

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `src/html5_cli.c:185`
- `src/html5_cli.c:192`

## Summary
The CLI URL-decode path allocates `malloc(slen)` for a copy of user input, then decodes in place with `modp_url_decode(copy, copy, slen)`. The decoder always appends a trailing `'\0'`, so inputs whose decoded length remains `slen` cause a one-byte heap out-of-bounds write.

## Provenance
- Verified by reproduction against the local target and patched locally
- Source finding originated from Swival Security Scanner: https://swival.dev

## Preconditions
- Run the CLI with `-u`
- Provide a non-empty argument whose decoded length does not shrink, such as `A`

## Proof
- In `src/html5_cli.c:185`, user-controlled `argv[offset]` is copied into a heap buffer allocated with `malloc(slen)`.
- In `src/html5_cli.c:192`, that buffer is passed in place to `modp_url_decode(copy, copy, slen)`.
- The decoder writes a trailing `'\0'` after consuming up to `len` bytes, so the destination requires capacity for at least `decoded_length + 1`.
- For unchanged inputs like `A`, `dest` advances to `copy + slen`; the terminator write lands one byte past the allocation.
- AddressSanitizer reproduction with `./src/html5 -u A` reports a heap-buffer-overflow on the decode path, with the allocation traced back to `malloc(slen)`.

## Why This Is A Real Bug
This is a direct heap out-of-bounds write on attacker-controlled input reachable from normal CLI usage. The write occurs deterministically for common non-empty inputs that do not contract during decoding, so it is not theoretical or dependent on undefined caller behavior elsewhere.

## Fix Requirement
Allocate enough space for the in-place decoded string plus its terminator, i.e. at least `slen + 1`, before calling `modp_url_decode`.

## Patch Rationale
The patch updates the CLI decode buffer allocation to reserve one extra byte for the mandatory trailing `'\0'` written by `modp_url_decode`. This preserves existing in-place decode behavior while satisfying the decoder’s actual destination size requirement.

## Residual Risk
None

## Patch
- Patched file: `010-url-decode-writes-one-byte-past-heap-buffer.patch`
- Change: increase the temporary decode buffer allocation in `src/html5_cli.c` from `malloc(slen)` to `malloc(slen + 1)` so in-place URL decoding has space for the final terminator.