# memccpy drops terminator byte and violates NULL-on-miss semantics

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/c/string.zig:229`

## Summary
`memccpy` in `lib/c/string.zig` computes the copy length as the index of the matched byte or `len`, then copies only `src[0..copying_len]` and always returns `dst + copying_len`. This violates standard `memccpy` behavior in two ways: it omits the matched byte from the copy, and it never returns `NULL` when the byte is absent.

## Provenance
- Verified from the provided finding and reproducer.
- API expectations confirmed against bundled libc headers:
  - `lib/libc/include/generic-glibc/string.h:54`
  - `lib/libc/include/generic-glibc/string.h:56`
  - `lib/libc/include/generic-musl/string.h:79`
  - `lib/libc/include/generic-musl/string.h:82`
  - `lib/libc/include/wasm-wasi-musl/string.h:98`
  - `lib/libc/include/wasm-wasi-musl/string.h:101`
- Reachability confirmed via:
  - `lib/c/string.zig:6`
  - `lib/c/string.zig:35`
  - `lib/c.zig:73`
- Scanner reference: https://swival.dev

## Preconditions
- Caller relies on standard `memccpy` copy/return semantics.

## Proof
At `lib/c/string.zig:229`, `copying_len` is computed as `findScalar(...) orelse len`. The implementation then:
- copies `src[0..copying_len]` into `dst`
- returns `dst + copying_len`

If `value` exists at index `i`, the copied range excludes `src[i]`, even though `memccpy` must copy through the matched byte and return a pointer to the byte after it.

If `value` does not exist, `copying_len` becomes `len`, all `len` bytes are copied, and the function still returns `dst + len`. Standard `memccpy` must instead return `NULL` when no matching byte is found.

This behavior is reachable because Zig exports this implementation as `memccpy` for musl/WASI libc targets through `lib/c/string.zig` and `lib/c.zig`.

## Why This Is A Real Bug
The implementation contradicts the contract declared by the bundled libc headers and the expected C ABI behavior. Callers cannot:
- preserve the delimiter byte in the destination buffer
- distinguish “delimiter found” from “delimiter not found” via the return value

That breaks control flow and data layout for any conforming consumer of `memccpy`.

## Fix Requirement
Update `memccpy` to:
- copy through the matched byte when `findScalar` succeeds
- return `NULL` when `findScalar` fails

## Patch Rationale
The patch should branch on the `findScalar` result:
- on hit at index `i`, copy `i + 1` bytes and return `dst + i + 1`
- on miss, copy `len` bytes and return `NULL`

This restores standard `memccpy` semantics while preserving existing behavior for the copied prefix.

## Residual Risk
None

## Patch
Patched in `002-memccpy-omits-matched-byte-and-never-returns-null.patch`.