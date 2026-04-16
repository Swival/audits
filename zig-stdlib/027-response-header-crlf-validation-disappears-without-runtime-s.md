# Response header CRLF validation disappears without runtime safety

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/http/Server.zig:290`
- `lib/std/http/Server.zig:371`
- `lib/std/http/Server.zig:444`
- `lib/std/http/Server.zig:553`
- Patch: `027-response-header-crlf-validation-disappears-without-runtime-s.patch`

## Summary
`std.http.Server` accepted `RespondOptions.extra_headers` with CR/LF in header names or values when runtime safety was disabled. Those bytes were then written directly into the HTTP response framing, enabling response splitting and injected header/body lines. The patch makes header validation unconditional before emission.

## Provenance
- Verified reproduced finding based on code-path inspection and patch review
- Source: `lib/std/http/Server.zig`
- Scanner reference: https://swival.dev

## Preconditions
- Runtime safety disabled
- Caller controls `RespondOptions.extra_headers` name or value
- Application reaches `respond`, `respondStreaming`, or `respondWebSocket` with attacker-influenced headers

## Proof
`Request.respondUnflushed` previously performed CR/LF and `:` checks for `extra_headers` only inside `if (std.debug.runtime_safety)`, then unconditionally emitted headers with:
```zig
try buffered.writer().writeVecAll(.{
    header.name,
    ": ",
    header.value,
    "\r\n",
});
```
With runtime safety off, a value such as:
```text
ok\r\nSet-Cookie: injected=1
```
produces an additional response header line on the wire. A header name containing `\r\n` has the same effect. This is reachable from `respond`, which delegates to `respondUnflushed`.

The same sink pattern also exists in `respondStreaming` and `respondWebSocket`, which emit `extra_headers` verbatim and lacked equivalent validation on the reproduced path summary.

## Why This Is A Real Bug
HTTP response framing is line-oriented. Writing attacker-controlled CR/LF into a header name or value before the terminating `\r\n` lets an attacker terminate the current header and start a new header or body line. Because no downstream escaping is evidenced before bytes reach the socket, this is a direct response-splitting primitive, not a hypothetical misuse.

## Fix Requirement
Validate or sanitize response header names and values before writing them, independent of runtime safety, across all response helpers that emit `extra_headers`.

## Patch Rationale
The patch removes reliance on `std.debug.runtime_safety` for header validation and enforces the invariant at the point of emission. That is the correct boundary because all response construction flows through these writers, and correctness must not depend on build mode.

## Residual Risk
None

## Patch
`027-response-header-crlf-validation-disappears-without-runtime-s.patch` makes response-header validation unconditional in `lib/std/http/Server.zig` so `extra_headers` cannot inject CR/LF-delimited lines in unsafe builds, covering the affected response emission paths.