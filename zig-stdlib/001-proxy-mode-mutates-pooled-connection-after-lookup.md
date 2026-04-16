# Proxy mode mutates pooled connection after lookup

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/http/Client.zig:1176`
- `lib/std/http/Client.zig:1001`
- `lib/std/http/Client.zig:1076`
- `lib/std/http/Client.zig:1621`

## Summary
`Client.connect` can reuse a pooled TCP connection to `proxy.host:proxy.port` that was created for direct use, then mutate that live connection into proxy mode by setting `connection.proxied = true` after pool lookup. That violates the pool key invariant because proxy mode changes request formatting and header emission without being part of connection selection.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Source: `lib/std/http/Client.zig`
- Scanner reference: https://swival.dev

## Preconditions
- A pooled direct connection to the proxy endpoint already exists
- Proxy fallback reuses that endpoint tuple via `connectTcp(proxy.host, proxy.port, proxy.protocol)`
- Pool lookup matches on host, port, and protocol, but not proxy mode

## Proof
- In proxy fallback, `Client.connect` first resolves a connection through `connectTcp(proxy.host, proxy.port, proxy.protocol)`
- Pool lookup in `findConnection` can select an existing direct connection because the endpoint tuple matches
- After reuse, code sets `connection.proxied = true` at `lib/std/http/Client.zig:1176` / reproduced at `lib/std/http/Client.zig:1621`
- This post-selection mutation is behaviorally significant:
  - `sendHead` uses absolute-form targets when `connection.proxied` is true at `lib/std/http/Client.zig:1001`
  - `sendHead` emits `proxy-authorization` when `connection.proxied` is true at `lib/std/http/Client.zig:1076`
- Therefore the same persistent socket can first serve direct requests to the proxy endpoint itself and later serve proxy-form requests with proxy credentials, proving the invariant violation

## Why This Is A Real Bug
Connection reuse is only safe when all request-relevant connection semantics are preserved across pooling. Here, proxy mode is not part of lookup identity, yet it changes on-wire request form and credential behavior. Reusing a direct connection and then flipping it to proxied changes semantics after selection, so the pooled object no longer represents the mode it was created and previously used for.

## Fix Requirement
Pool reuse must not allow direct and proxied connections for the same endpoint tuple to alias. The fix must either include proxy mode in pool matching or avoid mutating a reused direct connection into proxy mode, such as by forcing that reused connection closed and creating a mode-correct one.

## Patch Rationale
The patch in `001-proxy-mode-mutates-pooled-connection-after-lookup.patch` separates pooled connection identity by proxy mode instead of mutating a reused connection after lookup. That preserves the invariant that a pooled connection's reuse characteristics match its prior use and prevents request-form and proxy-auth behavior from changing on an already-selected socket.

## Residual Risk
None

## Patch
- `001-proxy-mode-mutates-pooled-connection-after-lookup.patch` fixes the bug by preventing fallback proxy mode from reusing a pooled direct connection and then flipping `connection.proxied` after selection
- The patch enforces mode-consistent reuse so direct and proxied connections to the same endpoint tuple are not treated as interchangeable