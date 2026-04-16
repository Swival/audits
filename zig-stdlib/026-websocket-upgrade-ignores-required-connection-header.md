# WebSocket upgrade ignores required Connection header

## Classification
Validation gap, medium severity, confidence: certain.

## Affected Locations
- `lib/std/http/Server.zig:428`
- `lib/std/http/Server.zig:500`
- `lib/std/http/Server.zig:531`
- `lib/std/Build/WebServer.zig:274`

## Summary
The HTTP server accepts a WebSocket opening handshake when `Upgrade: websocket` is present but `Connection` does not contain the required `Upgrade` token. `Request.Head.parse` uses `Connection` only for keep-alive handling, `upgradeRequested()` returns `.websocket` based solely on `Upgrade: websocket`, and `respondWebSocket()` does not revalidate the missing requirement before emitting `101 Switching Protocols`.

## Provenance
Reproduced from the verified finding and traced in source. Reference scanner: https://swival.dev

## Preconditions
- HTTP/1.1 `GET` request
- `Upgrade: websocket` header present
- Request reaches code that calls `request.upgradeRequested()` and then `request.respondWebSocket(...)`

## Proof
A malformed opening handshake without `Connection: Upgrade` remains upgradeable:
```http
GET / HTTP/1.1
Host: example
Upgrade: websocket
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

Observed code path:
- `Request.Head.parse` does not record whether `Connection` contains `Upgrade`; it only flips keep-alive behavior on `close` at `lib/std/http/Server.zig:428`.
- `Request.upgradeRequested()` returns `.websocket` when it sees `Upgrade: websocket`, without requiring a matching `Connection` token, at `lib/std/http/Server.zig:500`.
- `Request.respondWebSocket()` asserts only HTTP/1.1 and `GET`, then sends `101 Switching Protocols` without checking `Connection`, at `lib/std/http/Server.zig:531`.
- The shipped caller in `lib/std/Build/WebServer.zig:274` immediately upgrades on `.websocket`, making the gap reachable in normal use.

## Why This Is A Real Bug
RFC 6455 requires the client handshake to include a `Connection` header containing `Upgrade`. Accepting the handshake without that token is a protocol-validation failure, not a theoretical concern: the server emits a successful `101` for a malformed request. This can cause interoperability issues and incorrect behavior with intermediaries that rely on compliant upgrade semantics.

## Fix Requirement
Require the `Connection` header to contain the `Upgrade` token before either:
- returning `.websocket` from `upgradeRequested()`, or
- sending `101 Switching Protocols` from `respondWebSocket()`.

## Patch Rationale
The patch in `026-websocket-upgrade-ignores-required-connection-header.patch` adds explicit validation that `Connection` includes the `Upgrade` token before a request is treated as a WebSocket upgrade. This closes the gap at the decision point and prevents malformed handshakes from reaching a successful protocol switch.

## Residual Risk
None.

## Patch
`026-websocket-upgrade-ignores-required-connection-header.patch`