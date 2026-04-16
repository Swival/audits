# Request body assertion trusts malformed methods

## Classification
- Type: invariant violation
- Severity: low
- Confidence: certain

## Affected Locations
- `lib/std/http/Server.zig:541`
- `lib/std/http/Server.zig:628`
- `lib/std/http/Server.zig:631`

## Summary
A malformed persistent request can reach `discardBody` in `.received_head` with a body-capable method but without `Content-Length` or `Transfer-Encoding`. The code asserts framing must exist instead of handling the protocol error, so assertion-enabled builds abort during normal `respond` / `respondStreaming` use.

## Provenance
- Verified from the supplied reproducer and code-path analysis
- Patched in `028-request-body-assertion-trusts-malformed-methods.patch`
- Scanner reference: https://swival.dev

## Preconditions
- Persistent connection
- Body-capable method such as `POST`
- No `Content-Length`
- No `Transfer-Encoding`
- Application calls `respond` or `respondStreaming` without consuming a request body first

## Proof
A request such as:
```http
POST / HTTP/1.1
Host: example

```

is accepted through header parsing because method recognition does not require body framing. On the keep-alive response path, `respond` / `respondStreaming` invokes `discardBody`. In `.received_head`, `requestHasBody()` becomes true for `POST`, and execution reaches the framing assertion at `lib/std/http/Server.zig:628` and `lib/std/http/Server.zig:631`. With no framing headers present, the assertion fails. In Zig safety/debug-style builds, assertions lower to `unreachable`, producing a process abort rather than a graceful close or protocol error.

## Why This Is A Real Bug
The invariant being asserted is derived from untrusted request input and is not enforced earlier in the server path. A remote client can therefore trigger the abort with a syntactically malformed but parse-accepted request on a persistent connection. This is externally reachable denial of service in assertion-enabled builds, not a theoretical internal-only misuse.

## Fix Requirement
When a request method may carry a body but framing is absent, the server must not assert. It must treat the connection as non-reusable and close or otherwise fail gracefully.

## Patch Rationale
The patch changes the keep-alive body-discard path so unframed body-capable requests are treated as malformed connection state rather than trusted invariants. This preserves normal handling for valid framed bodies while preventing assertion-based termination on malformed input.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/std/http/Server.zig b/lib/std/http/Server.zig
--- a/lib/std/http/Server.zig
+++ b/lib/std/http/Server.zig
@@ -625,10 +625,14 @@ pub const Request = struct {
                 .received_head => {
                     if (!request.head.method.requestHasBody()) return;

-                    assert(request.head.transfer_encoding != .none or request.head.content_length != null);
+                    if (request.head.transfer_encoding == .none and request.head.content_length == null) {
+                        request.response.connection.data.closing = true;
+                        return;
+                    }

                     if (request.head.transfer_encoding != .none) {
                         try request.reader.discard();
                     } else {
```