# KeyUpdate zero-length body causes out-of-bounds read

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/crypto/tls/Client.zig:836`

## Summary
A TLS 1.3 client accepts a post-handshake `KeyUpdate` handshake length from decrypted input and reads `handshake[0]` without first validating that the body length is exactly 1. A malicious authenticated peer can send a zero-length `KeyUpdate` body, causing a runtime panic in safety-enabled builds and unchecked out-of-bounds behavior in unsafe builds.

## Provenance
- Verified from source and reproduced against the affected parser path
- Swival Security Scanner: https://swival.dev

## Preconditions
- TLS 1.3 peer sends a `KeyUpdate` handshake with zero-length body
- Message is delivered through authenticated encrypted application-data records and reaches post-handshake parsing in `readIndirect`

## Proof
The parser in `readIndirect` accepts the handshake length from decrypted cleartext, slices `handshake = cleartext[ct_i..next_handshake_i]`, and then handles `.key_update` by evaluating `@enumFromInt(handshake[0])` at `lib/std/crypto/tls/Client.zig:836` without checking `handshake.len >= 1`.

A valid reproducer record can decrypt to inner plaintext ending in handshake content type with bytes equivalent to:
```text
18 00 00 00 16
```

This encodes:
```text
type = key_update
length = 0
inner content type = handshake
```

Because the AEAD check succeeds before parsing, the malformed peer-controlled message reaches the buggy branch. With a zero-length body, `handshake[0]` indexes an empty slice. In safety-enabled Zig builds this triggers:
```text
thread panic: index out of bounds: index 0, len 0
```

## Why This Is A Real Bug
This is reachable from network input after normal TLS authentication and decryption, so it is not a theoretical parser edge case. The parser violates its own length assumptions before it can raise a protocol error. The result is a remotely triggerable client crash in safe builds and undefined behavior in unsafe builds. The issue is therefore a concrete denial-of-service bug with memory-safety implications in less checked build modes.

## Fix Requirement
Reject `.key_update` unless `handshake.len == 1` before reading `handshake[0]`, and return a protocol error for any other length.

## Patch Rationale
The patch adds an explicit length check in the `.key_update` handler before accessing the first byte, enforcing the TLS 1.3 `KeyUpdate` body size invariant at the use site. This converts malformed zero-length input from a crash/undefined-behavior condition into a clean protocol rejection, matching the intended parser behavior.

## Residual Risk
None

## Patch
Patched in `031-keyupdate-handshake-reads-byte-without-length-check.patch` by validating `handshake.len == 1` before `@enumFromInt(handshake[0])` in `lib/std/crypto/tls/Client.zig`.