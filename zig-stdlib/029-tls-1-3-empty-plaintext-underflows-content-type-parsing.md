# TLS 1.3 empty plaintext underflows content-type parsing

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/tls/Client.zig:773`
- Related pattern also present at `lib/std/crypto/tls/Client.zig:385`

## Summary
TLS 1.3 record handling trims trailing zero padding from decrypted plaintext and then unconditionally reads the final byte as the inner content type. When the decrypted plaintext is entirely zero padding, trimming yields an empty slice. The subsequent `msg.len - 1` and `msg[msg.len - 1]` underflow and index out of bounds instead of rejecting the record as invalid.

## Provenance
- Verified from the provided finding and reproducer
- Reproduced with a minimal Zig test showing `msg.len - 1` on an empty slice panics in checked builds and wraps in unchecked builds
- Source: `lib/std/crypto/tls/Client.zig`
- Scanner reference: `https://swival.dev`

## Preconditions
- TLS 1.3 application record decrypts to only zero padding
- The attacker controls the server side of a successfully established TLS 1.3 session

## Proof
In `readIndirect`, TLS 1.3 decryption produces `cleartext`, then:
```zig
msg = mem.trimEnd(u8, cleartext, "\x00");
```
If `cleartext` contains only `0x00` bytes, `msg.len == 0`. The code then evaluates the last byte position to parse the TLS 1.3 inner content type:
```zig
const inner_ct = msg[msg.len - 1];
```
That operation is invalid for an empty slice:
- checked builds: `msg.len - 1` traps with integer overflow
- unchecked builds: subtraction wraps to `usize.max`, producing an out-of-bounds access pattern

This is reachable from server-controlled record bytes after TLS 1.3 session establishment, so a malicious peer can trigger abnormal client termination instead of a handled protocol error. The same empty-trimmed-plaintext pattern also exists in the handshake receive path around `lib/std/crypto/tls/Client.zig:385`.

## Why This Is A Real Bug
TLS 1.3 requires the inner plaintext to end with a non-zero content-type byte after optional zero padding. An all-zero decrypted plaintext is therefore invalid input that must be rejected cleanly. The current logic does not validate that invariant before indexing the final byte, so malformed peer input causes a crash/out-of-bounds condition rather than a protocol error. Because the input is peer-controlled and reachable in normal network operation, this is a real remotely triggerable denial of service.

## Fix Requirement
Reject empty trimmed TLS 1.3 plaintext before subtracting 1 or indexing the last byte, and return a TLS decoding error instead of continuing content-type parsing. Apply the same guard anywhere TLS 1.3 inner plaintext is trimmed and then tail-indexed.

## Patch Rationale
The patch should add an explicit `msg.len == 0` check immediately after `mem.trimEnd` in the TLS 1.3 parsing paths. That enforces the protocol invariant at the boundary where it matters, prevents integer underflow and out-of-bounds access in all build modes, and converts malformed records into a deterministic handled error. Extending the same guard to the related handshake path removes the duplicated bug pattern.

## Residual Risk
None

## Patch
Patched in `029-tls-1-3-empty-plaintext-underflows-content-type-parsing.patch`, adding empty-slice validation after TLS 1.3 zero-padding trim so invalid all-zero plaintext is rejected before inner content-type parsing.