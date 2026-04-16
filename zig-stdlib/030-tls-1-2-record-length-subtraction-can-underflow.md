# TLS 1.2 short AEAD record triggers underflow and abort

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/tls/Client.zig:779`

## Summary
A server-controlled TLS 1.2 record length is reduced by `P.record_iv_length + P.mac_length` without first enforcing that the record is at least that large. For undersized AEAD records, the `u16` subtraction underflows, yielding a bogus large plaintext length. The client then reaches `input.take(message_len) catch unreachable` with only `5 + record_len` bytes buffered, causing an abort instead of returning a protocol error.

## Provenance
- Verified and patched from a reproduced finding generated via Swival Security Scanner: https://swival.dev
- Reproducer confirmed the crash path on a too-short TLS 1.2 AEAD record and validated that insufficient buffered data reaches an `unreachable` abort site.

## Preconditions
- TLS 1.2 AEAD record shorter than explicit IV plus tag

## Proof
A peer-controlled `record_len` is parsed from the TLS record header in `readIndirect`. In the TLS 1.2 path, the code computes:
```zig
const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
```
with no prior lower-bound check at `lib/std/crypto/tls/Client.zig:779`.

For a short record, such as `record_len = 8` with `P.record_iv_length = 8` and `P.mac_length = 16`, the arithmetic underflows:
```text
8 - 8 - 16 = 65520
```

The buffering logic only ensures `5 + record_len` bytes are available before parsing the record body, as reproduced from the `readIndirect` path. The oversized `message_len` later flows to:
- `lib/std/crypto/tls/Client.zig:1214`

where `input.take(message_len) catch unreachable` executes. With only the short record buffered, this `take` fails and the `catch unreachable` aborts the process.

This is reachable on any post-handshake TLS 1.2 AEAD record received from the peer.

## Why This Is A Real Bug
The failure is externally triggerable by a malicious server or an active attacker able to inject or modify TLS ciphertext. Instead of rejecting the malformed record with a TLS error, the client aborts. That is a denial-of-service condition in a network-facing parser reached before authentication of the malformed record contents completes.

## Fix Requirement
Reject TLS 1.2 records when `record_len < P.record_iv_length + P.mac_length` before computing `message_len`.

## Patch Rationale
The patch adds an explicit lower-bound validation in the TLS 1.2 AEAD record handling path in `lib/std/crypto/tls/Client.zig`. This mirrors the existing short-record validation already present during initialization and converts the malformed input into a normal TLS error path before any subtraction, decryption setup, or buffered slice extraction occurs.

## Residual Risk
None

## Patch
- `030-tls-1-2-record-length-subtraction-can-underflow.patch` adds a pre-subtraction size check in `lib/std/crypto/tls/Client.zig`
- The new guard rejects undersized TLS 1.2 AEAD records before `record_len - P.record_iv_length - P.mac_length` is evaluated
- This prevents `u16` underflow, avoids the oversized `message_len`, and removes the reachable `catch unreachable` abort path for this malformed input