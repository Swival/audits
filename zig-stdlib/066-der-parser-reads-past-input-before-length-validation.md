# DER header bounds check missing before parse reads

## Classification
- Severity: High
- Type: validation gap
- Confidence: certain

## Affected Locations
- `lib/std/crypto/Certificate.zig:617`

## Summary
`der.Element.parse(bytes, index)` reads the DER identifier and length bytes before proving that the two-byte header exists. When attacker-controlled certificate input is empty or only one byte long, parsing reaches unchecked `bytes[i]` accesses and faults before returning a structured parse error.

## Provenance
- Source: verified finding and local reproduction
- Reference: https://swival.dev
- Patch artifact: `066-der-parser-reads-past-input-before-length-validation.patch`

## Preconditions
- Attacker controls DER input shorter than two header bytes
- The input is processed through certificate parsing, including TLS certificate handling

## Proof
- Untrusted bytes reach `Certificate.parse()` and then `der.Element.parse(bytes, index)`.
- In the vulnerable flow, `parse` reads `bytes[i]` for the identifier, increments `i`, then reads `bytes[i]` for the length with no prior `bytes.len` check for the header.
- Reproduced with empty and one-byte certificates:
  - `Certificate{ .buffer = &.{}, .index = 0 }.parse()` aborts with `panic: index out of bounds: index 0, len 0`
  - `Certificate{ .buffer = &.{0x30}, .index = 0 }.parse()` aborts with `panic: index out of bounds: index 1, len 1`
- TLS reachability is confirmed because certificate decoding constructs `Certificate{ .buffer = certd.buf, .index = @intCast(certd.idx) }`, and the sub-decoder starts at index `0`, so a peer-controlled certificate of length `0` or `1` reaches the vulnerable parser state.

## Why This Is A Real Bug
The parser’s contract is to validate untrusted DER before dereferencing beyond available input. Here it dereferences first and validates later, so malformed remote input can terminate safety-checked builds and cause out-of-bounds read / undefined behavior in unchecked builds. This is a genuine memory-safety bug, not just a missing error case.

## Fix Requirement
Reject any element parse where fewer than two bytes remain before reading the DER header, and validate long-form length-byte availability before consuming those bytes.

## Patch Rationale
The patch adds explicit header-length guards at the start of `der.Element.parse` and preserves existing parse-error behavior for malformed inputs. This closes both the zero-byte and one-byte cases before any read occurs, and keeps long-form length parsing within proven bounds.

## Residual Risk
None

## Patch
```diff
--- a/lib/std/crypto/Certificate.zig
+++ b/lib/std/crypto/Certificate.zig
@@ -614,8 +614,13 @@ pub const der = struct {
         pub fn parse(bytes: []const u8, index: usize) ParseError!Element {
             var i = index;
 
+            if (bytes.len -| i < 2) {
+                return error.CertificateFieldHasInvalidLength;
+            }
+
             const id = Identifier.parse(bytes[i]);
             i += 1;
+
             const len_byte = bytes[i];
             i += 1;
 
```