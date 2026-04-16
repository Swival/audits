# Empty OID encoding causes out-of-bounds read

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/codecs/asn1/Oid.zig:49`
- `lib/std/crypto/codecs/asn1/Oid.zig:110`
- `lib/std/crypto/codecs/asn1.zig:204`
- `lib/std/crypto/codecs/asn1/der/Decoder.zig:88`
- `lib/std/crypto/codecs/asn1/der/Decoder.zig:109`

## Summary
`Oid.toDot` dereferences `encoded[0]` without first enforcing that the OBJECT IDENTIFIER payload is non-empty. Because `Oid.encoded` is public and DER decoding preserves zero-length primitive content, an empty OID state is reachable and causes a bounds trap when `toDot` is invoked.

## Provenance
- Verified by reproduction against the referenced source paths and control flow.
- External scanner reference: https://swival.dev

## Preconditions
- `Oid.encoded` is empty when `toDot` is called.

## Proof
- `Oid` stores arbitrary `[]const u8` in its public `encoded` field at `lib/std/crypto/codecs/asn1/Oid.zig:5`.
- `Oid.toDot` reads `encoded[0]` immediately at `lib/std/crypto/codecs/asn1/Oid.zig:49`.
- `Oid.decodeDer` returns `decoder.view(ele)` at `lib/std/crypto/codecs/asn1/Oid.zig:110` and does not reject zero-length content.
- The DER stack accepts and preserves empty primitive payloads: `Element.decode` allows `len == 0` at `lib/std/crypto/codecs/asn1.zig:204`, and `Decoder.element` plus `Decoder.view` return the empty slice unchanged at `lib/std/crypto/codecs/asn1/der/Decoder.zig:88` and `lib/std/crypto/codecs/asn1/der/Decoder.zig:109`.
- A DER blob `06 00` therefore decodes into `Oid{ .encoded = "" }`; a subsequent `toDot` call deterministically triggers an out-of-bounds slice access trap.

## Why This Is A Real Bug
The invalid state is reachable through public APIs, not only via manual construction. Zig slice bounds checks turn the access into a deterministic crash, so attacker-controlled malformed DER can induce denial of service in any caller that decodes an OID and later formats it with `toDot`. This is a real invariant violation even though it is not an unchecked memory-safety read.

## Fix Requirement
Reject empty OID encodings before any access to `encoded[0]`. `toDot` must return an error for empty input, and `decodeDer` should also reject zero-length OBJECT IDENTIFIER contents so malformed DER cannot construct the invalid state through the decoder path.

## Patch Rationale
The patch enforces the ASN.1 minimum-content invariant at the two trust boundaries that matter:
- formatting: `toDot` now fails safely instead of indexing an empty slice;
- decoding: `decodeDer` rejects zero-length OID payloads early, preventing propagation of invalid `Oid` values from DER input.

This preserves existing behavior for valid encodings while converting a crash-on-use condition into explicit error handling.

## Residual Risk
None

## Patch
- Patch file: `079-empty-oid-encoding-causes-out-of-bounds-read.patch`
- Patch intent:
  - add an empty-slice guard in `lib/std/crypto/codecs/asn1/Oid.zig` before `encoded[0]` is read;
  - reject zero-length OID content in `lib/std/crypto/codecs/asn1/Oid.zig` during DER decode.