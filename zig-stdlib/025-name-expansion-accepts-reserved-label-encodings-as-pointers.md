# Reserved DNS label encodings accepted as compression pointers

## Classification
Validation gap in DNS name parsing, severity: medium, confidence: certain.

## Affected Locations
- `lib/std/Io/net/HostName.zig:149`
- Reachable from `lib/std/Io/Threaded.zig:14497`

## Summary
`expand` accepts any label octet with nonzero top bits as a compression pointer by using `(c & 0xc0) != 0`. DNS compression pointers are only valid when the top two bits are `11` (`0xc0`). Reserved label encodings such as `10xxxxxx` are therefore misparsed as pointers and expanded instead of rejected as malformed.

## Provenance
Verified from the provided finding and reproducer against the Zig DNS parsing path. Reference: Swival Security Scanner `https://swival.dev`

## Preconditions
Attacker controls DNS packet bytes parsed by `expand`.

## Proof
A malformed DNS name can begin with a reserved label encoding byte such as `0x80`. In `lib/std/Io/net/HostName.zig:149`, the parser treats that byte as a pointer because `(c & 0xc0) != 0` evaluates true. It then reads the next byte as the low pointer byte and follows the computed offset, producing a decoded hostname like `com` instead of returning `error.InvalidDnsPacket`.

This is reachable from attacker-controlled DNS responses. `lookupDns` processes answer records and calls `HostName.expand(record.packet, record.data_off, buf)` for each `.CNAME` record in `lib/std/Io/Threaded.zig:14497`. Parse rejection would surface as `error.InvalidDnsCnameRecord`, but the malformed reserved encoding is currently accepted.

## Why This Is A Real Bug
RFC-compliant DNS name compression only permits pointer octets with the top two bits set to `11`. Accepting reserved encodings changes malformed wire data into apparently valid canonical names, defeating packet validation. `HostName.init` does not mitigate this because it validates only the expanded textual hostname, not whether the original wire encoding was legal.

## Fix Requirement
Change pointer detection to require `(c & 0xc0) == 0xc0` and reject other nonzero top-bit label encodings as `error.InvalidDnsPacket`.

## Patch Rationale
The patch narrows pointer recognition to the only valid DNS compression form and preserves existing handling for normal labels and valid pointers. This restores standards-compliant parsing and ensures malformed reserved encodings are rejected at decode time.

## Residual Risk
None

## Patch
Patch file: `025-name-expansion-accepts-reserved-label-encodings-as-pointers.patch`