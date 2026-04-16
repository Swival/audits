# UTCTime 50-99 years are misparsed as 2050-2099

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/Certificate.zig:421`

## Summary
`std.crypto.Certificate.parseTime()` handled ASN.1 `UTCTime` by unconditionally computing `year = 2000 + YY`. For `YY` values `50` through `99`, X.509 requires years `1950` through `1999`, but the parser produced `2050` through `2099`. This shifts certificate validity windows by 100 years and causes `Parsed.verify()` to make incorrect validity decisions.

## Provenance
- Reported from verified reproduction and patch generation against the current tree
- Reference: https://swival.dev

## Preconditions
- Certificate validity is encoded as ASN.1 `UTCTime`
- The `UTCTime` year is in the `50`-`99` range
- Certificate bytes come from untrusted DER parsed by `std.crypto.Certificate.parse()`

## Proof
A runtime reproduction used a self-signed certificate whose DER validity encodes:
- `notBefore = UTCTIME 500101000000Z`
- `notAfter = UTCTIME 991231235959Z`

Under X.509, these mean `1950-01-01 00:00:00Z` through `1999-12-31 23:59:59Z`. Running a small Zig program against this tree's `std.crypto.Certificate.parse()` and `verify()` produced:
- `not_before=2524608000`
- `not_after=4102444799`
- `verify_ok`

These epoch values correspond to `2050-01-01 00:00:00Z` and `2099-12-31 23:59:59Z`. This demonstrates that `parseTime()` reinterprets `50`-`99` as `2050`-`2099`, and `verify()` then accepts the certificate for a timestamp in the shifted future-valid window.

## Why This Is A Real Bug
This is a direct standards mismatch in certificate validity parsing, not a theoretical edge case. The validity fields are attacker-controlled DER input, the buggy branch is reachable for any parsed certificate using `UTCTime`, and the resulting timestamps feed directly into certificate verification. The reproduced behavior shows an objectively wrong acceptance decision: a certificate whose real validity ended in 1999 is treated as valid in 2055.

## Fix Requirement
Implement RFC 5280 `UTCTime` year mapping:
- `00`-`49` -> `2000`-`2049`
- `50`-`99` -> `1950`-`1999`

## Patch Rationale
The patch updates `parseTime()` in `lib/std/crypto/Certificate.zig` to decode the two-digit `UTCTime` year first, then map it using the RFC 5280 split at `50`. This is the minimal targeted fix because it preserves existing parsing behavior for `00`-`49` while correcting the invalid century assignment for `50`-`99`.

## Residual Risk
None

## Patch
`065-utctime-years-before-2000-are-accepted-as-20xx.patch`