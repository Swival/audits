# Malformed keychain signature assertion causes process abort

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/crypto/Certificate/Bundle/macos.zig:39`

## Summary
`rescanMac` accepts keychain file bytes from disk and `scanReader` parses an `ApplDbHeader` from that untrusted input. The code then validates the header magic with `assert(mem.eql(u8, &db_header.signature, "kych"));`, so any malformed 4-byte signature aborts the process in safety-enabled builds instead of returning a recoverable parse error.

## Provenance
- Reproduced from the provided finding and code inspection
- Reference: https://swival.dev

## Preconditions
- Attacker controls keychain file contents read by `rescanMac`

## Proof
- `scanReader` reads the header with `reader.takeStruct(ApplDbHeader, .big)`, which succeeds whenever enough bytes exist for the struct: `lib/std/crypto/Certificate/Bundle/macos.zig:37`
- The next step is `assert(mem.eql(u8, &db_header.signature, "kych"));`: `lib/std/crypto/Certificate/Bundle/macos.zig:39`
- A file containing any non-`kych` 4-byte signature reaches that assertion directly after successful header parsing
- In this tree, `std.debug.assert` lowers to `unreachable` on failure and panics in Debug and ReleaseSafe modes: `lib/std/debug.zig:407`, `lib/std/debug.zig:418`
- Result: malformed keychain input causes process termination rather than a returned parse/format error, yielding denial of service

## Why This Is A Real Bug
The signature check is performed on attacker-controlled file content after a successful bounded read, so this is a normal input-validation path, not an internal invariant. Using `assert` converts malformed external input into a crash condition. That is directly reachable under the stated precondition and changes behavior from error propagation to process abort.

## Fix Requirement
Replace the assertion-based magic check with a returned invalid-format or parse error so malformed keychain files are rejected without terminating the process.

## Patch Rationale
The patch removes the `assert` on the `ApplDbHeader.signature` field and returns an ordinary parse/format error when the signature is not `kych`. This preserves validation while restoring expected error-handling semantics for untrusted file input.

## Residual Risk
None

## Patch
- Patch file: `070-malformed-keychain-signature-triggers-assertion-abort.patch`
- Change: convert the keychain signature validation in `lib/std/crypto/Certificate/Bundle/macos.zig` from `assert(...)` to an explicit returned error on invalid magic
- Expected effect: malformed keychain files no longer abort the process; callers receive a recoverable parse failure instead