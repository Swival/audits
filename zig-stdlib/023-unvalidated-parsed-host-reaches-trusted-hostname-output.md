# Parsed URI host bypasses HostName validation

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Uri.zig:24`
- `lib/std/Uri.zig:31`
- `lib/std/http/Client.zig:1237`
- `lib/std/http/Client.zig:1240`
- `lib/std/http/Client.zig:1357`
- `lib/std/http/Client.zig:1368`
- `lib/std/http/Client.zig:1727`

## Summary
`Uri.parseAfterScheme` stores authority host bytes as `.percent_encoded` without hostname validation, but `Uri.host` is later consumed as if already trusted. `getHost` converts that parsed host into `std.net.HostName` via `toRaw` and treats `error.NoSpaceLeft` as unreachable, relying on a validation guarantee that parsing never established. A crafted parsed URI host therefore crosses a trust boundary into trusted `HostName` output and can also trigger a panic when percent-decoding expands beyond `HostName.max_len`.

## Provenance
- Verified from the provided finding and reproducer against the affected code paths
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Attacker controls a URI string later passed to `Uri.parse(...)` or `parseAfterScheme(...)`
- Program subsequently calls `getHost` or `getHostAlloc` on the parsed `Uri`

## Proof
A successful parse accepts an overlong percent-encoded host and later aborts in `getHost`:

```zig
const std = @import("std");

pub fn main() !void {
    var host: [512]u8 = undefined;
    @memset(host[0..], '"');

    var buf: [2048]u8 = undefined;
    const uri = try std.fmt.bufPrint(&buf, "http://{s}/", .{host[0..256]});

    const parsed = try std.Uri.parse(uri);
    var out: [std.net.HostName.max_len]u8 = undefined;
    _ = parsed.getHost(&out) catch unreachable;
}
```

Observed behavior:
- Parsing succeeds because `parseAfterScheme` stores host bytes directly as `.percent_encoded`
- `getHost` calls `toRaw` into a fixed `[HostName.max_len]u8` buffer
- Decoding 256 bytes into a 255-byte `HostName` buffer returns `error.NoSpaceLeft`
- `getHost` treats that error as unreachable and panics at `lib/std/Uri.zig:31`

This is reachable from stdlib consumers that trust `getHost` output, including:
- `lib/std/http/Client.zig:1727` before outbound connection setup
- `lib/std/http/Client.zig:1237` and `lib/std/http/Client.zig:1240` during redirect parent-domain checks
- `lib/std/http/Client.zig:1357` and `lib/std/http/Client.zig:1368` during proxy host parsing

## Why This Is A Real Bug
The bug is not theoretical:
- The documented invariant is that `Uri.host` is already validated, but the parsing path does not enforce that invariant
- The returned type is `std.net.HostName`, a trusted representation used by downstream networking code
- The trust mismatch is observable as both incorrect type promotion of invalid input and a concrete denial of service via panic
- The reproducer reaches the panic through public stdlib APIs with no undefined behavior or artificial setup

## Fix Requirement
Ensure parsed host data is validated before it can be exposed as `HostName`. Acceptable fixes are:
- validate host bytes during `parse` / `parseAfterScheme`, rejecting invalid authorities early; or
- validate in `getHost` / `getHostAlloc` before constructing or returning `HostName`, and stop treating overflow as unreachable

## Patch Rationale
The patch in `023-unvalidated-parsed-host-reaches-trusted-hostname-output.patch` should restore the broken invariant at the boundary where parsed host data becomes trusted. That prevents invalid parsed hosts from being retyped as `HostName` and eliminates the reachable `unreachable` panic caused by oversized percent-decoded output.

## Residual Risk
None

## Patch
- `023-unvalidated-parsed-host-reaches-trusted-hostname-output.patch` validates parsed host input before returning trusted `HostName` output, closing the trust-boundary violation and removing the panic path caused by unchecked percent-decoding overflow.