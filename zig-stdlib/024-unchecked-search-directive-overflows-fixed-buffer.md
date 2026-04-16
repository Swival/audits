# Unchecked search directive overflows fixed buffer

## Classification
High severity vulnerability; denial of service. Confidence: certain.

## Affected Locations
- `lib/std/Io/net/HostName.zig:373`
- `lib/std/Io/net/HostName.zig:460`
- `lib/std/Io/Threaded.zig:14287`

## Summary
`ResolvConf.parse` copies the remainder of a `search` or `domain` directive into `search_buffer`, a fixed `[255]u8` array, without validating that the directive length fits. An attacker-controlled directive longer than 255 bytes violates the buffer-length invariant and triggers a bounds-check panic in safety-enabled builds during parsing.

## Provenance
Verified by reproduction against the affected source and patched locally. Scanner source: https://swival.dev

## Preconditions
Attacker controls a `search` or `domain` line in `/etc/resolv.conf` whose payload exceeds 255 bytes.

## Proof
`ResolvConf.parse` tokenizes each `resolv.conf` line from `line_buf[512]` and, for `.domain` and `.search`, takes `line_it.rest()` and executes a copy into `rc.search_buffer[0..rest.len]` while `search_buffer` is only 255 bytes long.
A reproducer supplying a 300-byte `search` payload reached `HostName.ResolvConf.parse` and panicked at `lib/std/Io/net/HostName.zig:460` with:
```text
index out of bounds: index 300, len 255
```
This confirms attacker-reachable termination in safety-enabled builds. The resulting oversized logical length also conflicts with later consumers such as `lookupDnsSearch`, which slice based on `rc.search_len` at `lib/std/Io/Threaded.zig:14287`.

## Why This Is A Real Bug
The bug is directly reachable from untrusted resolver configuration content and causes process abort during parsing in checked builds, which is a real denial of service. The source pattern also breaks the invariant that `search_len <= search_buffer.len`, so downstream code cannot safely rely on the struct state once such input is accepted.

## Fix Requirement
Before copying a `search` or `domain` payload into `search_buffer`, enforce `rest.len <= rc.search_buffer.len`. Oversized directives must be rejected or safely truncated before updating `search_len`.

## Patch Rationale
The patch adds an explicit length guard in `ResolvConf.parse` before the copy into `search_buffer`. This preserves the struct invariant, prevents the out-of-bounds access, and turns attacker-controlled oversized directives into a handled parse failure instead of a crash.

## Residual Risk
None

## Patch
Patched in `024-unchecked-search-directive-overflows-fixed-buffer.patch`.