# WebSocket Coverage Update Reads Shared `mmap` Without Snapshot

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Build/Fuzz.zig:237`
- `lib/std/Build/WebServer.zig:333`
- `lib/std/Build/WebServer.zig:388`

## Summary
`prepareTables` maps the fuzz coverage file shared, and `sendUpdate` later reads `cov_header.seenBits()` from that shared mapping while connected WebSocket clients are serviced during active fuzzing. The coverage counters are loaded atomically, but the bitmap bytes are read as an ordinary slice, so the update payload can contain a torn, non-coherent coverage snapshot.

## Provenance
- Verified from the provided reproducer and source inspection
- Reproduced against the live update path driven by the WebSocket loop
- Scanner source: https://swival.dev

## Preconditions
- A WebSocket client is connected to the fuzz web UI
- Fuzzing is active in `.forever` mode
- Fuzzer workers continue mutating the shared coverage `mmap` while the server emits updates

## Proof
`lib/std/Build/WebServer.zig:333` calls `fuzz.sendUpdate` from the WebSocket service loop. That loop wakes periodically even without explicit notifications because `lib/std/Build/WebServer.zig:388` uses `futexWaitTimeout`, so a connected client repeatedly receives updates during ongoing fuzzing.

At `lib/std/Build/Fuzz.zig:237`, `sendUpdate` reads the coverage bitmap from the shared mapping via `cov_header.seenBits()`. The implementation already acknowledges this is unsound. Only header fields such as run counters are read with atomic loads; the bitmap bytes are not. Because fuzzers concurrently OR new bits into the same shared mapping, the server can serialize a payload assembled from ordinary reads racing with concurrent writers.

The original report overstated one transport detail: the bitmap is not handed directly to the kernel as a zero-copy scatter/gather buffer; it is copied in user space first. That does not change the bug. The race occurs at read time, before transmission, and the bytes copied can already represent an inconsistent snapshot.

## Why This Is A Real Bug
This is a real correctness bug because the UI update stream is intended to describe current fuzz progress, yet it can publish bitmap data that does not correspond to any coherent state of the shared coverage map. A client can therefore observe coverage bytes that disagree with the atomically read `n_runs` and `unique_runs` counters, or reflect a partially updated bitmap. The impact is limited to live fuzz reporting accuracy, but the race is reachable in normal operation and directly violates the intended snapshot semantics of an update.

## Fix Requirement
`sendUpdate` must avoid serializing the shared coverage mapping directly. It should first build a stable snapshot of the seen-bits bitmap, using copied or otherwise synchronized reads, and only then write that snapshot to the WebSocket.

## Patch Rationale
The patch changes the update path to snapshot the coverage bitmap before transmission instead of reading from the shared `mmap` during serialization. This removes the direct race between WebSocket update assembly and concurrent fuzzer writes, while preserving the existing atomic treatment of header counters. The result is a self-consistent payload for each emitted update.

## Residual Risk
None

## Patch
- Patched in `017-websocket-update-reads-shared-mmap-while-fuzzer-mutates-it.patch`
- The change updates `lib/std/Build/Fuzz.zig` so WebSocket updates send a copied snapshot of `seenBits()` rather than the shared mapped slice directly