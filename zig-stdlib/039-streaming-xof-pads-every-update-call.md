# Streaming XOF pads every update call

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/ascon.zig:607`

## Summary
- `AsconXof128.update()` and `AsconCxof128.update()` pad the absorb state on every `update()` call instead of only once at finalization.
- As a result, one logical message split across multiple `update()` calls produces a different XOF/CXOF output than the same bytes provided in one shot.
- This violates the expected streaming API invariant that chunking must not affect the digest/XOF result.

## Provenance
- Verified from the provided reproducer and code inspection in `lib/std/crypto/ascon.zig:607`
- Reproduced against the public streaming API using split versus one-shot inputs
- Reference: https://swival.dev

## Preconditions
- Caller supplies one logical XOF message via multiple `update()` calls

## Proof
- User-controlled bytes reach `AsconXof128.update()` / `AsconCxof128.update()` at `lib/std/crypto/ascon.zig:607`.
- Each `update()` absorbs full 8-byte blocks and then immediately XORs the `0x01` padding marker into the current rate position, even when more message bytes will follow.
- `squeeze()` later permutes and emits output from this already-padded state, so intermediate call boundaries become part of the effective input.
- Reproducer results:
  - `AsconXof128` one-shot `"Hello, World!"` -> `AAACADC8A87612C76051F8C8ACD1CE910894049073C62E775B875D582E39EC37`
  - `AsconXof128` split `update("Hello, "); update("World!")` -> `3CE067ECA0929FF670D204E7EA766FF2020918839BD6AE0E4E41C08DDABDB070`
  - `AsconCxof128` with customization `"cust"` one-shot -> `93CBB52DD7F74B977F35AD407029F1227A2B365D33479542673C04A91B009763`
  - `AsconCxof128` split updates -> `47E236AD4C50A6B91D9D6844EAB77846EC79F781D6E9C3E0F9CCF968EA60B5F7`

## Why This Is A Real Bug
- XOF/CXOF streaming interfaces are required to be chunking-invariant: splitting a message across multiple `update()` calls must be equivalent to absorbing the same byte string once.
- Here, transport or buffer boundaries alter the output, so the API no longer hashes the message bytes alone.
- The bug is reachable through the documented public streaming API, and existing tests already exercise multi-call `update()` patterns without asserting the required equivalence.

## Fix Requirement
- Buffer any trailing partial block across `update()` calls.
- Apply the `0x01` padding marker exactly once, at first `squeeze()` or equivalent finalization, after the full logical message has been absorbed.

## Patch Rationale
- The patch defers final padding until finalization and preserves incomplete rate-block bytes between `update()` calls.
- This restores chunking invariance for `AsconXof128` and `AsconCxof128` while keeping normal block absorption behavior unchanged for complete blocks.
- The added logic matches the XOF absorb/finalize model: absorb bytes incrementally, then pad once and squeeze.

## Residual Risk
- None

## Patch
- Patch file: `039-streaming-xof-pads-every-update-call.patch`
- Implements deferred final padding in `lib/std/crypto/ascon.zig`
- Buffers trailing partial input across `update()` calls and finalizes once on `squeeze()`
- Ensures split and one-shot inputs produce identical XOF/CXOF output for the same logical message