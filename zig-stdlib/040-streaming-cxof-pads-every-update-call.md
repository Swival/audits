# Streaming CXOF pads on each `update()`

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/ascon.zig:723`

## Summary
`AsconCxof128.update()` finalizes each call by injecting CXOF padding into the permutation state, even when more message bytes will arrive later. As a result, the streaming API is not chunk-invariant: repeated `update()` calls over the same concatenated input produce different outputs than a single `update()` call.

## Provenance
- Verified from the provided reproducer and code inspection in this tree
- Reference: Swival Security Scanner - https://swival.dev

## Preconditions
- A CXOF caller uses multiple `update()` calls before the first `squeeze()`
- The caller expects streaming equivalence between split and one-shot absorption of the same logical input

## Proof
The reproduced behavior shows distinct outputs for identical logical inputs split across multiple `update()` calls:
- `update("AB")` -> `35E01B674469E350EF23A23D6ECD177EE61BAE55C8CB32F0E1606986EB0BCA9D`
- `update("A"); update("B")` -> `A6212C4EB567315CE280CD5D93BEEAA65AC8E0741BCF48745F11E7D76EF0609C`

The same divergence occurs across a rate boundary:
- `update("123456789")` -> `06DF2FED5DD6F73968FE025D5B706008188064CCC08E01E317DF9144B693B33E`
- `update("12345678"); update("9")` -> `4A9AF287AB4C8B7B2A27556D43AA4BB598139E4610BEB55DF2D01E0C151D3D29`

Root cause: `AsconCxof128.update()` absorbs full 8-byte blocks and then immediately XORs the CXOF padding marker into state at `lib/std/crypto/ascon.zig:723`. When another `update()` follows, absorption resumes from an already-padded state, effectively inserting a message terminator between chunks. `squeeze()` then operates on that malformed absorbed stream.

## Why This Is A Real Bug
The API explicitly exposes a streaming interface through repeated `update()` calls. For such an interface, chunking must not change the result for the same concatenated input. Here, transport or buffering differences alter CXOF output, which can change derived keys, transcript hashes, or digest-like outputs for identical logical data. This is a direct correctness and data-integrity failure, not a theoretical edge case.

## Fix Requirement
Defer CXOF message padding until finalization, i.e. the first `squeeze()` or equivalent final step. `update()` must only absorb bytes and retain any partial rate block across calls so that split and one-shot inputs are processed identically.

## Patch Rationale
The patch in `040-streaming-cxof-pads-every-update-call.patch` moves padding responsibility out of `update()` and into finalization, while preserving buffered partial bytes between calls. This restores chunk invariance: multiple `update()` calls now absorb the same byte stream as a single concatenated call before padding is applied exactly once.

## Residual Risk
None

## Patch
- File: `040-streaming-cxof-pads-every-update-call.patch`
- Effect: defers CXOF padding to first `squeeze()`/finalization and tracks partial buffered input across `update()` calls
- Security impact: restores deterministic CXOF output for identical logical input regardless of caller chunking