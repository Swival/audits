# Section data length uses unchecked file-controlled bounds

## Classification
High severity validation gap. Confidence: certain.

## Affected Locations
- `lib/std/coff.zig:833`
- `lib/std/coff.zig:1169`
- `lib/std/debug/SelfInfo/Windows.zig:515`
- `lib/std/debug/SelfInfo/Windows.zig:519`

## Summary
`Coff.getSectionData` slices `self.data` using `SectionHeader` fields taken from attacker-controlled COFF/PE input without validating that `offset + size` stays within `self.data.len`. A crafted section header can therefore trigger a bounds trap and denial of service during section lookup.

## Provenance
- Verified from the provided finding and reproduction notes against `lib/std/coff.zig`.
- External scanner reference: https://swival.dev

## Preconditions
- Parsing attacker-controlled COFF/PE section headers.
- A caller reaches `Coff.getSectionData` for a section whose `virtual_size` combined with `pointer_to_raw_data` or `virtual_address` exceeds the backing buffer length.

## Proof
At `lib/std/coff.zig:833`, `getSectionData` derives:
- `offset = sec.virtual_address` for loaded images, or
- `offset = sec.pointer_to_raw_data` otherwise,

then returns a slice equivalent to:
```zig
self.data[offset..][0..sec.virtual_size]
```

Those fields originate from parsed section headers and are file-controlled. No guard ensures:
```zig
offset <= self.data.len
offset + sec.virtual_size <= self.data.len
```

The reproduced call path reaches this logic from section name lookup in `lib/std/debug/SelfInfo/Windows.zig:515` and `lib/std/debug/SelfInfo/Windows.zig:519`, with the vulnerable slice at `lib/std/coff.zig:1169`. A malformed PE/COFF with oversized section bounds causes Zig's runtime bounds checks to trap, producing a denial of service.

## Why This Is A Real Bug
The failing bounds are derived entirely from untrusted file metadata, and the vulnerable operation is a runtime-checked slice. When the computed range exceeds the buffer, execution aborts in safe builds. This is externally triggerable through crafted input and directly violates parser robustness expectations.

## Fix Requirement
Validate both `offset` and `offset + size` against `self.data.len` before slicing, and return an error instead of trapping.

## Patch Rationale
The patch in `010-section-data-length-uses-unchecked-file-controlled-bounds.patch` adds explicit range validation in `getSectionData` before constructing the returned slice. This converts malformed section extents from a runtime panic into normal error handling while preserving existing behavior for valid inputs.

## Residual Risk
None

## Patch
Patched in `010-section-data-length-uses-unchecked-file-controlled-bounds.patch`.