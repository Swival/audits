# Unchecked `file_id` Indexes Module Subsection Buffer

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/Pdb.zig:503`
- `lib/std/debug/Pdb.zig:882`
- `lib/std/debug/Pdb.zig:884`
- `lib/std/debug/SelfInfo/Windows.zig:318`
- `lib/std/debug/SelfInfo/Windows.zig:370`

## Summary
`getFileName` computes `subsect_index = checksum_offset + file_id` and immediately indexes `mod.subsect_info[subsect_index]` without first proving the index stays within the module subsection buffer or that enough bytes remain for a `FileChecksumEntryHeader`. Parsed PDB module data can supply `name_index` or inline-site `file_id` values that exceed the `file_checksums` subsection, causing a runtime out-of-bounds trap during source resolution.

## Provenance
- Verified from the supplied finding and reproducer
- Reachable through Windows symbolization and inline-site source lookup in the standard library
- Reference: https://swival.dev

## Preconditions
- Attacker controls PDB module file checksum references

## Proof
- `getLineNumberInfo` forwards `block_hdr.name_index` into `getFileName`.
- `getInlineSiteSourceLocation` may forward annotation-derived `file_id` into `getFileName`.
- In `lib/std/debug/Pdb.zig:503`, `subsect_index = checksum_offset + file_id` is used as `&mod.subsect_info[subsect_index]` before any bounds check against `mod.subsect_info.len`.
- During module parsing, the `file_checksums` subsection offset is recorded at `lib/std/debug/Pdb.zig:882` and `lib/std/debug/Pdb.zig:884`, but the subsection end is not retained and referenced offsets are not validated against subsection bounds.
- A malformed module can therefore point `name_index` or `file_id` beyond the remaining bytes of `subsect_info`.
- Reproduction confirms this becomes a runtime `index out of bounds` panic at the slice access, yielding denial of service in symbol/source resolution.

## Why This Is A Real Bug
The vulnerable path is exercised by normal Windows debug symbol handling. Accepted PDB data reaches `getLineNumberInfo` and `getInlineSiteSourceLocation`, which both depend on `getFileName` for source file lookup. Because the code trusts attacker-influenced offsets inside parsed module data, malformed PDB input can reliably crash the consumer. Even though the failure manifests as a bounds trap rather than a silent memory disclosure in normal builds, it is still a real availability bug triggered by untrusted debug metadata.

## Fix Requirement
Reject `file_id`-derived accesses unless the computed subsection index is within `mod.subsect_info` and enough bytes remain to read a full `FileChecksumEntryHeader`. Validation must occur before taking the address of `mod.subsect_info[subsect_index]`.

## Patch Rationale
The patch adds explicit bounds checks for `subsect_index` and header size before dereferencing the module subsection buffer. This converts malformed checksum references into a handled parse failure instead of a runtime panic, matching the intended contract for untrusted PDB parsing.

## Residual Risk
None

## Patch
- Patched in `067-unchecked-file-id-indexes-module-subsection-buffer.patch`
- The change guards `getFileName` in `lib/std/debug/Pdb.zig` by validating the computed checksum entry offset and required header bytes before accessing `mod.subsect_info`