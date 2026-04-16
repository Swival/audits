# Writable PT_LOAD copy ignores segment file offset

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/dynamic_library.zig:299`
- `lib/std/dynamic_library.zig:313`

## Summary
On Linux, `ElfDynLib.open` handles writable `PT_LOAD` segments by creating an anonymous mapping and copying initialized bytes from the ELF file into it. The copy uses `file_bytes[0..ph.p_filesz]` and writes to the mapping base, ignoring both `ph.p_offset` and the in-page destination offset derived from segment alignment. For any writable `PT_LOAD` with nonzero `p_offset`, initialized segment data is deterministically loaded from the wrong source bytes and into the wrong destination address.

## Provenance
- Verified from the provided finding and reproducer against `lib/std/dynamic_library.zig`
- Source file: `lib/std/dynamic_library.zig`
- Swival Security Scanner: https://swival.dev

## Preconditions
- Linux `ElfDynLib.open` loads an ELF containing a writable `PT_LOAD`
- That segment has nonzero `p_offset`
- The writable segment follows the anonymous-map-and-copy path

## Proof
- In `ElfDynLib.open`, writable `PT_LOAD` segments are mapped anonymously, then populated with:
  ```zig
  @memcpy(sect_mem[0..ph.p_filesz], file_bytes[0..ph.p_filesz]);
  ```
- This copy ignores `ph.p_offset`, so the source bytes come from the start of the file rather than the segment's file-backed range.
- The same path also ignores the segment's page-offset adjustment (`extra_bytes`), so bytes are written at the mapping base instead of the segment's intended in-memory start.
- Reproduction used an x86_64 Linux shared object with `int important = 0x11223344;`, where the writable `PT_LOAD` had `p_offset = 0x428` and `p_vaddr = 0x3428`, yielding `extra_bytes = 0x428`.
- Under the buggy logic, the 4 initialized bytes are copied to the page base rather than virtual address offset `0x428` within the mapping, leaving the symbol location zeroed instead of `0x11223344`.
- Result: initialized writable segment contents are corrupted on load.

## Why This Is A Real Bug
The behavior follows directly from attacker-controlled ELF program headers and unconditional copy logic in the writable `PT_LOAD` path. No race, undefined behavior assumption, or unusual environment is required. If `p_offset != 0`, the loader reads the wrong file region; if the segment is not page-aligned in-memory, it also writes to the wrong address within the mapped page. This breaks correct ELF loading semantics and causes deterministic corruption of writable initialized data and any metadata or code colocated in that segment.

## Fix Requirement
The writable `PT_LOAD` copy must:
- Read from `file_bytes[ph.p_offset .. ph.p_offset + ph.p_filesz]`
- Write to the destination starting at the segment's in-page offset, not the mapping base
- Preserve existing bounds and alignment expectations for the mapped segment

## Patch Rationale
The patch in `022-writable-pt-load-copy-ignores-segment-file-offset.patch` corrects both dimensions of the bug: it copies from the segment's actual file range and writes into the mapped memory at the proper offset within the page-aligned allocation. This matches ELF `PT_LOAD` semantics and restores correct initialization of writable segment contents.

## Residual Risk
None

## Patch
- `022-writable-pt-load-copy-ignores-segment-file-offset.patch` fixes the writable `PT_LOAD` initialization logic in `lib/std/dynamic_library.zig` so copied bytes honor both `ph.p_offset` and the segment's in-memory alignment offset.