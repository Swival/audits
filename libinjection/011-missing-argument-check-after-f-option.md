# Missing `-f` argument check causes null pointer crash

## Classification
- Severity: medium
- Type: validation gap
- Confidence: certain

## Affected Locations
- `src/html5_cli.c:152`
- `src/html5_cli.c:172`

## Summary
The CLI accepts `-f` as an option requiring a numeric argument, but the parser increments the argument index and immediately calls `atoi(argv[offset])` without verifying that another argument exists. When `-f` is the final token, `argv[offset]` resolves to the terminating null entry and `atoi` dereferences it, crashing the process.

## Provenance
- Verified from the provided finding and local reproduction details
- Reproduced against the CLI entrypoint in `src/html5_cli.c`
- Reference: https://swival.dev

## Preconditions
- Program is invoked with `-f` as the last argument

## Proof
- In the option loop, matching `-f` increments `offset` before validating bounds.
- With invocation `... -f`, `offset` becomes equal to `argc`.
- POSIX `argv[argc]` is the required terminating null pointer, not a valid argument string.
- The code then executes `atoi(argv[offset])` at `src/html5_cli.c:172`.
- ASan reproduction shows an immediate invalid read/null dereference inside `atoi`, with the stack resolving to `main` in `src/html5_cli.c:172`.

## Why This Is A Real Bug
This path is directly reachable from untrusted command-line input and requires no unusual environment or parser state. The failure occurs before any later validation can recover, producing a reliable denial of service in the standalone utility. Although the original report described it as an out-of-bounds argument access, the concrete manifestation here is dereferencing the null terminator entry of `argv`, which is still a memory-safety bug caused by missing input validation.

## Fix Requirement
Before parsing the `-f` value, verify that another argument is present. If it is missing, print usage and exit with an error instead of calling `atoi`.

## Patch Rationale
The patch adds an explicit post-`-f` argument presence check before `atoi`. This is the narrowest safe fix because it preserves existing option behavior for valid invocations while converting the crashing edge case into a normal usage error path.

## Residual Risk
None

## Patch
- Patch file: `011-missing-argument-check-after-f-option.patch`
- Change required in `src/html5_cli.c`: after consuming `-f`, check `offset < argc` before reading `argv[offset]`; on failure, print usage and return an error code.