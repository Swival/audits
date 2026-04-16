# Invalid Apache timestamp aborts parsing

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `misc/logscanner2.py:40`

## Summary
`doline()` falls through to Apache log parsing when JSON parsing fails. For regex-matching Apache lines, `parse_apache()` forwards the timestamp field directly to `parse_date()`. `parse_date()` assumes a valid Apache timestamp and performs unchecked month lookup and integer conversion, so malformed timestamp text raises `KeyError` or `ValueError` and aborts the entire scan instead of rejecting that line.

## Provenance
- Verified from the provided reproducer and patch context
- Scanner source: https://swival.dev

## Preconditions
- An Apache log line matches the parser regex
- The timestamp token is malformed, such as an invalid month or non-numeric day/time component

## Proof
A regex-matching line such as:
```text
1.2.3.4 - - [29/Foo/2013:01:30:19 +0000] "GET /diagnostics?id=1 HTTP/1.1" 200 123 "-" "ua" "-"
```

reaches `parse_apache()`, which passes `29/Foo/2013:01:30:19 +0000` into `parse_date()`.

In `parse_date()`:
- `months[datestr[3:6]]` raises `KeyError('Foo')` for an unexpected month token
- `int(datestr[0:2])` and later fixed-slice conversions raise `ValueError` for non-numeric fields such as `xx/Jul/...`
- these exceptions are uncaught by `parse_apache()`, `doline()`, and the main processing loop, so the process terminates

This reproduces as a scanner-level denial of service from a single malformed but regex-matching Apache line.

## Why This Is A Real Bug
The parser already accepts arbitrary log input and intentionally tolerates non-JSON lines by attempting Apache parsing. In that path, malformed timestamps are not rare or theoretical: log corruption, partial writes, upstream format drift, or attacker-controlled request logging can all produce regex-matching lines with invalid timestamp contents. Because the exception is unhandled at every caller layer, one bad line stops report generation for the whole file.

## Fix Requirement
Reject malformed Apache timestamps without throwing. The parser must validate or safely parse the timestamp and return `None` for invalid lines so scanning continues.

## Patch Rationale
The patch adds defensive handling around Apache timestamp parsing so invalid date components no longer propagate exceptions. This preserves existing behavior for valid lines while converting malformed timestamps into a parse miss, which is consistent with the parser’s line-oriented best-effort design.

## Residual Risk
None

## Patch
- Patch file: `003-invalid-apache-timestamp-aborts-parsing.patch`
- Patched area: `misc/logscanner2.py`
- Change: guard Apache timestamp parsing and return `None` on invalid timestamp input instead of letting `KeyError` or `ValueError` terminate processing