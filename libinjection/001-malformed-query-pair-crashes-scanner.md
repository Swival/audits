# Malformed query pair crashes scanner

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `misc/logscanner2.py:92`
- `misc/logscanner2.py:113`
- `misc/logscanner2.py:179`

## Summary
A `/diagnostics` request containing a query item without `=` causes `doline()` to build a one-element entry in `qsl` and then crash on `for k, v in qsl`. The resulting `ValueError` is uncaught and can terminate scanner processing for the malformed log entry and the surrounding scan loop.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Reference: https://swival.dev

## Preconditions
- A processed log line populates `data['request_uri']` with a `/diagnostics` URI
- The query string contains at least one parameter without `=`, such as `/diagnostics?foo&id=1`

## Proof
`doline()` parses the request URI and currently derives query items with manual splitting:

```python
qsl = [x.split('=', 1) for x in urlparts.query.split('&')]
for k,v in qsl:
```

For `/diagnostics?foo&id=1`, `urlparts.query` is `foo&id=1`, so `qsl` becomes:

```python
[['foo'], ['id', '1']]
```

The first element has length 1, so the unpacking loop raises:

```text
ValueError: not enough values to unpack
```

That exception is not handled in `doline()`, and the caller processes lines via `doline(line.strip())` without a surrounding `try/except`, allowing a single malformed Apache log entry such as the following to abort scanning:

```text
1.2.3.4 - - [29/Jul/2013:01:30:19 +0000] "GET /diagnostics?foo&id=1 HTTP/1.1" 200 123 "-" "ua" "-"
```

## Why This Is A Real Bug
The failure is directly reachable from log-controlled input that is already parsed into `request_uri`. Query parameters without `=` are valid enough to appear in real requests and logs, whether due to malformed clients, probing, or attacker input. Because the code assumes every split item is a key/value pair and does not catch the resulting exception, one bad record can stop the scanner instead of being safely ignored.

## Fix Requirement
Replace manual query splitting with a parser that only yields valid key/value pairs, or explicitly skip malformed items before unpacking so log scanning continues safely.

## Patch Rationale
The patch uses robust query parsing semantics so malformed query fragments no longer produce one-element list entries. This preserves existing behavior for well-formed parameters while preventing an uncaught unpacking exception from terminating the scanner on malformed `/diagnostics` requests.

## Residual Risk
None

## Patch
- `001-malformed-query-pair-crashes-scanner.patch`