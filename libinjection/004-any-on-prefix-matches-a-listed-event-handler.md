# Any `on*` Prefix Event Match Causes False-Positive XSS Detection

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `src/libinjection_xss.c:725`
- `src/libinjection_xss.c:1117`

## Summary
`is_black_attr` treats any attribute whose name begins with `on` followed by a listed event-name prefix as an event handler. The comparison truncates to the known event length and accepts matches when the candidate continues with extra characters, so names like `onloadx` are classified the same as `onload`. This produces false-positive XSS detections for benign custom attributes.

## Provenance
- Verified from the provided reproducer and source inspection in `src/libinjection_xss.c`
- Reproduced against the committed code using the project CLI harness
- Reference: https://swival.dev

## Preconditions
- HTML contains an attribute name beginning with `on` plus a complete listed event-name prefix
- The attribute is parsed as `ATTR_NAME` and evaluated by `is_black_attr`

## Proof
Reproduced with the project sources by compiling `src/html5_cli.c`, `src/libinjection_xss.c`, and `src/libinjection_html5.c`, then running:

```text
/tmp/html5_cli_poc '<img onloadx="foo">'
```

Observed behavior:
- tokenizer emits `ATTR_NAME,7,onloadx`
- tokenizer emits `ATTR_VALUE,3,foo`
- `libinjection_is_xss` reports injection at `src/libinjection_xss.c:1117`

Control cases:
- `<img onload="foo">` -> flagged, expected
- `<img onloadx="foo">` -> flagged, unexpected
- `<img onlo="foo">` -> not flagged
- `<img onzz="foo">` -> not flagged

Root cause at `src/libinjection_xss.c:725`:
- the `on` prefix is stripped
- `max_len = min(input_len - 2, strlen(event))`
- `cstrcasecmp_with_null(event, s_without_on, max_len)` is used
- when `input_len - 2` exceeds the event length, comparison still succeeds on the prefix only

## Why This Is A Real Bug
The behavior is directly observable in the shipped parser path and misclassifies syntactically distinct attribute names as dangerous event handlers. This is not theoretical: benign names such as `onloadx` and `onclick_meta` are rejected as XSS even though they are not event-handler attributes. The impact is incorrect blocking or sanitization decisions in consumers that rely on `libinjection_is_xss`.

## Fix Requirement
Require exact equality between the post-`on` suffix length and the listed event name length before accepting an event-handler match. Prefix-only matches with trailing characters must be rejected.

## Patch Rationale
The patch tightens `is_black_attr` so `on...` attributes only match when the suffix after `on` has the same length as the event name and the full suffix compares equal. This preserves all intended detections for real event handlers while eliminating the reproduced false positives from longer custom attribute names.

## Residual Risk
None

## Patch
- Patch file: `004-any-on-prefix-matches-a-listed-event-handler.patch`
- Change: enforce exact suffix-length equality before event-name comparison in `src/libinjection_xss.c`
- Effect: `onload` still matches, while `onloadx` and other longer prefixed names no longer trigger `TYPE_BLACK`