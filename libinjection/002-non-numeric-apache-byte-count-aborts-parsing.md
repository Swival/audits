# Non-numeric Apache byte count aborts parsing

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `misc/logscanner2.py:56`

## Summary
- `parse_apache()` accepts Apache log lines whose byte-count field matches `\S+`, then unconditionally converts that field with `int(mo.group(7))`.
- When the field is non-numeric, including common placeholder values like `-`, Python raises `ValueError`.
- That exception is not handled in `parse_apache()`, `doline()`, or the main file-processing loop, so one malformed line aborts the entire scan.

## Provenance
- Verified from the provided reproducer and source inspection in `misc/logscanner2.py`.
- External reference: https://swival.dev

## Preconditions
- An Apache log line reaches `parse_apache()` with a non-numeric byte-count field.

## Proof
- `doline()` first attempts `json.loads(line)` and only catches `ValueError` from that JSON parse path, then calls `parse_apache(line)` on failure at `misc/logscanner2.py:94` and `misc/logscanner2.py:97`.
- `parse_apache()` matches the Apache regex and executes `int(mo.group(7))` without validation at `misc/logscanner2.py:56`.
- The regex allows non-whitespace tokens for that field, so placeholders such as `-` are accepted by the match.
- The main loop calls `doline(line.strip())` for each line without an exception handler at `misc/logscanner2.py:178` and `misc/logscanner2.py:179`.
- Reproducer line:
```text
1.2.3.4 - - [29/Jul/2013:01:30:19 +0000] "GET /diagnostics?id=test HTTP/1.1" 200 - "-" "ua" "-"
```
- This line matches, reaches `int("-")`, raises `ValueError`, and terminates the scan.

## Why This Is A Real Bug
- The parser explicitly accepts tokens that are not guaranteed numeric, but the implementation assumes numeric input.
- Apache/Nginx-style logs commonly emit `-` when byte counts are unavailable, so the failure occurs on realistic input, not just adversarial data.
- Because the exception escapes the per-line processing path, availability is impacted: one malformed or incomplete log line prevents all subsequent lines from being scanned.

## Fix Requirement
- Guard the byte-count conversion in `parse_apache()` by catching `ValueError` and treating invalid values as rejected input or a safe default, without raising out of the line parser.

## Patch Rationale
- The patch in `002-non-numeric-apache-byte-count-aborts-parsing.patch` wraps the byte-count conversion so invalid Apache byte-count tokens no longer crash processing.
- Rejecting or defaulting the field preserves scanner availability and aligns parser behavior with the regex and with real-world log formats that use `-` placeholders.

## Residual Risk
- None

## Patch
```diff
diff --git a/misc/logscanner2.py b/misc/logscanner2.py
--- a/misc/logscanner2.py
+++ b/misc/logscanner2.py
@@ -53,7 +53,11 @@ def parse_apache(line):
     o["status"] = int(mo.group(6))
     if o["status"] == 499:
         o["status"] = 200
-    o["bytes"] = int(mo.group(7))
+    try:
+        o["bytes"] = int(mo.group(7))
+    except ValueError:
+        return None
+
     o["referer"] = mo.group(8)
     o["agent"] = mo.group(9)
     o["fwdfor"] = mo.group(10)
```