# Shutdown crashes when `fd` is uninitialized

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `misc/nullserver.py:15`
- `misc/nullserver.py:17`
- `misc/nullserver.py:97`

## Summary
`misc/nullserver.py` only initializes the global file handle `fd` inside the `__main__` block, but `ShutdownHandler.get()` is reachable whenever the module is imported because `application` is created at import time. A `/shutdown` request therefore calls `fd.close()` with no prior definition of `fd`, raising `NameError` and aborting shutdown before `sys.exit(0)` executes.

## Provenance
- Reproduced from the verified report and harness described by the user
- Reference: https://swival.dev

## Preconditions
- The module is loaded without executing `if __name__ == "__main__":`
- The exposed `/shutdown` route is invoked in that imported state

## Proof
- `misc/nullserver.py:97` initializes `fd` only under `if __name__ == "__main__":`
- `misc/nullserver.py:17` unconditionally executes `fd.close()` after declaring `global fd`
- In the reproduced import-based execution path, `application` exists but `fd` does not
- Invoking `ShutdownHandler.get()` in that state raises `NameError: name 'fd' is not defined` before shutdown completes

## Why This Is A Real Bug
The failure is reachable under a realistic deployment mode explicitly supported by the file’s structure: importing the module exposes `application` without running the startup block. In that state, `/shutdown` deterministically crashes the handler instead of performing an orderly shutdown, violating the handler’s shutdown invariant and leaving the route externally triggerable.

## Fix Requirement
Initialize `fd` at module scope and make shutdown tolerate the absence of an opened file handle by guarding the close operation.

## Patch Rationale
Defining `fd = None` at module load establishes the global invariant that `fd` always exists. Guarding `fd.close()` with a null check preserves normal behavior for the main execution path while preventing `NameError` when the module is imported without file initialization.

## Residual Risk
None

## Patch
```diff
diff --git a/misc/nullserver.py b/misc/nullserver.py
--- a/misc/nullserver.py
+++ b/misc/nullserver.py
@@
 import sys
 import time
 import tornado.web
 import tornado.options
 from tornado.options import define, options
 
+fd = None
+
 class ShutdownHandler(tornado.web.RequestHandler):
     def get(self):
         global fd
-        fd.close()
+        if fd is not None:
+            fd.close()
         sys.exit(0)
```