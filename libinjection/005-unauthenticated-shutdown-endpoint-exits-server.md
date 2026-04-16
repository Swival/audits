# Unauthenticated shutdown endpoint exits server

## Classification
Authorization flaw; severity: high; confidence: certain

## Affected Locations
`misc/nullserver.py:16`

## Summary
`misc/nullserver.py` exposed `/shutdown` without any authentication or authorization. A single remote `GET /shutdown` reached `ShutdownHandler.get()`, which closed the global file descriptor and called `sys.exit(0)`, terminating the server process and causing remote denial of service.

## Provenance
Verified from the provided finding and reproducer; reproduced locally against the vulnerable handler behavior. Scanner reference: https://swival.dev

## Preconditions
Network access to the server on port `8888`

## Proof
`misc/nullserver.py:16` routed `/shutdown` to `ShutdownHandler`.
`misc/nullserver.py:19` closed the global `fd`.
`misc/nullserver.py:20` called `sys.exit(0)` unconditionally from a GET handler.
Because `SystemExit` inherits from `BaseException`, it is not handled by Tornado's normal request exception path, so the process exits.
In reproduction, sending unauthenticated `GET /shutdown` to `127.0.0.1:8888` caused the server PID to disappear and the client to receive HTTP `000`.

## Why This Is A Real Bug
The vulnerable path is remotely reachable, requires no credentials, and directly terminates the process. This is a complete availability loss for the service from a single request, matching a practical high-severity denial-of-service condition.

## Fix Requirement
Remove the `/shutdown` route or gate shutdown behind authenticated, admin-only access before any process-exit behavior is reachable.

## Patch Rationale
The patch removes the remotely reachable unauthenticated shutdown capability so external clients can no longer trigger process termination through HTTP. This aligns the code with the requirement that server shutdown must not be exposed to untrusted users.

## Residual Risk
None

## Patch
`005-unauthenticated-shutdown-endpoint-exits-server.patch` removes or disables the `/shutdown` route in `misc/nullserver.py`, eliminating the unauthenticated code path that closed `fd` and invoked `sys.exit(0)`.