# Dependency cache miscompares identical generated lazy paths

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Build.zig:2185`
- `lib/std/Build.zig:2191`
- `lib/std/Build.zig:2240`

## Summary
The dependency cache key comparison for `LazyPath` values is inverted for string subpaths. In `userLazyPathsAreTheSame`, both `.src_path` and `.generated` return `false` when `sub_path` strings are equal, causing semantically identical dependency arguments to compare unequal. As a result, repeated dependency invocations with the same generated lazy-path argument miss `dependency_cache` and re-run dependency initialization.

## Provenance
- Reproduced from the verified report against the current code in `lib/std/Build.zig`
- Scanner source: https://swival.dev
- Patch artifact: `014-dependency-cache-treats-identical-generated-lazy-paths-as-di.patch`

## Preconditions
- Two dependency invocations use equal generated `LazyPath` arguments
- The cache comparison reaches `InitializedDepContext.eql` through normal dependency resolution

## Proof
`dependencyInner` records user-supplied dependency arguments, including `LazyPath`, into the dependency context. Cache lookup later calls `InitializedDepContext.eql`, which delegates to `userValuesAreSame`, then `userLazyPathsAreTheSame` for `LazyPath` comparison.

In `lib/std/Build.zig:2191`, the `.generated` branch checks matching `file` and `up`, then executes:
```zig
if (std.mem.eql(u8, lhs_gen.sub_path, rhs_gen.sub_path)) return false;
```
That is the wrong polarity: identical `sub_path` values are treated as unequal.

The same inverted check exists for `.src_path` at `lib/std/Build.zig:2185`.

Because equality returns `false` for equal generated lazy paths, equivalent dependency contexts do not match in `dependency_cache`. Execution then falls through the cache-miss path in `dependencyInner`, reaching child creation and dependency initialization at `lib/std/Build.zig:2240`, making duplicate initialization reachable.

## Why This Is A Real Bug
This violates the cache key invariant: equal dependency inputs must compare equal. The observed behavior is not theoretical; the comparison function deterministically rejects identical generated lazy paths. That directly defeats cache reuse and causes repeated configure-time work and duplicated dependency instances for the same logical dependency invocation.

## Fix Requirement
Negate the `std.mem.eql` result for `sub_path` comparison so equal strings are accepted and differing strings are rejected. Apply the same correction to both `.generated` and `.src_path` branches to restore consistent `LazyPath` equality semantics.

## Patch Rationale
The minimal safe fix is to invert the erroneous equality test in `userLazyPathsAreTheSame`. This preserves all existing structural checks (`owner`, `file`, `up`) and only corrects the final string comparison, aligning implementation behavior with expected cache-key equality.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/std/Build.zig b/lib/std/Build.zig
index 0000000..0000000 100644
--- a/lib/std/Build.zig
+++ b/lib/std/Build.zig
@@ -2182,14 +2182,14 @@ fn userLazyPathsAreTheSame(lhs: UserLazyPath, rhs: UserLazyPath) bool {
             const lhs_src = lhs.src_path;
             const rhs_src = rhs.src_path;
             if (lhs_src.owner != rhs_src.owner) return false;
-            if (std.mem.eql(u8, lhs_src.sub_path, rhs_src.sub_path)) return false;
+            if (!std.mem.eql(u8, lhs_src.sub_path, rhs_src.sub_path)) return false;
         },
         .generated => {
             const lhs_gen = lhs.generated;
             const rhs_gen = rhs.generated;
             if (lhs_gen.file != rhs_gen.file) return false;
             if (lhs_gen.up != rhs_gen.up) return false;
-            if (std.mem.eql(u8, lhs_gen.sub_path, rhs_gen.sub_path)) return false;
+            if (!std.mem.eql(u8, lhs_gen.sub_path, rhs_gen.sub_path)) return false;
         },
         .cwd_relative => {
             if (!std.mem.eql(u8, lhs.cwd_relative, rhs.cwd_relative)) return false;
```