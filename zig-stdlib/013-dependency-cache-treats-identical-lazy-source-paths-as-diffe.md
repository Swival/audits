# Dependency cache misses for identical lazy source paths

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/Build.zig:1519`
- `lib/std/Build.zig:2191`
- `lib/std/Build.zig:2196`

## Summary
`dependencyInner` caches dependencies by `user_input_options`, but equality for `LazyPath` values is inverted for `.src_path`. When two dependency calls pass the same owned source path, hashing places them in the same bucket while equality incorrectly reports them different, so the cache misses and equivalent dependencies are instantiated twice.

## Provenance
- Verified from the supplied reproducer and source inspection
- Scanner provenance: https://swival.dev

## Preconditions
- Dependency arguments include a `lazy_path` or `lazy_path_list` containing `.src_path`
- The compared `LazyPath` values refer to the same owner and same `sub_path`

## Proof
- `dependencyInner` consults `graph.dependency_cache` using `user_input_options` from dependency arguments in `lib/std/Build.zig:1519`.
- Hashing for `.src_path` includes owner and `sub_path`, so identical paths collide intentionally and reach equality comparison in `lib/std/Build.zig:2191`.
- Equality flows through `userValuesAreSame` into `userLazyPathsAreTheSame`.
- In the `.src_path` arm, after confirming equal owners, the code returns `false` when `std.mem.eql(u8, lhs_sp.sub_path, rhs_sp.sub_path)` is true in `lib/std/Build.zig:2196`.
- Reproducer: a minimal build script calling `b.dependency("other", .{ .lazy_path = b.path("same.txt") })` twice returns distinct dependency pointers, proving cache reuse fails for equivalent inputs.

## Why This Is A Real Bug
The dependency cache is intended to canonicalize repeated requests for the same package and same options. Existing standalone tests already assert that equivalent dependency arguments should reuse the same dependency object. Here, equivalent `.src_path` arguments hash identically but compare unequal solely because of an inverted predicate, causing duplicate `*Build.Dependency` and child `Build` creation. This is a concrete behavioral regression, not a theoretical concern.

## Fix Requirement
Negate the `.src_path` subpath check so equality returns `false` only when the `sub_path` values differ.

## Patch Rationale
The patch flips the inverted condition in `userLazyPathsAreTheSame` for `.src_path`, restoring consistency between hashing and equality for lazy source paths. This is the minimal fix needed to make equivalent dependency options hit the cache again.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/std/Build.zig b/lib/std/Build.zig
index 4c6f2d1..9a3b8f7 100644
--- a/lib/std/Build.zig
+++ b/lib/std/Build.zig
@@ -2193,7 +2193,7 @@ fn userLazyPathsAreTheSame(lhs: LazyPath, rhs: LazyPath) bool {
             const lhs_sp = lhs.src_path;
             const rhs_sp = rhs.src_path;
             if (lhs_sp.owner != rhs_sp.owner) return false;
-            if (std.mem.eql(u8, lhs_sp.sub_path, rhs_sp.sub_path)) return false;
+            if (!std.mem.eql(u8, lhs_sp.sub_path, rhs_sp.sub_path)) return false;
             return true;
         },
         .cwd_relative => |lhs_rel| {