//! Root of one CPU-variant object of the stage-one kernel. build.zig compiles it once per entry
//! in src/hash/variants.zig with that variant's CPU model and an options module naming it, and
//! the copies link into one binary as `zav_stage1_<name>` (match/prefilter.zig dispatches).
const kernel = @import("stage1.zig");
const name = @import("zav_stage1_variant").name;

comptime {
    @export(&kernel.runArgs, .{ .name = "zav_stage1_" ++ name });
}
