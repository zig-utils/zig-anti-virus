//! Root of one CPU-variant object. build.zig compiles it once per entry in variants.zig with that
//! variant's CPU model and an options module naming it; every copy exports the kernels under
//! `zav_hash_<algo>_blocks_<name>` so all of them link into one binary.
const kernel = @import("kernel.zig");
const name = @import("zav_hash_variant").name;

comptime {
    @export(&kernel.md5Blocks, .{ .name = "zav_hash_md5_blocks_" ++ name });
    @export(&kernel.sha1Blocks, .{ .name = "zav_hash_sha1_blocks_" ++ name });
    @export(&kernel.sha256Blocks, .{ .name = "zav_hash_sha256_blocks_" ++ name });
    @export(&kernel.caps, .{ .name = "zav_hash_caps_" ++ name });
}
