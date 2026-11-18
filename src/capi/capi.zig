//! C ABI exports. Every symbol carries a version suffix; see include/zav.h.
const zav = @import("zav");

export fn zav_abi_version() u32 {
    return 1;
}

export fn zav_version_v1() u32 {
    const v = zav.version;
    return @intCast(v.major * 10_000 + v.minor * 100 + v.patch);
}

test "abi version" {
    const std = @import("std");
    try std.testing.expectEqual(@as(u32, 1), zav_abi_version());
}
