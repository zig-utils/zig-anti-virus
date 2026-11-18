//! Runtime choice among the CPU-variant kernel objects. Every variant listed in variants.zig for the
//! target architecture is linked in; `active` picks the best one the running CPU supports, once.
//! Architectures without variants use `portable`, the kernels compiled into the engine itself.
const std = @import("std");
const builtin = @import("builtin");
const arch = @import("../simd/arch.zig");
const variants = @import("variants.zig");
const kernel = @import("kernel.zig");

pub const Requirement = variants.Requirement;

/// One variant's block kernels. Calls go through these pointers once per update, not per block.
pub const Kernels = struct {
    name: []const u8,
    requires: Requirement,
    md5: kernel.Md5Fn,
    sha1: kernel.Sha1Fn,
    sha256: kernel.Sha256Fn,
    caps: kernel.CapsFn,

    /// Whether this variant's SHA-1 runs on hardware instructions (as compiled, not as detected).
    pub fn hwSha1(k: *const Kernels) bool {
        return k.caps() & kernel.caps_hw_sha1 != 0;
    }

    pub fn hwSha256(k: *const Kernels) bool {
        return k.caps() & kernel.caps_hw_sha256 != 0;
    }
};

const specs = variants.forArch(builtin.cpu.arch);

/// The kernels compiled into the engine for its own target.
pub const portable: Kernels = .{
    .name = "portable",
    .requires = .none,
    .md5 = &kernel.md5Blocks,
    .sha1 = &kernel.sha1Blocks,
    .sha256 = &kernel.sha256Blocks,
    .caps = &kernel.caps,
};

/// Every linked variant, best first. Just `portable` on architectures without variants.
pub const all: []const Kernels = if (specs.len == 0) &.{portable} else blk: {
    var list: [specs.len]Kernels = undefined;
    for (specs, &list) |spec, *entry| entry.* = .{
        .name = spec.name,
        .requires = spec.requires,
        .md5 = @extern(kernel.Md5Fn, .{ .name = "zav_hash_md5_blocks_" ++ spec.name }),
        .sha1 = @extern(kernel.Sha1Fn, .{ .name = "zav_hash_sha1_blocks_" ++ spec.name }),
        .sha256 = @extern(kernel.Sha256Fn, .{ .name = "zav_hash_sha256_blocks_" ++ spec.name }),
        .caps = @extern(kernel.CapsFn, .{ .name = "zav_hash_caps_" ++ spec.name }),
    };
    const final = list;
    break :blk &final;
};

/// Whether a CPU with `features` may execute code built for `requirement`.
pub fn supports(features: arch.Features, requirement: Requirement) bool {
    return switch (requirement) {
        .none => true,
        .x86_64_v2 => features.x86_64_v2,
        .x86_64_v3 => features.x86_64_v3,
        .x86_64_v3_sha => features.x86_64_v3 and features.x86_sha,
        .aarch64_crypto => features.aarch64_aes and features.aarch64_sha1 and features.aarch64_sha2,
    };
}

/// The best variant for `features`. The last entry of `all` always requires nothing.
pub fn best(features: arch.Features) *const Kernels {
    for (all) |*k| if (supports(features, k.requires)) return k;
    unreachable;
}

/// The variant with this name, if it is linked.
pub fn byName(name: []const u8) ?*const Kernels {
    for (all) |*k| if (std.mem.eql(u8, k.name, name)) return k;
    return null;
}

var active_kernels: std.atomic.Value(?*const Kernels) = .init(null);

/// The best variant for the running CPU, detected on first use. Racing first calls agree.
pub fn active() *const Kernels {
    if (active_kernels.load(.acquire)) |k| return k;
    const k = best(arch.detect());
    active_kernels.store(k, .release);
    return k;
}

test "every architecture has a variant that runs anywhere" {
    try std.testing.expect(all.len >= 1);
    try std.testing.expectEqual(Requirement.none, all[all.len - 1].requires);
    try std.testing.expect(supports(.{}, all[all.len - 1].requires));
}

test "dispatch picks the hardware SHA path when the CPU has it" {
    const f = arch.detect();
    const k = active();
    try std.testing.expect(supports(f, k.requires));
    const cpu_has_sha = switch (builtin.cpu.arch) {
        // std's SHA-256 hardware rounds also use AVX2, so the SHA variant is built on x86-64-v3.
        .x86_64 => f.x86_64_v3 and f.x86_sha,
        .aarch64 => f.aarch64_aes and f.aarch64_sha1 and f.aarch64_sha2,
        else => return error.SkipZigTest,
    };
    if (!cpu_has_sha) return error.SkipZigTest;
    try std.testing.expect(k.hwSha1());
    try std.testing.expect(k.hwSha256());
}

test "variants report the hardware paths their CPU model implies" {
    const f = arch.detect();
    if (specs.len == 0) return error.SkipZigTest;
    for (all) |*k| {
        if (!supports(f, k.requires)) continue;
        const hw = switch (k.requires) {
            .x86_64_v3_sha, .aarch64_crypto => true,
            .none, .x86_64_v2, .x86_64_v3 => false,
        };
        try std.testing.expectEqual(hw, k.hwSha1());
        try std.testing.expectEqual(hw, k.hwSha256());
    }
}
