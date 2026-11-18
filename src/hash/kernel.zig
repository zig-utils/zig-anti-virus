//! Block-compression kernels with a C ABI, compiled for whatever CPU the including module targets.
//! The engine compiles this file once per CPU variant (variant_object.zig exports each copy under a
//! unique name) and once more into itself for the portable path. SHA-256 uses std's kernel, which
//! emits SHA-NI or ARMv8 sha256h only when the target enables them; SHA-1 uses sha1_hw.zig when
//! the target has the extension and std's software rounds otherwise; MD5 is std's software rounds.
const std = @import("std");
const builtin = @import("builtin");
const sha1_hw = @import("sha1_hw.zig");

pub const Md5Fn = *const fn (state: *[4]u32, data: [*]const u8, n: usize) callconv(.c) void;
pub const Sha1Fn = *const fn (state: *[5]u32, data: [*]const u8, n: usize) callconv(.c) void;
pub const Sha256Fn = *const fn (state: *[8]u32, data: [*]const u8, n: usize) callconv(.c) void;
pub const CapsFn = *const fn () callconv(.c) u32;

/// Capability bits a kernel set reports about the code it was compiled to.
pub const caps_hw_sha1: u32 = 1 << 0;
pub const caps_hw_sha256: u32 = 1 << 1;

const hw_sha256 = builtin.zig_backend != .stage2_c and switch (builtin.cpu.arch) {
    // The conditions std.crypto.sha2 uses to pick its hardware rounds.
    .x86_64 => builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 }),
    .aarch64 => builtin.cpu.has(.aarch64, .sha2),
    else => false,
};

pub fn caps() callconv(.c) u32 {
    return (if (sha1_hw.available) caps_hw_sha1 else 0) | (if (hw_sha256) caps_hw_sha256 else 0);
}

/// std's streaming types run whole blocks straight through their round function when the buffer
/// is empty, so seeding one with our chaining state and feeding block multiples is exactly the
/// compression function, without copying std's private code.
pub fn md5Blocks(state: *[4]u32, data: [*]const u8, n: usize) callconv(.c) void {
    var h = std.crypto.hash.Md5.init(.{});
    h.s = state.*;
    h.update(data[0 .. n * 64]);
    state.* = h.s;
}

pub fn sha1Blocks(state: *[5]u32, data: [*]const u8, n: usize) callconv(.c) void {
    if (comptime sha1_hw.available) return sha1_hw.blocks(state, data, n);
    var h = std.crypto.hash.Sha1.init(.{});
    h.s = state.*;
    h.update(data[0 .. n * 64]);
    state.* = h.s;
}

pub fn sha256Blocks(state: *[8]u32, data: [*]const u8, n: usize) callconv(.c) void {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.s = state.*;
    h.update(data[0 .. n * 64]);
    state.* = h.s;
}
