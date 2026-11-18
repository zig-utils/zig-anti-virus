//! The CPU variants the hash kernels are compiled for, one object each, linked into one binary.
//! This file is the single source of truth: build.zig imports it to create the objects and
//! dispatch.zig imports it to declare their symbols. It depends on std only.
const std = @import("std");

/// What the running CPU must support before a variant's code may execute.
pub const Requirement = enum {
    none,
    x86_64_v2,
    x86_64_v3,
    x86_64_v3_sha,
    aarch64_crypto,
};

pub const Spec = struct {
    /// Suffix of the exported symbols, `zav_hash_<algo>_blocks_<name>`.
    name: []const u8,
    /// CPU model name as `-Dcpu=` spells it.
    model: []const u8,
    /// Features added to the model.
    features: []const []const u8 = &.{},
    /// Features (usually tuning flags) removed from the model.
    features_sub: []const []const u8 = &.{},
    requires: Requirement,
};

const x86_64_specs = [_]Spec{
    .{ .name = "x86_64_v3_sha", .model = "x86_64_v3", .features = &.{"sha"}, .requires = .x86_64_v3_sha },
    .{ .name = "x86_64_v3", .model = "x86_64_v3", .requires = .x86_64_v3 },
    // LLVM's x86-64-v2 model sets fast_shld_rotate, which turns every rol into shld. In the SHA-1,
    // SHA-256 and MD5 dependency chains that halved throughput on an EPYC 7763 (E8), so v2 keeps
    // plain rotates. v3 rotates with BMI2 rorx and is unaffected.
    .{ .name = "x86_64_v2", .model = "x86_64_v2", .features_sub = &.{"fast_shld_rotate"}, .requires = .x86_64_v2 },
    .{ .name = "x86_64_baseline", .model = "x86_64", .requires = .none },
};

const aarch64_specs = [_]Spec{
    .{ .name = "aarch64_crypto", .model = "generic", .features = &.{ "aes", "sha2" }, .requires = .aarch64_crypto },
    .{ .name = "aarch64_baseline", .model = "generic", .requires = .none },
};

/// The variants built for an architecture, best first. Empty means the portable path: the kernels
/// compiled into the engine itself for its own target.
pub fn forArch(arch: std.Target.Cpu.Arch) []const Spec {
    return switch (arch) {
        .x86_64 => &x86_64_specs,
        .aarch64 => &aarch64_specs,
        else => &.{},
    };
}
