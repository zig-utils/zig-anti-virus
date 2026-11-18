//! zav: low-memory anti-malware engine. Module map follows docs/DESIGN.md section 10.
const std = @import("std");

pub const version = std.SemanticVersion{ .major = 0, .minor = 0, .patch = 0 };

pub const db = @import("db/root.zig");
pub const compile = @import("compile/root.zig");
pub const match = @import("match/root.zig");
pub const hash = @import("hash/root.zig");
pub const simd = @import("simd/root.zig");
pub const fmt = @import("fmt/root.zig");
pub const engine = @import("engine/root.zig");
pub const rt = @import("rt/root.zig");
pub const daemon = @import("daemon/root.zig");
pub const watch = @import("watch/root.zig");
pub const host = @import("host/root.zig");
pub const cve = @import("cve/root.zig");
pub const update = @import("update/root.zig");
pub const capi = @import("capi/root.zig");
pub const cli = @import("cli/root.zig");
/// zig-regex, re-exported so tools and embedders use the exact version the engine was built with.
pub const regex = @import("regex");

test {
    std.testing.refAllDecls(@This());
    _ = db;
    _ = compile;
    _ = match;
    _ = hash;
    _ = simd;
    _ = fmt;
    _ = engine;
    _ = rt;
    _ = daemon;
    _ = watch;
    _ = host;
    _ = cve;
    _ = update;
    _ = capi;
    _ = cli;
}
