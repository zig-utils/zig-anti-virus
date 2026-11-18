//! Offline signature compiler: ClamAV CVD/CLD, rule IR, YARA subset, Guardian rules, atom selection, layout.
//! See docs/DESIGN.md for the design this module implements.

pub const cvd = @import("cvd.zig");
pub const ir = @import("ir.zig");
pub const hashsig = @import("hashsig.zig");
pub const hash_build = @import("hash_build.zig");
pub const filters = @import("filters.zig");
pub const coverage = @import("coverage.zig");
pub const compiler = @import("compiler.zig");
pub const mbazaar = @import("mbazaar.zig");
pub const builtin = @import("builtin.zig");

test {
    _ = cvd;
    _ = ir;
    _ = hashsig;
    _ = hash_build;
    _ = filters;
    _ = coverage;
    _ = compiler;
    _ = mbazaar;
    _ = builtin;
    _ = @This();
}
