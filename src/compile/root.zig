//! Offline signature compiler: ClamAV CVD/CLD, rule IR, YARA subset, Guardian rules, atom selection, layout.
//! See docs/DESIGN.md for the design this module implements.

pub const cvd = @import("cvd.zig");
pub const ir = @import("ir.zig");
pub const hashsig = @import("hashsig.zig");

test {
    _ = cvd;
    _ = ir;
    _ = hashsig;
    _ = @This();
}
