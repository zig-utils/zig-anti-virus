//! Offline signature compiler: ClamAV CVD/CLD, rule IR, YARA subset, Guardian rules, atom selection, layout.
//! See docs/DESIGN.md for the design this module implements.

pub const cvd = @import("cvd.zig");

test {
    _ = cvd;
    _ = @This();
}
