//! File formats, containers and normalisers, streamed with bounded memory.
//! See docs/DESIGN.md for the design this module implements.

pub const types = @import("types.zig");
pub const detect = @import("detect.zig");

test {
    _ = types;
    _ = detect;
}
