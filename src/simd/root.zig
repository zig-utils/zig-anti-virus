//! Architecture detection and SIMD helpers (runtime byte shuffles per architecture).
//! See docs/DESIGN.md for the design this module implements.

pub const arch = @import("arch.zig");

test {
    _ = arch;
}
