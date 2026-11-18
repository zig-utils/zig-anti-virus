//! Runtime: work-stealing pool, epochs, event loop, directory walking, small-file I/O.
//! See docs/DESIGN.md for the design this module implements.

pub const vm = @import("vm.zig");

test {
    _ = vm;
}
