//! Matching kernels: hash index, need map, split-block Bloom prefilters, atom tables, verify VM, logical signatures.
//! See docs/DESIGN.md for the design this module implements.

pub const hashidx = @import("hashidx.zig");
pub const prog = @import("prog.zig");
pub const verify_vm = @import("verify_vm.zig");
pub const anchored = @import("anchored.zig");
pub const ldb_table = @import("ldb_table.zig");

test {
    _ = hashidx;
    _ = prog;
    _ = verify_vm;
    _ = anchored;
    _ = ldb_table;
}
